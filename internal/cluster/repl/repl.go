// Package repl replicates the configuration and the state between nodes.
//
// Config tables are journaled by SQLite triggers into the changelog (one
// entry per row change, numbered by seq and tagged with the primary epoch).
// Followers apply the entries in order, or a full snapshot when they are too
// far behind or have diverged. Triggers are generated at startup from the
// live schema, so new columns are picked up without hand-written SQL.
//
// State tables (sessions, usage counters, audit...) are written on every
// node: their triggers fill state_outbox, shipped to the peer and merged
// with per-table rules.
package repl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// ConfigTables are replicated through the changelog, in dependency order
// (parents before children). The filter limits which rows are config.
var ConfigTables = []struct {
	Name   string
	Filter string // SQL on NEW/OLD, "" = all rows
}{
	{"settings", ""}, {"users", ""}, {"webauthn_credentials", ""}, {"totp", ""}, {"recovery_codes", ""},
	{"api_tokens", ""}, {"certificates", ""}, {"zones", ""}, {"records", "source = 'manual'"}, {"forwarders", ""},
	{"interface_settings", ""}, {"vlans", ""}, {"dhcp_scopes", ""}, {"dhcp_reservations", ""}, {"epochs", ""},
}

// StateTables are merged between nodes (no single source of truth).
var StateTables = []string{"sessions", "webauthn_usage", "totp_usage", "recovery_usage", "login_guard", "audit_log", "user_activity"}

type column struct {
	name string
	blob bool
}

type table struct {
	name   string
	pk     string
	cols   []column
	filter string
}

// Store manages replication tables and triggers.
type Store struct {
	db     *store.DB
	config []*table
	state  map[string]*table
	byName map[string]*table
}

// Open inspects the schema and (re)creates the triggers.
func Open(ctx context.Context, db *store.DB) (*Store, error) {
	s := &Store{db: db, state: map[string]*table{}, byName: map[string]*table{}}
	for _, ct := range ConfigTables {
		t, err := s.inspect(ctx, ct.Name)
		if err != nil {
			return nil, err
		}
		t.filter = ct.Filter
		s.config = append(s.config, t)
		s.byName[t.name] = t
	}
	for _, name := range StateTables {
		t, err := s.inspect(ctx, name)
		if err != nil {
			return nil, err
		}
		s.state[name] = t
		s.byName[name] = t
	}
	return s, s.installTriggers(ctx)
}

func (s *Store) inspect(ctx context.Context, name string) (*table, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, type, pk FROM pragma_table_info(?) ORDER BY cid`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &table{name: name}
	for rows.Next() {
		var n, typ string
		var pk int
		if err := rows.Scan(&n, &typ, &pk); err != nil {
			return nil, err
		}
		t.cols = append(t.cols, column{name: n, blob: strings.EqualFold(typ, "BLOB")})
		if pk == 1 {
			t.pk = n
		}
	}
	if len(t.cols) == 0 || t.pk == "" {
		return nil, fmt.Errorf("replication: table %s missing or without single-column primary key", name)
	}
	return t, rows.Err()
}

// rowJSON is a json_object() expression of the row (blobs in hex).
func (t *table) rowJSON(prefix string) string {
	parts := make([]string, 0, len(t.cols))
	for _, c := range t.cols {
		v := prefix + "." + c.name
		if c.blob {
			v = "hex(" + v + ")"
		}
		parts = append(parts, fmt.Sprintf("'%s', %s", c.name, v))
	}
	return "json_object(" + strings.Join(parts, ", ") + ")"
}

const nowMs = `CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)`

func (s *Store) installTriggers(ctx context.Context) error {
	var stmts []string
	for _, t := range s.config {
		guard := `(SELECT applying = 0 AND record = 1 FROM repl_state WHERE id = 1)`
		cond := func(p string) string {
			if t.filter == "" {
				return guard
			}
			return guard + " AND " + p + "." + t.filter
		}
		ins := func(op, p string) string {
			row := "NULL"
			if op == "upsert" {
				row = t.rowJSON(p)
			}
			return fmt.Sprintf(`INSERT INTO changelog(epoch, tbl, pk, op, row, ts) VALUES ((SELECT epoch FROM repl_state WHERE id = 1), '%s', %s.%s, '%s', %s, %s)`,
				t.name, p, t.pk, op, row, nowMs)
		}
		stmts = append(stmts,
			fmt.Sprintf(`CREATE TRIGGER repl_%s_i AFTER INSERT ON %s WHEN %s BEGIN %s; END`, t.name, t.name, cond("NEW"), ins("upsert", "NEW")),
			fmt.Sprintf(`CREATE TRIGGER repl_%s_u AFTER UPDATE ON %s WHEN %s BEGIN %s; END`, t.name, t.name, cond("NEW"), ins("upsert", "NEW")),
			fmt.Sprintf(`CREATE TRIGGER repl_%s_d AFTER DELETE ON %s WHEN %s BEGIN %s; END`, t.name, t.name, cond("OLD"), ins("delete", "OLD")))
	}
	for _, t := range s.state {
		guard := `(SELECT applying = 0 FROM repl_state WHERE id = 1)`
		put := fmt.Sprintf(`INSERT INTO state_outbox(tbl, op, row) VALUES ('%s', 'upsert', %s)`, t.name, t.rowJSON("NEW"))
		del := fmt.Sprintf(`INSERT INTO state_outbox(tbl, op, row) VALUES ('%s', 'delete', json_object('%s', OLD.%s))`, t.name, t.pk, t.pk)
		stmts = append(stmts,
			fmt.Sprintf(`CREATE TRIGGER repl_%s_i AFTER INSERT ON %s WHEN %s BEGIN %s; END`, t.name, t.name, guard, put),
			fmt.Sprintf(`CREATE TRIGGER repl_%s_u AFTER UPDATE ON %s WHEN %s BEGIN %s; END`, t.name, t.name, guard, put),
			fmt.Sprintf(`CREATE TRIGGER repl_%s_d AFTER DELETE ON %s WHEN %s BEGIN %s; END`, t.name, t.name, guard, del))
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'repl\_%' ESCAPE '\'`)
		if err != nil {
			return err
		}
		var old []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return err
			}
			old = append(old, n)
		}
		rows.Close()
		for _, n := range old {
			if _, err := tx.ExecContext(ctx, `DROP TRIGGER `+n); err != nil {
				return err
			}
		}
		for _, st := range stmts {
			if _, err := tx.ExecContext(ctx, st); err != nil {
				return fmt.Errorf("%w: %s", err, st)
			}
		}
		return nil
	})
}

// SetRecording turns journaling of local config changes on (primary,
// single node) or off (secondary: config only comes from the primary).
func (s *Store) SetRecording(ctx context.Context, on bool, epoch uint64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE repl_state SET record = ?, epoch = ? WHERE id = 1`, b2i(on), epoch)
	return err
}

// Position returns the last journaled change (epoch, seq).
func (s *Store) Position(ctx context.Context) (epoch, seq uint64, err error) {
	var e, q sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT epoch, seq FROM changelog ORDER BY seq DESC LIMIT 1`).Scan(&e, &q)
	if errors.Is(err, sql.ErrNoRows) {
		be, _ := s.db.Meta(ctx, "repl_base_epoch")
		bs, _ := s.db.Meta(ctx, "repl_base_seq")
		var ue, us uint64
		fmt.Sscan(be, &ue)
		fmt.Sscan(bs, &us)
		return ue, us, nil
	}
	return uint64(e.Int64), uint64(q.Int64), err
}

// Has reports whether the journal holds (seq, epoch), or whether it is the
// snapshot base.
func (s *Store) Has(ctx context.Context, seq, epoch uint64) bool {
	if seq == 0 {
		return true
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM changelog WHERE seq = ? AND epoch = ?`, seq, epoch).Scan(&n)
	if n > 0 {
		return true
	}
	be, _ := s.db.Meta(ctx, "repl_base_epoch")
	bs, _ := s.db.Meta(ctx, "repl_base_seq")
	return be == fmt.Sprint(epoch) && bs == fmt.Sprint(seq)
}

// Oldest returns the first seq still in the journal (0 when empty).
func (s *Store) Oldest(ctx context.Context) uint64 {
	var v sql.NullInt64
	_ = s.db.QueryRowContext(ctx, `SELECT MIN(seq) FROM changelog`).Scan(&v)
	return uint64(v.Int64)
}

// ChangesAfter returns up to limit journal entries after seq.
func (s *Store) ChangesAfter(ctx context.Context, seq uint64, limit int) ([]proto.Change, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, epoch, tbl, pk, op, COALESCE(row, '') FROM changelog WHERE seq > ? ORDER BY seq LIMIT ?`, seq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.Change
	for rows.Next() {
		var c proto.Change
		if err := rows.Scan(&c.Seq, &c.Epoch, &c.Table, &c.PK, &c.Op, &c.Row); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// withApplying runs fn in a transaction on a dedicated connection with the
// triggers' "applying" switch on, optionally without foreign key checks.
func (s *Store) withApplying(ctx context.Context, noFK bool, fn func(*sql.Tx) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if noFK {
		if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return err
		}
		defer conn.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE repl_state SET applying = 1 WHERE id = 1`); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repl_state SET applying = 0 WHERE id = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

// decodeRow parses a row JSON keeping integers exact.
func decodeRow(raw string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// upsert writes a row (from the journal or a snapshot) into t.
func (s *Store) upsert(ctx context.Context, tx *sql.Tx, t *table, row map[string]any) error {
	var cols, marks, sets []string
	var args []any
	for _, c := range t.cols {
		v, ok := row[c.name]
		if !ok {
			continue // column unknown on the sender: keep the default
		}
		switch x := v.(type) {
		case json.Number:
			if i, err := x.Int64(); err == nil {
				v = i
			} else {
				f, _ := x.Float64()
				v = f
			}
		case string:
			if c.blob {
				b, err := hex.DecodeString(x)
				if err != nil {
					return err
				}
				v = b
			}
		}
		cols = append(cols, c.name)
		marks = append(marks, "?")
		args = append(args, v)
		if c.name != t.pk {
			sets = append(sets, c.name+" = excluded."+c.name)
		}
	}
	q := fmt.Sprintf(`INSERT INTO %s(%s) VALUES (%s) ON CONFLICT(%s) DO `, t.name, strings.Join(cols, ", "), strings.Join(marks, ", "), t.pk)
	if len(sets) == 0 {
		q += "NOTHING"
	} else {
		q += "UPDATE SET " + strings.Join(sets, ", ")
	}
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

// Apply applies journal entries received from the primary, in order, and
// records them in the local journal with the same numbers.
func (s *Store) Apply(ctx context.Context, changes []proto.Change) error {
	if len(changes) == 0 {
		return nil
	}
	return s.withApplying(ctx, false, func(tx *sql.Tx) error {
		for _, c := range changes {
			t := s.byName[c.Table]
			if t == nil {
				return fmt.Errorf("replication: unknown table %s", c.Table)
			}
			switch c.Op {
			case "upsert":
				row, err := decodeRow(c.Row)
				if err != nil {
					return err
				}
				if err := s.upsert(ctx, tx, t, row); err != nil {
					return fmt.Errorf("apply %s %s: %w", c.Table, c.PK, err)
				}
			case "delete":
				if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, t.name, t.pk), c.PK); err != nil {
					return err
				}
			}
			var row any
			if c.Row != "" {
				row = c.Row
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO changelog(seq, epoch, tbl, pk, op, row, ts) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				c.Seq, c.Epoch, c.Table, c.PK, c.Op, row, time.Now().UnixMilli()); err != nil {
				return err
			}
		}
		return nil
	})
}

// dump returns all config rows of t (as JSON objects), ordered by key.
func (s *Store) dump(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, t *table) ([]string, error) {
	where := ""
	if t.filter != "" {
		where = " WHERE " + t.filter
	}
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`SELECT %s FROM %s AS NEW%s ORDER BY %s`, t.rowJSON("NEW"), t.name, where, t.pk))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Hashes fingerprints each config table, and all of them together.
func (s *Store) Hashes(ctx context.Context) (map[string]string, string, error) {
	out := map[string]string{}
	all := sha256.New()
	for _, t := range s.config {
		rows, err := s.dump(ctx, s.db, t)
		if err != nil {
			return nil, "", err
		}
		h := sha256.New()
		for _, r := range rows {
			h.Write([]byte(r))
			h.Write([]byte{'\n'})
		}
		sum := hex.EncodeToString(h.Sum(nil))[:16]
		out[t.name] = sum
		fmt.Fprintf(all, "%s=%s\n", t.name, sum)
	}
	return out, hex.EncodeToString(all.Sum(nil))[:16], nil
}

// Snapshot captures the whole configuration (rows, position, epochs).
func (s *Store) Snapshot(ctx context.Context) (*proto.Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snap := &proto.Snapshot{Tables: map[string][]map[string]any{}}
	var e, q sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT epoch, seq FROM changelog ORDER BY seq DESC LIMIT 1`).Scan(&e, &q); err == nil {
		snap.Epoch, snap.Seq = uint64(e.Int64), uint64(q.Int64)
	} else {
		snap.Epoch, snap.Seq, _ = s.Position(ctx)
	}
	for _, t := range s.config {
		rows, err := s.dump(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		list := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			m, err := decodeRow(r)
			if err != nil {
				return nil, err
			}
			list = append(list, m)
		}
		snap.Tables[t.name] = list
	}
	return snap, nil
}

// ApplySnapshot replaces the local configuration with the snapshot. Local
// journal entries are dropped (call SaveConflicts first if needed). State
// tables are untouched; foreign keys are not checked during the swap so
// leases of unchanged scopes survive.
func (s *Store) ApplySnapshot(ctx context.Context, snap *proto.Snapshot) error {
	return s.withApplying(ctx, true, func(tx *sql.Tx) error {
		// Children first for deletes.
		for i := len(s.config) - 1; i >= 0; i-- {
			t := s.config[i]
			keep := map[string]bool{}
			for _, r := range snap.Tables[t.name] {
				keep[fmt.Sprint(r[t.pk])] = true
			}
			where := ""
			if t.filter != "" {
				where = " WHERE " + t.filter
			}
			rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT CAST(%s AS TEXT) FROM %s%s`, t.pk, t.name, where))
			if err != nil {
				return err
			}
			var del []string
			for rows.Next() {
				var k string
				if err := rows.Scan(&k); err != nil {
					rows.Close()
					return err
				}
				if !keep[k] {
					del = append(del, k)
				}
			}
			rows.Close()
			for _, k := range del {
				if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE CAST(%s AS TEXT) = ?`, t.name, t.pk), k); err != nil {
					return err
				}
			}
		}
		for _, t := range s.config {
			for _, r := range snap.Tables[t.name] {
				if err := s.upsert(ctx, tx, t, r); err != nil {
					return fmt.Errorf("snapshot %s: %w", t.name, err)
				}
			}
		}
		// Leases and DHCP records of deleted scopes/zones go away too.
		for _, q := range []string{
			`DELETE FROM dhcp_leases WHERE scope_id NOT IN (SELECT id FROM dhcp_scopes)`,
			`DELETE FROM records WHERE zone_id NOT IN (SELECT id FROM zones)`,
			`DELETE FROM dhcp_reservations WHERE scope_id NOT IN (SELECT id FROM dhcp_scopes)`,
			`DELETE FROM changelog`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		for k, v := range map[string]uint64{"repl_base_epoch": snap.Epoch, "repl_base_seq": snap.Seq} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, fmt.Sprint(v)); err != nil {
				return err
			}
		}
		// New local entries (if this node becomes primary) continue after the base.
		if _, err := tx.ExecContext(ctx, `DELETE FROM sqlite_sequence WHERE name = 'changelog'`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name, seq) VALUES ('changelog', ?)`, snap.Seq)
		return err
	})
}

// SaveConflicts moves local journal entries of epoch that the primary does
// not have (seq >= fromSeq) into the conflicts table.
func (s *Store) SaveConflicts(ctx context.Context, epoch, fromSeq uint64) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, epoch, tbl, pk, op, COALESCE(row, '') FROM changelog WHERE epoch = ? AND seq >= ? ORDER BY seq`, epoch, fromSeq)
	if err != nil {
		return 0, err
	}
	var list []proto.Change
	for rows.Next() {
		var c proto.Change
		if err := rows.Scan(&c.Seq, &c.Epoch, &c.Table, &c.PK, &c.Op, &c.Row); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, c)
	}
	rows.Close()
	now := time.Now().UnixMilli()
	for _, c := range list {
		if c.Table == "epochs" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO conflicts(id, epoch, seq, tbl, pk, op, row, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ids.New(), c.Epoch, c.Seq, c.Table, c.PK, c.Op, nullIfEmpty(c.Row), now); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// Conflict is a change lost by a former primary.
type Conflict struct {
	ID         string    `json:"id"`
	Epoch      uint64    `json:"epoch"`
	Seq        uint64    `json:"seq"`
	Table      string    `json:"table"`
	PK         string    `json:"pk"`
	Op         string    `json:"op"`
	Row        string    `json:"row"`
	DetectedAt time.Time `json:"detectedAt"`
	Status     string    `json:"status"`
}

// Conflicts lists the saved conflicts.
func (s *Store) Conflicts(ctx context.Context) ([]Conflict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, epoch, seq, tbl, pk, op, COALESCE(row, ''), detected_at, status FROM conflicts ORDER BY detected_at DESC, seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Conflict{}
	for rows.Next() {
		var c Conflict
		var at int64
		if err := rows.Scan(&c.ID, &c.Epoch, &c.Seq, &c.Table, &c.PK, &c.Op, &c.Row, &at, &c.Status); err != nil {
			return nil, err
		}
		c.DetectedAt = time.UnixMilli(at)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Reapply applies a saved conflict as a normal local change (on the
// primary, so it is journaled and replicated) and marks it done.
func (s *Store) Reapply(ctx context.Context, id string) error {
	var c Conflict
	err := s.db.QueryRowContext(ctx, `SELECT tbl, pk, op, COALESCE(row, '') FROM conflicts WHERE id = ? AND status = 'pending'`, id).
		Scan(&c.Table, &c.PK, &c.Op, &c.Row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	t := s.byName[c.Table]
	if t == nil {
		return fmt.Errorf("table inconnue %s", c.Table)
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if c.Op == "delete" {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, t.name, t.pk), c.PK); err != nil {
				return err
			}
		} else {
			row, err := decodeRow(c.Row)
			if err != nil {
				return err
			}
			if err := s.upsert(ctx, tx, t, row); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE conflicts SET status = 'reapplied' WHERE id = ?`, id)
		return err
	})
}

// Dismiss marks a conflict as ignored.
func (s *Store) Dismiss(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE conflicts SET status = 'dismissed' WHERE id = ? AND status = 'pending'`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Epochs returns the epoch history (newest first).
func (s *Store) Epochs(ctx context.Context) ([]proto.EpochStart, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT epoch, start_seq, node_id, name, at, reason FROM epochs ORDER BY epoch DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []proto.EpochStart{}
	for rows.Next() {
		var e proto.EpochStart
		var at int64
		if err := rows.Scan(&e.Epoch, &e.StartSeq, &e.NodeID, &e.Name, &at, &e.Reason); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// BeginEpoch makes this node the journal writer for epoch: the epoch row is
// the first journaled change of the new term.
func (s *Store) BeginEpoch(ctx context.Context, epoch uint64, nodeID, name, reason string) error {
	if err := s.SetRecording(ctx, true, epoch); err != nil {
		return err
	}
	_, seq, err := s.Position(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO epochs(epoch, start_seq, node_id, name, at, reason) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(epoch) DO NOTHING`, epoch, seq+1, nodeID, name, time.Now().UnixMilli(), reason)
	return err
}

// Trim keeps the journal below keep entries.
func (s *Store) Trim(ctx context.Context, keep int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM changelog WHERE seq <= (SELECT MAX(seq) FROM changelog) - ?`, keep)
	return err
}

// ---- state ----

// Outbox returns pending state rows (with their outbox ids).
func (s *Store) Outbox(ctx context.Context, limit int) ([]int64, []proto.StateRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, tbl, op, row FROM state_outbox ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var idsOut []int64
	var out []proto.StateRow
	for rows.Next() {
		var id int64
		var r proto.StateRow
		if err := rows.Scan(&id, &r.Table, &r.Op, &r.Row); err != nil {
			return nil, nil, err
		}
		idsOut = append(idsOut, id)
		out = append(out, r)
	}
	return idsOut, out, rows.Err()
}

// AckOutbox removes sent rows.
func (s *Store) AckOutbox(ctx context.Context, upTo int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM state_outbox WHERE id <= ?`, upTo)
	return err
}

// ClearOutbox drops pending rows (the peer will get a full state exchange).
func (s *Store) ClearOutbox(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM state_outbox`)
	return err
}

// FullState returns every state row (initial exchange after a (re)join).
func (s *Store) FullState(ctx context.Context) ([]proto.StateRow, error) {
	var out []proto.StateRow
	names := make([]string, 0, len(s.state))
	for n := range s.state {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rows, err := s.dump(ctx, s.db, s.state[n])
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, proto.StateRow{Table: n, Op: "upsert", Row: r})
		}
	}
	return out, nil
}

// merge rules: column -> "max" (keep the larger), "keep" (never overwrite
// a non-null value), default: take the incoming value.
var mergeRules = map[string]map[string]string{
	"sessions":       {"last_seen_at": "max", "revoked_at": "keep", "elevated_until": "max"},
	"webauthn_usage": {"sign_count": "max", "last_used_at": "max"},
	"totp_usage":     {"last_counter": "max"},
	"login_guard":    {"failures": "max", "locked_until": "max", "updated_at": "max"},
	"user_activity":  {"last_login_at": "max"},
}

// ApplyState merges state rows received from the peer.
func (s *Store) ApplyState(ctx context.Context, rows []proto.StateRow) error {
	if len(rows) == 0 {
		return nil
	}
	return s.withApplying(ctx, true, func(tx *sql.Tx) error {
		for _, r := range rows {
			t := s.state[r.Table]
			if t == nil {
				continue
			}
			row, err := decodeRow(r.Row)
			if err != nil {
				return err
			}
			if r.Op == "delete" {
				if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, t.name, t.pk), fmt.Sprint(row[t.pk])); err != nil {
					return err
				}
				continue
			}
			if t.name == "audit_log" {
				// Append-only: keep the local numbering, ignore known entries.
				delete(row, "seq")
				var n int
				_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE id = ?`, row["id"]).Scan(&n)
				if n > 0 {
					continue
				}
				if err := s.insertNoPK(ctx, tx, t, row); err != nil {
					return err
				}
				continue
			}
			if err := s.mergeUpsert(ctx, tx, t, row); err != nil {
				return fmt.Errorf("state %s: %w", t.name, err)
			}
		}
		return nil
	})
}

func (s *Store) insertNoPK(ctx context.Context, tx *sql.Tx, t *table, row map[string]any) error {
	var cols, marks []string
	var args []any
	for _, c := range t.cols {
		v, ok := row[c.name]
		if !ok {
			continue
		}
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				v = i
			}
		}
		cols, marks, args = append(cols, c.name), append(marks, "?"), append(args, v)
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(%s) VALUES (%s)`, t.name, strings.Join(cols, ", "), strings.Join(marks, ", ")), args...)
	return err
}

func (s *Store) mergeUpsert(ctx context.Context, tx *sql.Tx, t *table, row map[string]any) error {
	var cols, marks, sets []string
	var args []any
	rules := mergeRules[t.name]
	for _, c := range t.cols {
		v, ok := row[c.name]
		if !ok {
			continue
		}
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				v = i
			}
		}
		if s, ok := v.(string); ok && c.blob {
			b, err := hex.DecodeString(s)
			if err != nil {
				return err
			}
			v = b
		}
		cols, marks, args = append(cols, c.name), append(marks, "?"), append(args, v)
		if c.name == t.pk {
			continue
		}
		switch rules[c.name] {
		case "max":
			sets = append(sets, fmt.Sprintf("%s = CASE WHEN excluded.%s IS NULL THEN %s.%s WHEN %s.%s IS NULL THEN excluded.%s ELSE max(%s.%s, excluded.%s) END",
				c.name, c.name, t.name, c.name, t.name, c.name, c.name, t.name, c.name, c.name))
		case "keep":
			sets = append(sets, fmt.Sprintf("%s = COALESCE(%s.%s, excluded.%s)", c.name, t.name, c.name, c.name))
		default:
			sets = append(sets, c.name+" = excluded."+c.name)
		}
	}
	q := fmt.Sprintf(`INSERT INTO %s(%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s`, t.name, strings.Join(cols, ", "),
		strings.Join(marks, ", "), t.pk, strings.Join(sets, ", "))
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Equal compares two snapshots' rows (tests).
func Equal(a, b *proto.Snapshot) bool {
	ja, _ := json.Marshal(a.Tables)
	jb, _ := json.Marshal(b.Tables)
	return bytes.Equal(ja, jb)
}
