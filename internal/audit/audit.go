// Package audit writes an append-only, chained audit log. Each entry stores
// the hash of the previous entry of the same node, so removing or editing a
// line breaks the chain and is detected by Verify.
//
// Entries are keyed (version 2): the hash is an HMAC-SHA256 with a sub-key
// of the data key (DEK), which both nodes of a cluster share. Without the
// key, an entry cannot be rewritten so that the chain still verifies.
// Entries written before version 2 keep their plain SHA-256 hash.
//
// Old entries are purged after a retention period. The hash of the last
// purged entry of each node is kept (meta table) as the new start of its
// chain, so the rest stays verifiable.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

// Result values.
const (
	Success = "success"
	Failure = "failure"
)

// Size limits of a stored entry. Entries are written before authentication
// (failed logins) and replicated to the other node: no field may grow
// without bound.
const (
	maxAction       = 96
	maxActor        = 128
	maxIP           = 64
	maxTarget       = 256
	maxResult       = 16
	maxDetailString = 1024
	maxDetails      = 16 << 10
)

// DefaultRetentionDays is how long entries are kept by default.
const DefaultRetentionDays = 365

const (
	chainPurpose   = "audit-chain"
	keyringPurpose = "audit-keyring"
	keyringMeta    = "audit_keyring"
	anchorMeta     = "audit_anchor:" // + node id
	v2Prefix       = "v2:"
	verifyEvery    = 24 * time.Hour
)

// Entry is one audit line.
type Entry struct {
	ID      string         `json:"id"`
	TS      time.Time      `json:"ts"`
	NodeID  string         `json:"nodeId"`
	Actor   string         `json:"actor"`
	IP      string         `json:"ip"`
	Action  string         `json:"action"`
	Target  string         `json:"target"`
	Result  string         `json:"result"`
	Details map[string]any `json:"details"`
}

// Log writes audit entries.
type Log struct {
	db     *store.DB
	nodeID string
	log    *slog.Logger
	mu     sync.Mutex // serializes the chain, purges and key changes
	box    *secrets.Box

	thMu     sync.Mutex
	throttle map[string]*throttled
	dropped  int

	maintMu    sync.Mutex
	lastVerify time.Time

	// Now is the clock (tests).
	Now func() time.Time
}

// New returns an audit log bound to a node. Call SetKey to key the chain.
func New(db *store.DB, nodeID string, log *slog.Logger) *Log {
	return &Log{db: db, nodeID: nodeID, log: log, throttle: map[string]*throttled{}, Now: time.Now}
}

// SetKey keys the chain with a sub-key of the data key. When the data key
// changes (a node joins a cluster, a restore brings another key), the old
// sub-key is kept in a local keyring so the entries it signed stay
// verifiable on this node.
func (l *Log) SetKey(box *secrets.Box) {
	l.mu.Lock()
	l.box = box
	l.mu.Unlock()
	box.OnReplace(l.rekey)
}

// Record appends an entry. Errors are logged, never returned: auditing must
// not break the action being audited, but a failure is visible in the logs.
// The entry is written even if ctx is canceled (client gone): the action
// it describes may already be done.
func (l *Log) Record(ctx context.Context, e Entry) {
	if err := l.record(context.WithoutCancel(ctx), e); err != nil {
		l.log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

type throttled struct {
	until   time.Time
	skipped int
}

const maxThrottleKeys = 10000

// RecordThrottled records e at most once per window for key (for example
// refused logins of one client): the entry tells how many were skipped
// since the previous one ("suppressed"). It keeps a flood of identical
// events from filling the disk.
func (l *Log) RecordThrottled(ctx context.Context, key string, window time.Duration, e Entry) {
	now := l.Now()
	l.thMu.Lock()
	t := l.throttle[key]
	if t != nil && now.Before(t.until) {
		t.skipped++
		l.thMu.Unlock()
		return
	}
	if t == nil && len(l.throttle) >= maxThrottleKeys {
		for k, v := range l.throttle {
			if !now.Before(v.until) {
				delete(l.throttle, k)
			}
		}
		if len(l.throttle) >= maxThrottleKeys {
			l.dropped++
			l.thMu.Unlock()
			return
		}
	}
	skipped := 0
	if t != nil {
		skipped = t.skipped
	}
	l.throttle[key] = &throttled{until: now.Add(window)}
	dropped := l.dropped
	l.dropped = 0
	l.thMu.Unlock()
	d := make(map[string]any, len(e.Details)+2)
	for k, v := range e.Details {
		d[k] = v
	}
	if skipped > 0 {
		d["suppressed"] = skipped
	}
	if dropped > 0 {
		d["suppressedOther"] = dropped
	}
	e.Details = d
	l.Record(ctx, e)
}

func (l *Log) record(ctx context.Context, e Entry) error {
	if e.ID == "" {
		e.ID = ids.New()
	}
	if e.TS.IsZero() {
		e.TS = l.Now()
	}
	if e.Result == "" {
		e.Result = Success
	}
	e.NodeID = l.nodeID
	e.Action, e.Actor, e.IP = clip(e.Action, maxAction), clip(e.Actor, maxActor), clip(e.IP, maxIP)
	e.Target, e.Result = clip(e.Target, maxTarget), clip(e.Result, maxResult)
	details, err := encodeDetails(e.Details)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var key []byte
	if l.box != nil {
		key = l.box.SubKey(chainPurpose)
	}
	return l.db.Tx(ctx, func(tx *sql.Tx) error {
		a, err := readAnchor(ctx, tx, e.NodeID)
		if err != nil {
			return err
		}
		// One chain per node: entries replicated from the other node have
		// their own chain. Copies of purged entries sent back by the other
		// node (ts <= MaxTS) are not part of the chain any more.
		var prev string
		err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE node_id = ? AND ts > ? ORDER BY seq DESC LIMIT 1`,
			e.NodeID, a.MaxTS).Scan(&prev)
		if errors.Is(err, sql.ErrNoRows) {
			prev, err = a.Hash, nil
		}
		if err != nil {
			return err
		}
		h := chainHash(key, prev, e, details)
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID, e.TS.UnixMilli(), e.NodeID, e.Actor, e.IP, e.Action, e.Target, e.Result, details, prev, h)
		return err
	})
}

// clip shortens s to at most n bytes (plus an ellipsis), on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// encodeDetails returns the details as JSON, long strings shortened and the
// whole bounded.
func encodeDetails(d map[string]any) (string, error) {
	if d == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	if len(raw) <= maxDetailString {
		return string(raw), nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if raw, err = json.Marshal(clipValue(v)); err != nil {
		return "", err
	}
	if len(raw) > maxDetails {
		raw, _ = json.Marshal(map[string]any{"truncated": true, "size": len(raw)})
	}
	return string(raw), nil
}

func clipValue(v any) any {
	switch x := v.(type) {
	case string:
		return clip(x, maxDetailString)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[clip(k, maxDetailString)] = clipValue(e)
		}
		return out
	case []any:
		for i := range x {
			x[i] = clipValue(x[i])
		}
		return x
	}
	return v
}

// chainHash is the hash of an entry: plain SHA-256 (version 1) without a
// key, else "v2:<key id>:<HMAC-SHA256>".
func chainHash(key []byte, prev string, e Entry, details string) string {
	var s hash.Hash
	if key == nil {
		s = sha256.New()
	} else {
		s = hmac.New(sha256.New, key)
		s.Write([]byte("leazone-audit-v2|"))
	}
	for _, f := range []string{prev, e.ID, strconv.FormatInt(e.TS.UnixMilli(), 10), e.NodeID, e.Actor, e.IP,
		e.Action, e.Target, e.Result, details} {
		fmt.Fprintf(s, "%d:%s|", len(f), f)
	}
	sum := hex.EncodeToString(s.Sum(nil))
	if key == nil {
		return sum
	}
	return v2Prefix + keyID(key) + ":" + sum
}

// keyID names a chain key without revealing it.
func keyID(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("leazone-audit-key-id"))
	return hex.EncodeToString(m.Sum(nil)[:4])
}

// parseHash returns the version of a stored hash and its key id (v2).
func parseHash(h string) (version int, kid string) {
	if rest, ok := strings.CutPrefix(h, v2Prefix); ok {
		kid, sum, ok := strings.Cut(rest, ":")
		if !ok || len(kid) != 8 || len(sum) != 64 {
			return 0, ""
		}
		return 2, kid
	}
	if len(h) == 64 {
		return 1, ""
	}
	return 0, ""
}

// ---- anchors and keyring (local meta table) ----

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// anchor is the start of a node chain after a purge: the last purged entry.
type anchor struct {
	ID    string `json:"id"`
	Hash  string `json:"hash"`
	TS    int64  `json:"ts"`
	MaxTS int64  `json:"maxTs"` // newest purged entry: older copies are stale
}

func readAnchor(ctx context.Context, q querier, node string) (anchor, error) {
	var a anchor
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, anchorMeta+node).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal([]byte(v), &a)
}

func writeAnchor(ctx context.Context, q querier, node string, a anchor) error {
	v, _ := json.Marshal(a)
	_, err := q.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		anchorMeta+node, string(v))
	return err
}

func keyringBox(dek []byte) *secrets.Box {
	b, err := secrets.NewBox(secrets.DeriveKey(dek, keyringPurpose))
	if err != nil {
		panic(err)
	}
	return b
}

// loadKeyring returns the retired chain keys (key id -> key), sealed in
// meta with a sub-key of dek.
func loadKeyring(ctx context.Context, q querier, dek []byte) (map[string][]byte, error) {
	ring := map[string][]byte{}
	var sealed string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, keyringMeta).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return ring, nil
	}
	if err != nil {
		return ring, err
	}
	pt, err := keyringBox(dek).Open(sealed, keyringMeta)
	if err != nil {
		return ring, err
	}
	var enc map[string]string
	if err := json.Unmarshal(pt, &enc); err != nil {
		return ring, err
	}
	for kid, k := range enc {
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil {
			ring[kid] = raw
		}
	}
	return ring, nil
}

func saveKeyring(ctx context.Context, q querier, dek []byte, ring map[string][]byte) error {
	enc := make(map[string]string, len(ring))
	for kid, k := range ring {
		enc[kid] = base64.StdEncoding.EncodeToString(k)
	}
	pt, _ := json.Marshal(enc)
	_, err := q.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		keyringMeta, keyringBox(dek).Seal(pt, keyringMeta))
	return err
}

// rekey keeps the chain key of the old data key (OnReplace hook).
func (l *Log) rekey(old, cur []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	ring, err := loadKeyring(ctx, l.db, old)
	if err != nil {
		l.log.Warn("audit keyring unreadable, older retired keys are lost", "err", err)
		ring = map[string][]byte{}
	}
	k := secrets.DeriveKey(old, chainPurpose)
	ring[keyID(k)] = k
	if err := saveKeyring(ctx, l.db, cur, ring); err != nil {
		l.log.Error("audit keyring not saved: entries signed with the previous data key can no longer be verified", "err", err)
		return
	}
	l.log.Info("audit chain key changed with the data key; previous key kept to verify older entries", "kid", keyID(k))
}

// keys returns every chain key this node knows: current and retired.
func (l *Log) keys(ctx context.Context) (map[string][]byte, error) {
	l.mu.Lock()
	box := l.box
	l.mu.Unlock()
	out := map[string][]byte{}
	if box == nil {
		return out, nil
	}
	ring, err := loadKeyring(ctx, l.db, box.Key())
	if err != nil {
		l.log.Warn("audit keyring unreadable", "err", err)
	}
	for kid, k := range ring {
		out[kid] = k
	}
	cur := box.SubKey(chainPurpose)
	out[keyID(cur)] = cur
	return out, nil
}

// ---- listing ----

// Query filters the log, newest first.
type Query struct {
	Limit  int
	Cursor string // seq of the last item of the previous page
	Q      string
	Action string // prefix
}

// List returns a page of entries and the cursor for the next page.
func (l *Log) List(ctx context.Context, q Query) ([]Entry, string, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	where := []string{"1=1"}
	var args []any
	if q.Cursor != "" {
		seq, err := strconv.ParseInt(q.Cursor, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("bad cursor")
		}
		where = append(where, "seq < ?")
		args = append(args, seq)
	}
	if q.Action != "" {
		where = append(where, "action LIKE ? ESCAPE '\\'")
		args = append(args, escapeLike(q.Action)+"%")
	}
	if q.Q != "" {
		where = append(where, "(actor LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
		p := "%" + escapeLike(q.Q) + "%"
		args = append(args, p, p, p, p)
	}
	args = append(args, q.Limit+1)
	rows, err := l.db.QueryContext(ctx, `SELECT seq, id, ts, node_id, actor, ip, action, target, result, details
		FROM audit_log WHERE `+strings.Join(where, " AND ")+` ORDER BY seq DESC LIMIT ?`, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []Entry
	var seqs []int64
	for rows.Next() {
		var seq int64
		var e Entry
		var ts int64
		var details string
		if err := rows.Scan(&seq, &e.ID, &ts, &e.NodeID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Result, &details); err != nil {
			return nil, "", err
		}
		e.TS = time.UnixMilli(ts)
		_ = json.Unmarshal([]byte(details), &e.Details)
		out = append(out, e)
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > q.Limit {
		out = out[:q.Limit]
		next = strconv.FormatInt(seqs[q.Limit-1], 10)
	}
	return out, next, nil
}

// ---- verification ----

// row is what the chain walk needs of an entry.
type row struct {
	seq        int64
	id         string
	ts         int64
	prev, hash string
	st         status
}

type status int

const (
	stBad     status = iota // hash does not match the content
	stV1                    // valid unkeyed hash
	stV2                    // valid HMAC
	stUnknown               // HMAC with a key this node does not have
)

// walk follows a node chain from start (the anchor hash, "" at first) by
// the prev_hash links: the order does not depend on the local numbering
// (entries of the other node may arrive out of order). Rows not reached
// are returned as orphans.
func walk(rows []row, start string) (chain, orphans []int) {
	next := make(map[string][]int, len(rows))
	for i, r := range rows {
		next[r.prev] = append(next[r.prev], i)
	}
	on := make([]bool, len(rows))
	cur := start
	for {
		i := -1
		for _, j := range next[cur] {
			if !on[j] {
				i = j
				break
			}
		}
		if i < 0 {
			break
		}
		on[i] = true
		chain = append(chain, i)
		cur = rows[i].hash
	}
	for i := range rows {
		if !on[i] {
			orphans = append(orphans, i)
		}
	}
	return chain, orphans
}

// Head is the last entry of a node chain.
type Head struct {
	ID   string
	Hash string
}

// Report is the result of a verification.
type Report struct {
	Checked int
	// Unverified counts entries of another node signed with a key this node
	// never had (written by that node before it joined the cluster). Their
	// links are checked, not their content.
	Unverified int
	BrokenID   string // first entry (local order) that breaks the chain
	Reason     string
	Heads      map[string]Head // node id -> chain head
}

// Verify walks the whole log and returns the id of the first broken entry.
func (l *Log) Verify(ctx context.Context) (brokenID string, err error) {
	r, err := l.VerifyReport(ctx)
	return r.BrokenID, err
}

// VerifyReport checks every entry and every chain link, and writes the
// head of each chain to the application log: an outside copy of the
// heads reveals entries deleted at the end of the log.
func (l *Log) VerifyReport(ctx context.Context) (Report, error) {
	rep := Report{Heads: map[string]Head{}}
	keys, err := l.keys(ctx)
	if err != nil {
		return rep, err
	}
	rs, err := l.db.QueryContext(ctx, `SELECT seq, id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash
		FROM audit_log ORDER BY seq`)
	if err != nil {
		return rep, err
	}
	byNode := map[string][]row{}
	for rs.Next() {
		var e Entry
		var r row
		var details string
		if err := rs.Scan(&r.seq, &e.ID, &r.ts, &e.NodeID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Result, &details, &r.prev, &r.hash); err != nil {
			rs.Close()
			return rep, err
		}
		e.TS = time.UnixMilli(r.ts)
		r.id = e.ID
		switch v, kid := parseHash(r.hash); v {
		case 1:
			if chainHash(nil, r.prev, e, details) == r.hash {
				r.st = stV1
			}
		case 2:
			if k, ok := keys[kid]; !ok {
				r.st = stUnknown
			} else if hmac.Equal([]byte(chainHash(k, r.prev, e, details)), []byte(r.hash)) {
				r.st = stV2
			}
		}
		byNode[e.NodeID] = append(byNode[e.NodeID], r)
		rep.Checked++
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return rep, err
	}
	brokenSeq := int64(-1)
	broken := func(r row, reason string) {
		if brokenSeq < 0 || r.seq < brokenSeq {
			brokenSeq, rep.BrokenID, rep.Reason = r.seq, r.id, reason
		}
	}
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		rows := byNode[node]
		a, err := readAnchor(ctx, l.db, node)
		if err != nil {
			return rep, err
		}
		chain, orphans := walk(rows, a.Hash)
		keyed := false
		for _, i := range chain {
			r := rows[i]
			switch r.st {
			case stBad:
				broken(r, "contenu modifié")
			case stV1:
				if keyed {
					broken(r, "entrée non signée après des entrées signées")
				}
			case stV2:
				keyed = true
			case stUnknown:
				// This node's own entries are always signed with a key it has.
				if node == l.nodeID || keyed {
					broken(r, "signée avec une clé inconnue")
				} else {
					rep.Unverified++
				}
			}
		}
		for _, i := range orphans {
			if r := rows[i]; r.ts > a.MaxTS {
				broken(r, "chaîne interrompue (entrée supprimée ou insérée)")
			}
		}
		if len(chain) > 0 {
			h := rows[chain[len(chain)-1]]
			rep.Heads[node] = Head{ID: h.id, Hash: h.hash}
		}
	}
	for _, node := range nodes {
		if h, ok := rep.Heads[node]; ok {
			l.log.Info("audit chain head", "node", node, "id", h.ID, "hash", h.Hash)
		}
	}
	if rep.BrokenID != "" {
		l.log.Error("audit chain broken", "id", rep.BrokenID, "reason", rep.Reason)
	}
	return rep, nil
}

// logHeads writes the newest entry of each node to the application log
// (cheap anchor between two full verifications).
func (l *Log) logHeads(ctx context.Context) {
	rows, err := l.db.QueryContext(ctx, `SELECT node_id, id, hash, MAX(seq) FROM audit_log GROUP BY node_id ORDER BY node_id`)
	if err != nil {
		l.log.Warn("audit chain head", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var node, id, h string
		var seq int64
		if rows.Scan(&node, &id, &h, &seq) == nil {
			l.log.Info("audit chain head", "node", node, "id", id, "hash", h)
		}
	}
}

// ---- retention ----

// Purge deletes the entries older than retention, in chain order. For each
// node, the last purged entry becomes the anchor of the remaining chain.
// Deletions are local: the other node purges its own copy (deletes of
// audit_log are not replicated, the numbering differs between nodes).
func (l *Log) Purge(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.Now().Add(-retention).UnixMilli()
	rs, err := l.db.QueryContext(ctx, `SELECT DISTINCT node_id FROM audit_log`)
	if err != nil {
		return 0, err
	}
	var nodes []string
	for rs.Next() {
		var n string
		if err := rs.Scan(&n); err != nil {
			rs.Close()
			return 0, err
		}
		nodes = append(nodes, n)
	}
	rs.Close()
	total := 0
	for _, node := range nodes {
		n, err := l.purgeNode(ctx, node, cutoff)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (l *Log) purgeNode(ctx context.Context, node string, cutoff int64) (int, error) {
	var n int
	err := l.db.Tx(ctx, func(tx *sql.Tx) error {
		a, err := readAnchor(ctx, tx, node)
		if err != nil {
			return err
		}
		rs, err := tx.QueryContext(ctx, `SELECT seq, id, ts, prev_hash, hash FROM audit_log WHERE node_id = ? ORDER BY seq`, node)
		if err != nil {
			return err
		}
		var rows []row
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.seq, &r.id, &r.ts, &r.prev, &r.hash); err != nil {
				rs.Close()
				return err
			}
			rows = append(rows, r)
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return err
		}
		chain, orphans := walk(rows, a.Hash)
		na := a
		var del []int64
		for _, i := range chain {
			r := rows[i]
			if r.ts >= cutoff {
				break
			}
			del = append(del, r.seq)
			na.ID, na.Hash, na.TS = r.id, r.hash, r.ts
			na.MaxTS = max(na.MaxTS, r.ts)
		}
		// Old entries off the chain: copies of purged entries sent back by
		// the other node, or the remains of a chain broken long ago.
		for _, i := range orphans {
			if r := rows[i]; r.ts < cutoff || r.ts <= na.MaxTS {
				del = append(del, r.seq)
				na.MaxTS = max(na.MaxTS, r.ts)
			}
		}
		if len(del) == 0 {
			return nil
		}
		// Not replicated: the other node numbers its entries differently.
		if _, err := tx.ExecContext(ctx, `UPDATE repl_state SET applying = 1 WHERE id = 1`); err != nil {
			return err
		}
		for len(del) > 0 {
			chunk := del[:min(len(del), 500)]
			del = del[len(chunk):]
			args := make([]any, len(chunk))
			for i, s := range chunk {
				args[i] = s
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE seq IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
			if err != nil {
				return err
			}
			c, _ := res.RowsAffected()
			n += int(c)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE repl_state SET applying = 0 WHERE id = 1`); err != nil {
			return err
		}
		return writeAnchor(ctx, tx, node, na)
	})
	return n, err
}

// Maintain is the periodic work (hourly): purge the entries older than
// retentionDays (0 keeps everything), write the chain heads to the
// application log, and verify the whole log once a day.
func (l *Log) Maintain(ctx context.Context, retentionDays int) {
	if retentionDays > 0 {
		if n, err := l.Purge(ctx, time.Duration(retentionDays)*24*time.Hour); err != nil {
			l.log.Warn("audit purge", "err", err)
		} else if n > 0 {
			l.log.Info("audit entries purged", "count", n, "retentionDays", retentionDays)
		}
	}
	l.maintMu.Lock()
	due := l.Now().Sub(l.lastVerify) >= verifyEvery
	if due {
		l.lastVerify = l.Now()
	}
	l.maintMu.Unlock()
	if !due {
		l.logHeads(ctx)
		return
	}
	if _, err := l.VerifyReport(ctx); err != nil {
		l.log.Warn("audit verification", "err", err)
	}
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
