// Package audit writes an append-only, hash-chained audit log. Each entry
// stores the hash of the previous one, so removing or editing a line breaks
// the chain and is detected by Verify.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/store"
)

// Result values.
const (
	Success = "success"
	Failure = "failure"
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
	mu     sync.Mutex // serializes the hash chain
}

// New returns an audit log bound to a node.
func New(db *store.DB, nodeID string, log *slog.Logger) *Log {
	return &Log{db: db, nodeID: nodeID, log: log}
}

// Record appends an entry. Errors are logged, never returned: auditing must
// not break the action being audited, but a failure is visible in the logs.
func (l *Log) Record(ctx context.Context, e Entry) {
	if err := l.record(ctx, e); err != nil {
		l.log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

func (l *Log) record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.ID == "" {
		e.ID = ids.New()
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Result == "" {
		e.Result = Success
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.NodeID = l.nodeID
	details, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	return l.db.Tx(ctx, func(tx *sql.Tx) error {
		var prev string
		err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		h := chainHash(prev, e, string(details))
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID, e.TS.UnixMilli(), e.NodeID, e.Actor, e.IP, e.Action, e.Target, e.Result, string(details), prev, h)
		return err
	})
}

func chainHash(prev string, e Entry, details string) string {
	s := sha256.New()
	for _, f := range []string{prev, e.ID, strconv.FormatInt(e.TS.UnixMilli(), 10), e.NodeID, e.Actor, e.IP,
		e.Action, e.Target, e.Result, details} {
		fmt.Fprintf(s, "%d:%s|", len(f), f)
	}
	return hex.EncodeToString(s.Sum(nil))
}

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

// Verify walks the whole chain and returns the id of the first broken entry.
func (l *Log) Verify(ctx context.Context) (brokenID string, err error) {
	rows, err := l.db.QueryContext(ctx, `SELECT id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash
		FROM audit_log ORDER BY seq`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e Entry
		var ts int64
		var details, prevHash, h string
		if err := rows.Scan(&e.ID, &ts, &e.NodeID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Result, &details, &prevHash, &h); err != nil {
			return "", err
		}
		e.TS = time.UnixMilli(ts)
		if prevHash != prev || chainHash(prev, e, details) != h {
			return e.ID, nil
		}
		prev = h
	}
	return "", rows.Err()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
