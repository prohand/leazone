package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	return db
}

func keyedLog(t *testing.T, db *store.DB, node string, box *secrets.Box) (*Log, *bytes.Buffer) {
	var buf bytes.Buffer
	l := New(db, node, slog.New(slog.NewTextHandler(&buf, nil)))
	if box != nil {
		l.SetKey(box)
	}
	return l, &buf
}

func mustVerify(t *testing.T, l *Log) Report {
	t.Helper()
	r, err := l.VerifyReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.BrokenID != "" {
		t.Fatalf("chain reported broken at %s: %s", r.BrokenID, r.Reason)
	}
	return r
}

func mustBreak(t *testing.T, l *Log) {
	t.Helper()
	if id, err := l.Verify(context.Background()); err != nil || id == "" {
		t.Fatalf("tampering not detected (%v)", err)
	}
}

// A keyed entry cannot be rewritten without the key: recomputing a plain
// SHA-256 or an HMAC with another key is detected.
func TestKeyedChainNeedsTheKey(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	box, _ := secrets.NewBox(secrets.NewDEK())
	l, logs := keyedLog(t, db, "n1", box)
	for _, a := range []string{"auth.login.success", "user.create", "auth.login.failure"} {
		l.Record(ctx, Entry{Actor: "admin", Action: a, Target: "bob"})
	}
	var h string
	_ = db.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE action = 'user.create'`).Scan(&h)
	if !strings.HasPrefix(h, "v2:") {
		t.Fatalf("entry not keyed: %q", h)
	}
	r := mustVerify(t, l)
	if !strings.Contains(logs.String(), "audit chain head") || r.Heads["n1"].Hash == "" {
		t.Fatal("chain head not written to the application log")
	}

	// Rewrite the middle entry and give it a hash an attacker can compute.
	rewrite := func(key []byte) {
		var e Entry
		var ts int64
		var details, prev string
		_ = db.QueryRowContext(ctx, `SELECT id, ts, node_id, ip, action, target, result, details, prev_hash FROM audit_log WHERE action = 'user.create'`).
			Scan(&e.ID, &ts, &e.NodeID, &e.IP, &e.Action, &e.Target, &e.Result, &details, &prev)
		e.TS, e.Actor = time.UnixMilli(ts), "someone"
		if _, err := db.ExecContext(ctx, `UPDATE audit_log SET actor = ?, hash = ? WHERE id = ?`, e.Actor, chainHash(key, prev, e, details), e.ID); err != nil {
			t.Fatal(err)
		}
		// Re-link the next entry so only the signature can tell.
		var newHash string
		_ = db.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE id = ?`, e.ID).Scan(&newHash)
		_, _ = db.ExecContext(ctx, `UPDATE audit_log SET prev_hash = ? WHERE action = 'auth.login.failure'`, newHash)
	}
	rewrite(nil) // plain SHA-256 (version 1) after keyed entries
	mustBreak(t, l)
	rewrite(secrets.NewDEK()) // HMAC with a key this node does not have
	mustBreak(t, l)
}

// Entries written before the upgrade (version 1) and after (version 2)
// verify together.
func TestChainUpgradeFromUnkeyed(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	old, _ := keyedLog(t, db, "n1", nil)
	old.Record(ctx, Entry{Actor: "admin", Action: "user.create"})
	old.Record(ctx, Entry{Actor: "admin", Action: "user.update"})
	box, _ := secrets.NewBox(secrets.NewDEK())
	l, _ := keyedLog(t, db, "n1", box)
	l.Record(ctx, Entry{Actor: "admin", Action: "user.delete"})
	mustVerify(t, l)
	if _, err := db.ExecContext(ctx, `UPDATE audit_log SET target = 'x' WHERE action = 'user.update'`); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, l)
}

// A new data key (cluster join, restore) keeps the older entries verifiable
// through the keyring.
func TestChainSurvivesKeyChange(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	box, _ := secrets.NewBox(secrets.NewDEK())
	l, _ := keyedLog(t, db, "n1", box)
	l.Record(ctx, Entry{Action: "a"})
	if err := box.Replace(secrets.NewDEK()); err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, Entry{Action: "b"})
	swap := box.BeginReplace()
	if err := swap(secrets.NewDEK()); err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, Entry{Action: "c"})
	mustVerify(t, l)
	// Without the keyring, the node's own older entries are refused.
	if _, err := db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, keyringMeta); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, l)
}

// Entries of the other node signed with a key this node never had are
// accepted (links only) at the start of that node's chain, never after
// entries it could verify.
func TestChainOtherNodeUnknownKey(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	shared, _ := secrets.NewBox(secrets.NewDEK())
	own, _ := secrets.NewBox(secrets.NewDEK())
	n2, _ := keyedLog(t, db, "n2", own) // n2 before it joined
	n2.Record(ctx, Entry{Action: "a"})
	n2.Record(ctx, Entry{Action: "b"})
	l, _ := keyedLog(t, db, "n1", shared)
	l.Record(ctx, Entry{Action: "c"})
	r := mustVerify(t, l)
	if r.Unverified != 2 {
		t.Fatalf("unverified = %d, want 2", r.Unverified)
	}
	// n2 joins: it adopts the shared key.
	n2.box = shared
	n2.Record(ctx, Entry{Action: "d"})
	mustVerify(t, l)
	n2.box = own
	n2.Record(ctx, Entry{Action: "e"}) // unknown key after a verified entry
	mustBreak(t, l)
}

// The chain is followed by its links, not by the local numbering: entries
// of the other node may arrive out of order.
func TestChainOutOfOrderReplication(t *testing.T) {
	ctx := context.Background()
	src := testDB(t)
	box, _ := secrets.NewBox(secrets.NewDEK())
	n2, _ := keyedLog(t, src, "n2", box)
	for _, a := range []string{"a", "b", "c", "d"} {
		n2.Record(ctx, Entry{Action: a})
	}
	dst := testDB(t)
	// Copy in the order d, b, a, c.
	for _, a := range []string{"d", "b", "a", "c"} {
		var r []any
		if err := src.QueryRowContext(ctx, `SELECT id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash
			FROM audit_log WHERE action = ?`, a).Scan(scanAll(&r, 11)...); err != nil {
			t.Fatal(err)
		}
		if _, err := dst.ExecContext(ctx, `INSERT INTO audit_log(id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r...); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := keyedLog(t, dst, "n1", box)
	mustVerify(t, l)
}

// The purge keeps the chain verifiable (the last purged hash is the new
// start), is not replicated, and copies of purged entries sent back by the
// other node do not break anything.
func TestPurgeKeepsChainVerifiable(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	rs, err := repl.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	_ = rs
	box, _ := secrets.NewBox(secrets.NewDEK())
	l, _ := keyedLog(t, db, "n1", box)
	now := time.Now()
	for i := 0; i < 5; i++ {
		l.Record(ctx, Entry{Action: "old", TS: now.Add(-400*24*time.Hour + time.Duration(i)*time.Minute)})
	}
	for i := 0; i < 3; i++ {
		l.Record(ctx, Entry{Action: "recent", TS: now.Add(-time.Duration(3-i) * time.Hour)})
	}
	var stale []any
	_ = db.QueryRowContext(ctx, `SELECT id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash
		FROM audit_log WHERE action = 'old' ORDER BY seq LIMIT 1`).Scan(scanAll(&stale, 11)...)
	if _, err := db.ExecContext(ctx, `DELETE FROM state_outbox`); err != nil {
		t.Fatal(err)
	}
	n, err := l.Purge(ctx, 365*24*time.Hour)
	if err != nil || n != 5 {
		t.Fatalf("purged %d (%v), want 5", n, err)
	}
	var outbox int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM state_outbox WHERE tbl = 'audit_log' AND op = 'delete'`).Scan(&outbox)
	if outbox != 0 {
		t.Fatalf("purge was sent to the other node (%d deletes)", outbox)
	}
	mustVerify(t, l)
	l.Record(ctx, Entry{Action: "after"})
	mustVerify(t, l)

	// The other node sends back a purged entry: ignored, then purged again.
	if _, err := db.ExecContext(ctx, `INSERT INTO audit_log(id, ts, node_id, actor, ip, action, target, result, details, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, stale...); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, l)
	l.Record(ctx, Entry{Action: "after2"})
	mustVerify(t, l)
	if n, _ := l.Purge(ctx, 365*24*time.Hour); n != 1 {
		t.Fatalf("stale copy not purged (%d)", n)
	}
	mustVerify(t, l)

	// Removing an entry in the middle is still detected.
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE action = 'after'`); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, l)
}

func scanAll(dst *[]any, n int) []any {
	*dst = make([]any, n)
	ptrs := make([]any, n)
	for i := range *dst {
		ptrs[i] = &(*dst)[i]
	}
	return ptrs
}

// Fields are bounded: a huge user name sent to the login form cannot fill
// the disk.
func TestRecordTruncatesFields(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	l, _ := keyedLog(t, db, "n1", nil)
	huge := strings.Repeat("é", 1<<19) // 1 MiB
	l.Record(ctx, Entry{Actor: huge, Target: huge, IP: huge, Action: huge,
		Details: map[string]any{"username": huge, "list": []string{huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge, huge}}})
	l.Record(ctx, Entry{Details: map[string]any{"username": huge}})
	var size int
	_ = db.QueryRowContext(ctx, `SELECT MAX(length(actor) + length(target) + length(ip) + length(action) + length(details)) FROM audit_log`).Scan(&size)
	if size > 20<<10 {
		t.Fatalf("entry is %d bytes", size)
	}
	mustVerify(t, l)
}

// Throttled entries: one line per key and window, with the skipped count.
func TestRecordThrottled(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	l, _ := keyedLog(t, db, "n1", nil)
	now := time.Now()
	l.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		l.RecordThrottled(ctx, "ip:1", time.Minute, Entry{Action: "auth.login.failure"})
	}
	l.RecordThrottled(ctx, "ip:2", time.Minute, Entry{Action: "auth.login.failure"})
	now = now.Add(2 * time.Minute)
	l.RecordThrottled(ctx, "ip:1", time.Minute, Entry{Action: "auth.login.failure"})
	items, _, _ := l.List(ctx, Query{})
	if len(items) != 3 {
		t.Fatalf("%d entries, want 3", len(items))
	}
	if items[0].Details["suppressed"] != float64(4) {
		t.Fatalf("suppressed = %v", items[0].Details["suppressed"])
	}
}
