package repl

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/prohand/leazone/internal/store"
)

func node(t *testing.T) (*store.DB, *Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background(), t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return db, s
}

func exec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func sameConfig(t *testing.T, a, b *Store) {
	t.Helper()
	ctx := context.Background()
	ha, ta, _ := a.Hashes(ctx)
	hb, tb, _ := b.Hashes(ctx)
	if ta != tb {
		for k := range ha {
			if ha[k] != hb[k] {
				t.Errorf("table %s differs", k)
			}
		}
		t.Fatal("configs differ")
	}
}

// seed writes a few config rows on db (as the primary would through the API).
func seed(t *testing.T, db *store.DB) {
	exec(t, db, `INSERT INTO users(id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at, password_changed_at)
		VALUES ('u1', 'admin', 'admin', 'h', X'00FF10', 0, 1, 1, 1)`)
	exec(t, db, `INSERT INTO zones(id, name, kind, ttl, soa_primary_ns, soa_admin_email, soa_refresh, soa_retry, soa_expire, soa_minimum, serial, created_at, updated_at)
		VALUES ('z1', 'maison.lan', 'primary', 3600, 'ns.maison.lan.', 'a@maison.lan', 1, 1, 1, 1, 1, 1, 1)`)
	exec(t, db, `INSERT INTO records(id, zone_id, name, type, data, created_at, updated_at) VALUES ('r1', 'z1', 'nas', 'A', '{"ip":"10.0.0.1"}', 1, 1)`)
	exec(t, db, `INSERT INTO records(id, zone_id, name, type, data, source, dhcp_owner, created_at, updated_at) VALUES ('r2', 'z1', 'pc', 'A', '{"ip":"10.0.0.2"}', 'dhcp', 'x', 1, 1)`)
	exec(t, db, `INSERT INTO settings(key, value, updated_at) VALUES ('dns', '{"cacheSize":100}', 1)`)
}

func TestIncrementalReplication(t *testing.T) {
	ctx := context.Background()
	adb, a := node(t)
	bdb, b := node(t)
	if err := b.SetRecording(ctx, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.BeginEpoch(ctx, 1, "A", "node1", "bootstrap"); err != nil {
		t.Fatal(err)
	}
	seed(t, adb)
	ch, _ := a.ChangesAfter(ctx, 0, 1000)
	for _, c := range ch {
		if c.Table == "records" && c.PK == "r2" {
			t.Fatal("DHCP record journaled as config")
		}
	}
	if err := b.Apply(ctx, ch); err != nil {
		t.Fatal(err)
	}
	sameConfig(t, a, b)
	// The blob column survived the round trip.
	var h []byte
	bdb.QueryRow(`SELECT webauthn_handle FROM users WHERE id = 'u1'`).Scan(&h)
	if len(h) != 3 || h[1] != 0xFF {
		t.Fatalf("blob: %x", h)
	}
	ea, sa, _ := a.Position(ctx)
	eb, sb, _ := b.Position(ctx)
	if ea != eb || sa != sb || ea != 1 {
		t.Fatalf("positions %d/%d vs %d/%d", ea, sa, eb, sb)
	}
	// Update + cascaded delete.
	exec(t, adb, `UPDATE settings SET value = '{"cacheSize":200}' WHERE key = 'dns'`)
	exec(t, adb, `DELETE FROM zones WHERE id = 'z1'`)
	ch, _ = a.ChangesAfter(ctx, sb, 1000)
	if err := b.Apply(ctx, ch); err != nil {
		t.Fatal(err)
	}
	sameConfig(t, a, b)
	var n int
	bdb.QueryRow(`SELECT COUNT(*) FROM records WHERE source = 'manual'`).Scan(&n)
	if n != 0 {
		t.Fatal("cascaded delete not replicated")
	}
	// Local writes on a follower are not journaled.
	exec(t, bdb, `INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES ('v1', 20, 'x', 1, 1)`)
	_, saNow, _ := a.Position(ctx)
	if _, sb2, _ := b.Position(ctx); sb2 != saNow {
		t.Fatalf("follower journaled a local write: %d", sb2)
	}
}

func TestSnapshotAndDivergence(t *testing.T) {
	ctx := context.Background()
	adb, a := node(t)
	bdb, b := node(t)
	a.BeginEpoch(ctx, 1, "A", "node1", "bootstrap")
	seed(t, adb)
	// B joins with a snapshot.
	snap, err := a.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.SetRecording(ctx, false, 0)
	if err := b.ApplySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	sameConfig(t, a, b)
	_, sa, _ := a.Position(ctx)
	if _, sb, _ := b.Position(ctx); sb != sa {
		t.Fatalf("snapshot position %d, want %d", sb, sa)
	}
	if !b.Has(ctx, sa, 1) {
		t.Fatal("snapshot base not recognised")
	}

	// A writes one change that never reaches B, then dies; B becomes primary (epoch 2).
	exec(t, adb, `INSERT INTO forwarders(id, domain, position, protocol, address, port, created_at, updated_at) VALUES ('f-lost', '', 0, 'udp', '1.1.1.1', 53, 1, 1)`)
	if err := b.BeginEpoch(ctx, 2, "B", "node2", "failover"); err != nil {
		t.Fatal(err)
	}
	exec(t, bdb, `INSERT INTO forwarders(id, domain, position, protocol, address, port, created_at, updated_at) VALUES ('f-new', '', 0, 'udp', '9.9.9.9', 53, 1, 1)`)
	// A comes back: its last entry is not on B -> conflicts + snapshot.
	ea, saLast, _ := a.Position(ctx)
	if b.Has(ctx, saLast, ea) {
		t.Fatal("divergent entry reported as known")
	}
	ep, _ := b.Epochs(ctx)
	start := ep[0].StartSeq // first seq of epoch 2 on B
	if n, err := a.SaveConflicts(ctx, ea, start); err != nil || n != 1 {
		t.Fatalf("conflicts: %d %v", n, err)
	}
	snap2, _ := b.Snapshot(ctx)
	a.SetRecording(ctx, false, 0)
	if err := a.ApplySnapshot(ctx, snap2); err != nil {
		t.Fatal(err)
	}
	sameConfig(t, a, b)
	cs, _ := a.Conflicts(ctx)
	if len(cs) != 1 || cs[0].PK != "f-lost" {
		t.Fatalf("conflicts: %+v", cs)
	}
}

func TestStateMerge(t *testing.T) {
	ctx := context.Background()
	adb, a := node(t)
	bdb, b := node(t)
	for _, db := range []*store.DB{adb, bdb} {
		exec(t, db, `INSERT INTO users(id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at, password_changed_at)
			VALUES ('u1', 'admin', 'admin', 'h', X'01', 0, 1, 1, 1)`)
	}
	b.ClearOutbox(ctx)
	a.ClearOutbox(ctx)
	exec(t, adb, `INSERT INTO sessions(id_hash, public_id, user_id, auth_level, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent)
		VALUES ('s1', 'p1', 'u1', 'full', 'c', 1, 500, 9999, '1.2.3.4', 'ua')`)
	exec(t, adb, `INSERT INTO totp_usage(user_id, last_counter) VALUES ('u1', 42)`)
	exec(t, bdb, `INSERT INTO totp_usage(user_id, last_counter) VALUES ('u1', 50)`)
	_, rows, _ := a.Outbox(ctx, 100)
	if len(rows) != 2 {
		t.Fatalf("outbox: %+v", rows)
	}
	if err := b.ApplyState(ctx, rows); err != nil {
		t.Fatal(err)
	}
	var seen, counter int64
	bdb.QueryRow(`SELECT last_seen_at FROM sessions WHERE id_hash = 's1'`).Scan(&seen)
	bdb.QueryRow(`SELECT last_counter FROM totp_usage WHERE user_id = 'u1'`).Scan(&counter)
	if seen != 500 || counter != 50 {
		t.Fatalf("merge: seen=%d counter=%d (TOTP counter must keep the max: anti-replay)", seen, counter)
	}
	// Applied rows are not echoed back.
	if _, rows, _ := b.Outbox(ctx, 100); len(rows) != 1 { // only B's own totp insert
		t.Fatalf("echo: %+v", rows)
	}
}

// Downgrading the schema must not leave replication triggers that name
// dropped tables or columns (every later write would fail).
func TestMigrateDownWithTriggers(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, _ := node(t) // migrated, triggers installed
	seed(t, db)
	if err := db.MigrateDown(ctx, 3, t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	exec(t, db, `INSERT INTO users(id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at, password_changed_at, last_login_at)
		VALUES ('u2', 'bob', 'admin', 'h', X'02', 0, 1, 1, 1, 5)`)
	exec(t, db, `UPDATE records SET name = 'nas2' WHERE id = 'r1'`)
	if err := db.MigrateDown(ctx, 0, t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, db); err != nil {
		t.Fatal(err)
	}
}
