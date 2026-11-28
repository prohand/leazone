package backup

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

const testPassword = "un mot de passe de sauvegarde"

func newService(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "leazone.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	rs, err := repl.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	return &Service{DB: db, Repl: rs, Box: box, Node: "test", Time: 1, MemoryKiB: 64, WrapDEK: func([]byte) string { return "x" }}
}

func addUser(t *testing.T, s *Service, id, role, hash string, changedAt int64, disabled int) {
	t.Helper()
	if _, err := s.DB.Exec(`INSERT INTO users(id, username, role, password_hash, webauthn_handle, disabled, created_at, updated_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)`, id, id, role, hash, []byte("h-"+id), disabled, changedAt); err != nil {
		t.Fatal(err)
	}
}

func addToken(t *testing.T, s *Service, id, user string) {
	t.Helper()
	if _, err := s.DB.Exec(`INSERT INTO api_tokens(id, user_id, name, prefix, secret_hash, scope, created_at) VALUES (?, ?, 'n', ?, 'h', 'write', 1)`,
		id, user, "p-"+id); err != nil {
		t.Fatal(err)
	}
}

type userRow struct {
	role, hash string
	changedAt  int64
	disabled   int
}

func getUser(t *testing.T, s *Service, id string) (userRow, bool) {
	t.Helper()
	var u userRow
	err := s.DB.QueryRow(`SELECT role, password_hash, password_changed_at, disabled FROM users WHERE id = ?`, id).Scan(&u.role, &u.hash, &u.changedAt, &u.disabled)
	return u, err == nil
}

func activeTokens(t *testing.T, s *Service, user string) int {
	t.Helper()
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL`, user).Scan(&n)
	return n
}

// A restore must not give back access removed since the backup: a deleted
// account comes back disabled and without API tokens; a newer password, a
// disabled flag and a lower role set here since the backup are kept.
func TestRestoreKeepsRemovedAccessRemoved(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	addUser(t, s, "admin", "admin", "old-admin-hash", 100, 0)
	addUser(t, s, "gone", "admin", "gone-hash", 100, 0)
	addUser(t, s, "bob", "admin", "old-bob-hash", 100, 0)
	addUser(t, s, "eve", "operator", "eve-hash", 100, 0)
	addToken(t, s, "tk-gone", "gone")
	addToken(t, s, "tk-admin", "admin")
	file, err := s.Create(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	// Since the backup: "gone" deleted, bob demoted and new password, eve
	// disabled, admin unchanged.
	if _, err := s.DB.Exec(`DELETE FROM users WHERE id = 'gone'`); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(`UPDATE users SET role = 'readonly', password_hash = 'new-bob-hash', password_changed_at = 200 WHERE id = 'bob'`)
	s.DB.Exec(`UPDATE users SET disabled = 1 WHERE id = 'eve'`)

	dry, err := s.Restore(ctx, file, testPassword, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Users) != 3 {
		t.Fatalf("dry run report: %+v", dry.Users)
	}
	if u, _ := getUser(t, s, "bob"); u.role != "readonly" {
		t.Fatal("dry run changed the database")
	}
	res, err := s.Restore(ctx, file, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := getUser(t, s, "gone"); !ok || g.disabled != 1 {
		t.Fatalf("deleted account restored enabled: %+v %v", g, ok)
	}
	if activeTokens(t, s, "gone") != 0 {
		t.Fatal("API token of a deleted account restored")
	}
	if b, _ := getUser(t, s, "bob"); b.role != "readonly" || b.hash != "new-bob-hash" || b.changedAt != 200 {
		t.Fatalf("bob: %+v", b)
	}
	if e, _ := getUser(t, s, "eve"); e.disabled != 1 {
		t.Fatal("account disabled since the backup enabled again")
	}
	if a, _ := getUser(t, s, "admin"); a.disabled != 0 || a.hash != "old-admin-hash" || activeTokens(t, s, "admin") != 1 {
		t.Fatalf("unchanged admin: %+v", a)
	}
	want := map[string]string{"gone": "disabled", "bob": "password,role", "eve": "disabled"}
	for _, u := range res.Users {
		got := ""
		if u.Disabled {
			got = "disabled"
		} else {
			for i, k := range u.Kept {
				if i > 0 {
					got += ","
				}
				got += k
			}
		}
		if want[u.ID] != got {
			t.Errorf("report for %s: %q, want %q", u.ID, got, want[u.ID])
		}
		delete(want, u.ID)
	}
	if len(want) > 0 || res.Summary() == "" {
		t.Fatalf("missing from the report: %v (%q)", want, res.Summary())
	}
}

// A backup of another installation (no shared account, e.g. a new install)
// is restored as is: that is the disaster recovery case.
func TestRestoreOnNewInstallKeepsBackupAccounts(t *testing.T) {
	ctx := context.Background()
	src := newService(t)
	addUser(t, src, "admin", "admin", "hash", 100, 0)
	addUser(t, src, "ops", "operator", "hash", 100, 0)
	addToken(t, src, "tk", "ops")
	file, err := src.Create(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	dst := newService(t)
	dst.Box = src.Box // same data key: only the accounts matter here
	addUser(t, dst, "fresh-admin", "admin", "hash", 500, 0)
	res, err := dst.Restore(ctx, file, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 0 {
		t.Fatalf("new install: %+v", res.Users)
	}
	if u, ok := getUser(t, dst, "ops"); !ok || u.disabled != 0 || activeTokens(t, dst, "ops") != 1 {
		t.Fatalf("ops: %+v %v", u, ok)
	}
	if _, ok := getUser(t, dst, "fresh-admin"); ok {
		t.Fatal("the account of the new install was kept")
	}
}

// Merging may leave no active admin (all disabled here since): refused.
func TestRestoreMergedNeedsAnAdmin(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	addUser(t, s, "admin", "admin", "hash", 100, 0)
	addUser(t, s, "ops", "operator", "hash", 100, 0)
	file, err := s.Create(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(`UPDATE users SET role = 'operator' WHERE id = 'admin'`)
	if _, err := s.Restore(ctx, file, testPassword, true); err != ErrNoAdmin {
		t.Fatalf("restore without an active admin after merge: %v", err)
	}
}
