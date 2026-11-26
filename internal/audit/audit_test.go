package audit

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/prohand/leazone/internal/store"
)

func TestChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, _ := store.Open(filepath.Join(t.TempDir(), "a.db"))
	defer db.Close()
	if err := db.Migrate(ctx, t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	l := New(db, "n1", log)
	for _, a := range []string{"auth.login.success", "user.create", "auth.login.failure"} {
		l.Record(ctx, Entry{Actor: "admin", IP: "10.0.0.1", Action: a, Target: "bob"})
	}
	if id, err := l.Verify(ctx); err != nil || id != "" {
		t.Fatalf("intact chain reported broken: %q %v", id, err)
	}
	items, next, _ := l.List(ctx, Query{Limit: 2})
	if len(items) != 2 || next == "" || items[0].Action != "auth.login.failure" {
		t.Fatalf("page 1: %+v next=%q", items, next)
	}
	items, next, _ = l.List(ctx, Query{Limit: 2, Cursor: next})
	if len(items) != 1 || next != "" {
		t.Fatalf("page 2: %+v next=%q", items, next)
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_log SET actor = 'someone' WHERE action = 'user.create'`); err != nil {
		t.Fatal(err)
	}
	if id, _ := l.Verify(ctx); id == "" {
		t.Fatal("tampering not detected")
	}
}
