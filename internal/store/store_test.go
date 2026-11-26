package store

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestMigrateUpDownWithBackup(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx, filepath.Join(dir, "backups"), log); err != nil {
		t.Fatal(err)
	}
	v, _ := db.SchemaVersion(ctx)
	if v != LatestSchema() {
		t.Fatalf("schema %d, want %d", v, LatestSchema())
	}
	// Idempotent.
	if err := db.Migrate(ctx, filepath.Join(dir, "backups"), log); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateDown(ctx, 0, filepath.Join(dir, "backups"), log); err != nil {
		t.Fatal(err)
	}
	if v, _ := db.SchemaVersion(ctx); v != 0 {
		t.Fatalf("after down: %d", v)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "backups", "leazone-*.db"))
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	// The backup still holds the data.
	b, err := Open(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if got, _ := b.Meta(ctx, "k"); got != "v" {
		t.Fatalf("backup content = %q", got)
	}
	// And up again works.
	if err := db.Migrate(ctx, filepath.Join(dir, "backups"), log); err != nil {
		t.Fatal(err)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	db, _ := Open(filepath.Join(dir, "t.db"))
	defer db.Close()
	_ = db.Migrate(ctx, dir, log)
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations VALUES (999, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, dir, log); err == nil {
		t.Fatal("a database from a newer version must be refused")
	}
}
