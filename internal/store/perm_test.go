package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The database, its WAL and shared-memory files and the backup copies are
// private from their creation, whatever the umask.
func TestFilesPrivateFromCreation(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "leazone.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t(x)`); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if m := perm(t, p); m != 0o600 {
			t.Errorf("%s: %o", filepath.Base(p), m)
		}
	}
	bdir := filepath.Join(dir, "backups")
	dst, err := db.Backup(ctx, bdir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if m := perm(t, bdir); m != 0o700 {
		t.Errorf("backup directory: %o", m)
	}
	if m := perm(t, dst); m != 0o600 {
		t.Errorf("backup: %o", m)
	}
}
