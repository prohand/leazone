package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/witness"
)

func TestClusterKeyCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"cluster", "gen-key"}, &out, &errOut); code != 0 {
		t.Fatalf("gen-key: %d %s", code, errOut.String())
	}
	key := strings.TrimSpace(out.String())
	if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 32 || pki.WeakKey(key) {
		t.Fatalf("generated key %q", key)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster_key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAZONE_CONFIG_DIR", dir)
	t.Setenv("LEAZONE_CLUSTER_KEY_FILE", path)
	out.Reset()
	if code := run([]string{"cluster", "witness-key"}, &out, &errOut); code != 0 {
		t.Fatalf("witness-key: %d %s", code, errOut.String())
	}
	wk := strings.TrimSpace(out.String())
	// The witness started with this key matches what the nodes derive.
	got, legacy, err := witness.ResolveKey(wk, "")
	if err != nil || legacy || got != wk {
		t.Fatalf("witness key %q: %v", wk, err)
	}
	if strings.Contains(wk, key) {
		t.Fatal("witness key shows the cluster key")
	}
}

func TestRestrictExec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leazone")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := restrictExec(path); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o750 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}
