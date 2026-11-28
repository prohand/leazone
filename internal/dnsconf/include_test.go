package dnsconf

import (
	"os"
	"path/filepath"
	"testing"
)

// The line by line fallback must never read files of the server.
func TestParseOneRRRefusesInclude(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.zone")
	if err := os.WriteFile(f, []byte("leak 300 IN A 192.0.2.66\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr, err := parseOneRR("$INCLUDE "+f, "maison.lan.", 300)
	if err == nil || rr != nil {
		t.Fatalf("$INCLUDE followed: rr=%v err=%v", rr, err)
	}
	rr, err = parseOneRR("www 60 IN A 192.0.2.1", "maison.lan.", 300)
	if err != nil || rr == nil || rr.Header().Name != "www.maison.lan." || rr.Header().Ttl != 60 {
		t.Fatalf("plain record: rr=%v err=%v", rr, err)
	}
	rr, err = parseOneRR("www IN A 192.0.2.1", "maison.lan.", 120)
	if err != nil || rr.Header().Ttl != 120 {
		t.Fatalf("default TTL: rr=%v err=%v", rr, err)
	}
}
