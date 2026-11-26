package dnsconf

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prohand/leazone/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background(), t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	return New(db)
}

func TestReverseZone(t *testing.T) {
	cases := map[string]string{
		"192.168.20.0/24": "20.168.192.in-addr.arpa",
		"10.0.0.0/8":      "10.in-addr.arpa",
		"172.16.0.0/16":   "16.172.in-addr.arpa",
		"2001:db8::/32":   "8.b.d.0.1.0.0.2.ip6.arpa",
	}
	for in, want := range cases {
		got, err := ReverseZone(netip.MustParsePrefix(in))
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := ReverseZone(netip.MustParsePrefix("192.168.1.0/25")); err == nil {
		t.Error("/25 accepted")
	}
}

func TestNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{"@", "@"}, {"", "@"}, {"WWW", "www"}, {"www.maison.lan", "www"}, {"www.maison.lan.", "www"},
		{"maison.lan.", "@"}, {"*.dev", "*.dev"}, {"_sip._tcp", "_sip._tcp"},
	}
	for _, c := range cases {
		got, err := RelativeName(c.in, "maison.lan")
		if err != nil || got != c.want {
			t.Errorf("RelativeName(%q) = %q %v, want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"www.other.lan.", "a..b", "-bad", "dev.*", "é"} {
		if _, err := RelativeName(bad, "maison.lan"); err == nil {
			t.Errorf("RelativeName(%q) accepted", bad)
		}
	}
	if h, _ := HostTarget("mail", "maison.lan"); h != "mail.maison.lan." {
		t.Error(h)
	}
	if h, _ := HostTarget("mail.maison.lan", "maison.lan"); h != "mail.maison.lan." {
		t.Error("no double zone suffix expected, got", h)
	}
	if h, _ := HostTarget("smtp.example.com.", "maison.lan"); h != "smtp.example.com." {
		t.Error(h)
	}
}

func TestRecordsRules(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	z, err := s.CreateZone(ctx, ZoneInput{Name: "Maison.LAN."})
	if err != nil {
		t.Fatal(err)
	}
	if z.Name != "maison.lan" || z.Kind != KindPrimary || z.SOA.PrimaryNS != "ns.maison.lan." {
		t.Fatalf("%+v", z)
	}
	if _, err := s.CreateZone(ctx, ZoneInput{Name: "maison.lan"}); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("duplicate zone: %v", err)
	}
	add := func(name, typ string, d RecordData) error {
		_, err := s.CreateRecord(ctx, z.ID, RecordInput{Name: name, Type: typ, Data: d})
		return err
	}
	if err := add("www", "A", RecordData{IP: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if err := add("www", "A", RecordData{IP: "192.168.1.10"}); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("duplicate record: %v", err)
	}
	if err := add("www", "CNAME", RecordData{Target: "web"}); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("CNAME next to A: %v", err)
	}
	if err := add("@", "CNAME", RecordData{Target: "web"}); err == nil {
		t.Fatal("CNAME at apex accepted")
	}
	if err := add("v6", "A", RecordData{IP: "::1"}); err == nil {
		t.Fatal("IPv6 in A accepted")
	}
	if err := add("@", "MX", RecordData{Preference: 10, Exchange: "mail"}); err != nil {
		t.Fatal(err)
	}
	if err := add("_sip._tcp", "SRV", RecordData{Priority: 10, Weight: 5, Port: 5060, Target: "pbx"}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 300)
	if err := add("@", "TXT", RecordData{Text: long}); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.Records(ctx, z.ID)
	if len(recs) != 4 {
		t.Fatalf("records = %d", len(recs))
	}
	z2, _ := s.Zone(ctx, z.ID)
	if z2.Serial <= z.Serial {
		t.Fatalf("serial not increased: %d -> %d", z.Serial, z2.Serial)
	}

	// Export then import into a new zone gives the same records.
	out, err := s.Export(ctx, z.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mail.maison.lan.") || !strings.Contains(out, "SOA") {
		t.Fatalf("export:\n%s", out)
	}
	if err := s.DeleteZone(ctx, z.ID); err != nil {
		t.Fatal(err)
	}
	z3, _ := s.CreateZone(ctx, ZoneInput{Name: "maison.lan"})
	res, err := s.Import(ctx, z3.ID, out, false)
	if err != nil || res.Imported != 4 || res.Skipped != 1 { // SOA skipped
		t.Fatalf("import: %+v %v", res, err)
	}
}

func TestForwarderValidationAndOrder(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := ValidateForwarder(ForwarderInput{Protocol: "doh", DoHURL: "https://dns.quad9.net/dns-query"}); err == nil {
		t.Fatal("DoH without bootstrap IP accepted")
	}
	f, err := ValidateForwarder(ForwarderInput{Protocol: "doh", DoHURL: "https://1.1.1.1/dns-query"})
	if err != nil || f.Port != 443 || f.Address != "1.1.1.1" {
		t.Fatalf("%+v %v", f, err)
	}
	a, _ := s.CreateForwarder(ctx, ForwarderInput{Protocol: "udp", Address: "192.168.1.1"})
	b, _ := s.CreateForwarder(ctx, ForwarderInput{Protocol: "dot", Address: "9.9.9.9", TLSServerName: "dns.quad9.net"})
	c, _ := s.CreateForwarder(ctx, ForwarderInput{Protocol: "tcp", Address: "10.0.0.53", Domain: "corp.local"})
	if a.Position != 0 || b.Position != 1 || c.Position != 0 || b.Port != 853 {
		t.Fatalf("positions %d %d %d", a.Position, b.Position, c.Position)
	}
	zero := 0
	if _, err := s.UpdateForwarder(ctx, b.ID, ForwarderInput{Protocol: "dot", Address: "9.9.9.9", Position: &zero}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Forwarders(ctx)
	if list[0].ID != b.ID || list[1].ID != a.ID || list[2].Domain != "corp.local" {
		t.Fatalf("order: %v %v %v", list[0].ID, list[1].ID, list[2].Domain)
	}
}
