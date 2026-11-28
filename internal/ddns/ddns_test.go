package ddns

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/store"
)

type countReload struct{ n atomic.Int32 }

func (c *countReload) ReloadSoon() { c.n.Add(1) }

func setup(t *testing.T) (*Updater, *dhcpconf.Scope, *countReload) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx, t.TempDir(), log); err != nil {
		t.Fatal(err)
	}
	dns, dhcp := dnsconf.New(db), dhcpconf.New(db)
	if _, err := dns.EnsureZone(ctx, "lan"); err != nil {
		t.Fatal(err)
	}
	if _, err := dns.EnsureReverseZones(ctx, netip.MustParsePrefix("10.0.10.0/24")); err != nil {
		t.Fatal(err)
	}
	sc, err := dhcp.CreateScope(ctx, dhcpconf.ScopeInput{Name: "s10", Network: "10.0.10.0/24",
		RangeStart: "10.0.10.100", RangeEnd: "10.0.10.149", DDNSDomain: "lan"})
	if err != nil {
		t.Fatal(err)
	}
	rl := &countReload{}
	return &Updater{DNS: dns, DHCP: dhcp, Reload: rl, Log: log}, sc, rl
}

func lease(ip, mac, host string) dhcpsrv.Lease {
	return dhcpsrv.Lease{IP: netip.MustParseAddr(ip), MAC: mac, Hostname: host, State: dhcpsrv.StateBound}
}

// A client cannot register names that other clients look up to find a
// proxy or a tunnel; a reservation made by the admin can.
func TestForbiddenNamesForClients(t *testing.T) {
	u, sc, _ := setup(t)
	ctx := context.Background()
	for i, h := range []string{"wpad", "isatap", "localhost", "WPAD"} {
		l := lease("10.0.10.10"+string(rune('0'+i)), "02:00:00:00:00:0"+string(rune('1'+i)), h)
		if name := u.Bound(ctx, sc, l); name != "" {
			t.Errorf("%s registered as %s", h, name)
		}
	}
	if _, err := u.DHCP.CreateReservation(ctx, dhcpconf.ReservationInput{ScopeID: sc.ID, MAC: "02:00:00:00:00:99",
		IP: "10.0.10.50", Hostname: "wpad"}); err != nil {
		t.Fatal(err)
	}
	if name := u.Bound(ctx, sc, lease("10.0.10.50", "02:00:00:00:00:99", "")); name != "wpad.lan." {
		t.Fatalf("reserved wpad: %q", name)
	}
	if name := u.Bound(ctx, sc, lease("10.0.10.120", "02:00:00:00:00:a0", "laptop")); name != "laptop.lan." {
		t.Fatalf("normal name: %q", name)
	}
}

// Binding again with the same name and address writes nothing and does
// not reload DNS (no full reload and re-signing per renewal or flood).
func TestBoundUnchangedNoReload(t *testing.T) {
	u, sc, rl := setup(t)
	ctx := context.Background()
	l := lease("10.0.10.120", "02:00:00:00:00:01", "laptop")
	if name := u.Bound(ctx, sc, l); name != "laptop.lan." || rl.n.Load() != 1 {
		t.Fatalf("first bind: %q, reloads %d", name, rl.n.Load())
	}
	if name := u.Bound(ctx, sc, l); name != "laptop.lan." || rl.n.Load() != 1 {
		t.Fatalf("same bind: %q, reloads %d", name, rl.n.Load())
	}
	l.Hostname = "laptop2"
	if name := u.Bound(ctx, sc, l); name != "laptop2.lan." || rl.n.Load() != 2 {
		t.Fatalf("renamed: %q, reloads %d", name, rl.n.Load())
	}
	recs, _ := u.DNS.DHCPOwnerRecords(ctx, Owner(sc.ID, l))
	if len(recs) != 2 {
		t.Fatalf("records after rename: %+v", recs)
	}
}
