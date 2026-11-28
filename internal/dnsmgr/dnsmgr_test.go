package dnsmgr

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssrv"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/store"
)

type noIfaces struct{}

func (noIfaces) Interfaces() []netif.Interface     { return nil }
func (noIfaces) Subscribe(func([]netif.Interface)) {}
func (noIfaces) Kick()                             {}

func freePort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// A configuration saved before 0.0.0.0 / :: were refused still starts, and
// does not listen on every address.
func TestUnspecifiedExtraListenIgnored(t *testing.T) {
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
	st := dnsconf.DefaultSettings()
	st.ExtraListenAddresses = []string{"0.0.0.0", "::", "127.0.0.1"}
	if err := db.PutSetting(ctx, dnsconf.SettingsKey, st); err != nil { // as an older version saved it
		t.Fatal(err)
	}
	m := New(dnsconf.New(db), dnssrv.New(log, freePort(t)), noIfaces{}, log)
	t.Cleanup(m.Engine.Close)
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	ls := m.Engine.Listeners()
	if len(ls) != 2 {
		t.Fatalf("listeners: %+v", ls)
	}
	for _, l := range ls {
		if !strings.HasPrefix(l.Address, "127.0.0.1:") {
			t.Fatalf("listening on %s", l.Address)
		}
	}
}

func TestSoonDelayPacesReloads(t *testing.T) {
	now := time.Now()
	if d := soonDelay(now, time.Time{}); d != reloadDelay {
		t.Fatalf("first reload in %v", d)
	}
	if d := soonDelay(now, now.Add(-500*time.Millisecond)); d != reloadMinGap-500*time.Millisecond {
		t.Fatalf("reload right after another in %v", d)
	}
	if d := soonDelay(now, now.Add(-time.Minute)); d != reloadDelay {
		t.Fatalf("reload long after the last one in %v", d)
	}
}
