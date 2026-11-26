package dnssec

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

func TestRetiredZSKOutlivesLongTTL(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx, dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	conf := dnsconf.New(db)
	z, err := conf.CreateZone(ctx, dnsconf.ZoneInput{Name: "maison.lan"})
	if err != nil {
		t.Fatal(err)
	}
	ttl := uint32(5 * 24 * 3600) // longer than RetireDelay
	if _, err := conf.CreateRecord(ctx, z.ID, dnsconf.RecordInput{Name: "www", Type: "A", TTL: &ttl,
		Data: dnsconf.RecordData{IP: "192.168.1.10"}}); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	s := NewStore(db, box)
	now := time.Now()
	s.Now = func() time.Time { return now }
	if _, err := s.Enable(ctx, z.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	// Automatic ZSK rollover: pre-publication, then the old key retires.
	now = now.Add(ZSKLifetime)
	if _, err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(PrePublish)
	if _, err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := s.Zone(ctx, z.ID)
	if err != nil {
		t.Fatal(err)
	}
	var retired *Key
	for _, k := range info.Keys {
		if k.Role == ZSK && k.State == StateRetired {
			retired = k
		}
	}
	if retired == nil || retired.RetireAt == nil {
		t.Fatalf("no retired ZSK: %+v", info.Keys)
	}
	if d := retired.RetireAt.Sub(now); d <= time.Duration(ttl)*time.Second {
		t.Fatalf("retired ZSK removed after %v, records are cached for %ds", d, ttl)
	}
}
