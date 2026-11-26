package querylog

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkFilterPagination(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "logs.db"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Old matching entries, then many recent ones that share the text
	// prefix ("10.1.") but are outside 10.1.16.0/20.
	for i := 0; i < 5; i++ {
		l.AddDNS(DNSEntry{Time: now, Client: "10.1.16.5", Name: "old.example", Type: "A", Rcode: "NOERROR", Source: "cache"})
	}
	for i := 0; i < 500; i++ {
		l.AddDNS(DNSEntry{Time: now, Client: "10.1.99.1", Name: "new.example", Type: "A", Rcode: "NOERROR", Source: "cache"})
	}
	l.Flush()
	ctx := context.Background()
	f := DNSFilter{Client: netip.MustParsePrefix("10.1.16.0/20"), Limit: 20}
	found := 0
	for page := 0; page < 100; page++ {
		items, next, err := l.DNS(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		found += len(items)
		if next == nil {
			break
		}
		f.Before = *next
	}
	if found != 5 {
		t.Fatalf("found %d matching entries through the pages, want 5", found)
	}
}

func TestRetentionAndFilters(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "logs.db"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Now = func() time.Time { return now }
	l.AddDNS(DNSEntry{Time: now.Add(-10 * 24 * time.Hour), Client: "10.0.0.1", Name: "old.example", Type: "A", Rcode: "NOERROR", Source: "cache"})
	for i := 0; i < 50; i++ {
		l.AddDNS(DNSEntry{Time: now, Client: "192.168.1.5", Name: "www.example.com", Type: "AAAA", Rcode: "NOERROR", Source: "forwarder"})
	}
	l.AddDHCP(DHCPEntry{Time: now, Event: "ack", MAC: "02:00:00:00:00:01", IP: "192.168.1.100"})
	l.Flush()
	ctx := context.Background()
	l.Cleanup(ctx)
	st, _ := l.Status(ctx)
	if st.DNSEntries != 50 || st.DHCPEntries != 1 {
		t.Fatalf("after retention: %+v", st)
	}
	items, next, err := l.DNS(ctx, DNSFilter{Type: "aaaa", Limit: 20})
	if err != nil || len(items) != 20 || next == nil {
		t.Fatalf("page: %d %v %v", len(items), next, err)
	}
	// Disabled DNS logging: nothing queued.
	s := DefaultSettings()
	s.DNSQueries = false
	l.SetSettings(s)
	l.AddDNS(DNSEntry{Time: now, Client: "1.1.1.1", Name: "x.example"})
	l.Flush()
	if st, _ := l.Status(ctx); st.DNSEntries != 50 {
		t.Fatalf("logged while disabled: %+v", st)
	}
	// Size limit: everything above is trimmed, oldest first.
	s.DNSQueries, s.MaxSizeMB = true, 10
	l.SetSettings(s)
	for i := 0; i < 60000; i++ {
		l.dnsCh <- DNSEntry{Time: now, Client: "192.168.1.5", Name: "a-rather-long-name-to-fill-the-database.example.com", Type: "A",
			Rcode: "NOERROR", Source: "forwarder", Answer: "192.0.2.1 and some padding to make rows bigger"}
		if len(l.dnsCh) > 15000 {
			l.Flush()
		}
	}
	l.Flush()
	before := l.size()
	l.Cleanup(ctx)
	if after := l.size(); before > 10<<20 && after > 10<<20 {
		t.Fatalf("size not reduced: %d -> %d", before, after)
	}
	if err := l.Purge(ctx); err != nil {
		t.Fatal(err)
	}
}
