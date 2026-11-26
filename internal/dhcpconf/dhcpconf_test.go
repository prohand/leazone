package dhcpconf

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/prohand/leazone/internal/store"
)

func newStore(t *testing.T) *Store {
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

func vid(v int) *int { return &v }

func TestScopeValidationAndIsolation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	in := ScopeInput{Name: "20 - Invités", VLANID: vid(20), Network: "192.168.20.0/24", RangeStart: "192.168.20.100",
		RangeEnd: "192.168.20.199", Gateway: "192.168.20.1", DNSServers: []string{"192.168.20.2"}, DDNSDomain: "invites.lan",
		Exclusions: []Range{{"192.168.20.150", "192.168.20.155"}}, Options: []Option{{Code: 66, Type: "string", Value: "tftp.lan"}}}
	sc, err := s.CreateScope(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if sc.VLANName != "Invités" || sc.LeaseTime != 86400 || sc.Mode() != "none" {
		t.Fatalf("%+v", sc)
	}
	// Overlapping network refused (a client must never get an IP of another VLAN).
	in2 := in
	in2.Name, in2.Network, in2.RangeStart, in2.RangeEnd = "autre", "192.168.20.128/25", "192.168.20.130", "192.168.20.140"
	in2.Gateway, in2.Exclusions = "", nil
	if _, err := s.CreateScope(ctx, in2); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("overlap accepted: %v", err)
	}
	bad := []ScopeInput{
		{Name: "x", Network: "192.168.30.0/24", RangeStart: "192.168.31.1", RangeEnd: "192.168.30.9", DDNSDomain: "a.lan"},
		{Name: "x", Network: "192.168.30.0/24", RangeStart: "192.168.30.10", RangeEnd: "192.168.30.20", Gateway: "192.168.30.15", DDNSDomain: "a.lan"},
		{Name: "x", Network: "192.168.30.0/24", RangeStart: "192.168.30.10", RangeEnd: "192.168.30.20", Options: []Option{{Code: 6, Type: "ip", Value: "1.1.1.1"}}, DDNSDomain: "a.lan"},
		{Name: "x", Network: "192.168.30.0/24", RangeStart: "192.168.30.10", RangeEnd: "192.168.30.20"}, // DDNS without domain
	}
	for i, b := range bad {
		var v Validation
		if _, err := s.CreateScope(ctx, b); !errors.As(err, &v) {
			t.Errorf("bad scope %d accepted: %v", i, err)
		}
	}
	// Reservations.
	if _, err := s.CreateReservation(ctx, ReservationInput{ScopeID: sc.ID, MAC: "AA-BB-CC-00-11-22", IP: "192.168.20.10", Hostname: "Imprimante Bureau"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateReservation(ctx, ReservationInput{ScopeID: sc.ID, MAC: "aa:bb:cc:00:11:23", IP: "192.168.20.10"}); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("duplicate IP accepted: %v", err)
	}
	if _, err := s.CreateReservation(ctx, ReservationInput{ScopeID: sc.ID, MAC: "aa:bb:cc:00:11:24", IP: "192.168.21.10"}); err == nil {
		t.Fatal("reservation outside the network accepted")
	}
	list, _ := s.Reservations(ctx, sc.ID)
	if len(list) != 1 || list[0].MAC != "aa:bb:cc:00:11:22" || list[0].Hostname != "imprimante-bureau" {
		t.Fatalf("%+v", list[0])
	}
	if err := s.DeleteVLAN(ctx, "nope"); err == nil {
		t.Fatal("unknown vlan deleted")
	}
}

// TestUpdateScopeChecksReservations: a scope change must not turn a
// reservation into the gateway, network or broadcast address.
func TestUpdateScopeChecksReservations(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	in := ScopeInput{Name: "lan", Network: "192.168.20.0/24", RangeStart: "192.168.20.100", RangeEnd: "192.168.20.120",
		Gateway: "192.168.20.1", DDNSDomain: "lan.lan"}
	sc, err := s.CreateScope(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	for i, ip := range []string{"192.168.20.10", "192.168.20.127"} {
		mac := []string{"aa:bb:cc:00:11:01", "aa:bb:cc:00:11:02"}[i]
		if _, err := s.CreateReservation(ctx, ReservationInput{ScopeID: sc.ID, MAC: mac, IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	gw := in
	gw.Gateway = "192.168.20.10"
	if _, err := s.UpdateScope(ctx, sc.ID, gw); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("reservation on the new gateway accepted: %v", err)
	}
	small := in
	small.Network = "192.168.20.0/25" // .127 becomes the broadcast address
	if _, err := s.UpdateScope(ctx, sc.ID, small); !errors.As(err, new(ErrConflict)) {
		t.Fatalf("reservation on the new broadcast address accepted: %v", err)
	}
	ok := in
	ok.Gateway = "192.168.20.254"
	if _, err := s.UpdateScope(ctx, sc.ID, ok); err != nil {
		t.Fatal(err)
	}
}
