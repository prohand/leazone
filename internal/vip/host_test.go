//go:build linux

package vip

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// A LEAZONE_VIP equal to an address of the host (primary, not added by
// Leazone) is neither taken over nor removed: a wrong setting, or a user
// running a binary with file capabilities, must not cut the host off.
func TestHostAddressNeverRemoved(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	l := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "lzvip2"}, PeerName: "lzvip3"}
	if err := netlink.LinkAdd(l); err != nil {
		t.Skip(err)
	}
	defer netlink.LinkDel(l)
	netlink.LinkSetUp(l)
	link, _ := netlink.LinkByName("lzvip2")
	has := func(ip string) bool {
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
		for _, a := range addrs {
			if a.IP.Equal(net.ParseIP(ip)) {
				return true
			}
		}
		return false
	}
	host, _ := netlink.ParseAddr("10.78.0.2/24")
	if err := netlink.AddrAdd(link, host); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, _ := New("10.78.0.2/24", "lzvip2", log)
	if err := m.Down(); !errors.Is(err, ErrHostAddress) || !has("10.78.0.2") {
		t.Fatalf("host address removed at startup: %v", err)
	}
	if err := m.Up(); !errors.Is(err, ErrHostAddress) {
		t.Fatalf("host address taken as the VIP: %v", err)
	}
	if err := m.Down(); !has("10.78.0.2") {
		t.Fatalf("host address removed after a refused Up: %v", err)
	}
	// A VIP left by an older version (default label, secondary next to the
	// host address) is still cleaned up.
	old, _ := netlink.ParseAddr("10.78.0.10/24")
	old.Label = "lzvip2"
	if err := netlink.AddrAdd(link, old); err != nil {
		t.Fatal(err)
	}
	m2, _ := New("10.78.0.10/24", "lzvip2", log)
	if err := m2.Down(); err != nil || has("10.78.0.10") {
		t.Fatalf("stale secondary VIP not removed: %v", err)
	}
	// Our own VIP alone in its subnet (primary, but labeled) is cleaned up too.
	m3, _ := New("10.79.0.10/24", "lzvip2", log)
	if err := m3.Up(); err != nil || !has("10.79.0.10") {
		t.Fatalf("up: %v", err)
	}
	m4, _ := New("10.79.0.10/24", "lzvip2", log)
	if err := m4.Down(); err != nil || has("10.79.0.10") {
		t.Fatalf("stale labeled VIP not removed: %v", err)
	}
}
