//go:build linux

package vip

import (
	"io"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestUpDown(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	l := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "lzvip0"}, PeerName: "lzvip1"}
	if err := netlink.LinkAdd(l); err != nil {
		t.Skip(err)
	}
	defer netlink.LinkDel(l)
	netlink.LinkSetUp(l)
	m, _ := New("10.77.0.10/24", "lzvip0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	has := func() bool {
		link, _ := netlink.LinkByName("lzvip0")
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
		for _, a := range addrs {
			if a.IP.Equal(net.ParseIP("10.77.0.10")) {
				return true
			}
		}
		return false
	}
	if err := m.Up(); err != nil || !has() {
		t.Fatalf("up: %v", err)
	}
	if err := m.Up(); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := m.Down(); err != nil || has() {
		t.Fatalf("down: %v", err)
	}
}
