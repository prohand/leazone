//go:build linux

package netif

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestHotAdd creates a veth pair, then (if the kernel supports 802.1Q) a VLAN
// on it, and checks the watcher reports type, VLAN ID, parent, address, and
// removal. Needs root (CAP_NET_ADMIN): skipped otherwise.
func TestHotAdd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create test interfaces")
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "lzt0"}, PeerName: "lzt1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create veth: %v", err)
	}
	defer netlink.LinkDel(veth)

	w := NewWatcher(slog.New(slog.NewTextHandler(io.Discard, nil)))
	changes := make(chan []Interface, 64)
	w.Subscribe(func(l []Interface) { changes <- l })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	<-changes // initial snapshot

	p, _ := netlink.LinkByName("lzt0")
	target := netlink.Link(p)
	name, wantType := "lzt0", TypeVirtual
	vlan := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "lzt0.20", ParentIndex: p.Attrs().Index}, VlanId: 20}
	if err := netlink.LinkAdd(vlan); err == nil {
		defer netlink.LinkDel(vlan)
		target, name, wantType = vlan, "lzt0.20", TypeVLAN
	} else {
		t.Logf("802.1Q not supported by this kernel (%v): testing hot add on the veth only", err)
	}
	_ = netlink.LinkSetUp(target)
	addr, _ := netlink.ParseAddr("10.99.20.1/24")
	if err := netlink.AddrAdd(target, addr); err != nil {
		t.Fatal(err)
	}

	wait := func(cond func([]Interface) bool) []Interface {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case l := <-changes:
				if cond(l) {
					return l
				}
			case <-deadline:
				t.Fatalf("timeout waiting for %s", name)
			}
		}
	}
	l := wait(func(l []Interface) bool { it, ok := find(l, name); return ok && len(it.IPv4()) == 1 })
	it, _ := find(l, name)
	if it.Type != wantType || it.IPv4()[0].String() != "10.99.20.1" {
		t.Fatalf("got %+v", it)
	}
	if wantType == TypeVLAN && (it.VLANID != 20 || it.Parent != "lzt0") {
		t.Fatalf("vlan = %+v", it)
	}
	if err := netlink.LinkDel(target); err != nil {
		t.Fatal(err)
	}
	wait(func(l []Interface) bool { _, ok := find(l, name); return !ok })
}

func find(l []Interface, name string) (Interface, bool) {
	for _, it := range l {
		if it.Name == name {
			return it, true
		}
	}
	return Interface{}, false
}
