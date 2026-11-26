//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// newNS creates an empty network namespace (closed at cleanup).
func newNS(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	return ns
}

// inNS runs fn on a thread switched to ns.
func inNS(t *testing.T, ns netns.NsHandle, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		orig, _ := netns.Get()
		defer orig.Close()
		if err := netns.Set(ns); err != nil {
			t.Error(err)
			return
		}
		defer netns.Set(orig)
		fn()
	}()
	<-done
}

// segment creates a veth pair: host side named host (with hostCIDR, "" for
// none), the peer moved into ns as "eth0" (with peerCIDR, "" for none).
func segment(t *testing.T, host, hostCIDR string, ns netns.NsHandle, peerCIDR string) {
	t.Helper()
	l := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host}, PeerName: host + "p"}
	if old, err := netlink.LinkByName(host); err == nil {
		netlink.LinkDel(old)
	}
	if err := netlink.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(l) })
	if hostCIDR != "" {
		a, _ := netlink.ParseAddr(hostCIDR)
		netlink.AddrAdd(l, a)
	}
	netlink.LinkSetUp(l)
	peer, _ := netlink.LinkByName(host + "p")
	if err := netlink.LinkSetNsFd(peer, int(ns)); err != nil {
		t.Fatal(err)
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, _ := h.LinkByName(host + "p")
	h.LinkSetName(p, "eth0")
	if peerCIDR != "" {
		a, _ := netlink.ParseAddr(peerCIDR)
		h.AddrAdd(p, a)
	}
	h.LinkSetUp(p)
	if lo, err := h.LinkByName("lo"); err == nil {
		h.LinkSetUp(lo)
	}
}

// dhcpClient runs a full DORA from eth0 of ns and returns the ACK.
func dhcpClient(t *testing.T, ns netns.NsHandle, timeout time.Duration) (*dhcpv4.DHCPv4, error) {
	var ack *dhcpv4.DHCPv4
	var err error
	inNS(t, ns, func() {
		c, e := nclient4.New("eth0", nclient4.WithTimeout(timeout/3), nclient4.WithRetry(2))
		if e != nil {
			err = e
			return
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var lease *nclient4.Lease
		lease, err = c.Request(ctx, dhcpv4.WithOption(dhcpv4.OptHostName("client-"+fmt.Sprint(int(ns)))))
		if err == nil {
			ack = lease.ACK
		}
	})
	return ack, err
}

// relay forwards client broadcasts from routerNS's eth0 (giaddr) to the
// server and the replies back, adding option 82 like a switch would.
func relay(t *testing.T, routerNS netns.NsHandle, giaddr, server netip.Addr) {
	var conn *net.UDPConn
	inNS(t, routerNS, func() {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 67})
		if err != nil {
			t.Fatal(err)
		}
		conn = c
	})
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			m, err := dhcpv4.FromBytes(buf[:n])
			if err != nil {
				continue
			}
			if m.OpCode == dhcpv4.OpcodeBootRequest && from.Port == 68 {
				m.GatewayIPAddr = net.IP(giaddr.AsSlice())
				m.HopCount++
				m.UpdateOption(dhcpv4.OptRelayAgentInfo(
					dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(1), []byte("Gi1/0/40")),
					dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(2), []byte("switch-etage-4"))))
				conn.WriteToUDP(m.ToBytes(), &net.UDPAddr{IP: net.IP(server.AsSlice()), Port: 67})
			} else if m.OpCode == dhcpv4.OpcodeBootReply {
				m.Options.Del(dhcpv4.OptionRelayAgentInformation)
				// Clients without an address: subnet broadcast reaches them.
				b := giaddr.As4()
				conn.WriteToUDP(m.ToBytes(), &net.UDPAddr{IP: net.IPv4(b[0], b[1], b[2], 255), Port: 68})
			}
		}
	}()
}

// TestPhase3DHCP: 3 VLAN-like segments served directly + 1 segment behind a
// relay; every client gets an address of its own network, nothing is served
// where DHCP is off; leases show option 82; DDNS registers the clients.
func TestPhase3DHCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	direct := []int{10, 20, 30}
	clients := map[int]netns.NsHandle{}
	for _, n := range append(direct, 50) {
		ns := newNS(t)
		clients[n] = ns
		segment(t, fmt.Sprintf("lzd%d", n), fmt.Sprintf("10.%d.0.2/24", n), ns, "")
	}
	// Relayed segment: client40 <-> router <-> host.
	client40, router := newNS(t), newNS(t)
	segment(t, "lzr40", "", client40, "")
	// Move the host side of lzr40 into the router as its client leg.
	l, _ := netlink.LinkByName("lzr40")
	netlink.LinkSetNsFd(l, int(router))
	rh, _ := netlink.NewHandleAt(router)
	rl, _ := rh.LinkByName("lzr40")
	ga, _ := netlink.ParseAddr("10.40.0.1/24")
	rh.AddrAdd(rl, ga)
	rh.LinkSetUp(rl)
	rh.Close()
	segment(t, "lzup", "10.99.0.1/30", router, "10.99.0.2/30")
	route := &netlink.Route{Dst: &net.IPNet{IP: net.IP{10, 40, 0, 0}, Mask: net.CIDRMask(24, 32)}, Gw: net.IP{10, 99, 0, 2}}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.RouteDel(route) })
	relay(t, router, netip.MustParseAddr("10.40.0.1"), netip.MustParseAddr("10.99.0.1"))

	c := startContainer(t, "leazone-it3", "127.0.0.1:18447")
	a := newAPI(t, c)
	a.loginAdmin()

	for _, n := range direct {
		in := map[string]any{"name": fmt.Sprintf("%d - VLAN %d", n, n), "vlanId": n, "network": fmt.Sprintf("10.%d.0.0/24", n),
			"rangeStart": fmt.Sprintf("10.%d.0.100", n), "rangeEnd": fmt.Sprintf("10.%d.0.199", n), "gateway": fmt.Sprintf("10.%d.0.1", n),
			"interface": fmt.Sprintf("lzd%d", n), "ddnsDomain": fmt.Sprintf("v%d.lan", n)}
		if s := a.do("POST", "/api/v1/dhcp/scopes", in, nil); s != 201 {
			t.Fatalf("scope %d: %d", n, s)
		}
		a.do("PATCH", "/api/v1/interfaces/"+fmt.Sprintf("lzd%d", n), map[string]any{"dhcpEnabled": true}, nil)
	}
	in := map[string]any{"name": "40 - relais", "vlanId": 40, "network": "10.40.0.0/24", "rangeStart": "10.40.0.100",
		"rangeEnd": "10.40.0.199", "gateway": "10.40.0.1", "relay": true, "ddnsDomain": "v40.lan"}
	if s := a.do("POST", "/api/v1/dhcp/scopes", in, nil); s != 201 {
		t.Fatalf("relay scope: %d", s)
	}
	var st struct {
		Listening bool
		Error     string
	}
	a.do("GET", "/api/v1/dhcp/status", nil, &st)
	if !st.Listening {
		t.Fatalf("DHCP not listening: %s", st.Error)
	}

	for _, n := range direct {
		ack, err := dhcpClient(t, clients[n], 12*time.Second)
		if err != nil {
			t.Fatalf("client on segment %d: %v", n, err)
		}
		want := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", n))
		got, _ := netip.AddrFromSlice(ack.YourIPAddr.To4())
		if !want.Contains(got) {
			t.Fatalf("segment %d: client got %v", n, got)
		}
		t.Logf("✔ direct segment %d: client got %v (router %v)", n, got, ack.Router())
	}
	ack, err := dhcpClient(t, client40, 12*time.Second)
	if err != nil {
		t.Fatalf("relayed client: %v", err)
	}
	got, _ := netip.AddrFromSlice(ack.YourIPAddr.To4())
	if !netip.MustParsePrefix("10.40.0.0/24").Contains(got) {
		t.Fatalf("relayed client got %v", got)
	}
	t.Logf("✔ relayed segment 40: client got %v through the relay", got)

	if _, err := dhcpClient(t, clients[50], 4*time.Second); err == nil {
		t.Fatal("a client got an address on a segment where DHCP is disabled")
	}
	t.Log("✔ no answer on the segment where DHCP is disabled")

	var leases struct {
		Items []struct {
			IP, State, CircuitID, RemoteID, GIAddr string
			DNSName                                 *string
		}
	}
	a.do("GET", "/api/v1/dhcp/leases", nil, &leases)
	bound, opt82, dns := 0, false, 0
	for _, l := range leases.Items {
		if l.State == "bound" {
			bound++
		}
		if l.CircuitID == "Gi1/0/40" && l.RemoteID == "switch-etage-4" && l.GIAddr == "10.40.0.1" {
			opt82 = true
		}
		if l.DNSName != nil && strings.HasSuffix(*l.DNSName, ".lan.") {
			dns++
		}
	}
	if bound != 4 || !opt82 || dns != 4 {
		t.Fatalf("leases: bound=%d opt82=%v dns=%d %+v", bound, opt82, dns, leases.Items)
	}
	t.Log("✔ 4 leases bound, option 82 shown for the relayed client, 4 names registered in DNS")
}
