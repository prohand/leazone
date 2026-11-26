package dhcpsrv

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/prohand/leazone/internal/dhcpconf"
	"github.com/prohand/leazone/internal/netif"
	"github.com/prohand/leazone/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func ptr[T any](v T) *T { return &v }

func scope(id, iface string, n int, relay bool) *dhcpconf.Scope {
	net := fmt.Sprintf("10.0.%d.0/24", n)
	sc := &dhcpconf.Scope{ID: id, Name: id, Enabled: true, Network: net, RangeStart: fmt.Sprintf("10.0.%d.100", n),
		RangeEnd: fmt.Sprintf("10.0.%d.149", n), LeaseTime: 3600, Gateway: fmt.Sprintf("10.0.%d.1", n),
		DNSServers: []string{fmt.Sprintf("10.0.%d.2", n)}, Domain: "lan", Relay: relay}
	if iface != "" {
		sc.Interface = ptr(iface)
	}
	return sc
}

func iface(idx int, name string, cidr string) netif.Interface {
	return netif.Interface{Index: idx, Name: name, Addresses: []netif.Address{{Prefix: netip.MustParsePrefix(cidr)}}}
}

type hooks struct {
	mu    sync.Mutex
	bound map[string]string // mac -> ip
	ended int
}

func (h *hooks) Bound(_ context.Context, _ *dhcpconf.Scope, l Lease) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bound[l.MAC] = l.IP.String()
	return l.Hostname + ".lan."
}
func (h *hooks) Ended(context.Context, *dhcpconf.Scope, Lease) { h.mu.Lock(); h.ended++; h.mu.Unlock() }

type fakePing map[string]bool

func (f fakePing) InUse(_ context.Context, ip netip.Addr) bool { return f[ip.String()] }

// newEngine: 3 direct VLAN interfaces (eth0.10/20/30), one relayed network
// (10.0.40.0/24), and eth0.50 with DHCP enabled but no scope.
func newEngine(t *testing.T) (*Engine, *hooks, *time.Time) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background(), t.TempDir(), quiet); err != nil {
		t.Fatal(err)
	}
	// The lease table references scopes: create them.
	cs := dhcpconf.New(db)
	for _, n := range []int{10, 20, 30, 40} {
		in := dhcpconf.ScopeInput{Name: fmt.Sprint("s", n), Network: fmt.Sprintf("10.0.%d.0/24", n),
			RangeStart: fmt.Sprintf("10.0.%d.100", n), RangeEnd: fmt.Sprintf("10.0.%d.149", n), DDNSDomain: "lan"}
		if _, err := cs.CreateScope(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := cs.Scopes(context.Background())
	idOf := map[string]string{}
	for _, s := range all {
		idOf[s.Name] = s.ID
	}
	e, err := NewEngine(context.Background(), db, quiet)
	if err != nil {
		t.Fatal(err)
	}
	h := &hooks{bound: map[string]string{}}
	e.Hooks = h
	now := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { return now }
	e.SetConfig([]*dhcpconf.Scope{
		scope(idOf["s10"], "eth0.10", 10, false), scope(idOf["s20"], "eth0.20", 20, false),
		scope(idOf["s30"], "eth0.30", 30, false), scope(idOf["s40"], "", 40, true),
	}, nil)
	e.SetInterfaces([]netif.Interface{
		iface(10, "eth0.10", "10.0.10.2/24"), iface(20, "eth0.20", "10.0.20.2/24"), iface(30, "eth0.30", "10.0.30.2/24"),
		iface(1, "eth0", "192.168.1.2/24"), iface(50, "eth0.50", "10.0.50.2/24"),
	}, map[string]bool{"eth0.10": true, "eth0.20": true, "eth0.30": true, "eth0.50": true})
	return e, h, &now
}

func mac(i int) net.HardwareAddr { return net.HardwareAddr{0x02, 0, 0, 0, byte(i >> 8), byte(i)} }

func discover(hw net.HardwareAddr, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	m, _ := dhcpv4.NewDiscovery(hw, mods...)
	return m
}

func request(hw net.HardwareAddr, ip, server netip.Addr, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	all := []dhcpv4.Modifier{dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithHwAddr(hw),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.IP(ip.AsSlice())))}
	if server.IsValid() {
		all = append(all, dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(server.AsSlice()))))
	}
	m, _ := dhcpv4.New(append(all, mods...)...)
	return m
}

// dora runs DISCOVER + REQUEST and returns the acked IP (invalid if none).
func dora(t *testing.T, e *Engine, hw net.HardwareAddr, ifidx int, mods ...dhcpv4.Modifier) (netip.Addr, *Reply) {
	t.Helper()
	ctx := context.Background()
	off := e.Handle(ctx, Packet{Msg: discover(hw, mods...), IfIndex: ifidx})
	if off == nil {
		return netip.Addr{}, nil
	}
	ip := ipOf(off.Msg.YourIPAddr)
	sid := ipOf(off.Msg.ServerIdentifier())
	ack := e.Handle(ctx, Packet{Msg: request(hw, ip, sid, mods...), IfIndex: ifidx})
	if ack == nil || ack.Msg.MessageType() != dhcpv4.MessageTypeAck {
		return netip.Addr{}, ack
	}
	return ipOf(ack.Msg.YourIPAddr), ack
}

func TestDirectAndRelayGiveTheRightNetwork(t *testing.T) {
	e, h, _ := newEngine(t)
	for i, n := range []int{10, 20, 30} {
		ip, r := dora(t, e, mac(i), n)
		if !netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/24", n)).Contains(ip) {
			t.Fatalf("VLAN %d: got %v", n, ip)
		}
		if !r.Broadcast || r.IfIndex != n || ipOf(r.Msg.ServerIdentifier()).String() != fmt.Sprintf("10.0.%d.2", n) {
			t.Fatalf("VLAN %d reply routing: %+v", n, r)
		}
		if gw := r.Msg.Options.Get(dhcpv4.OptionRouter); net.IP(gw).String() != fmt.Sprintf("10.0.%d.1", n) {
			t.Fatalf("router option: %v", gw)
		}
	}
	// Relayed (giaddr 10.0.40.1), with option 82.
	o82 := dhcpv4.OptRelayAgentInfo(dhcpv4.OptGeneric(subCircuitID, []byte("Gi1/0/7")), dhcpv4.OptGeneric(subRemoteID, []byte("sw-etage2")))
	relay := []dhcpv4.Modifier{dhcpv4.WithGatewayIP(net.IP{10, 0, 40, 1}), dhcpv4.WithOption(o82)}
	ip, r := dora(t, e, mac(9), 1, relay...)
	if !netip.MustParsePrefix("10.0.40.0/24").Contains(ip) || !r.ToRelay || r.To.String() != "10.0.40.1" {
		t.Fatalf("relay: %v %+v", ip, r)
	}
	if r.Msg.Options.Get(dhcpv4.OptionRelayAgentInformation) == nil {
		t.Fatal("option 82 not echoed")
	}
	var found bool
	for _, l := range e.Leases() {
		if l.IP == ip && l.CircuitID == "Gi1/0/7" && l.RemoteID == "sw-etage2" && l.GIAddr == "10.0.40.1" && l.State == StateBound {
			found = true
		}
	}
	if !found {
		t.Fatalf("option 82 not stored: %+v", e.Leases())
	}
	if len(h.bound) != 4 {
		t.Fatalf("DDNS hook calls: %d", len(h.bound))
	}
}

func TestIsolation(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	if r := e.Handle(ctx, Packet{Msg: discover(mac(1)), IfIndex: 50}); r != nil {
		t.Fatal("answered on an interface without scope")
	}
	if r := e.Handle(ctx, Packet{Msg: discover(mac(1)), IfIndex: 1}); r != nil {
		t.Fatal("answered on an interface where DHCP is disabled")
	}
	if r := e.Handle(ctx, Packet{Msg: discover(mac(1), dhcpv4.WithGatewayIP(net.IP{172, 16, 0, 1})), IfIndex: 1}); r != nil {
		t.Fatal("answered an unknown relay")
	}
	// A client of VLAN 20 asking for an address of VLAN 10 gets a NAK.
	r := e.Handle(ctx, Packet{Msg: request(mac(2), netip.MustParseAddr("10.0.10.120"), netip.Addr{}), IfIndex: 20})
	if r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("cross-VLAN request not refused: %v", r)
	}
	// Disabling DHCP on the interface stops the service at once.
	e.SetInterfaces([]netif.Interface{iface(10, "eth0.10", "10.0.10.2/24")}, map[string]bool{})
	if r := e.Handle(ctx, Packet{Msg: discover(mac(3)), IfIndex: 10}); r != nil {
		t.Fatal("answered after DHCP was disabled on the interface")
	}
}

func TestLifecycleRenewReleaseExpire(t *testing.T) {
	e, h, now := newEngine(t)
	ctx := context.Background()
	hw := mac(7)
	ip, _ := dora(t, e, hw, 10, dhcpv4.WithOption(dhcpv4.OptHostName("PC-Salon")))
	if !ip.IsValid() {
		t.Fatal("no lease")
	}
	// Same client asks again later: same address (sticky).
	*now = now.Add(10 * time.Minute)
	if ip2, _ := dora(t, e, hw, 10); ip2 != ip {
		t.Fatalf("sticky address: %v then %v", ip, ip2)
	}
	// Renewal (ciaddr, unicast).
	renew, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithHwAddr(hw), dhcpv4.WithClientIP(net.IP(ip.AsSlice())))
	r := e.Handle(ctx, Packet{Msg: renew, IfIndex: 10})
	if r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeAck || r.Broadcast || r.To != ip {
		t.Fatalf("renew: %+v", r)
	}
	// Expiry ends the lease and removes DNS.
	*now = now.Add(2 * time.Hour)
	e.Sweep(ctx)
	if h.ended != 1 {
		t.Fatalf("ended hooks = %d", h.ended)
	}
	// Release.
	ip3, _ := dora(t, e, hw, 10)
	rel, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithHwAddr(hw), dhcpv4.WithClientIP(net.IP(ip3.AsSlice())))
	e.Handle(ctx, Packet{Msg: rel, IfIndex: 10})
	for _, l := range e.Leases() {
		if l.IP == ip3 && l.State != StateReleased {
			t.Fatalf("after release: %s", l.State)
		}
	}
	// Leases survive a restart (persisted).
	e2, _ := NewEngine(ctx, e.db.db, quiet)
	if len(e2.leases) == 0 {
		t.Fatal("leases not persisted")
	}
}

func TestReservationDeclineAndPing(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	s10 := e.Scope(e.scopes[firstScope(e, "eth0.10")].ID)
	res := &dhcpconf.Reservation{ID: "r1", ScopeID: s10.ID, MAC: mac(42).String(), IP: "10.0.10.100"}
	scopes := []*dhcpconf.Scope{}
	for _, s := range e.scopes {
		scopes = append(scopes, s.Scope)
	}
	e.SetConfig(scopes, []*dhcpconf.Reservation{res})
	// Another client never gets the reserved address, even the first one of the range.
	if ip, _ := dora(t, e, mac(1), 10); ip.String() == "10.0.10.100" {
		t.Fatal("reserved address given to another client")
	}
	if ip, _ := dora(t, e, mac(42), 10); ip.String() != "10.0.10.100" {
		t.Fatalf("reservation: got %v", ip)
	}
	// DECLINE: the address is avoided afterwards.
	ip, _ := dora(t, e, mac(5), 10)
	dec, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline), dhcpv4.WithHwAddr(mac(5)),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.IP(ip.AsSlice()))))
	e.Handle(ctx, Packet{Msg: dec, IfIndex: 10})
	if ip2, _ := dora(t, e, mac(5), 10); ip2 == ip || !ip2.IsValid() {
		t.Fatalf("declined address offered again: %v", ip2)
	}
	// Ping check: an address answering ping is skipped.
	for _, s := range e.scopes {
		s.PingCheck = true
	}
	next := ""
	e.mu.Lock()
	sc := e.scopes[firstScope(e, "eth0.10")]
	if a, ok := e.pick(sc, mac(77).String(), "", netip.Addr{}, e.Now(), nil); ok {
		next = a.String()
	}
	e.mu.Unlock()
	e.Pinger = fakePing{next: true}
	if ip, _ := dora(t, e, mac(77), 10); ip.String() == next || !ip.IsValid() {
		t.Fatalf("address answering ping was offered: %v", ip)
	}
}

func firstScope(e *Engine, ifname string) string {
	for id, s := range e.scopes {
		if s.Interface != nil && *s.Interface == ifname {
			return id
		}
	}
	return ""
}

// TestNeverTwoClientsOneAddress hammers a small pool with many concurrent
// clients and random behaviour (INIT-REBOOT with other clients' addresses,
// releases, time passing) and checks that no address is ever acknowledged
// to two different clients at the same time.
func TestNeverTwoClientsOneAddress(t *testing.T) {
	e, _, now := newEngine(t)
	ctx := context.Background()
	var mu sync.Mutex
	type holder struct {
		mac   string
		until time.Time
	}
	held := map[netip.Addr]holder{}
	violations, acks := 0, 0
	// A client holds one address: an ACK for another address ends its
	// previous lease. While a client's request is in flight, the server may
	// already have freed its old address: such a conflict only counts if the
	// request does not move the client.
	type suspect struct {
		ip  netip.Addr
		msg string
	}
	inflight := map[string]bool{}
	suspects := map[string][]suspect{}
	begin := func(m string) { mu.Lock(); inflight[m] = true; mu.Unlock() }
	end := func(m string, acked netip.Addr) {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range suspects[m] {
			if !acked.IsValid() || acked == s.ip {
				violations++
				t.Error(s.msg)
			}
		}
		delete(suspects, m)
		delete(inflight, m)
	}
	check := func(ip netip.Addr, m string) {
		mu.Lock()
		defer mu.Unlock()
		acks++
		if h, ok := held[ip]; ok && h.mac != m && e.Now().Before(h.until) {
			msg := fmt.Sprintf("%v acknowledged to %s while held by %s", ip, m, h.mac)
			if inflight[h.mac] {
				suspects[h.mac] = append(suspects[h.mac], suspect{ip, msg})
			} else {
				violations++
				t.Error(msg)
			}
		}
		for a, h := range held {
			if h.mac == m {
				delete(held, a)
			}
		}
		held[ip] = holder{m, e.Now().Add(time.Hour)}
	}
	release := func(ip netip.Addr, m string) {
		mu.Lock()
		defer mu.Unlock()
		if h, ok := held[ip]; ok && h.mac == m {
			delete(held, ip)
		}
	}
	rng := rand.New(rand.NewSource(1))
	var rngMu sync.Mutex
	rnd := func(n int) int { rngMu.Lock(); defer rngMu.Unlock(); return rng.Intn(n) }

	var wg sync.WaitGroup
	for c := 0; c < 80; c++ { // 80 clients for 50 addresses
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			hw := mac(1000 + c)
			for step := 0; step < 30; step++ {
				switch rnd(4) {
				case 0, 1:
					begin(hw.String())
					ip, r := dora(t, e, hw, 10)
					if ip.IsValid() {
						check(ip, hw.String())
					} else if r != nil && r.Msg.MessageType() != dhcpv4.MessageTypeNak {
						t.Errorf("unexpected reply %v", r.Msg.MessageType())
					}
					end(hw.String(), ip)
				case 2:
					// INIT-REBOOT asking for a random address (maybe someone else's).
					want := netip.MustParseAddr(fmt.Sprintf("10.0.10.%d", 100+rnd(50)))
					begin(hw.String())
					var acked netip.Addr
					r := e.Handle(ctx, Packet{Msg: request(hw, want, netip.Addr{}), IfIndex: 10})
					if r != nil && r.Msg.MessageType() == dhcpv4.MessageTypeAck {
						check(want, hw.String())
						acked = want
					}
					end(hw.String(), acked)
				case 3:
					for _, l := range e.Leases() {
						if l.MAC == hw.String() && l.State == StateBound {
							rel, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithHwAddr(hw),
								dhcpv4.WithClientIP(net.IP(l.IP.AsSlice())))
							release(l.IP, hw.String())
							e.Handle(ctx, Packet{Msg: rel, IfIndex: 10})
						}
					}
				}
			}
		}(c)
	}
	wg.Wait()
	_ = now
	if violations > 0 {
		t.Fatalf("%d duplicate acknowledgements", violations)
	}
	if acks < 200 {
		t.Fatalf("only %d acknowledgements: the test did not exercise the allocator", acks)
	}
	t.Logf("%d acknowledgements, no address held by two clients", acks)
}

// TestSplitPoolNeverOverlaps simulates two nodes that cannot talk to each
// other (no lease sync): each only allocates its own addresses, so they can
// never give the same new address to two clients.
func TestSplitPoolNeverOverlaps(t *testing.T) {
	a, _, _ := newEngine(t)
	b, _, _ := newEngine(t)
	a.Owns = func(_ string, ip uint32) bool { return ip%2 == 0 }
	b.Owns = func(_ string, ip uint32) bool { return ip%2 == 1 }
	given := map[netip.Addr]string{}
	for c := 0; c < 60; c++ {
		e := a
		if c%2 == 1 {
			e = b
		}
		hw := mac(2000 + c)
		ip, _ := dora(t, e, hw, 10)
		if !ip.IsValid() {
			continue // this node's half is full
		}
		if other, ok := given[ip]; ok {
			t.Fatalf("%v given to %s and %s", ip, other, hw)
		}
		given[ip] = hw.String()
		// The other node, which does not know this lease, refuses an
		// INIT-REBOOT for an address it does not own.
		other := b
		if e == b {
			other = a
		}
		r := other.Handle(context.Background(), Packet{Msg: request(mac(9999), ip, netip.Addr{}), IfIndex: 10})
		if r != nil && r.Msg.MessageType() == dhcpv4.MessageTypeAck {
			t.Fatalf("other node acknowledged %v that it does not own", ip)
		}
	}
	if len(given) != 50 {
		t.Fatalf("expected the whole pool (50) to be used, got %d", len(given))
	}
}

// TestSelectingOtherServerKeepsItsOffer: in HA, the offer of the chosen
// server reaches the other node by lease sync; the REQUEST naming the other
// server must not release it.
func TestSelectingOtherServerKeepsItsOffer(t *testing.T) {
	e, _, now := newEngine(t)
	e.NodeID = "me"
	ctx := context.Background()
	sc := e.scopes[firstScope(e, "eth0.10")]
	ip := netip.MustParseAddr("10.0.10.120")
	hw := mac(55)
	e.ApplyRemote(ctx, []Lease{{ScopeID: sc.ID, IP: ip, MAC: hw.String(), State: StateOffered, Starts: *now,
		Ends: now.Add(time.Minute), Owner: "other", HLC: now.UnixMilli() + 1}})
	req := request(hw, ip, netip.MustParseAddr("10.0.10.3")) // server id of the other node
	if r := e.Handle(ctx, Packet{Msg: req, IfIndex: 10}); r != nil {
		t.Fatal("answered a request for another server")
	}
	for _, l := range e.Leases() {
		if l.IP == ip && l.State != StateOffered {
			t.Fatalf("other node's offer changed to %s", l.State)
		}
	}
}

func TestLoadBalanceMaxSecs(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	mine := ClientHash(discover(mac(61)))
	e.mu.Lock()
	e.Serves = func(b uint8) bool { return b != mine } // this client belongs to the partner
	e.mu.Unlock()
	if r := e.Handle(ctx, Packet{Msg: discover(mac(61)), IfIndex: 10}); r != nil {
		t.Fatal("answered the partner's client")
	}
	// The client has been waiting 6 s: the partner is probably down or restarting.
	waited := discover(mac(61), func(d *dhcpv4.DHCPv4) { d.NumSeconds = 6 })
	if r := e.Handle(ctx, Packet{Msg: waited, IfIndex: 10}); r == nil {
		t.Fatal("client waiting for 6 s not answered")
	}
}

// scopesOf returns copies of the engine's scopes (to change the config).
func scopesOf(e *Engine) map[string]*dhcpconf.Scope {
	out := map[string]*dhcpconf.Scope{}
	for id, s := range e.scopes {
		c := *s.Scope
		out[id] = &c
	}
	return out
}

func setConfig(e *Engine, scopes map[string]*dhcpconf.Scope, res ...*dhcpconf.Reservation) {
	list := []*dhcpconf.Scope{}
	for _, s := range scopes {
		list = append(list, s)
	}
	e.SetConfig(list, res)
}

func renew(hw net.HardwareAddr, ip netip.Addr) *dhcpv4.DHCPv4 {
	m, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithHwAddr(hw), dhcpv4.WithClientIP(net.IP(ip.AsSlice())))
	return m
}

func leaseOf(e *Engine, ip netip.Addr) *Lease {
	for _, l := range e.Leases() {
		if l.IP == ip {
			return &l
		}
	}
	return nil
}

// An IPv6 address (UI release, lease sync) must not panic with the engine
// lock held: the DHCP service would be stuck.
func TestIPv6AddressDoesNotLockEngine(t *testing.T) {
	e, _, now := newEngine(t)
	ctx := context.Background()
	id := firstScope(e, "eth0.10")
	for _, ip := range []string{"::1", "::ffff:10.0.10.100"} {
		if _, err := e.Release(ctx, id, netip.MustParseAddr(ip)); err != store.ErrNotFound {
			t.Fatalf("release %s: %v", ip, err)
		}
	}
	if _, err := e.Release(ctx, id, netip.Addr{}); err != store.ErrNotFound {
		t.Fatalf("release zero address: %v", err)
	}
	e.ApplyRemote(ctx, []Lease{{ScopeID: id, IP: netip.MustParseAddr("fe80::1"), MAC: "x", State: StateBound, Ends: now.Add(time.Hour), HLC: 1},
		{ScopeID: id, MAC: "y", State: StateBound, Ends: now.Add(time.Hour), HLC: 1}})
	done := make(chan struct{})
	go func() { e.Leases(); dora(t, e, mac(1), 10); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("engine locked")
	}
}

// A renewal of an address that the configuration no longer allows
// (reservation for another client, exclusion) gets a NAK.
func TestRenewNakWhenAddressNoLongerAllowed(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	id := firstScope(e, "eth0.10")
	a, _ := dora(t, e, mac(1), 10)
	b, _ := dora(t, e, mac(2), 10)
	scopes := scopesOf(e)
	scopes[id].Exclusions = []dhcpconf.Range{{Start: b.String(), End: b.String()}}
	setConfig(e, scopes, &dhcpconf.Reservation{ID: "r1", ScopeID: id, MAC: mac(3).String(), IP: a.String()})
	for hw, ip := range map[int]netip.Addr{1: a, 2: b} {
		r := e.Handle(ctx, Packet{Msg: renew(mac(hw), ip), IfIndex: 10})
		if r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeNak {
			t.Fatalf("renewal of %v not refused: %v", ip, r)
		}
	}
	// The reservation owner gets the address.
	if ip, _ := dora(t, e, mac(3), 10); ip != a {
		t.Fatalf("reserved address: got %v", ip)
	}
}

// A client moving to a new address (here its new reservation) ends its old
// lease: the end of the old lease must not remove the DNS records of the new
// one (they share the DNS owner key).
func TestMovedClientOldLeaseEndKeepsDNS(t *testing.T) {
	e, h, now := newEngine(t)
	ctx := context.Background()
	id := firstScope(e, "eth0.10")
	old, _ := dora(t, e, mac(1), 10)
	nw := netip.MustParseAddr("10.0.10.140")
	setConfig(e, scopesOf(e), &dhcpconf.Reservation{ID: "r1", ScopeID: id, MAC: mac(1).String(), IP: nw.String()})
	if r := e.Handle(ctx, Packet{Msg: renew(mac(1), old), IfIndex: 10}); r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("renewal of the old address: %v", r)
	}
	*now = now.Add(10 * time.Minute)
	if ip, _ := dora(t, e, mac(1), 10); ip != nw {
		t.Fatalf("got %v", ip)
	}
	if l := leaseOf(e, old); l == nil || l.State != StateReleased {
		t.Fatalf("old lease: %+v", l)
	}
	// Neither the UI release nor the expiry of the old lease ends DNS.
	if _, err := e.Release(ctx, id, old); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Hour)
	e.Sweep(ctx)
	if h.ended != 1 { // only the new lease, now expired
		t.Fatalf("ended hooks = %d", h.ended)
	}
}

// A lease received from a peer whose clock is ahead must not make the peer
// reject our later changes of that lease.
func TestHLCMonotonic(t *testing.T) {
	e, _, now := newEngine(t)
	e.NodeID = "a"
	ctx := context.Background()
	id := firstScope(e, "eth0.10")
	ip := netip.MustParseAddr("10.0.10.120")
	future := now.Add(time.Hour).UnixMilli()
	e.ApplyRemote(ctx, []Lease{{ScopeID: id, IP: ip, MAC: mac(1).String(), State: StateBound, Starts: *now,
		Ends: now.Add(time.Hour), Owner: "b", HLC: future}})
	if r := e.Handle(ctx, Packet{Msg: renew(mac(1), ip), IfIndex: 10}); r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("renew: %v", r)
	}
	l := leaseOf(e, ip)
	if l.HLC <= future {
		t.Fatalf("local change HLC %d not after the peer's %d", l.HLC, future)
	}
	// Any later local change is also ordered after what was seen.
	other, _ := dora(t, e, mac(2), 10)
	if o := leaseOf(e, other); o.HLC <= l.HLC {
		t.Fatalf("HLC went back: %d after %d", o.HLC, l.HLC)
	}
}

// Relayed requests: the network named by the relay (giaddr, 82.5, 118) wins
// over the relay agent list of another scope, whatever the map order.
func TestRelayScopeSelectionPrefersNetwork(t *testing.T) {
	e, _, _ := newEngine(t)
	scopes := scopesOf(e)
	var s40 string
	for id, s := range scopes {
		if s.Relay {
			s40 = id
			s.RelayAgents = []string{"10.0.40.1"}
		}
	}
	for n := 60; n < 66; n++ {
		sc := scope(fmt.Sprint("s", n), "", n, true)
		sc.RelayAgents = []string{"10.0.40.1"}
		scopes[sc.ID] = sc
	}
	setConfig(e, scopes)
	sel := func(mods ...dhcpv4.Modifier) string {
		m := discover(mac(1), append([]dhcpv4.Modifier{dhcpv4.WithGatewayIP(net.IP{10, 0, 40, 1})}, mods...)...)
		e.mu.Lock()
		defer e.mu.Unlock()
		if s, _ := e.selectScope(Packet{Msg: m, IfIndex: 1}); s != nil {
			return s.ID
		}
		return ""
	}
	for i := 0; i < 30; i++ {
		if got := sel(); got != s40 {
			t.Fatalf("giaddr 10.0.40.1: got scope %s", got)
		}
		if got := sel(dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionSubnetSelection, []byte{10, 0, 62, 0}))); got != "s62" {
			t.Fatalf("subnet selection 10.0.62.0: got scope %s", got)
		}
		o82 := dhcpv4.OptRelayAgentInfo(dhcpv4.OptGeneric(subLinkSelection, []byte{10, 0, 64, 0}))
		if got := sel(dhcpv4.WithOption(o82)); got != "s64" {
			t.Fatalf("link selection 10.0.64.0: got scope %s", got)
		}
		// No scope holds the selected network: relay agent list, first scope by ID.
		if got := sel(dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionSubnetSelection, []byte{10, 0, 99, 0}))); got != min(s40, "s60") {
			t.Fatalf("fallback: got scope %s", got)
		}
	}
}

// Active-passive: the passive node never answers, even a client that has
// been waiting (the max-seconds fallback is for load balancing only).
func TestPassiveNodeNeverAnswers(t *testing.T) {
	e, _, now := newEngine(t)
	ctx := context.Background()
	id := firstScope(e, "eth0.10")
	ip := netip.MustParseAddr("10.0.10.120")
	// A lease known by sync from the active node.
	e.ApplyRemote(ctx, []Lease{{ScopeID: id, IP: ip, MAC: mac(1).String(), State: StateBound, Starts: *now,
		Ends: now.Add(time.Hour), Owner: "active", HLC: now.UnixMilli()}})
	e.SetPolicy(func(string, uint32) bool { return false }, func(byte) bool { return false })
	waited := func(d *dhcpv4.DHCPv4) { d.NumSeconds = 30 }
	for i, m := range []*dhcpv4.DHCPv4{discover(mac(1), waited), discover(mac(2), waited), request(mac(1), ip, netip.Addr{}, waited)} {
		if r := e.Handle(ctx, Packet{Msg: m, IfIndex: 10}); r != nil {
			t.Fatalf("message %d answered by the passive node: %v", i, r.Msg.MessageType())
		}
	}
}

// A lease released from the UI gets a NAK at renewal.
func TestUIReleaseNaksRenewal(t *testing.T) {
	e, _, _ := newEngine(t)
	ctx := context.Background()
	ip, _ := dora(t, e, mac(1), 10)
	if _, err := e.Release(ctx, firstScope(e, "eth0.10"), ip); err != nil {
		t.Fatal(err)
	}
	if r := e.Handle(ctx, Packet{Msg: renew(mac(1), ip), IfIndex: 10}); r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("renewal after release: %v", r)
	}
	if ip2, _ := dora(t, e, mac(1), 10); !ip2.IsValid() {
		t.Fatal("no new lease after the NAK")
	}
}

// Only the client holding an address may decline it; declining a bound
// lease ends its DNS records.
func TestDeclineNeedsOwnLease(t *testing.T) {
	e, h, _ := newEngine(t)
	ctx := context.Background()
	decline := func(hw net.HardwareAddr, ip netip.Addr) {
		m, _ := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline), dhcpv4.WithHwAddr(hw),
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.IP(ip.AsSlice()))))
		e.Handle(ctx, Packet{Msg: m, IfIndex: 10})
	}
	ip, _ := dora(t, e, mac(1), 10)
	free := netip.MustParseAddr("10.0.10.140")
	decline(mac(9), ip)
	decline(mac(9), free)
	if l := leaseOf(e, ip); l.State != StateBound || l.MAC != mac(1).String() {
		t.Fatalf("lease declined by another client: %+v", l)
	}
	if l := leaseOf(e, free); l != nil {
		t.Fatalf("free address declined by an unknown client: %+v", l)
	}
	decline(mac(1), ip)
	if l := leaseOf(e, ip); l.State != StateDeclined {
		t.Fatalf("own lease not declined: %+v", l)
	}
	if h.ended != 1 {
		t.Fatalf("ended hooks = %d", h.ended)
	}
}

// The per-MAC rate limit of "ignored" events is purged.
func TestIgnoredRateLimitPurged(t *testing.T) {
	e, _, now := newEngine(t)
	ctx := context.Background()
	e.OnEvent = func(Event) {}
	for i := 0; i < 10; i++ {
		e.Handle(ctx, Packet{Msg: discover(mac(i)), IfIndex: 50})
	}
	count := func() (n int) { e.ignored.Range(func(any, any) bool { n++; return true }); return }
	if count() != 10 {
		t.Fatalf("ignored entries = %d", count())
	}
	*now = now.Add(2 * time.Minute)
	e.Sweep(ctx)
	if count() != 0 {
		t.Fatalf("ignored entries after sweep = %d", count())
	}
}

// Renew-only (no address owned, e.g. a node cut from its peer): an active
// lease is still renewed, but an expired one is not handed out again.
func TestRenewOnlyKeepsActiveLeasesOnly(t *testing.T) {
	e, _, now := newEngine(t)
	ctx := context.Background()
	active, _ := dora(t, e, mac(1), 10)
	expired, _ := dora(t, e, mac(2), 10)
	if !active.IsValid() || !expired.IsValid() {
		t.Fatal("no lease")
	}
	e.SetPolicy(func(string, uint32) bool { return false }, func(byte) bool { return true })
	// Lease time is long enough for one hour; move past the end of mac(2)'s
	// lease after renewing mac(1)'s.
	*now = now.Add(time.Duration(e.scopes[firstScope(e, "eth0.10")].LeaseTime) * time.Second / 2)
	if r := e.Handle(ctx, Packet{Msg: renew(mac(1), active), IfIndex: 10}); r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("renewal of an active lease: %v", r)
	}
	*now = now.Add(time.Duration(e.scopes[firstScope(e, "eth0.10")].LeaseTime)*time.Second/2 + time.Minute)
	if r := e.Handle(ctx, Packet{Msg: discover(mac(2)), IfIndex: 10}); r != nil {
		t.Fatalf("expired address offered again in renew-only: %v", ipOf(r.Msg.YourIPAddr))
	}
	if r := e.Handle(ctx, Packet{Msg: request(mac(2), expired, netip.Addr{}), IfIndex: 10}); r == nil || r.Msg.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("INIT-REBOOT on an expired lease in renew-only: %v", r)
	}
}
