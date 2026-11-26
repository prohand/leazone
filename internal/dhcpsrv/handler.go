package dhcpsrv

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/prohand/leazone/internal/dhcpconf"
)

// Packet is a received request with its arrival context.
type Packet struct {
	Msg     *dhcpv4.DHCPv4
	IfIndex int        // receiving interface
	Dst     netip.Addr // destination address (broadcast or one of ours)
}

// Reply is what to send back.
type Reply struct {
	Msg       *dhcpv4.DHCPv4
	To        netip.Addr // destination IP
	ToRelay   bool       // send to the relay (server port) instead of the client port
	Broadcast bool       // 255.255.255.255 on IfIndex
	IfIndex   int
	Src       netip.Addr // our address (server identifier)
}

// Relay agent sub-options (RFC 3046, RFC 3527).
var (
	subCircuitID     = dhcpv4.GenericOptionCode(1)
	subRemoteID      = dhcpv4.GenericOptionCode(2)
	subLinkSelection = dhcpv4.GenericOptionCode(5)
)

func ipOf(b net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(b.To4())
	if !ok {
		return netip.Addr{}
	}
	return a
}

// printable renders a relay sub-option: text when printable, else hex.
func printable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range string(b) {
		if c > unicode.MaxASCII || !unicode.IsPrint(c) {
			return hex.EncodeToString(b)
		}
	}
	return string(b)
}

func clientIDOf(m *dhcpv4.DHCPv4) string {
	b := m.Options.Get(dhcpv4.OptionClientIdentifier)
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = hex.EncodeToString([]byte{v})
	}
	return strings.Join(parts, ":")
}

// selectScope finds the scope for a request, or nil (the request is
// ignored). It never falls back to another scope: a client only ever gets
// an address of the network it is attached to. It also returns our address
// to use as server identifier.
func (e *Engine) selectScope(p Packet) (*scopeRT, netip.Addr) {
	m := p.Msg
	gi := ipOf(m.GatewayIPAddr)
	if gi.IsValid() && !gi.IsUnspecified() {
		// Relayed: link selection (82.5) or subnet selection (118) first.
		sel := gi
		if ri := m.RelayAgentInfo(); ri != nil {
			if b := ri.Get(subLinkSelection); len(b) == 4 {
				sel = netip.AddrFrom4([4]byte(b))
			}
		}
		if b := m.Options.Get(dhcpv4.OptionSubnetSelection); len(b) == 4 {
			sel = netip.AddrFrom4([4]byte(b))
		}
		for _, s := range e.scopes {
			if !s.Enabled || !s.Relay {
				continue
			}
			match := s.prefix.Contains(sel)
			for _, a := range s.RelayAgents {
				if a == gi.String() {
					match = true
				}
			}
			if match {
				return s, e.localAddr(p, s)
			}
		}
		return nil, netip.Addr{}
	}
	it, ok := e.ifaces[p.IfIndex]
	if !ok || !e.dhcpOn[it.Name] {
		return nil, netip.Addr{}
	}
	var found *scopeRT
	for _, s := range e.scopes {
		if !s.Enabled || s.Interface == nil || *s.Interface != it.Name {
			continue
		}
		if found == nil {
			found = s
			continue
		}
		// Several scopes on one interface: the one holding the interface IP.
		for _, a := range it.IPv4() {
			if s.prefix.Contains(a) {
				found = s
			}
		}
	}
	if found == nil {
		return nil, netip.Addr{}
	}
	var src netip.Addr
	for _, a := range it.IPv4() {
		if found.prefix.Contains(a) {
			src = a
			break
		}
	}
	if !src.IsValid() {
		if v4 := it.IPv4(); len(v4) > 0 {
			src = v4[0]
		}
	}
	return found, src
}

// localAddr returns our address for a relayed request: the unicast
// destination, else an interface address (the relay targets one of them).
func (e *Engine) localAddr(p Packet, s *scopeRT) netip.Addr {
	if p.Dst.IsValid() && p.Dst.Is4() && !p.Dst.IsMulticast() && p.Dst != netip.AddrFrom4([4]byte{255, 255, 255, 255}) && !p.Dst.IsUnspecified() {
		return p.Dst
	}
	if it, ok := e.ifaces[p.IfIndex]; ok {
		if v4 := it.IPv4(); len(v4) > 0 {
			return v4[0]
		}
	}
	return netip.Addr{}
}

// Handle processes one request and returns the reply (nil = no answer).
func (e *Engine) Handle(ctx context.Context, p Packet) *Reply {
	m := p.Msg
	if m.OpCode != dhcpv4.OpcodeBootRequest {
		return nil
	}
	mt := m.MessageType()
	mac := m.ClientHWAddr.String()
	cid := clientIDOf(m)

	e.mu.Lock()
	s, src := e.selectScope(p)
	if s == nil {
		e.mu.Unlock()
		e.log.Debug("DHCP request ignored: no scope for this interface/relay", "type", mt, "mac", mac,
			"giaddr", m.GatewayIPAddr, "ifindex", p.IfIndex)
		return nil
	}
	if !src.IsValid() {
		e.mu.Unlock()
		e.log.Warn("DHCP: no local IPv4 address to answer from", "scope", s.Name)
		return nil
	}
	e.mu.Unlock()

	if !e.answers(p, mt, src) {
		return nil
	}
	switch mt {
	case dhcpv4.MessageTypeDiscover:
		return e.discover(ctx, p, s, src, mac, cid)
	case dhcpv4.MessageTypeRequest:
		r := e.request(ctx, p, s, src, mac, cid)
		if r != nil && r.Msg.MessageType() == dhcpv4.MessageTypeAck && e.Sync != nil {
			// The peer must know the lease before the client uses it.
			e.Sync(ctx)
		}
		return r
	case dhcpv4.MessageTypeDecline:
		e.decline(ctx, p, s, mac, cid)
	case dhcpv4.MessageTypeRelease:
		e.release(ctx, p, s, mac, cid)
	case dhcpv4.MessageTypeInform:
		return e.reply(p, s, src, dhcpv4.MessageTypeAck, netip.Addr{}, 0)
	}
	return nil
}

// answers applies the HA rules: in load balancing each client is served
// by the node owning its RFC 3074 bucket. A client that picked us (server
// identifier) or renews by unicast to our address is always answered.
func (e *Engine) answers(p Packet, mt dhcpv4.MessageType, src netip.Addr) bool {
	m := p.Msg
	switch mt {
	case dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return true
	case dhcpv4.MessageTypeRequest:
		if sid := ipOf(m.ServerIdentifier()); sid.IsValid() && !sid.IsUnspecified() {
			return true // SELECTING: handled (ignored if another server was chosen)
		}
		if ci := ipOf(m.ClientIPAddr); ci.IsValid() && !ci.IsUnspecified() && p.Dst == src {
			return true // RENEWING: unicast to us
		}
	}
	e.mu.Lock()
	serves := e.Serves
	e.mu.Unlock()
	return serves(ClientHash(m))
}

func (e *Engine) leaseFields(p Packet, l *Lease) {
	m := p.Msg
	if h := dhcpconf.Hostname(m.HostName()); h != "" {
		l.Hostname = h
	}
	if gi := ipOf(m.GatewayIPAddr); gi.IsValid() && !gi.IsUnspecified() {
		l.GIAddr = gi.String()
	} else {
		l.GIAddr = ""
	}
	if ri := m.RelayAgentInfo(); ri != nil {
		l.CircuitID = printable(ri.Get(subCircuitID))
		l.RemoteID = printable(ri.Get(subRemoteID))
	}
}

func (e *Engine) discover(ctx context.Context, p Packet, s *scopeRT, src netip.Addr, mac, cid string) *Reply {
	requested := ipOf(p.Msg.RequestedIPAddress())
	skip := map[uint32]bool{}
	for attempt := 0; attempt < 4; attempt++ {
		e.mu.Lock()
		now := e.Now()
		ip, ok := e.pick(s, mac, cid, requested, now, skip)
		if !ok {
			e.mu.Unlock()
			e.log.Warn("DHCP pool exhausted", "scope", s.Name, "mac", mac)
			return nil
		}
		u := dhcpconf.U32(ip)
		cur := e.leaseAt(s.ID, u)
		known := cur != nil && cur.sameClient(mac, cid) && cur.State == StateBound && cur.Active(now)
		needPing := s.PingCheck && e.Pinger != nil && !known
		if needPing {
			if e.pending[s.ID] == nil {
				e.pending[s.ID] = map[uint32]bool{}
			}
			e.pending[s.ID][u] = true
		}
		e.mu.Unlock()

		if needPing {
			inUse := e.Pinger.InUse(ctx, ip)
			e.mu.Lock()
			delete(e.pending[s.ID], u)
			if inUse {
				e.log.Warn("DHCP: address answers to ping, marked as in conflict", "ip", ip, "scope", s.Name)
				e.store(ctx, &Lease{ScopeID: s.ID, IP: ip, State: StateDeclined, Starts: now, Ends: now.Add(declineHold)})
				e.mu.Unlock()
				skip[u] = true
				continue
			}
			e.mu.Unlock()
		}

		e.mu.Lock()
		now = e.Now()
		// Re-check after the ping: another request may have taken it.
		if !e.usable(s, u, mac, cid, now) && s.reservationFor(mac, cid) == nil {
			e.mu.Unlock()
			skip[u] = true
			continue
		}
		l := &Lease{ScopeID: s.ID, IP: ip, MAC: mac, ClientID: cid, State: StateOffered, Starts: now, Ends: now.Add(offerHold)}
		if cur != nil && cur.sameClient(mac, cid) {
			l.Hostname, l.DNSName = cur.Hostname, cur.DNSName
			if cur.State == StateBound && cur.Active(now) {
				// A bound client re-discovering keeps its lease bound.
				l.State, l.Starts, l.Ends = StateBound, cur.Starts, cur.Ends
			}
		}
		e.leaseFields(p, l)
		e.store(ctx, l)
		e.mu.Unlock()
		return e.reply(p, s, src, dhcpv4.MessageTypeOffer, ip, time.Duration(s.LeaseTime)*time.Second)
	}
	return nil
}

func (e *Engine) nak(p Packet, s *scopeRT, src netip.Addr) *Reply {
	return e.reply(p, s, src, dhcpv4.MessageTypeNak, netip.Addr{}, 0)
}

func (e *Engine) request(ctx context.Context, p Packet, s *scopeRT, src netip.Addr, mac, cid string) *Reply {
	m := p.Msg
	sid := ipOf(m.ServerIdentifier())
	ciaddr := ipOf(m.ClientIPAddr)
	want := ipOf(m.RequestedIPAddress())
	if !want.IsValid() || want.IsUnspecified() {
		want = ciaddr // RENEWING / REBINDING
	}
	if sid.IsValid() && !sid.IsUnspecified() && sid != src {
		// SELECTING another server's offer: free ours.
		e.mu.Lock()
		// Only our own offer: the chosen server's offer reached us through
		// lease sync and must stay untouched.
		if l := e.clientLease(s.ID, mac, cid); l != nil && l.State == StateOffered && (l.Owner == "" || l.Owner == e.NodeID) {
			nl := *l
			nl.State, nl.Ends = StateReleased, e.Now()
			e.store(ctx, &nl)
		}
		e.mu.Unlock()
		return nil
	}
	if !want.IsValid() || want.IsUnspecified() {
		return e.nak(p, s, src)
	}
	// Isolation: an address outside this scope's network is always refused.
	if !s.prefix.Contains(want) {
		e.log.Info("DHCP NAK: requested address is not in the client's network", "mac", mac, "ip", want, "scope", s.Name)
		return e.nak(p, s, src)
	}
	e.mu.Lock()
	now := e.Now()
	u := dhcpconf.U32(want)
	cur := e.leaseAt(s.ID, u)
	mine := cur != nil && cur.sameClient(mac, cid) && (cur.State == StateOffered || cur.State == StateBound)
	r := s.reservationFor(mac, cid)
	switch {
	case r != nil && r.IP != want.String():
		e.mu.Unlock()
		return e.nak(p, s, src) // the client must move to its reserved address
	case mine:
	case r != nil:
		// Reserved for this client but no lease yet (e.g. after a restart).
		if cur != nil && cur.Active(now) && !cur.sameClient(mac, cid) {
			e.mu.Unlock()
			return e.nak(p, s, src)
		}
	default:
		// INIT-REBOOT or renewal of a lease we do not know (lost database,
		// other node...): accept only if the address is free and allocatable.
		if !e.usable(s, u, mac, cid, now) || (cur == nil && !e.Owns(s.ID, u)) {
			e.mu.Unlock()
			e.log.Info("DHCP NAK: address not available", "mac", mac, "ip", want, "scope", s.Name)
			return e.nak(p, s, src)
		}
	}
	lt := time.Duration(s.LeaseTime) * time.Second
	l := &Lease{ScopeID: s.ID, IP: want, MAC: mac, ClientID: cid, State: StateBound, Starts: now, Ends: now.Add(lt)}
	wasBound := cur != nil && cur.State == StateBound && cur.sameClient(mac, cid) && cur.Active(now)
	if cur != nil && cur.sameClient(mac, cid) {
		l.Hostname, l.DNSName = cur.Hostname, cur.DNSName
	}
	e.leaseFields(p, l)
	nameChanged := cur == nil || cur.Hostname != l.Hostname
	e.store(ctx, l)
	e.mu.Unlock()

	if e.Hooks != nil && (!wasBound || nameChanged || l.DNSName == "") {
		if name := e.Hooks.Bound(ctx, s.Scope, *l); name != l.DNSName {
			e.mu.Lock()
			if cur := e.leaseAt(s.ID, u); cur != nil && cur.sameClient(mac, cid) {
				c := *cur
				c.DNSName = name
				e.store(ctx, &c)
			}
			e.mu.Unlock()
		}
	}
	return e.reply(p, s, src, dhcpv4.MessageTypeAck, want, lt)
}

func (e *Engine) decline(ctx context.Context, p Packet, s *scopeRT, mac, cid string) {
	ip := ipOf(p.Msg.RequestedIPAddress())
	if !ip.IsValid() || !s.prefix.Contains(ip) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	if cur := e.leaseAt(s.ID, dhcpconf.U32(ip)); cur != nil && !cur.sameClient(mac, cid) {
		return // only the client holding the address may decline it
	}
	e.log.Warn("DHCP DECLINE: address already used on the network", "ip", ip, "mac", mac, "scope", s.Name)
	e.store(ctx, &Lease{ScopeID: s.ID, IP: ip, State: StateDeclined, Starts: now, Ends: now.Add(declineHold)})
}

func (e *Engine) release(ctx context.Context, p Packet, s *scopeRT, mac, cid string) {
	ip := ipOf(p.Msg.ClientIPAddr)
	e.mu.Lock()
	cur := e.leaseAt(s.ID, dhcpconf.U32(ip))
	if cur == nil || !cur.sameClient(mac, cid) || cur.State != StateBound {
		e.mu.Unlock()
		return
	}
	was := *cur
	nl := *cur
	nl.State, nl.Ends, nl.DNSName = StateReleased, e.Now(), ""
	e.store(ctx, &nl)
	e.mu.Unlock()
	if e.Hooks != nil {
		e.Hooks.Ended(ctx, s.Scope, was)
	}
}

// reply builds an OFFER/ACK/NAK with the scope options and its destination.
func (e *Engine) reply(p Packet, s *scopeRT, src netip.Addr, mt dhcpv4.MessageType, yiaddr netip.Addr, lease time.Duration) *Reply {
	req := p.Msg
	mods := []dhcpv4.Modifier{dhcpv4.WithMessageType(mt), dhcpv4.WithServerIP(net.IP(src.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(src.AsSlice())))}
	if mt != dhcpv4.MessageTypeNak {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptSubnetMask(dhcpconf.Mask(s.prefix))),
			dhcpv4.WithOption(dhcpv4.OptBroadcastAddress(net.IP(dhcpconf.Broadcast(s.prefix).AsSlice()))))
		if yiaddr.IsValid() {
			mods = append(mods, dhcpv4.WithYourIP(net.IP(yiaddr.AsSlice())),
				dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(lease)),
				dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(lease/2)),
				dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(lease*7/8)))
		}
		if s.gateway.IsValid() {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptRouter(net.IP(s.gateway.AsSlice()))))
		}
		if ips := toIPs(s.DNSServers); len(ips) > 0 {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDNS(ips...)))
		}
		if ips := toIPs(s.NTPServers); len(ips) > 0 {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptNTPServers(ips...)))
		}
		if s.Domain != "" {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(s.Domain)))
		}
		for _, o := range s.Options {
			if b, err := o.Encode(); err == nil {
				mods = append(mods, dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(o.Code), b)))
			}
		}
	}
	// RFC 3046: echo the relay agent information.
	if raw := req.Options.Get(dhcpv4.OptionRelayAgentInformation); len(raw) > 0 {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionRelayAgentInformation, raw)))
	}
	msg, err := dhcpv4.NewReplyFromRequest(req, mods...)
	if err != nil {
		e.log.Error("DHCP reply build failed", "err", err)
		return nil
	}
	r := &Reply{Msg: msg, Src: src, IfIndex: p.IfIndex}
	gi := ipOf(req.GatewayIPAddr)
	ci := ipOf(req.ClientIPAddr)
	switch {
	case gi.IsValid() && !gi.IsUnspecified():
		r.To, r.ToRelay, r.IfIndex = gi, true, 0
		if mt == dhcpv4.MessageTypeNak {
			msg.SetBroadcast() // the relay must broadcast a NAK
		}
	case mt == dhcpv4.MessageTypeNak:
		r.Broadcast = true
	case ci.IsValid() && !ci.IsUnspecified():
		r.To = ci
	default:
		// No IP yet: broadcast on the receiving interface (works with every
		// client without writing the host ARP table).
		r.Broadcast = true
	}
	return r
}

func toIPs(list []string) []net.IP {
	var out []net.IP
	for _, s := range list {
		if ip := net.ParseIP(s).To4(); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
