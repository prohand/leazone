package dnssrv

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssec"
	"github.com/prohand/leazone/internal/ratelimit"
)

// Sources of an answer (for the lookup tool and, later, query logs).
const (
	SourceLocal     = "local"
	SourceCache     = "cache"
	SourceForwarder = "forwarder"
	SourceRefused   = "refused"
	SourceBlocked   = "blocked"
	SourceError     = "error"
)

// Blocker decides whether a recursive query is blocked (ad blocking).
type Blocker interface {
	Filter(name string, client, local netip.Addr, count bool) (blocked, nullIP bool)
}

// QueryInfo describes an answered query (logs, statistics).
type QueryInfo struct {
	Time    time.Time
	Client  netip.Addr
	Name    string
	Type    uint16
	Rcode   int
	Source  string
	Latency time.Duration
	Answer  string // first answer, short form
}

// DNSSECConfig is the DNSSEC input of the engine.
type DNSSECConfig struct {
	Keys     map[string][]*dnssec.Key // signing keys by zone id (empty = no signing)
	NSECMode map[string]string        // "nsec" or "nsec3" by zone id
	Validate bool                     // validate forwarded answers
}

// state is the immutable configuration used to answer queries.
type state struct {
	zones     *zoneSet
	fwd       *forwarders
	recursion []netip.Prefix
}

// Engine answers DNS queries and manages listeners.
type Engine struct {
	log   *slog.Logger
	port  int
	roots *x509.CertPool // nil = system roots (tests inject their own)

	st    atomic.Pointer[state]
	cache *cache
	sf    singleflight.Group

	mu        sync.Mutex
	listeners map[string]*listener // by IP

	blocker   Blocker
	observer  func(*QueryInfo)
	dnssecCfg atomic.Pointer[DNSSECConfig]
	sigs      *sigCache
	anchors   []*dns.DS
	validator atomic.Pointer[validator]
	signedWin atomic.Uint64 // inception of the signatures in use (0 = none)

	// Abuse limits: response rate per source network for clients outside
	// the recursion networks (UDP), recursive queries in flight, TCP
	// connections.
	rrl      *ratelimit.Limiter[netip.Prefix]
	slip     atomic.Uint64
	inflight chan struct{}
	clientMu sync.Mutex
	perCli   map[netip.Addr]int
	tcp      *connLimits

	queries, local, forwarded, refused, failed, blocked, bogus, limited atomic.Uint64
}

// Abuse limits.
const (
	// maxUDPSize caps UDP answers whatever the client's EDNS buffer size
	// (DNS flag day 2020: no IP fragmentation, smaller reflection).
	maxUDPSize = 1232
	// Response rate limiting, per /24 (IPv4) or /56 (IPv6), only for the
	// clients outside the recursion networks: beyond, every other answer is
	// replaced by an empty truncated one (a real client retries over TCP)
	// and the others are dropped.
	rrlRate  = 20
	rrlBurst = 40
	rrlKeys  = 65536
	// Recursive queries in flight (waiting for the forwarders), in all
	// and per client: beyond, SERVFAIL at once.
	maxInflight       = 1000
	maxInflightClient = 100
)

// rrlKey is the source network a client is limited with.
func rrlKey(a netip.Addr) netip.Prefix {
	bits := 24
	if a.Is6() {
		bits = 56
	}
	p, _ := a.Prefix(bits)
	return p
}

// acquireRecursion takes a slot for a recursive query of client.
func (e *Engine) acquireRecursion(client netip.Addr) (release func(), ok bool) {
	select {
	case e.inflight <- struct{}{}:
	default:
		return nil, false
	}
	e.clientMu.Lock()
	if e.perCli[client] >= maxInflightClient {
		e.clientMu.Unlock()
		<-e.inflight
		return nil, false
	}
	e.perCli[client]++
	e.clientMu.Unlock()
	return func() {
		e.clientMu.Lock()
		if e.perCli[client]--; e.perCli[client] <= 0 {
			delete(e.perCli, client)
		}
		e.clientMu.Unlock()
		<-e.inflight
	}, true
}

// New creates an engine listening on the given port (53 in production).
func New(log *slog.Logger, port int) *Engine {
	e := &Engine{log: log, port: port, cache: newCache(), listeners: map[string]*listener{}, sigs: newSigCache(),
		rrl: ratelimit.New[netip.Prefix](rrlRate, rrlBurst, rrlKeys), inflight: make(chan struct{}, maxInflight),
		perCli: map[netip.Addr]int{}, tcp: newConnLimits(maxTCPConns, maxTCPConnsPerIP)}
	e.anchors, _ = ParseAnchors(RootAnchors)
	e.st.Store(&state{zones: &zoneSet{zones: map[string]*zoneData{}}, fwd: &forwarders{}})
	return e
}

// SetRootCAs replaces the trusted roots for DoT/DoH (tests only).
func (e *Engine) SetRootCAs(p *x509.CertPool) { e.roots = p }

// SetObserver installs a function called after each answer (before
// serving). It must not block.
func (e *Engine) SetObserver(f func(*QueryInfo)) { e.observer = f }

// SetBlocker installs the ad blocker (before serving).
func (e *Engine) SetBlocker(b Blocker) { e.blocker = b }

// SetTrustAnchors replaces the root trust anchors (tests only).
func (e *Engine) SetTrustAnchors(a []*dns.DS) { e.anchors = a }

// SetDNSSEC sets the DNSSEC configuration used by the next Load.
func (e *Engine) SetDNSSEC(c DNSSECConfig) { e.dnssecCfg.Store(&c) }

// NeedsResign reports whether signed zones should be reloaded to renew
// their signatures (the validity window moves every day).
func (e *Engine) NeedsResign(now time.Time) bool {
	w := e.signedWin.Load()
	inc, _ := sigWindow(now)
	return w != 0 && w != uint64(inc)
}

// Port is the DNS port.
func (e *Engine) Port() int { return e.port }

// Load applies a full configuration snapshot. It is cheap enough to call
// after every change (LAN-sized zones).
func (e *Engine) Load(zones []*dnsconf.Zone, recs map[string][]*dnsconf.Record, fwd []*dnsconf.Forwarder, st dnsconf.Settings) {
	old := e.st.Load()
	var nets []netip.Prefix
	for _, n := range st.RecursionNetworks {
		if p, err := netip.ParsePrefix(n); err == nil {
			nets = append(nets, p)
		}
	}
	e.cache.configure(st.CacheSize, st.CacheMinTTL, st.CacheMaxTTL, st.CacheNegativeMaxTTL)
	var sg *signing
	c := e.dnssecCfg.Load()
	if c != nil && len(c.Keys) > 0 {
		now := time.Now()
		sg = &signing{keys: c.Keys, nsec: c.NSECMode, now: now, cache: e.sigs}
		e.sigs.begin()
		defer e.sigs.end()
		inc, _ := sigWindow(now)
		e.signedWin.Store(uint64(inc))
	} else {
		e.signedWin.Store(0)
	}
	e.st.Store(&state{zones: buildZones(zones, recs, sg), fwd: buildForwarders(fwd, old.fwd, e.roots), recursion: nets})
	if c != nil && c.Validate {
		e.validator.Store(newValidator(e.anchors, func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			m, _, err := e.forward(ctx, e.st.Load(), dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}, true, true)
			return m, err
		}))
	} else {
		e.validator.Store(nil)
	}
}

// ServeDNS implements dns.Handler.
func (e *Engine) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	e.queries.Add(1)
	client := addrOf(w.RemoteAddr())
	_, udp := w.RemoteAddr().(*net.UDPAddr)
	if udp && !e.mayRecurse(e.st.Load(), client) && !e.rrl.Allow(rrlKey(client)) {
		e.limited.Add(1)
		if e.slip.Add(1)%2 == 0 {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			_ = w.WriteMsg(m)
		}
		return
	}
	start := time.Now()
	resp, src := e.handleFrom(context.Background(), r, client, addrOf(w.LocalAddr()))
	if resp == nil {
		return
	}
	if e.observer != nil && len(r.Question) == 1 {
		qi := &QueryInfo{Time: start, Client: client, Name: r.Question[0].Name, Type: r.Question[0].Qtype,
			Rcode: resp.Rcode, Source: src, Latency: time.Since(start)}
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			qi.Answer = strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
			if rr.Header().Rrtype != r.Question[0].Qtype {
				qi.Answer = dns.TypeToString[rr.Header().Rrtype] + " " + qi.Answer
			}
			if len(qi.Answer) > 120 {
				qi.Answer = qi.Answer[:120]
			}
			break
		}
		e.observer(qi)
	}
	if udp {
		size := dns.MinMsgSize
		if o := r.IsEdns0(); o != nil {
			size = min(int(max(o.UDPSize(), dns.MinMsgSize)), maxUDPSize)
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// handle builds the response for a query from client. It returns the source.
func (e *Engine) handle(ctx context.Context, r *dns.Msg, client netip.Addr) (*dns.Msg, string) {
	return e.handleFrom(ctx, r, client, netip.Addr{})
}

// handleFrom is handle for a query received on the local address local.
func (e *Engine) handleFrom(ctx context.Context, r *dns.Msg, client, local netip.Addr) (*dns.Msg, string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	var do bool
	if o := r.IsEdns0(); o != nil {
		do = o.Do()
		if o.Version() != 0 {
			m.SetRcode(r, dns.RcodeBadVers)
			m.SetEdns0(ednsSize, do)
			return m, SourceError
		}
	}
	var ede *dns.EDNS0_EDE
	finish := func(src string) (*dns.Msg, string) {
		if r.IsEdns0() != nil && m.IsEdns0() == nil {
			m.SetEdns0(ednsSize, do)
			if ede != nil {
				o := m.IsEdns0()
				o.Option = append(o.Option, ede)
			}
		}
		return m, src
	}
	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		return finish(SourceError)
	}
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return finish(SourceError)
	}
	q := r.Question[0]
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		m.Rcode = dns.RcodeNotImplemented
		return finish(SourceError)
	}
	st := e.st.Load()

	// 1. Local zones answer everyone. A delegation inside a local zone is
	// only a referral for clients that may not recurse (or when no forwarder
	// serves it): the others get it resolved like any recursive query.
	res := st.zones.answer(q.Name, q.Qtype, !e.mayRecurse(st, client))
	if res.authorized && !(res.referral && e.mayRecurse(st, client) && len(st.fwd.pick(q.Name)) > 0) {
		e.local.Add(1)
		m.Authoritative = res.msg.Authoritative
		m.Rcode = res.msg.Rcode
		m.Answer, m.Ns, m.Extra = res.msg.Answer, res.msg.Ns, res.msg.Extra
		if do {
			st.zones.addDNSSEC(m, q.Name, q.Qtype)
		}
		if res.cnameOut == "" || !e.mayRecurse(st, client) {
			return finish(SourceLocal)
		}
		// A local CNAME points outside: resolve the target like a recursive
		// query (ad blocking, DNSSEC validation).
		target := dns.Question{Name: res.cnameOut, Qtype: q.Qtype, Qclass: q.Qclass}
		release, ok := e.acquireRecursion(client)
		if !ok {
			e.limited.Add(1)
			m.Authoritative = false
			return finish(SourceLocal) // the local part of the chain only
		}
		defer release()
		up, _, src, x, err := e.recurse(ctx, st, m, q, target, r.CheckingDisabled, do, client, local, false)
		ede = x
		if err == nil && up == nil {
			return finish(src) // blocked or bogus
		}
		if err == nil {
			m.Answer = append(m.Answer, up.Answer...)
			m.Rcode = up.Rcode
		}
		m.Authoritative = false
		return finish(SourceLocal)
	}

	// 2. Recursion is limited to the allowed networks.
	if !e.mayRecurse(st, client) {
		e.refused.Add(1)
		m.Rcode = dns.RcodeRefused
		m.RecursionAvailable = false
		return finish(SourceRefused)
	}

	// 3. Ad blocking, cache or forwarders, DNSSEC validation.
	release, ok := e.acquireRecursion(client)
	if !ok {
		e.limited.Add(1)
		m.Rcode = dns.RcodeServerFailure
		return finish(SourceError)
	}
	defer release()
	up, secure, src, x, err := e.recurse(ctx, st, m, q, q, r.CheckingDisabled, do, client, local, true)
	ede = x
	if err != nil {
		e.failed.Add(1)
		m.Rcode = dns.RcodeServerFailure
		return finish(SourceError)
	}
	if up == nil {
		return finish(src)
	}
	if src == SourceForwarder {
		e.forwarded.Add(1)
	}
	m.Rcode = up.Rcode
	m.Answer, m.Ns = up.Answer, up.Ns
	for _, rr := range up.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			m.Extra = append(m.Extra, rr)
		}
	}
	// AD only when we validated it ourselves (RFC 6840 §5.8).
	m.AuthenticatedData = secure && (do || r.AuthenticatedData)
	return finish(src)
}

// recurse resolves q for a client allowed to recurse: ad blocking, cache or
// forwarders, DNSSEC validation (unless the client set CD) and CNAME
// cloaking. orig is the client's question (q itself, or the local name
// whose CNAME leads to q); count tells the blocker to count the query.
// It returns the upstream answer, without DNSSEC records when !do, and
// whether it was validated. A nil answer with a nil error means m was
// turned into the final answer (blocked name, bogus data) with ede.
func (e *Engine) recurse(ctx context.Context, st *state, m *dns.Msg, orig, q dns.Question, clientCD, do bool,
	client, local netip.Addr, count bool) (up *dns.Msg, secure bool, src string, ede *dns.EDNS0_EDE, err error) {
	if e.blocker != nil {
		if blocked, null := e.blocker.Filter(q.Name, client, local, count); blocked {
			e.blocked.Add(1)
			return nil, false, SourceBlocked, blockedReply(m, orig, null), nil
		}
	}
	v := e.validator.Load()
	cd := clientCD
	if v != nil {
		cd = true // get the signed data even if the forwarder finds it bogus
	}
	up, src, err = e.forward(ctx, st, q, do || v != nil, cd)
	if err != nil {
		return nil, false, SourceError, nil, err
	}
	if v != nil && !clientCD {
		status, why := v.checkCached(ctx, q, up)
		if status == vBogus {
			e.bogus.Add(1)
			e.log.Info("DNSSEC: bogus answer", "name", q.Name, "type", dns.TypeToString[q.Qtype], "reason", why)
			m.Answer, m.Ns, m.Extra = nil, nil, nil
			m.Rcode = dns.RcodeServerFailure
			m.Authoritative, m.AuthenticatedData = false, false
			return nil, false, SourceError, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: why}, nil
		}
		secure = status == vSecure
	}
	if e.blocker != nil {
		// CNAME cloaking: a tracker hidden behind a CNAME is blocked too.
		for _, rr := range up.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				if blocked, null := e.blocker.Filter(c.Target, client, local, false); blocked {
					e.blocked.Add(1)
					return nil, false, SourceBlocked, blockedReply(m, orig, null), nil
				}
			}
		}
	}
	if !do {
		up.Answer, up.Ns = stripDNSSEC(up.Answer, q.Qtype), stripDNSSEC(up.Ns, q.Qtype)
	}
	return up, secure, src, nil, nil
}

// blockedReply turns m into the answer for a blocked name.
func blockedReply(m *dns.Msg, q dns.Question, nullIP bool) *dns.EDNS0_EDE {
	m.Answer, m.Ns, m.Extra = nil, nil, nil
	m.Authoritative, m.AuthenticatedData = false, false
	if !nullIP {
		m.Rcode = dns.RcodeNameError
	} else {
		m.Rcode = dns.RcodeSuccess
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
		}
	}
	return &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: "bloqué par Leazone"}
}

func (e *Engine) mayRecurse(st *state, client netip.Addr) bool {
	for _, p := range st.recursion {
		if p.Contains(client) {
			return true
		}
	}
	return false
}

// forward answers from the cache or the upstreams, merging identical
// concurrent queries.
func (e *Engine) forward(ctx context.Context, st *state, q dns.Question, do, cd bool) (*dns.Msg, string, error) {
	q.Name = dns.Fqdn(q.Name)
	if m := e.cache.get(q, do, cd); m != nil {
		return m, SourceCache, nil
	}
	key := cacheKey(q, do, cd)
	v, err, _ := e.sf.Do(key, func() (any, error) {
		qm := new(dns.Msg)
		qm.SetQuestion(q.Name, q.Qtype)
		qm.Question[0].Qclass = q.Qclass
		qm.RecursionDesired = true
		qm.CheckingDisabled = cd
		qm.SetEdns0(ednsSize, do)
		r, _, err := st.fwd.resolve(ctx, qm)
		if err != nil {
			return nil, err
		}
		e.cache.set(q, do, cd, r)
		return r, nil
	})
	if err != nil {
		return nil, "", err
	}
	return v.(*dns.Msg).Copy(), SourceForwarder, nil
}

// LookupResult is returned by Lookup (UI test tool).
type LookupResult struct {
	Rcode     string   `json:"rcode"`
	Source    string   `json:"source"`
	Forwarder string   `json:"forwarder,omitempty"`
	LatencyMs float64  `json:"latencyMs"`
	Answers   []string `json:"answers"`
	Authority []string `json:"authority"`
}

// Lookup resolves a name as a local client would.
func (e *Engine) Lookup(ctx context.Context, name string, qtype uint16) LookupResult {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	start := time.Now()
	r, src := e.handle(ctx, q, netip.MustParseAddr("127.0.0.1"))
	res := LookupResult{Rcode: dns.RcodeToString[r.Rcode], Source: src, Answers: []string{}, Authority: []string{},
		LatencyMs: float64(time.Since(start).Microseconds()) / 1000}
	for _, rr := range r.Answer {
		res.Answers = append(res.Answers, rr.String())
	}
	for _, rr := range r.Ns {
		res.Authority = append(res.Authority, rr.String())
	}
	if src == SourceForwarder {
		if ups := e.st.Load().fwd.pick(name); len(ups) > 0 {
			for _, u := range ups {
				if h := u.health(); h.Healthy && h.LastCheckAt != nil {
					res.Forwarder = u.label()
					break
				}
			}
		}
	}
	return res
}

// FlushCache empties the cache (name == "") or one name and its sub-names.
func (e *Engine) FlushCache(name string) int {
	if v := e.validator.Load(); v != nil {
		v.flush()
	}
	return e.cache.flush(name)
}

// TestForwarder tests a forwarder configuration with the engine's roots.
func (e *Engine) TestForwarder(ctx context.Context, f dnsconf.Forwarder) TestResult {
	u := newUpstream(f, e.roots)
	defer u.close()
	q := new(dns.Msg)
	q.SetQuestion(".", dns.TypeNS)
	q.SetEdns0(ednsSize, false)
	start := time.Now()
	r, err := u.exchange(ctx, q)
	res := TestResult{LatencyMs: float64(time.Since(start).Microseconds()) / 1000, Answers: []string{}}
	if err != nil {
		res.Error = humanError(err)
		return res
	}
	res.Rcode = dns.RcodeToString[r.Rcode]
	for _, rr := range r.Answer {
		res.Answers = append(res.Answers, rr.String())
	}
	res.OK = r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError
	if !res.OK {
		res.Error = "réponse " + res.Rcode
	}
	return res
}

// Stats summarizes the engine counters.
type Stats struct {
	Queries, Local, Forwarded, Refused, Failed uint64
	Blocked, Bogus                             uint64
	Limited                                    uint64 // dropped or refused by the abuse limits
	CacheEntries                               int
	CacheHits, CacheMisses                     uint64
}

// Stats returns the counters.
func (e *Engine) Stats() Stats {
	return Stats{Queries: e.queries.Load(), Local: e.local.Load(), Forwarded: e.forwarded.Load(),
		Refused: e.refused.Load(), Failed: e.failed.Load(),
		Blocked: e.blocked.Load(), Bogus: e.bogus.Load(), Limited: e.limited.Load(), CacheEntries: e.cache.len(),
		CacheHits: e.cache.hits.Load(), CacheMisses: e.cache.misses.Load()}
}

// Health returns the health of every configured forwarder.
func (e *Engine) Health() map[string]Health {
	out := map[string]Health{}
	for id, u := range e.st.Load().fwd.all {
		out[id] = u.health()
	}
	return out
}

// ---- listeners ----

// ListenAddr is an IP to serve, with the interface it belongs to.
type ListenAddr struct {
	IP        netip.Addr
	Interface string
}

type listener struct {
	addr     ListenAddr
	udp, tcp *dns.Server
	udpErr   string
	tcpErr   string
	lastTry  time.Time
}

// ListenerStatus is reported to the UI.
type ListenerStatus struct {
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Interface string `json:"interface"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
}

// SetListeners starts/stops servers so exactly the given IPs are served.
// Failed binds are retried by Retry (called periodically by the app).
func (e *Engine) SetListeners(addrs []ListenAddr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	want := map[string]ListenAddr{}
	for _, a := range addrs {
		if a.IP.Is6() && a.IP.IsLinkLocalUnicast() {
			continue // needs a zone index; not supported for listening
		}
		want[a.IP.String()] = a
	}
	for ip, l := range e.listeners {
		if _, ok := want[ip]; !ok {
			l.stop()
			delete(e.listeners, ip)
			e.log.Info("DNS stopped listening", "ip", ip)
		}
	}
	for ip, a := range want {
		if l, ok := e.listeners[ip]; ok {
			l.addr = a
			continue
		}
		l := &listener{addr: a}
		e.listeners[ip] = l
		e.start(l)
	}
}

// Retry restarts listeners whose bind failed (port freed, address back...).
func (e *Engine) Retry() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.listeners {
		if (l.udp == nil || l.tcp == nil) && time.Since(l.lastTry) > 20*time.Second {
			e.start(l)
		}
	}
}

func (e *Engine) start(l *listener) {
	l.lastTry = time.Now()
	hostport := net.JoinHostPort(l.addr.IP.String(), strconv.Itoa(e.port))
	if l.udp == nil {
		pc, err := net.ListenPacket("udp", hostport)
		if err != nil {
			l.udpErr = bindError(err, l.addr.IP, e.port)
			e.log.Error("DNS listen failed", "addr", hostport, "proto", "udp", "err", l.udpErr)
		} else {
			l.udpErr = ""
			l.udp = &dns.Server{PacketConn: pc, Handler: e, UDPSize: ednsSize}
			go serve(e.log, l.udp)
		}
	}
	if l.tcp == nil {
		ln, err := net.Listen("tcp", hostport)
		if err != nil {
			l.tcpErr = bindError(err, l.addr.IP, e.port)
			e.log.Error("DNS listen failed", "addr", hostport, "proto", "tcp", "err", l.tcpErr)
		} else {
			l.tcpErr = ""
			l.tcp = &dns.Server{Listener: e.tcp.wrap(ln), Handler: e, ReadTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 10 * time.Second }}
			go serve(e.log, l.tcp)
		}
	}
	if l.udp != nil && l.tcp != nil {
		e.log.Info("DNS listening", "addr", hostport, "interface", l.addr.Interface)
	}
}

func serve(log *slog.Logger, s *dns.Server) {
	if err := s.ActivateAndServe(); err != nil {
		log.Debug("DNS server stopped", "err", err)
	}
}

func (l *listener) stop() {
	if l.udp != nil {
		_ = l.udp.Shutdown()
	}
	if l.tcp != nil {
		_ = l.tcp.Shutdown()
	}
}

// Close stops every listener.
func (e *Engine) Close() {
	e.SetListeners(nil)
}

// Listeners reports the state of each listener, sorted by address.
func (e *Engine) Listeners() []ListenerStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ListenerStatus
	for _, l := range e.listeners {
		hp := net.JoinHostPort(l.addr.IP.String(), strconv.Itoa(e.port))
		for _, p := range []struct {
			proto string
			ok    bool
			err   string
		}{{"udp", l.udp != nil, l.udpErr}, {"tcp", l.tcp != nil, l.tcpErr}} {
			s := ListenerStatus{Address: hp, Protocol: p.proto, Interface: l.addr.Interface, State: "listening"}
			if !p.ok {
				s.State, s.Error = "error", p.err
			}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Protocol > out[j].Protocol
	})
	return out
}

// bindError explains a bind failure in French, with the usual fix.
func bindError(err error, ip netip.Addr, port int) string {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Sprintf("le port %d est déjà utilisé sur %s par un autre programme (autre serveur DNS, dnsmasq, "+
			"ou systemd-resolved s'il écoute sur toutes les adresses : mettez DNSStubListener=no dans "+
			"/etc/systemd/resolved.conf puis systemctl restart systemd-resolved). Vérifiez avec : ss -lntup | grep ':%d '",
			port, ip, port)
	case errors.Is(err, syscall.EACCES):
		return fmt.Sprintf("permission refusée pour le port %d : ajoutez la capability NET_BIND_SERVICE au conteneur", port)
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return fmt.Sprintf("l'adresse %s n'existe pas sur cet hôte", ip)
	}
	return err.Error()
}
