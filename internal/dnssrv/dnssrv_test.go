package dnssrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func u32(v uint32) *uint32 { return &v }

// testZones builds a zone set directly from config objects.
func testZones() ([]*dnsconf.Zone, map[string][]*dnsconf.Record) {
	z := &dnsconf.Zone{ID: "z1", Name: "maison.lan", Kind: dnsconf.KindPrimary, TTL: 3600, Serial: 2026010100,
		SOA: dnsconf.SOA{PrimaryNS: "ns.maison.lan.", AdminEmail: "admin@maison.lan", Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}}
	recs := []*dnsconf.Record{
		{Name: "www", Type: "A", Data: dnsconf.RecordData{IP: "192.168.1.10"}},
		{Name: "www", Type: "AAAA", Data: dnsconf.RecordData{IP: "fd00::10"}},
		{Name: "web", Type: "CNAME", Data: dnsconf.RecordData{Target: "www.maison.lan."}},
		{Name: "ext", Type: "CNAME", Data: dnsconf.RecordData{Target: "target.example."}},
		{Name: "_sip._tcp", Type: "SRV", TTL: u32(60), Data: dnsconf.RecordData{Priority: 1, Weight: 1, Port: 5060, Target: "www.maison.lan."}},
		{Name: "*.dev", Type: "A", Data: dnsconf.RecordData{IP: "192.168.1.50"}},
		{Name: "sub", Type: "NS", Data: dnsconf.RecordData{Host: "ns.sub.maison.lan."}},
		{Name: "ns.sub", Type: "A", Data: dnsconf.RecordData{IP: "192.168.1.53"}},
		{Name: "@", Type: "MX", Data: dnsconf.RecordData{Preference: 10, Exchange: "www.maison.lan."}},
	}
	return []*dnsconf.Zone{z}, map[string][]*dnsconf.Record{"z1": recs}
}

func ask(t *testing.T, e *Engine, name string, qtype uint16, from string) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _ := e.handle(context.Background(), q, netip.MustParseAddr(from))
	return r
}

func TestAuthoritative(t *testing.T) {
	e := New(quiet, 0)
	z, r := testZones()
	e.Load(z, r, nil, dnsconf.DefaultSettings())

	m := ask(t, e, "WWW.maison.lan", dns.TypeA, "203.0.113.1") // public client: local zones still answer
	if m.Rcode != dns.RcodeSuccess || !m.Authoritative || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("A: %v", m)
	}
	m = ask(t, e, "web.maison.lan", dns.TypeA, "192.168.1.2")
	if len(m.Answer) != 2 || m.Answer[0].Header().Rrtype != dns.TypeCNAME || m.Answer[1].Header().Rrtype != dns.TypeA {
		t.Fatalf("CNAME chain: %v", m.Answer)
	}
	m = ask(t, e, "nope.maison.lan", dns.TypeA, "192.168.1.2")
	if m.Rcode != dns.RcodeNameError || len(m.Ns) != 1 || m.Ns[0].Header().Ttl != 300 {
		t.Fatalf("NXDOMAIN: %v", m)
	}
	m = ask(t, e, "www.maison.lan", dns.TypeMX, "192.168.1.2")
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Fatalf("NODATA: %v", m)
	}
	m = ask(t, e, "_tcp.maison.lan", dns.TypeA, "192.168.1.2") // empty non-terminal
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("empty non-terminal: %v", m)
	}
	m = ask(t, e, "app.dev.maison.lan", dns.TypeA, "192.168.1.2")
	if len(m.Answer) != 1 || m.Answer[0].Header().Name != "app.dev.maison.lan." {
		t.Fatalf("wildcard: %v", m)
	}
	m = ask(t, e, "host.sub.maison.lan", dns.TypeA, "192.168.1.2")
	if m.Authoritative || len(m.Ns) != 1 || len(m.Extra) != 1 {
		t.Fatalf("referral: %v", m)
	}
	m = ask(t, e, "maison.lan", dns.TypeSOA, "192.168.1.2")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.SOA).Serial != 2026010100 {
		t.Fatalf("SOA: %v", m)
	}
}

// upstreamHandler answers A queries with 10.0.0.<n> and counts queries.
type upstreamHandler struct {
	ip    string
	count atomic.Int32
	trunc bool // answer with TC=1 over UDP
}

func (h *upstreamHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	h.count.Add(1)
	m := new(dns.Msg)
	m.SetReply(r)
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp && h.trunc {
		m.Truncated = true
		_ = w.WriteMsg(m)
		return
	}
	if r.Question[0].Name == "missing.example." {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
			Ns: "ns.example.", Mbox: "a.example.", Minttl: 120}}
	} else {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A: net.ParseIP(h.ip)}}
	}
	_ = w.WriteMsg(m)
}

func startUDPTCP(t *testing.T, h dns.Handler) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	su := &dns.Server{PacketConn: pc, Handler: h}
	st := &dns.Server{Listener: ln, Handler: h}
	go su.ActivateAndServe()
	go st.ActivateAndServe()
	t.Cleanup(func() { su.Shutdown(); st.Shutdown() })
	return port
}

func fwd(id, domain, proto, addr string, port int) *dnsconf.Forwarder {
	return &dnsconf.Forwarder{ID: id, Domain: domain, Protocol: proto, Address: addr, Port: port, Enabled: true, TLSVerify: true,
		TLSServerName: "example.com"}
}

func TestForwardingFailoverCacheACL(t *testing.T) {
	up := &upstreamHandler{ip: "10.0.0.1"}
	port := startUDPTCP(t, up)
	corp := &upstreamHandler{ip: "10.9.9.9"}
	corpPort := startUDPTCP(t, corp)
	dead := freePort(t)

	e := New(quiet, 0)
	st := dnsconf.DefaultSettings()
	e.Load(nil, nil, []*dnsconf.Forwarder{
		fwd("dead", "", "udp", "127.0.0.1", dead),
		fwd("ok", "", "udp", "127.0.0.1", port),
		fwd("corp", "corp.local", "tcp", "127.0.0.1", corpPort),
	}, st)

	m := ask(t, e, "example.org", dns.TypeA, "192.168.1.5")
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("failover: %v", m)
	}
	if h := e.Health()["dead"]; h.Healthy || h.LastError == "" {
		t.Fatalf("dead forwarder health: %+v", h)
	}
	// Second query: from cache.
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	if _, src := e.handle(context.Background(), q, netip.MustParseAddr("192.168.1.5")); src != SourceCache {
		t.Fatalf("source = %s, want cache", src)
	}
	if up.count.Load() != 1 {
		t.Fatalf("upstream queries = %d, want 1", up.count.Load())
	}
	// Conditional forwarder.
	m = ask(t, e, "srv.corp.local", dns.TypeA, "192.168.1.5")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.9.9.9" {
		t.Fatalf("conditional: %v", m)
	}
	// Negative caching uses min(SOA TTL, minimum) = 120.
	m = ask(t, e, "missing.example", dns.TypeA, "192.168.1.5")
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("nxdomain: %v", m)
	}
	// Public clients cannot recurse.
	m = ask(t, e, "example.org", dns.TypeA, "203.0.113.9")
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("ACL: %v", m)
	}
	// Flush by name.
	if n := e.FlushCache("example.org"); n != 1 {
		t.Fatalf("flushed %d", n)
	}
	ask(t, e, "example.org", dns.TypeA, "192.168.1.5")
	if up.count.Load() != 3 { // example.org, missing.example, example.org again
		t.Fatalf("flush did not force a new upstream query (%d)", up.count.Load())
	}
}

func TestCacheTTL(t *testing.T) {
	c := newCache()
	c.configure(10, 60, 100, 900)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	q := dns.Question{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.2.3.4")}}
	c.set(q, false, m) // TTL 10 raised to the minimum 60
	now = now.Add(30 * time.Second)
	got := c.get(q, false)
	if got == nil || got.Answer[0].Header().Ttl != 30 {
		t.Fatalf("ttl after 30 s: %v", got)
	}
	now = now.Add(31 * time.Second)
	if c.get(q, false) != nil {
		t.Fatal("expired entry returned")
	}
	// LRU eviction.
	c.configure(2, 0, 100, 900)
	for i := 0; i < 3; i++ {
		qi := dns.Question{Name: strconv.Itoa(i) + ".example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		mi := new(dns.Msg)
		mi.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: qi.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 50}, A: net.ParseIP("1.2.3.4")}}
		c.set(qi, false, mi)
	}
	if c.len() != 2 || c.get(dns.Question{Name: "0.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false) != nil {
		t.Fatal("LRU eviction failed")
	}
}

func TestTruncatedFallsBackToTCP(t *testing.T) {
	up := &upstreamHandler{ip: "10.0.0.7", trunc: true}
	port := startUDPTCP(t, up)
	e := New(quiet, 0)
	e.Load(nil, nil, []*dnsconf.Forwarder{fwd("u", "", "udp", "127.0.0.1", port)}, dnsconf.DefaultSettings())
	m := ask(t, e, "big.example", dns.TypeA, "127.0.0.1")
	if len(m.Answer) != 1 || up.count.Load() != 2 {
		t.Fatalf("TCP fallback: %v (queries %d)", m, up.count.Load())
	}
}

// tlsPair returns a server config and a client root pool from an httptest cert.
func tlsPair(t *testing.T) (*tls.Config, *x509.CertPool) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	cert := ts.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()
	return &tls.Config{Certificates: []tls.Certificate{cert}}, pool
}

func TestDoTAndDoH(t *testing.T) {
	srvConf, pool := tlsPair(t)
	up := &upstreamHandler{ip: "10.0.0.8"}

	// DoT server.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvConf)
	if err != nil {
		t.Fatal(err)
	}
	dot := &dns.Server{Listener: ln, Handler: up, Net: "tcp-tls"}
	go dot.ActivateAndServe()
	defer dot.Shutdown()
	dotPort := ln.Addr().(*net.TCPAddr).Port

	// DoH server.
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if r.Header.Get("Content-Type") != "application/dns-message" || q.Unpack(body) != nil || q.Id != 0 {
			http.Error(w, "bad", 400)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.9")}}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	doh.TLS = srvConf
	doh.EnableHTTP2 = true
	doh.StartTLS()
	defer doh.Close()
	dohPort := doh.Listener.Addr().(*net.TCPAddr).Port

	e := New(quiet, 0)
	e.SetRootCAs(pool)
	dotF := fwd("dot", "", "dot", "127.0.0.1", dotPort)
	dohF := fwd("doh", "doh.test", "doh", "127.0.0.1", dohPort)
	dohF.DoHURL = "https://example.com:" + strconv.Itoa(dohPort) + "/dns-query"
	e.Load(nil, nil, []*dnsconf.Forwarder{dotF, dohF}, dnsconf.DefaultSettings())

	for i := 0; i < 3; i++ { // reuses the pooled DoT connection
		m := ask(t, e, "dot"+strconv.Itoa(i)+".example", dns.TypeA, "127.0.0.1")
		if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.0.0.8" {
			t.Fatalf("DoT: %v", m)
		}
	}
	m := ask(t, e, "x.doh.test", dns.TypeA, "127.0.0.1")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.0.0.9" {
		t.Fatalf("DoH: %v", m)
	}

	// Certificate checks: wrong name is refused, unless verification is off.
	bad := *dotF
	bad.TLSServerName = "wrong.name"
	if res := e.TestForwarder(context.Background(), bad); res.OK || !strings.Contains(res.Error, "certificat") {
		t.Fatalf("wrong name accepted: %+v", res)
	}
	bad.TLSVerify = false
	if res := e.TestForwarder(context.Background(), bad); !res.OK {
		t.Fatalf("tlsVerify=false: %+v", res)
	}
	if res := e.TestForwarder(context.Background(), *dohF); !res.OK || res.LatencyMs <= 0 {
		t.Fatalf("DoH test: %+v", res)
	}
}

func TestListenersAndConflict(t *testing.T) {
	port := freePort(t)
	e := New(quiet, port)
	z, r := testZones()
	e.Load(z, r, nil, dnsconf.DefaultSettings())
	e.SetListeners([]ListenAddr{{IP: netip.MustParseAddr("127.0.0.1"), Interface: "lo"}})
	defer e.Close()
	c := &dns.Client{Net: "udp", Timeout: time.Second}
	q := new(dns.Msg)
	q.SetQuestion("www.maison.lan.", dns.TypeA)
	resp, _, err := c.Exchange(q, "127.0.0.1:"+strconv.Itoa(port))
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("udp query: %v %v", resp, err)
	}
	c.Net = "tcp"
	if resp, _, err := c.Exchange(q, "127.0.0.1:"+strconv.Itoa(port)); err != nil || len(resp.Answer) != 1 {
		t.Fatalf("tcp query: %v %v", resp, err)
	}
	// A second engine on the same port reports a clear error.
	e2 := New(quiet, port)
	e2.SetListeners([]ListenAddr{{IP: netip.MustParseAddr("127.0.0.1")}})
	defer e2.Close()
	ls := e2.Listeners()
	if len(ls) != 2 || ls[0].State != "error" || !strings.Contains(ls[0].Error, "déjà utilisé") {
		t.Fatalf("conflict status: %+v", ls)
	}
	// Removing the address stops the listener.
	e.SetListeners(nil)
	if len(e.Listeners()) != 0 {
		t.Fatal("listener not removed")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		if ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}
