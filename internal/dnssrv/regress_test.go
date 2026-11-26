package dnssrv

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssec"
)

// tamperer proxies queries to an authoritative engine and, once on is set,
// changes the A records of the answers (keeping the signatures).
type tamperer struct {
	auth *Engine
	on   atomic.Bool
}

func (h *tamperer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp, _ := h.auth.handle(context.Background(), r, netip.MustParseAddr("127.0.0.1"))
	if h.on.Load() {
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = net.IPv4(10, 6, 6, 6)
			}
		}
	}
	_ = w.WriteMsg(resp)
}

// validatingEngine forwards to h with ksk as trust anchor.
func validatingEngine(t *testing.T, h dns.Handler, ksk *dnssec.Key, st dnsconf.Settings) *Engine {
	t.Helper()
	val := New(quiet, 0)
	val.SetTrustAnchors([]*dns.DS{ksk.DNSKEY.ToDS(dns.SHA256)})
	val.SetDNSSEC(DNSSECConfig{Validate: true})
	val.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", startUDPTCP(t, h))}, st)
	return val
}

func TestDNSSECVerdictBoundToAnswer(t *testing.T) {
	auth, _, ksk := signedPair(t, dns.ECDSAP256SHA256, "nsec3")
	h := &tamperer{auth: auth}
	st := dnsconf.DefaultSettings()
	st.CacheSize = 0 // every query reaches the forwarder
	val := validatingEngine(t, h, ksk, st)
	if m := askDO(val, "www.maison.lan", dns.TypeA); m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData {
		t.Fatalf("genuine answer: %v", m)
	}
	// A later, forged answer must not inherit the "secure" verdict.
	h.on.Store(true)
	if m := askDO(val, "www.maison.lan", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("forged answer accepted: %v", m)
	}
}

// cdUpstream behaves like a validating resolver for a bogus zone: SERVFAIL,
// unless the query has the CD bit, then the unvalidated data.
type cdUpstream struct{}

func (cdUpstream) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if !r.CheckingDisabled {
		m.Rcode = dns.RcodeServerFailure
	} else {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A: net.ParseIP("10.6.6.6")}}
	}
	_ = w.WriteMsg(m)
}

func TestCacheSeparatesCD(t *testing.T) {
	e := New(quiet, 0)
	e.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", startUDPTCP(t, cdUpstream{}))}, dnsconf.DefaultSettings())
	q := new(dns.Msg)
	q.SetQuestion("bogus.example.", dns.TypeA)
	q.CheckingDisabled = true
	if r, _ := e.handle(context.Background(), q, netip.MustParseAddr("192.168.1.2")); len(r.Answer) != 1 {
		t.Fatalf("CD=1: %v", r)
	}
	// A client that wants validated data must not get the CD=1 answer.
	if m := ask(t, e, "bogus.example", dns.TypeA, "192.168.1.3"); m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
		t.Fatalf("CD=0 client got the unvalidated answer: %v", m)
	}
}

func TestCacheKeyUnknownTypes(t *testing.T) {
	// Types without a mnemonic must not share a cache entry.
	c := newCache()
	c.configure(10, 0, 3600, 900)
	q1 := dns.Question{Name: "x.example.", Qtype: 65280, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "x.example.", Qtype: 65281, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: 65280, Class: dns.ClassINET, Ttl: 60}, Rdata: "00"}}
	c.set(q1, false, false, m)
	if c.get(q2, false, false) != nil {
		t.Fatal("TYPE65281 answered from the TYPE65280 entry")
	}
	if c.get(q1, false, false) == nil {
		t.Fatal("TYPE65280 not cached")
	}
}

func TestMemoKey(t *testing.T) {
	m := new(dns.Msg)
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.", Mbox: "a.example."}}
	q1 := dns.Question{Name: "x.example.", Qtype: 65280, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "x.example.", Qtype: 65281, Qclass: dns.ClassINET}
	if memoKey(q1, m) == memoKey(q2, m) {
		t.Fatal("unknown types share a verdict")
	}
	// The same answer later (lower TTLs, from the cache) keeps its verdict.
	m2 := m.Copy()
	m2.Ns[0].Header().Ttl = 100
	if memoKey(q1, m) != memoKey(q1, m2) {
		t.Fatal("TTL changes the key")
	}
	m2.Ns[0].(*dns.SOA).Serial = 7
	if memoKey(q1, m) == memoKey(q1, m2) {
		t.Fatal("content does not change the key")
	}
}
