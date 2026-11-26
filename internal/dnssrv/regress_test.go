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

// wildcardForger answers wildcard queries with the genuine signed answer
// but replaces the denial proof by signed NSEC/NSEC3 records of the same
// zone that do not cover the queried name.
type wildcardForger struct {
	auth   *Engine
	target string
	kept   atomic.Int32
}

func (h *wildcardForger) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp, _ := h.auth.handle(context.Background(), r, netip.MustParseAddr("127.0.0.1"))
	if r.Question[0].Name == h.target {
		var ns []dns.RR
	donors:
		for _, donor := range []string{"zz.maison.lan", "0.maison.lan", "a.b.nope.maison.lan", "nope.maison.lan"} {
			for _, s := range group(askDO(h.auth, donor, dns.TypeA).Ns) {
				covers := false
				for _, rr := range s.rrs {
					switch n := rr.(type) {
					case *dns.NSEC:
						covers = covers || nsecCovers(n, h.target)
					case *dns.NSEC3:
						covers = covers || n.Cover(h.target)
					default:
						covers = true // keep only denial records
					}
				}
				if covers {
					continue
				}
				h.kept.Add(1)
				ns = append(ns, s.rrs...)
				for _, sig := range s.sigs {
					ns = append(ns, sig)
				}
				break donors // one is enough (and keeps the reply small)
			}
		}
		resp.Ns = ns
	}
	_ = w.WriteMsg(resp)
}

func TestDNSSECWildcardProofMustCover(t *testing.T) {
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			auth, _, ksk := signedPair(t, dns.ECDSAP256SHA256, mode)
			h := &wildcardForger{auth: auth, target: "app.dev.maison.lan."}
			val := validatingEngine(t, h, ksk, dnsconf.DefaultSettings())
			m := askDO(val, "app.dev.maison.lan", dns.TypeA)
			if h.kept.Load() == 0 {
				t.Fatal("no unrelated denial record to forge with")
			}
			if m.Rcode != dns.RcodeServerFailure {
				t.Fatalf("wildcard answer with an unrelated proof accepted: %v", m)
			}
		})
	}
}

func TestDNSSECDelegationNSECNoData(t *testing.T) {
	// The NSEC(3) of a delegation point (NS, no SOA) only proves the absence
	// of a DS; it must not deny other types at the child apex (RFC 6840 §4.1).
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			_, val, _ := signedPair(t, dns.ECDSAP256SHA256, mode)
			if m := askDO(val, "sub.maison.lan", dns.TypeA); m.AuthenticatedData || m.Rcode != dns.RcodeServerFailure {
				t.Fatalf("delegation NSEC accepted as NODATA: %v", m)
			}
			if m := askDO(val, "sub.maison.lan", dns.TypeDS); !m.AuthenticatedData || m.Rcode != dns.RcodeSuccess {
				t.Fatalf("DS denial at the delegation: %v", m)
			}
		})
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
