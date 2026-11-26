package dnssrv

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/dnssec"
)

// signedPair starts an authoritative engine serving a signed zone and a
// validating engine forwarding to it, with the zone's KSK as trust anchor.
func signedPair(t *testing.T, alg uint8, mode string) (auth, val *Engine, ksk *dnssec.Key) {
	t.Helper()
	ksk, err := dnssec.Generate("maison.lan", dnssec.KSK, alg)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := dnssec.Generate("maison.lan", dnssec.ZSK, alg)
	if err != nil {
		t.Fatal(err)
	}
	ksk.State, zsk.State = dnssec.StateActive, dnssec.StateActive
	auth = New(quiet, 0)
	auth.SetDNSSEC(DNSSECConfig{Keys: map[string][]*dnssec.Key{"z1": {ksk, zsk}}, NSECMode: map[string]string{"z1": mode}})
	z, r := testZones()
	auth.Load(z, r, nil, dnsconf.DefaultSettings())
	port := startUDPTCP(t, auth)

	val = New(quiet, 0)
	val.SetTrustAnchors([]*dns.DS{ksk.DNSKEY.ToDS(dns.SHA256)})
	val.SetDNSSEC(DNSSECConfig{Validate: true})
	val.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", port)}, dnsconf.DefaultSettings())
	return auth, val, ksk
}

func askDO(e *Engine, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.SetEdns0(4096, true)
	r, _ := e.handle(context.Background(), q, netip.MustParseAddr("192.168.1.2"))
	return r
}

func TestDNSSECSignAndValidate(t *testing.T) {
	for _, c := range []struct {
		alg  uint8
		mode string
	}{{dns.ECDSAP256SHA256, "nsec3"}, {dns.ECDSAP256SHA256, "nsec"}, {dns.ED25519, "nsec3"}, {dns.ED25519, "nsec"}} {
		t.Run(fmt.Sprintf("alg%d-%s", c.alg, c.mode), func(t *testing.T) {
			auth, val, _ := signedPair(t, c.alg, c.mode)

			// The authoritative side returns signatures with DO.
			m := askDO(auth, "www.maison.lan", dns.TypeA)
			if !hasRR(m.Answer, dns.TypeRRSIG) {
				t.Fatalf("no RRSIG: %v", m)
			}
			m = askDO(auth, "maison.lan", dns.TypeDNSKEY)
			if n := countRR(m.Answer, dns.TypeDNSKEY); n != 2 || !hasRR(m.Answer, dns.TypeRRSIG) {
				t.Fatalf("DNSKEY: %v", m)
			}

			cases := []struct {
				name  string
				qtype uint16
				rcode int
			}{
				{"www.maison.lan", dns.TypeA, dns.RcodeSuccess},         // positive
				{"web.maison.lan", dns.TypeA, dns.RcodeSuccess},         // CNAME chain
				{"nope.maison.lan", dns.TypeA, dns.RcodeNameError},      // NXDOMAIN
				{"a.b.nope.maison.lan", dns.TypeA, dns.RcodeNameError},  // NXDOMAIN, deeper
				{"www.maison.lan", dns.TypeMX, dns.RcodeSuccess},        // NODATA
				{"_tcp.maison.lan", dns.TypeA, dns.RcodeSuccess},        // empty non-terminal
				{"app.dev.maison.lan", dns.TypeA, dns.RcodeSuccess},     // wildcard
				{"app.dev.maison.lan", dns.TypeTXT, dns.RcodeSuccess},   // wildcard NODATA
				{"sub.maison.lan", dns.TypeDS, dns.RcodeSuccess},        // no DS at an insecure delegation
				{"maison.lan", dns.TypeMX, dns.RcodeSuccess},            // apex
				{"_sip._tcp.maison.lan", dns.TypeSRV, dns.RcodeSuccess}, // SRV
				{"zz.maison.lan", dns.TypeAAAA, dns.RcodeNameError},     // after the last name
				{"0.maison.lan", dns.TypeAAAA, dns.RcodeNameError},      // before the first name
				{"x.www.maison.lan", dns.TypeA, dns.RcodeNameError},     // below an existing name
				{"sub.maison.lan", dns.TypeNS, dns.RcodeSuccess},        // referral (not validated: no recursion here)
			}
			for _, cs := range cases {
				m := askDO(val, cs.name, cs.qtype)
				if cs.qtype == dns.TypeNS {
					continue
				}
				if m.Rcode != cs.rcode || !m.AuthenticatedData {
					t.Errorf("%s %s: rcode %s, AD %v\n%v", cs.name, dns.TypeToString[cs.qtype], dns.RcodeToString[m.Rcode], m.AuthenticatedData, m)
				}
			}
			// Without DO, the AD bit is not set and signatures are stripped.
			q := new(dns.Msg)
			q.SetQuestion("www.maison.lan.", dns.TypeA)
			r, _ := val.handle(context.Background(), q, netip.MustParseAddr("192.168.1.2"))
			if r.AuthenticatedData || hasRR(r.Answer, dns.TypeRRSIG) || len(r.Answer) != 1 {
				t.Fatalf("no DO: %v", r)
			}
		})
	}
}

func TestDNSSECBogus(t *testing.T) {
	auth, _, _ := signedPair(t, dns.ECDSAP256SHA256, "nsec3")
	// A trust anchor that matches no key: everything in the zone is bogus.
	other, _ := dnssec.Generate("maison.lan", dnssec.KSK, dns.ECDSAP256SHA256)
	val := New(quiet, 0)
	val.SetTrustAnchors([]*dns.DS{other.DNSKEY.ToDS(dns.SHA256)})
	val.SetDNSSEC(DNSSECConfig{Validate: true})
	val.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", startUDPTCP(t, auth))}, dnsconf.DefaultSettings())
	m := askDO(val, "www.maison.lan", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("bogus should SERVFAIL: %v", m)
	}
	if o := m.IsEdns0(); o == nil || !strings.Contains(o.String(), "DNSSEC Bogus") {
		t.Fatalf("EDE: %v", m)
	}
	// CD bit: the client gets the data anyway, without AD.
	q := new(dns.Msg)
	q.SetQuestion("www.maison.lan.", dns.TypeA)
	q.SetEdns0(4096, true)
	q.CheckingDisabled = true
	r, _ := val.handle(context.Background(), q, netip.MustParseAddr("192.168.1.2"))
	if r.Rcode != dns.RcodeSuccess || r.AuthenticatedData {
		t.Fatalf("CD: %v", r)
	}
}

func TestDNSSECTamperedAnswer(t *testing.T) {
	auth, _, ksk := signedPair(t, dns.ED25519, "nsec")
	// A man in the middle changes the address but keeps the signature.
	evil := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp, _ := auth.handle(context.Background(), r, netip.MustParseAddr("127.0.0.1"))
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = a.A.To4()
				a.A[3] = 66
			}
		}
		_ = w.WriteMsg(resp)
	})
	port := startUDPTCP(t, evil)
	val := New(quiet, 0)
	val.SetTrustAnchors([]*dns.DS{ksk.DNSKEY.ToDS(dns.SHA256)})
	val.SetDNSSEC(DNSSECConfig{Validate: true})
	val.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", port)}, dnsconf.DefaultSettings())
	if m := askDO(val, "www.maison.lan", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("tampered answer accepted: %v", m)
	}
}

func TestDNSSECInsecureOutsideAnchor(t *testing.T) {
	// Names outside the trust anchor are insecure (no AD), not bogus.
	h := &upstreamHandler{ip: "198.51.100.7"}
	port := startUDPTCP(t, h)
	other, _ := dnssec.Generate("maison.lan", dnssec.KSK, dns.ECDSAP256SHA256)
	val := New(quiet, 0)
	val.SetTrustAnchors([]*dns.DS{other.DNSKEY.ToDS(dns.SHA256)})
	val.SetDNSSEC(DNSSECConfig{Validate: true})
	val.Load(nil, nil, []*dnsconf.Forwarder{fwd("f1", "", "udp", "127.0.0.1", port)}, dnsconf.DefaultSettings())
	m := askDO(val, "example.org", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || m.AuthenticatedData || len(m.Answer) != 1 {
		t.Fatalf("insecure: %v", m)
	}
}

func TestSignatureWindowShared(t *testing.T) {
	// Ed25519 signatures are identical on two nodes loading the same keys.
	ksk, _ := dnssec.Generate("maison.lan", dnssec.KSK, dns.ED25519)
	zsk, _ := dnssec.Generate("maison.lan", dnssec.ZSK, dns.ED25519)
	ksk.State, zsk.State = dnssec.StateActive, dnssec.StateActive
	var sigs [2]string
	for i := range sigs {
		e := New(quiet, 0)
		e.SetDNSSEC(DNSSECConfig{Keys: map[string][]*dnssec.Key{"z1": {ksk, zsk}}, NSECMode: map[string]string{"z1": "nsec3"}})
		z, r := testZones()
		e.Load(z, r, nil, dnsconf.DefaultSettings())
		for _, rr := range askDO(e, "www.maison.lan", dns.TypeA).Answer {
			if s, ok := rr.(*dns.RRSIG); ok {
				sigs[i] = s.Signature
			}
		}
	}
	if sigs[0] == "" || sigs[0] != sigs[1] {
		t.Fatalf("signatures differ: %q %q", sigs[0], sigs[1])
	}
}

func hasRR(rrs []dns.RR, t uint16) bool { return countRR(rrs, t) > 0 }

func countRR(rrs []dns.RR, t uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			n++
		}
	}
	return n
}
