package dnssrv

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/dnsconf"
)

// forger proxies queries to an authoritative engine and lets a test
// rewrite the answer for one name.
type forger struct {
	auth   *Engine
	target string
	edit   func(resp *dns.Msg)
}

func (h *forger) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp, _ := h.auth.handle(context.Background(), r, netip.MustParseAddr("127.0.0.1"))
	if r.Question[0].Qtype == dns.TypeA && r.Question[0].Name == h.target {
		h.edit(resp)
	}
	_ = w.WriteMsg(resp)
}

// An answer whose RRSIG names another signer (an existing name that is not
// a zone, an insecure delegation, a name that does not exist, a zone above
// the trust anchor) must not be accepted as "insecure".
func TestDNSSECForgedSignerName(t *testing.T) {
	for _, signer := range []string{"www.maison.lan.", "sub.maison.lan.", "nope.maison.lan.", "lan.", "."} {
		t.Run(signer, func(t *testing.T) {
			auth, _, ksk := signedPair(t, dns.ED25519, "nsec")
			h := &forger{auth: auth, target: "www.maison.lan.", edit: func(resp *dns.Msg) {
				for _, rr := range resp.Answer {
					switch r := rr.(type) {
					case *dns.A:
						r.A = r.A.To4()
						r.A[3] = 66
					case *dns.RRSIG:
						r.SignerName = signer
					}
				}
			}}
			val := validatingEngine(t, h, ksk, dnsconf.DefaultSettings())
			if m := askDO(val, "www.maison.lan", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
				t.Fatalf("forged answer accepted: %v", m)
			}
		})
	}
}

// A forged NXDOMAIN whose RRSIG names an insecure zone (or a zone above
// the trust anchor) must be bogus.
func TestDNSSECForgedNegativeSigner(t *testing.T) {
	for _, signer := range []string{"sub.maison.lan.", "lan.", "www.maison.lan."} {
		t.Run(signer, func(t *testing.T) {
			auth, _, ksk := signedPair(t, dns.ED25519, "nsec")
			h := &forger{auth: auth, target: "www.maison.lan.", edit: func(resp *dns.Msg) {
				soa, _ := dns.NewRR(signer + " 300 IN SOA ns. h. 1 2 3 4 5")
				sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: signer, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
					TypeCovered: dns.TypeSOA, SignerName: signer, Algorithm: dns.ED25519}
				resp.Answer = nil
				resp.Rcode = dns.RcodeNameError
				resp.Ns = []dns.RR{soa, sig}
			}}
			val := validatingEngine(t, h, ksk, dnsconf.DefaultSettings())
			if m := askDO(val, "www.maison.lan", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
				t.Fatalf("forged NXDOMAIN accepted: %v", m)
			}
		})
	}
}

// The wildcard check must read the label count of the RRSIG that was
// verified, not of the first RRSIG of the set.
func TestDNSSECWildcardLabelsFromVerifiedSig(t *testing.T) {
	auth, _, ksk := signedPair(t, dns.ED25519, "nsec")
	h := &forger{auth: auth, target: "app.dev.maison.lan.", edit: func(resp *dns.Msg) {
		var ans, sigs []dns.RR
		for _, rr := range resp.Answer {
			if s, ok := rr.(*dns.RRSIG); ok {
				fake := dns.Copy(s).(*dns.RRSIG)
				fake.Labels = 4 // claims no wildcard expansion
				sigs = append([]dns.RR{fake}, sigs...)
				sigs = append(sigs, s)
			} else {
				ans = append(ans, rr)
			}
		}
		resp.Answer = append(ans, sigs...)
		resp.Ns = nil // drop the proof that the name does not exist
	}}
	val := validatingEngine(t, h, ksk, dnsconf.DefaultSettings())
	if m := askDO(val, "app.dev.maison.lan", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("wildcard answer without proof accepted: %v", m)
	}
}

// The trust anchor denies its own DS (like the root for "DS ."): secure.
func TestDNSSECDSDenialAtAnchor(t *testing.T) {
	_, val, _ := signedPair(t, dns.ED25519, "nsec")
	if m := askDO(val, "maison.lan", dns.TypeDS); m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData {
		t.Fatalf("DS denial at the anchor: %v", m)
	}
}

// Data below a proven insecure delegation stays "insecure" (no AD, no
// SERVFAIL), signed by the child's own keys or not at all.
func TestDNSSECInsecureDelegationStillAnswers(t *testing.T) {
	for _, signed := range []bool{false, true} {
		auth, _, ksk := signedPair(t, dns.ED25519, "nsec")
		h := &forger{auth: auth, target: "host.sub.maison.lan.", edit: func(resp *dns.Msg) {
			a, _ := dns.NewRR("host.sub.maison.lan. 300 IN A 192.168.1.77")
			resp.Answer = []dns.RR{a}
			if signed {
				resp.Answer = append(resp.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "host.sub.maison.lan.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
					TypeCovered: dns.TypeA, SignerName: "sub.maison.lan.", Algorithm: dns.ED25519, Labels: 4})
			}
			resp.Ns, resp.Extra = nil, nil
			resp.Rcode = dns.RcodeSuccess
		}}
		val := validatingEngine(t, h, ksk, dnsconf.DefaultSettings())
		m := askDO(val, "host.sub.maison.lan", dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || m.AuthenticatedData || len(m.Answer) == 0 {
			t.Fatalf("signed=%v: answer below an insecure delegation: %v", signed, m)
		}
	}
}
