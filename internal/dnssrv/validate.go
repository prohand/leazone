package dnssrv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSSEC validation of forwarded answers. The chain of trust is built from
// the root trust anchors with DS and DNSKEY queries sent to the forwarders
// (DO and CD bits set, so the forwarders return the raw signed data).
//
// Result: secure (AD bit), insecure (no AD: the zone is not signed, proven
// by a signed denial of its DS), bogus (SERVFAIL).

type vstatus int

const (
	vInsecure vstatus = iota
	vSecure
	vBogus
)

func (s vstatus) String() string {
	return [...]string{"insecure", "secure", "bogus"}[s]
}

// RootAnchors are the root zone KSK digests published by IANA
// (https://data.iana.org/root-anchors/root-anchors.xml).
var RootAnchors = []string{
	". 0 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". 0 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// maxNSEC3Iterations: above, the answer is treated as insecure (RFC 9276).
const maxNSEC3Iterations = 150

type keyEntry struct {
	keys []*dns.DNSKEY
	st   vstatus
	why  string
	exp  time.Time
}

type validator struct {
	anchors []*dns.DS // all for the same owner (the root, or a test zone)
	query   func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
	now     func() time.Time

	mu   sync.Mutex
	keys map[string]keyEntry
	memo map[string]memoEntry
}

type memoEntry struct {
	st  vstatus
	why string
	exp time.Time
}

func newValidator(anchors []*dns.DS, query func(context.Context, string, uint16) (*dns.Msg, error)) *validator {
	return &validator{anchors: anchors, query: query, now: time.Now, keys: map[string]keyEntry{}, memo: map[string]memoEntry{}}
}

// ParseAnchors parses DS records in presentation format.
func ParseAnchors(lines []string) ([]*dns.DS, error) {
	var out []*dns.DS
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			return nil, err
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("not a DS record: %s", l)
		}
		out = append(out, ds)
	}
	return out, nil
}

func (v *validator) anchorZone() string {
	if len(v.anchors) == 0 {
		return "."
	}
	return strings.ToLower(v.anchors[0].Hdr.Name)
}

// ---- helpers ----

type rrset struct {
	owner string
	t     uint16
	rrs   []dns.RR
	sigs  []*dns.RRSIG
}

// group splits a section into RRsets with their signatures.
func group(section []dns.RR) []*rrset {
	type key struct {
		o string
		t uint16
	}
	idx := map[key]*rrset{}
	var out []*rrset
	get := func(o string, t uint16) *rrset {
		k := key{strings.ToLower(o), t}
		if s := idx[k]; s != nil {
			return s
		}
		s := &rrset{owner: k.o, t: t}
		idx[k] = s
		out = append(out, s)
		return s
	}
	for _, rr := range section {
		switch r := rr.(type) {
		case *dns.RRSIG:
			s := get(r.Hdr.Name, r.TypeCovered)
			s.sigs = append(s.sigs, r)
		case *dns.OPT:
		default:
			s := get(rr.Header().Name, rr.Header().Rrtype)
			s.rrs = append(s.rrs, rr)
		}
	}
	// Drop signature-only sets.
	res := out[:0]
	for _, s := range out {
		if len(s.rrs) > 0 {
			res = append(res, s)
		}
	}
	return res
}

func supportedAlg(a uint8) bool {
	switch a {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

// verifySet checks that one signature of the set is valid with one key.
func (v *validator) verifySet(s *rrset, signer string, keys []*dns.DNSKEY) bool {
	now := v.now()
	for _, sig := range s.sigs {
		if !strings.EqualFold(sig.SignerName, signer) || !sig.ValidityPeriod(now) || !dns.IsSubDomain(signer, s.owner) {
			continue
		}
		for _, k := range keys {
			if k.Flags&dns.ZONE == 0 || k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			if sig.Verify(k, s.rrs) == nil {
				return true
			}
		}
	}
	return false
}

// ---- chain of trust ----

// trustedKeys returns the validated DNSKEY set of a zone.
func (v *validator) trustedKeys(ctx context.Context, zone string) ([]*dns.DNSKEY, vstatus, string) {
	zone = strings.ToLower(dns.Fqdn(zone))
	v.mu.Lock()
	if e, ok := v.keys[zone]; ok && v.now().Before(e.exp) {
		v.mu.Unlock()
		return e.keys, e.st, e.why
	}
	v.mu.Unlock()
	keys, st, why := v.fetchKeys(ctx, zone)
	ttl := 10 * time.Minute
	if st == vBogus {
		ttl = time.Minute
	}
	if ctx.Err() == nil {
		v.mu.Lock()
		if len(v.keys) > 10000 {
			v.keys = map[string]keyEntry{}
		}
		v.keys[zone] = keyEntry{keys, st, why, v.now().Add(ttl)}
		v.mu.Unlock()
	}
	return keys, st, why
}

func (v *validator) fetchKeys(ctx context.Context, zone string) ([]*dns.DNSKEY, vstatus, string) {
	var dsSet []*dns.DS
	switch {
	case zone == v.anchorZone():
		dsSet = v.anchors
	case !dns.IsSubDomain(v.anchorZone(), zone):
		return nil, vInsecure, "hors de l'ancre de confiance"
	default:
		r, err := v.query(ctx, zone, dns.TypeDS)
		if err != nil {
			return nil, vBogus, "DS de " + zone + " : " + err.Error()
		}
		var set *rrset
		for _, s := range group(r.Answer) {
			if s.t == dns.TypeDS && s.owner == zone {
				set = s
			}
		}
		if set == nil {
			// No DS: the zone is insecure if the parent proves it.
			neg := v.negative(ctx, zone, dns.TypeDS, r)
			if neg.st == vSecure {
				return nil, vInsecure, "pas de DS pour " + zone
			}
			return nil, neg.st, neg.why
		}
		if len(set.sigs) == 0 {
			return nil, vBogus, "DS de " + zone + " non signé"
		}
		parent := strings.ToLower(set.sigs[0].SignerName)
		if parent == zone || !dns.IsSubDomain(parent, zone) {
			return nil, vBogus, "DS de " + zone + " signé par " + parent
		}
		pkeys, pst, why := v.trustedKeys(ctx, parent)
		if pst != vSecure {
			return nil, pst, why
		}
		if !v.verifySet(set, parent, pkeys) {
			return nil, vBogus, "signature invalide du DS de " + zone
		}
		for _, rr := range set.rrs {
			dsSet = append(dsSet, rr.(*dns.DS))
		}
	}
	usable := false
	for _, ds := range dsSet {
		if supportedAlg(ds.Algorithm) && (ds.DigestType == dns.SHA1 || ds.DigestType == dns.SHA256 || ds.DigestType == dns.SHA384) {
			usable = true
		}
	}
	if !usable {
		return nil, vInsecure, "algorithme non pris en charge pour " + zone
	}
	r, err := v.query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, vBogus, "DNSKEY de " + zone + " : " + err.Error()
	}
	var set *rrset
	for _, s := range group(r.Answer) {
		if s.t == dns.TypeDNSKEY && s.owner == zone {
			set = s
		}
	}
	if set == nil {
		return nil, vBogus, "pas de DNSKEY pour " + zone
	}
	var keys []*dns.DNSKEY
	for _, rr := range set.rrs {
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	for _, ds := range dsSet {
		for _, k := range keys {
			if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
				continue
			}
			d := k.ToDS(ds.DigestType)
			if d == nil || !strings.EqualFold(d.Digest, ds.Digest) {
				continue
			}
			if v.verifySet(set, zone, []*dns.DNSKEY{k}) {
				return keys, vSecure, ""
			}
		}
	}
	return nil, vBogus, "aucune clé de " + zone + " ne correspond au DS"
}

// zoneStatus tells whether name is in a signed zone, walking the DS chain
// from the trust anchor. It is used for answers without signatures.
func (v *validator) zoneStatus(ctx context.Context, name string) (vstatus, string) {
	name = strings.ToLower(dns.Fqdn(name))
	anchor := v.anchorZone()
	if !dns.IsSubDomain(anchor, name) {
		return vInsecure, ""
	}
	if _, st, why := v.trustedKeys(ctx, anchor); st != vSecure {
		return st, why
	}
	labels := dns.SplitDomainName(name)
	skip := dns.CountLabel(anchor)
	for i := len(labels) - skip - 1; i >= 0; i-- {
		a := dns.Fqdn(strings.Join(labels[i:], "."))
		r, err := v.query(ctx, a, dns.TypeDS)
		if err != nil {
			return vBogus, "DS de " + a + " : " + err.Error()
		}
		hasDS := false
		for _, s := range group(r.Answer) {
			if s.t == dns.TypeDS && s.owner == a {
				hasDS = true
			}
		}
		if hasDS {
			if _, st, why := v.trustedKeys(ctx, a); st != vSecure {
				return st, why
			}
			continue
		}
		neg := v.negative(ctx, a, dns.TypeDS, r)
		if neg.st != vSecure {
			return neg.st, neg.why
		}
		if neg.cut || neg.optOut {
			return vInsecure, "délégation non signée : " + a
		}
		if neg.nxdomain {
			break
		}
	}
	return vSecure, ""
}

// ---- denial of existence ----

type negResult struct {
	st       vstatus
	why      string
	cut      bool // name is a delegation (NS) without DS
	optOut   bool // NSEC3 opt-out span: unsigned delegations may exist
	nxdomain bool
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// commonAncestor returns the longest common suffix of two names.
func commonAncestor(a, b string) string {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
	var common []string
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0 && la[i] == lb[j]; i, j = i-1, j-1 {
		common = append([]string{la[i]}, common...)
	}
	return dns.Fqdn(strings.Join(common, "."))
}

func nsecCovers(n *dns.NSEC, name string) bool {
	owner, next := strings.ToLower(n.Hdr.Name), strings.ToLower(n.NextDomain)
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	if canonicalCompare(next, owner) <= 0 { // last record of the chain
		return true
	}
	return canonicalCompare(name, next) < 0
}

// negative validates a NXDOMAIN or NODATA answer for name/qtype.
func (v *validator) negative(ctx context.Context, name string, qtype uint16, m *dns.Msg) negResult {
	name = strings.ToLower(dns.Fqdn(name))
	sets := group(m.Ns)
	signer := ""
	for _, s := range sets {
		if len(s.sigs) > 0 {
			signer = strings.ToLower(s.sigs[0].SignerName)
			break
		}
	}
	if signer == "" {
		return negResult{st: vBogus, why: "réponse négative non signée pour " + name}
	}
	keys, st, why := v.trustedKeys(ctx, signer)
	if st != vSecure {
		return negResult{st: st, why: why}
	}
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, s := range sets {
		switch s.t {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeSOA:
			if !v.verifySet(s, signer, keys) {
				return negResult{st: vBogus, why: "signature invalide (" + dns.TypeToString[s.t] + " " + s.owner + ")"}
			}
			for _, rr := range s.rrs {
				switch r := rr.(type) {
				case *dns.NSEC:
					nsecs = append(nsecs, r)
				case *dns.NSEC3:
					nsec3s = append(nsec3s, r)
				}
			}
		}
	}
	nx := m.Rcode == dns.RcodeNameError
	res := negResult{st: vSecure, nxdomain: nx}
	switch {
	case len(nsecs) > 0:
		if v.nsecProof(name, qtype, nx, nsecs, &res) {
			return res
		}
	case len(nsec3s) > 0:
		for _, n := range nsec3s {
			if n.Iterations > maxNSEC3Iterations {
				return negResult{st: vInsecure, why: "NSEC3 avec trop d'itérations"}
			}
		}
		if v.nsec3Proof(name, qtype, nx, nsec3s, &res) {
			return res
		}
	}
	return negResult{st: vBogus, why: "preuve de non-existence absente ou incomplète pour " + name}
}

func (v *validator) nsecProof(name string, qtype uint16, nx bool, nsecs []*dns.NSEC, res *negResult) bool {
	var cover *dns.NSEC
	for _, n := range nsecs {
		if strings.EqualFold(n.Hdr.Name, name) {
			if nx {
				return false // the name exists
			}
			if hasType(n.TypeBitMap, qtype) || hasType(n.TypeBitMap, dns.TypeCNAME) {
				return false
			}
			cut := hasType(n.TypeBitMap, dns.TypeNS) && !hasType(n.TypeBitMap, dns.TypeSOA)
			if cut && qtype != dns.TypeDS {
				return false // a parent-side NSEC says nothing of the child (RFC 6840 §4.1)
			}
			res.cut = cut
			return true
		}
		if nsecCovers(n, name) {
			cover = n
		}
	}
	if cover == nil {
		return false
	}
	ce := commonAncestor(name, cover.Hdr.Name)
	if c2 := commonAncestor(name, cover.NextDomain); dns.CountLabel(c2) > dns.CountLabel(ce) {
		ce = c2
	}
	if !nx && dns.IsSubDomain(name, strings.ToLower(cover.NextDomain)) {
		return true // empty non-terminal
	}
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	for _, n := range nsecs {
		if strings.EqualFold(n.Hdr.Name, wild) {
			// The wildcard exists: only a NODATA for this type is possible.
			return !nx && !hasType(n.TypeBitMap, qtype) && !hasType(n.TypeBitMap, dns.TypeCNAME)
		}
	}
	if !nx {
		return false
	}
	for _, n := range nsecs {
		if nsecCovers(n, wild) {
			return true
		}
	}
	return false
}

func (v *validator) nsec3Proof(name string, qtype uint16, nx bool, ns []*dns.NSEC3, res *negResult) bool {
	match := func(n string) *dns.NSEC3 {
		for _, r := range ns {
			if r.Match(n) {
				return r
			}
		}
		return nil
	}
	cover := func(n string) *dns.NSEC3 {
		for _, r := range ns {
			if r.Cover(n) {
				return r
			}
		}
		return nil
	}
	if !nx {
		if m := match(name); m != nil {
			if hasType(m.TypeBitMap, qtype) || hasType(m.TypeBitMap, dns.TypeCNAME) {
				return false
			}
			cut := hasType(m.TypeBitMap, dns.TypeNS) && !hasType(m.TypeBitMap, dns.TypeSOA)
			if cut && qtype != dns.TypeDS {
				return false // a parent-side NSEC3 says nothing of the child (RFC 6840 §4.1)
			}
			res.cut = cut
			return true
		}
	}
	// Closest encloser proof.
	next := name
	ce := ""
	for a := parentName(name); ; a = parentName(a) {
		if match(a) != nil {
			ce = a
			break
		}
		if a == "." {
			break
		}
		next = a
	}
	if ce == "" {
		return false
	}
	c := cover(next)
	if c == nil {
		return false
	}
	if c.Flags&1 == 1 { // opt-out: an unsigned delegation may be there
		res.optOut = true
		return qtype == dns.TypeDS || nx
	}
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	if nx {
		return cover(wild) != nil
	}
	if w := match(wild); w != nil {
		return !hasType(w.TypeBitMap, qtype) && !hasType(w.TypeBitMap, dns.TypeCNAME)
	}
	return false
}

// ---- answers ----

// check validates a forwarded answer for qname/qtype.
func (v *validator) check(ctx context.Context, qname string, qtype uint16, m *dns.Msg) (vstatus, string) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return vInsecure, ""
	}
	result := vSecure
	cur := strings.ToLower(dns.Fqdn(qname))
	answered := false
	for _, s := range group(m.Answer) {
		if s.t == dns.TypeCNAME && s.owner == cur && len(s.rrs) > 0 {
			cur = strings.ToLower(s.rrs[0].(*dns.CNAME).Target)
		} else if s.owner == cur && (s.t == qtype || qtype == dns.TypeANY) {
			answered = true
		}
		if len(s.sigs) == 0 {
			st, why := v.zoneStatus(ctx, s.owner)
			if st == vSecure {
				return vBogus, "enregistrement non signé dans une zone signée : " + s.owner
			}
			if st == vBogus {
				return vBogus, why
			}
			result = vInsecure
			continue
		}
		signer := strings.ToLower(s.sigs[0].SignerName)
		keys, st, why := v.trustedKeys(ctx, signer)
		if st == vBogus {
			return vBogus, why
		}
		if st == vInsecure {
			result = vInsecure
			continue
		}
		if !v.verifySet(s, signer, keys) {
			return vBogus, "signature invalide pour " + s.owner + " " + dns.TypeToString[s.t]
		}
		// Wildcard expansion: the exact name must be proven absent.
		if labels := int(s.sigs[0].Labels); labels < dns.CountLabel(s.owner) {
			if !v.wildcardProof(s.owner, labels, signer, keys, m.Ns) {
				return vBogus, "réponse par joker sans preuve : " + s.owner
			}
		}
	}
	if answered {
		return result, ""
	}
	// Negative answer for the last name of the chain.
	hasSig := false
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasSig = true
		}
	}
	if !hasSig {
		st, why := v.zoneStatus(ctx, cur)
		if st == vSecure {
			return vBogus, "réponse négative non signée dans une zone signée : " + cur
		}
		if st == vBogus {
			return vBogus, why
		}
		return vInsecure, ""
	}
	neg := v.negative(ctx, cur, qtype, m)
	if neg.st == vBogus {
		return vBogus, neg.why
	}
	if neg.st == vInsecure || neg.optOut || result == vInsecure {
		return vInsecure, ""
	}
	return vSecure, ""
}

// memoKey identifies a question and the answer given for it. The verdict
// is bound to the content: another answer to the same question (the cache
// entry expired or was evicted, a forged reply) is validated again.
func memoKey(q dns.Question, m *dns.Msg) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n", m.Rcode)
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			c := dns.Copy(rr)
			c.Header().Ttl = 0 // TTLs decrease while the answer is cached
			io.WriteString(h, c.String()+"\n")
		}
		h.Write([]byte{0})
	}
	return strings.ToLower(q.Name) + "/" + strconv.Itoa(int(q.Qtype)) + "/" + hex.EncodeToString(h.Sum(nil))
}

// wildcardProof tells whether the authority section proves that owner, an
// answer synthesized from a wildcard with the given label count (from the
// RRSIG), does not exist itself: a signed NSEC covering owner, or a signed
// NSEC3 covering the next closer name (RFC 4035 §5.3.4, RFC 5155 §8.8).
func (v *validator) wildcardProof(owner string, labels int, signer string, keys []*dns.DNSKEY, ns []dns.RR) bool {
	idx := dns.Split(owner)
	if labels < 0 || labels >= len(idx) {
		return false
	}
	// The closest encloser has `labels` labels; the next closer one more.
	nextCloser := owner[idx[len(idx)-labels-1]:]
	for _, a := range group(ns) {
		if (a.t != dns.TypeNSEC && a.t != dns.TypeNSEC3) || !v.verifySet(a, signer, keys) {
			continue
		}
		for _, rr := range a.rrs {
			switch r := rr.(type) {
			case *dns.NSEC:
				if nsecCovers(r, owner) {
					return true
				}
			case *dns.NSEC3:
				if r.Iterations <= maxNSEC3Iterations && r.Cover(nextCloser) {
					return true
				}
			}
		}
	}
	return false
}

// checkCached is check with a short memory per question and answer (the
// forwarded answer usually comes from the cache, so it is checked once).
func (v *validator) checkCached(ctx context.Context, q dns.Question, m *dns.Msg) (vstatus, string) {
	key := memoKey(q, m)
	now := v.now()
	v.mu.Lock()
	e, ok := v.memo[key]
	v.mu.Unlock()
	if ok && now.Before(e.exp) {
		return e.st, e.why
	}
	st, why := v.check(ctx, q.Name, q.Qtype, m)
	ttl := uint32(300)
	for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Ns...) {
		ttl = min(ttl, rr.Header().Ttl)
	}
	if st == vBogus {
		ttl = min(ttl, 30)
	}
	if ctx.Err() == nil && ttl > 0 {
		v.mu.Lock()
		if len(v.memo) > 20000 {
			v.memo = map[string]memoEntry{}
		}
		v.memo[key] = memoEntry{st, why, now.Add(time.Duration(ttl) * time.Second)}
		v.mu.Unlock()
	}
	return st, why
}

func (v *validator) flush() {
	v.mu.Lock()
	v.keys, v.memo = map[string]keyEntry{}, map[string]memoEntry{}
	v.mu.Unlock()
}

// stripDNSSEC removes DNSSEC records a client did not ask for (no DO bit).
func stripDNSSEC(rrs []dns.RR, qtype uint16) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			if rr.Header().Rrtype != qtype {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}
