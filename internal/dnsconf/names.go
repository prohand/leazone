// Package dnsconf stores and validates the DNS configuration: zones,
// records, forwarders, DNS settings and per-interface settings. Every write
// goes through this package so phase 4 can journal it for HA sync.
package dnsconf

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// NormalizeZoneName turns user input into a canonical zone name without the
// trailing dot. A network such as 192.168.1.0/24 becomes its reverse zone.
func NormalizeZoneName(in string) (name, kind string, err error) {
	in = strings.ToLower(strings.TrimSpace(in))
	if strings.Contains(in, "/") {
		p, err := netip.ParsePrefix(in)
		if err != nil {
			return "", "", fmt.Errorf("réseau invalide")
		}
		name, err = ReverseZone(p)
		return name, KindReverse, err
	}
	in = strings.TrimSuffix(in, ".")
	if in == "" {
		return "", "", fmt.Errorf("nom obligatoire")
	}
	if err := checkHostname(in, false); err != nil {
		return "", "", err
	}
	if IsReverseName(in) {
		return in, KindReverse, nil
	}
	return in, KindPrimary, nil
}

// IsReverseName reports whether a name is under in-addr.arpa or ip6.arpa.
func IsReverseName(n string) bool {
	n = strings.TrimSuffix(strings.ToLower(n), ".")
	return strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa")
}

// ReverseZone returns the reverse zone of a network. IPv4 prefixes must be
// /8, /16 or /24; IPv6 prefixes a multiple of 4.
func ReverseZone(p netip.Prefix) (string, error) {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		if p.Bits()%8 != 0 || p.Bits() == 0 || p.Bits() > 24 {
			return "", fmt.Errorf("pour une zone inverse IPv4, utilisez un réseau /8, /16 ou /24")
		}
		b := a.As4()
		var parts []string
		for i := p.Bits()/8 - 1; i >= 0; i-- {
			parts = append(parts, fmt.Sprint(b[i]))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa", nil
	}
	if p.Bits()%4 != 0 || p.Bits() == 0 || p.Bits() > 124 {
		return "", fmt.Errorf("pour une zone inverse IPv6, utilisez un préfixe multiple de 4")
	}
	b := a.As16()
	var nibbles []string
	for i := 0; i < p.Bits()/4; i++ {
		v := b[i/2]
		if i%2 == 0 {
			v >>= 4
		}
		nibbles = append(nibbles, fmt.Sprintf("%x", v&0xf))
	}
	for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa", nil
}

// checkHostname validates a domain name (LDH labels, underscores allowed for
// SRV/TXT owner names, optional "*" first label when wildcard is true).
func checkHostname(n string, wildcard bool) error {
	if len(n) > 253 {
		return fmt.Errorf("nom trop long (253 caractères max)")
	}
	labels := strings.Split(n, ".")
	for i, l := range labels {
		if l == "" {
			return fmt.Errorf("nom invalide : label vide")
		}
		if len(l) > 63 {
			return fmt.Errorf("label trop long (63 caractères max) : %s", l)
		}
		if l == "*" && wildcard && i == 0 {
			continue
		}
		for j, r := range l {
			ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || (r == '-' && j > 0 && j < len(l)-1)
			if !ok {
				return fmt.Errorf("caractère non autorisé dans %q (lettres, chiffres, tiret, souligné)", l)
			}
		}
	}
	return nil
}

// RelativeName converts a user-provided owner name to the stored form:
// "@" for the apex, otherwise the labels relative to the zone, lowercase.
// Accepts "@", "www", "www.zone.lan", "www.zone.lan." and "*".
func RelativeName(in, zone string) (string, error) {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" || in == "@" {
		return "@", nil
	}
	abs := strings.HasSuffix(in, ".")
	in = strings.TrimSuffix(in, ".")
	if in == zone {
		return "@", nil
	}
	if strings.HasSuffix(in, "."+zone) {
		in = strings.TrimSuffix(in, "."+zone)
	} else if abs {
		return "", fmt.Errorf("le nom doit être dans la zone %s", zone)
	}
	if err := checkHostname(in, true); err != nil {
		return "", err
	}
	if strings.Contains(in, "*") && !strings.HasPrefix(in, "*") {
		return "", fmt.Errorf("le joker * doit être le premier label")
	}
	return in, nil
}

// FQDN returns the absolute owner name of a relative name in a zone.
func FQDN(rel, zone string) string {
	if rel == "@" {
		return dns.Fqdn(zone)
	}
	return dns.Fqdn(rel + "." + zone)
}

// HostTarget normalizes a target host name to an absolute name. Relative
// names are completed with the zone, except when they already end with the
// zone name (common mistake: "mail.zone.lan" without the final dot).
func HostTarget(in, zone string) (string, error) {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		return "", fmt.Errorf("nom obligatoire")
	}
	if in == "@" {
		return dns.Fqdn(zone), nil
	}
	if strings.HasSuffix(in, ".") {
		if err := checkHostname(strings.TrimSuffix(in, "."), false); err != nil {
			return "", err
		}
		return in, nil
	}
	if err := checkHostname(in, false); err != nil {
		return "", err
	}
	if in == zone || strings.HasSuffix(in, "."+zone) {
		return dns.Fqdn(in), nil
	}
	return dns.Fqdn(in + "." + zone), nil
}
