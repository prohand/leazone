// Package dhcpconf stores and validates the DHCP configuration: VLAN labels,
// scopes (with exclusions and options) and reservations.
package dhcpconf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// U32 converts an IPv4 address to an integer.
func U32(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }

// FromU32 converts an integer to an IPv4 address.
func FromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Broadcast returns the broadcast address of an IPv4 prefix.
func Broadcast(p netip.Prefix) netip.Addr {
	p = p.Masked()
	return FromU32(U32(p.Addr()) | (^uint32(0) >> p.Bits()))
}

// Mask returns the netmask of an IPv4 prefix.
func Mask(p netip.Prefix) net.IPMask { return net.CIDRMask(p.Bits(), 32) }

func parseV4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Unmap().Is4() {
		return netip.Addr{}, fmt.Errorf("adresse IPv4 invalide : %q", s)
	}
	return a.Unmap(), nil
}

// NormalizeMAC returns aa:bb:cc:dd:ee:ff or an error.
func NormalizeMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(strings.ReplaceAll(s, "-", ":"))
	if err != nil || len(hw) != 6 {
		if len(s) == 12 { // aabbccddeeff
			if hw2, err2 := net.ParseMAC(s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]); err2 == nil {
				return hw2.String(), nil
			}
		}
		return "", fmt.Errorf("adresse MAC invalide (format aa:bb:cc:dd:ee:ff)")
	}
	return hw.String(), nil
}

// NormalizeHex returns lowercase colon-separated hex bytes ("01:aa:bb").
func NormalizeHex(s string) (string, []byte, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil, nil
	}
	clean := strings.NewReplacer(":", "", "-", "", " ", "").Replace(s)
	if len(clean)%2 != 0 {
		return "", nil, fmt.Errorf("hexadécimal invalide")
	}
	b := make([]byte, len(clean)/2)
	for i := range b {
		var v byte
		if _, err := fmt.Sscanf(clean[2*i:2*i+2], "%02x", &v); err != nil {
			return "", nil, fmt.Errorf("hexadécimal invalide")
		}
		b[i] = v
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":"), b, nil
}
