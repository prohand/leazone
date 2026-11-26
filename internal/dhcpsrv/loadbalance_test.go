package dhcpsrv

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestRFC3074TableIsAPermutation(t *testing.T) {
	seen := map[byte]bool{}
	for _, v := range loadbMxTbl {
		seen[v] = true
	}
	if len(seen) != 256 {
		t.Fatalf("table has %d distinct values", len(seen))
	}
}

func TestLoadBalancingSplitsClients(t *testing.T) {
	a := Buckets([]string{"node-b", "node-a"}, "node-a")
	b := Buckets([]string{"node-a", "node-b"}, "node-b")
	countA := 0
	for i := 0; i < 2000; i++ {
		hw := net.HardwareAddr{0x02, 0x42, byte(i >> 8), byte(i), byte(i * 7), byte(i * 13)}
		m, _ := dhcpv4.NewDiscovery(hw)
		h := ClientHash(m)
		if a(h) == b(h) {
			t.Fatalf("bucket %d served by both or none", h)
		}
		if a(h) {
			countA++
		}
	}
	if countA < 800 || countA > 1200 {
		t.Fatalf("unbalanced split: node A gets %d/2000", countA)
	}
	// The client identifier wins over chaddr.
	m1, _ := dhcpv4.NewDiscovery(net.HardwareAddr{1, 2, 3, 4, 5, 6}, dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{1, 9, 9, 9, 9, 9, 9})))
	m2, _ := dhcpv4.NewDiscovery(net.HardwareAddr{6, 5, 4, 3, 2, 1}, dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{1, 9, 9, 9, 9, 9, 9})))
	if ClientHash(m1) != ClientHash(m2) {
		t.Fatal("same client-id must give the same bucket")
	}
}
