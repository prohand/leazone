package cluster

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

const testPeer = "https://192.0.2.2:7443"

// idleNode builds a node that is not started (no loops, no listener).
func idleNode(t *testing.T, db *store.DB) *Node {
	t.Helper()
	if db == nil {
		var err error
		if db, err = store.Open(filepath.Join(t.TempDir(), "n.db")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.Migrate(context.Background(), t.TempDir(), quiet); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := repl.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := dhcpsrv.NewEngine(context.Background(), db, quiet)
	if err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	cfg := &config.Config{ClusterKey: testKey, NodeName: "node1", ClusterAddr: "https://192.0.2.1:7443",
		Peers: []string{testPeer}, Witness: "https://192.0.2.3:7443", PreferredRole: "primary"}
	n, err := New(Deps{Config: cfg, DB: db, Repl: rs, Box: box, NodeID: "id-b", Log: quiet, DHCP: eng,
		ConfigApplied: func(context.Context) {}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The DHCP split only counts the configured nodes: a reinstalled peer (new
// node ID) replaces its old ID instead of adding a third share.
func TestPeerNodeIDReplaced(t *testing.T) {
	n := idleNode(t, nil)
	p := n.peers[testPeer]
	self := n.selfStatus(context.Background())
	n.mu.Lock()
	n.peerStatus(p, self, proto.NodeStatus{NodeID: "id-a", Addr: testPeer})
	n.peerStatus(p, self, proto.NodeStatus{NodeID: "id-c", Addr: testPeer}) // reinstalled
	n.mu.Unlock()
	if v, _ := n.d.DB.Meta(context.Background(), "cluster_nodes"); v != testPeer+"=id-c" {
		t.Fatalf("persisted %q", v)
	}
	// After a restart the split is known before the first heartbeat.
	n2 := idleNode(t, n.d.DB)
	if got := n2.peers[testPeer].nodeID; got != "id-c" {
		t.Fatalf("restored %q", got)
	}
	// Two shares only: "id-b" (index 0 of [id-b id-c]) owns even addresses.
	n2.mu.Lock()
	n2.role = proto.RoleSecondary
	n2.peers[testPeer].lastIn = time.Now()
	n2.mu.Unlock()
	n2.applyDHCPPolicy()
	if !n2.d.DHCP.Owns("s", 10) || n2.d.DHCP.Owns("s", 11) {
		t.Fatal("pool not split in two between the configured nodes")
	}
	// Older format (bare list of every ID ever seen): the one foreign ID is
	// the single peer; stale lists are ignored.
	_ = n.d.DB.SetMeta(context.Background(), "cluster_nodes", "id-a,id-b")
	if got := idleNode(t, n.d.DB).peers[testPeer].nodeID; got != "id-a" {
		t.Fatalf("legacy %q", got)
	}
	_ = n.d.DB.SetMeta(context.Background(), "cluster_nodes", "id-a,id-b,id-c")
	if got := idleNode(t, n.d.DB).peers[testPeer].nodeID; got != "" {
		t.Fatalf("ambiguous legacy list used: %q", got)
	}
}

// A node that is not primary and cannot see its peer (which may be primary
// in partner-down, serving the whole pool) hands out no new address.
func TestIsolatedNodeAllocatesNothing(t *testing.T) {
	n := idleNode(t, nil)
	n.mu.Lock()
	n.peers[testPeer].nodeID = "id-a"
	n.role = proto.RoleIsolated
	n.mu.Unlock()
	n.applyDHCPPolicy()
	for ip := uint32(0); ip < 8; ip++ {
		if n.d.DHCP.Owns("s", ip) {
			t.Fatalf("isolated node may allocate %d", ip)
		}
	}
	// Its own clients are still answered (renewals).
	served := 0
	for b := 0; b < 256; b++ {
		if n.d.DHCP.Serves(byte(b)) {
			served++
		}
	}
	if served != 128 {
		t.Fatalf("serves %d buckets", served)
	}
	// Peer visible again: back to its own half.
	n.mu.Lock()
	n.peers[testPeer].lastIn = time.Now()
	n.mu.Unlock()
	n.applyDHCPPolicy()
	if !n.d.DHCP.Owns("s", 1) && !n.d.DHCP.Owns("s", 0) {
		t.Fatal("no share with the peer back")
	}
}

// Lease changes made while the peer is down are kept for its return.
func TestOutboxKeptWhilePeerDown(t *testing.T) {
	n := idleNode(t, nil)
	n.d.DHCP.Requeue([]dhcpsrv.Lease{{ScopeID: "s", IP: netip.MustParseAddr("10.0.0.5"), MAC: "aa"}})
	n.shipLeases(context.Background())
	if got := n.d.DHCP.TakeOutbox(); len(got) != 1 {
		t.Fatalf("outbox dropped while the peer is down: %v", got)
	}
}

func TestLeaseUpdateIPv4Only(t *testing.T) {
	if _, ok := fromUpdate(proto.LeaseUpdate{ScopeID: "s", IP: "2001:db8::1"}); ok {
		t.Fatal("IPv6 lease accepted")
	}
	if _, ok := fromUpdate(proto.LeaseUpdate{ScopeID: "s", IP: "10.0.0.1"}); !ok {
		t.Fatal("IPv4 lease refused")
	}
}

// A config write that passed Writable on the primary is journaled even if
// the node loses its role meanwhile: the step-down waits for it.
func TestStepDownWaitsForWrites(t *testing.T) {
	n := idleNode(t, nil)
	ctx := context.Background()
	if err := n.d.Repl.BeginEpoch(ctx, 1, "id-b", "node1", "test"); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.role, n.epoch = proto.RolePrimary, 1
	n.mu.Unlock()
	done, err := n.BeginWrite()
	if err != nil {
		t.Fatal(err)
	}
	stepped := make(chan struct{})
	go func() {
		n.becomeSecondary(ctx, "test")
		close(stepped)
	}()
	// The role is gone at once (no new write)...
	deadline := time.Now().Add(2 * time.Second)
	for n.Writable() == nil {
		if time.Now().After(deadline) {
			t.Fatal("still writable")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// ...but the write in progress is still journaled.
	_, before, _ := n.d.Repl.Position(ctx)
	if _, err := n.d.DB.Exec(`INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES ('v', 20, 'v', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	_, after, _ := n.d.Repl.Position(ctx)
	if after != before+1 {
		t.Fatal("write in progress during the step-down was not journaled")
	}
	select {
	case <-stepped:
		t.Fatal("step-down finished before the write")
	default:
	}
	done()
	<-stepped
	if _, err := n.d.DB.Exec(`INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES ('w', 21, 'w', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, last, _ := n.d.Repl.Position(ctx); last != after {
		t.Fatal("still journaling after the step-down")
	}
}
