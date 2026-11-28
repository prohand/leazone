package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/config"
)

// mtlsClient is a client with a certificate of ca named name.
func mtlsClient(t *testing.T, ca *pki.CA, name string, allow pki.Allow) *http.Client {
	t.Helper()
	cert, err := ca.Issue(name)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(cert, allow)}}
}

func call(c *http.Client, method, url string, body any) (int, error) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rd)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func testKeys(t *testing.T) (*pki.CA, *pki.CA) {
	t.Helper()
	keys, err := pki.DeriveKeys(testKey)
	if err != nil {
		t.Fatal(err)
	}
	nodeCA, err := keys.NodeCA()
	if err != nil {
		t.Fatal(err)
	}
	witnessCA, err := keys.WitnessCA()
	if err != nil {
		t.Fatal(err)
	}
	return nodeCA, witnessCA
}

// A node can only speak for itself (node ID of the request = common name of
// its certificate), and the witness key gives no access to the node port.
func TestNodeIdentityBoundToCertificate(t *testing.T) {
	h := newHarness(t)
	n1, n2 := h.add("node1", "primary"), h.add("node2", "secondary")
	h.start(n1, "primary")
	h.start(n2, "secondary")
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
	nodeCA, witnessCA := testKeys(t)
	base1 := "https://" + n1.addr

	evil := mtlsClient(t, nodeCA, "node:id-evil", pki.AnyNode)
	if code, err := call(evil, http.MethodPost, base1+"/cluster/v1/heartbeat", proto.NodeStatus{NodeID: "id-node2", Addr: "https://" + n2.addr}); err != nil || code != http.StatusForbidden {
		t.Fatalf("heartbeat in the name of another node: %d %v", code, err)
	}
	if code, err := call(evil, http.MethodGet, base1+"/cluster/v1/changes?after=0&epoch=0&node=id-node2", nil); err != nil || code != http.StatusForbidden {
		t.Fatalf("changes in the name of another node: %d %v", code, err)
	}
	if code, err := call(evil, http.MethodPost, "https://"+n2.addr+"/cluster/v1/handoff", proto.Handoff{FromID: "id-node1", Epoch: 99}); err != nil || code != http.StatusForbidden {
		t.Fatalf("handoff in the name of another node: %d %v", code, err)
	}
	// The witness refuses a lease request for another node.
	wevil := mtlsClient(t, witnessCA, "node:id-evil", pki.OnlyWitness)
	if code, err := call(wevil, http.MethodPost, h.witness+"/witness/v1/acquire", proto.LeaseRequest{NodeID: "id-node2", LeaseMs: 2000}); err != nil || code != http.StatusForbidden {
		t.Fatalf("acquire in the name of another node: %d %v", code, err)
	}
	// What the witness key can sign is refused on the node port...
	forged := mtlsClient(t, witnessCA, "node:id-node2", nil)
	if _, err := call(forged, http.MethodPost, base1+"/cluster/v1/heartbeat", proto.NodeStatus{NodeID: "id-node2"}); err == nil {
		t.Fatal("node port accepted a certificate made with the witness key")
	}
	// ...and a node certificate named "witness" is not a node.
	asWitness := mtlsClient(t, nodeCA, "witness", nil)
	if _, err := call(asWitness, http.MethodGet, base1+"/cluster/v1/snapshot", nil); err == nil {
		t.Fatal("node port accepted a certificate that is not node:<id>")
	}
	// Nodes refuse a "witness" signed by the node CA (they expect the witness CA).
	if _, err := call(mtlsClient(t, nodeCA, "node:id-node1", pki.OnlyWitness), http.MethodGet, h.witness+"/witness/v1/state", nil); err == nil {
		t.Fatal("witness reached with the node CA")
	}
	if primaries(n1, n2) != 1 || !n1.node.IsPrimary() {
		t.Fatal("roles changed")
	}
}

// A handoff only makes a node primary when the witness transferred the
// lease to it.
func TestHandoffNeedsTheWitnessLease(t *testing.T) {
	h := newHarness(t)
	n1, n2 := h.add("node1", "primary"), h.add("node2", "secondary")
	h.start(n1, "primary")
	h.start(n2, "secondary")
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
	h.waitSame(n1, n2, 3*time.Second)
	nodeCA, _ := testKeys(t)
	_, seq := n2.node.position(context.Background())
	n1.node.mu.Lock()
	epoch := n1.node.epoch
	n1.node.mu.Unlock()
	// A handoff sent with node1's identity, without any lease transfer.
	c := mtlsClient(t, nodeCA, "node:id-node1", pki.AnyNode)
	code, err := call(c, http.MethodPost, "https://"+n2.addr+"/cluster/v1/handoff", proto.Handoff{FromID: "id-node1", Epoch: epoch + 1, Seq: seq})
	if err != nil {
		t.Fatal(err)
	}
	if code == http.StatusOK || n2.node.IsPrimary() {
		t.Fatalf("handoff without the witness lease made node2 primary (HTTP %d)", code)
	}
	if !n1.node.IsPrimary() {
		t.Fatal("node1 lost its role")
	}
}

// oldPeer runs, at addr, a node of another protocol version (another CA): it
// refuses our certificates and we refuse its own.
func oldPeer(t *testing.T, addr string) {
	t.Helper()
	keys, err := pki.DeriveKeys("the key of an older protocol version 0123")
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := keys.NodeCA()
	cert, _ := ca.Issue("node:id-old")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	ts.Listener.Close()
	ts.Listener = ln
	ts.TLS = ca.ServerConfig(cert, pki.AnyNode)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
}

type alwaysUp struct{}

func (alwaysUp) InUse(context.Context, netip.Addr) bool { return true }

// During an update (one node on the old protocol, the other on the new
// one), the nodes cannot talk to each other. A node that sees its peer
// refuse its certificates must not take its place, even when the ping
// witness answers: the peer may well be primary.
func TestMismatchedPeerIsNotADeadPeer(t *testing.T) {
	h := newHarness(t)
	n1 := h.add("node1", "primary")
	peerAddr := freeAddr(t)
	oldPeer(t, peerAddr)
	h.startWith(n1, "primary", func(cfg *config.Config, d *Deps) {
		cfg.Peers = []string{"https://" + peerAddr}
		cfg.Witness = "ping:192.0.2.9"
		d.Pinger = alwaysUp{}
	})
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n1.node.IsPrimary() {
			t.Fatal("node became primary although its peer runs (other protocol version)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.waitRole(n1, proto.RoleIncompatible, time.Second)
	// The peer may serve the whole pool (it does not see us): no new address here.
	if owns, _ := n1.node.dhcpPolicy(); owns("s", 10) || owns("s", 11) {
		t.Fatal("new addresses given next to a peer that cannot see this node")
	}
	if v := n1.node.Status(context.Background()); len(v.Gaps) == 0 {
		t.Fatal("the Cluster page does not explain the incompatibility")
	}
}

// A primary that loses the witness while its peer runs another protocol
// version (it cannot see us, and may get the role from the witness) steps
// down: an incompatible peer does not count for the quorum.
func TestPrimaryStepsDownWithOnlyAMismatchedPeer(t *testing.T) {
	h := newHarness(t)
	n1 := h.add("node1", "primary")
	peerAddr := freeAddr(t)
	h.startWith(n1, "primary", func(cfg *config.Config, _ *Deps) {
		cfg.Peers = []string{"https://" + peerAddr}
	})
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	oldPeer(t, peerAddr) // the peer comes back with the other version
	time.Sleep(400 * time.Millisecond)
	n1.node.mu.Lock()
	seen := n1.node.anyAlivePeer() != nil
	n1.node.mu.Unlock()
	if !seen {
		t.Fatal("the mismatched peer is not seen as running")
	}
	cut(n1, h.witnessHost(), true)
	h.waitRole(n1, proto.RoleIsolated, 4*time.Second)
}
