package cluster

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/witness"
)

const testKey = "test cluster key 0123456789"

var quiet = testLogger()

// partition drops requests to blocked hosts (simulated network cut).
type partition struct {
	mu      sync.Mutex
	blocked map[string]bool
	next    http.RoundTripper
}

func (p *partition) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	b := p.blocked[r.URL.Host]
	p.mu.Unlock()
	if b {
		return nil, fmt.Errorf("network cut (test)")
	}
	return p.next.RoundTrip(r)
}

// viaPartition applies the cuts of p to another transport (the witness one).
type viaPartition struct {
	p    *partition
	next http.RoundTripper
}

func (v *viaPartition) RoundTrip(r *http.Request) (*http.Response, error) {
	v.p.mu.Lock()
	b := v.p.blocked[r.URL.Host]
	v.p.mu.Unlock()
	if b {
		return nil, fmt.Errorf("network cut (test)")
	}
	return v.next.RoundTrip(r)
}

type testNode struct {
	name   string
	addr   string // host:port
	db     *store.DB
	node   *Node
	cancel context.CancelFunc
	net    *partition
	dek    []byte
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

type harness struct {
	t       *testing.T
	nodes   map[string]*testNode
	witness string
	wsrv    *httptest.Server
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, nodes: map[string]*testNode{}}
	keys, err := pki.DeriveKeys(testKey)
	if err != nil {
		t.Fatal(err)
	}
	// The witness only knows the witness key.
	ca, err := pki.WitnessCA(keys.WitnessKey())
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ca.Issue(pki.WitnessName)
	w, err := witness.New(t.TempDir(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	h.wsrv = httptest.NewUnstartedServer(w.Handler())
	h.wsrv.TLS = ca.ServerConfig(cert, pki.AnyNode)
	h.wsrv.Config.ErrorLog = slog.NewLogLogger(quiet.Handler(), slog.LevelDebug)
	h.wsrv.StartTLS()
	t.Cleanup(h.wsrv.Close)
	h.witness = h.wsrv.URL
	// Shorter witness grace after "restart": the witness here is fresh.
	return h
}

// add prepares a node (database survives restarts).
func (h *harness) add(name, preferred string) *testNode { return h.addWith(name, 2000) }

func (h *harness) addWith(name string, leaseMs int) *testNode {
	db, err := store.Open(filepath.Join(h.t.TempDir(), name+".db"))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background(), h.t.TempDir(), quiet); err != nil {
		h.t.Fatal(err)
	}
	st := Settings{HeartbeatMs: 100, FailCount: 3, LeaseMs: leaseMs, FailbackMode: "auto", FailbackDelaySec: 0, DHCPMode: "load-balancing"}
	_ = db.PutSetting(context.Background(), SettingsKey, st)
	tn := &testNode{name: name, addr: freeAddr(h.t), db: db, dek: secrets.NewDEK()}
	h.nodes[name] = tn
	return tn
}

func (h *harness) start(tn *testNode, preferred string) { h.startWith(tn, preferred, nil) }

// startWith starts a node; mod may change its configuration and deps first.
func (h *harness) startWith(tn *testNode, preferred string, mod func(*config.Config, *Deps)) {
	var peers []string
	for _, o := range h.nodes {
		if o != tn {
			peers = append(peers, "https://"+o.addr)
		}
	}
	cfg := &config.Config{ClusterKey: testKey, NodeName: tn.name, ClusterAddr: "https://" + tn.addr, ClusterListen: tn.addr,
		Peers: peers, Witness: h.witness, PreferredRole: preferred}
	ctx, cancel := context.WithCancel(context.Background())
	tn.cancel = cancel
	rs, err := repl.Open(ctx, tn.db)
	if err != nil {
		h.t.Fatal(err)
	}
	box, _ := secrets.NewBox(tn.dek)
	eng, err := dhcpsrv.NewEngine(ctx, tn.db, quiet)
	if err != nil {
		h.t.Fatal(err)
	}
	nodeID := "id-" + tn.name
	d := Deps{Config: cfg, DB: tn.db, Repl: rs, Box: box, NodeID: nodeID, Log: quiet.With("node", tn.name),
		ConfigApplied: func(context.Context) {}, DHCP: eng,
		SetDEK: func(_ context.Context, k []byte) error { return box.Replace(k) }}
	if mod != nil {
		mod(cfg, &d)
	}
	n, err := New(d)
	if err != nil {
		h.t.Fatal(err)
	}
	tn.net = &partition{blocked: map[string]bool{}, next: n.client.Transport}
	n.client.Transport = tn.net
	n.wclient.Transport = &viaPartition{p: tn.net, next: n.wclient.Transport}
	tn.node = n
	if err := n.Start(ctx); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) stop(tn *testNode) {
	tn.cancel()
	time.Sleep(150 * time.Millisecond)
}

// cut blocks traffic from a to b (one direction).
func cut(a *testNode, host string, on bool) {
	a.net.mu.Lock()
	a.net.blocked[host] = on
	a.net.mu.Unlock()
}

func (h *harness) witnessHost() string { return strings.TrimPrefix(h.witness, "https://") }

func (h *harness) waitRole(tn *testNode, want proto.Role, d time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		tn.node.mu.Lock()
		r := tn.node.role
		tn.node.mu.Unlock()
		if r == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tn.node.mu.Lock()
	r := tn.node.role
	tn.node.mu.Unlock()
	h.t.Fatalf("%s: role %s, want %s", tn.name, r, want)
}

func (h *harness) waitSame(a, b *testNode, d time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		_, ha, _ := a.node.d.Repl.Hashes(context.Background())
		_, hb, _ := b.node.d.Repl.Hashes(context.Background())
		if ha == hb {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	h.t.Fatalf("configs of %s and %s differ", a.name, b.name)
}

func write(t *testing.T, tn *testNode, id string) {
	t.Helper()
	if err := tn.node.Writable(); err != nil {
		t.Fatalf("%s not writable: %v", tn.name, err)
	}
	if _, err := tn.db.Exec(`INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES (?, ?, ?, 1, 1)`,
		id, 100+len(id)+int(time.Now().UnixNano()%3000), id); err != nil {
		t.Fatal(err)
	}
	tn.node.AfterWrite(context.Background())
}

func hasVLAN(tn *testNode, id string) bool {
	var n int
	tn.db.QueryRow(`SELECT COUNT(*) FROM vlans WHERE id = ?`, id).Scan(&n)
	return n == 1
}

func primaries(nodes ...*testNode) int {
	n := 0
	for _, tn := range nodes {
		if tn.node.IsPrimary() {
			n++
		}
	}
	return n
}

func TestFailoverAndReturn(t *testing.T) {
	h := newHarness(t)
	n1, n2 := h.add("node1", "primary"), h.add("node2", "secondary")
	h.start(n1, "primary")
	h.start(n2, "secondary")
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
	if n2.node.Writable() == nil {
		t.Fatal("secondary accepts config writes")
	}
	// Same data key on both nodes (secrets readable everywhere).
	write(t, n1, "before")
	h.waitSame(n1, n2, 3*time.Second)
	if string(n1.node.d.Box.Key()) != string(n2.node.d.Box.Key()) {
		t.Fatal("data key not adopted by the secondary")
	}
	if !hasVLAN(n2, "before") {
		t.Fatal("change not replicated")
	}

	// Primary dies.
	h.stop(n1)
	h.waitRole(n2, proto.RolePrimary, 5*time.Second)
	n2.node.mu.Lock()
	pd := n2.node.partnerDown
	n2.node.mu.Unlock()
	if !pd {
		t.Fatal("partner-down not set although the witness confirmed")
	}
	write(t, n2, "during-outage")

	// Original primary returns: secondary first, catches up, then takes back its role.
	h.start(n1, "primary")
	h.waitRole(n1, proto.RolePrimary, 8*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
	if !hasVLAN(n1, "during-outage") {
		t.Fatal("change made during the outage lost after failback")
	}
	h.waitSame(n1, n2, 3*time.Second)
	hist, _ := n1.node.d.Repl.Epochs(context.Background())
	// The handoff message may be late under load: then node1 takes the role
	// by itself (the witness already gave it), with its own epoch.
	if len(hist) < 3 || hist[0].NodeID != "id-node1" ||
		(hist[0].Reason != "retour du primaire d'origine" && hist[0].Reason != "démarrage du cluster") {
		t.Fatalf("history: %+v", hist)
	}
	if primaries(n1, n2) != 1 {
		t.Fatal("not exactly one primary")
	}
}

func TestSplitBrainNeverTwoPrimaries(t *testing.T) {
	h := newHarness(t)
	n1, n2 := h.add("node1", "primary"), h.add("node2", "secondary")
	h.start(n1, "primary")
	h.start(n2, "secondary")
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)

	// Cut the link between the nodes; both still see the witness.
	cut(n1, n2.addr, true)
	cut(n2, n1.addr, true)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if primaries(n1, n2) > 1 {
			t.Fatal("split brain: two primaries")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !n1.node.IsPrimary() {
		t.Fatal("the primary lost its role although it still holds the witness lease")
	}
	// Heal.
	cut(n1, n2.addr, false)
	cut(n2, n1.addr, false)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
}

func TestIsolatedPrimaryStepsDownAndLostChangeBecomesConflict(t *testing.T) {
	h := newHarness(t)
	n1, n2 := h.addWith("node1", 4000), h.addWith("node2", 4000)
	h.start(n1, "primary")
	h.start(n2, "secondary")
	h.waitRole(n1, proto.RolePrimary, 3*time.Second)
	h.waitRole(n2, proto.RoleSecondary, 3*time.Second)
	write(t, n1, "synced")
	h.waitSame(n1, n2, 3*time.Second)

	// node1 loses the network (peer and witness) but does not know yet.
	cut(n1, n2.addr, true)
	cut(n2, n1.addr, true)
	cut(n1, h.witnessHost(), true)
	// Let the follower's in-flight long poll (1 s) end: after that nothing
	// written on node1 can reach node2.
	time.Sleep(1200 * time.Millisecond)
	if !n1.node.IsPrimary() {
		t.Fatal("node1 stepped down too early for this scenario")
	}
	if _, err := n1.db.Exec(`INSERT INTO vlans(id, vlan_id, name, created_at, updated_at) VALUES ('lost', 3999, 'lost', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	// node1 steps down (no quorum), node2 is promoted by the witness.
	h.waitRole(n2, proto.RolePrimary, 6*time.Second)
	if n1.node.IsPrimary() {
		t.Fatal("isolated primary kept its role")
	}
	write(t, n2, "new")
	// Network back: node1 rejoins, keeps the lost change as a conflict.
	cut(n1, n2.addr, false)
	cut(n2, n1.addr, false)
	cut(n1, h.witnessHost(), false)
	h.waitRole(n1, proto.RolePrimary, 8*time.Second) // auto failback (delay 0)
	h.waitSame(n1, n2, 3*time.Second)
	if hasVLAN(n1, "lost") || !hasVLAN(n1, "new") {
		t.Fatal("lost change applied or new change missing")
	}
	cs, _ := n1.node.Conflicts(context.Background())
	if len(cs) != 1 || cs[0].PK != "lost" {
		t.Fatalf("conflicts: %+v", cs)
	}
	// The admin re-applies it: it reaches both nodes.
	if err := n1.node.Reapply(context.Background(), cs[0].ID); err != nil {
		t.Fatal(err)
	}
	if !hasVLAN(n1, "lost") {
		var rec, app int
		n1.db.QueryRow(`SELECT record, applying FROM repl_state`).Scan(&rec, &app)
		cs2, _ := n1.node.Conflicts(context.Background())
		t.Fatalf("re-apply did not write on node1 (primary=%v record=%d applying=%d conflicts=%+v)", n1.node.IsPrimary(), rec, app, cs2)
	}
	h.waitSame(n1, n2, 3*time.Second)
	if !hasVLAN(n2, "lost") {
		t.Fatal("re-applied conflict not replicated")
	}
}

func TestVersionCompatibility(t *testing.T) {
	base := proto.NodeStatus{Version: "1.4.2", Protocol: "1.0", Schema: 4}
	cases := []struct {
		v       string
		schema  int
		ok, cfg bool
	}{
		{"1.4.3", 4, true, true},
		{"1.5.0", 4, true, false},
		{"1.4.2", 5, true, false},
		{"1.6.0", 4, false, false},
		{"2.0.0", 4, false, false},
	}
	for _, c := range cases {
		got := compare(base, proto.NodeStatus{Version: c.v, Protocol: "1.0", Schema: c.schema})
		if got.ok != c.ok || got.config != c.cfg {
			t.Errorf("%s schema %d: %+v", c.v, c.schema, got)
		}
		if !got.config && got.message == "" {
			t.Errorf("%s: no message for the UI", c.v)
		}
	}
}

func testLogger() *slog.Logger {
	if os.Getenv("CLUSTER_DEBUG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
