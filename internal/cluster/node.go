// Package cluster runs a Leazone node in high availability: heartbeats,
// primary election with the witness, config/state/lease replication,
// virtual IP and return of the original primary.
package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
	"github.com/prohand/leazone/internal/version"
	"github.com/prohand/leazone/internal/vip"
)

// Settings are the cluster settings (replicated, settings key "cluster").
type Settings struct {
	HeartbeatMs      int    `json:"heartbeatMs"`
	FailCount        int    `json:"failCount"`
	LeaseMs          int    `json:"leaseMs"`
	FailbackMode     string `json:"failbackMode"` // auto | manual
	FailbackDelaySec int    `json:"failbackDelaySec"`
	DHCPMode         string `json:"dhcpMode"` // load-balancing | active-passive
}

// SettingsKey is the settings table key.
const SettingsKey = "cluster"

// DefaultSettings are used until changed in the UI.
func DefaultSettings() Settings {
	return Settings{HeartbeatMs: 1000, FailCount: 3, LeaseMs: 6000, FailbackMode: "auto", FailbackDelaySec: 300, DHCPMode: "load-balancing"}
}

// Validate checks the settings. It returns field -> message.
func (s *Settings) Validate() map[string]string {
	e := map[string]string{}
	if s.HeartbeatMs < 100 || s.HeartbeatMs > 10000 {
		e["heartbeatMs"] = "entre 100 et 10000 ms"
	}
	if s.FailCount < 2 || s.FailCount > 20 {
		e["failCount"] = "entre 2 et 20"
	}
	if s.LeaseMs < 2*s.HeartbeatMs*s.FailCount/2 || s.LeaseMs < 2000 || s.LeaseMs > 60000 {
		e["leaseMs"] = "entre 2000 et 60000 ms, et au moins le délai de détection"
	}
	if s.FailbackMode != "auto" && s.FailbackMode != "manual" {
		e["failbackMode"] = "auto ou manual"
	}
	if s.FailbackDelaySec < 0 || s.FailbackDelaySec > 86400 {
		e["failbackDelaySec"] = "entre 0 et 86400 secondes"
	}
	if s.DHCPMode != "load-balancing" && s.DHCPMode != "active-passive" {
		e["dhcpMode"] = "load-balancing ou active-passive"
	}
	return e
}

// Deps are the parts of the node the cluster drives.
type Deps struct {
	Config *config.Config
	DB     *store.DB
	Repl   *repl.Store
	Box    *secrets.Box
	NodeID string
	Log    *slog.Logger
	// ConfigApplied reloads every runtime component after replicated changes.
	ConfigApplied func(ctx context.Context)
	// SetDEK stores a data key received from the primary (wrapped locally).
	SetDEK func(ctx context.Context, dek []byte) error
	DHCP   *dhcpsrv.Engine
	VIP    *vip.Manager
	VLANs  func() []string
	Audit  func(ctx context.Context, action, target string, details map[string]any)
	Pinger interface {
		InUse(ctx context.Context, ip netip.Addr) bool
	}
}

type peer struct {
	addr    string
	status  proto.NodeStatus
	lastOK  time.Time // last successful outgoing heartbeat
	lastIn  time.Time // last incoming heartbeat
	latency time.Duration
	lastErr string
	acked   uint64 // follower position confirmed by its pulls
	ackedAt time.Time
	compat  compatibility
	// mismatch: the peer runs but refuses our certificates or we refuse
	// its own (other cluster key or protocol version): nothing can be
	// exchanged, not even the DHCP leases.
	mismatch bool
	hashes   map[string]string
	// nodeID is the last node ID seen at this address (persisted): it
	// changes when the peer is reinstalled.
	nodeID string
	// Full lease/state exchange: needed after the peer was down,
	// incompatible or restarted; retried until it succeeds.
	needExchange  bool
	exchanging    bool
	exchangeAfter time.Time
}

type compatibility struct {
	ok      bool   // can sync leases/state
	config  bool   // can sync config (same schema and version line)
	message string // shown in the UI when not fully compatible
}

// Node is a cluster member.
type Node struct {
	d    Deps
	ca   *pki.CA         // node CA: port 7443 between nodes
	cert tls.Certificate // "node:<id>", node CA
	kek  []byte          // wraps the data key in snapshots
	// client talks to the peers (node CA, server must be "node:<id>");
	// wclient talks to the witness (witness CA, server must be "witness").
	client   *http.Client
	wclient  *http.Client
	started  time.Time
	witnessM string // container | ping | none

	settings atomic.Pointer[Settings] // read without n.mu (used under it)

	mu          sync.Mutex
	role        proto.Role
	epoch       uint64
	primaryID   string
	primaryURL  string
	peers       map[string]*peer // by cluster address
	lastPrimary time.Time        // last time a live primary was seen
	witness     witnessState
	partnerDown bool
	handingOff  bool
	frozen      string // non-empty: config writes blocked (mixed versions)
	inSyncSince time.Time
	forceResync bool
	blocked     string // last reason the node could not promote
	lastApplied time.Time
	syncMu      sync.Mutex
	// promoteMu serializes the two ways to become primary: the election
	// (asFollower) and a planned handoff from the peer, so a node is not
	// promoted twice (one extra epoch) when both happen together.
	promoteMu sync.Mutex
	// writeMu: config writes hold it shared from the Writable check to
	// their commit (BeginWrite); losing the primary role takes it
	// exclusively before journaling stops, so no write in progress on the
	// primary ends up unjournaled.
	writeMu      sync.RWMutex
	stateMu      sync.Mutex
	appliedNotif chan struct{}
}

type witnessState struct {
	reachable bool
	lastOK    time.Time // last successful renew (we sent it at this time)
	lastErr   string
	state     proto.WitnessState
}

// New prepares a node; Start runs it.
func New(d Deps) (*Node, error) {
	keys, err := pki.DeriveKeys(d.Config.ClusterKey)
	if err != nil {
		return nil, err
	}
	if pki.WeakKey(d.Config.ClusterKey) {
		d.Log.Warn("the cluster key looks weak: use 32 random bytes (leazone cluster gen-key), see the README")
	}
	ca, err := keys.NodeCA()
	if err != nil {
		return nil, err
	}
	cert, err := ca.Issue(pki.NodePrefix + d.NodeID)
	if err != nil {
		return nil, err
	}
	wca, err := keys.WitnessCA()
	if err != nil {
		return nil, err
	}
	wcert, err := wca.Issue(pki.NodePrefix + d.NodeID)
	if err != nil {
		return nil, err
	}
	n := &Node{d: d, ca: ca, cert: cert, kek: keys.KEK(), started: time.Now(), role: proto.RoleJoining, peers: map[string]*peer{},
		appliedNotif: make(chan struct{}, 1)}
	def := DefaultSettings()
	n.settings.Store(&def)
	n.client = &http.Client{Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(cert, pki.AnyNode), Proxy: nil,
		MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second}, Timeout: 10 * time.Second}
	n.wclient = &http.Client{Transport: &http.Transport{TLSClientConfig: wca.ClientConfig(wcert, pki.OnlyWitness), Proxy: nil,
		MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second}, Timeout: 10 * time.Second}
	for _, a := range d.Config.Peers {
		n.peers[a] = &peer{addr: a, needExchange: true}
	}
	switch {
	case strings.HasPrefix(d.Config.Witness, "https://"):
		n.witnessM = "container"
	case strings.HasPrefix(d.Config.Witness, "ping:"):
		n.witnessM = "ping"
	default:
		n.witnessM = "none"
	}
	if v, _ := d.DB.Meta(context.Background(), "cluster_nodes"); v != "" {
		n.loadNodeIDs(v)
	}
	return n, nil
}

// loadNodeIDs restores the node ID last seen at each peer address
// ("addr=id,..."), so the DHCP split is right before the first heartbeat.
// The older format (a bare list of IDs, never purged) is only used when it
// designates the single configured peer unambiguously.
func (n *Node) loadNodeIDs(v string) {
	var legacy []string
	for _, e := range strings.Split(v, ",") {
		addr, id, ok := strings.Cut(e, "=")
		if !ok {
			if e != "" && e != n.d.NodeID {
				legacy = append(legacy, e)
			}
			continue
		}
		if p := n.peers[addr]; p != nil {
			p.nodeID = id
		}
	}
	if len(legacy) == 1 && len(n.peers) == 1 {
		for _, p := range n.peers {
			if p.nodeID == "" {
				p.nodeID = legacy[0]
			}
		}
	}
}

// saveNodeIDs persists the node ID of each configured peer (n.mu held).
func (n *Node) saveNodeIDs() {
	var list []string
	for _, p := range n.peers {
		if p.nodeID != "" {
			list = append(list, p.addr+"="+p.nodeID)
		}
	}
	sort.Strings(list)
	_ = n.d.DB.SetMeta(context.Background(), "cluster_nodes", strings.Join(list, ","))
}

func (n *Node) log() *slog.Logger { return n.d.Log }

// loadSettings reads the replicated cluster settings.
func (n *Node) loadSettings(ctx context.Context) {
	st := DefaultSettings()
	if _, err := n.d.DB.GetSetting(ctx, SettingsKey, &st); err != nil {
		n.log().Warn("cluster settings", "err", err)
	}
	if len(st.Validate()) > 0 {
		st = DefaultSettings()
	}
	n.settings.Store(&st)
}

// Settings returns the current settings.
func (n *Node) Settings() Settings { return *n.settings.Load() }

func (n *Node) interval() time.Duration {
	return time.Duration(n.Settings().HeartbeatMs) * time.Millisecond
}

func (n *Node) deadAfter() time.Duration {
	s := n.Settings()
	return time.Duration(s.HeartbeatMs*s.FailCount) * time.Millisecond
}

func (n *Node) leaseDur() time.Duration {
	return time.Duration(n.Settings().LeaseMs) * time.Millisecond
}

// Start opens the cluster port and runs the loops until ctx is done.
func (n *Node) Start(ctx context.Context) error {
	// Until elected, a node never journals local config writes.
	epoch, _, err := n.d.Repl.Position(ctx)
	if err != nil {
		return err
	}
	n.epoch = epoch
	if err := n.d.Repl.SetRecording(ctx, false, epoch); err != nil {
		return err
	}
	n.loadSettings(ctx)
	// A node starts as non-primary: remove a VIP left on the host interface
	// by a previous run that crashed while primary.
	if n.d.VIP != nil {
		_ = n.d.VIP.Down()
	}
	if err := n.serve(ctx); err != nil {
		return err
	}
	n.applyDHCPPolicy()
	go n.loop(ctx, n.heartbeats)
	go n.loop(ctx, n.decide)
	go n.follow(ctx)
	go n.shipLoop(ctx)
	n.d.DHCP.Sync = n.syncLeasesNow
	n.log().Info("cluster node started", "node", n.d.Config.NodeName, "addr", n.d.Config.ClusterAddr,
		"peers", n.d.Config.Peers, "witness", n.witnessM, "preferred", n.d.Config.PreferredRole)
	return nil
}

func (n *Node) loop(ctx context.Context, fn func(context.Context)) {
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(n.interval()):
		}
	}
}

// ---- status ----

func (n *Node) position(ctx context.Context) (uint64, uint64) {
	e, s, _ := n.d.Repl.Position(ctx)
	return e, s
}

func (n *Node) selfStatus(ctx context.Context) proto.NodeStatus {
	_, seq := n.position(ctx)
	_, hash, _ := n.d.Repl.Hashes(ctx)
	n.mu.Lock()
	defer n.mu.Unlock()
	st := proto.NodeStatus{NodeID: n.d.NodeID, Name: n.d.Config.NodeName, Addr: n.d.Config.ClusterAddr,
		PublicURL: n.d.Config.PublicURL, Role: n.role, Preferred: n.d.Config.PreferredRole, Epoch: n.epoch, Seq: seq,
		ConfigHash: hash, Version: version.Version, Protocol: version.ClusterProtocol, Schema: store.LatestSchema(),
		PrimaryID: n.primaryID, PartnerDown: n.partnerDown, Time: time.Now(), StartedAt: n.started, LastAppliedAt: n.lastApplied}
	if n.d.VLANs != nil {
		st.VLANs = n.d.VLANs()
	}
	return st
}

func (p *peer) alive(deadAfter time.Duration) bool {
	last := p.lastOK
	if p.lastIn.After(last) {
		last = p.lastIn
	}
	return !last.IsZero() && time.Since(last) < deadAfter
}

// compare decides what can be synchronized with a peer's version.
func compare(local, remote proto.NodeStatus) compatibility {
	lp, rp := strings.SplitN(local.Protocol, ".", 2)[0], strings.SplitN(remote.Protocol, ".", 2)[0]
	lmaj, lmin := semver(local.Version)
	rmaj, rmin := semver(remote.Version)
	switch {
	case lp != rp:
		return compatibility{message: fmt.Sprintf("protocoles de cluster incompatibles (%s / %s)", local.Protocol, remote.Protocol)}
	case lmaj != rmaj || absDiff(lmin, rmin) > 1:
		return compatibility{message: fmt.Sprintf("versions incompatibles : %s et %s. Mettez les deux nœuds dans la même version.", local.Version, remote.Version)}
	case local.Schema != remote.Schema || lmin != rmin:
		return compatibility{ok: true, message: fmt.Sprintf("mise à jour en cours (%s et %s) : configuration en lecture seule jusqu'à ce que les deux nœuds aient la même version", local.Version, remote.Version)}
	}
	return compatibility{ok: true, config: true}
}

func semver(v string) (int, int) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	maj, _ := strconv.Atoi(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return maj, minor
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// ---- heartbeats ----

func (n *Node) heartbeats(ctx context.Context) {
	self := n.selfStatus(ctx)
	n.mu.Lock()
	peers := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.Unlock()
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *peer) {
			defer wg.Done()
			hctx, cancel := context.WithTimeout(ctx, n.interval())
			defer cancel()
			start := time.Now()
			var st proto.NodeStatus
			err := n.post(hctx, p.addr+"/cluster/v1/heartbeat", self, &st)
			n.mu.Lock()
			defer n.mu.Unlock()
			if err != nil {
				p.lastErr = err.Error()
				if pki.IsMismatch(err) {
					// The peer runs but with certificates of another cluster
					// key or protocol version (e.g. during an update): it is
					// alive and incompatible, so this node does not take its
					// place (asFollower) and does not count it for the quorum
					// (asPrimary). It may itself be primary, unseen by us.
					p.lastOK, p.mismatch = time.Now(), true
					p.compat = compatibility{message: "l'autre nœud refuse nos certificats (clé de cluster ou version du protocole " +
						"de cluster différente) : mettez les deux nœuds et le témoin dans la même version, avec la même clé"}
				}
				return
			}
			p.lastOK, p.latency, p.lastErr = time.Now(), time.Since(start), ""
			n.peerStatus(p, self, st)
		}(p)
	}
	wg.Wait()
	n.transitions(ctx)
}

// peerStatus records a peer status (n.mu held).
func (n *Node) peerStatus(p *peer, self, st proto.NodeStatus) {
	if !p.status.StartedAt.IsZero() && !st.StartedAt.Equal(p.status.StartedAt) {
		p.needExchange = true // restarted: what it had not shipped yet is only in its database
	}
	p.status = st
	p.compat = compare(self, st)
	p.mismatch = false
	if st.NodeID != "" && st.NodeID != p.nodeID {
		// New peer, or reinstalled (new node ID): the old ID no longer
		// takes a share of the DHCP pool.
		p.nodeID = st.NodeID
		n.saveNodeIDs()
	}
}

// exchangeRetry is the delay before a failed full exchange is tried again.
const exchangeRetry = 5 * time.Second

// transitions runs full exchanges when a peer comes (back) online or
// becomes compatible, and retries them until they succeed.
func (n *Node) transitions(ctx context.Context) {
	n.mu.Lock()
	var back []*peer
	now := time.Now()
	for _, p := range n.peers {
		if !p.alive(n.deadAfter()) || !p.compat.ok {
			p.needExchange = true // exchange again once it is reachable and compatible
			continue
		}
		if p.needExchange && !p.exchanging && !now.Before(p.exchangeAfter) {
			p.exchanging = true
			back = append(back, p)
			n.log().Info("peer online: exchanging leases and state", "peer", p.status.Name)
		}
	}
	n.mu.Unlock()
	for _, p := range back {
		go func(p *peer) {
			err := n.fullExchange(context.WithoutCancel(ctx), p)
			n.mu.Lock()
			p.exchanging = false
			if err == nil {
				p.needExchange = false
			} else {
				p.exchangeAfter = time.Now().Add(exchangeRetry)
			}
			n.mu.Unlock()
			if err != nil {
				n.log().Warn("full exchange with the peer failed, will retry", "err", err)
			}
		}(p)
	}
	n.applyDHCPPolicy()
}

// ---- election ----

// livePrimary returns the live peer that is primary with the highest epoch.
func (n *Node) livePrimary() *peer {
	var best *peer
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.ok && p.status.Role == proto.RolePrimary {
			if best == nil || p.status.Epoch > best.status.Epoch {
				best = p
			}
		}
	}
	return best
}

// anyCompatiblePeer returns a live peer we can work with (n.mu held). Only
// such a peer counts for the quorum: an incompatible one may not see us.
func (n *Node) anyCompatiblePeer() *peer {
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.ok {
			return p
		}
	}
	return nil
}

func (n *Node) anyAlivePeer() *peer {
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) {
			return p
		}
	}
	return nil
}

// peerSeenWithin reports whether a peer was heard from within d (n.mu held).
func (n *Node) peerSeenWithin(d time.Duration) bool {
	for _, p := range n.peers {
		if p.alive(d) {
			return true
		}
	}
	return false
}

// leaseMargin is how long before the end of the witness lease the primary
// gives up its role when it cannot renew. The next check may come up to
// one witness call (at most interval) plus one loop pause (interval) later,
// plus one interval for the rest of the round.
func (n *Node) leaseMargin() time.Duration { return 3 * n.interval() }

func (n *Node) decide(ctx context.Context) {
	n.mu.Lock()
	role := n.role
	n.mu.Unlock()
	if role == proto.RolePrimary {
		n.asPrimary(ctx)
	} else {
		n.asFollower(ctx)
	}
	n.applyDHCPPolicy()
}

func (n *Node) asFollower(ctx context.Context) {
	lastEpoch, mySeq := n.position(ctx)
	n.mu.Lock()
	if n.handingOff {
		n.mu.Unlock()
		return
	}
	// Incompatible peer: no sync, no election games.
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && !p.compat.ok {
			n.role = proto.RoleIncompatible
			n.mu.Unlock()
			return
		}
	}
	if p := n.livePrimary(); p != nil {
		if n.role != proto.RoleSecondary || n.primaryID != p.status.NodeID {
			n.log().Info("following primary", "primary", p.status.Name, "epoch", p.status.Epoch)
		}
		n.role, n.primaryID, n.primaryURL = proto.RoleSecondary, p.status.NodeID, p.status.PublicURL
		if p.status.Epoch > n.epoch {
			n.epoch = p.status.Epoch
		}
		n.lastPrimary = time.Now()
		n.mu.Unlock()
		return
	}
	since := n.lastPrimary
	if since.IsZero() {
		since = n.started
	}
	wait := n.deadAfter()
	if n.d.Config.PreferredRole != "primary" {
		wait += 2 * n.interval() // let the preferred primary win when both start together
	}
	peerUp := n.anyAlivePeer()
	var peerSeq uint64
	var peerEpoch uint64
	if peerUp != nil {
		peerSeq, peerEpoch = peerUp.status.Seq, peerUp.status.Epoch
	}
	myEpoch := n.epoch
	n.mu.Unlock()

	if time.Since(since) < wait {
		return
	}
	// Never promote a node that is behind a live peer: the peer will.
	if peerUp != nil && (peerEpoch > myEpoch || (peerEpoch == myEpoch && peerSeq > mySeq)) {
		return
	}
	// A brand new node does not take over while a peer may hold real data,
	// unless it is the preferred primary.
	if myEpoch == 0 && mySeq == 0 && n.d.Config.PreferredRole != "primary" && peerUp == nil {
		n.setRole(proto.RoleIsolated)
		return
	}
	n.promoteMu.Lock()
	defer n.promoteMu.Unlock()
	n.mu.Lock()
	already := n.role == proto.RolePrimary || n.handingOff
	n.mu.Unlock()
	if already {
		return // a handoff made this node primary meanwhile
	}
	switch n.witnessM {
	case "container":
		resp, err := n.witnessCall(ctx, "acquire", proto.LeaseRequest{NodeID: n.d.NodeID, Name: n.d.Config.NodeName,
			Epoch: myEpoch, Seq: mySeq, LastEpoch: &lastEpoch, LeaseMs: int64(n.Settings().LeaseMs)})
		if err != nil || !resp.Granted {
			reason := "témoin injoignable"
			if err == nil {
				reason = resp.Reason
			}
			n.setRole(proto.RoleIsolated)
			n.noteBlocked(reason)
			return
		}
		n.mu.Lock()
		n.witness.lastOK, n.witness.reachable = time.Now(), true
		n.mu.Unlock()
		n.becomePrimary(ctx, resp.Epoch, n.promoteReason(peerUp))
	case "ping":
		ip := netip.MustParseAddr(strings.TrimPrefix(n.d.Config.Witness, "ping:"))
		ok := n.d.Pinger != nil && n.d.Pinger.InUse(ctx, ip)
		n.mu.Lock()
		n.witness.reachable = ok
		if ok {
			n.witness.lastOK = time.Now()
		}
		n.mu.Unlock()
		if !ok {
			n.setRole(proto.RoleIsolated)
			n.noteBlocked("l'IP témoin " + ip.String() + " ne répond pas (ce nœud est peut-être isolé)")
			return
		}
		n.becomePrimary(ctx, max(myEpoch, peerEpoch)+1, n.promoteReason(peerUp))
	default:
		// No witness: only the preferred primary starts as primary, and only
		// when it sees its peer (both agree). Otherwise: manual promotion.
		if n.d.Config.PreferredRole == "primary" && peerUp != nil {
			n.becomePrimary(ctx, max(myEpoch, peerEpoch)+1, "démarrage du cluster (sans témoin)")
			return
		}
		n.setRole(proto.RoleIsolated)
	}
}

// noteBlocked logs why the node cannot promote, once per reason.
func (n *Node) noteBlocked(reason string) {
	n.mu.Lock()
	same := n.blocked == reason
	n.blocked = reason
	n.mu.Unlock()
	if !same {
		n.log().Warn("cannot become primary", "reason", reason)
	}
}

func (n *Node) promoteReason(peerUp *peer) string {
	if peerUp == nil {
		return "le primaire ne répond plus"
	}
	return "démarrage du cluster"
}

func (n *Node) setRole(r proto.Role) {
	n.mu.Lock()
	if n.role != r {
		n.log().Info("cluster role", "role", r)
	}
	n.role = r
	if r != proto.RolePrimary {
		n.partnerDown = false
	}
	n.mu.Unlock()
}

// becomePrimary starts a new epoch on this node. It waits for any config
// sync in progress so nothing from the peer is applied afterwards.
func (n *Node) becomePrimary(ctx context.Context, epoch uint64, reason string) {
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	if err := n.d.Repl.BeginEpoch(ctx, epoch, n.d.NodeID, n.d.Config.NodeName, reason); err != nil {
		n.log().Error("begin epoch", "err", err)
		return
	}
	n.mu.Lock()
	n.role, n.epoch, n.primaryID, n.primaryURL = proto.RolePrimary, epoch, n.d.NodeID, n.d.Config.PublicURL
	n.inSyncSince, n.blocked = time.Time{}, ""
	// The witness just confirmed the peer is gone: serve all DHCP clients.
	n.partnerDown = n.witnessM == "container" && n.anyAlivePeer() == nil
	n.mu.Unlock()
	n.applyDHCPPolicy()
	n.log().Warn("this node is now PRIMARY", "epoch", epoch, "reason", reason)
	if n.d.VIP != nil {
		_ = n.d.VIP.Up()
	}
	if n.d.Audit != nil {
		n.d.Audit(ctx, "cluster.primary", n.d.Config.NodeName, map[string]any{"epoch": epoch, "reason": reason})
	}
	n.d.ConfigApplied(ctx)
}

// becomeSecondary stops writing config and releases the VIP.
func (n *Node) becomeSecondary(ctx context.Context, reason string) {
	n.mu.Lock()
	was := n.role
	n.role, n.partnerDown, n.lastPrimary = proto.RoleSecondary, false, time.Now()
	epoch := n.epoch
	n.mu.Unlock()
	// No new config write passes Writable from here on.
	n.applyDHCPPolicy()
	if n.d.VIP != nil {
		_ = n.d.VIP.Down()
	}
	// Writes that started as primary finish while still journaled, then
	// journaling stops.
	n.writeMu.Lock()
	_ = n.d.Repl.SetRecording(ctx, false, epoch)
	n.writeMu.Unlock()
	if was == proto.RolePrimary {
		n.log().Warn("this node is no longer primary", "reason", reason)
		if n.d.Audit != nil {
			n.d.Audit(ctx, "cluster.stepdown", n.d.Config.NodeName, map[string]any{"reason": reason})
		}
	}
}

func (n *Node) asPrimary(ctx context.Context) {
	lastEpoch, seq := n.position(ctx)
	n.mu.Lock()
	myEpoch := n.epoch
	// A peer elected with a newer epoch wins (e.g. after a split).
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.ok && p.status.Role == proto.RolePrimary &&
			(p.status.Epoch > myEpoch || (p.status.Epoch == myEpoch && p.status.NodeID < n.d.NodeID)) {
			n.mu.Unlock()
			n.becomeSecondary(ctx, "un autre nœud est primaire avec un mandat plus récent")
			return
		}
	}
	peerUp := n.anyCompatiblePeer()
	// Partner-down (whole pool served here) waits two more intervals after
	// the peer is declared dead, so that a peer cut from us has applied
	// its own "no new addresses" policy first (see applyDHCPPolicy).
	peerRecent := n.peerSeenWithin(n.deadAfter() + 2*n.interval())
	n.mu.Unlock()

	witnessOK := false
	switch n.witnessM {
	case "container":
		sent := time.Now()
		resp, err := n.witnessCall(ctx, "renew", proto.LeaseRequest{NodeID: n.d.NodeID, Name: n.d.Config.NodeName,
			Epoch: myEpoch, Seq: seq, LastEpoch: &lastEpoch, LeaseMs: int64(n.Settings().LeaseMs)})
		n.mu.Lock()
		switch {
		case err == nil && resp.Granted:
			n.witness.lastOK, n.witness.reachable, n.witness.lastErr = sent, true, ""
			witnessOK = true
		case err == nil:
			n.witness.reachable, n.witness.lastErr = true, resp.Reason
			n.mu.Unlock()
			n.becomeSecondary(ctx, "le témoin a donné le rôle à un autre nœud")
			return
		default:
			n.witness.reachable, n.witness.lastErr = false, err.Error()
			// Keep the role while the lease we got is still valid, with a
			// margin covering the time until the next check.
			witnessOK = time.Since(n.witness.lastOK) < n.leaseDur()-n.leaseMargin()
		}
		n.mu.Unlock()
		if peerUp == nil && !witnessOK {
			n.becomeSecondary(ctx, "plus de quorum (ni l'autre nœud ni le témoin)")
			n.setRole(proto.RoleIsolated)
			return
		}
	case "ping":
		ip := netip.MustParseAddr(strings.TrimPrefix(n.d.Config.Witness, "ping:"))
		ok := n.d.Pinger != nil && n.d.Pinger.InUse(ctx, ip)
		n.mu.Lock()
		n.witness.reachable = ok
		if ok {
			n.witness.lastOK = time.Now()
		}
		n.mu.Unlock()
	}
	n.mu.Lock()
	// Partner down: only when the witness confirms we hold the lease.
	n.partnerDown = !peerRecent && n.witnessM == "container" && witnessOK
	n.mu.Unlock()
	n.maybeFailback(ctx, seq)
}

// ---- failback ----

func (n *Node) maybeFailback(ctx context.Context, mySeq uint64) {
	if n.d.Config.PreferredRole == "primary" {
		return
	}
	_, myHash, _ := n.d.Repl.Hashes(ctx)
	n.mu.Lock()
	var target *peer
	for _, p := range n.peers {
		st := p.status
		if p.alive(n.deadAfter()) && p.compat.config && st.Preferred == "primary" && st.Role == proto.RoleSecondary &&
			st.Seq == mySeq && st.ConfigHash == myHash {
			target = p
		}
	}
	if target == nil {
		n.inSyncSince = time.Time{}
		n.mu.Unlock()
		return
	}
	if n.inSyncSince.IsZero() {
		n.inSyncSince = time.Now()
		n.log().Info("original primary is back and in sync", "node", target.status.Name)
	}
	s := n.Settings()
	ready := s.FailbackMode == "auto" && time.Since(n.inSyncSince) >= time.Duration(s.FailbackDelaySec)*time.Second
	n.mu.Unlock()
	if ready {
		if err := n.Failback(ctx); err != nil {
			n.log().Warn("automatic failback failed", "err", err)
		}
	}
}

// Failback hands the primary role back to the preferred primary.
func (n *Node) Failback(ctx context.Context) error {
	n.mu.Lock()
	if n.role != proto.RolePrimary {
		n.mu.Unlock()
		return errors.New("ce nœud n'est pas primaire")
	}
	var target *peer
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.status.Role == proto.RoleSecondary && p.compat.config {
			if target == nil || p.status.Preferred == "primary" {
				target = p
			}
		}
	}
	if target == nil {
		n.mu.Unlock()
		return errors.New("aucun nœud secondaire à jour et joignable")
	}
	n.handingOff = true
	epoch := n.epoch
	targetID, targetName := target.status.NodeID, target.status.Name
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.handingOff = false
		n.mu.Unlock()
	}()
	// New writes are refused (handingOff); let those in progress commit.
	n.writeMu.Lock()
	n.writeMu.Unlock() //nolint:staticcheck // empty critical section: waits for writers
	// Wait for the target to have everything.
	lastEpoch, seq := n.position(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for {
		n.mu.Lock()
		acked := target.acked
		n.mu.Unlock()
		if acked >= seq {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("le nœud cible n'a pas rattrapé les dernières modifications")
		}
		time.Sleep(50 * time.Millisecond)
	}
	newEpoch := epoch + 1
	if n.witnessM == "container" {
		resp, err := n.witnessCall(ctx, "transfer", proto.LeaseRequest{NodeID: n.d.NodeID, Name: n.d.Config.NodeName, Epoch: epoch,
			Seq: seq, LastEpoch: &lastEpoch, To: targetID, ToName: targetName, ToSeq: seq, LeaseMs: int64(n.Settings().LeaseMs)})
		if err != nil || !resp.Granted {
			if err == nil {
				err = errors.New(resp.Reason)
			}
			return fmt.Errorf("le témoin a refusé la rebascule : %w", err)
		}
		newEpoch = resp.Epoch
	}
	n.becomeSecondary(ctx, "rebascule vers "+targetName)
	if err := n.post(ctx, target.addr+"/cluster/v1/handoff", proto.Handoff{FromID: n.d.NodeID, Epoch: newEpoch, Seq: seq}, nil); err != nil {
		n.log().Warn("handoff message failed: the target will take the role by itself", "err", err)
	}
	return nil
}

// Promote forces this node to become primary (no witness, or when the admin
// knows the other node is down).
func (n *Node) Promote(ctx context.Context) error {
	n.mu.Lock()
	if n.role == proto.RolePrimary {
		n.mu.Unlock()
		return errors.New("ce nœud est déjà primaire")
	}
	if p := n.livePrimary(); p != nil {
		n.mu.Unlock()
		return fmt.Errorf("%s est primaire et joignable : utilisez « Rebasculer » depuis ce nœud", p.status.Name)
	}
	epoch := n.epoch
	for _, p := range n.peers {
		epoch = max(epoch, p.status.Epoch)
	}
	n.mu.Unlock()
	lastEpoch, seq := n.position(ctx)
	if n.witnessM == "container" {
		resp, err := n.witnessCall(ctx, "acquire", proto.LeaseRequest{NodeID: n.d.NodeID, Name: n.d.Config.NodeName,
			Epoch: epoch, Seq: seq, LastEpoch: &lastEpoch, LeaseMs: int64(n.Settings().LeaseMs)})
		if err != nil {
			return fmt.Errorf("témoin injoignable : %w", err)
		}
		if !resp.Granted {
			return errors.New("le témoin refuse : " + resp.Reason)
		}
		n.becomePrimary(ctx, resp.Epoch, "promotion manuelle")
		return nil
	}
	n.becomePrimary(ctx, epoch+1, "promotion manuelle")
	return nil
}

// ---- DHCP policy ----

func (n *Node) applyDHCPPolicy() {
	if n.d.DHCP == nil {
		return
	}
	n.mu.Lock()
	mode := n.Settings().DHCPMode
	role, partnerDown := n.role, n.partnerDown
	peerSeen := n.anyAlivePeer() != nil
	mismatch := false
	for _, p := range n.peers {
		mismatch = mismatch || (p.mismatch && p.alive(n.deadAfter()))
	}
	// Only the nodes configured now share the pool: this node and the ID
	// last seen at each peer address (a reinstalled peer replaces its old
	// ID, so both nodes compute the same split).
	nodes := []string{n.d.NodeID}
	for _, p := range n.peers {
		nodes = append(nodes, p.nodeID)
	}
	n.mu.Unlock()
	nodes = uniq(nodes)
	all := func(string, uint32) bool { return true }
	allC := func(byte) bool { return true }
	none := func(string, uint32) bool { return false }
	noneC := func(byte) bool { return false }
	switch {
	case partnerDown && role == proto.RolePrimary:
		n.d.DHCP.SetPolicy(all, allC)
	case mode == "active-passive" && role == proto.RolePrimary:
		n.d.DHCP.SetPolicy(all, allC)
	case mode == "active-passive" && role == proto.RoleSecondary:
		n.d.DHCP.SetPolicy(none, noneC)
	case role != proto.RolePrimary && (mode == "active-passive" || (n.witnessM == "container" && !peerSeen) || mismatch):
		// Not following a primary that may be serving the whole pool
		// (active-passive, partner-down after the witness gave it the role
		// while we are cut from it, or a peer of another protocol version
		// that cannot see us): no new address, existing leases and
		// reservations only (own clients).
		n.d.DHCP.SetPolicy(none, dhcpsrv.Buckets(nodes, n.d.NodeID))
	default:
		// Load balancing, or a degraded state: own clients and own addresses.
		n.d.DHCP.SetPolicy(dhcpsrv.AddressOwner(nodes, n.d.NodeID), dhcpsrv.Buckets(nodes, n.d.NodeID))
	}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
