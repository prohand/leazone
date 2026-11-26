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
	addr     string
	status   proto.NodeStatus
	lastOK   time.Time // last successful outgoing heartbeat
	lastIn   time.Time // last incoming heartbeat
	latency  time.Duration
	lastErr  string
	acked    uint64 // follower position confirmed by its pulls
	ackedAt  time.Time
	wasAlive bool
	compat   compatibility
	hashes   map[string]string
}

type compatibility struct {
	ok      bool   // can sync leases/state
	config  bool   // can sync config (same schema and version line)
	message string // shown in the UI when not fully compatible
}

// Node is a cluster member.
type Node struct {
	d        Deps
	ca       *pki.CA
	cert     tls.Certificate
	client   *http.Client
	started  time.Time
	witnessM string // container | ping | none

	settings atomic.Pointer[Settings] // read without n.mu (used under it)

	mu           sync.Mutex
	role         proto.Role
	epoch        uint64
	primaryID    string
	primaryURL   string
	peers        map[string]*peer // by cluster address
	lastPrimary  time.Time        // last time a live primary was seen
	witness      witnessState
	partnerDown  bool
	handingOff   bool
	frozen       string // non-empty: config writes blocked (mixed versions)
	inSyncSince  time.Time
	forceResync  bool
	blocked      string // last reason the node could not promote
	lastApplied  time.Time
	knownNodes   []string
	syncMu       sync.Mutex
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
	ca, err := pki.Derive(d.Config.ClusterKey)
	if err != nil {
		return nil, err
	}
	cert, err := ca.Issue("node:" + d.NodeID)
	if err != nil {
		return nil, err
	}
	n := &Node{d: d, ca: ca, cert: cert, started: time.Now(), role: proto.RoleJoining, peers: map[string]*peer{},
		appliedNotif: make(chan struct{}, 1)}
	def := DefaultSettings()
	n.settings.Store(&def)
	n.client = &http.Client{Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(cert), Proxy: nil,
		MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second}, Timeout: 10 * time.Second}
	for _, a := range d.Config.Peers {
		n.peers[a] = &peer{addr: a}
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
		n.knownNodes = strings.Split(v, ",")
	}
	return n, nil
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
	p.status = st
	p.compat = compare(self, st)
	if st.NodeID != "" && !contains(n.knownNodes, st.NodeID) {
		n.knownNodes = append(n.knownNodes, st.NodeID)
		sort.Strings(n.knownNodes)
		_ = n.d.DB.SetMeta(context.Background(), "cluster_nodes", strings.Join(n.knownNodes, ","))
	}
}

// transitions runs full exchanges when a peer comes (back) online.
func (n *Node) transitions(ctx context.Context) {
	n.mu.Lock()
	var back []*peer
	for _, p := range n.peers {
		alive := p.alive(n.deadAfter())
		if alive && !p.wasAlive && p.compat.ok {
			back = append(back, p)
		}
		p.wasAlive = alive
	}
	n.mu.Unlock()
	for _, p := range back {
		n.log().Info("peer online: exchanging leases and state", "peer", p.status.Name)
		go n.fullExchange(context.WithoutCancel(ctx), p)
	}
	n.applyDHCPPolicy()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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

func (n *Node) anyAlivePeer() *peer {
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) {
			return p
		}
	}
	return nil
}

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
	n.mu.Unlock()
	_ = n.d.Repl.SetRecording(ctx, false, n.epoch)
	if n.d.VIP != nil {
		_ = n.d.VIP.Down()
	}
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
	peerUp := n.anyAlivePeer()
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
			// Keep the role while the lease we got is still valid (with margin).
			witnessOK = time.Since(n.witness.lastOK) < n.leaseDur()-n.interval()
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
	n.partnerDown = peerUp == nil && n.witnessM == "container" && witnessOK
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
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.handingOff = false
		n.mu.Unlock()
	}()
	// Writes are blocked: wait for the target to have everything.
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
			Seq: seq, LastEpoch: &lastEpoch, To: target.status.NodeID, ToName: target.status.Name, ToSeq: seq, LeaseMs: int64(n.Settings().LeaseMs)})
		if err != nil || !resp.Granted {
			if err == nil {
				err = errors.New(resp.Reason)
			}
			return fmt.Errorf("le témoin a refusé la rebascule : %w", err)
		}
		newEpoch = resp.Epoch
	}
	n.becomeSecondary(ctx, "rebascule vers "+target.status.Name)
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
	nodes := append([]string{n.d.NodeID}, n.knownNodes...)
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
