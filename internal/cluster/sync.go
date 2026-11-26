package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/secrets"
)

// ---- transport ----

func (n *Node) post(ctx context.Context, url string, in, out any) error {
	return n.do(ctx, http.MethodPost, url, in, out)
}

func (n *Node) do(ctx context.Context, method, url string, in, out any) error {
	return n.doWith(ctx, n.client, method, url, in, out)
}

// doLong is do without the client's overall 10 s timeout, for the snapshot
// and the full exchange: ctx bounds them (60 s).
func (n *Node) doLong(ctx context.Context, method, url string, in, out any) error {
	return n.doWith(ctx, &http.Client{Transport: n.client.Transport}, method, url, in, out)
}

func (n *Node) doWith(ctx context.Context, c *http.Client, method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s : HTTP %d %s", url, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (n *Node) witnessCall(ctx context.Context, op string, req proto.LeaseRequest) (proto.LeaseResponse, error) {
	var resp proto.LeaseResponse
	cctx, cancel := context.WithTimeout(ctx, n.interval())
	defer cancel()
	err := n.post(cctx, n.d.Config.Witness+"/witness/v1/"+op, req, &resp)
	n.mu.Lock()
	if err != nil {
		n.witness.reachable, n.witness.lastErr = false, err.Error()
	} else {
		n.witness.reachable = true
		n.witness.state = proto.WitnessState{Epoch: resp.Epoch, PrimaryID: resp.PrimaryID, PrimaryName: resp.PrimaryName,
			Committed: resp.Committed, LeaseActive: true, Time: time.Now()}
	}
	n.mu.Unlock()
	return resp, err
}

// serve runs the cluster HTTPS server (mutual TLS).
func (n *Node) serve(ctx context.Context) error {
	mux := http.NewServeMux()
	j := func(path string, fn func(*http.Request) (any, int)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			out, code := fn(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	j("POST /cluster/v1/heartbeat", n.hHeartbeat)
	j("GET /cluster/v1/changes", n.hChanges)
	j("GET /cluster/v1/snapshot", n.hSnapshot)
	j("POST /cluster/v1/state", n.hState)
	j("GET /cluster/v1/state", n.hFullState)
	j("POST /cluster/v1/leases", n.hLeases)
	j("GET /cluster/v1/leases", n.hAllLeases)
	j("POST /cluster/v1/handoff", n.hHandoff)
	j("POST /cluster/v1/reapply", n.hReapply)
	j("POST /cluster/v1/resync", func(*http.Request) (any, int) {
		n.mu.Lock()
		n.forceResync = true
		n.mu.Unlock()
		return map[string]bool{"ok": true}, http.StatusOK
	})
	ln, err := net.Listen("tcp", n.d.Config.ClusterListen)
	if err != nil {
		return fmt.Errorf("port de cluster %s : %w", n.d.Config.ClusterListen, err)
	}
	srv := &http.Server{Handler: mux, TLSConfig: n.ca.ServerConfig(n.cert), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			n.log().Error("cluster server", "err", err)
		}
	}()
	return nil
}

func (n *Node) peerByID(id string) *peer {
	for _, p := range n.peers {
		if p.status.NodeID == id {
			return p
		}
	}
	return nil
}

func (n *Node) hHeartbeat(r *http.Request) (any, int) {
	var st proto.NodeStatus
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&st); err != nil {
		return map[string]string{"error": "bad request"}, http.StatusBadRequest
	}
	self := n.selfStatus(r.Context())
	n.mu.Lock()
	p := n.peers[st.Addr]
	if p == nil {
		p = n.peerByID(st.NodeID)
	}
	if p != nil {
		p.lastIn = time.Now()
		n.peerStatus(p, self, st)
	}
	n.mu.Unlock()
	return self, http.StatusOK
}

// ---- config replication (primary side) ----

func (n *Node) hChanges(r *http.Request) (any, int) {
	ctx := r.Context()
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	fepoch, _ := strconv.ParseUint(q.Get("epoch"), 10, 64)
	from := q.Get("node")
	n.mu.Lock()
	if n.role != proto.RolePrimary {
		n.mu.Unlock()
		return map[string]string{"error": "not primary"}, http.StatusConflict
	}
	p := n.peerByID(from)
	frozen := p != nil && !p.compat.config
	n.mu.Unlock()
	epoch, seq := n.position(ctx)
	resp := proto.ChangesResponse{Epoch: epoch, Seq: seq, Frozen: frozen, DEK: dekFingerprint(n.d.Box.Key())}
	// The follower's position counts as acknowledged (failback, AfterWrite)
	// only when its history is ours up to that point: a divergent follower
	// with a high seq has not got our changes.
	if p != nil && after <= seq && n.d.Repl.Has(ctx, after, fepoch) {
		n.mu.Lock()
		p.acked, p.ackedAt = after, time.Now()
		n.mu.Unlock()
	}
	if frozen {
		return resp, http.StatusOK // mixed versions: no config sync until aligned
	}
	if after == 0 && fepoch == 0 && seq > 0 {
		resp.Snapshot, resp.Reason = true, "nouveau nœud"
		return resp, http.StatusOK
	}
	if after > seq || !n.d.Repl.Has(ctx, after, fepoch) {
		resp.Snapshot, resp.Reason = true, "historique différent"
		// Tell the follower where our history diverged from its epoch.
		if eps, err := n.d.Repl.Epochs(ctx); err == nil {
			var next uint64
			for _, e := range eps {
				if e.Epoch > fepoch && (next == 0 || e.StartSeq < next) {
					next = e.StartSeq
				}
			}
			resp.Changes = []proto.Change{{Epoch: fepoch, Seq: next}} // marker: divergent from this seq
		}
		return resp, http.StatusOK
	}
	if oldest := n.d.Repl.Oldest(ctx); oldest > 0 && after+1 < oldest {
		resp.Snapshot, resp.Reason = true, "trop en retard"
		return resp, http.StatusOK
	}
	// Long poll: wait up to 1 s for something new.
	deadline := time.Now().Add(time.Second)
	for {
		ch, err := n.d.Repl.ChangesAfter(ctx, after, 500)
		if err != nil {
			return map[string]string{"error": err.Error()}, http.StatusInternalServerError
		}
		if len(ch) > 0 || time.Now().After(deadline) || ctx.Err() != nil {
			resp.Changes = ch
			resp.Epoch, resp.Seq = n.position(ctx)
			return resp, http.StatusOK
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (n *Node) hSnapshot(r *http.Request) (any, int) {
	snap, err := n.d.Repl.Snapshot(r.Context())
	if err != nil {
		return map[string]string{"error": err.Error()}, http.StatusInternalServerError
	}
	kek, err := pki.KEK(n.d.Config.ClusterKey)
	if err != nil {
		return map[string]string{"error": err.Error()}, http.StatusInternalServerError
	}
	wrap, _ := secrets.NewBox(kek)
	snap.DEK = wrap.Seal(n.d.Box.Key(), "cluster-dek")
	snap.Epochs, _ = n.d.Repl.Epochs(r.Context())
	return snap, http.StatusOK
}

// ---- config replication (follower side) ----

func (n *Node) follow(ctx context.Context) {
	for ctx.Err() == nil {
		n.mu.Lock()
		var target pullTarget
		if n.role == proto.RoleSecondary {
			if p := n.livePrimary(); p != nil && p.compat.ok {
				target = pullTarget{addr: p.addr, compatMsg: p.compat.message}
			}
		}
		force := n.forceResync
		n.mu.Unlock()
		if target.addr == "" {
			time.Sleep(n.interval())
			continue
		}
		if err := n.pull(ctx, target, force); err != nil {
			n.log().Warn("config sync", "err", err)
			time.Sleep(n.interval())
		}
	}
}

// pullTarget is a copy of what the follower needs from the primary's peer
// entry (peers are updated concurrently by the heartbeats).
type pullTarget struct {
	addr      string
	compatMsg string
}

func (n *Node) pull(ctx context.Context, p pullTarget, force bool) error {
	epoch, seq := n.position(ctx)
	if force {
		n.syncMu.Lock()
		defer n.syncMu.Unlock()
		if !n.stillFollowing(p.addr) {
			return nil
		}
		return n.snapshotLocked(ctx, p, false, "resynchronisation demandée")
	}
	var resp proto.ChangesResponse
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/cluster/v1/changes?after=%d&epoch=%d&node=%s", p.addr, seq, epoch, n.d.NodeID)
	if err := n.do(cctx, http.MethodGet, url, nil, &resp); err != nil {
		return err
	}
	n.mu.Lock()
	if resp.Frozen {
		n.frozen = p.compatMsg
	} else {
		n.frozen = ""
	}
	n.mu.Unlock()
	// Apply only if still following (the role may have changed meanwhile:
	// a node that became primary must never take changes from the peer).
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	if !n.stillFollowing(p.addr) {
		return nil
	}
	if !resp.Snapshot && resp.DEK != "" && resp.DEK != dekFingerprint(n.d.Box.Key()) {
		// The primary's data key changed (backup restored): rows ahead are
		// encrypted with a key we do not have yet. The snapshot carries it.
		resp.Snapshot, resp.Reason, resp.Changes = true, "clé de données changée (restauration)", nil
	}
	if resp.Snapshot {
		// One marker change: our history diverged from the primary's.
		return n.snapshotLocked(ctx, p, len(resp.Changes) == 1, resp.Reason)
	}
	if len(resp.Changes) == 0 {
		n.markApplied()
		return nil
	}
	if err := n.d.Repl.Apply(ctx, resp.Changes); err != nil {
		// Something does not fit (manual edit, bug): start over cleanly.
		n.log().Error("applying changes failed, taking a snapshot", "err", err)
		return n.snapshotLocked(ctx, p, false, "erreur d'application")
	}
	n.markApplied()
	n.d.ConfigApplied(ctx)
	return nil
}

func (n *Node) stillFollowing(addr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != proto.RoleSecondary {
		return false
	}
	p := n.peers[addr]
	return p != nil && p.status.NodeID == n.primaryID
}

func (n *Node) markApplied() {
	n.mu.Lock()
	n.lastApplied = time.Now()
	n.mu.Unlock()
}

// snapshotLocked replaces the config with the primary's (n.syncMu held).
// When our history diverged, the local changes the primary does not have
// are kept as conflicts first.
func (n *Node) snapshotLocked(ctx context.Context, p pullTarget, diverged bool, reason string) error {
	var snap proto.Snapshot
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := n.doLong(cctx, http.MethodGet, p.addr+"/cluster/v1/snapshot", nil, &snap); err != nil {
		return err
	}
	kek, err := pki.KEK(n.d.Config.ClusterKey)
	if err != nil {
		return err
	}
	unwrap, _ := secrets.NewBox(kek)
	dek, err := unwrap.Open(snap.DEK, "cluster-dek")
	if err != nil {
		return fmt.Errorf("clé de données du cluster illisible (clé de cluster différente ?) : %w", err)
	}
	if !bytes.Equal(dek, n.d.Box.Key()) {
		if err := n.d.SetDEK(ctx, dek); err != nil {
			return err
		}
	}
	if diverged {
		// After the download (a failed one is retried) and before the
		// journal is replaced; SaveConflicts is idempotent.
		k, err := n.d.Repl.SaveConflicts(ctx, snap.Epochs, snap.Seq)
		if err != nil {
			return fmt.Errorf("conflits : %w", err)
		}
		if k > 0 {
			n.log().Warn("changes made here were not replicated before the failover: kept as conflicts", "count", k)
			if n.d.Audit != nil {
				n.d.Audit(ctx, "cluster.conflicts", n.d.Config.NodeName, map[string]any{"count": k})
			}
		}
	}
	if err := n.d.Repl.ApplySnapshot(ctx, &snap); err != nil {
		return err
	}
	n.mu.Lock()
	n.forceResync = false
	n.epoch = max(n.epoch, snap.Epoch)
	n.lastApplied = time.Now()
	n.mu.Unlock()
	n.log().Info("configuration synchronized from the primary (snapshot)", "reason", reason, "epoch", snap.Epoch, "seq", snap.Seq)
	n.d.ConfigApplied(ctx)
	return nil
}

// ---- state and leases ----

func (n *Node) hState(r *http.Request) (any, int) {
	var rows []proto.StateRow
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&rows); err != nil {
		return map[string]string{"error": "bad request"}, http.StatusBadRequest
	}
	if err := n.d.Repl.ApplyState(r.Context(), rows); err != nil {
		return map[string]string{"error": err.Error()}, http.StatusInternalServerError
	}
	return map[string]bool{"ok": true}, http.StatusOK
}

func (n *Node) hFullState(r *http.Request) (any, int) {
	rows, err := n.d.Repl.FullState(r.Context())
	if err != nil {
		return map[string]string{"error": err.Error()}, http.StatusInternalServerError
	}
	return rows, http.StatusOK
}

func toUpdate(l dhcpsrv.Lease) proto.LeaseUpdate {
	return proto.LeaseUpdate{ScopeID: l.ScopeID, IP: l.IP.String(), MAC: l.MAC, ClientID: l.ClientID, Hostname: l.Hostname,
		State: l.State, Starts: l.Starts, Ends: l.Ends, CircuitID: l.CircuitID, RemoteID: l.RemoteID, GIAddr: l.GIAddr,
		Owner: l.Owner, HLC: l.HLC}
}

func fromUpdate(u proto.LeaseUpdate) (dhcpsrv.Lease, bool) {
	ip, err := netip.ParseAddr(u.IP)
	if err != nil || !ip.Is4() {
		return dhcpsrv.Lease{}, false // DHCPv4 leases only
	}
	return dhcpsrv.Lease{ScopeID: u.ScopeID, IP: ip, MAC: u.MAC, ClientID: u.ClientID, Hostname: u.Hostname, State: u.State,
		Starts: u.Starts, Ends: u.Ends, CircuitID: u.CircuitID, RemoteID: u.RemoteID, GIAddr: u.GIAddr, Owner: u.Owner, HLC: u.HLC}, true
}

func (n *Node) hLeases(r *http.Request) (any, int) {
	var ups []proto.LeaseUpdate
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&ups); err != nil {
		return map[string]string{"error": "bad request"}, http.StatusBadRequest
	}
	list := make([]dhcpsrv.Lease, 0, len(ups))
	for _, u := range ups {
		if l, ok := fromUpdate(u); ok {
			list = append(list, l)
		}
	}
	n.d.DHCP.ApplyRemote(r.Context(), list)
	return map[string]bool{"ok": true}, http.StatusOK
}

func (n *Node) hAllLeases(*http.Request) (any, int) {
	all := n.d.DHCP.Leases()
	out := make([]proto.LeaseUpdate, 0, len(all))
	for _, l := range all {
		out = append(out, toUpdate(l))
	}
	return out, http.StatusOK
}

// alivePeers returns the peers we can sync leases/state with.
func (n *Node) alivePeers() []*peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*peer
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.ok {
			out = append(out, p)
		}
	}
	return out
}

// syncLeasesNow sends pending lease changes and waits for the peer (500 ms
// max). Called before each DHCPACK.
func (n *Node) syncLeasesNow(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	n.shipLeases(cctx)
}

func (n *Node) shipLeases(ctx context.Context) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	peers := n.alivePeers()
	if len(peers) == 0 {
		// Peer down: keep the outbox (capped by the engine); the full
		// exchange at its return also covers what was dropped.
		return
	}
	list := n.d.DHCP.TakeOutbox()
	if len(list) == 0 {
		return
	}
	ups := make([]proto.LeaseUpdate, 0, len(list))
	for _, l := range list {
		ups = append(ups, toUpdate(l))
	}
	for _, p := range peers {
		if err := n.post(ctx, p.addr+"/cluster/v1/leases", ups, nil); err != nil {
			n.d.DHCP.Requeue(list)
			return
		}
	}
}

func (n *Node) shipState(ctx context.Context) {
	peers := n.alivePeers()
	if len(peers) == 0 {
		return
	}
	idsOut, rows, err := n.d.Repl.Outbox(ctx, 2000)
	if err != nil || len(rows) == 0 {
		return
	}
	for _, p := range peers {
		if err := n.post(ctx, p.addr+"/cluster/v1/state", rows, nil); err != nil {
			return
		}
	}
	_ = n.d.Repl.AckOutbox(ctx, idsOut[len(idsOut)-1])
}

func (n *Node) shipLoop(ctx context.Context) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			n.shipLeases(sctx)
			n.shipState(sctx)
			cancel()
		}
	}
}

// fullExchange pulls all leases and state of a peer that just came back.
// It fails unless both were received and applied.
func (n *Node) fullExchange(ctx context.Context, p *peer) error {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var ups []proto.LeaseUpdate
	if err := n.doLong(cctx, http.MethodGet, p.addr+"/cluster/v1/leases", nil, &ups); err != nil {
		return fmt.Errorf("baux : %w", err)
	}
	list := make([]dhcpsrv.Lease, 0, len(ups))
	for _, u := range ups {
		if l, ok := fromUpdate(u); ok {
			list = append(list, l)
		}
	}
	n.d.DHCP.ApplyRemote(cctx, list)
	var rows []proto.StateRow
	if err := n.doLong(cctx, http.MethodGet, p.addr+"/cluster/v1/state", nil, &rows); err != nil {
		return fmt.Errorf("état : %w", err)
	}
	if err := n.d.Repl.ApplyState(cctx, rows); err != nil {
		return fmt.Errorf("état : %w", err)
	}
	return nil
}

// ---- planned switchover ----

func (n *Node) hHandoff(r *http.Request) (any, int) {
	var h proto.Handoff
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&h); err != nil {
		return map[string]string{"error": "bad request"}, http.StatusBadRequest
	}
	_, seq := n.position(r.Context())
	if seq != h.Seq {
		return map[string]string{"error": "pas à jour"}, http.StatusConflict
	}
	n.becomePrimary(context.WithoutCancel(r.Context()), h.Epoch, "retour du primaire d'origine")
	return map[string]bool{"ok": true}, http.StatusOK
}

// dekFingerprint identifies a data key without revealing it.
func dekFingerprint(key []byte) string {
	h := sha256.Sum256(append([]byte("leazone-dek-id:"), key...))
	return hex.EncodeToString(h[:8])
}
