package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/cluster/repl"
	"github.com/prohand/leazone/internal/store"
)

// NotPrimaryError is returned for config writes on a secondary.
type NotPrimaryError struct{ PrimaryURL, PrimaryName string }

func (e NotPrimaryError) Error() string {
	if e.PrimaryName != "" {
		return "ce nœud est secondaire : modifiez la configuration sur le primaire (" + e.PrimaryName + ")"
	}
	return "ce nœud n'est pas primaire : configuration en lecture seule"
}

// FrozenError is returned while the nodes run different versions.
type FrozenError struct{ Msg string }

func (e FrozenError) Error() string { return e.Msg }

// IsPrimary reports whether config may be written here.
func (n *Node) IsPrimary() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.role == proto.RolePrimary
}

// Writable returns nil when a config change is allowed on this node.
func (n *Node) Writable() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != proto.RolePrimary {
		name := ""
		for _, p := range n.peers {
			if p.status.NodeID == n.primaryID {
				name = p.status.Name
			}
		}
		return NotPrimaryError{PrimaryURL: n.primaryURL, PrimaryName: name}
	}
	if n.handingOff {
		return FrozenError{"rebascule en cours : réessayez dans quelques secondes"}
	}
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.ok && !p.compat.config {
			return FrozenError{p.compat.message}
		}
	}
	return nil
}

// AfterWrite waits until the change just written is safe: applied by the
// secondary (2 s max), or else recorded as committed by the witness.
func (n *Node) AfterWrite(ctx context.Context) {
	_, seq := n.position(ctx)
	n.mu.Lock()
	var follower *peer
	for _, p := range n.peers {
		if p.alive(n.deadAfter()) && p.compat.config && time.Since(p.ackedAt) < 3*n.interval() {
			follower = p
		}
	}
	epoch := n.epoch
	n.mu.Unlock()
	if follower != nil {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			n.mu.Lock()
			acked := follower.acked
			n.mu.Unlock()
			if acked >= seq {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if n.witnessM == "container" {
		resp, err := n.witnessCall(ctx, "renew", proto.LeaseRequest{NodeID: n.d.NodeID, Name: n.d.Config.NodeName, Epoch: epoch,
			Seq: seq, LeaseMs: int64(n.Settings().LeaseMs)})
		if err == nil && resp.Granted {
			return
		}
	}
	n.log().Warn("configuration change not yet replicated (the other node is down or late)", "seq", seq)
}

// NodeView is a node as shown on the Cluster page.
type NodeView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Addr        string     `json:"addr"`
	Self        bool       `json:"self"`
	Online      bool       `json:"online"`
	Role        proto.Role `json:"role"`
	Preferred   string     `json:"preferredRole"`
	LatencyMs   float64    `json:"latencyMs"`
	LastSeen    *time.Time `json:"lastSeen"`
	LastSync    *time.Time `json:"lastSync"`
	Epoch       uint64     `json:"epoch"`
	Seq         uint64     `json:"seq"`
	ConfigHash  string     `json:"configHash"`
	Version     string     `json:"version"`
	PartnerDown bool       `json:"partnerDown"`
	Error       string     `json:"error"`
}

// Gap is a difference detected between nodes.
type Gap struct {
	Kind   string `json:"kind"` // config | vlan | version | sync
	Detail string `json:"detail"`
}

// View is the Cluster page model.
type View struct {
	Enabled     bool               `json:"enabled"`
	Role        proto.Role         `json:"role"`
	Epoch       uint64             `json:"epoch"`
	Seq         uint64             `json:"seq"`
	PrimaryURL  string             `json:"primaryUrl"`
	Writable    bool               `json:"writable"`
	ReadOnlyWhy string             `json:"readOnlyReason"`
	Nodes       []NodeView         `json:"nodes"`
	Witness     WitnessView        `json:"witness"`
	Gaps        []Gap              `json:"gaps"`
	Conflicts   int                `json:"conflicts"`
	History     []proto.EpochStart `json:"history"`
	Settings    Settings           `json:"settings"`
	VIP         *VIPView           `json:"vip"`
}

// WitnessView describes the witness.
type WitnessView struct {
	Mode      string     `json:"mode"` // container | ping | none
	Address   string     `json:"address"`
	Reachable bool       `json:"reachable"`
	LastOK    *time.Time `json:"lastOk"`
	Error     string     `json:"error"`
	Epoch     uint64     `json:"epoch"`
	Primary   string     `json:"primary"`
}

// VIPView describes the virtual IP.
type VIPView struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	HeldHere  bool   `json:"heldHere"`
	Error     string `json:"error"`
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// Status builds the Cluster page model.
func (n *Node) Status(ctx context.Context) View {
	self := n.selfStatus(ctx)
	conflicts, _ := n.d.Repl.Conflicts(ctx)
	pending := 0
	for _, c := range conflicts {
		if c.Status == "pending" {
			pending++
		}
	}
	hist, _ := n.d.Repl.Epochs(ctx)
	werr := n.Writable()
	n.mu.Lock()
	defer n.mu.Unlock()
	v := View{Enabled: true, Role: n.role, Epoch: n.epoch, Seq: self.Seq, PrimaryURL: n.primaryURL, Writable: werr == nil,
		Conflicts: pending, History: hist, Settings: n.Settings(), Gaps: []Gap{}}
	if werr != nil {
		v.ReadOnlyWhy = werr.Error()
	}
	v.Nodes = append(v.Nodes, NodeView{ID: self.NodeID, Name: self.Name, Addr: self.Addr, Self: true, Online: true, Role: n.role,
		Preferred: self.Preferred, Epoch: n.epoch, Seq: self.Seq, ConfigHash: self.ConfigHash, Version: self.Version,
		PartnerDown: n.partnerDown, LastSync: tp(n.lastApplied)})
	for _, p := range n.peers {
		st := p.status
		last := p.lastOK
		if p.lastIn.After(last) {
			last = p.lastIn
		}
		nv := NodeView{ID: st.NodeID, Name: st.Name, Addr: p.addr, Online: p.alive(n.deadAfter()), Role: st.Role,
			Preferred: st.Preferred, LatencyMs: float64(p.latency.Microseconds()) / 1000, LastSeen: tp(last),
			LastSync: tp(st.LastAppliedAt), Epoch: st.Epoch, Seq: st.Seq, ConfigHash: st.ConfigHash, Version: st.Version,
			PartnerDown: st.PartnerDown, Error: p.lastErr}
		if nv.Name == "" {
			nv.Name = p.addr
		}
		if !nv.Online {
			nv.Role = "offline"
		}
		v.Nodes = append(v.Nodes, nv)
		if !nv.Online {
			continue
		}
		if p.compat.message != "" {
			v.Gaps = append(v.Gaps, Gap{"version", p.compat.message})
		}
		if st.Seq == self.Seq && st.ConfigHash != "" && st.ConfigHash != self.ConfigHash {
			v.Gaps = append(v.Gaps, Gap{"config", "même version de configuration mais contenu différent sur " + st.Name +
				" : utilisez « Forcer la resynchro »"})
		} else if st.Seq != self.Seq {
			v.Gaps = append(v.Gaps, Gap{"sync", st.Name + " n'est pas encore à jour (version " + itoa(st.Seq) + " / " + itoa(self.Seq) + ")"})
		}
		for _, g := range vlanGaps(self.Name, self.VLANs, st.Name, st.VLANs) {
			v.Gaps = append(v.Gaps, g)
		}
	}
	sort.SliceStable(v.Nodes, func(i, j int) bool { return v.Nodes[i].Name < v.Nodes[j].Name })
	v.Witness = WitnessView{Mode: n.witnessM, Address: n.d.Config.Witness, Reachable: n.witness.reachable,
		LastOK: tp(n.witness.lastOK), Error: n.witness.lastErr, Epoch: n.witness.state.Epoch, Primary: n.witness.state.PrimaryName}
	if n.d.VIP != nil {
		held, verr := n.d.VIP.Status()
		v.VIP = &VIPView{Address: n.d.VIP.Prefix.String(), Interface: n.d.VIP.Interface, HeldHere: held, Error: verr}
	}
	return v
}

func itoa(v uint64) string { b, _ := json.Marshal(v); return string(b) }

// vlanGaps lists VLANs seen on one node but not on the other.
func vlanGaps(aName string, a []string, bName string, b []string) []Gap {
	in := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	var out []Gap
	for _, v := range a {
		if !in(b, v) {
			out = append(out, Gap{"vlan", "VLAN " + v + " présent sur " + aName + " mais absent de " + bName})
		}
	}
	for _, v := range b {
		if !in(a, v) {
			out = append(out, Gap{"vlan", "VLAN " + v + " présent sur " + bName + " mais absent de " + aName})
		}
	}
	return out
}

// Resync forces a full snapshot: here if secondary, on the peers if primary.
func (n *Node) Resync(ctx context.Context) error {
	n.mu.Lock()
	role := n.role
	n.mu.Unlock()
	if role != proto.RolePrimary {
		n.mu.Lock()
		n.forceResync = true
		n.mu.Unlock()
		return nil
	}
	var lastErr error
	for _, p := range n.alivePeers() {
		if err := n.post(ctx, p.addr+"/cluster/v1/resync", map[string]bool{}, nil); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// SetSettings stores new cluster settings (on the primary, replicated).
func (n *Node) SetSettings(ctx context.Context, st Settings) error {
	if errs := st.Validate(); len(errs) > 0 {
		return SettingsError(errs)
	}
	if err := n.d.DB.PutSetting(ctx, SettingsKey, st); err != nil {
		return err
	}
	n.loadSettings(ctx)
	n.applyDHCPPolicy()
	return nil
}

// SettingsError carries field errors.
type SettingsError map[string]string

func (e SettingsError) Error() string { return "paramètres de cluster invalides" }

// Reload is called after replicated changes (settings may have changed).
func (n *Node) Reload(ctx context.Context) {
	n.loadSettings(ctx)
	n.applyDHCPPolicy()
}

// Conflicts lists the changes lost by this node as a former primary.
func (n *Node) Conflicts(ctx context.Context) ([]repl.Conflict, error) {
	return n.d.Repl.Conflicts(ctx)
}

// Reapply applies a conflict on the primary (forwarded when needed).
func (n *Node) Reapply(ctx context.Context, id string) error {
	list, err := n.d.Repl.Conflicts(ctx)
	if err != nil {
		return err
	}
	var c *repl.Conflict
	for i := range list {
		if list[i].ID == id && list[i].Status == "pending" {
			c = &list[i]
		}
	}
	if c == nil {
		return store.ErrNotFound
	}
	if n.IsPrimary() {
		return n.d.Repl.Reapply(ctx, id)
	}
	n.mu.Lock()
	primary := n.livePrimary()
	n.mu.Unlock()
	if primary == nil {
		return errors.New("aucun primaire joignable")
	}
	if err := n.post(ctx, primary.addr+"/cluster/v1/reapply", proto.Change{Table: c.Table, PK: c.PK, Op: c.Op, Row: c.Row}, nil); err != nil {
		return err
	}
	return n.d.Repl.Dismiss(ctx, id) // done on the primary
}

// Dismiss ignores a conflict.
func (n *Node) Dismiss(ctx context.Context, id string) error { return n.d.Repl.Dismiss(ctx, id) }

func (n *Node) hReapply(r *http.Request) (any, int) {
	var c proto.Change
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c); err != nil {
		return map[string]string{"error": "bad request"}, http.StatusBadRequest
	}
	if !n.IsPrimary() {
		return map[string]string{"error": "not primary"}, http.StatusConflict
	}
	if err := n.d.Repl.ApplyLocal(r.Context(), c); err != nil {
		return map[string]string{"error": err.Error()}, http.StatusInternalServerError
	}
	n.d.ConfigApplied(r.Context())
	return map[string]bool{"ok": true}, http.StatusOK
}
