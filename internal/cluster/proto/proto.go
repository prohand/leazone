// Package proto holds the messages exchanged between nodes and the witness.
package proto

import "time"

// Role of a node.
type Role string

// Roles and states shown in the UI.
const (
	RoleStandalone   Role = "standalone"   // no cluster configured
	RoleJoining      Role = "joining"      // starting, looking for the primary
	RoleSecondary    Role = "secondary"    // follows the primary
	RolePrimary      Role = "primary"      // source of truth
	RoleIsolated     Role = "isolated"     // lost the primary and cannot promote (no witness)
	RoleIncompatible Role = "incompatible" // versions too different to sync
)

// NodeStatus is sent in every heartbeat.
type NodeStatus struct {
	NodeID        string    `json:"nodeId"`
	Name          string    `json:"name"`
	Addr          string    `json:"addr"`
	PublicURL     string    `json:"publicUrl"`
	Role          Role      `json:"role"`
	Preferred     string    `json:"preferredRole"`
	Epoch         uint64    `json:"epoch"`
	Seq           uint64    `json:"seq"`
	ConfigHash    string    `json:"configHash"`
	Version       string    `json:"version"`
	Protocol      string    `json:"protocol"`
	Schema        int       `json:"schema"`
	VLANs         []string  `json:"vlans"` // "20@eno1.20=192.168.20.0/24"
	PrimaryID     string    `json:"primaryId"`
	PartnerDown   bool      `json:"partnerDown"`
	Time          time.Time `json:"time"`
	StartedAt     time.Time `json:"startedAt"`
	LastAppliedAt time.Time `json:"lastAppliedAt"`
}

// LeaseRequest asks the witness to renew or acquire the primary lease.
type LeaseRequest struct {
	NodeID  string `json:"nodeId"`
	Name    string `json:"name"`
	Epoch   uint64 `json:"epoch"`
	Seq     uint64 `json:"seq"`     // last config change the node has
	LeaseMs int64  `json:"leaseMs"` // requested lease duration
	// LastEpoch is the epoch of the node's last config change (Seq). With
	// Seq it orders histories: a node whose last change belongs to an older
	// epoch than the committed one misses changes even with a higher Seq.
	// Optional: nil from older nodes (the witness then only
	// compares Seq, as before).
	LastEpoch *uint64 `json:"lastEpoch,omitempty"`
	To        string  `json:"to"` // transfer: target node
	ToName    string  `json:"toName"`
	ToSeq     uint64  `json:"toSeq"`
}

// LeaseResponse is the witness answer.
type LeaseResponse struct {
	Granted     bool   `json:"granted"`
	Epoch       uint64 `json:"epoch"`
	PrimaryID   string `json:"primaryId"`
	PrimaryName string `json:"primaryName"`
	Committed   uint64 `json:"committed"`
	// CommittedEpoch is the epoch of the committed change (0 if unknown).
	CommittedEpoch uint64 `json:"committedEpoch,omitempty"`
	Reason         string `json:"reason"`
}

// WitnessState is the public state of the witness.
type WitnessState struct {
	Epoch       uint64 `json:"epoch"`
	PrimaryID   string `json:"primaryId"`
	PrimaryName string `json:"primaryName"`
	Committed   uint64 `json:"committed"`
	// CommittedEpoch is the epoch of the committed change (0 if unknown).
	CommittedEpoch uint64    `json:"committedEpoch,omitempty"`
	LeaseActive    bool      `json:"leaseActive"`
	Version        string    `json:"version"`
	Time           time.Time `json:"time"`
}

// Change is one row change of a config table.
type Change struct {
	Seq   uint64 `json:"seq"`
	Epoch uint64 `json:"epoch"`
	Table string `json:"table"`
	PK    string `json:"pk"`
	Op    string `json:"op"`  // upsert | delete
	Row   string `json:"row"` // JSON object (upsert)
}

// ChangesResponse answers a follower's pull.
type ChangesResponse struct {
	Epoch    uint64   `json:"epoch"`
	Seq      uint64   `json:"seq"`
	Snapshot bool     `json:"snapshot"` // the follower must take a snapshot
	Reason   string   `json:"reason"`
	Changes  []Change `json:"changes"`
	Frozen   bool     `json:"frozen"`        // mixed versions: config is read-only
	DEK      string   `json:"dek,omitempty"` // fingerprint of the primary's data key
}

// Snapshot is the whole replicated configuration.
type Snapshot struct {
	Epoch  uint64                      `json:"epoch"`
	Seq    uint64                      `json:"seq"`
	Epochs []EpochStart                `json:"epochs"`
	DEK    string                      `json:"dek"` // data key wrapped with the cluster KEK
	Tables map[string][]map[string]any `json:"tables"`
	Hashes map[string]string           `json:"hashes"`
}

// EpochStart records when an epoch began.
type EpochStart struct {
	Epoch    uint64    `json:"epoch"`
	StartSeq uint64    `json:"startSeq"` // first seq written in this epoch
	NodeID   string    `json:"nodeId"`
	Name     string    `json:"name"`
	At       time.Time `json:"at"`
	Reason   string    `json:"reason"`
}

// StateRow is a replicated state row (sessions, usage counters, audit...).
type StateRow struct {
	Table string `json:"table"`
	Row   string `json:"row"`
	Op    string `json:"op"`
}

// LeaseUpdate is a replicated DHCP lease.
type LeaseUpdate struct {
	ScopeID   string    `json:"scopeId"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	ClientID  string    `json:"clientId"`
	Hostname  string    `json:"hostname"`
	State     string    `json:"state"`
	Starts    time.Time `json:"starts"`
	Ends      time.Time `json:"ends"`
	CircuitID string    `json:"circuitId"`
	RemoteID  string    `json:"remoteId"`
	GIAddr    string    `json:"giaddr"`
	DNSName   string    `json:"dnsName"`
	Owner     string    `json:"owner"`
	HLC       int64     `json:"hlc"`
}

// Handoff asks a node to become primary (planned switchover).
type Handoff struct {
	FromID string `json:"fromId"`
	Epoch  uint64 `json:"epoch"`
	Seq    uint64 `json:"seq"`
}
