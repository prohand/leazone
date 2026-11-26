// Package witness is the tie-breaker of a two-node cluster. It runs on a
// third host ("leazone witness"), stores almost nothing (epoch, current
// primary, last committed config change) and grants a time-limited primary
// lease. A node becomes primary only with this lease, so two nodes cut from
// each other can never both be primary.
package witness

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
	"github.com/prohand/leazone/internal/version"
)

const (
	minLease = 2 * time.Second
	maxLease = 60 * time.Second
)

// persisted is what survives a restart.
type persisted struct {
	Epoch       uint64 `json:"epoch"`
	PrimaryID   string `json:"primaryId"`
	PrimaryName string `json:"primaryName"`
	Committed   uint64 `json:"committed"`
	// CommittedEpoch is the epoch of the committed change (0: unknown,
	// e.g. a state file written by an older version).
	CommittedEpoch uint64 `json:"committedEpoch,omitempty"`
}

// Witness holds the lease.
type Witness struct {
	path string
	log  *slog.Logger
	now  func() time.Time // monotonic clock in production

	mu      sync.Mutex
	st      persisted
	expires time.Time
}

// New loads the state file. After a restart the lease is considered held
// for one more lease period, so a primary that was renewing keeps its role.
func New(dataDir string, log *slog.Logger) (*Witness, error) {
	w := &Witness{path: filepath.Join(dataDir, "witness.json"), log: log, now: time.Now}
	b, err := os.ReadFile(w.path)
	if err == nil {
		if err := json.Unmarshal(b, &w.st); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	w.expires = w.now().Add(maxLease / 2)
	return w, nil
}

// commit saves st then makes it the current state. On a write error
// nothing changes (neither the state nor the lease).
func (w *Witness) commit(st persisted, expires time.Time) error {
	if st != w.st {
		if err := w.save(st); err != nil {
			return err
		}
	}
	w.st, w.expires = st, expires
	return nil
}

func (w *Witness) save(st persisted) error {
	b, _ := json.Marshal(st)
	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, w.path)
}

func leaseOf(ms int64) time.Duration {
	d := time.Duration(ms) * time.Millisecond
	if d < minLease {
		d = minLease
	}
	if d > maxLease {
		d = maxLease
	}
	return d
}

func (w *Witness) resp(granted bool, reason string) proto.LeaseResponse {
	return proto.LeaseResponse{Granted: granted, Epoch: w.st.Epoch, PrimaryID: w.st.PrimaryID, PrimaryName: w.st.PrimaryName,
		Committed: w.st.Committed, CommittedEpoch: w.st.CommittedEpoch, Reason: reason}
}

// raise records (lastEpoch, seq) as committed when it is further than the
// current committed position. Without lastEpoch (older node) only the seq
// is known.
func (st *persisted) raise(lastEpoch *uint64, seq uint64) {
	if lastEpoch == nil {
		st.Committed = max(st.Committed, seq)
		return
	}
	if *lastEpoch > st.CommittedEpoch || (*lastEpoch == st.CommittedEpoch && seq > st.Committed) {
		st.CommittedEpoch, st.Committed = *lastEpoch, seq
	}
}

// behind reports whether a node at (lastEpoch, seq) may miss committed
// changes: its last change is older than the committed one, by seq or by
// epoch (a higher seq in an older epoch is a divergent history, not a
// more recent one).
func (st *persisted) behind(lastEpoch *uint64, seq uint64) bool {
	if seq < st.Committed {
		return true
	}
	return lastEpoch != nil && *lastEpoch < st.CommittedEpoch
}

// Renew extends the lease of the current primary and records its last
// committed change.
func (w *Witness) Renew(r proto.LeaseRequest) proto.LeaseResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.NodeID != w.st.PrimaryID || r.Epoch != w.st.Epoch {
		return w.resp(false, "ce nœud n'est plus le primaire")
	}
	next := w.st
	next.raise(r.LastEpoch, r.Seq)
	if err := w.commit(next, w.now().Add(leaseOf(r.LeaseMs))); err != nil {
		return w.resp(false, "témoin : écriture impossible : "+err.Error())
	}
	return w.resp(true, "")
}

// Acquire grants the primary role to a node when the previous primary's
// lease has expired and the candidate has every committed change.
func (w *Witness) Acquire(r proto.LeaseRequest) proto.LeaseResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if w.st.PrimaryID != "" && w.st.PrimaryID != r.NodeID && now.Before(w.expires) {
		return w.resp(false, "le primaire actuel ("+w.st.PrimaryName+") est toujours en vie")
	}
	if w.st.behind(r.LastEpoch, r.Seq) {
		return w.resp(false, "ce nœud n'a pas toutes les modifications validées : il ne peut pas devenir primaire")
	}
	next := w.st
	next.Epoch++
	next.PrimaryID, next.PrimaryName = r.NodeID, r.Name
	next.raise(r.LastEpoch, r.Seq)
	if err := w.commit(next, now.Add(leaseOf(r.LeaseMs))); err != nil {
		return w.resp(false, "témoin : écriture impossible : "+err.Error())
	}
	w.log.Info("primary lease granted", "node", r.Name, "epoch", w.st.Epoch)
	return w.resp(true, "")
}

// Transfer hands the lease from the current primary to another node
// (planned switchover, e.g. return of the original primary).
func (w *Witness) Transfer(r proto.LeaseRequest) proto.LeaseResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.NodeID != w.st.PrimaryID || r.Epoch != w.st.Epoch {
		return w.resp(false, "seul le primaire actuel peut céder son rôle")
	}
	if r.ToSeq < w.st.Committed || r.ToSeq < r.Seq {
		return w.resp(false, "le nœud cible n'est pas à jour")
	}
	next := w.st
	next.Epoch++
	next.PrimaryID, next.PrimaryName = r.To, r.ToName
	next.raise(r.LastEpoch, r.Seq)
	if err := w.commit(next, w.now().Add(leaseOf(r.LeaseMs))); err != nil {
		return w.resp(false, "témoin : écriture impossible : "+err.Error())
	}
	w.log.Info("primary lease transferred", "to", r.ToName, "epoch", w.st.Epoch)
	return w.resp(true, "")
}

// State reports the current state.
func (w *Witness) State() proto.WitnessState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return proto.WitnessState{Epoch: w.st.Epoch, PrimaryID: w.st.PrimaryID, PrimaryName: w.st.PrimaryName,
		Committed: w.st.Committed, CommittedEpoch: w.st.CommittedEpoch, LeaseActive: w.now().Before(w.expires), Version: version.Version, Time: time.Now()}
}

// Handler exposes the witness API.
func (w *Witness) Handler() http.Handler {
	mux := http.NewServeMux()
	post := func(path string, fn func(proto.LeaseRequest) proto.LeaseResponse) {
		mux.HandleFunc("POST "+path, func(rw http.ResponseWriter, r *http.Request) {
			var req proto.LeaseRequest
			if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 1<<16)).Decode(&req); err != nil {
				http.Error(rw, "bad request", http.StatusBadRequest)
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(fn(req))
		})
	}
	post("/witness/v1/renew", w.Renew)
	post("/witness/v1/acquire", w.Acquire)
	post("/witness/v1/transfer", w.Transfer)
	mux.HandleFunc("GET /witness/v1/state", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(w.State())
	})
	return mux
}

// Run serves the witness on listen (mutual TLS with the cluster CA).
func Run(ctx context.Context, listen, dataDir, clusterKey string, log *slog.Logger) error {
	ca, err := pki.Derive(clusterKey)
	if err != nil {
		return err
	}
	cert, err := ca.Issue("witness")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	w, err := New(dataDir, log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: w.Handler(), TLSConfig: ca.ServerConfig(cert), ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("witness ready", "listen", listen, "epoch", w.State().Epoch, "primary", w.State().PrimaryName)
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
