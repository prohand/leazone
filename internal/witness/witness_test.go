package witness

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/proto"
)

func TestLeaseRules(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	w.now = func() time.Time { return now }
	w.expires = now // fresh witness: nothing held

	a := proto.LeaseRequest{NodeID: "a", Name: "node1", Seq: 10, LeaseMs: 6000}
	r := w.Acquire(a)
	if !r.Granted || r.Epoch != 1 {
		t.Fatalf("first acquire: %+v", r)
	}
	a.Epoch = 1
	// The other node cannot take the role while the lease runs.
	b := proto.LeaseRequest{NodeID: "b", Name: "node2", Seq: 10, LeaseMs: 6000}
	if r := w.Acquire(b); r.Granted {
		t.Fatal("split brain: lease granted twice")
	}
	// Primary renews and commits up to seq 20 (secondary lagging).
	a.Seq = 20
	if r := w.Renew(a); !r.Granted || r.Committed != 20 {
		t.Fatalf("renew: %+v", r)
	}
	// Primary dies: after the lease, a stale secondary is still refused...
	now = now.Add(7 * time.Second)
	if r := w.Acquire(b); r.Granted {
		t.Fatal("stale node promoted: committed changes would be lost")
	}
	// ...an up-to-date one is accepted, with a new epoch.
	b.Seq = 20
	r = w.Acquire(b)
	if !r.Granted || r.Epoch != 2 || r.PrimaryID != "b" {
		t.Fatalf("failover: %+v", r)
	}
	// The old primary coming back cannot renew with its old epoch.
	if r := w.Renew(a); r.Granted {
		t.Fatal("old primary renewed after failover")
	}
	// Planned return: b transfers to a.
	b.Epoch = 2
	if r := w.Transfer(proto.LeaseRequest{NodeID: "b", Name: "node2", Epoch: 2, Seq: 25, To: "a", ToName: "node1", ToSeq: 25, LeaseMs: 6000}); !r.Granted || r.Epoch != 3 || r.PrimaryID != "a" {
		t.Fatalf("transfer: %+v", r)
	}
	// State survives a restart, and the lease is kept for a while.
	w2, _ := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if st := w2.State(); st.Epoch != 3 || st.PrimaryID != "a" || st.Committed != 25 || !st.LeaseActive {
		t.Fatalf("after restart: %+v", st)
	}
}
