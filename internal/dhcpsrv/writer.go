package dhcpsrv

import (
	"context"
	"database/sql"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// leaseWriter persists lease changes in order, outside the engine lock:
// the engine queues each change while it holds e.mu (so the database sees
// them in the order of memory) and a single goroutine writes them, several
// at a time in one transaction. Callers that must not answer before the
// change is on disk (a DHCPACK) wait for it with wait, without the lock.
type leaseWriter struct {
	db  leaseDB
	log *slog.Logger
	q   chan dbOp

	mu       sync.Mutex
	queued   uint64        // sequence of the last queued change
	applied  uint64        // sequence of the last written change
	progress chan struct{} // closed (and replaced) after each batch
}

type dbOp struct {
	seq   uint64
	put   *Lease // nil = delete
	scope string
	ip    netip.Addr
}

// writeQueue bounds the changes waiting to be written: when it is full the
// engine waits (back pressure) instead of growing memory.
const writeQueue = 4096

func newLeaseWriter(db leaseDB, log *slog.Logger) *leaseWriter {
	w := &leaseWriter{db: db, log: log, q: make(chan dbOp, writeQueue), progress: make(chan struct{})}
	go w.run()
	return w
}

// put queues a copy of l (caller holds e.mu).
func (w *leaseWriter) put(l *Lease) {
	c := *l
	w.enqueue(dbOp{put: &c, scope: l.ScopeID, ip: l.IP})
}

// delete queues the removal of a lease (caller holds e.mu).
func (w *leaseWriter) delete(scopeID string, ip netip.Addr) {
	w.enqueue(dbOp{scope: scopeID, ip: ip})
}

func (w *leaseWriter) enqueue(op dbOp) {
	w.mu.Lock()
	w.queued++
	op.seq = w.queued
	w.mu.Unlock()
	w.q <- op
}

// wait returns once every change queued so far is written (or ctx ends).
func (w *leaseWriter) wait(ctx context.Context) {
	w.mu.Lock()
	target := w.queued
	for w.applied < target {
		ch := w.progress
		w.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
		w.mu.Lock()
	}
	w.mu.Unlock()
}

func (w *leaseWriter) run() {
	for op := range w.q {
		batch := []dbOp{op}
	more:
		for len(batch) < 256 {
			select {
			case o := <-w.q:
				batch = append(batch, o)
			default:
				break more
			}
		}
		w.write(batch)
		w.mu.Lock()
		w.applied = batch[len(batch)-1].seq
		close(w.progress)
		w.progress = make(chan struct{})
		w.mu.Unlock()
	}
}

func (w *leaseWriter) write(batch []dbOp) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := w.db.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, op := range batch {
			if err := op.apply(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		return
	}
	// One bad change (its scope was just deleted...) must not lose the
	// others: write them one by one.
	for _, op := range batch {
		if err := op.apply(ctx, w.db.db); err != nil {
			w.log.Error("lease persist failed", "ip", op.ip, "err", err)
		}
	}
}

func (op dbOp) apply(ctx context.Context, x execer) error {
	if op.put != nil {
		return putLease(ctx, x, op.put)
	}
	return deleteLease(ctx, x, op.scope, op.ip)
}
