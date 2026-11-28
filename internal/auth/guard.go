package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Brute-force protection: after N failures a key is locked for 1 minute,
// then the lock doubles at each new failure, up to 1 hour. Counters are
// forgotten after 24 hours without failure.
const (
	userThreshold = 5
	ipThreshold   = 20
	baseLock      = time.Minute
	maxLock       = time.Hour
	guardMemory   = 24 * time.Hour
	// ipInFlight is the number of attempts of one client verified at once.
	ipInFlight = 4
)

// RateLimitError tells the client how long to wait.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("trop de tentatives, réessayez dans %d s", int(e.RetryAfter.Seconds())+1)
}

func threshold(key string) int {
	if strings.HasPrefix(key, "ip:") {
		return ipThreshold
	}
	return userThreshold
}

// GuardCheck returns a *RateLimitError if any key is locked.
func (s *Service) GuardCheck(ctx context.Context, keys ...string) error {
	now := s.Now()
	var worst time.Duration
	for _, k := range keys {
		var until int64
		err := s.db.QueryRowContext(ctx, `SELECT locked_until FROM login_guard WHERE key = ?`, k).Scan(&until)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if d := time.UnixMilli(until).Sub(now); d > worst {
			worst = d
		}
	}
	if worst > 0 {
		return &RateLimitError{RetryAfter: worst}
	}
	return nil
}

// GuardEnter is GuardCheck for an attempt that is about to be verified. The
// check and the reservation of the attempt are atomic: concurrent attempts
// count as already failed until they end, so a parallel burst cannot run
// more attempts than the threshold allows. The caller records the outcome
// (GuardFail / GuardReset) and then calls release.
func (s *Service) GuardEnter(ctx context.Context, keys ...string) (release func(), err error) {
	s.guardMu.Lock()
	defer s.guardMu.Unlock()
	now := s.Now()
	var worst time.Duration
	for _, k := range keys {
		var failures int
		var until, updated int64
		err := s.db.QueryRowContext(ctx, `SELECT failures, locked_until, updated_at FROM login_guard WHERE key = ?`, k).
			Scan(&failures, &until, &updated)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if now.Sub(time.UnixMilli(updated)) > guardMemory {
			failures = 0
		}
		if d := time.UnixMilli(until).Sub(now); d > worst {
			worst = d
		}
		// Attempts in flight may all still fail: refuse one that could go
		// over the threshold until they end.
		if n := s.inflight[k]; n > 0 && failures+n >= threshold(k) && worst < time.Second {
			worst = time.Second
		}
		// Each attempt may cost an Argon2 computation: one client cannot
		// run many at once even below its failure threshold.
		if strings.HasPrefix(k, "ip:") && s.inflight[k] >= ipInFlight && worst < time.Second {
			worst = time.Second
		}
	}
	if worst > 0 {
		return nil, &RateLimitError{RetryAfter: worst}
	}
	if s.inflight == nil {
		s.inflight = map[string]int{}
	}
	for _, k := range keys {
		s.inflight[k]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.guardMu.Lock()
			defer s.guardMu.Unlock()
			for _, k := range keys {
				if s.inflight[k]--; s.inflight[k] <= 0 {
					delete(s.inflight, k)
				}
			}
		})
	}, nil
}

// GuardFail records one failure for each key and locks keys over threshold.
func (s *Service) GuardFail(ctx context.Context, keys ...string) error {
	now := s.Now()
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, k := range keys {
			var failures int
			var updated int64
			err := tx.QueryRowContext(ctx, `SELECT failures, updated_at FROM login_guard WHERE key = ?`, k).Scan(&failures, &updated)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if now.Sub(time.UnixMilli(updated)) > guardMemory {
				failures = 0
			}
			failures++
			var locked int64
			if over := failures - threshold(k); over >= 0 {
				d := baseLock << min(over, 10)
				if d > maxLock {
					d = maxLock
				}
				locked = now.Add(d).UnixMilli()
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO login_guard(key, failures, locked_until, updated_at) VALUES (?, ?, ?, ?)
				ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, locked_until = excluded.locked_until,
				updated_at = excluded.updated_at`, k, failures, locked, now.UnixMilli()); err != nil {
				return err
			}
		}
		return nil
	})
}

// GuardReset clears the counters of the given keys (after a success).
func (s *Service) GuardReset(ctx context.Context, keys ...string) error {
	for _, k := range keys {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM login_guard WHERE key = ?`, k); err != nil {
			return err
		}
	}
	return nil
}

func randRead(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
