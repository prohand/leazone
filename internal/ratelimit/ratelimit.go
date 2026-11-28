// Package ratelimit is a token bucket per key (client address, MAC...)
// with bounded memory, for the DNS and DHCP servers.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows rate events per second per key, with bursts of burst.
// It tracks at most maxKeys keys: when the table is full, keys whose bucket
// is full again are forgotten (at most once per second); if none can be,
// new keys are refused until some can (fail closed: a flood of new keys
// cannot evict the buckets of the keys being limited).
type Limiter[K comparable] struct {
	rate, burst float64
	maxKeys     int

	mu        sync.Mutex
	now       func() time.Time
	m         map[K]bucket
	lastPurge time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter.
func New[K comparable](rate, burst float64, maxKeys int) *Limiter[K] {
	return &Limiter[K]{rate: rate, burst: burst, maxKeys: maxKeys, now: time.Now, m: map[K]bucket{}}
}

// SetClock replaces the clock (tests).
func (l *Limiter[K]) SetClock(now func() time.Time) {
	l.mu.Lock()
	l.now = now
	l.mu.Unlock()
}

// Allow takes one token for key and reports whether it was available.
func (l *Limiter[K]) Allow(key K) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.m[key]
	if !ok {
		if len(l.m) >= l.maxKeys && !l.purge(now) {
			return false
		}
		b = bucket{tokens: l.burst, last: now}
	} else if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		l.m[key] = b
		return false
	}
	b.tokens--
	l.m[key] = b
	return true
}

// purge forgets the keys whose bucket is full again. It runs at most once
// per second (amortized O(1) per call) and reports whether room was made.
func (l *Limiter[K]) purge(now time.Time) bool {
	if now.Sub(l.lastPurge) < time.Second {
		return false
	}
	l.lastPurge = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.m {
		if now.Sub(b.last) >= full {
			delete(l.m, k)
		}
	}
	return len(l.m) < l.maxKeys
}

// Len is the number of keys tracked.
func (l *Limiter[K]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
