package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New[string](2, 4, 3)
	l.SetClock(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("over the burst allowed")
	}
	if !l.Allow("b") {
		t.Fatal("other key limited")
	}
	now = now.Add(500 * time.Millisecond) // one token back
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("refill")
	}
	// Table full: a new key is refused while no bucket is full again.
	l.Allow("c")
	if l.Allow("d") {
		t.Fatal("new key accepted with a full table")
	}
	now = now.Add(3 * time.Second) // every bucket full again: purged
	if !l.Allow("d") || l.Len() != 1 {
		t.Fatalf("purge: len %d", l.Len())
	}
}
