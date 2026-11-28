package stats

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestSummary(t *testing.T) {
	r := New()
	now := time.Date(2026, 11, 26, 12, 30, 15, 0, time.UTC)
	r.Now = func() time.Time { return now }
	for i := 0; i < 120; i++ { // 2 queries/s over the last minute
		r.Record(Query{Time: now.Add(-time.Duration(i) * 500 * time.Millisecond), Client: "10.0.0.1", Name: "a.example.", Source: "cache"})
	}
	r.Record(Query{Time: now.Add(-2 * time.Hour), Client: "10.0.0.2", Name: "old.example", Source: "forwarder"})
	r.Record(Query{Time: now.Add(-25 * time.Hour), Client: "10.0.0.3", Name: "too-old.example", Source: "forwarder"})
	r.Record(Query{Time: now, Client: "10.0.0.2", Name: "ads.example", Source: "blocked"})
	s := r.Summary(5)
	if s.QPS != 2 {
		t.Fatalf("qps %v", s.QPS)
	}
	if s.Queries24h != 122 || s.Blocked24h != 1 {
		t.Fatalf("24h: %+v", s)
	}
	if len(s.Series) != 60 || s.Series[59].Queries == 0 {
		t.Fatalf("series: %+v", s.Series[58:])
	}
	if s.TopDomains[0].Name != "a.example" || s.TopClients[0].Name != "10.0.0.1" || s.TopBlocked[0].Name != "ads.example" {
		t.Fatalf("tops: %+v", s)
	}
	for _, d := range s.TopDomains {
		if d.Name == "too-old.example" {
			t.Fatal("entry older than 24 h")
		}
	}
	if s.CacheHitRate < 99 {
		t.Fatalf("cache rate %v", s.CacheHitRate)
	}
}

func TestBoundedMaps(t *testing.T) {
	r := New()
	now := time.Now()
	for i := 0; i < 3*topCapacity; i++ {
		r.Record(Query{Time: now, Client: "10.0.0.1", Name: fmt.Sprintf("n%d.example", i)})
	}
	h := r.hours[(now.Unix()-now.Unix()%3600)/3600%hours]
	if len(h.domains) > topCapacity {
		t.Fatalf("map grew to %d", len(h.domains))
	}
}

// Once the map is full of names seen several times, new names must not
// cost a full pass each (the pass runs at most once per topCapacity/2 new
// names), and the frequent names stay.
func TestBumpAmortized(t *testing.T) {
	m := map[string]uint64{}
	for i := 0; i < topCapacity; i++ {
		m[fmt.Sprintf("heavy%d", i)] = uint64(5 + i%7)
	}
	m["top"] = 1000
	before := prunes.Load()
	n := 4 * topCapacity
	for i := 0; i < n; i++ {
		bump(m, fmt.Sprintf("new%d", i))
		if len(m) > topCapacity {
			t.Fatalf("map grew to %d", len(m))
		}
	}
	if p := prunes.Load() - before; p > int64(2*n/topCapacity+1) {
		t.Fatalf("%d full passes for %d new names", p, n)
	}
	if m["top"] != 1000 {
		t.Fatal("frequent name dropped")
	}
}

func TestNth(t *testing.T) {
	for _, a := range [][]uint64{{5}, {3, 1, 2}, {1, 1, 1, 1}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}} {
		for k := range a {
			b := append([]uint64(nil), a...)
			c := append([]uint64(nil), a...)
			slices.Sort(c)
			if got := nth(b, k); got != c[k] {
				t.Fatalf("nth(%v, %d) = %d, want %d", a, k, got, c[k])
			}
		}
	}
}
