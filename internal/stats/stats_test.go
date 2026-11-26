package stats

import (
	"fmt"
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
