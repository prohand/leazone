// Package stats keeps the DNS statistics of the dashboard in memory: a
// one-hour series (10-second buckets) and 24 hourly buckets with the top
// domains, clients and blocked domains. Maps are bounded, so memory stays
// small whatever the traffic.
package stats

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	bucket      = 10 * time.Second
	seriesLen   = 360 // one hour of 10 s buckets
	hours       = 24
	topCapacity = 2000 // entries per map per hour
)

// Query is what the DNS server reports for each answer.
type Query struct {
	Time   time.Time
	Client string
	Name   string
	Source string // local, cache, forwarder, blocked, refused, error
	Failed bool   // SERVFAIL or error
}

type slot struct {
	start                    int64 // unix seconds of the bucket start, 0 = empty
	queries, cached, blocked uint64
}

type hourly struct {
	start                            int64
	queries, cached, blocked, failed uint64
	domains, clients, blockedNames   map[string]uint64
}

// Recorder aggregates queries. It is safe for concurrent use.
type Recorder struct {
	mu     sync.Mutex
	series [seriesLen]slot
	hours  [hours]*hourly
	start  time.Time
	Now    func() time.Time
}

// New returns an empty recorder.
func New() *Recorder { return &Recorder{start: time.Now(), Now: time.Now} }

// Started returns when the recorder started.
func (r *Recorder) Started() time.Time { return r.start }

// Record adds a query.
func (r *Recorder) Record(q Query) {
	sec := q.Time.Unix()
	bs := sec - sec%int64(bucket/time.Second)
	hs := sec - sec%3600
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	r.mu.Lock()
	defer r.mu.Unlock()
	// A late (older) query never overwrites a newer bucket.
	s := &r.series[(bs/10)%seriesLen]
	if s.start > bs {
		s = &slot{}
	} else if s.start != bs {
		*s = slot{start: bs}
	}
	s.queries++
	h := r.hours[(hs/3600)%hours]
	if h != nil && h.start > hs {
		return
	}
	if h == nil || h.start != hs {
		h = &hourly{start: hs, domains: map[string]uint64{}, clients: map[string]uint64{}, blockedNames: map[string]uint64{}}
		r.hours[(hs/3600)%hours] = h
	}
	h.queries++
	switch q.Source {
	case "cache":
		s.cached++
		h.cached++
	case "blocked":
		s.blocked++
		h.blocked++
		bump(h.blockedNames, name)
	}
	if q.Failed {
		h.failed++
	}
	if name != "" {
		bump(h.domains, name)
	}
	if q.Client != "" {
		bump(h.clients, q.Client)
	}
}

// bump increments a bounded counter map: when full, the entries seen once
// are dropped (they would not make a top list anyway).
func bump(m map[string]uint64, k string) {
	if _, ok := m[k]; !ok && len(m) >= topCapacity {
		for kk, v := range m {
			if v <= 1 {
				delete(m, kk)
			}
		}
		if len(m) >= topCapacity {
			return
		}
	}
	m[k]++
}

// Point is one minute of the series.
type Point struct {
	T       time.Time `json:"t"`
	Queries uint64    `json:"queries"`
	Cached  uint64    `json:"cached"`
	Blocked uint64    `json:"blocked"`
}

// Count is a top list entry.
type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// Summary is the DNS part of the dashboard.
type Summary struct {
	QPS          float64 `json:"qps"`
	Queries24h   uint64  `json:"queries24h"`
	CacheHitRate float64 `json:"cacheHitRate"`
	Blocked24h   uint64  `json:"blocked24h"`
	Failed24h    uint64  `json:"failed24h"`
	Series       []Point `json:"series"`
	TopDomains   []Count `json:"topDomains"`
	TopClients   []Count `json:"topClients"`
	TopBlocked   []Count `json:"topBlocked"`
}

// Summary computes the dashboard numbers (n entries per top list).
func (r *Recorder) Summary(n int) Summary {
	now := r.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Summary{Series: make([]Point, 0, 60)}
	// Series: the last 60 full or current minutes.
	curMin := now - now%60
	minutes := map[int64]*Point{}
	for i := 0; i < 60; i++ {
		t := curMin - int64(59-i)*60
		p := Point{T: time.Unix(t, 0).UTC()}
		out.Series = append(out.Series, p)
	}
	for i := range out.Series {
		minutes[out.Series[i].T.Unix()] = &out.Series[i]
	}
	// Queries per second over the last ~minute: the current bucket and the
	// five before it, divided by the time they really cover.
	curBucket := now - now%10
	qpsFrom := curBucket - 50
	var lastMin, hourQ, hourC uint64
	for _, s := range r.series {
		if s.start == 0 || now-s.start >= 3600 {
			continue
		}
		if p := minutes[s.start-s.start%60]; p != nil {
			p.Queries += s.queries
			p.Cached += s.cached
			p.Blocked += s.blocked
		}
		if s.start >= qpsFrom {
			lastMin += s.queries
		}
		hourQ += s.queries
		hourC += s.cached
	}
	out.QPS = float64(int(float64(lastMin)/float64(max(now-qpsFrom, 1))*10+0.5)) / 10
	if hourQ > 0 {
		out.CacheHitRate = float64(int(float64(hourC)/float64(hourQ)*1000+0.5)) / 10
	}
	doms, clis, blk := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	for _, h := range r.hours {
		if h == nil || now-h.start >= 24*3600 {
			continue
		}
		out.Queries24h += h.queries
		out.Blocked24h += h.blocked
		out.Failed24h += h.failed
		merge(doms, h.domains)
		merge(clis, h.clients)
		merge(blk, h.blockedNames)
	}
	out.TopDomains, out.TopClients, out.TopBlocked = top(doms, n), top(clis, n), top(blk, n)
	return out
}

func merge(dst, src map[string]uint64) {
	for k, v := range src {
		dst[k] += v
	}
}

func top(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
