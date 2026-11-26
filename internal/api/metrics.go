package api

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/version"
)

// Prometheus metrics on /metrics, for API tokens (read scope is enough) or
// a logged-in session. Values are read at scrape time.

func (s *Server) registerMetrics() {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		&metricsCollector{s: s})
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
	s.mux.Handle("GET /metrics", s.guard(need(auth.PermRead), h.ServeHTTP))
}

type metricsCollector struct{ s *Server }

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("leazone_"+name, help, labels, nil)
}

var (
	mBuild          = desc("build_info", "Leazone version.", "version", "commit")
	mDNSQueries     = desc("dns_queries_total", "DNS queries received (UDP and TCP).")
	mDNSAnswers     = desc("dns_answers_total", "DNS answers by origin.", "source")
	mDNSCacheHits   = desc("dns_cache_hits_total", "Cache hits.")
	mDNSCacheMisses = desc("dns_cache_misses_total", "Cache misses.")
	mDNSCacheSize   = desc("dns_cache_entries", "Entries in the DNS cache.")
	mDNSBogus       = desc("dns_dnssec_bogus_total", "Forwarded answers refused by DNSSEC validation.")
	mFwdUp          = desc("dns_forwarder_up", "Forwarder health (1 = answers).", "forwarder", "protocol", "address")
	mFwdLatency     = desc("dns_forwarder_latency_seconds", "Latency of the last forwarder check.", "forwarder", "protocol", "address")
	mScopeSize      = desc("dhcp_scope_addresses", "Addresses in the scope range.", "scope", "network")
	mScopeUsed      = desc("dhcp_scope_used_addresses", "Addresses in use (leases and reservations).", "scope", "network")
	mScopeActive    = desc("dhcp_scope_active_leases", "Active leases.", "scope", "network")
	mBlockQueries   = desc("blocking_checked_total", "Queries checked by the ad blocker.")
	mBlockBlocked   = desc("blocking_blocked_total", "Queries blocked.")
	mBlockDomains   = desc("blocking_domains", "Blocked domains loaded.")
	mBlockPaused    = desc("blocking_paused", "1 while blocking is paused.")
	mRole           = desc("cluster_role", "Role of this node (1 for the current role).", "role")
	mPeerUp         = desc("cluster_peer_up", "Other node reachable.", "node")
	mWitness        = desc("cluster_witness_reachable", "Witness reachable.")
	mEpoch          = desc("cluster_epoch", "Current term (increases at each failover).")
	mGaps           = desc("cluster_gaps", "Differences found between the nodes.")
	mLogsDropped    = desc("logs_dropped_total", "Log entries not written (too many at once).")
)

func (c *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{mBuild, mDNSQueries, mDNSAnswers, mDNSCacheHits, mDNSCacheMisses, mDNSCacheSize, mDNSBogus,
		mFwdUp, mFwdLatency, mScopeSize, mScopeUsed, mScopeActive, mBlockQueries, mBlockBlocked, mBlockDomains, mBlockPaused,
		mRole, mPeerUp, mWitness, mEpoch, mGaps, mLogsDropped} {
		ch <- d
	}
}

func (c *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.s
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gauge := func(d *prometheus.Desc, v float64, l ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, l...)
	}
	counter := func(d *prometheus.Desc, v float64, l ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, l...)
	}
	gauge(mBuild, 1, version.Version, version.Commit)

	if s.dns != nil {
		st := s.dns.Engine.Stats()
		counter(mDNSQueries, float64(st.Queries))
		for src, v := range map[string]uint64{"local": st.Local, "forwarder": st.Forwarded, "refused": st.Refused,
			"error": st.Failed, "blocked": st.Blocked} {
			counter(mDNSAnswers, float64(v), src)
		}
		counter(mDNSCacheHits, float64(st.CacheHits))
		counter(mDNSCacheMisses, float64(st.CacheMisses))
		gauge(mDNSCacheSize, float64(st.CacheEntries))
		counter(mDNSBogus, float64(st.Bogus))
		if fwd, err := s.dns.Store.Forwarders(ctx); err == nil {
			health := s.dns.Engine.Health()
			for _, f := range fwd {
				h, ok := health[f.ID]
				if !ok || !f.Enabled {
					continue
				}
				up := 0.0
				if h.Healthy {
					up = 1
				}
				gauge(mFwdUp, up, f.ID, f.Protocol, f.Address)
				gauge(mFwdLatency, h.LastLatencyMs/1000, f.ID, f.Protocol, f.Address)
			}
		}
	}
	if s.dhcp != nil {
		if scopes, err := s.dhcp.Conf.Scopes(ctx); err == nil {
			usage := s.dhcp.Engine.Usage()
			for _, sc := range scopes {
				u := usage[sc.ID]
				gauge(mScopeSize, float64(u.Size), sc.Name, sc.Network)
				gauge(mScopeUsed, float64(u.Used), sc.Name, sc.Network)
				gauge(mScopeActive, float64(u.Active), sc.Name, sc.Network)
			}
		}
	}
	if s.blocking != nil && s.blocking.Engine.Enabled() {
		st := s.blocking.Engine.Status(0)
		counter(mBlockQueries, float64(st.Queries))
		counter(mBlockBlocked, float64(st.Blocked))
		gauge(mBlockDomains, float64(st.Domains))
		p := 0.0
		if st.Paused {
			p = 1
		}
		gauge(mBlockPaused, p)
	}
	if s.cluster != nil {
		v := s.cluster.Status(ctx)
		for _, r := range []string{"primary", "secondary", "isolated", "incompatible", "joining"} {
			val := 0.0
			if string(v.Role) == r {
				val = 1
			}
			gauge(mRole, val, r)
		}
		for _, n := range v.Nodes {
			if n.Self {
				continue
			}
			up := 0.0
			if n.Online {
				up = 1
			}
			gauge(mPeerUp, up, n.Name)
		}
		w := 0.0
		if v.Witness.Reachable {
			w = 1
		}
		gauge(mWitness, w)
		gauge(mEpoch, float64(v.Epoch))
		gauge(mGaps, float64(len(v.Gaps)))
	}
	if s.qlog != nil {
		counter(mLogsDropped, float64(s.qlog.Dropped()))
	}
}
