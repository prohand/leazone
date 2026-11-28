package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prohand/leazone/internal/audit"
	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/config"
	"github.com/prohand/leazone/internal/dnsconf"
	"github.com/prohand/leazone/internal/querylog"
	"github.com/prohand/leazone/internal/stats"
)

func (s *Server) registerObserveRoutes() {
	s.handle("GET /dashboard", need(auth.PermRead), s.getDashboard)
	s.handle("GET /events", need(auth.PermRead), s.events)
	s.handle("GET /logs/dns", need(auth.PermRead), s.dnsLog)
	s.handle("GET /logs/dhcp", need(auth.PermRead), s.dhcpLog)
	s.handle("GET /logs/settings", need(auth.PermRead), s.getLogSettings)
	s.handle("PUT /logs/settings", need(auth.PermConfigWrite), s.putLogSettings)
	s.handle("GET /logs/status", need(auth.PermRead), s.logStatus)
	s.handle("POST /logs/purge", needStepUp(auth.PermAdmin), s.purgeLogs)
}

// ---- dashboard ----

type dashScope struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Network string  `json:"network"`
	VLANID  *int    `json:"vlanId"`
	Size    int     `json:"size"`
	Used    int     `json:"used"`
	Percent float64 `json:"percent"`
	// AlertThreshold is the scope's alert level (percent); Alert is
	// percent >= AlertThreshold, as in the scope usage.
	AlertThreshold int  `json:"alertThreshold"`
	Alert          bool `json:"alert"`
}

type dashboard struct {
	GeneratedAt   time.Time     `json:"generatedAt"`
	Node          string        `json:"node"`
	UptimeSeconds int64         `json:"uptimeSeconds"`
	DNS           stats.Summary `json:"dns"`
	DHCP          struct {
		ActiveLeases int         `json:"activeLeases"`
		Scopes       []dashScope `json:"scopes"`
	} `json:"dhcp"`
	HA *struct {
		Role             string `json:"role"`
		PeerOnline       bool   `json:"peerOnline"`
		WitnessReachable bool   `json:"witnessReachable"`
		Gaps             int    `json:"gaps"`
	} `json:"ha"`
	Blocking *struct {
		Percent float64 `json:"percent"`
		Blocked uint64  `json:"blocked"`
		Queries uint64  `json:"queries"`
		Paused  bool    `json:"paused"`
	} `json:"blocking"`
}

func (s *Server) buildDashboard(ctx context.Context) (*dashboard, error) {
	d := &dashboard{GeneratedAt: time.Now().UTC(), Node: s.cfg.NodeName}
	if s.stats != nil {
		d.UptimeSeconds = int64(time.Since(s.stats.Started()).Seconds())
		d.DNS = s.stats.Summary(10)
	}
	d.DHCP.Scopes = []dashScope{}
	if s.dhcp != nil {
		scopes, err := s.dhcp.Conf.Scopes(ctx)
		if err != nil {
			return nil, err
		}
		usage := s.dhcp.Engine.Usage()
		for _, sc := range scopes {
			u := usageOf(sc, usage[sc.ID])
			d.DHCP.ActiveLeases += u.ActiveLeases
			d.DHCP.Scopes = append(d.DHCP.Scopes, dashScope{ID: sc.ID, Name: sc.Name, Network: sc.Network, VLANID: sc.VLANID,
				Size: u.Size, Used: u.Used, Percent: u.Percent, AlertThreshold: u.AlertThreshold, Alert: u.Alert})
		}
	}
	if s.cluster != nil {
		v := s.cluster.Status(ctx)
		d.HA = &struct {
			Role             string `json:"role"`
			PeerOnline       bool   `json:"peerOnline"`
			WitnessReachable bool   `json:"witnessReachable"`
			Gaps             int    `json:"gaps"`
		}{Role: string(v.Role), WitnessReachable: v.Witness.Reachable, Gaps: len(v.Gaps)}
		for _, n := range v.Nodes {
			if !n.Self && n.Online {
				d.HA.PeerOnline = true
			}
		}
	}
	if s.blocking != nil && s.blocking.Engine.Enabled() {
		st := s.blocking.Engine.Status(0)
		d.Blocking = &struct {
			Percent float64 `json:"percent"`
			Blocked uint64  `json:"blocked"`
			Queries uint64  `json:"queries"`
			Paused  bool    `json:"paused"`
		}{st.Percent, st.Blocked, st.Queries, st.Paused}
	}
	return d, nil
}

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildDashboard(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// events streams the dashboard every 2 s and lease changes (SSE).
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: do not buffer
	w.WriteHeader(http.StatusOK)
	send := func(event string, data any) bool {
		b := []byte("{}")
		if data != nil {
			var err error
			if b, err = json.Marshal(data); err != nil {
				return false
			}
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	ctx := r.Context()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var lastLeases uint64
	if s.dhcp != nil {
		lastLeases = s.dhcp.Engine.Version()
	}
	lastPing := time.Now()
	// Sessions end: re-check the caller every minute.
	recheck := time.Now()
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
		if time.Since(recheck) > time.Minute {
			recheck = time.Now()
			if p, err := s.authenticate(r); err != nil || p == nil {
				return
			}
		}
		d, err := s.buildDashboard(ctx)
		if err == nil && !send("dashboard", d) {
			return
		}
		if s.dhcp != nil {
			if v := s.dhcp.Engine.Version(); v != lastLeases {
				lastLeases = v
				if !send("leases", nil) {
					return
				}
			}
		}
		if time.Since(lastPing) > 15*time.Second {
			lastPing = time.Now()
			if !send("ping", nil) {
				return
			}
		}
	}
}

// ---- logs ----

func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

func (s *Server) dnsLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := querylog.DNSFilter{Q: q.Get("q"), Type: q.Get("type"), Rcode: q.Get("rcode"), Source: q.Get("source")}
	errs := dnsconf.Validation{}
	if c := strings.TrimSpace(q.Get("client")); c != "" {
		p, err := config.ParsePrefixOrAddr(c)
		if err != nil {
			errs["client"] = "adresse ou réseau invalide"
		}
		f.Client = p
	}
	var err error
	if f.From, err = parseTime(q.Get("from")); err != nil {
		errs["from"] = "date invalide"
	}
	if f.To, err = parseTime(q.Get("to")); err != nil {
		errs["to"] = "date invalide"
	}
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if len(errs) > 0 {
		s.fail(w, r, errs)
		return
	}
	items, next, err := s.qlog.DNS(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

func (s *Server) dhcpLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := querylog.DHCPFilter{Q: q.Get("q"), Event: q.Get("event"), Scope: q.Get("scope")}
	errs := dnsconf.Validation{}
	var err error
	if f.From, err = parseTime(q.Get("from")); err != nil {
		errs["from"] = "date invalide"
	}
	if f.To, err = parseTime(q.Get("to")); err != nil {
		errs["to"] = "date invalide"
	}
	if len(errs) > 0 {
		s.fail(w, r, errs)
		return
	}
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	items, next, err := s.qlog.DHCP(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

func (s *Server) getLogSettings(w http.ResponseWriter, r *http.Request) {
	st, err := querylog.LoadSettings(r.Context(), s.db)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putLogSettings(w http.ResponseWriter, r *http.Request) {
	in := querylog.DefaultSettings()
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.db.PutSetting(r.Context(), querylog.SettingsKey, in); err != nil {
		s.fail(w, r, err)
		return
	}
	s.qlog.SetSettings(in)
	s.record(r, "logs.settings.update", "logs", audit.Success, map[string]any{"after": in})
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) logStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.qlog.Status(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) purgeLogs(w http.ResponseWriter, r *http.Request) {
	if err := s.qlog.Purge(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.record(r, "logs.purge", s.cfg.NodeName, audit.Success, nil)
	s.logStatus(w, r)
}
