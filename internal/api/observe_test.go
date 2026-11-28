package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/querylog"
	"github.com/prohand/leazone/internal/stats"
)

func TestDashboardAndLogs(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)
	if _, err := h.auth.CreateUser(t.Context(), "lecteur", auth.RoleReadonly, adminPass); err != nil {
		t.Fatal(err)
	}
	ro := h.client()
	ro.login("lecteur", adminPass)

	now := time.Now()
	for i, q := range []struct{ client, name, source string }{
		{"192.168.20.5", "www.example.com", "forwarder"},
		{"192.168.20.5", "www.example.com", "cache"},
		{"192.168.20.6", "ads.example.net", "blocked"},
		{"10.0.0.9", "nas.maison.lan", "local"},
	} {
		h.stats.Record(stats.Query{Time: now, Client: q.client, Name: q.name + ".", Source: q.source})
		h.qlog.AddDNS(querylog.DNSEntry{Time: now.Add(time.Duration(i) * time.Millisecond), Client: q.client, Name: q.name,
			Type: "A", Rcode: "NOERROR", Source: q.source, LatencyMs: 1.5})
	}
	h.qlog.AddDHCP(querylog.DHCPEntry{Time: now, Event: "ack", MAC: "02:00:00:00:00:01", IP: "192.168.20.100", Hostname: "pc-salon"})
	h.qlog.AddDHCP(querylog.DHCPEntry{Time: now, Event: "nak", MAC: "02:00:00:00:00:02", IP: "10.9.9.9", Detail: "adresse demandée refusée"})
	h.qlog.Flush()

	var d struct {
		DNS struct {
			Queries24h   int
			CacheHitRate float64
			Series       []struct{ Queries int }
			TopDomains   []struct {
				Name  string
				Count int
			}
			TopClients []struct{ Name string }
			TopBlocked []struct{ Name string }
		}
		DHCP struct{ Scopes []any }
		HA   any
	}
	if s := ro.do("GET", "/api/v1/dashboard", nil, &d); s != 200 {
		t.Fatalf("dashboard: %d", s)
	}
	if d.DNS.Queries24h != 4 || d.DNS.CacheHitRate != 25 || len(d.DNS.Series) != 60 || d.DNS.TopDomains[0].Name != "www.example.com" ||
		d.DNS.TopDomains[0].Count != 2 || d.DNS.TopClients[0].Name != "192.168.20.5" || d.DNS.TopBlocked[0].Name != "ads.example.net" || d.HA != nil {
		t.Fatalf("dashboard: %+v", d)
	}

	type page struct {
		Items []struct {
			ID           int64
			Name, Client string
		}
		NextCursor *int64
	}
	var p page
	ro.do("GET", "/api/v1/logs/dns?q=example&limit=2", nil, &p)
	if len(p.Items) != 2 || p.NextCursor == nil || p.Items[0].Name != "ads.example.net" {
		t.Fatalf("page 1: %+v", p)
	}
	var p2 page
	ro.do("GET", "/api/v1/logs/dns?q=example&limit=2&before="+itoa64(*p.NextCursor), nil, &p2)
	if len(p2.Items) != 1 || p2.NextCursor != nil {
		t.Fatalf("page 2: %+v", p2)
	}
	ro.do("GET", "/api/v1/logs/dns?client=192.168.20.0/24", nil, &p)
	if len(p.Items) != 3 {
		t.Fatalf("client network: %+v", p)
	}
	ro.do("GET", "/api/v1/logs/dns?source=local", nil, &p)
	if len(p.Items) != 1 || p.Items[0].Client != "10.0.0.9" {
		t.Fatalf("source: %+v", p)
	}
	ro.expect("GET", "/api/v1/logs/dns?client=nope", nil, 422, TValidation)
	var dh struct {
		Items []struct{ Event, Detail string }
	}
	ro.do("GET", "/api/v1/logs/dhcp?event=nak", nil, &dh)
	if len(dh.Items) != 1 || dh.Items[0].Detail == "" {
		t.Fatalf("dhcp log: %+v", dh)
	}
	ro.do("GET", "/api/v1/logs/dhcp?q=salon", nil, &dh)
	if len(dh.Items) != 1 || dh.Items[0].Event != "ack" {
		t.Fatalf("dhcp search: %+v", dh)
	}

	// Settings: replicated config, validated.
	ro.expect("PUT", "/api/v1/logs/settings", map[string]any{"dnsQueries": false, "retentionDays": 3, "maxSizeMb": 100}, 403, TForbidden)
	c.expect("PUT", "/api/v1/logs/settings", map[string]any{"retentionDays": 0, "maxSizeMb": 100}, 422, TValidation)
	if s := c.do("PUT", "/api/v1/logs/settings", map[string]any{"dnsQueries": false, "dhcpEvents": true, "retentionDays": 3, "maxSizeMb": 100}, nil); s != 200 {
		t.Fatalf("settings: %d", s)
	}
	h.qlog.AddDNS(querylog.DNSEntry{Time: now, Client: "1.1.1.1", Name: "ignored.example", Source: "cache"})
	h.qlog.Flush()
	var st struct{ DNSEntries, DHCPEntries int }
	ro.do("GET", "/api/v1/logs/status", nil, &st)
	if st.DNSEntries != 4 || st.DHCPEntries != 2 {
		t.Fatalf("status: %+v", st)
	}
	ro.expect("POST", "/api/v1/logs/purge", nil, 403, TForbidden)
	c.do("POST", "/api/v1/logs/purge", nil, &st)
	if st.DNSEntries != 0 {
		t.Fatalf("purge: %+v", st)
	}
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func TestEventsStream(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+testHost+"/api/v1/events", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("events: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var event, data string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if event != "dashboard" || !strings.Contains(data, `"dns"`) {
		t.Fatalf("first event: %q %q", event, data)
	}
	// Not logged in: no stream.
	anon := h.client()
	anon.expect("GET", "/api/v1/events", nil, 401, TUnauthenticated)
}

func TestMetrics(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)
	var tk struct{ Token string }
	if s := c.do("POST", "/api/v1/me/tokens", map[string]string{"name": "prometheus", "scope": "read"}, &tk); s != 201 {
		t.Fatalf("token: %d", s)
	}
	get := func(token string) (int, string) {
		req, _ := http.NewRequest("GET", "https://"+testHost+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := h.client().hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if s, _ := get(""); s != 401 {
		t.Fatalf("without token: %d", s)
	}
	if s, _ := get("lz_bad_token"); s != 401 {
		t.Fatalf("bad token: %d", s)
	}
	s, body := get(tk.Token)
	for _, want := range []string{"leazone_build_info", "leazone_dns_queries_total", "leazone_dns_cache_entries", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics %d: missing %s\n%.600s", s, want, body)
		}
	}
}

func TestDashboardScopeAlertThreshold(t *testing.T) {
	h := newHarness(t, nil)
	addVLANIface(h)
	c := adminClient(t, h)
	in := map[string]any{"name": "20 - Invités", "vlanId": 20, "network": "10.20.0.0/24", "rangeStart": "10.20.0.100",
		"rangeEnd": "10.20.0.199", "gateway": "10.20.0.1", "dnsServers": []string{"10.20.0.2"}, "interface": "eth0.20",
		"ddnsDomain": "invites.lan", "alertThreshold": 65}
	var out map[string]any
	if s := c.do("POST", "/api/v1/dhcp/scopes", in, &out); s != 201 {
		t.Fatalf("create scope: %d %v", s, out)
	}
	var d struct {
		DHCP struct {
			Scopes []struct {
				Name           string
				AlertThreshold int
				Alert          *bool
			}
		}
	}
	if s := c.do("GET", "/api/v1/dashboard", nil, &d); s != 200 {
		t.Fatalf("dashboard: %d", s)
	}
	if len(d.DHCP.Scopes) != 1 || d.DHCP.Scopes[0].AlertThreshold != 65 || d.DHCP.Scopes[0].Alert == nil || *d.DHCP.Scopes[0].Alert {
		t.Fatalf("dashboard scopes: %+v", d.DHCP.Scopes)
	}
}
