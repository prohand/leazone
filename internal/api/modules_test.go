package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/auth"
)

func TestModulesAndBlocking(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)
	if _, err := h.auth.CreateUser(t.Context(), "lecteur", auth.RoleReadonly, adminPass); err != nil {
		t.Fatal(err)
	}
	ro := h.client()
	ro.login("lecteur", adminPass)

	var mods struct{ Blocking, DNSSEC, DNSSECValidation bool }
	if s := ro.do("GET", "/api/v1/settings/modules", nil, &mods); s != 200 || mods.Blocking || mods.DNSSEC {
		t.Fatalf("modules: %d %+v", s, mods)
	}
	ro.expect("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": true}, 403, TForbidden)
	if s := c.do("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": true, "dnssec": true}, nil); s != 200 {
		t.Fatalf("enable modules: %d", s)
	}

	// A list served over HTTP.
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# test\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n"))
	}))
	defer lists.Close()
	var l struct {
		ID      string
		Entries int
		Error   string
	}
	if s := c.do("POST", "/api/v1/blocking/lists", map[string]any{"name": "Test", "url": lists.URL + "/hosts"}, &l); s != 201 || l.Entries != 2 {
		t.Fatalf("create list: %d %+v", s, l)
	}
	c.expect("POST", "/api/v1/blocking/lists", map[string]any{"name": "Bad", "url": "ftp://x"}, 422, TValidation)

	var chk struct {
		Blocked      bool
		Reason       string
		PolicyActive bool
	}
	ro.do("POST", "/api/v1/blocking/check", map[string]string{"name": "x.ads.example.com"}, &chk)
	if !chk.Blocked || chk.Reason != "liste « Test »" {
		t.Fatalf("check: %+v", chk)
	}
	var lk struct{ Rcode, Source string }
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "ads.example.com", "type": "A"}, &lk)
	if lk.Rcode != "NXDOMAIN" || lk.Source != "blocked" {
		t.Fatalf("lookup: %+v", lk)
	}

	// Whitelist wins.
	var rule struct{ ID string }
	if s := c.do("POST", "/api/v1/blocking/rules", map[string]string{"domain": "ads.example.com", "kind": "allow"}, &rule); s != 201 {
		t.Fatalf("allow rule: %d", s)
	}
	ro.do("POST", "/api/v1/blocking/check", map[string]string{"name": "ads.example.com"}, &chk)
	if chk.Blocked || chk.Reason != "liste blanche" {
		t.Fatalf("whitelist: %+v", chk)
	}
	c.expect("POST", "/api/v1/blocking/rules", map[string]string{"domain": "ads.example.com", "kind": "allow"}, 409, TConflict)
	c.do("DELETE", "/api/v1/blocking/rules/"+rule.ID, nil, nil)

	// Policy: not for 192.168.30.0/24.
	if s := c.do("POST", "/api/v1/blocking/policies", map[string]any{"targetKind": "network", "target": "192.168.30.0/24", "enabled": false}, nil); s != 201 {
		t.Fatalf("policy: %d", s)
	}
	ro.do("POST", "/api/v1/blocking/check", map[string]string{"name": "ads.example.com", "client": "192.168.30.4"}, &chk)
	if !chk.Blocked || chk.PolicyActive {
		t.Fatalf("policy check: %+v", chk)
	}

	// Pause.
	var st struct {
		Paused  bool
		Blocked int
		Top     []struct{ Domain string }
	}
	ro.expect("POST", "/api/v1/blocking/pause", map[string]int{"minutes": 5}, 403, TForbidden)
	if s := c.do("POST", "/api/v1/blocking/pause", map[string]int{"minutes": 5}, &st); s != 200 || !st.Paused {
		t.Fatalf("pause: %d %+v", s, st)
	}
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "ads.example.com", "type": "A"}, &lk)
	if lk.Source == "blocked" {
		t.Fatal("blocked while paused")
	}
	c.do("POST", "/api/v1/blocking/pause", map[string]int{"minutes": 0}, &st)
	if st.Paused || st.Blocked != 1 || len(st.Top) != 1 || st.Top[0].Domain != "ads.example.com" {
		t.Fatalf("resume: %+v", st)
	}
	if s := c.do("POST", "/api/v1/blocking/refresh", nil, nil); s != 200 {
		t.Fatalf("refresh: %d", s)
	}

	// Module off: nothing is blocked any more.
	c.do("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": false}, nil)
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "ads.example.com", "type": "A"}, &lk)
	if lk.Source == "blocked" {
		t.Fatal("blocked with module off")
	}

	// Changing modules needs a recent step-up.
	h.clock = 6 * time.Minute
	c.expect("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": true}, 403, TStepUp)
}

func TestDNSSECAPI(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)
	c.do("PUT", "/api/v1/settings/modules", map[string]bool{"dnssec": true}, nil)
	var z struct{ ID string }
	c.do("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, &z)
	c.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "192.168.20.5"}}, nil)

	type key struct {
		Role, State string
		KeyTag      int
	}
	var info struct {
		Enabled   bool
		Algorithm int
		NSECMode  string
		Keys      []key
		DS        []string
		DSPending bool
	}
	if s := c.do("POST", "/api/v1/dnssec/zones/"+z.ID+"/enable", map[string]any{"algorithm": 15, "nsecMode": "nsec"}, &info); s != 200 {
		t.Fatalf("enable: %d", s)
	}
	if !info.Enabled || info.Algorithm != 15 || info.NSECMode != "nsec" || len(info.Keys) != 2 || len(info.DS) != 1 || !info.DSPending {
		t.Fatalf("enabled zone: %+v", info)
	}
	c.expect("POST", "/api/v1/dnssec/zones/"+z.ID+"/enable", nil, 409, TConflict)

	var lk struct {
		Rcode   string
		Answers []string
	}
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "maison.lan", "type": "DNSKEY"}, &lk)
	if len(lk.Answers) != 2 {
		t.Fatalf("DNSKEY: %+v", lk)
	}

	// ZSK rollover: a new key is pre-published.
	c.do("POST", "/api/v1/dnssec/zones/"+z.ID+"/rollover", map[string]string{"type": "zsk"}, &info)
	if len(info.Keys) != 3 {
		t.Fatalf("rollover: %+v", info.Keys)
	}
	c.expect("POST", "/api/v1/dnssec/zones/"+z.ID+"/rollover", map[string]string{"type": "zsk"}, 409, TConflict)
	c.do("POST", "/api/v1/dnssec/zones/"+z.ID+"/ds-published", nil, &info)
	if info.DSPending {
		t.Fatalf("ds published: %+v", info)
	}
	c.expect("POST", "/api/v1/dnssec/zones/"+z.ID+"/ds-published", nil, 409, TConflict)

	// Export: admin with step-up.
	req, _ := http.NewRequest("GET", "https://"+testHost+"/api/v1/dnssec/zones/"+z.ID+"/export", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if resp.StatusCode != 200 || !strings.Contains(body, "Private-key-format") || !strings.Contains(body, "DNSKEY") {
		t.Fatalf("export: %d %s", resp.StatusCode, body)
	}
	var list struct{ Items []struct{ Name string } }
	c.do("GET", "/api/v1/dnssec/zones", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: %+v", list)
	}
	h.clock = 6 * time.Minute
	c.expect("GET", "/api/v1/dnssec/zones/"+z.ID+"/export", nil, 403, TStepUp)
	c.expect("POST", "/api/v1/dnssec/zones/"+z.ID+"/disable", nil, 403, TStepUp)
}
