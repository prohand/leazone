package api

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prohand/leazone/internal/auth"
)

// adminClient returns a fully logged-in admin (TOTP enrolled). MFA is only
// required for admins, so the other test users log in with a password.
func adminClient(t *testing.T, h *harness) *testClient {
	sec := h.auth.Security()
	sec.MFARequiredFor = "admins"
	h.auth.SetSecurity(context.Background(), sec)
	c := h.client()
	c.login("admin", adminPass)
	var setup struct{ Secret string }
	c.do("POST", "/api/v1/me/totp/setup", nil, &setup)
	if s := c.do("POST", "/api/v1/me/totp/confirm", map[string]string{"code": totpCode(t, setup.Secret, time.Now())}, nil); s != 200 {
		t.Fatalf("admin TOTP enrollment: %d", s)
	}
	return c
}

func TestDNSZonesRecordsLookup(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)

	var z struct {
		ID, Name, Kind string
		Serial         uint32
	}
	if s := c.do("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, &z); s != 201 || z.Name != "maison.lan" {
		t.Fatalf("create zone: %d %+v", s, z)
	}
	var rz struct{ Name, Kind string }
	c.do("POST", "/api/v1/dns/zones", map[string]any{"name": "192.168.20.0/24"}, &rz)
	if rz.Name != "20.168.192.in-addr.arpa" || rz.Kind != "reverse" {
		t.Fatalf("reverse zone: %+v", rz)
	}
	c.expect("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, 409, TConflict)

	var rec struct{ ID, FQDN, Value string }
	if s := c.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "192.168.20.5"}}, &rec); s != 201 {
		t.Fatalf("create record: %d", s)
	}
	var verr struct {
		Errors map[string]string `json:"errors"`
	}
	if s := c.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "bad", "type": "A", "data": map[string]string{"ip": "nope"}}, &verr); s != 422 || verr.Errors["data.ip"] == "" {
		t.Fatalf("validation: %d %+v", s, verr)
	}

	// The record is served right away (engine reloaded).
	var lr struct {
		Rcode, Source string
		Answers       []string
	}
	c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": "nas.maison.lan", "type": "A"}, &lr)
	if lr.Rcode != "NOERROR" || lr.Source != "local" || len(lr.Answers) != 1 || !strings.Contains(lr.Answers[0], "192.168.20.5") {
		t.Fatalf("lookup: %+v", lr)
	}

	if s := c.do("GET", "/api/v1/dns/zones/"+z.ID+"/export", nil, nil); s != 200 {
		t.Fatalf("export: %d", s)
	}

	// Operators manage records but not zones; read-only users only read.
	h.auth.CreateUser(context.Background(), "op", auth.RoleOperator, "operator password")
	h.auth.CreateUser(context.Background(), "ro", auth.RoleReadonly, "readonly password")
	op := h.client()
	op.login("op", "operator password")
	if s := op.do("PUT", "/api/v1/dns/zones/"+z.ID+"/records/"+rec.ID, map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "192.168.20.6"}}, nil); s != 200 {
		t.Fatalf("operator edits record: %d", s)
	}
	op.expect("POST", "/api/v1/dns/zones", map[string]any{"name": "other.lan"}, 403, TForbidden)
	ro := h.client()
	ro.login("ro", "readonly password")
	ro.expect("DELETE", "/api/v1/dns/zones/"+z.ID+"/records/"+rec.ID, nil, 403, TForbidden)
	if s := ro.do("GET", "/api/v1/dns/zones/"+z.ID+"/records", nil, nil); s != 200 {
		t.Fatalf("readonly reads records: %d", s)
	}

	// Deleting a zone needs a recent step-up.
	h.clock = 6 * time.Minute
	c.expect("DELETE", "/api/v1/dns/zones/"+z.ID, nil, 403, TStepUp)
}

func TestDNSForwardersAndListeners(t *testing.T) {
	h := newHarness(t, nil)
	c := adminClient(t, h)

	// Upstream answering everything with 10.1.2.3.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	upPort := pc.LocalAddr().(*net.UDPAddr).Port
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.1.2.3")}}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	var test struct {
		OK    bool
		Error string
	}
	c.do("POST", "/api/v1/dns/forwarders/test", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": upPort}, &test)
	if !test.OK {
		t.Fatalf("forwarder test: %+v", test)
	}
	c.do("POST", "/api/v1/dns/forwarders/test", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": freePort(t)}, &test)
	if test.OK || test.Error == "" {
		t.Fatalf("dead forwarder test: %+v", test)
	}
	var f struct{ ID string }
	if s := c.do("POST", "/api/v1/dns/forwarders", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": upPort}, &f); s != 201 {
		t.Fatalf("create forwarder: %d", s)
	}

	// Enable DNS on "lo": the engine listens on 127.0.0.1:<port>.
	var it struct {
		DNSEnabled   bool
		DNSListeners []struct{ State, Error string }
	}
	if s := c.do("PATCH", "/api/v1/interfaces/lo", map[string]any{"dnsEnabled": true}, &it); s != 200 || !it.DNSEnabled || len(it.DNSListeners) != 2 || it.DNSListeners[0].State != "listening" {
		t.Fatalf("patch interface: %d %+v", s, it)
	}
	cl := &dns.Client{Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	r, _, err := cl.Exchange(q, "127.0.0.1:"+strconv.Itoa(h.dnsPort))
	if err != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.1.2.3" {
		t.Fatalf("query through listener: %v %v", r, err)
	}
	var st struct {
		Cache struct{ Entries int }
	}
	c.do("GET", "/api/v1/dns/status", nil, &st)
	if st.Cache.Entries != 1 {
		t.Fatalf("cache entries = %d", st.Cache.Entries)
	}
	var fl struct{ Removed int }
	c.do("POST", "/api/v1/dns/cache/flush", map[string]any{}, &fl)
	if fl.Removed != 1 {
		t.Fatalf("flush removed %d", fl.Removed)
	}
	// Disable DNS: the listener goes away.
	c.do("PATCH", "/api/v1/interfaces/lo", map[string]any{"dnsEnabled": false}, &it)
	if len(it.DNSListeners) != 0 {
		t.Fatalf("listeners after disable: %+v", it.DNSListeners)
	}
}
