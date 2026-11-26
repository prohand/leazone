//go:build integration

package integration

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pquerna/otp/totp"
)

// metricsBody scrapes /metrics with a bearer token.
func metricsBody(t *testing.T, a *api, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", a.base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPhase6Operations(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create test interfaces")
	}
	veth(t, "lz6a", "10.66.0.1/24")

	// Upstream resolver for forwarded queries.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upPort := pc.LocalAddr().(*net.UDPAddr).Port
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A: net.ParseIP("10.200.0.1")}}
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()

	// The backup password is the admin password file (already mounted).
	env := "LEAZONE_BACKUP_PASSWORD_FILE=/run/admin_password"
	c := startContainer(t, "leazone-it6a", "127.0.0.1:18450", env)
	a := newAPI(t, c)
	a.loginAdmin()
	var z struct{ ID string }
	a.do("POST", "/api/v1/dns/zones", map[string]any{"name": "maison.lan"}, &z)
	a.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", map[string]any{"name": "nas", "type": "A", "data": map[string]string{"ip": "10.66.0.10"}}, nil)
	a.do("POST", "/api/v1/dns/forwarders", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": upPort}, nil)
	a.do("PATCH", "/api/v1/interfaces/lz6a", map[string]any{"dnsEnabled": true}, nil)
	waitAnswer(t, "10.66.0.1", "nas.maison.lan", "10.66.0.10")
	for i := 0; i < 5; i++ {
		query("10.66.0.1", "www.example.org", dns.TypeA, "udp")
		query("10.66.0.1", "nas.maison.lan", dns.TypeA, "udp")
	}

	// ---- Logs ----
	var logs struct {
		Items []struct{ Name, Source, Client, Rcode string }
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a.do("GET", "/api/v1/logs/dns?q=example.org", nil, &logs)
		if len(logs.Items) >= 5 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if len(logs.Items) < 5 || logs.Items[0].Source == "" || logs.Items[0].Client != "10.66.0.1" {
		t.Fatalf("DNS log: %+v", logs.Items)
	}
	a.do("GET", "/api/v1/logs/dns?source=cache", nil, &logs)
	if len(logs.Items) < 4 {
		t.Fatalf("cached answers in the log: %+v", logs.Items)
	}
	t.Logf("✔ DNS query log in /data/logs.db: %d answers from the cache, filters work", len(logs.Items))

	// ---- Dashboard ----
	var d struct {
		DNS struct {
			Queries24h   int
			CacheHitRate float64
			TopDomains   []struct{ Name string }
		}
	}
	a.do("GET", "/api/v1/dashboard", nil, &d)
	if d.DNS.Queries24h < 10 || d.DNS.CacheHitRate <= 0 || len(d.DNS.TopDomains) < 2 {
		t.Fatalf("dashboard: %+v", d)
	}
	t.Logf("✔ dashboard: %d queries, %.0f %% from the cache, top domain %s", d.DNS.Queries24h, d.DNS.CacheHitRate, d.DNS.TopDomains[0].Name)

	// ---- Metrics ----
	var tk struct{ Token string }
	if s := a.do("POST", "/api/v1/me/tokens", map[string]string{"name": "prometheus", "scope": "read"}, &tk); s != 201 {
		t.Fatalf("token: %d", s)
	}
	if s, _ := metricsBody(t, a, "lz_nope_nope"); s != 401 {
		t.Fatalf("metrics without a valid token: %d", s)
	}
	s, body := metricsBody(t, a, tk.Token)
	if s != 200 || !strings.Contains(body, "leazone_dns_queries_total ") || !strings.Contains(body, `leazone_dns_forwarder_up{`) {
		t.Fatalf("metrics: %d\n%.800s", s, body)
	}
	t.Log("✔ Prometheus /metrics: refused without token, served with an API token")

	// ---- Backup ----
	out, err := exec.Command("docker", "exec", "leazone-it6a", "/leazone", "backup").CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("format: leazone-backup/1")) {
		t.Fatalf("leazone backup: %v\n%.300s", err, out)
	}
	backup := out
	var auto struct {
		Enabled bool
		Items   []struct{ Name string }
	}
	a.do("GET", "/api/v1/backups", nil, &auto)
	if !auto.Enabled || len(auto.Items) != 1 {
		t.Fatalf("automatic backup: %+v", auto)
	}
	t.Logf("✔ « docker exec … leazone backup » (%d bytes) and daily automatic backup %s", len(backup), auto.Items[0].Name)

	// ---- Restore on a new node ----
	exec.Command("docker", "stop", "-t", "2", "leazone-it6a").Run()
	c2 := startContainer(t, "leazone-it6b", "127.0.0.1:18451", env)
	cmd := exec.Command("docker", "exec", "-i", "leazone-it6b", "/leazone", "restore", "-")
	cmd.Stdin = bytes.NewReader(backup)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("leazone restore: %v\n%s", err, out)
	}
	// The DNS of the new node answers with the restored zone and interface settings.
	waitAnswer(t, "10.66.0.1", "nas.maison.lan", "10.66.0.10")
	// The admin of the backup logs in with its TOTP; its API token works.
	b := newAPI(t, c2)
	var st struct {
		State     string `json:"state"`
		CSRFToken string `json:"csrfToken"`
	}
	b.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "integration admin password"}, &st)
	if st.State != "mfa_required" {
		t.Fatalf("login after restore: %+v", st)
	}
	b.csrf = st.CSRFToken
	code, _ := totp.GenerateCode(a.totpSecret, time.Now())
	if s := b.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"code": code}, nil); s != 200 {
		t.Fatalf("TOTP of the backup on the new node: %d", s)
	}
	if s, _ := metricsBody(t, b, tk.Token); s != 200 {
		t.Fatalf("API token of the backup on the new node: %d", s)
	}
	t.Log("✔ backup restored on a fresh node (other data key): zone served, admin TOTP and API token work")
}
