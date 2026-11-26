//go:build integration

package integration

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// delvImage has BIND's delv (an independent DNSSEC validator). Build it with
// test/integration/delv.Dockerfile; the test is skipped without it.
const delvImage = "lz-delv"

func queryDO(server, name string, qtype uint16) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.SetEdns0(1232, true)
	r, _, err := c.Exchange(q, net.JoinHostPort(server, "53"))
	return r, err
}

func TestPhase5Modules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create test interfaces")
	}
	veth(t, "lzb0", "10.57.0.1/24")

	// Upstream resolver and block list server (host loopback).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upPort := pc.LocalAddr().(*net.UDPAddr).Port
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case q.Name == "cloaked.example.org.":
			m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "metrics.tracker.example.net."}}
		case q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A: net.ParseIP("10.200.0.1")}}
		}
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("! AdBlock list\n||ads.example.com^\n||tracker.example.net^\n@@||ok.tracker.example.net^\n"))
	}))
	defer lists.Close()

	c := startContainer(t, "leazone-it5", "127.0.0.1:18449")
	a := newAPI(t, c)
	a.loginAdmin()
	a.do("PATCH", "/api/v1/interfaces/lzb0", map[string]any{"dnsEnabled": true}, nil)
	a.do("POST", "/api/v1/dns/forwarders", map[string]any{"protocol": "udp", "address": "127.0.0.1", "port": upPort}, nil)
	waitAnswer(t, "10.57.0.1", "ads.example.com", "10.200.0.1")
	t.Log("✔ modules off by default: nothing blocked")

	// ---- Blocking ----
	if s := a.do("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": true}, nil); s != 200 {
		t.Fatalf("modules: %d", s)
	}
	var l struct {
		Entries int
		Error   string
	}
	if s := a.do("POST", "/api/v1/blocking/lists", map[string]any{"name": "Test", "url": lists.URL + "/list.txt"}, &l); s != 201 || l.Entries != 3 {
		t.Fatalf("list: %d %+v", s, l)
	}
	r, err := queryDO("10.57.0.1", "www.ads.example.com", dns.TypeA)
	if err != nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked: %v %v", r, err)
	}
	if o := r.IsEdns0(); o == nil || !strings.Contains(o.String(), "Blocked") {
		t.Fatalf("EDE Blocked missing: %v", r)
	}
	t.Log("✔ list downloaded by URL (AdBlock format): sub-domain blocked with NXDOMAIN + EDE « Blocked »")
	if r, _ := queryDO("10.57.0.1", "ok.tracker.example.net", dns.TypeA); r == nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("exception: %v", r)
	}
	if r, _ := queryDO("10.57.0.1", "cloaked.example.org", dns.TypeA); r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("CNAME cloaking: %v", r)
	}
	t.Log("✔ AdBlock exception (@@) honoured, tracker hidden behind a CNAME blocked")

	a.do("POST", "/api/v1/blocking/rules", map[string]string{"domain": "ads.example.com", "kind": "allow"}, nil)
	if r, _ := queryDO("10.57.0.1", "ads.example.com", dns.TypeA); r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist: %v", r)
	}
	t.Log("✔ manual whitelist wins over the list")

	a.do("PUT", "/api/v1/blocking/settings", map[string]any{"responseMode": "null-ip", "refreshHours": 24, "defaultEnabled": true}, nil)
	r, _ = queryDO("10.57.0.1", "tracker.example.net", dns.TypeA)
	if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatalf("null ip: %v", r)
	}
	r, _ = queryDO("10.57.0.1", "tracker.example.net", dns.TypeAAAA)
	if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "::" {
		t.Fatalf("null ip v6: %v", r)
	}
	t.Log("✔ « adresse nulle » mode answers 0.0.0.0 and ::")

	a.do("POST", "/api/v1/blocking/policies", map[string]any{"targetKind": "interface", "target": "lzb0", "enabled": false}, nil)
	if r, _ := queryDO("10.57.0.1", "tracker.example.net", dns.TypeA); r == nil || r.Answer[0].(*dns.A).A.String() != "10.200.0.1" {
		t.Fatalf("interface policy: %v", r)
	}
	t.Log("✔ per-interface policy: blocking off on lzb0")

	var st struct {
		Queries, Blocked int
		Percent          float64
		Top              []struct{ Domain string }
	}
	a.do("GET", "/api/v1/blocking/status", nil, &st)
	if st.Blocked < 3 || st.Queries < st.Blocked || len(st.Top) == 0 {
		t.Fatalf("stats: %+v", st)
	}
	t.Logf("✔ statistics: %d/%d blocked (%.1f %%), top %s", st.Blocked, st.Queries, st.Percent, st.Top[0].Domain)

	// ---- DNSSEC ----
	if exec.Command("docker", "image", "inspect", delvImage).Run() != nil {
		t.Skip("image " + delvImage + " missing: DNSSEC checked by unit tests only")
	}
	a.do("PUT", "/api/v1/settings/modules", map[string]bool{"blocking": true, "dnssec": true}, nil)
	type zinfo struct {
		DS []string
	}
	anchors := []string{}
	for _, zc := range []struct {
		name string
		alg  int
		mode string
	}{{"maison.lan", 13, "nsec3"}, {"labo.lan", 15, "nsec"}} {
		var z struct{ ID string }
		a.do("POST", "/api/v1/dns/zones", map[string]any{"name": zc.name}, &z)
		for _, rec := range []map[string]any{
			{"name": "nas", "type": "A", "data": map[string]string{"ip": "10.57.0.10"}},
			{"name": "*.dev", "type": "A", "data": map[string]string{"ip": "10.57.0.20"}},
			{"name": "_sip._tcp", "type": "SRV", "data": map[string]any{"priority": 1, "weight": 1, "port": 5060, "target": "nas." + zc.name + "."}},
			{"name": "sub", "type": "NS", "data": map[string]string{"host": "ns.sub." + zc.name + "."}},
			{"name": "ns.sub", "type": "A", "data": map[string]string{"ip": "10.57.0.53"}},
		} {
			if s := a.do("POST", "/api/v1/dns/zones/"+z.ID+"/records", rec, nil); s != 201 {
				t.Fatalf("record %v: %d", rec, s)
			}
		}
		var info zinfo
		if s := a.do("POST", "/api/v1/dnssec/zones/"+z.ID+"/enable", map[string]any{"algorithm": zc.alg, "nsecMode": zc.mode}, &info); s != 200 || len(info.DS) != 1 {
			t.Fatalf("enable %s: %d %+v", zc.name, s, info)
		}
		f := strings.Fields(info.DS[0]) // owner ttl IN DS tag alg digesttype digest
		anchors = append(anchors, f[0]+" static-ds "+f[4]+" "+f[5]+" "+f[6]+` "`+f[7]+`";`)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	conf := filepath.Join(dir, "anchors.conf")
	os.WriteFile(conf, []byte("trust-anchors {\n"+strings.Join(anchors, "\n")+"\n};\n"), 0o644)

	delv := func(root, name, qtype string) string {
		out, _ := exec.Command("docker", "run", "--rm", "--network", "host", "-v", conf+":/anchors.conf:ro", delvImage,
			"delv", "@10.57.0.1", "-a", "/anchors.conf", "+root="+root, name, qtype).CombinedOutput()
		return string(out)
	}
	for _, zone := range []string{"maison.lan", "labo.lan"} {
		for _, c := range []struct {
			name, qtype, want string
		}{
			{"nas." + zone, "A", "; fully validated"},
			{"app.dev." + zone, "A", "; fully validated"}, // wildcard
			{"_sip._tcp." + zone, "SRV", "; fully validated"},
			{zone, "DNSKEY", "; fully validated"},
			{"nope." + zone, "A", "; negative response, fully validated"},      // NXDOMAIN
			{"nas." + zone, "MX", "; negative response, fully validated"},      // NODATA
			{"_tcp." + zone, "A", "; negative response, fully validated"},      // empty non-terminal
			{"app.dev." + zone, "TXT", "; negative response, fully validated"}, // wildcard NODATA
			{"sub." + zone, "DS", "; negative response, fully validated"},      // insecure delegation
		} {
			out := delv(zone, c.name, c.qtype)
			if !strings.Contains(out, c.want) {
				t.Fatalf("delv %s %s: want %q\n%s", c.name, c.qtype, c.want, out)
			}
		}
	}
	t.Log("✔ BIND delv validates both zones (ECDSA P-256 + NSEC3, Ed25519 + NSEC): answers, wildcard, NXDOMAIN, NODATA, empty non-terminal, insecure delegation")

	// Wrong trust anchor: delv must refuse.
	bad := strings.Replace(anchors[0], `"`, `"00`, 1)
	os.WriteFile(conf, []byte("trust-anchors {\n"+bad[:len(bad)-4]+`";`+"\n};\n"), 0o644)
	if out := delv("maison.lan", "nas.maison.lan", "A"); strings.Contains(out, "fully validated") {
		t.Fatalf("validated with a wrong anchor:\n%s", out)
	}
	t.Log("✔ a wrong DS is refused by the validator")
}
