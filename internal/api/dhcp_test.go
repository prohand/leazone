package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/prohand/leazone/internal/auth"
	"github.com/prohand/leazone/internal/dhcpsrv"
	"github.com/prohand/leazone/internal/netif"
)

func addVLANIface(h *harness) {
	h.ifaces.list = append(h.ifaces.list, netif.Interface{Index: 20, Name: "eth0.20", Type: netif.TypeVLAN, VLANID: 20,
		Parent: "eth0", Up: true, Addresses: []netif.Address{{Prefix: netip.MustParsePrefix("10.20.0.2/24")}}})
	for _, fn := range h.ifaces.subs {
		fn(h.ifaces.list)
	}
}

// lease runs DISCOVER/REQUEST against the engine as if received on ifindex 20.
func lease(t *testing.T, h *harness, mac net.HardwareAddr, host string) netip.Addr {
	t.Helper()
	ctx := context.Background()
	d, _ := dhcpv4.NewDiscovery(mac, dhcpv4.WithOption(dhcpv4.OptHostName(host)))
	off := h.dhcp.Engine.Handle(ctx, dhcpsrv.Packet{Msg: d, IfIndex: 20})
	if off == nil {
		t.Fatal("no offer")
	}
	req, _ := dhcpv4.NewRequestFromOffer(off.Msg, dhcpv4.WithOption(dhcpv4.OptHostName(host)))
	ack := h.dhcp.Engine.Handle(ctx, dhcpsrv.Packet{Msg: req, IfIndex: 20})
	if ack == nil || ack.Msg.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("no ack: %v", ack)
	}
	a, _ := netip.AddrFromSlice(ack.Msg.YourIPAddr.To4())
	return a
}

func waitLookup(t *testing.T, c *testClient, name, typ, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lr struct {
		Rcode   string
		Answers []string
	}
	for time.Now().Before(deadline) {
		c.do("POST", "/api/v1/dns/lookup", map[string]string{"name": name, "type": typ}, &lr)
		joined := strings.Join(lr.Answers, " ")
		if (want == "" && lr.Rcode == "NXDOMAIN") || (want != "" && strings.Contains(joined, want)) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("lookup %s %s: want %q, got %+v", name, typ, want, lr)
}

func TestDHCPScopeLeaseDDNSAndVLANView(t *testing.T) {
	h := newHarness(t, nil)
	addVLANIface(h)
	c := adminClient(t, h)

	var sc struct {
		ID           string
		Mode         string
		ReverseZones []string
	}
	in := map[string]any{"name": "20 - Invités", "vlanId": 20, "network": "10.20.0.0/24", "rangeStart": "10.20.0.100",
		"rangeEnd": "10.20.0.199", "gateway": "10.20.0.1", "dnsServers": []string{"10.20.0.2"}, "interface": "eth0.20",
		"ddnsDomain": "invites.lan"}
	if s := c.do("POST", "/api/v1/dhcp/scopes", in, &sc); s != 201 || sc.Mode != "direct" || sc.ReverseZones[0] != "0.20.10.in-addr.arpa" {
		t.Fatalf("create scope: %d %+v", s, sc)
	}
	// The reverse zone and the DDNS zone were created.
	var zones struct{ Items []struct{ Name string } }
	c.do("GET", "/api/v1/dns/zones", nil, &zones)
	names := ""
	for _, z := range zones.Items {
		names += z.Name + " "
	}
	if !strings.Contains(names, "invites.lan") || !strings.Contains(names, "0.20.10.in-addr.arpa") {
		t.Fatalf("auto zones: %s", names)
	}
	// DHCP must be enabled on the interface before anything is served.
	if s := c.do("PATCH", "/api/v1/interfaces/eth0.20", map[string]any{"dhcpEnabled": true}, nil); s != 200 {
		t.Fatalf("enable DHCP: %d", s)
	}
	ip := lease(t, h, net.HardwareAddr{2, 0, 0, 0, 0, 1}, "Tablette")
	if !netip.MustParsePrefix("10.20.0.0/24").Contains(ip) {
		t.Fatalf("lease ip %v", ip)
	}
	var leases struct {
		Items []struct {
			IP, State, MAC string
			DNSName        *string
			VLANID         *int
		}
	}
	c.do("GET", "/api/v1/dhcp/leases?vlan=20", nil, &leases)
	if len(leases.Items) != 1 || leases.Items[0].State != "bound" || leases.Items[0].DNSName == nil || *leases.Items[0].DNSName != "tablette.invites.lan." {
		t.Fatalf("leases: %+v", leases)
	}
	waitLookup(t, c, "tablette.invites.lan", "A", ip.String())
	waitLookup(t, c, ip.String()[len("10.20.0."):]+".0.20.10.in-addr.arpa", "PTR", "tablette.invites.lan.")

	// VLAN view.
	var vl struct {
		Items []struct {
			VLANID     int
			Name       string
			Interfaces []struct{ Name string }
			Scopes     []struct {
				ActiveLeases int
				Size         int
				Mode         string
			}
		}
	}
	c.do("GET", "/api/v1/vlans", nil, &vl)
	if len(vl.Items) != 1 || vl.Items[0].VLANID != 20 || vl.Items[0].Name != "20 - Invités" || len(vl.Items[0].Interfaces) != 1 ||
		vl.Items[0].Scopes[0].ActiveLeases != 1 || vl.Items[0].Scopes[0].Size != 100 {
		t.Fatalf("vlans: %+v", vl)
	}

	// Operators manage leases and reservations, read-only users do not.
	h.auth.CreateUser(context.Background(), "op", auth.RoleOperator, "operator password")
	op := h.client()
	op.login("op", "operator password")
	var res struct{ ID, IP string }
	if s := op.do("POST", "/api/v1/dhcp/leases/"+sc.ID+"/"+ip.String()+"/reserve", nil, &res); s != 201 || res.IP != ip.String() {
		t.Fatalf("lease -> reservation: %d %+v", s, res)
	}
	op.expect("POST", "/api/v1/dhcp/scopes", in, 403, TForbidden)
	if s := op.do("DELETE", "/api/v1/dhcp/leases/"+sc.ID+"/"+ip.String(), nil, nil); s != 204 {
		t.Fatalf("release: %d", s)
	}
	// Releasing removes the DNS name.
	waitLookup(t, c, "tablette.invites.lan", "A", "")
}

// fakeTechnitium serves the subset of the Technitium API used by the import.
func fakeTechnitium(t *testing.T) *httptest.Server {
	ok := func(w http.ResponseWriter, resp any) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "response": resp})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/settings/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			json.NewEncoder(w).Encode(map[string]any{"status": "invalid-token"})
			return
		}
		ok(w, map[string]any{"version": "13.6", "forwarders": []string{"dns.quad9.net (9.9.9.9:853)"}, "forwarderProtocol": "Tls"})
	})
	mux.HandleFunc("/api/zones/list", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"zones": []map[string]any{
			{"name": "maison.lan", "type": "Primary", "internal": false},
			{"name": "corp.local", "type": "Forwarder", "internal": false},
			{"name": "localhost", "type": "Primary", "internal": true},
			{"name": "example.org", "type": "Secondary", "internal": false},
		}})
	})
	mux.HandleFunc("/api/zones/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("$ORIGIN maison.lan.\n@ 3600 IN SOA ns.maison.lan. hostmaster.maison.lan. 1 3600 600 604800 300\n" +
			"nas 3600 IN A 192.168.1.10\nwww 3600 IN CNAME nas\n@ 3600 IN MX 10 nas\n" +
			"app 3600 IN APP \"Split Horizon\" \"x\" \"y\"\n")) // a Technitium-only type
	})
	mux.HandleFunc("/api/zones/records/get", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"records": []map[string]any{
			{"name": "corp.local", "type": "FWD", "ttl": 3600, "rData": map[string]any{"protocol": "Udp", "forwarder": "10.0.0.53"}},
		}})
	})
	mux.HandleFunc("/api/dhcp/scopes/list", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"scopes": []map[string]any{{"name": "Bureau", "enabled": true}}})
	})
	mux.HandleFunc("/api/dhcp/scopes/get", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"name": "Bureau", "startingAddress": "10.20.0.50", "endingAddress": "10.20.0.90",
			"subnetMask": "255.255.255.0", "leaseTimeDays": 1, "leaseTimeHours": 0, "leaseTimeMinutes": 0,
			"domainName": "bureau.lan", "dnsUpdates": true, "routerAddress": "10.20.0.1", "dnsServers": []string{"10.20.0.2"},
			"genericOptions": []map[string]any{{"code": 66, "value": "74:66:74:70"}},
			"exclusions":     []map[string]any{{"startingAddress": "10.20.0.60", "endingAddress": "10.20.0.62"}},
			"reservedLeases": []map[string]any{{"hostName": "imprimante", "hardwareAddress": "00-11-22-33-44-55", "address": "10.20.0.10", "comments": "RDC"}}})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestTechnitiumImport(t *testing.T) {
	h := newHarness(t, nil)
	addVLANIface(h)
	tech := fakeTechnitium(t)
	h.srv.importClient = tech.Client()
	c := adminClient(t, h)

	var rep struct {
		DryRun                   bool
		Source                   string
		Created, Skipped, Errors int
		Items                    []struct{ Kind, Name, Action, Detail string }
	}
	body := map[string]any{"url": tech.URL, "token": "tok", "dryRun": true}
	if s := c.do("POST", "/api/v1/import/technitium", body, &rep); s != 200 || !rep.DryRun || rep.Source != "Technitium DNS Server 13.6" {
		t.Fatalf("preview: %d %+v", s, rep)
	}
	// Preview writes nothing.
	var zones struct{ Items []struct{ Name string } }
	c.do("GET", "/api/v1/dns/zones", nil, &zones)
	if len(zones.Items) != 0 {
		t.Fatalf("dry run created zones: %+v", zones)
	}
	body["dryRun"] = false
	c.do("POST", "/api/v1/import/technitium", body, &rep)
	got := map[string]string{}
	for _, it := range rep.Items {
		got[it.Kind+" "+it.Name] = it.Action
	}
	want := map[string]string{
		"zone maison.lan": "create", "zone example.org": "skip", "forwarder corp.local → 10.0.0.53": "create",
		"forwarder global → dns.quad9.net (9.9.9.9:853)": "create", "scope Bureau": "create", "reservation 10.20.0.10": "create",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q (report %+v)", k, got[k], v, rep.Items)
		}
	}
	// Imported data is live.
	waitLookup(t, c, "nas.maison.lan", "A", "192.168.1.10")
	var fw struct {
		Items []struct{ Domain, Protocol, Address, TLSServerName string }
	}
	c.do("GET", "/api/v1/dns/forwarders", nil, &fw)
	if len(fw.Items) != 2 || fw.Items[0].Protocol != "dot" || fw.Items[0].TLSServerName != "dns.quad9.net" || fw.Items[1].Domain != "corp.local" {
		t.Fatalf("forwarders: %+v", fw)
	}
	var scopes struct {
		Items []struct {
			Name, Mode string
			Interface  *string
			VLANID     *int
			LeaseTime  int
			Options    []struct{ Code int }
		}
	}
	c.do("GET", "/api/v1/dhcp/scopes", nil, &scopes)
	sc := scopes.Items[0]
	if sc.Mode != "direct" || *sc.Interface != "eth0.20" || *sc.VLANID != 20 || sc.LeaseTime != 86400 || sc.Options[0].Code != 66 {
		t.Fatalf("scope: %+v", sc)
	}
	// Running it again skips everything.
	c.do("POST", "/api/v1/import/technitium", body, &rep)
	if rep.Created != 0 {
		t.Fatalf("second import created %d objects: %+v", rep.Created, rep.Items)
	}
	// A wrong token gives a clear error.
	body["token"] = "bad"
	var p problemResp
	if s := c.do("POST", "/api/v1/import/technitium", body, &p); s != 502 || p.Type != TUpstream {
		t.Fatalf("bad token: %d %+v", s, p)
	}
}
