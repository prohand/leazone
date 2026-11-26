//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// haImages builds two images that only differ by version (update scenario).
func haImages(t *testing.T) (string, string) {
	if a, b := os.Getenv("LEAZONE_HA_IMAGE_A"), os.Getenv("LEAZONE_HA_IMAGE_B"); a != "" && b != "" {
		return a, b
	}
	build := func(tag, ver string) {
		args := []string{"build", "--network", "host", "-q", "-t", tag, "--build-arg", "VERSION=" + ver}
		for _, k := range []string{"GO_IMAGE", "NODE_IMAGE"} {
			if v := os.Getenv(k); v != "" {
				args = append(args, "--build-arg", k+"="+v)
			}
		}
		run(t, "docker", append(args, repoRoot())...)
	}
	build("leazone:ha-a", "0.4.0")
	build("leazone:ha-b", "0.5.0")
	return "leazone:ha-a", "leazone:ha-b"
}

func certFor(t *testing.T, ips ...string) ([]byte, []byte, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leazone-ha-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, ip := range ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), pool
}

type haEnv struct {
	t     *testing.T
	dir   string
	pool  *x509.CertPool
	token string
}

const (
	netLink = "lz1link" // node <-> node, DHCP clients (eth0 in both nodes: first network by name)
	netA    = "lz2a"    // node1 <-> witness
	netB    = "lz3b"    // node2 <-> witness
)

var nodeIP = map[string]string{"lzha1": "10.88.0.11", "lzha2": "10.88.0.12"}
var mgmtIP = map[string]string{"lzha1": "10.88.1.11", "lzha2": "10.88.2.12"}

func (e *haEnv) cleanup() {
	for _, c := range []string{"lzha1", "lzha2", "lzhaw"} {
		exec.Command("docker", "rm", "-f", c).Run()
		exec.Command("docker", "volume", "rm", "-f", c+"-data").Run()
	}
	for _, n := range []string{netLink, netA, netB} {
		exec.Command("docker", "network", "rm", n).Run()
	}
}

func (e *haEnv) startNode(name, image, preferred string) {
	e.t.Helper()
	exec.Command("docker", "rm", "-f", name).Run()
	peer := "lzha2"
	witness := "https://10.88.1.13:7443"
	if name == "lzha2" {
		peer, witness = "lzha1", "https://10.88.2.13:7443"
	}
	args := []string{"create", "--name", name, "--network", netLink, "--ip", nodeIP[name], "--user", "1000:1000", "--read-only",
		"--tmpfs", "/tmp:mode=1777", "--tmpfs", "/logs:mode=1777", "--security-opt", "no-new-privileges:true",
		"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--cap-add", "NET_RAW",
		"-e", "LEAZONE_NODE_NAME=" + name, "-e", "LEAZONE_PREFERRED_ROLE=" + preferred,
		"-e", "LEAZONE_CLUSTER_ADDR=https://" + nodeIP[name] + ":7443", "-e", "LEAZONE_CLUSTER_PEERS=https://" + nodeIP[peer] + ":7443",
		"-e", "LEAZONE_CLUSTER_LISTEN=:7443", "-e", "LEAZONE_WITNESS=" + witness,
		"-e", "LEAZONE_CLUSTER_KEY_FILE=/run/cluster_key", "-e", "LEAZONE_ADMIN_PASSWORD_FILE=/run/admin_password",
		"-v", e.dir + "/cluster_key:/run/cluster_key:ro", "-v", e.dir + "/admin_password:/run/admin_password:ro",
		"-v", name + "-data:/data", "-v", e.dir + "/tls:/data/tls:ro", image}
	run(e.t, "docker", args...)
	other := netA
	if name == "lzha2" {
		other = netB
	}
	run(e.t, "docker", "network", "connect", "--ip", mgmtIP[name], other, name)
	run(e.t, "docker", "start", name)
}

func (e *haEnv) client(name string) *api {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool}, Proxy: nil}
	a := &api{t: e.t, base: "https://" + mgmtIP[name] + ":8443", hc: &http.Client{Jar: jar, Transport: tr, Timeout: 20 * time.Second}}
	return a
}

type clusterView struct {
	Role, ReadOnlyReason string
	Writable             bool
	Nodes                []struct {
		Name, Role string
		Online     bool
	}
	Gaps []struct{ Kind, Detail string }
}

func (e *haEnv) view(name string) (clusterView, bool) {
	a := e.client(name)
	a.hc.Timeout = 3 * time.Second
	req, _ := http.NewRequest("GET", a.base+"/api/v1/cluster", nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := a.hc.Do(req)
	if err != nil {
		return clusterView{}, false
	}
	defer resp.Body.Close()
	var v clusterView
	if resp.StatusCode != 200 || jsonDecode(resp, &v) != nil {
		return clusterView{}, false
	}
	return v, true
}

func (e *haEnv) waitRole(name, role string, d time.Duration) clusterView {
	e.t.Helper()
	deadline := time.Now().Add(d)
	var last clusterView
	for time.Now().Before(deadline) {
		if v, ok := e.view(name); ok {
			last = v
			if v.Role == role {
				return v
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.t.Fatalf("%s: role %q, want %q", name, last.Role, role)
	return last
}

// tok calls the API of a node with the admin API token.
func (e *haEnv) tok(name, method, path string, body, out any) int {
	a := e.client(name)
	return a.doToken(method, path, body, out, e.token)
}

func (e *haEnv) waitZone(name, zone string, d time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		var z struct{ Items []struct{ Name string } }
		if e.tok(name, "GET", "/api/v1/dns/zones", nil, &z) == 200 {
			for _, it := range z.Items {
				if it.Name == zone {
					return
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	e.t.Fatalf("zone %s not on %s", zone, name)
}

var leaseRe = regexp.MustCompile(`lease of (\d+\.\d+\.\d+\.\d+) obtained`)

// dhcpClient runs busybox udhcpc on the link network and returns the IP.
func (e *haEnv) dhcpClient(i int) string {
	e.t.Helper()
	mac := fmt.Sprintf("02:42:00:00:aa:%02x", i)
	out, _ := exec.Command("docker", "run", "--rm", "--network", netLink, "--mac-address", mac, busybox(),
		"udhcpc", "-i", "eth0", "-f", "-q", "-n", "-t", "6", "-T", "2", "-s", "/bin/true").CombinedOutput()
	m := leaseRe.FindStringSubmatch(string(out))
	if m == nil {
		e.t.Fatalf("client %d: no lease:\n%s", i, out)
	}
	return m[1]
}

func busybox() string {
	if v := os.Getenv("BUSYBOX_IMAGE"); v != "" {
		return v
	}
	return "mirror.gcr.io/library/busybox:1.36"
}

func TestPhase4HA(t *testing.T) {
	imgA, imgB := haImages(t)
	e := &haEnv{t: t, dir: t.TempDir()}
	os.Chmod(e.dir, 0o755)
	e.cleanup()
	t.Cleanup(func() {
		if t.Failed() {
			for _, c := range []string{"lzha1", "lzha2", "lzhaw"} {
				out, _ := exec.Command("docker", "logs", "--tail", "40", c).CombinedOutput()
				t.Logf("--- %s ---\n%s", c, out)
			}
		}
		if os.Getenv("KEEP") == "" {
			e.cleanup()
		}
	})
	os.WriteFile(filepath.Join(e.dir, "cluster_key"), []byte("integration cluster key 0123456789abcdef\n"), 0o644)
	os.WriteFile(filepath.Join(e.dir, "admin_password"), []byte("integration admin password\n"), 0o644)
	c, k, pool := certFor(t, "10.88.0.11", "10.88.0.12", "10.88.1.11", "10.88.2.12")
	e.pool = pool
	os.Mkdir(filepath.Join(e.dir, "tls"), 0o755)
	os.WriteFile(filepath.Join(e.dir, "tls", "cert.pem"), c, 0o644)
	os.WriteFile(filepath.Join(e.dir, "tls", "key.pem"), k, 0o644)

	run(t, "docker", "network", "create", "--subnet", "10.88.0.0/24", "--ip-range", "10.88.0.0/26", netLink)
	run(t, "docker", "network", "create", "--subnet", "10.88.1.0/24", netA)
	run(t, "docker", "network", "create", "--subnet", "10.88.2.0/24", netB)
	run(t, "docker", "create", "--name", "lzhaw", "--network", netA, "--ip", "10.88.1.13", "--user", "1000:1000", "--read-only",
		"--tmpfs", "/tmp:mode=1777", "--cap-drop", "ALL", "-e", "LEAZONE_CLUSTER_LISTEN=:7443",
		"-e", "LEAZONE_CLUSTER_KEY_FILE=/run/cluster_key", "-v", e.dir+"/cluster_key:/run/cluster_key:ro",
		"-v", "lzhaw-data:/data", imgA, "witness")
	run(t, "docker", "network", "connect", "--ip", "10.88.2.13", netB, "lzhaw")
	run(t, "docker", "start", "lzhaw")
	e.startNode("lzha1", imgA, "primary")
	e.startNode("lzha2", imgA, "secondary")

	// node1 becomes primary; the admin enrolls TOTP there and creates an API token.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("docker", "logs", "lzha1").CombinedOutput()
		if strings.Contains(string(out), "this node is now PRIMARY") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	a1 := e.client("lzha1")
	a1.loginAdmin()
	st := map[string]any{"heartbeatMs": 500, "failCount": 3, "leaseMs": 4000, "failbackMode": "auto", "failbackDelaySec": 5, "dhcpMode": "load-balancing"}
	if s := a1.do("PUT", "/api/v1/cluster/settings", st, nil); s != 200 {
		t.Fatalf("cluster settings: %d", s)
	}
	var tk struct{ Token string }
	if s := a1.do("POST", "/api/v1/me/tokens", map[string]string{"name": "ha-test", "scope": "write"}, &tk); s != 201 {
		t.Fatalf("token: %d", s)
	}
	e.token = tk.Token
	e.waitRole("lzha2", "secondary", 30*time.Second)
	v1 := e.waitRole("lzha1", "primary", 10*time.Second)
	t.Logf("✔ node1 primary, node2 secondary (%d nodes seen)", len(v1.Nodes))

	// Config replication and read-only secondary.
	if s := e.tok("lzha1", "POST", "/api/v1/dns/zones", map[string]any{"name": "ha.lan"}, nil); s != 201 {
		t.Fatalf("zone on primary: %d", s)
	}
	e.waitZone("lzha2", "ha.lan", 10*time.Second)
	var p struct{ Type, PrimaryURL string }
	if s := e.tok("lzha2", "POST", "/api/v1/dns/zones", map[string]any{"name": "nope.lan"}, &p); s != 409 || p.Type != "urn:leazone:not-primary" {
		t.Fatalf("write on secondary: %d %+v", s, p)
	}
	t.Log("✔ config replicated to node2, node2 read-only (409 not-primary)")

	// DHCP load balancing on the shared segment.
	scope := map[string]any{"name": "lan", "network": "10.88.0.0/24", "rangeStart": "10.88.0.100", "rangeEnd": "10.88.0.150",
		"interface": "eth0", "ddnsDomain": "ha.lan", "dnsServers": []string{"10.88.0.11", "10.88.0.12"}}
	if s := e.tok("lzha1", "POST", "/api/v1/dhcp/scopes", scope, nil); s != 201 {
		t.Fatalf("scope: %d", s)
	}
	if s := e.tok("lzha1", "PATCH", "/api/v1/interfaces/eth0", map[string]any{"dhcpEnabled": true}, nil); s != 200 {
		t.Fatalf("enable DHCP: %d", s)
	}
	time.Sleep(2 * time.Second) // replication + reload on node2
	ips := map[string]bool{}
	for i := 1; i <= 6; i++ {
		ip := e.dhcpClient(i)
		if ips[ip] {
			t.Fatalf("address %s given twice", ip)
		}
		ips[ip] = true
	}
	time.Sleep(time.Second)
	for _, n := range []string{"lzha1", "lzha2"} {
		var l struct{ Items []struct{ IP, State string } }
		e.tok(n, "GET", "/api/v1/dhcp/leases", nil, &l)
		bound := 0
		for _, it := range l.Items {
			if it.State == "bound" {
				bound++
			}
		}
		if bound != 6 {
			t.Fatalf("%s sees %d bound leases, want 6 (lease sync)", n, bound)
		}
	}
	t.Logf("✔ 6 DHCP clients served by the two nodes, unique addresses, leases known by both: %v", keys(ips))

	// Primary failure.
	run(t, "docker", "stop", "-t", "2", "lzha1")
	start := time.Now()
	e.waitRole("lzha2", "primary", 40*time.Second)
	t.Logf("✔ node2 promoted %.1f s after node1 stopped", time.Since(start).Seconds())
	if s := e.tok("lzha2", "POST", "/api/v1/dns/zones", map[string]any{"name": "outage.lan"}, nil); s != 201 {
		t.Fatalf("zone during outage: %d", s)
	}
	ip := e.dhcpClient(20)
	t.Logf("✔ change made during the outage; new DHCP client served by node2 alone (%s)", ip)

	// Return of node1: secondary, resync, then back to primary (auto, 5 s).
	run(t, "docker", "start", "lzha1")
	e.waitRole("lzha1", "primary", 60*time.Second)
	e.waitRole("lzha2", "secondary", 10*time.Second)
	e.waitZone("lzha1", "outage.lan", 5*time.Second)
	t.Log("✔ node1 back as primary after resync; the change made during the outage is there")

	// Split brain: cut the node-to-node link only (both still see the witness).
	run(t, "docker", "network", "disconnect", netLink, "lzha2")
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) {
		v1, ok1 := e.view("lzha1")
		v2, ok2 := e.view("lzha2")
		if ok1 && ok2 && v1.Role == "primary" && v2.Role == "primary" {
			t.Fatal("split brain: both nodes are primary")
		}
		time.Sleep(300 * time.Millisecond)
	}
	run(t, "docker", "network", "connect", "--ip", nodeIP["lzha2"], netLink, "lzha2")
	e.waitRole("lzha2", "secondary", 30*time.Second)
	e.waitRole("lzha1", "primary", 5*time.Second)
	t.Log("✔ link between nodes cut for 15 s: never two primaries; back to normal after repair")

	// Rolling update: node2 gets the new version while node1 runs the old one.
	run(t, "docker", "stop", "-t", "2", "lzha2")
	exec.Command("docker", "rm", "-f", "lzha2").Run()
	e.startNode("lzha2", imgB, "secondary")
	deadline = time.Now().Add(40 * time.Second)
	var frozen clusterView
	for time.Now().Before(deadline) {
		if v, ok := e.view("lzha1"); ok && !v.Writable && strings.Contains(v.ReadOnlyReason, "mise à jour") {
			frozen = v
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if frozen.ReadOnlyReason == "" {
		t.Fatal("mixed versions not detected on the primary")
	}
	var ro struct{ Type string }
	if s := e.tok("lzha1", "POST", "/api/v1/dns/zones", map[string]any{"name": "frozen.lan"}, &ro); s != 409 || ro.Type != "urn:leazone:read-only" {
		t.Fatalf("write during update: %d %+v", s, ro)
	}
	ip2 := e.dhcpClient(30)
	t.Logf("✔ mixed versions 0.4/0.5: config frozen (%q), DHCP still served (%s)", frozen.ReadOnlyReason, ip2)
	// Then node1 is updated too: back to writable.
	run(t, "docker", "stop", "-t", "2", "lzha1")
	exec.Command("docker", "rm", "-f", "lzha1").Run()
	e.startNode("lzha1", imgB, "primary")
	e.waitRole("lzha1", "primary", 60*time.Second)
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := e.view("lzha1"); ok && v.Writable {
			t.Log("✔ both nodes on 0.5: configuration writable again, node1 primary")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("configuration still read-only after updating both nodes")
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
