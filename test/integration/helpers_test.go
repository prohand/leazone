//go:build integration

// Package integration runs Leazone in Docker and checks it from the host.
// Run as root (creates test interfaces) with Docker available:
//
//	go test -tags integration -v ./test/integration/
//
// Env: LEAZONE_TEST_IMAGE to reuse an image, GO_IMAGE / NODE_IMAGE to build
// with registry mirrors.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const testImage = "leazone:integration"

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// image builds the image once per test binary (or uses LEAZONE_TEST_IMAGE).
func image(t *testing.T) string {
	t.Helper()
	if img := os.Getenv("LEAZONE_TEST_IMAGE"); img != "" {
		return img
	}
	args := []string{"build", "--network", "host", "-q", "-t", testImage, "--build-arg", "VERSION=0.2.0-test"}
	for _, k := range []string{"GO_IMAGE", "NODE_IMAGE"} {
		if v := os.Getenv(k); v != "" {
			args = append(args, "--build-arg", k+"="+v)
		}
	}
	run(t, "docker", append(args, repoRoot())...)
	os.Setenv("LEAZONE_TEST_IMAGE", testImage)
	return testImage
}

// container is a running Leazone container (host network, hardened).
type container struct {
	name  string
	url   string
	roots *x509.CertPool
}

// testCert returns a self-signed certificate for 127.0.0.1 and a pool trusting it.
func testCert(t *testing.T) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leazone-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), pool
}

func startContainer(t *testing.T, name, httpAddr string, extraEnv ...string) *container {
	t.Helper()
	img := image(t)
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	pw := filepath.Join(dir, "admin_password")
	os.WriteFile(pw, []byte("integration admin password\n"), 0o644)
	// A test certificate provided as files in /data/tls (one of the supported
	// ways to give Leazone its HTTPS certificate). The client trusts it.
	certPEM, keyPEM, pool := testCert(t)
	tlsDir := filepath.Join(dir, "tls")
	os.Mkdir(tlsDir, 0o755)
	os.WriteFile(filepath.Join(tlsDir, "cert.pem"), certPEM, 0o644)
	os.WriteFile(filepath.Join(tlsDir, "key.pem"), keyPEM, 0o644)
	exec.Command("docker", "rm", "-f", name).Run()
	exec.Command("docker", "volume", "rm", "-f", name+"-data").Run()
	args := []string{"run", "-d", "--name", name, "--network", "host", "--user", "1000:1000", "--read-only",
		"--tmpfs", "/tmp:mode=1777", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
		"--cap-add", "NET_BIND_SERVICE", "--cap-add", "NET_RAW",
		"-e", "LEAZONE_HTTP_LISTEN=" + httpAddr, "-e", "LEAZONE_ADMIN_PASSWORD_FILE=/run/admin_password",
		"-v", pw + ":/run/admin_password:ro", "-v", name + "-data:/data", "-v", tlsDir + ":/data/tls:ro",
		"--tmpfs", "/logs:mode=1777"}
	for _, e := range extraEnv {
		args = append(args, "-e", e)
	}
	run(t, "docker", append(args, img)...)
	c := &container{name: name, url: "https://" + httpAddr, roots: pool}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "50", name).CombinedOutput()
			t.Logf("docker logs %s:\n%s", name, out)
		}
		exec.Command("docker", "rm", "-f", name).Run()
		exec.Command("docker", "volume", "rm", "-f", name+"-data").Run()
	})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("docker", "exec", name, "/leazone", "healthcheck").Run() == nil {
			return c
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("container %s not healthy", name)
	return nil
}

// api is a logged-in API client.
type api struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string

	totpSecret string // set by loginAdmin
}

func newAPI(t *testing.T, c *container) *api {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.roots}, Proxy: nil}
	return &api{t: t, base: c.url, hc: &http.Client{Jar: jar, Transport: tr, Timeout: 20 * time.Second}}
}

func (a *api) do(method, path string, body, out any) int {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, a.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", a.base)
	if a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			a.t.Fatalf("%s %s: %v (%s)", method, path, err, raw)
		}
	}
	return resp.StatusCode
}

// loginAdmin logs in and enrolls TOTP on first login, returning a full session.
func (a *api) loginAdmin() {
	a.t.Helper()
	var st struct {
		State     string `json:"state"`
		CSRFToken string `json:"csrfToken"`
	}
	if s := a.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "integration admin password"}, &st); s != 200 {
		a.t.Fatalf("login: %d", s)
	}
	a.csrf = st.CSRFToken
	if st.State != "mfa_setup_required" {
		a.t.Fatalf("unexpected state %s", st.State)
	}
	var setup struct{ Secret string }
	a.do("POST", "/api/v1/me/totp/setup", nil, &setup)
	a.totpSecret = setup.Secret
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	if s := a.do("POST", "/api/v1/me/totp/confirm", map[string]string{"code": code}, nil); s != 200 {
		a.t.Fatalf("totp confirm: %d", s)
	}
}

func jsonDecode(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

// doToken calls the API with a bearer token (no cookie, no CSRF).
func (a *api) doToken(method, path string, body, out any, token string) int {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.hc.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode
}
