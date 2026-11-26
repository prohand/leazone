package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestPlainSecretsRefused(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(env(map[string]string{"LEAZONE_CONFIG_DIR": dir, "LEAZONE_ADMIN_PASSWORD": "secret"}))
	if err == nil || !strings.Contains(err.Error(), "_FILE") {
		t.Fatalf("plain secret accepted: %v", err)
	}
	c, err := Load(env(map[string]string{"LEAZONE_CONFIG_DIR": dir, "LEAZONE_ADMIN_PASSWORD": "secret", "LEAZONE_ALLOW_PLAIN_SECRETS": "true"}))
	if err != nil || c.AdminPassword != "secret" {
		t.Fatalf("explicitly allowed plain secret: %v", err)
	}
}

func TestSecretFileAndYAML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pw"), []byte("from-file\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "leazone.yaml"), []byte("http_listen: \":9443\"\npublic_url: https://leazone.lan/\n"), 0o600)
	c, err := Load(env(map[string]string{"LEAZONE_CONFIG_DIR": dir, "LEAZONE_ADMIN_PASSWORD_FILE": filepath.Join(dir, "pw"),
		"LEAZONE_TRUSTED_PROXIES": "10.0.0.5, 192.168.1.0/24"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminPassword != "from-file" || c.HTTPListen != ":9443" || c.PublicURL != "https://leazone.lan" || len(c.Proxies()) != 2 {
		t.Fatalf("%+v", c)
	}
	os.WriteFile(filepath.Join(dir, "leazone.yaml"), []byte("unknown_key: 1\n"), 0o600)
	if _, err := Load(env(map[string]string{"LEAZONE_CONFIG_DIR": dir})); err == nil {
		t.Fatal("unknown YAML key accepted")
	}
}

func TestPublicURLMustBeHTTPS(t *testing.T) {
	if _, err := Load(env(map[string]string{"LEAZONE_CONFIG_DIR": t.TempDir(), "LEAZONE_PUBLIC_URL": "http://x.lan"})); err == nil {
		t.Fatal("http public URL accepted")
	}
}

func TestClusterURLsAndKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "key"), []byte("\n"), 0o600)
	e := map[string]string{"LEAZONE_CONFIG_DIR": dir, "LEAZONE_CLUSTER_ADDR": "https://10.0.0.1:7443/",
		"LEAZONE_CLUSTER_PEERS": "https://10.0.0.2:7443/", "LEAZONE_WITNESS": "https://10.0.0.3:7443//",
		"LEAZONE_CLUSTER_KEY_FILE": filepath.Join(dir, "key")}
	// Peers configured but an empty key file: refused instead of starting alone.
	if _, err := Load(env(e)); err == nil || !strings.Contains(err.Error(), "cluster key") {
		t.Fatalf("empty cluster key accepted: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "key"), []byte("k\n"), 0o600)
	c, err := Load(env(e))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterAddr != "https://10.0.0.1:7443" || c.Peers[0] != "https://10.0.0.2:7443" || c.Witness != "https://10.0.0.3:7443" {
		t.Fatalf("not normalized: %q %q %q", c.ClusterAddr, c.Peers, c.Witness)
	}
	if c.ControlSocket != filepath.Join("/data", "run", "leazone.sock") {
		t.Fatalf("control socket %q", c.ControlSocket)
	}
}
