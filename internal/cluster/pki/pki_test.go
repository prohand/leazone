package pki

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKey = "a shared cluster key 123"

func mustKeys(t *testing.T, key string) *Keys {
	t.Helper()
	k, err := DeriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCA(t *testing.T) func(*CA, error) *CA {
	return func(ca *CA, err error) *CA {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
}

// serve starts a TLS server that echoes the client's common name.
func serve(t *testing.T, ca *CA, name string, allow Allow) *httptest.Server {
	t.Helper()
	cert, err := ca.Issue(name)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok "+r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	ts.TLS = ca.ServerConfig(cert, allow)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func get(url string, ca *CA, name string, allow Allow) (string, error) {
	c, err := ca.Issue(name)
	if err != nil {
		return "", err
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(c, allow)}}
	resp, err := hc.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestSameKeySameCAAndMutualTLS(t *testing.T) {
	a := mustCA(t)(mustKeys(t, testKey).NodeCA())
	b := mustCA(t)(mustKeys(t, testKey).NodeCA())
	if !a.cert.Equal(b.cert) {
		t.Fatal("same key must give the same CA")
	}
	other := mustCA(t)(mustKeys(t, "another cluster key 456").NodeCA())
	if _, err := DeriveKeys("short"); err == nil {
		t.Fatal("short key accepted")
	}

	ts := serve(t, a, "node:a", AnyNode)
	if body, err := get(ts.URL, b, "node:b", AnyNode); err != nil || body != "ok node:b" {
		t.Fatalf("member: %q %v", body, err)
	}
	_, err := get(ts.URL, other, "node:b", AnyNode)
	if err == nil {
		t.Fatal("a node with another cluster key was accepted")
	}
	if !IsMismatch(err) {
		t.Fatalf("another cluster key is not reported as a mismatch: %v", err)
	}
	// A client without certificate is refused.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := hc.Get(ts.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("anonymous client: %v", err)
	}
}

// The common name is checked on both sides: a certificate of the right CA
// with another identity is refused.
func TestCommonNameChecked(t *testing.T) {
	ca := mustCA(t)(mustKeys(t, testKey).NodeCA())
	ts := serve(t, ca, "node:a", AnyNode)
	_, err := get(ts.URL, ca, "witness", nil)
	if err == nil {
		t.Fatal("server accepted a client whose name is not node:<id>")
	}
	// The server's refusal (a TLS alert) also shows a running peer.
	if !IsMismatch(err) {
		t.Fatalf("server refusal not reported as a mismatch: %v", err)
	}
	if _, err := get(ts.URL, ca, "node:", nil); err == nil {
		t.Fatal("server accepted an empty node ID")
	}
	// The client expects the witness: a node certificate is refused.
	if _, err := get(ts.URL, ca, "node:b", OnlyWitness); err == nil || !IsMismatch(err) {
		t.Fatalf("client accepted a server that is not the witness: %v", err)
	}
}

// The witness key is a one-way derivation: the witness CA cannot sign a
// certificate that the nodes accept on their port, and the witness key
// cannot be turned into the node CA.
func TestWitnessCannotImpersonateANode(t *testing.T) {
	k := mustKeys(t, testKey)
	nodeCA := mustCA(t)(k.NodeCA())
	wk := k.WitnessKey()
	if !IsWitnessKey(wk) || IsWitnessKey(testKey) {
		t.Fatal("witness key format")
	}
	if wk == testKey || strings.Contains(wk, testKey) {
		t.Fatal("witness key reveals the cluster key")
	}
	witnessCA := mustCA(t)(WitnessCA(wk))
	fromNodes := mustCA(t)(k.WitnessCA())
	if !witnessCA.cert.Equal(fromNodes.cert) {
		t.Fatal("nodes and witness must derive the same witness CA")
	}
	if witnessCA.cert.Equal(nodeCA.cert) {
		t.Fatal("witness CA must differ from the node CA")
	}
	// The node port refuses a "node:x" certificate signed by the witness CA.
	ts := serve(t, nodeCA, "node:a", AnyNode)
	forged, _ := witnessCA.Issue("node:x")
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: witnessCA.ClientConfig(forged, nil)}}
	if _, err := hc.Get(ts.URL); err == nil {
		t.Fatal("node port accepted a certificate made with the witness key")
	}
	// Nodes reach the witness with a witness-CA certificate and check its name.
	ws := serve(t, witnessCA, WitnessName, AnyNode)
	if body, err := get(ws.URL, fromNodes, "node:a", OnlyWitness); err != nil || body != "ok node:a" {
		t.Fatalf("node -> witness: %q %v", body, err)
	}
	if _, err := WitnessCA(testKey); err == nil {
		t.Fatal("a cluster key was accepted as a witness key")
	}
}

func TestKeyScheduleSeparatesSecrets(t *testing.T) {
	k := mustKeys(t, testKey)
	k2 := mustKeys(t, "another cluster key 456")
	if string(k.KEK()) == string(k2.KEK()) || k.WitnessKey() == k2.WitnessKey() {
		t.Fatal("different cluster keys must give different secrets")
	}
	if string(k.KEK()) == string(k.sub("witness", 32)) {
		t.Fatal("KEK and witness key must differ")
	}
}

func TestWeakKey(t *testing.T) {
	for key, weak := range map[string]bool{
		"short but 16 chars":                           true,
		"0123456789abcdef0123456789ab":                 true,
		GenerateClusterKey():                           false,
		"a long passphrase of more than 32 characters": false,
	} {
		if WeakKey(key) != weak {
			t.Errorf("WeakKey(%q) = %v", key, !weak)
		}
	}
}
