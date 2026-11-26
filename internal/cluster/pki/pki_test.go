package pki

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameKeySameCAAndMutualTLS(t *testing.T) {
	a, err := Derive("a shared cluster key 123")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Derive("a shared cluster key 123")
	if !a.cert.Equal(b.cert) {
		t.Fatal("same key must give the same CA")
	}
	other, _ := Derive("another cluster key 456")
	if _, err := Derive("short"); err == nil {
		t.Fatal("short key accepted")
	}

	srvCert, _ := a.Issue("node-a")
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok "+r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	ts.TLS = a.ServerConfig(srvCert)
	ts.StartTLS()
	defer ts.Close()

	get := func(ca *CA) (string, error) {
		c, _ := ca.Issue("node-b")
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(c)}}
		resp, err := hc.Get(ts.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if body, err := get(b); err != nil || body != "ok node-b" {
		t.Fatalf("member: %q %v", body, err)
	}
	if _, err := get(other); err == nil {
		t.Fatal("a node with another cluster key was accepted")
	}
	// A client without certificate is refused.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := hc.Get(ts.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("anonymous client: %v", err)
	}
}
