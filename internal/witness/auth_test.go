package witness

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/cluster/pki"
	"github.com/prohand/leazone/internal/cluster/proto"
)

const nodesKey = "the cluster key of the nodes 0123456789"

func TestResolveKey(t *testing.T) {
	keys, err := pki.DeriveKeys(nodesKey)
	if err != nil {
		t.Fatal(err)
	}
	wk := keys.WitnessKey()
	if k, legacy, err := ResolveKey(wk, ""); err != nil || legacy || k != wk {
		t.Fatalf("witness key: %q %v %v", k, legacy, err)
	}
	// Older deployment: only the cluster key. Same witness key, flagged.
	if k, legacy, err := ResolveKey("", nodesKey); err != nil || !legacy || k != wk {
		t.Fatalf("cluster key: %q %v %v", k, legacy, err)
	}
	// The witness key put in the old secret is used as such.
	if k, legacy, err := ResolveKey("", wk); err != nil || legacy || k != wk {
		t.Fatalf("witness key in the cluster key secret: %q %v %v", k, legacy, err)
	}
	if _, _, err := ResolveKey(nodesKey, ""); err == nil {
		t.Fatal("a cluster key accepted as LEAZONE_WITNESS_KEY_FILE")
	}
	if _, _, err := ResolveKey("", ""); err == nil {
		t.Fatal("no key accepted")
	}
}

// The witness only serves clients with a witness-CA certificate named
// node:<id>, and a node can only ask a lease for itself.
func TestHandlerBindsNodeToCertificate(t *testing.T) {
	keys, err := pki.DeriveKeys(nodesKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := pki.WitnessCA(keys.WitnessKey())
	nodeCA, _ := keys.NodeCA()
	w, err := New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	w.expires = time.Now()
	cert, _ := ca.Issue(pki.WitnessName)
	ts := httptest.NewUnstartedServer(w.Handler())
	ts.TLS = ca.ServerConfig(cert, pki.AnyNode)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	defer ts.Close()
	post := func(ca *pki.CA, name string, req proto.LeaseRequest) (proto.LeaseResponse, int, error) {
		c, _ := ca.Issue(name)
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: ca.ClientConfig(c, nil)}}
		b, _ := json.Marshal(req)
		resp, err := hc.Post(ts.URL+"/witness/v1/acquire", "application/json", bytes.NewReader(b))
		if err != nil {
			return proto.LeaseResponse{}, 0, err
		}
		defer resp.Body.Close()
		var out proto.LeaseResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out, resp.StatusCode, nil
	}
	if _, code, err := post(ca, "node:b", proto.LeaseRequest{NodeID: "a", LeaseMs: 6000}); err != nil || code != http.StatusForbidden {
		t.Fatalf("lease asked for another node: %d %v", code, err)
	}
	if _, _, err := post(ca, pki.WitnessName, proto.LeaseRequest{NodeID: "witness", LeaseMs: 6000}); err == nil {
		t.Fatal("a client named witness was served")
	}
	if _, _, err := post(nodeCA, "node:a", proto.LeaseRequest{NodeID: "a", LeaseMs: 6000}); err == nil {
		t.Fatal("a node CA certificate was accepted by the witness")
	}
	if r, code, err := post(ca, "node:a", proto.LeaseRequest{NodeID: "a", Name: "node1", LeaseMs: 6000}); err != nil || code != http.StatusOK || !r.Granted {
		t.Fatalf("own lease: %+v %d %v", r, code, err)
	}
}
