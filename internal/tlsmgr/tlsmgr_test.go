package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

func pair(t *testing.T, notAfter time.Time) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leazone.lan"},
		DNSNames: []string{"leazone.lan"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}

func TestSelfSignedThenImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, _ := store.Open(filepath.Join(dir, "t.db"))
	defer db.Close()
	if err := db.Migrate(ctx, dir, log); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	m, err := New(ctx, db, box, log, dir, []string{"leazone.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.SelfSigned() {
		t.Fatal("expected a self-signed certificate on first start")
	}
	c, k := pair(t, time.Now().Add(-time.Hour))
	if _, err := m.Import(ctx, c, k); err == nil {
		t.Fatal("expired certificate accepted")
	}
	c, _ = pair(t, time.Now().Add(90*24*time.Hour))
	_, k2 := pair(t, time.Now().Add(90*24*time.Hour))
	if _, err := m.Import(ctx, c, k2); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if !m.SelfSigned() {
		t.Fatal("failed import replaced the active certificate")
	}
	c, k = pair(t, time.Now().Add(90*24*time.Hour))
	info, err := m.Import(ctx, c, k)
	if err != nil || info.Source != SourceImport {
		t.Fatalf("import: %v %+v", err, info)
	}
	// Survives a restart.
	m2, err := New(ctx, db, box, log, dir, nil)
	if err != nil || m2.Info().Fingerprint != info.Fingerprint {
		t.Fatalf("after restart: %v %+v", err, m2.Info())
	}
}

// An expired certificate must not stop the service: a self-signed one is
// regenerated, a file one is served with a warning.
func TestExpiredCertificateAtStartup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, _ := store.Open(filepath.Join(dir, "t.db"))
	defer db.Close()
	if err := db.Migrate(ctx, dir, log); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(secrets.NewDEK())
	c, k := pair(t, time.Now().Add(-time.Hour))
	if _, err := db.ExecContext(ctx, `INSERT INTO certificates(id, source, active, cert_pem, key_enc, not_after, created_at)
		VALUES ('old', ?, 1, ?, ?, 0, 0)`, SourceSelfSigned, c, box.Seal([]byte(k), "cert:old")); err != nil {
		t.Fatal(err)
	}
	m, err := New(ctx, db, box, log, dir, []string{"leazone.lan"})
	if err != nil {
		t.Fatalf("expired self-signed certificate blocks the start: %v", err)
	}
	if !m.SelfSigned() || time.Until(m.Info().NotAfter) < 300*24*time.Hour {
		t.Fatalf("self-signed certificate not renewed: %+v", m.Info())
	}

	// Renewal while running, 30 days before expiry.
	c, k = pair(t, time.Now().Add(10*24*time.Hour))
	if err := m.load(c, k, SourceSelfSigned); err != nil {
		t.Fatal(err)
	}
	if err := m.RenewIfNeeded(ctx); err != nil || time.Until(m.Info().NotAfter) < 300*24*time.Hour {
		t.Fatalf("expiring self-signed certificate not renewed: %v %+v", err, m.Info())
	}
	// A recent one is kept.
	fp := m.Info().Fingerprint
	if err := m.RenewIfNeeded(ctx); err != nil || m.Info().Fingerprint != fp {
		t.Fatalf("valid certificate replaced: %v", err)
	}

	// An expired certificate given as a file is served (with a warning).
	fdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fdir, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	c, k = pair(t, time.Now().Add(-time.Hour))
	_ = os.WriteFile(filepath.Join(fdir, "tls", "cert.pem"), []byte(c), 0o600)
	_ = os.WriteFile(filepath.Join(fdir, "tls", "key.pem"), []byte(k), 0o600)
	mf, err := New(ctx, db, box, log, fdir, nil)
	if err != nil || mf.Info().Source != SourceFile {
		t.Fatalf("expired file certificate: %v %+v", err, mf)
	}
	if err := mf.RenewIfNeeded(ctx); err != nil || mf.Info().Source != SourceFile {
		t.Fatalf("file certificate replaced: %v", err)
	}
}
