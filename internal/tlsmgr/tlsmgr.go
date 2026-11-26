// Package tlsmgr provides the HTTPS certificate of the UI/API: a certificate
// dropped in <data>/tls/, one imported from the UI, or a self-signed one
// generated on first start (installation only).
package tlsmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prohand/leazone/internal/ids"
	"github.com/prohand/leazone/internal/secrets"
	"github.com/prohand/leazone/internal/store"
)

// Sources of the active certificate.
const (
	SourceSelfSigned = "selfsigned"
	SourceImport     = "import"
	SourceFile       = "file"
)

// Info describes the active certificate.
type Info struct {
	Source      string    `json:"source"`
	Subject     string    `json:"subject"`
	DNSNames    []string  `json:"dnsNames"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprintSha256"`
}

// Manager serves and replaces the certificate at runtime.
type Manager struct {
	db      *store.DB
	box     *secrets.Box
	log     *slog.Logger
	dataDir string

	mu   sync.RWMutex
	cert *tls.Certificate
	info Info
}

// New loads the certificate, generating a self-signed one if needed.
func New(ctx context.Context, db *store.DB, box *secrets.Box, log *slog.Logger, dataDir string, names []string) (*Manager, error) {
	m := &Manager{db: db, box: box, log: log, dataDir: dataDir}
	certFile := filepath.Join(dataDir, "tls", "cert.pem")
	keyFile := filepath.Join(dataDir, "tls", "key.pem")
	if _, err := os.Stat(certFile); err == nil {
		c, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		k, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("%s found but %s unreadable: %w", certFile, keyFile, err)
		}
		if err := m.set(string(c), string(k), SourceFile); err != nil {
			return nil, fmt.Errorf("%s: %w", certFile, err)
		}
		log.Info("using certificate from file", "file", certFile, "notAfter", m.info.NotAfter)
		return m, nil
	}

	var id, source, certPEM, keyEnc string
	err := db.QueryRowContext(ctx, `SELECT id, source, cert_pem, key_enc FROM certificates WHERE active = 1`).
		Scan(&id, &source, &certPEM, &keyEnc)
	switch {
	case err == nil:
		key, err := box.Open(keyEnc, "cert:"+id)
		if err != nil {
			return nil, fmt.Errorf("certificate key: %w", err)
		}
		if err := m.set(certPEM, string(key), source); err != nil {
			return nil, err
		}
		// Renew an expiring self-signed certificate automatically.
		if source == SourceSelfSigned && time.Until(m.info.NotAfter) < 30*24*time.Hour {
			return m, m.generateSelfSigned(ctx, names)
		}
		return m, nil
	case errors.Is(err, sql.ErrNoRows):
		return m, m.generateSelfSigned(ctx, names)
	default:
		return nil, err
	}
}

func (m *Manager) generateSelfSigned(ctx context.Context, names []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Leazone (auto-signé)", Organization: []string{"Leazone"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(397 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, n := range append(names, "localhost") {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	tpl.IPAddresses = append(tpl.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	if err := m.store(ctx, certPEM, keyPEM, SourceSelfSigned); err != nil {
		return err
	}
	m.log.Warn("self-signed certificate generated: import a trusted certificate before production (passkeys need it)",
		"names", tpl.DNSNames, "notAfter", tpl.NotAfter.Format(time.DateOnly))
	return nil
}

// Import validates and activates a PEM certificate chain and private key.
func (m *Manager) Import(ctx context.Context, certPEM, keyPEM string) (Info, error) {
	if m.Info().Source == SourceFile {
		return Info{}, errors.New("le certificat est fourni par fichier dans /data/tls : remplacez les fichiers puis redémarrez")
	}
	if err := m.store(ctx, certPEM, keyPEM, SourceImport); err != nil {
		return Info{}, err
	}
	return m.Info(), nil
}

func (m *Manager) store(ctx context.Context, certPEM, keyPEM, source string) error {
	// Validate first, without touching the active certificate.
	tmp := &Manager{}
	if err := tmp.set(certPEM, keyPEM, source); err != nil {
		return err
	}
	id := ids.New()
	enc := m.box.Seal([]byte(keyPEM), "cert:"+id)
	err := m.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET active = 0`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE active = 0 AND source = ?`, SourceSelfSigned); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO certificates(id, source, active, cert_pem, key_enc, not_after, created_at)
			VALUES (?, ?, 1, ?, ?, ?, ?)`, id, source, certPEM, enc, tmp.info.NotAfter.UnixMilli(), time.Now().UnixMilli())
		return err
	})
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cert, m.info = tmp.cert, tmp.info
	m.mu.Unlock()
	return nil
}

// set parses and checks a certificate/key pair, then makes it active in memory.
func (m *Manager) set(certPEM, keyPEM, source string) error {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("certificat ou clé invalide : %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("certificat expiré le %s", leaf.NotAfter.Format(time.DateOnly))
	}
	if err := checkKeyStrength(leaf.PublicKey); err != nil {
		return err
	}
	pair.Leaf = leaf
	sum := sha256.Sum256(leaf.Raw)
	info := Info{Source: source, Subject: leaf.Subject.String(), DNSNames: append([]string{}, leaf.DNSNames...),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: colonHex(sum[:])}
	for _, ip := range leaf.IPAddresses {
		info.DNSNames = append(info.DNSNames, ip.String())
	}
	m.mu.Lock()
	m.cert, m.info = &pair, info
	m.mu.Unlock()
	return nil
}

func checkKeyStrength(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("clé RSA trop courte (2048 bits minimum)")
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errors.New("type de clé non supporté")
	}
	return nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// GetCertificate is used by tls.Config.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert, nil
}

// Info returns a description of the active certificate.
func (m *Manager) Info() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.info
}

// SelfSigned reports whether the active certificate is the generated one.
func (m *Manager) SelfSigned() bool { return m.Info().Source == SourceSelfSigned }

// TLSConfig returns a hardened server configuration.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}
