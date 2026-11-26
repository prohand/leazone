// Package tlsmgr provides the HTTPS certificate of the UI/API: a certificate
// dropped in <data>/tls/, one imported from the UI, or a self-signed one
// generated on first start (installation only) and renewed automatically.
//
// An expired certificate never prevents the service from starting: a
// self-signed one is regenerated, a file or imported one is served with a
// warning (DNS and DHCP must run even if the web UI certificate lapsed).
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
	names   []string // names of the self-signed certificate

	mu   sync.RWMutex
	cert *tls.Certificate
	info Info
}

// New loads the certificate, generating a self-signed one if needed.
func New(ctx context.Context, db *store.DB, box *secrets.Box, log *slog.Logger, dataDir string, names []string) (*Manager, error) {
	m := &Manager{db: db, box: box, log: log, dataDir: dataDir, names: names}
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
		if err := m.load(string(c), string(k), SourceFile); err != nil {
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
		if err := m.load(certPEM, string(key), source); err != nil {
			return nil, err
		}
		// Renew an expired or expiring self-signed certificate automatically.
		return m, m.RenewIfNeeded(ctx)
	case errors.Is(err, sql.ErrNoRows):
		return m, m.generateSelfSigned(ctx, names)
	default:
		return nil, err
	}
}

// renewBefore is how long before expiry a self-signed certificate is renewed.
const renewBefore = 30 * 24 * time.Hour

// RenewIfNeeded regenerates the self-signed certificate when it expires in
// less than 30 days (or already expired). File and imported certificates are
// left alone (only a warning is logged when they expire soon).
func (m *Manager) RenewIfNeeded(ctx context.Context) error {
	info := m.Info()
	left := time.Until(info.NotAfter)
	if info.Source != SourceSelfSigned {
		if left < renewBefore {
			m.log.Warn("HTTPS certificate expires soon or has expired: import a new one",
				"source", info.Source, "notAfter", info.NotAfter.Format(time.DateOnly))
		}
		return nil
	}
	if left >= renewBefore {
		return nil
	}
	m.log.Info("renewing the self-signed certificate", "notAfter", info.NotAfter.Format(time.DateOnly))
	return m.generateSelfSigned(ctx, m.names)
}

// Run checks the certificate twice a day until ctx is done and renews the
// self-signed one before it expires. beginWrite (optional) tells whether this
// node may change the replicated configuration: in a cluster only the
// primary renews, the other node picks the new certificate up with Reload.
func (m *Manager) Run(ctx context.Context, beginWrite func() (done func(), err error)) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.renewTick(ctx, beginWrite)
	}
}

// renewTick renews the certificate when needed, only where config may be
// written (cluster primary), holding that right until the change is stored.
func (m *Manager) renewTick(ctx context.Context, beginWrite func() (func(), error)) {
	if beginWrite != nil {
		done, err := beginWrite()
		if err != nil {
			return
		}
		defer done()
	}
	if err := m.RenewIfNeeded(ctx); err != nil {
		m.log.Warn("certificate renewal failed", "err", err)
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

// Reload re-reads the active certificate from the database (after
// replication: both nodes serve the same certificate). Certificates given
// as files in <data>/tls are kept.
func (m *Manager) Reload(ctx context.Context) error {
	if m.Info().Source == SourceFile {
		return nil
	}
	var id, source, certPEM, keyEnc string
	err := m.db.QueryRowContext(ctx, `SELECT id, source, cert_pem, key_enc FROM certificates WHERE active = 1`).
		Scan(&id, &source, &certPEM, &keyEnc)
	if err != nil {
		return nil // keep the current one
	}
	if m.Info().Fingerprint != "" {
		cur := m.Info()
		tmp := &Manager{}
		key, err := m.box.Open(keyEnc, "cert:"+id)
		if err != nil {
			return err
		}
		if err := tmp.load(certPEM, string(key), source); err != nil {
			return err
		}
		if tmp.info.Fingerprint == cur.Fingerprint {
			return nil
		}
		m.mu.Lock()
		m.cert, m.info = tmp.cert, tmp.info
		m.mu.Unlock()
		m.log.Info("certificate updated from the cluster", "subject", tmp.info.Subject)
	}
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

// set parses and checks a new certificate/key pair (an expired one is
// refused), then makes it active in memory.
func (m *Manager) set(certPEM, keyPEM, source string) error {
	return m.activate(certPEM, keyPEM, source, false)
}

// load is set for a certificate already in use (file, database): an expired
// certificate is served with a warning rather than stopping the service.
func (m *Manager) load(certPEM, keyPEM, source string) error {
	return m.activate(certPEM, keyPEM, source, true)
}

func (m *Manager) activate(certPEM, keyPEM, source string, allowExpired bool) error {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("certificat ou clé invalide : %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		if !allowExpired {
			return fmt.Errorf("certificat expiré le %s", leaf.NotAfter.Format(time.DateOnly))
		}
		if m.log != nil && source != SourceSelfSigned {
			m.log.Warn("HTTPS certificate has expired: browsers will refuse it, import a new one",
				"source", source, "notAfter", leaf.NotAfter.Format(time.DateOnly))
		}
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
