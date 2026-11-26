// Package pki derives the cluster certificate authority from the shared
// cluster key and issues short-lived node certificates. Every node and the
// witness derive the same CA key from the same secret, so there is no
// enrollment step: knowing the cluster key is what makes a cluster member.
// Peers authenticate each other with mutual TLS against this CA.
package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// MinKeyLength is the minimum length of the cluster key.
const MinKeyLength = 16

// CA is the cluster authority.
type CA struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	pool *x509.CertPool
}

// Derive builds the CA from the cluster key. The same key always gives the
// same CA key pair (and the same certificate).
func Derive(clusterKey string) (*CA, error) {
	if len(clusterKey) < MinKeyLength {
		return nil, fmt.Errorf("la clé de cluster doit faire au moins %d caractères (ex : openssl rand -base64 32)", MinKeyLength)
	}
	seed, err := hkdf.Key(sha256.New, []byte(clusterKey), []byte("leazone-cluster"), "ca-ed25519", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Leazone cluster CA"},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{key: key, cert: cert, pool: pool}, nil
}

// KEK derives the key that wraps the data encryption key in snapshots.
func KEK(clusterKey string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(clusterKey), []byte("leazone-cluster"), "dek-wrap", 32)
}

// Issue returns a fresh certificate for a node (or the witness), valid for
// both server and client authentication. It lives in memory only.
func (ca *CA) Issue(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// verify checks that the peer certificate is signed by the cluster CA. Peers
// are addressed by IP, so the identity is the CA signature, not a host name.
func (ca *CA) verify(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("pas de certificat de cluster")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: ca.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("certificat de cluster refusé (clé de cluster différente ?) : %w", err)
	}
	return nil
}

// ServerConfig requires and verifies a client certificate from the CA.
func (ca *CA) ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
	}
}

// ClientConfig presents our certificate and verifies the server against the
// CA (host name checks are replaced by the CA check, see verify).
func (ca *CA) ClientConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// The standard verification needs a host name; we verify the chain
		// ourselves in VerifyPeerCertificate instead (CA pinning).
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return ca.verify(raw)
		},
	}
}
