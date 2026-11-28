// Package pki derives the cluster keys from the shared cluster key and issues
// short-lived certificates. There is no enrollment step: knowing the cluster
// key is what makes a cluster node.
//
// Key schedule (protocol 2):
//
//	root        = Argon2id(cluster key, fixed domain salt)      slow, once per process
//	node CA     = Ed25519(HKDF(root, "node-ca-ed25519"))      nodes only (port 7443)
//	KEK         = HKDF(root, "dek-wrap")                      wraps the data key in snapshots
//	witness key = HKDF(root, "witness")                       given to the witness
//	witness CA  = Ed25519(HKDF(witness key, "witness-ca-ed25519"))
//
// The witness only holds the witness key: it can derive the witness CA but
// nothing on the node side (one-way derivation). Nodes derive both, so they
// talk to the witness with a certificate of the witness CA, and to each other
// with a certificate of the node CA. Certificates carry the identity in their
// common name: "node:<id>" for a node, "witness" for the witness, and every
// TLS configuration checks it.
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
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// MinKeyLength is the minimum length of the cluster key.
const MinKeyLength = 16

// Argon2id parameters of the root key. 64 MiB and 3 passes take well under
// a second on a small host (Raspberry Pi) and are computed once per process.
const (
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4
	argonSalt    = "leazone-cluster-key/v2"
)

// Names used in certificates.
const (
	// NodePrefix starts the common name of a node certificate ("node:<id>").
	NodePrefix = "node:"
	// WitnessName is the common name of the witness certificate.
	WitnessName = "witness"
	// witnessKeyPrefix marks a witness key, so it is not confused with a
	// cluster key.
	witnessKeyPrefix = "lzw1-"
)

// Keys are the secrets derived from the cluster key.
type Keys struct {
	root []byte
}

var (
	rootMu    sync.Mutex
	rootCache = map[string][]byte{}
)

// DeriveKeys runs the slow derivation of the cluster key (memoized: the
// same key is stretched once per process).
func DeriveKeys(clusterKey string) (*Keys, error) {
	if len(clusterKey) < MinKeyLength {
		return nil, fmt.Errorf("la clé de cluster doit faire au moins %d caractères (générez-la avec : leazone cluster gen-key)", MinKeyLength)
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	root, ok := rootCache[clusterKey]
	if !ok {
		root = argon2.IDKey([]byte(clusterKey), []byte(argonSalt), argonTime, argonMemKiB, argonThreads, 32)
		rootCache[clusterKey] = root
	}
	return &Keys{root: root}, nil
}

// WeakKey reports whether a cluster key looks too weak to resist an offline
// guessing attack: neither 32 random bytes in base64 nor 32 characters long.
func WeakKey(clusterKey string) bool {
	if len(clusterKey) >= 32 {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(clusterKey); err == nil && len(b) >= 32 {
			return false
		}
	}
	return true
}

// GenerateClusterKey returns a new random cluster key (32 bytes, base64).
func GenerateClusterKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (k *Keys) sub(info string, n int) []byte {
	b, err := hkdf.Key(sha256.New, k.root, []byte("leazone-cluster"), info, n)
	if err != nil {
		panic(err) // only fails for n too large
	}
	return b
}

// NodeCA is the authority of the nodes (port 7443 between nodes).
func (k *Keys) NodeCA() (*CA, error) {
	return newCA(k.sub("node-ca-ed25519", ed25519.SeedSize), "Leazone cluster CA")
}

// KEK derives the key that wraps the data encryption key in snapshots.
func (k *Keys) KEK() []byte { return k.sub("dek-wrap", 32) }

// WitnessKey is the secret given to the witness, printable.
func (k *Keys) WitnessKey() string {
	return witnessKeyPrefix + base64.RawURLEncoding.EncodeToString(k.sub("witness", 32))
}

// WitnessCA is the witness authority (also derived by the nodes).
func (k *Keys) WitnessCA() (*CA, error) { return WitnessCA(k.WitnessKey()) }

// WitnessCA derives the witness authority from a witness key.
func WitnessCA(witnessKey string) (*CA, error) {
	raw, err := parseWitnessKey(witnessKey)
	if err != nil {
		return nil, err
	}
	seed, err := hkdf.Key(sha256.New, raw, []byte("leazone-witness"), "witness-ca-ed25519", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return newCA(seed, "Leazone witness CA")
}

// IsWitnessKey reports whether s has the format of a witness key.
func IsWitnessKey(s string) bool {
	_, err := parseWitnessKey(s)
	return err == nil
}

func parseWitnessKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, witnessKeyPrefix) {
		return nil, errors.New("ce n'est pas une clé témoin (obtenez-la sur un nœud avec : leazone cluster witness-key)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, witnessKeyPrefix))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("clé témoin invalide (obtenez-la sur un nœud avec : leazone cluster witness-key)")
	}
	return raw, nil
}

// CA is a certificate authority derived from a secret.
type CA struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	pool *x509.CertPool
}

// newCA builds the CA from a seed. The same seed always gives the same CA
// key pair (and the same certificate).
func newCA(seed []byte, name string) (*CA, error) {
	key := ed25519.NewKeyFromSeed(seed)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
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

// Issue returns a fresh certificate (common name: the identity), valid for
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

// Allow decides whether a certificate common name is accepted.
type Allow func(cn string) bool

// AnyNode accepts a node certificate ("node:<id>").
func AnyNode(cn string) bool { return strings.HasPrefix(cn, NodePrefix) && len(cn) > len(NodePrefix) }

// OnlyWitness accepts the witness certificate.
func OnlyWitness(cn string) bool { return cn == WitnessName }

// MismatchError is returned when the peer's certificate is not one of ours
// (another cluster key, another protocol version, or not the expected role).
type MismatchError struct{ Err error }

func (e *MismatchError) Error() string {
	return "certificat de cluster refusé (clé de cluster ou version de protocole différente ?) : " + e.Err.Error()
}

func (e *MismatchError) Unwrap() error { return e.Err }

// verify checks that the peer certificate is signed by this CA and carries
// an accepted identity. Peers are addressed by IP, so the identity is the
// CA signature and the common name, not a host name.
func (ca *CA) verify(rawCerts [][]byte, allow Allow) error {
	if len(rawCerts) == 0 {
		return &MismatchError{errors.New("pas de certificat")}
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return &MismatchError{err}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return &MismatchError{err}
	}
	if allow != nil && !allow(cert.Subject.CommonName) {
		return &MismatchError{fmt.Errorf("identité %q non autorisée ici", cert.Subject.CommonName)}
	}
	return nil
}

// ServerConfig requires a client certificate from this CA whose common
// name passes allow.
func (ca *CA) ServerConfig(cert tls.Certificate, allow Allow) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return ca.verify(raw, allow)
		},
	}
}

// ClientConfig presents our certificate and verifies the server against the
// CA and allow (host name checks are replaced by these, see verify).
func (ca *CA) ClientConfig(cert tls.Certificate, allow Allow) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// The standard verification needs a host name; we verify the chain
		// ourselves in VerifyPeerCertificate instead (CA pinning).
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return ca.verify(raw, allow)
		},
	}
}

// PeerNodeID returns the node ID of the client certificate of r ("node:<id>").
func PeerNodeID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if !AnyNode(cn) {
		return "", false
	}
	return strings.TrimPrefix(cn, NodePrefix), true
}

// IsMismatch reports whether err shows that the other side speaks TLS but
// with certificates of another cluster key or protocol version: either we
// refused its certificate, or it refused ours. Such a peer is running, even
// though nothing can be exchanged with it.
func IsMismatch(err error) bool {
	if err == nil {
		return false
	}
	var me *MismatchError
	if errors.As(err, &me) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		// A TLS alert from the server (e.g. "bad certificate", "unknown
		// certificate authority") after it checked our certificate.
		return strings.Contains(op.Err.Error(), "certificate")
	}
	return false
}
