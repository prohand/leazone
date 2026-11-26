// Package secrets encrypts sensitive values at rest (TOTP secrets, private
// keys...) with a data encryption key (DEK). The DEK itself is stored in the
// database, wrapped by a key encryption key (KEK): a local master key file on
// a single node, or a key derived from the cluster key in HA (phase 4).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const prefix = "v1:"

// Box encrypts and decrypts values with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
	key  []byte
}

// NewBox builds a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secrets: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, key: append([]byte(nil), key...)}, nil
}

// Seal encrypts plaintext. aad binds the ciphertext to its context (for
// example the table and row id) so it cannot be moved to another row.
func (b *Box) Seal(plaintext []byte, aad string) string {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := b.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return prefix + base64.RawStdEncoding.EncodeToString(ct)
}

// Open decrypts a value produced by Seal with the same aad.
func (b *Box) Open(sealed, aad string) ([]byte, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return nil, errors.New("secrets: unknown format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(sealed[len(prefix):])
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("secrets: ciphertext too short")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("secrets: decryption failed (wrong key or corrupted data)")
	}
	return pt, nil
}

// SubKey derives an independent 32-byte key for a given purpose (HMAC of
// recovery codes, cookies...). Derived keys are identical on every node that
// shares the same DEK.
func (b *Box) SubKey(purpose string) []byte {
	k, err := hkdf.Key(sha256.New, b.key, nil, "leazone:"+purpose, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// MAC returns hex-free base64 HMAC-SHA256 of msg with the purpose sub-key.
func (b *Box) MAC(purpose, msg string) string {
	m := hmac.New(sha256.New, b.SubKey(purpose))
	m.Write([]byte(msg))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

// LoadOrCreateMasterKey reads the 32-byte local master key, creating it with
// 0600 permissions on first start.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: master key must be 32 bytes, found %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// NewDEK returns a fresh random data key.
func NewDEK() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}
