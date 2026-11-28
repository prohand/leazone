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
	"sync"
)

const prefix = "v1:"

// Box encrypts and decrypts values with AES-256-GCM. Its key can be
// replaced at runtime (a node joining a cluster adopts the cluster's key).
type Box struct {
	mu   sync.RWMutex
	aead cipher.AEAD
	key  []byte

	hookMu sync.Mutex
	hooks  []func(old, new []byte)
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

// OnReplace registers fn, called after each change of the key with copies
// of the old and the new key, outside the Box lock (fn may use the Box).
// Data derived from the key (the audit chain keyed with SubKey...) can keep
// what it needs of the old key.
func (b *Box) OnReplace(fn func(old, new []byte)) {
	b.hookMu.Lock()
	b.hooks = append(b.hooks, fn)
	b.hookMu.Unlock()
}

func (b *Box) replaced(old, new []byte) {
	if hmac.Equal(old, new) {
		return
	}
	b.hookMu.Lock()
	hooks := append([]func(old, new []byte){}, b.hooks...)
	b.hookMu.Unlock()
	for _, fn := range hooks {
		fn(append([]byte(nil), old...), append([]byte(nil), new...))
	}
}

// Replace swaps the key.
func (b *Box) Replace(key []byte) error {
	nb, err := NewBox(key)
	if err != nil {
		return err
	}
	b.mu.Lock()
	old := b.key
	b.aead, b.key = nb.aead, nb.key
	b.mu.Unlock()
	b.replaced(old, nb.key)
	return nil
}

// BeginReplace blocks Seal, Open and the derived keys until the returned
// function is called with the new key (nil keeps the current one). Use it
// to swap the key right when the data encrypted with the new key is
// committed, so no value is sealed with the old key in between.
func (b *Box) BeginReplace() func(key []byte) error {
	b.mu.Lock()
	var once sync.Once
	return func(key []byte) error {
		var err error
		var old, cur []byte
		once.Do(func() {
			defer b.mu.Unlock()
			if key == nil {
				return
			}
			var nb *Box
			if nb, err = NewBox(key); err == nil {
				old = b.key
				b.aead, b.key = nb.aead, nb.key
				cur = nb.key
			}
		})
		if cur != nil {
			b.replaced(old, cur)
		}
		return err
	}
}

// Key returns a copy of the key (to wrap it for replication).
func (b *Box) Key() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]byte(nil), b.key...)
}

// Seal encrypts plaintext. aad binds the ciphertext to its context (for
// example the table and row id) so it cannot be moved to another row.
func (b *Box) Seal(plaintext []byte, aad string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := b.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return prefix + base64.RawStdEncoding.EncodeToString(ct)
}

// Open decrypts a value produced by Seal with the same aad.
func (b *Box) Open(sealed, aad string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
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
	b.mu.RLock()
	defer b.mu.RUnlock()
	return DeriveKey(b.key, purpose)
}

// DeriveKey is SubKey for a raw data key (for example the old key given to
// an OnReplace hook).
func DeriveKey(key []byte, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, key, nil, "leazone:"+purpose, 32)
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
