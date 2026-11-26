// Package ids generates random identifiers and secrets.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// New returns a random 128-bit identifier as 26 lowercase base32 chars.
func New() string { return Random(16) }

// Random returns n random bytes encoded in lowercase base32.
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return enc.EncodeToString(b)
}

// Password returns a random password of length n that is easy to type
// (no ambiguous characters).
func Password(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for _, c := range b {
		// 256 % 54 bias is negligible for passwords of 20+ chars, but we
		// reject the biased tail anyway.
		for int(c) >= 256-256%len(alphabet) {
			var one [1]byte
			_, _ = rand.Read(one[:])
			c = one[0]
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}
