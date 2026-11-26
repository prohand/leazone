package auth

import (
	"crypto/rand"
	"strings"
)

// RecoveryCodeCount is the number of codes generated at once.
const RecoveryCodeCount = 10

// Crockford-like alphabet without ambiguous characters (0/O, 1/I/L, U).
const recoveryAlphabet = "abcdefghjkmnpqrstvwxyz23456789"

// NewRecoveryCodes returns RecoveryCodeCount codes like "k3f9q-2mx7p"
// (about 49 bits of entropy each).
func NewRecoveryCodes() []string {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		var sb strings.Builder
		for j := 0; j < 10; j++ {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[randIndex(len(recoveryAlphabet))])
		}
		codes[i] = sb.String()
	}
	return codes
}

// NormalizeRecoveryCode removes separators and spaces and lowercases.
func NormalizeRecoveryCode(c string) string {
	c = strings.ToLower(c)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, c)
}

func randIndex(n int) int {
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if int(b[0]) < 256-256%n {
			return int(b[0]) % n
		}
	}
}
