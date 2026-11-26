// Package auth implements accounts, passwords, MFA (passkeys, TOTP, recovery
// codes), sessions, API tokens, roles and brute-force protection.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost parameters. They are stored in each hash
// so they can be raised later without breaking existing passwords.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

// DefaultArgon2 follows current OWASP guidance with extra margin.
var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 4, KeyLen: 32}

// MinPasswordLength is enforced for every new password.
const MinPasswordLength = 12

// HashPassword returns a PHC formatted Argon2id hash.
func HashPassword(password string, p Argon2Params) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC Argon2id hash in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified when the user does not exist, so the response time
// does not reveal whether an account exists.
var dummyHash, _ = HashPassword("leazone-dummy-password", DefaultArgon2)

// CheckPasswordPolicy validates a new password.
func CheckPasswordPolicy(pw, username string) error {
	if len([]rune(pw)) < MinPasswordLength {
		return fmt.Errorf("le mot de passe doit contenir au moins %d caractères", MinPasswordLength)
	}
	if len(pw) > 1024 {
		return errors.New("le mot de passe est trop long")
	}
	if strings.EqualFold(pw, username) {
		return errors.New("le mot de passe ne doit pas être le nom d'utilisateur")
	}
	return nil
}
