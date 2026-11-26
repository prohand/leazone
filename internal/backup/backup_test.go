package backup

import (
	"encoding/base64"
	"errors"
	"testing"
)

// KDF parameters come from the file: absurd costs are refused before any
// Argon2 computation (also for a dry run).
func TestKDFBounds(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString(make([]byte, 16))
	ok := KDF{Name: "argon2id", Time: 1, MemoryKiB: 64, Threads: 1, Salt: salt}
	if _, err := deriveKey("password", ok); err != nil {
		t.Fatal(err)
	}
	for _, k := range []KDF{
		{Name: "argon2id", Time: 1, MemoryKiB: 4 << 20, Threads: 1, Salt: salt},
		{Name: "argon2id", Time: 1, MemoryKiB: 64, Threads: 255, Salt: salt},
		{Name: "argon2id", Time: 20, MemoryKiB: 64, Threads: 1, Salt: salt},
	} {
		if _, err := deriveKey("password", k); !errors.Is(err, ErrFormat) {
			t.Fatalf("%+v accepted", k)
		}
	}
}
