package secrets

import (
	"testing"
	"time"
)

// While a key replacement is pending, Seal waits and then uses the new key.
func TestBeginReplaceBlocksSeal(t *testing.T) {
	b, _ := NewBox(NewDEK())
	newKey := NewDEK()
	swap := b.BeginReplace()
	sealed := make(chan string)
	go func() { sealed <- b.Seal([]byte("x"), "aad") }()
	select {
	case <-sealed:
		t.Fatal("Seal did not wait for the new key")
	case <-time.After(50 * time.Millisecond):
	}
	if err := swap(newKey); err != nil {
		t.Fatal(err)
	}
	nb, _ := NewBox(newKey)
	if _, err := nb.Open(<-sealed, "aad"); err != nil {
		t.Fatal("sealed with the old key")
	}
	// nil keeps the key.
	b.BeginReplace()(nil)
	if _, err := nb.Open(b.Seal([]byte("y"), "aad"), "aad"); err != nil {
		t.Fatal(err)
	}
}
