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

// OnReplace hooks get the old and new keys after a real change only, and
// DeriveKey on the old key gives the old SubKey.
func TestOnReplaceHook(t *testing.T) {
	k1, k2, k3 := NewDEK(), NewDEK(), NewDEK()
	b, _ := NewBox(k1)
	oldSub := b.SubKey("p")
	var calls [][2][]byte
	b.OnReplace(func(o, n []byte) {
		_ = b.SubKey("p") // the Box is usable from the hook
		calls = append(calls, [2][]byte{o, n})
	})
	if err := b.Replace(k1); err != nil { // same key: no call
		t.Fatal(err)
	}
	if err := b.Replace(k2); err != nil {
		t.Fatal(err)
	}
	if err := b.BeginReplace()(k3); err != nil {
		t.Fatal(err)
	}
	_ = b.BeginReplace()(nil)
	if len(calls) != 2 || string(calls[0][0]) != string(k1) || string(calls[0][1]) != string(k2) ||
		string(calls[1][0]) != string(k2) || string(calls[1][1]) != string(k3) {
		t.Fatalf("hook calls: %d", len(calls))
	}
	if string(DeriveKey(k1, "p")) != string(oldSub) {
		t.Fatal("DeriveKey differs from SubKey")
	}
}
