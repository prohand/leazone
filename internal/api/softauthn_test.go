package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthenticator is a minimal software FIDO2 authenticator (ES256, "none"
// attestation, user verification always performed) used to test the real
// WebAuthn code paths end to end.
type softAuthenticator struct {
	t      *testing.T
	origin string
	rpID   string
	creds  map[string]*softCred // by base64url credential id
}

type softCred struct {
	id         []byte
	key        *ecdsa.PrivateKey
	userHandle []byte
	count      uint32
}

func newSoftAuthenticator(t *testing.T, origin, rpID string) *softAuthenticator {
	return &softAuthenticator{t: t, origin: origin, rpID: rpID, creds: map[string]*softCred{}}
}

var b64 = base64.RawURLEncoding

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) authData(flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], count)
	out = append(out, c[:]...)
	return append(out, attested...)
}

// create answers navigator.credentials.create() options ({publicKey: ...}).
func (a *softAuthenticator) create(options json.RawMessage) json.RawMessage {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		a.t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	uh, _ := b64.DecodeString(o.PublicKey.User.ID)
	cred := &softCred{id: id, key: key, userHandle: uh}
	a.creds[b64.EncodeToString(id)] = cred

	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	attested := make([]byte, 16) // AAGUID zero
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(id)))
	attested = append(attested, l[:]...)
	attested = append(attested, id...)
	attested = append(attested, cose...)
	ad := a.authData(0x01|0x04|0x40, 0, attested) // UP | UV | AT
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return out
}

// get answers navigator.credentials.get() options. With an empty allow list
// (discoverable login) it uses the first stored credential.
func (a *softAuthenticator) get(options json.RawMessage) json.RawMessage {
	var o struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		a.t.Fatal(err)
	}
	var cred *softCred
	for _, ac := range o.PublicKey.AllowCredentials {
		if c, ok := a.creds[ac.ID]; ok {
			cred = c
		}
	}
	if cred == nil && len(o.PublicKey.AllowCredentials) == 0 {
		for _, c := range a.creds {
			cred = c
			break
		}
	}
	if cred == nil {
		a.t.Fatal("soft authenticator: no matching credential")
	}
	cred.count++
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	ad := a.authData(0x01|0x04, cred.count, nil)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(cred.id), "rawId": b64.EncodeToString(cred.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(cred.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
	return out
}
