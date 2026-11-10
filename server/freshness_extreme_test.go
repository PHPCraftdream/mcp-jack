package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

func TestRequestFreshnessExtremeClockDoesNotWrap(t *testing.T) {
	const minimum int64 = -1 << 63
	const maximum int64 = 1<<63 - 1
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := NewMemoryState()
	if err := state.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "public-fixture"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		now    int64
		ts     int64
		accept bool
	}{
		{minimum, 0, false},
		{minimum + 1, 1, false},
		{minimum + 999999999999, 999999999999, false},
		{minimum + 1, 0, false},
		{maximum, 0, false},
		{-31, 0, false},
		{31, 0, false},
		{-30, 0, true},
		{0, 0, true},
		{30, 0, true},
	}
	for _, sample := range cases {
		t.Run(fmt.Sprintf("now%d-ts%d", sample.now, sample.ts), func(t *testing.T) {
			nonces := NewNonceStore()
			verifier, err := NewVerifier(Config{Aud: "svc", State: state, Nonces: nonces, Window: 30, Now: func() int64 { return sample.now }})
			if err != nil {
				t.Fatal(err)
			}
			auth := jack.RequestAuth{Kid: kid, TS: sample.ts, Nonce: jack.EncodeBase64URL(make([]byte, 16))}
			message := jack.RequestSigningString("GET", "/mcp", "svc", kid, auth.TS, auth.Nonce, nil)
			auth.Sig = jack.EncodeBase64URL(ed25519.Sign(key, []byte(message)))
			request := Request{Method: "GET", Target: "/mcp", AuthValues: []string{jack.FormatRequestAuth(auth)}}
			result := verifier.Verify(request)
			defer result.Done()
			if sample.accept {
				if !result.Accepted || !result.NonceRecorded || nonces.Len() != 1 {
					t.Fatalf("inclusive boundary rejected: %+v", result)
				}
			} else if result.Accepted || result.HTTPStatus != 401 || result.Code != jack.CodeTimestampOutOfWindow || result.NonceRecorded || nonces.Len() != 0 {
				t.Fatalf("stale request accepted or nonce store touched: %+v", result)
			}
		})
	}
}
