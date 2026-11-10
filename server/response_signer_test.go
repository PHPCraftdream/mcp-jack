package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
)

type testResponseSigner struct {
	public      []byte
	panicPublic bool
	sign        func([]byte) ([]byte, error)
}

func (signer *testResponseSigner) PublicKey() []byte {
	if signer.panicPublic {
		panic("private provider detail")
	}
	return signer.public
}

func (signer *testResponseSigner) Sign(message []byte) ([]byte, error) { return signer.sign(message) }

func responseFixtureKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mcp-jack public response provider fixture " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func TestOpaqueResponseSignerCapturesPublicIdentityWithoutPrivateExport(t *testing.T) {
	key := responseFixtureKey("server")
	public := key.Public().(ed25519.PublicKey)
	calls := 0
	provider := &testResponseSigner{public: public, sign: func(message []byte) ([]byte, error) {
		calls++
		return ed25519.Sign(key, message), nil
	}}
	verifier, err := NewVerifier(Config{Aud: "test", State: NewMemoryState(), Nonces: NewNonceStore()})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := NewHandler(HandlerConfig{Verifier: verifier, ResponseSigner: provider}, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	handler := wrapped.(*handler)
	if len(handler.key) != 0 || handler.signer == nil || calls != 0 {
		t.Fatal("constructor requested private key or signed prematurely")
	}
	clear(public)
	if _, err := responseSignature(provider, handler.public, "exact public response message"); err != nil || calls != 1 {
		t.Fatalf("provider-owned public buffer changed captured identity: %v", err)
	}
	if _, err := NewHandler(HandlerConfig{Verifier: verifier, ServerKey: key, ResponseSigner: provider}, http.NotFoundHandler()); err == nil {
		t.Fatal("ambiguous signing profiles accepted")
	}
}

func TestOpaqueResponseSignerRejectsBadPublicIdentityAndProviderPanic(t *testing.T) {
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	for _, provider := range []*testResponseSigner{
		nil, {public: nil}, {public: make([]byte, 31)}, {public: identity}, {panicPublic: true},
	} {
		if public, err := responsePublicKey(provider); !errors.Is(err, errResponseSigner) || public != nil {
			t.Fatalf("bad public identity accepted: %v", err)
		}
	}
}

func TestOpaqueResponseSignerValidatesExactMessageKeyAndProviderOutputWithoutRetry(t *testing.T) {
	key := responseFixtureKey("server")
	other := responseFixtureKey("other")
	public := key.Public().(ed25519.PublicKey)
	for name, sign := range map[string]func([]byte) ([]byte, error){
		"error":     func([]byte) ([]byte, error) { return nil, errors.New("private provider detail") },
		"panic":     func([]byte) ([]byte, error) { panic("private provider detail") },
		"nil-panic": func([]byte) ([]byte, error) { panic(nil) },
		"short":     func([]byte) ([]byte, error) { return make([]byte, 63), nil },
		"wrong-key": func(message []byte) ([]byte, error) { return ed25519.Sign(other, message), nil },
		"mutated-message": func(message []byte) ([]byte, error) {
			message[0] ^= 1
			return ed25519.Sign(key, message), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			provider := &testResponseSigner{public: public, sign: func(message []byte) ([]byte, error) {
				calls++
				return sign(message)
			}}
			signature, err := responseSignature(provider, public, "exact immutable message")
			if !errors.Is(err, errResponseSigner) || signature != nil || calls != 1 || bytes.Contains([]byte(err.Error()), []byte("private provider detail")) {
				t.Fatalf("bad provider output accepted, leaked or retried: %v calls=%d", err, calls)
			}
		})
	}
}
