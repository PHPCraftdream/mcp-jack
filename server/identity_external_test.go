package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	server "github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// externalIdentity is a package-external Identity implementation: exactly
// what fabricated values would look like to the accessor.
type externalIdentity struct {
	kid   string
	name  string
	admin bool
}

func (e externalIdentity) Kid() string  { return e.kid }
func (e externalIdentity) Name() string { return e.name }
func (e externalIdentity) Admin() bool  { return e.admin }

// fabricatingContext is a valid context.Context whose Value answers EVERY
// key query — including the SDK's own unexported key, should consumer code
// capture it — with a chosen value.
type fabricatingContext struct {
	context.Context
	val any
}

func (c fabricatingContext) Value(any) any { return c.val }

// aliceKeyForTest derives alice's Ed25519 key from the fixture keys.json.
func aliceKeyForTest(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys: %v", err)
	}
	for _, k := range keys.Keys {
		if k.Name == "alice" {
			seed, err := hex.DecodeString(k.SeedHex)
			if err != nil {
				t.Fatalf("hex.DecodeString(alice seed): %v", err)
			}
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	t.Fatal("no alice key in keys.json")
	return nil
}

// signedAliceRequest builds a forwarded tools/call request signed with key,
// exactly the way the internal tests sign one: a fresh 16-byte nonce (fixed
// bytes are fine — the verifier under test has a fresh nonce store), the
// fixture clock as timestamp.
func signedAliceRequest(t *testing.T, key ed25519.PrivateKey, body []byte) *http.Request {
	t.Helper()
	nonce := make([]byte, 16)
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonceB64 := jack.EncodeBase64URL(nonce)
	signing := jack.RequestSigningString("POST", "/mcp", "https://svc.example.test", kid, 1767225600, nonceB64, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	req.Header.Set("Jack-Auth", jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: 1767225600, Nonce: nonceB64, Sig: sig}))
	return req
}

// captureGenuineSnapshot drives one real authenticated forwarded request
// through the exported middleware and returns the SDK-origin identity view
// the wrapped handler read.
func captureGenuineSnapshot(t *testing.T) server.Identity {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("spec.LoadRegistry: %v", err)
	}
	st := server.NewMemoryState()
	if err := st.Update(func(e *server.StateEdit) error {
		for _, entry := range registry.Keys {
			e.PutKey(server.RegistryEntry{
				Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name,
				Admin:     entry.Admin != nil && *entry.Admin,
				NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
			})
		}
		return nil
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	v, err := server.NewVerifier(server.Config{
		Aud: "https://svc.example.test", State: st, Nonces: server.NewNonceStore(),
		Native: server.NewNativeTools(server.NativeOptions{}),
		Now:    func() int64 { return 1767225600 },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	var captured server.Identity
	h, err := server.NewHandler(server.HandlerConfig{Verifier: v, ServerKey: aliceKeyForTest(t)}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = server.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{}}}`)
	req := signedAliceRequest(t, aliceKeyForTest(t), body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || captured == nil {
		t.Fatalf("genuine snapshot capture failed: status %d, captured %v", rec.Code, captured)
	}
	return captured
}

// TestIdentityFromContextAbsent checks that a context the SDK never touched
// carries no identity.
func TestIdentityFromContextAbsent(t *testing.T) {
	id, ok := server.IdentityFromContext(context.Background())
	if ok {
		t.Fatalf("ok = true with identity %v, want false", id)
	}
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
}

// TestIdentityFromContextRejectsForeignKeys documents that only the SDK's
// unexported context key surfaces an identity: package-external code cannot
// inject one, not with a string key and not with an Identity value as the
// key itself (spec 02 section 3).
func TestIdentityFromContextRejectsForeignKeys(t *testing.T) {
	foreign := externalIdentity{kid: "k", name: "n", admin: true}
	ctx := context.WithValue(context.Background(), "jack-identity", foreign)
	if id, ok := server.IdentityFromContext(ctx); ok {
		t.Fatalf("identity %v injected via a string key, want none", id)
	}
	ctx2 := context.WithValue(context.Background(), foreign, foreign)
	if id, ok := server.IdentityFromContext(ctx2); ok {
		t.Fatalf("identity %v injected via an Identity key, want none", id)
	}
}

// TestIdentityFromContextRejectsFabricatedImplementations is the provenance
// control (spec 02 section 3): a custom context returning a consumer-built
// Identity — fabricated values, or nil — must not obtain ok=true from the
// public accessor, and the accessor must return no view at all.
func TestIdentityFromContextRejectsFabricatedImplementations(t *testing.T) {
	ctx := fabricatingContext{Context: context.Background(), val: externalIdentity{kid: "fabricated", name: "fabricated", admin: true}}
	id, ok := server.IdentityFromContext(ctx)
	if ok {
		t.Fatalf("fabricated identity %v recognized by IdentityFromContext", id)
	}
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
	id, ok = server.IdentityFromContext(fabricatingContext{Context: context.Background(), val: nil})
	if ok {
		t.Fatal("nil context value recognized by IdentityFromContext")
	}
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
}

// TestIdentityFromContextRejectsReboundGenuineSnapshot proves the token/view
// split: even the unaltered SDK-origin view a handler legitimately received
// is not accepted when re-bound into a custom context.Value implementation,
// because only the SDK-internal identityToken stored by the middleware is
// recognized — the view consumers hold is not storable (spec 02 section 3).
func TestIdentityFromContextRejectsReboundGenuineSnapshot(t *testing.T) {
	genuine := captureGenuineSnapshot(t)
	ctx := fabricatingContext{Context: context.Background(), val: genuine}
	id, ok := server.IdentityFromContext(ctx)
	if ok {
		t.Fatalf("re-bound genuine snapshot %v recognized by IdentityFromContext", id)
	}
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
}

// TestIdentityFromContextRejectsAlteredCopies covers the alteration path:
// there is no way to alter an SDK snapshot (unexported fields, read-only
// methods), so the closest external stand-in is a consumer implementation
// mirroring the genuine snapshot's kid and name with Admin forced true. The
// accessor must reject it even though the readable values match a verified
// identity (spec 02 section 3).
func TestIdentityFromContextRejectsAlteredCopies(t *testing.T) {
	genuine := captureGenuineSnapshot(t)
	altered := externalIdentity{kid: genuine.Kid(), name: genuine.Name(), admin: true}
	ctx := fabricatingContext{Context: context.Background(), val: altered}
	id, ok := server.IdentityFromContext(ctx)
	if ok {
		t.Fatalf("altered copy %v recognized by IdentityFromContext", id)
	}
	if id != nil {
		t.Fatalf("identity = %v, want nil", id)
	}
}
