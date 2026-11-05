package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

const fixtureNow int64 = 1767225600
const fixtureAud = "https://svc.example.test"

// seedSignerByName returns the InMemorySigner derived from the named key of
// the spec keys.json ("alice", "newbie", ...).
func seedSignerByName(t *testing.T, name string) *InMemorySigner {
	t.Helper()
	kf, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys: %v", err)
	}
	for _, k := range kf.Keys {
		if k.Name == name {
			return seedSignerFromTestKey(t, k)
		}
	}
	t.Fatalf("keys.json has no key named %q", name)
	return nil
}

// seedSignerByKid is seedSignerByName keyed by kid instead of name.
func seedSignerByKid(t *testing.T, kid string) *InMemorySigner {
	t.Helper()
	kf, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys: %v", err)
	}
	for _, k := range kf.Keys {
		if k.Kid == kid {
			return seedSignerFromTestKey(t, k)
		}
	}
	t.Fatalf("keys.json has no key with kid %q", kid)
	return nil
}

// seedSignerFromTestKey derives an InMemorySigner from a spec.TestKey.
func seedSignerFromTestKey(t *testing.T, k spec.TestKey) *InMemorySigner {
	t.Helper()
	seed, err := hex.DecodeString(k.SeedHex)
	if err != nil {
		t.Fatalf("key %q: bad seed hex: %v", k.Name, err)
	}
	sig, err := NewInMemorySigner(seed)
	if err != nil {
		t.Fatalf("key %q: NewInMemorySigner: %v", k.Name, err)
	}
	return sig
}

// fixtureKeys loads keys.json once and returns the kid -> 32-byte public key
// map built from the derived signers, along with the raw TestKey slice.
func fixtureKeys(t *testing.T) (map[string][]byte, []spec.TestKey) {
	t.Helper()
	kf, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("spec.LoadKeys: %v", err)
	}
	keys := make(map[string][]byte, len(kf.Keys))
	for _, k := range kf.Keys {
		sig := seedSignerFromTestKey(t, k)
		keys[sig.KID()] = sig.PublicKey()
	}
	return keys, kf.Keys
}

// fixedClock returns a clock function returning time.Unix(unix, 0).
func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

// nonceQueueError reports nonce-source failures to the caller.
type nonceQueueError struct{ msg string }

func (e *nonceQueueError) Error() string { return e.msg }

// queuedNonce decodes the given base64url nonces in order; it fails the test
// when exhausted or on bad input.
func queuedNonce(t *testing.T, nonces ...string) NonceSource {
	t.Helper()
	i := 0
	return func() ([]byte, error) {
		if i >= len(nonces) {
			return nil, &nonceQueueError{"nonce queue exhausted"}
		}
		n, err := jack.DecodeBase64URLFixed(nonces[i], 16)
		i++
		if err != nil {
			return nil, &nonceQueueError{"bad nonce: " + err.Error()}
		}
		return n, nil
	}
}

// testServer is an httptest server that verifies incoming requests with the
// root-package jack primitives and can sign its responses with its own fresh
// key.
//
// Tests set s.Handle after newTestServer returns. Requests made before the
// assignment would race; the handler responds 500 when s.Handle is nil, so
// the window is benign.
type testServer struct {
	*httptest.Server
	Key    ed25519.PrivateKey                                              // server signing key
	Pub    []byte                                                          // 32-byte server public key
	Kid    string                                                          // jack.KeyID(Pub)
	Keys   map[string][]byte                                               // client kid -> public key accepted for verification
	Aud    string                                                          // audience used in request signing strings
	Now    int64                                                           // response timestamp; tests may adjust
	Handle func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) // per-test response logic
}

// newTestServer starts the server; its handler verifies each request per
// spec 01 section 4. The handler runs in the server goroutine and must not
// call t.Fatal/t.Errorf, so on verification failure it silently serves a 401.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	keys, _ := fixtureKeys(t)
	s := &testServer{
		Key:  priv,
		Pub:  pub,
		Kid:  jack.KeyID(pub),
		Keys: keys,
		Aud:  fixtureAud,
		Now:  fixtureNow,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, authErr := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		body, readErr := io.ReadAll(r.Body)
		r.Body.Close()
		if authErr != nil || readErr != nil {
			s.writeUnsignedJSON(w, http.StatusUnauthorized, []byte(`{"error":{"code":"unknown_key","message":"verification failed"}}`))
			return
		}
		clientPub, ok := s.Keys[auth.Kid]
		msg := []byte(jack.RequestSigningString(r.Method, r.URL.RequestURI(), s.Aud, auth.Kid, auth.TS, auth.Nonce, body))
		sig, sigErr := jack.DecodeBase64URLFixed(auth.Sig, ed25519.SignatureSize)
		if !ok || sigErr != nil || !jack.Verify(clientPub, msg, sig) {
			s.writeUnsignedJSON(w, http.StatusUnauthorized, []byte(`{"error":{"code":"unknown_key","message":"verification failed"}}`))
			return
		}
		if s.Handle == nil {
			s.writeUnsignedJSON(w, http.StatusInternalServerError, []byte(`{"error":{"code":"internal","message":"no handler"}}`))
			return
		}
		s.Handle(w, auth, body)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// writeSignedJSON signs status+auth.Sig+kid+ts+body per spec 01 section 5
// with the server key and writes it with the Jack-Auth header
// (jack.FormatResponseAuth) and Content-Type application/json. ts = s.Now.
func (s *testServer) writeSignedJSON(w http.ResponseWriter, auth jack.RequestAuth, status int, body []byte) {
	ts := s.Now
	msg := []byte(jack.ResponseSigningString(status, auth.Sig, s.Kid, ts, body))
	sig := ed25519.Sign(s.Key, msg)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: s.Kid, TS: ts, Sig: jack.EncodeBase64URL(sig)}))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeUnsignedJSON writes status+body without a Jack-Auth header.
func (s *testServer) writeUnsignedJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// rpcResultBody wraps a structuredContent raw JSON value into a JSON-RPC 2.0
// / MCP CallToolResult response body.
func rpcResultBody(structured json.RawMessage) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":` + string(structured) + `}}`)
}
