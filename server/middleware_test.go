package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// testNow is the fixed clock of the fixtures (2026-01-01T00:00:00Z).
const testNow int64 = 1767225600

func testPrivateKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	for _, k := range keys.Keys {
		if k.Name == name {
			seed, err := hex.DecodeString(k.SeedHex)
			if err != nil {
				t.Fatalf("seed of %s: %v", name, err)
			}
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	t.Fatalf("no test key %q", name)
	return nil
}

var nonceCounter atomic.Uint64

// signedRequest builds a request signed with key, with a fresh nonce.
func signedRequest(t *testing.T, key ed25519.PrivateKey, method, target string, body []byte) (*http.Request, string) {
	t.Helper()
	nonce := make([]byte, 16)
	n := nonceCounter.Add(1)
	for i := 0; i < 8; i++ {
		nonce[i] = byte(n >> (8 * i))
	}
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonceB64 := jack.EncodeBase64URL(nonce)
	signing := jack.RequestSigningString(method, target, "https://svc.example.test", kid, testNow, nonceB64, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Jack-Auth", jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: testNow, Nonce: nonceB64, Sig: sig}))
	return req, sig
}

func toolCallBody(name string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`)
}

type fakeNative struct{ calls atomic.Int32 }

func (f *fakeNative) Call(c *NativeCall) (NativeResult, *jack.Error) {
	f.calls.Add(1)
	c.Target = "target-1"
	return NativeResult{Structured: map[string]any{"tool": c.Tool, "kid": c.Kid}}, nil
}

type harness struct {
	handler http.Handler
	next    *atomic.Int32
	seen    *[]byte
	audit   *MemoryAuditSink
	native  *fakeNative
	server  ed25519.PrivateKey
}

// newHarness wires a verifier over the fixture registry and default policy in
// front of a wrapped handler produced by wrap.
func newHarness(t *testing.T, maxBody int64, wrap func(w http.ResponseWriter, r *http.Request)) *harness {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	h := &harness{next: new(atomic.Int32), seen: new([]byte), audit: NewMemoryAuditSink(), native: &fakeNative{}, server: testPrivateKey(t, "svc")}
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: NewNonceStore(),
		Policy: loadTestPolicy(t, "policy.json"), Audit: h.audit, Native: h.native,
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.next.Add(1)
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		*h.seen = body.Bytes()
		wrap(w, r)
	})
	h.handler, err = NewHandler(HandlerConfig{Verifier: v, ServerKey: h.server, MaxBodyBytes: maxBody}, next)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
}

// assertSigned checks the Jack-Auth header of rec against the server key and
// the request signature.
func assertSigned(t *testing.T, rec *httptest.ResponseRecorder, server ed25519.PrivateKey, requestSig string) {
	t.Helper()
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
	pub := server.Public().(ed25519.PublicKey)
	if auth.Kid != jack.KeyID(pub) {
		t.Fatalf("response kid %q is not the server key", auth.Kid)
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		t.Fatalf("response sig: %v", err)
	}
	signing := jack.ResponseSigningString(rec.Code, requestSig, auth.Kid, auth.TS, rec.Body.Bytes())
	if !jack.Verify(pub, []byte(signing), sig) {
		t.Fatal("response signature does not verify")
	}
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("error body %q: %v", rec.Body.String(), err)
	}
	return env.Error.Code
}

func TestMiddlewareForwardsAndSigns(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	body := toolCallBody("svc.status")
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp?x=1", body)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if h.next.Load() != 1 || !bytes.Equal(*h.seen, body) {
		t.Fatalf("the wrapped handler saw %q (calls %d), want the exact request body", *h.seen, h.next.Load())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareUnauthenticatedIsRejectedUnsigned(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(toolCallBody("svc.status")))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != jack.CodeMissingAuth {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != "Jack-Auth" {
		t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}
	if rec.Header().Get("Jack-Auth") != "" {
		t.Fatal("an authentication failure must not be signed")
	}
	if h.next.Load() != 0 {
		t.Fatal("the wrapped handler must not be reached")
	}
}

func TestMiddlewareSignsAuthorizationRejection(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.restart"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || errorCode(t, rec) != jack.CodeInsufficientScope {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if h.next.Load() != 0 {
		t.Fatal("the wrapped handler must not be reached")
	}
}

func TestMiddlewareRefusesStreams(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: x\n\n"))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareBodyLimit(t *testing.T) {
	h := newHarness(t, 64, okHandler)
	big := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 200) + `"}}`)
	req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", big)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if h.next.Load() != 0 {
		t.Fatal("the wrapped handler must not be reached")
	}
}

func TestMiddlewareMethodNotAllowed(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, _ := signedRequest(t, testPrivateKey(t, "alice"), "PUT", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestMiddlewareAnswersNativeToolsItself(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, sig := signedRequest(t, testPrivateKey(t, "root"), "POST", "/mcp", toolCallBody("jack.admin.user.list"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if h.next.Load() != 0 || h.native.calls.Load() != 1 {
		t.Fatalf("next calls %d, native calls %d", h.next.Load(), h.native.calls.Load())
	}

	var resp struct {
		ID     int `json:"id"`
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
			IsError           bool           `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body %q: %v", rec.Body.String(), err)
	}
	if resp.ID != 1 || resp.Result.IsError || resp.Result.StructuredContent["tool"] != "jack.admin.user.list" {
		t.Fatalf("unexpected native response: %s", rec.Body.String())
	}

	events := h.audit.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Tool != "jack.admin.user.list" || e.Outcome != AuditSuccess || e.ActorName != "root" || e.Target != "target-1" || e.Time != testNow {
		t.Fatalf("audit event = %+v", e)
	}
}

func TestVerifierDeniesNativeToolsWithoutAnImplementation(t *testing.T) {
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: NewNonceStore(),
		Policy: loadTestPolicy(t, "policy-wildcard.json"), Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req, _ := signedRequest(t, testPrivateKey(t, "root"), "POST", "/mcp", toolCallBody("jack.whoami"))
	res := v.Verify(Request{Method: req.Method, Target: req.RequestURI, AuthValues: req.Header.Values("Jack-Auth"), Body: toolCallBody("jack.whoami")})
	if res.Accepted || res.HTTPStatus != 403 || res.Code != jack.CodeOperationDenied {
		t.Fatalf("result = %+v", res)
	}
}
