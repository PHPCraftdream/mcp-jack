package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// streamProbe is a test handler that behaves like a blocking SSE handler. Its
// mode selects how it commits the response; unless a write fails it then
// blocks until its request context ends or the test releases it. It never
// polls or writes periodically.
//
//   - "write": Write one event (needs no Flusher, so it reaches a blocking
//     handler on a writer without Flush too).
//   - "writeheader": WriteHeader(200) only, then block; tests cooperative
//     stopping through context cancellation after the header commit.
//   - "flush": needs http.Flusher; Write, then Flush, then block. Where the
//     writer has no Flusher it fails fast with flusherMissing instead of
//     hanging.
//   - "flushonly": needs http.Flusher; Flush as the commit, then block.
//
// The result fields are written by the handler goroutine and read by the test
// only after the middleware returned (serveBounded waits on a channel close).
type streamProbe struct {
	mode        string
	contentType string
	release     chan struct{}
	once        sync.Once

	flusherMissing atomic.Bool
	firstWriteOK   bool
	writeErr       error
	endedBy        string
	ctxErrAtReturn error
}

func newStreamProbe(t *testing.T, mode, contentType string) *streamProbe {
	p := &streamProbe{mode: mode, contentType: contentType, release: make(chan struct{})}
	// Frees a handler parked by a baseline run that never refuses the stream.
	t.Cleanup(p.free)
	return p
}

func (p *streamProbe) free() { p.once.Do(func() { close(p.release) }) }

func (p *streamProbe) handle(w http.ResponseWriter, r *http.Request) {
	defer func() { p.ctxErrAtReturn = r.Context().Err() }()
	w.Header().Set("Content-Type", p.contentType)
	switch p.mode {
	case "write":
		if !p.write(w) {
			return
		}
	case "writeheader":
		w.WriteHeader(http.StatusOK)
	case "flush", "flushonly":
		f, ok := w.(http.Flusher)
		if !ok {
			p.flusherMissing.Store(true)
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		if p.mode == "flush" {
			if !p.write(w) {
				return
			}
		}
		f.Flush()
	}
	select {
	case <-r.Context().Done():
		p.endedBy = "context"
	case <-p.release:
		p.endedBy = "release"
	}
}

// write sends one event and records the outcome; false means it failed.
func (p *streamProbe) write(w http.ResponseWriter) bool {
	if _, err := w.Write([]byte("data: hello\n\n")); err != nil {
		p.writeErr = err
		return false
	}
	p.firstWriteOK = true
	return true
}

// serveBounded runs the middleware in a goroutine and waits for it to return.
// The timeout is only a failure bound: the probe is released so the run ends.
func serveBounded(t *testing.T, h http.Handler, req *http.Request, p *streamProbe) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.free()
		<-done
		t.Fatal("the middleware awaited the end of the stream instead of refusing it")
	}
	return rec
}

func TestMiddlewareRefusesLiveStream(t *testing.T) {
	p := newStreamProbe(t, "write", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("stream bytes leaked into the answer: %s", rec.Body.String())
	}
	if !errors.Is(p.writeErr, errStreamRefused) {
		t.Fatalf("write error = %v, want errStreamRefused", p.writeErr)
	}
	if p.firstWriteOK {
		t.Fatal("the first write succeeded on a refused stream")
	}
	if p.endedBy != "" {
		t.Fatalf("handler ended by %q, want a straight return from the write error", p.endedBy)
	}
	if p.ctxErrAtReturn == nil {
		t.Fatal("the request context of the wrapped handler was not cancelled")
	}
}

func TestMiddlewareCancelsStreamContextAfterHeaderCommit(t *testing.T) {
	p := newStreamProbe(t, "writeheader", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if p.endedBy != "context" {
		t.Fatalf("handler ended by %q, want context cancellation", p.endedBy)
	}
	if p.ctxErrAtReturn == nil {
		t.Fatal("the request context of the wrapped handler was not cancelled")
	}
}

func TestMiddlewareRefusesLiveStreamWithFlusher(t *testing.T) {
	// On a writer without Flush this fails fast with flusherMissing.
	p := newStreamProbe(t, "flush", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if p.flusherMissing.Load() {
		t.Fatal("the wrapped handler did not get an http.Flusher")
	}
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("stream bytes leaked into the answer: %s", rec.Body.String())
	}
	// Write is the first commit, so it fails before the handler flushes.
	if !errors.Is(p.writeErr, errStreamRefused) {
		t.Fatalf("write error = %v, want errStreamRefused", p.writeErr)
	}
}

func TestMiddlewareCancelsStreamContextAfterFlushCommit(t *testing.T) {
	// On a writer without Flush this fails fast with flusherMissing.
	p := newStreamProbe(t, "flushonly", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if p.flusherMissing.Load() {
		t.Fatal("the wrapped handler did not get an http.Flusher")
	}
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if p.endedBy != "context" {
		t.Fatalf("handler ended by %q, want context cancellation", p.endedBy)
	}
}

func TestMiddlewareRefusalIsBoundToOriginalRequestSignature(t *testing.T) {
	p := newStreamProbe(t, "write", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	foreign := "A" + sig
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
	sigBytes, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		t.Fatalf("response sig: %v", err)
	}
	signing := jack.ResponseSigningString(rec.Code, foreign, auth.Kid, auth.TS, rec.Body.Bytes())
	if jack.Verify(h.server.Public().(ed25519.PublicKey), []byte(signing), sigBytes) {
		t.Fatal("the answer verifies against a foreign request signature")
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareRefusesLiveStreamContentTypeVariants(t *testing.T) {
	for _, ct := range []string{
		"Text/Event-Stream",
		"TEXT/EVENT-STREAM; charset=utf-8",
		"  text/event-stream  ;x",
		`text/event-stream; charset="`,
		"text/event-stream;;;=",
	} {
		t.Run(ct, func(t *testing.T) {
			p := newStreamProbe(t, "write", ct)
			h := newHarness(t, 0, p.handle)
			req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
			rec := serveBounded(t, h.handler, req, p)
			if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			assertSigned(t, rec, h.server, sig)
			if p.firstWriteOK {
				t.Fatal("a write succeeded on a refused stream")
			}
		})
	}
}

func TestMiddlewareRefusesLateEventStreamContentType(t *testing.T) {
	cases := []struct {
		name string
		run  func(w http.ResponseWriter)
	}{
		{"after write and flush", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"a":1}`))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			w.Header().Set("Content-Type", "text/event-stream")
		}},
		{"after WriteHeader, mixed case and malformed", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", `Text/Event-Stream; charset="`)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) { c.run(w) })
			req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			assertSigned(t, rec, h.server, sig)
			if strings.Contains(rec.Body.String(), `{"a":1}`) {
				t.Fatalf("handler bytes leaked into the answer: %s", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareRefusesStreamWithoutWrite(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareKeepsOrdinaryResponseWithFlush(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "yes")
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"a":`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte(`1}`))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated || rec.Body.String() != `{"a":1}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Custom") != "yes" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("Content-Length = %q for a %d byte body", rec.Header().Get("Content-Length"), rec.Body.Len())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareSignsUpstreamFailure(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "boom" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewarePropagatesAbortPanic(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	var got any
	func() {
		defer func() { got = recover() }()
		h.handler.ServeHTTP(rec, req)
	}()
	if got != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want http.ErrAbortHandler", got)
	}
	if rec.Body.Len() != 0 || rec.Header().Get("Jack-Auth") != "" {
		t.Fatalf("a response was written after the panic: %q", rec.Body.String())
	}
}

func TestBufferedWriterRefusesEventStream(t *testing.T) {
	for _, ct := range []string{
		"text/event-stream", "Text/Event-Stream", "TEXT/EVENT-STREAM; charset=utf-8",
		"  text/event-stream  ;x", `text/event-stream; charset="`, "text/event-stream;;;=",
	} {
		for _, via := range []string{"write", "writeheader", "flush"} {
			t.Run(via+"/"+ct, func(t *testing.T) {
				var cancels int
				bw := &bufferedWriter{header: http.Header{}, cancel: func() { cancels++ }}
				bw.Header().Set("Content-Type", ct)
				switch via {
				case "write":
					n, err := bw.Write([]byte("data: x\n\n"))
					if n != 0 || !errors.Is(err, errStreamRefused) {
						t.Fatalf("Write = %d, %v", n, err)
					}
				case "writeheader":
					bw.WriteHeader(http.StatusOK)
				case "flush":
					bw.Flush()
				}
				if !bw.refused || cancels != 1 {
					t.Fatalf("refused = %v, cancels = %d", bw.refused, cancels)
				}
				for i := 0; i < 3; i++ {
					n, err := bw.Write([]byte("more"))
					if n != 0 || !errors.Is(err, errStreamRefused) {
						t.Fatalf("later Write = %d, %v", n, err)
					}
					bw.WriteHeader(http.StatusTeapot)
					bw.Flush()
				}
				if bw.body.Len() != 0 {
					t.Fatalf("%d stream bytes retained", bw.body.Len())
				}
				if cancels != 1 {
					t.Fatalf("cancel called %d times, want 1", cancels)
				}
			})
		}
	}
}

func TestBufferedWriterKeepsOrdinaryResponses(t *testing.T) {
	for _, ct := range []string{"text/event-streams", "application/json; x=text/event-stream", "", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			var cancels int
			bw := &bufferedWriter{header: http.Header{}, cancel: func() { cancels++ }}
			if ct != "" {
				bw.Header().Set("Content-Type", ct)
			}
			bw.WriteHeader(http.StatusAccepted)
			bw.WriteHeader(http.StatusTeapot)
			if n, err := bw.Write([]byte("abc")); n != 3 || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
			bw.Flush()
			if bw.refused || cancels != 0 || bw.status != http.StatusAccepted || bw.body.String() != "abc" {
				t.Fatalf("refused=%v cancels=%d status=%d body=%q", bw.refused, cancels, bw.status, bw.body.String())
			}
		})
	}
}

func TestBufferedWriterImplicitStatusAndFlush(t *testing.T) {
	bw := &bufferedWriter{header: http.Header{}}
	_, _ = bw.Write([]byte("x"))
	bw.WriteHeader(http.StatusTeapot)
	if bw.status != http.StatusOK {
		t.Fatalf("status = %d, want implicit 200", bw.status)
	}
	fl := &bufferedWriter{header: http.Header{}}
	fl.Flush()
	if !fl.committed || fl.status != http.StatusOK {
		t.Fatalf("Flush: committed=%v status=%d", fl.committed, fl.status)
	}
	var _ http.Flusher = fl
	// The writer cannot observe a header change after the commit, so it does
	// not refuse here; forward checks the final header when the handler
	// returns (TestMiddlewareRefusesLateEventStreamContentType).
	fl.Header().Set("Content-Type", "text/event-stream")
	if _, err := fl.Write([]byte("x")); err != nil || fl.refused {
		t.Fatalf("the writer refused after a post-commit header change: %v", err)
	}
}
