package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	auditimpl "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// testNow is the fixed clock of the fixtures (2026-01-01T00:00:00Z).
const testNow = testfixture.Now

func testPrivateKey(t *testing.T, name string) ed25519.PrivateKey {
	return testfixture.PrivateKey(t, name)
}

// registryFromFixture loads the default fixture registry into an in-memory
// state store (the neutral shared helper in internal/testfixture).
func registryFromFixture(t *testing.T, doc spec.RegistryDocument) *stateimpl.MemoryState {
	t.Helper()
	return testfixture.Registry(t, doc)
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

func (f *fakeNative) Call(c *verify.NativeCall) (verify.NativeResult, *jack.Error) {
	f.calls.Add(1)
	c.Target = "target-1"
	return verify.NativeResult{Structured: map[string]any{"tool": c.Tool, "kid": c.Kid}}, nil
}

type harness struct {
	handler http.Handler
	next    *atomic.Int32
	seen    *[]byte
	audit   *auditimpl.MemoryAuditSink
	native  *fakeNative
	server  ed25519.PrivateKey
}

// newHarness wires a verifier over the fixture registry in front of a
// wrapped handler produced by wrap.
func newHarness(t *testing.T, maxBody int64, wrap func(w http.ResponseWriter, r *http.Request)) *harness {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	h := &harness{next: new(atomic.Int32), seen: new([]byte), audit: auditimpl.NewMemoryAuditSink(), native: &fakeNative{}, server: testPrivateKey(t, "svc")}
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
		Audit: h.audit, Native: h.native,
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

const overflowBody = `{"error":{"code":"response_too_large","message":"upstream response exceeds the configured limit"}}`

// newCapHarness is newHarness with a configurable response cap.
func newCapHarness(t *testing.T, maxBody, maxResp int64, wrap func(w http.ResponseWriter, r *http.Request)) *harness {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	h := &harness{next: new(atomic.Int32), seen: new([]byte), audit: auditimpl.NewMemoryAuditSink(), native: &fakeNative{}, server: testPrivateKey(t, "svc")}
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
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
	h.handler, err = NewHandler(HandlerConfig{Verifier: v, ServerKey: h.server, MaxBodyBytes: maxBody, MaxResponseBytes: maxResp}, next)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// serveGet sends one signed GET through h and returns the recorder and the
// request signature.
func serveGet(t *testing.T, h *harness) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec, sig
}

func signatureVerifies(t *testing.T, rec *httptest.ResponseRecorder, server ed25519.PrivateKey, requestSig string) bool {
	t.Helper()
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		t.Fatalf("response sig: %v", err)
	}
	signing := jack.ResponseSigningString(rec.Code, requestSig, auth.Kid, auth.TS, rec.Body.Bytes())
	return jack.Verify(server.Public().(ed25519.PublicKey), []byte(signing), sig)
}

// chunked returns a handler that sets upstream headers and writes chunks of
// the given sizes, filled with 'a'.
func chunked(sizes ...int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "yes")
		w.Header().Add("Set-Cookie", "session=secret")
		w.WriteHeader(http.StatusCreated)
		for _, n := range sizes {
			if _, err := w.Write(bytes.Repeat([]byte("a"), n)); err != nil {
				return
			}
		}
	}
}

func assertPassed(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness, size int) {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if rec.Body.String() != strings.Repeat("a", size) {
		t.Fatalf("body length %d, want exactly %d bytes", rec.Body.Len(), size)
	}
	if rec.Header().Get("Content-Type") != "text/plain" || rec.Header().Get("X-Upstream") != "yes" || rec.Header().Get("Set-Cookie") != "session=secret" {
		t.Fatalf("upstream headers were not preserved: %v", rec.Header())
	}
	assertSigned(t, rec, h.server, sig)
}

func assertOverflow(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness) {
	t.Helper()
	if rec.Code != http.StatusBadGateway || errorCode(t, rec) != "response_too_large" {
		t.Fatalf("got %d (%d body bytes), want 502 response_too_large", rec.Code, rec.Body.Len())
	}
	if rec.Body.String() != overflowBody {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	for _, name := range []string{"X-Upstream", "Set-Cookie"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("upstream header %s leaked", name)
		}
	}
	if strings.Contains(rec.Body.String(), "aaaa") {
		t.Fatal("partial upstream body leaked")
	}
	assertSigned(t, rec, h.server, sig)
}

func assertStreamRefusal(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness) {
	t.Helper()
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s, want the signed 501", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

type responseKeyProviderFunc func(ResponseKeyRequest) (ResponseKeyAuthorization, error)

func (provider responseKeyProviderFunc) AuthorizeResponse(input ResponseKeyRequest) (ResponseKeyAuthorization, error) {
	return provider(input)
}

type leaseWireRecorder struct {
	*httptest.ResponseRecorder
	held *bool
	t    *testing.T
}

func (writer leaseWireRecorder) WriteHeader(status int) {
	if !*writer.held {
		writer.t.Error("lease released before headers")
	}
	writer.ResponseRecorder.WriteHeader(status)
}
func (writer leaseWireRecorder) Write(body []byte) (int, error) {
	if !*writer.held {
		writer.t.Error("lease released before body")
	}
	return writer.ResponseRecorder.Write(body)
}

func responseKeyFixture(t *testing.T, provider ResponseKeyProvider) (http.Handler, func(byte) *http.Request, *nonceimpl.NonceStore) {
	t.Helper()
	user := responseFixtureKey("leased-user")
	public := user.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := stateimpl.NewMemoryState()
	if err := state.Update(func(edit *stateimpl.StateEdit) error {
		edit.PutKey(stateimpl.RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "caller"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	nonces := nonceimpl.NewNonceStore()
	verifier, err := verify.NewVerifier(verify.Config{Aud: "public", State: state, Nonces: nonces, Now: func() int64 { return 100 }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{Verifier: verifier, ResponseKeys: provider}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App-Private", "not-on-refusal")
		_, _ = w.Write([]byte("application payload"))
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := func(value byte) *http.Request {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		auth := jack.RequestAuth{Kid: kid, TS: 100, Nonce: jack.EncodeBase64URL(bytes.Repeat([]byte{value}, 16))}
		message := jack.RequestSigningString("POST", "/mcp", "public", kid, auth.TS, auth.Nonce, body)
		auth.Sig = jack.EncodeBase64URL(ed25519.Sign(user, []byte(message)))
		r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
		r.Header.Set("Jack-Auth", jack.FormatRequestAuth(auth))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	return handler, request, nonces
}

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

// identityState builds an in-memory state with the fixture root and alice
// keys, both admin, so tests can demote alice the way the protocol would.
func identityState(t *testing.T) *stateimpl.MemoryState {
	t.Helper()
	st := stateimpl.NewMemoryState()
	err := st.Update(func(e *stateimpl.StateEdit) error {
		for _, name := range []string{"root", "alice"} {
			pub := testPrivateKey(t, name).Public().(ed25519.PublicKey)
			e.PutKey(stateimpl.RegistryEntry{
				Kid:       jack.KeyID(pub),
				PublicKey: base64.RawURLEncoding.EncodeToString(pub),
				Name:      name,
				Admin:     true,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return st
}

// identityProbe wraps a handler that records the identity of every request
// it receives before answering.
type identityProbe struct {
	mu     sync.Mutex
	ids    []verify.Identity
	okSeen bool
}

func (p *identityProbe) handle(w http.ResponseWriter, r *http.Request) {
	id, ok := verify.IdentityFromContext(r.Context())
	p.mu.Lock()
	p.ids = append(p.ids, id)
	p.okSeen = p.okSeen || ok
	p.mu.Unlock()
	okHandler(w, r)
}

func (p *identityProbe) identity(i int) (verify.Identity, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.ids) {
		return nil, false
	}
	return p.ids[i], p.okSeen
}

func (p *identityProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ids)
}
