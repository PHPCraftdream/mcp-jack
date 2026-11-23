// Package streamtest carries the spec 05 exemption tests that only the
// middleware can prove: the Jack-Accept opt-in (1.1), the signed refusal of a
// stream the deployment may not carry (1.2), the per-identity stream limit
// (3.3), the duration close (3.4), the heartbeat grant handed to the wrapped
// handler (3.5), the nonce commitment before the first stream byte (3.6), the
// client-disconnect cancellation (3.7), the requests that may open a stream at
// all (3.8), the rotation cutoff (5.1) and an end-to-end check against the
// public client verifier. It is a test-only package.
package streamtest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/server/internal/transport"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// streamAud is the fixture audience of spec 01 section 3.1.
const streamAud = "https://svc.example.test"

const (
	// progressEvent is the data value of the progress notification the test
	// handlers produce.
	progressEvent = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}`
	// progressFrame is the one-event SSE body of progressEvent.
	progressFrame = "data: " + progressEvent + "\n\n"
	// finalEvent is the 6.3 final response the middleware writes for the
	// server-initiated events/stream subscription of request id 7.
	finalEvent = `{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":7}}}`
	// notificationStreamBody is the signed events/stream notification of 3.8:
	// it carries no id, so it cannot open a stream.
	notificationStreamBody = `{"jsonrpc":"2.0","method":"events/stream","params":{"name":"email.received","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	// nullIDStreamBody is the same request with a null id: a null id is not an
	// opening request either (3.8).
	nullIDStreamBody = `{"jsonrpc":"2.0","id":null,"method":"events/stream","params":{"name":"email.received","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	// clientResponseBody is a client-sent JSON-RPC response object, which is
	// not a request and must never open a stream (3.8).
	clientResponseBody = `{"jsonrpc":"2.0","id":1,"result":{}}`
)

// clock is the mutable test clock handed to the verifier and to the request
// signer.
type clock struct {
	mu sync.Mutex
	ts int64
}

// Now returns the current Unix time in seconds.
func (c *clock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ts
}

// Set moves the clock to ts.
func (c *clock) Set(ts int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ts = ts
}

// Add advances the clock by d.
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ts += int64(d / time.Second)
}

// harness is one middleware over the fixture registry.
type harness struct {
	handler http.Handler
	server  ed25519.PrivateKey
	clock   *clock
	next    *atomic.Int32
}

// fixtureVerifier builds the verifier of the fixture registry over clk.
func fixtureVerifier(t *testing.T, clk *clock) *verify.Verifier {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	v, err := verify.NewVerifier(verify.Config{
		Aud:    streamAud,
		State:  testfixture.Registry(t, registry),
		Nonces: nonceimpl.NewNonceStore(),
		Now:    clk.Now,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// countNext wraps next so the harness can count the forwarded requests.
func countNext(h *harness, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.next.Add(1)
		next.ServeHTTP(w, r)
	})
}

// newHarness wires a verifier over the fixture registry in front of next, with
// the fixture "svc" key as the server key and clk as the clock of both the
// verifier and the requests.
func newHarness(t *testing.T, profile modern.Profile, streams *transport.StreamOptions, next http.Handler) (*harness, *clock) {
	t.Helper()
	if next == nil {
		t.Fatal("newHarness: next handler must be set")
	}
	clk := &clock{ts: testfixture.Now}
	h := &harness{server: testfixture.PrivateKey(t, "svc"), clock: clk, next: new(atomic.Int32)}
	handler, err := transport.NewHandler(transport.HandlerConfig{
		Verifier:  fixtureVerifier(t, clk),
		ServerKey: h.server,
		Profile:   profile,
		Streams:   streams,
	}, countNext(h, next))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.handler = handler
	return h, clk
}

// newResponseKeysHarness is newHarness with the spec 05 section 5.1
// ResponseKeys signing profile instead of a fixed server key.
func newResponseKeysHarness(t *testing.T, profile modern.Profile, provider transport.ResponseKeyProvider, next http.Handler) (*harness, *clock) {
	t.Helper()
	if next == nil {
		t.Fatal("newResponseKeysHarness: next handler must be set")
	}
	clk := &clock{ts: testfixture.Now}
	h := &harness{clock: clk, next: new(atomic.Int32)}
	handler, err := transport.NewHandler(transport.HandlerConfig{
		Verifier:     fixtureVerifier(t, clk),
		ResponseKeys: provider,
		Profile:      profile,
	}, countNext(h, next))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.handler = handler
	return h, clk
}

// durableDeployment is the deployment identity the durable double writes into
// every receipt.
const durableDeployment = "streamtest-durable-deployment"

// durableNonces is a minimal durable admission double: it records the committed
// (kid, nonce) pairs and refuses a duplicate, like the real store does.
type durableNonces struct {
	mu     sync.Mutex
	seen   map[string]bool
	fenced bool
}

// Reserve commits the (kid, nonce) pair and returns the confirmed receipt and
// the serving lease of it, or the 401 replayed_nonce refusal of a duplicate
// and of every reservation after Fence.
func (d *durableNonces) Reserve(a verify.NonceAdmission) (verify.NonceReceipt, verify.NonceLease, *jack.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = make(map[string]bool)
	}
	key := a.KID + "\x00" + a.Nonce
	if d.fenced || d.seen[key] {
		return verify.NonceReceipt{}, nil, &jack.Error{HTTPStatus: http.StatusUnauthorized, Code: jack.CodeReplayedNonce}
	}
	d.seen[key] = true
	receipt := verify.NonceReceipt{
		Version: 1, DeploymentID: durableDeployment, StoreGeneration: 1, OwnerGeneration: 1,
		KID: a.KID, Nonce: a.Nonce, Signature: a.Signature,
		RequestHash: jack.BodyHash([]byte(a.SigningBytes)),
		Timestamp:   a.Timestamp, RetainUntil: a.Timestamp + a.Window, HighWater: a.Timestamp,
	}
	receipt.OperationID[0] = 1
	intent, err := verify.NonceIntentID(receipt.DeploymentID, a, receipt.OperationID)
	if err != nil {
		return verify.NonceReceipt{}, nil, &jack.Error{
			HTTPStatus: http.StatusServiceUnavailable,
			Code:       "durability_unavailable",
			Message:    "durable admission is unavailable",
		}
	}
	receipt.IntentID = intent
	return receipt, durableLease{}, nil
}

// Fence closes admission for good.
func (d *durableNonces) Fence() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fenced = true
}

// durableLease is the no-op serving lease of the double: the double keeps the
// reservation, so the lease is always valid and releasing it does nothing.
type durableLease struct{}

func (durableLease) Valid() bool { return true }
func (durableLease) Release()    {}

// newDurableHarness is newHarness over a verifier whose nonce admission is the
// durable store instead of the volatile one. The fixture registry implements
// verify.AdmissionStateStore, which verify.NewVerifier requires for a durable
// store (see server/admission_test.go).
func newDurableHarness(t *testing.T, store verify.DurableNonceStore, next http.Handler) (*harness, *clock) {
	t.Helper()
	if next == nil {
		t.Fatal("newDurableHarness: next handler must be set")
	}
	if store == nil {
		t.Fatal("newDurableHarness: durable store must be set")
	}
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	clk := &clock{ts: testfixture.Now}
	v, err := verify.NewVerifier(verify.Config{
		Aud:           streamAud,
		State:         testfixture.Registry(t, registry),
		DurableNonces: store,
		Now:           clk.Now,
		Window:        30,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	h := &harness{server: testfixture.PrivateKey(t, "svc"), clock: clk, next: new(atomic.Int32)}
	handler, err := transport.NewHandler(transport.HandlerConfig{
		Verifier:  v,
		ServerKey: h.server,
		Profile:   modern.ProfileModern,
	}, countNext(h, next))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.handler = handler
	return h, clk
}

// waitClosed waits up to 10 s for ch to be closed and fails the test
// otherwise.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish within 10 s", what)
	}
}

// signedPost signs a POST request over target with the fixture audience and a
// 16-byte nonce filled with nonceByte, then adds the unsigned Jack-Accept
// opt-in when accept is not empty.
func signedPost(t *testing.T, clk *clock, key ed25519.PrivateKey, target string, body []byte, nonceByte byte, accept string) (*http.Request, string) {
	t.Helper()
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonce := jack.EncodeBase64URL(bytes.Repeat([]byte{nonceByte}, 16))
	ts := clk.Now()
	signing := jack.RequestSigningString("POST", target, streamAud, kid, ts, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	req := httptest.NewRequest("POST", target, bytes.NewReader(body))
	req.Header.Set("Jack-Auth", jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: ts, Nonce: nonce, Sig: sig}))
	if accept != "" {
		req.Header.Set("Jack-Accept", accept)
	}
	return req, sig
}

// modernStreamBody is the signed body of the modern events/stream request id.
func modernStreamBody(id int) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) +
		`,"method":"events/stream","params":{"name":"email.received","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
}

// modernMirrors sets the three unsigned mirror headers of the request.
func modernMirrors(req *http.Request, name string) {
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "events/stream")
	req.Header.Set("Mcp-Name", name)
}

// streamHeaders flattens h into the received order of the public verifier:
// names sorted, every value its own entry.
func streamHeaders(h http.Header) []clientstream.Header {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []clientstream.Header
	for _, name := range names {
		for _, value := range h[name] {
			out = append(out, clientstream.Header{Name: name, Value: value})
		}
	}
	return out
}

// verifyStream verifies rec as one s1 stream with the public client verifier.
func verifyStream(t *testing.T, rec *httptest.ResponseRecorder, clk *clock, requestSig string, pub ed25519.PublicKey, frameMax int64) clientstream.Result {
	t.Helper()
	result, err := clientstream.Verify(clientstream.Expectation{
		Now:           func() time.Time { return time.Unix(clk.Now(), 0) },
		Window:        30 * time.Second,
		Keys:          map[string]clientstream.Key{jack.KeyID(pub): {PublicKey: pub}},
		RequestSig:    requestSig,
		FrameMaxBytes: frameMax,
		StreamIdle:    0,
	}, http.StatusOK, streamHeaders(rec.Header()), [][]byte{rec.Body.Bytes()})
	if err != nil {
		t.Fatalf("stream verification: %v", err)
	}
	return result
}

// assertResponseSignature checks the v1 Jack-Auth header of a non-stream
// answer against the response signing string over the request signature.
func assertResponseSignature(t *testing.T, rec *httptest.ResponseRecorder, pub ed25519.PublicKey, requestSig string) {
	t.Helper()
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
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

// errorCode returns the error.code member of a JSON error body.
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

// parsedFrame is one event of an SSE body, with the frame chain metadata.
type parsedFrame struct {
	event string
	data  string
	seq   uint64
	ts    int64
}

// parseFrames splits an SSE body into its events and parses the jack chain
// line of each frame.
func parseFrames(t *testing.T, body []byte) []parsedFrame {
	t.Helper()
	var frames []parsedFrame
	var cur parsedFrame
	var data []string
	open := false
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case line == "":
			if open {
				cur.data = strings.Join(data, "\n")
				frames = append(frames, cur)
			}
			cur, data, open = parsedFrame{}, nil, false
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
			open = true
		case line == "data:":
			data = append(data, "")
			open = true
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
			open = true
		case strings.HasPrefix(line, "jack: "):
			for _, part := range strings.Split(strings.TrimPrefix(line, "jack: "), ",") {
				switch {
				case strings.HasPrefix(part, "seq="):
					n, err := strconv.ParseUint(strings.TrimPrefix(part, "seq="), 10, 64)
					if err != nil {
						t.Fatalf("frame seq %q: %v", part, err)
					}
					cur.seq = n
				case strings.HasPrefix(part, "ts="):
					n, err := strconv.ParseInt(strings.TrimPrefix(part, "ts="), 10, 64)
					if err != nil {
						t.Fatalf("frame ts %q: %v", part, err)
					}
					cur.ts = n
				}
			}
			open = true
		}
	}
	return frames
}

// TestStreamOptInSignsTheAnswer covers spec 05 1.1, 2.1 and 2.16: the
// Jack-Accept opt-in turns a committed text/event-stream answer into the signed
// stream, closed by a jack-end frame.
func TestStreamOptInSignsTheAnswer(t *testing.T) {
	h, clk := newHarness(t, modern.ProfileModern, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
	}))
	req, sig := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(1), 1, "s1")
	modernMirrors(req, "email.received")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	auths := rec.Header().Values("Jack-Auth")
	if len(auths) != 1 {
		t.Fatalf("Jack-Auth headers = %q, want exactly one", auths)
	}
	if !strings.HasPrefix(auths[0], "s1 kid=") {
		t.Fatalf("Jack-Auth = %q, want the s1 open header", auths[0])
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q", got)
	}
	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) < 2 || frames[len(frames)-1].event != "jack-end" {
		t.Fatalf("frames do not end with jack-end: %+v", frames)
	}
	if !strings.HasSuffix(rec.Body.String(), "\n\n") {
		t.Fatalf("body does not end with the end frame terminator: %q", rec.Body.String())
	}
	result := verifyStream(t, rec, clk, sig, h.server.Public().(ed25519.PublicKey), 0)
	if !result.Complete {
		t.Fatal("the end frame was not verified")
	}
	if len(result.Messages) != 1 || result.Messages[0] != progressEvent {
		t.Fatalf("messages = %q, want exactly the progress notification", result.Messages)
	}
}

// TestStreamWithoutOptInKeepsTheSigned501 covers spec 05 1.1 and 1.2: without
// the opt-in, and in a deployment profile that cannot carry a modern stream,
// a text/event-stream answer stays the signed 501.
func TestStreamWithoutOptInKeepsTheSigned501(t *testing.T) {
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
	})
	cases := []struct {
		name    string
		profile modern.Profile
		accept  string
	}{
		{"modern without Jack-Accept", modern.ProfileModern, ""},
		{"legacy profile with Jack-Accept", modern.ProfileLegacy, "s1"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, clk := newHarness(t, tc.profile, nil, sse)
			req, sig := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(1), byte(2+i), tc.accept)
			modernMirrors(req, "email.received")
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != "streaming_unsupported" {
				t.Fatalf("error code = %q, want streaming_unsupported", code)
			}
			assertResponseSignature(t, rec, h.server.Public().(ed25519.PublicKey), sig)
			if got := rec.Header().Get("Content-Type"); strings.EqualFold(got, "text/event-stream") {
				t.Fatalf("Content-Type = %q, want a JSON refusal", got)
			}
			if bytes.Contains(rec.Body.Bytes(), []byte("event: ")) {
				t.Fatalf("body = %q, want no event-stream bytes", rec.Body.String())
			}
		})
	}
}

// TestStreamLimitRefusalIsSigned429 covers spec 05 3.3: the per-identity limit
// refuses a second stream with the signed 429 before any of its bytes, and the
// slot is freed when the first stream ends.
func TestStreamLimitRefusalIsSigned429(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := w.Write([]byte(progressFrame)); err != nil {
			return
		}
		once.Do(func() { close(started) })
		<-release
	})
	h, clk := newHarness(t, modern.ProfileModern, &transport.StreamOptions{MaxConcurrentStreams: 1}, sse)

	alice := testfixture.PrivateKey(t, "alice")
	reqA, _ := signedPost(t, clk, alice, "/mcp", modernStreamBody(1), 10, "s1")
	modernMirrors(reqA, "email.received")
	recA := httptest.NewRecorder()
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		h.handler.ServeHTTP(recA, reqA)
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		close(release)
		<-doneA
		t.Fatal("stream A never wrote its first event")
	}

	reqB, sigB := signedPost(t, clk, alice, "/mcp", modernStreamBody(7), 11, "s1")
	modernMirrors(reqB, "email.received")
	recB := httptest.NewRecorder()
	h.handler.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body %s", recB.Code, recB.Body.String())
	}
	want := `{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"stream_limit_exceeded"}}`
	if got := recB.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	assertResponseSignature(t, recB, h.server.Public().(ed25519.PublicKey), sigB)

	close(release)
	<-doneA
	if recA.Code != http.StatusOK {
		t.Fatalf("stream A status = %d", recA.Code)
	}
	if frames := parseFrames(t, recA.Body.Bytes()); len(frames) < 2 || frames[len(frames)-1].event != "jack-end" {
		t.Fatalf("stream A did not end with jack-end: %+v", frames)
	}

	reqC, _ := signedPost(t, clk, alice, "/mcp", modernStreamBody(9), 12, "s1")
	modernMirrors(reqC, "email.received")
	recC := httptest.NewRecorder()
	h.handler.ServeHTTP(recC, reqC)
	if recC.Code != http.StatusOK {
		t.Fatalf("status after the slot was freed = %d, body %s", recC.Code, recC.Body.String())
	}
	if frames := parseFrames(t, recC.Body.Bytes()); len(frames) < 2 || frames[len(frames)-1].event != "jack-end" {
		t.Fatalf("stream C did not end with jack-end: %+v", frames)
	}
}

// TestStreamAdmitsOnlyRequests covers spec 05 3.8: only an opt-in POST whose
// body is a JSON-RPC request with a usable id may open an s1 stream. A
// notification and a null id get the signed 202 with no body, and a
// client-sent response object never gets a stream at all.
func TestStreamAdmitsOnlyRequests(t *testing.T) {
	// One handler answers text/event-stream for every sub-case: the decision
	// belongs to the middleware, not to the shape of the answer.
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
	})
	h, clk := newHarness(t, modern.ProfileModern, nil, sse)

	cases := []struct {
		name string
		// body is the signed request body of the sub-case.
		body []byte
		// mirrors says whether the modern mirror headers of the body are sent;
		// a client-sent response object has no mirror obligation (S12).
		mirrors bool
		// nonceByte keeps the signed requests of the sub-cases apart.
		nonceByte byte
		want      int
	}{
		{"request", modernStreamBody(1), true, 70, http.StatusOK},
		{"notification", []byte(notificationStreamBody), true, 71, http.StatusAccepted},
		{"client response object", []byte(clientResponseBody), false, 72, http.StatusNotImplemented},
		{"request with a null id", []byte(nullIDStreamBody), true, 73, http.StatusAccepted},
	}
	alice := testfixture.PrivateKey(t, "alice")
	pub := h.server.Public().(ed25519.PublicKey)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, sig := signedPost(t, clk, alice, "/mcp", tc.body, tc.nonceByte, "s1")
			if tc.mirrors {
				modernMirrors(req, "email.received")
			}
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, body %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			switch tc.want {
			case http.StatusOK:
				for _, want := range []string{"event: message", "event: jack-end"} {
					if !strings.Contains(rec.Body.String(), want) {
						t.Fatalf("the request did not open a stream (%q missing): %q", want, rec.Body.String())
					}
				}
			case http.StatusAccepted:
				if rec.Body.Len() != 0 {
					t.Fatalf("body = %q, want the empty 202 body", rec.Body.String())
				}
				assertResponseSignature(t, rec, pub, sig)
				if bytes.Contains(rec.Body.Bytes(), []byte("event: ")) {
					t.Fatalf("body = %q, want no stream", rec.Body.String())
				}
			case http.StatusNotImplemented:
				if code := errorCode(t, rec); code != "streaming_unsupported" {
					t.Fatalf("error code = %q, want streaming_unsupported", code)
				}
				assertResponseSignature(t, rec, pub, sig)
				if bytes.Contains(rec.Body.Bytes(), []byte("event: ")) {
					t.Fatalf("body = %q, want no stream", rec.Body.String())
				}
			}
		})
	}
}

// TestStreamNotificationKeepsThe202 covers spec 05 3.8: a JSON-RPC
// notification has no id to bind a stream to, so the handler's
// text/event-stream answer is never streamed and the request keeps the signed
// 202 with an empty body.
func TestStreamNotificationKeepsThe202(t *testing.T) {
	h, clk := newHarness(t, modern.ProfileModern, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
	}))
	req, sig := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", []byte(notificationStreamBody), 20, "s1")
	modernMirrors(req, "email.received")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s, want 202", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want the empty 202 body", rec.Body.String())
	}
	assertResponseSignature(t, rec, h.server.Public().(ed25519.PublicKey), sig)
	if got := rec.Header().Get("Content-Type"); strings.EqualFold(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want the 202 content type", got)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("event: ")) {
		t.Fatalf("body = %q, want no stream", rec.Body.String())
	}
}

// TestStreamGrantReachesTheHandler covers spec 05 3.5: an opt-in request hands
// the wrapped handler the granted heartbeat, clamped to floor(W*500)
// milliseconds (15 s with the default 30 s window), and a request without the
// opt-in sees no grant.
func TestStreamGrantReachesTheHandler(t *testing.T) {
	type seen struct {
		grant transport.StreamGrant
		ok    bool
	}
	cases := []struct {
		name    string
		accept  string
		body    []byte
		mirrors bool
		granted bool
	}{
		{"opt-in grant", "s1", modernStreamBody(15), true, true},
		{"no Jack-Accept", "", []byte(`{"jsonrpc":"2.0","id":15,"method":"tools/list","params":{}}`), false, false},
	}
	alice := testfixture.PrivateKey(t, "alice")
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The report channel is buffered: the handler runs inside
			// ServeHTTP, so it must never block on the test goroutine.
			report := make(chan seen, 1)
			h, clk := newHarness(t, modern.ProfileModern, &transport.StreamOptions{Heartbeat: 60 * time.Second}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				grant, ok := transport.StreamFromContext(r.Context())
				report <- seen{grant: grant, ok: ok}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(progressFrame))
			}))
			req, sig := signedPost(t, clk, alice, "/mcp", tc.body, byte(80+i), tc.accept)
			if tc.mirrors {
				modernMirrors(req, "email.received")
			}
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)

			var got seen
			select {
			case got = <-report:
			case <-time.After(10 * time.Second):
				t.Fatal("the handler reported no stream grant")
			}
			if got.ok != tc.granted {
				t.Fatalf("StreamFromContext ok = %v, want %v", got.ok, tc.granted)
			}
			if !tc.granted {
				if rec.Code != http.StatusNotImplemented {
					t.Fatalf("status without the opt-in = %d, body %s", rec.Code, rec.Body.String())
				}
				if bytes.Contains(rec.Body.Bytes(), []byte("event: ")) {
					t.Fatalf("body without the opt-in contains stream bytes: %q", rec.Body.String())
				}
				assertResponseSignature(t, rec, h.server.Public().(ed25519.PublicKey), sig)
				return
			}
			// 60 s was requested; floor(30 s * 500) ms = 15 s is granted.
			if got.grant.Heartbeat != 15*time.Second {
				t.Fatalf("Heartbeat grant = %v, want %v", got.grant.Heartbeat, 15*time.Second)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// replayWhileStreaming proves that request A consumed its nonce before its
// first stream byte: A is opened in a goroutine, and once its handler reports
// the first event the identical signed request is sent while A is still
// running. A is released only after the replay was answered.
func replayWhileStreaming(t *testing.T, h *harness, clk *clock, body []byte, nonceByte byte, started, release chan struct{}) (*httptest.ResponseRecorder, *httptest.ResponseRecorder, string) {
	t.Helper()
	alice := testfixture.PrivateKey(t, "alice")
	first, _ := signedPost(t, clk, alice, "/mcp", body, nonceByte, "s1")
	modernMirrors(first, "email.received")
	// The identical signed request: same kid, ts, nonce and body, hence the
	// same signature, with a fresh body reader.
	replay, sig := signedPost(t, clk, alice, "/mcp", body, nonceByte, "s1")
	modernMirrors(replay, "email.received")

	recFirst := httptest.NewRecorder()
	doneFirst := make(chan struct{})
	go func() {
		defer close(doneFirst)
		h.handler.ServeHTTP(recFirst, first)
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		close(release)
		waitClosed(t, doneFirst, "the first stream")
		t.Fatal("the handler never wrote its first stream event")
	}
	select {
	case <-doneFirst:
		t.Fatal("the first stream ended before the replay was sent")
	default:
	}

	recReplay := httptest.NewRecorder()
	h.handler.ServeHTTP(recReplay, replay)

	close(release)
	waitClosed(t, doneFirst, "the first stream")
	if recFirst.Code != http.StatusOK {
		t.Fatalf("first status = %d, body %s", recFirst.Code, recFirst.Body.String())
	}
	frames := parseFrames(t, recFirst.Body.Bytes())
	if len(frames) == 0 || frames[len(frames)-1].event != "jack-end" {
		t.Fatalf("the first stream did not end with jack-end: %+v", frames)
	}
	return recFirst, recReplay, sig
}

// TestStreamNonceBeforeFirstByteAndReplayRefused covers spec 05 3.6: the nonce
// is committed before the first stream byte, so the same signed request is a
// replayed_nonce refusal while the first stream is still running.
func TestStreamNonceBeforeFirstByteAndReplayRefused(t *testing.T) {
	// gate is the handler of both sub-tests: it writes one event, reports it
	// and blocks until the test releases it.
	gate := func(started, release chan struct{}) http.Handler {
		var once sync.Once
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if _, err := w.Write([]byte(progressFrame)); err != nil {
				return
			}
			once.Do(func() { close(started) })
			<-release
		})
	}

	t.Run("volatile nonce store", func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		h, clk := newHarness(t, modern.ProfileModern, nil, gate(started, release))
		pub := h.server.Public().(ed25519.PublicKey)
		recFirst, recReplay, sig := replayWhileStreaming(t, h, clk, modernStreamBody(5), 30, started, release)

		for _, want := range []string{"event: message", "event: jack-end"} {
			if !strings.Contains(recFirst.Body.String(), want) {
				t.Fatalf("first response carried no stream bytes (%q missing): %q", want, recFirst.Body.String())
			}
		}
		if recReplay.Code != http.StatusUnauthorized {
			t.Fatalf("replay status = %d, body %s", recReplay.Code, recReplay.Body.String())
		}
		if code := errorCode(t, recReplay); code != jack.CodeReplayedNonce {
			t.Fatalf("replay code = %q, want %q", code, jack.CodeReplayedNonce)
		}
		assertResponseSignature(t, recReplay, pub, sig)
		if strings.Contains(recReplay.Body.String(), "event: ") {
			t.Fatalf("replay answered with a stream: %q", recReplay.Body.String())
		}
	})

	t.Run("durable nonce store", func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		store := &durableNonces{}
		h, clk := newDurableHarness(t, store, gate(started, release))
		recFirst, recReplay, _ := replayWhileStreaming(t, h, clk, modernStreamBody(5), 31, started, release)

		for _, want := range []string{"event: message", "event: jack-end"} {
			if !strings.Contains(recFirst.Body.String(), want) {
				t.Fatalf("first response carried no stream bytes (%q missing): %q", want, recFirst.Body.String())
			}
		}
		if recReplay.Code != http.StatusUnauthorized {
			t.Fatalf("replay status = %d, body %s", recReplay.Code, recReplay.Body.String())
		}
		if code := errorCode(t, recReplay); code != jack.CodeReplayedNonce {
			t.Fatalf("replay code = %q, want %q", code, jack.CodeReplayedNonce)
		}
		// The attempted duplicate is refused before a receipt is created, so
		// NonceRecorded is false and the refusal is intentionally unsigned.
		if len(recReplay.Header().Values("Jack-Auth")) != 0 {
			t.Fatalf("durable replay has Jack-Auth headers: %q", recReplay.Header().Values("Jack-Auth"))
		}
		if strings.Contains(recReplay.Body.String(), "event: ") {
			t.Fatalf("replay answered with a stream: %q", recReplay.Body.String())
		}
		if store.fenced {
			t.Fatal("a definite replayed_nonce refusal must not fence the durable store")
		}
	})
}
