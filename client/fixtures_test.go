package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errSpyBase is the canned error returned by the spy base for allowed URLs,
// so no network is needed.
var errSpyBase = errors.New("spy base: canned error")

// spyBase counts calls and records the last request.
type spyBase struct {
	calls int
	last  *http.Request
	fn    func(*http.Request) (*http.Response, error)
}

func (s *spyBase) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	s.last = r
	if s.fn != nil {
		return s.fn(r)
	}
	return nil, errSpyBase
}

// spySigner counts every use of the wrapped signer.
type spySigner struct {
	inner *InMemorySigner
	calls int
}

func (s *spySigner) Sign(m []byte) ([]byte, error) { s.calls++; return s.inner.Sign(m) }
func (s *spySigner) PublicKey() []byte             { s.calls++; return s.inner.PublicKey() }
func (s *spySigner) KID() string                   { s.calls++; return s.inner.KID() }

// closeSpyBody records Close.
type closeSpyBody struct {
	io.Reader
	closed bool
	reads  int
}

func (b *closeSpyBody) Read(p []byte) (int, error) { b.reads++; return b.Reader.Read(p) }
func (b *closeSpyBody) Close() error               { b.closed = true; return nil }

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
// the window is benign. A test that needs the request (not just the verified
// auth and body) sets HandleRequest instead; it runs after verification and
// before s.Handle and must write the response itself.
type testServer struct {
	*httptest.Server
	Key    ed25519.PrivateKey                                              // server signing key
	Pub    []byte                                                          // 32-byte server public key
	Kid    string                                                          // jack.KeyID(Pub)
	Keys   map[string][]byte                                               // client kid -> public key accepted for verification
	Aud    string                                                          // audience used in request signing strings
	Now    int64                                                           // response timestamp; tests may adjust
	Handle func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) // per-test response logic
	// HandleRequest, when non-nil, runs after verification and before
	// Handle, so a test can inspect the request (path, headers, method) and
	// must write the response itself.
	HandleRequest func(w http.ResponseWriter, auth jack.RequestAuth, r *http.Request, body []byte)
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
		if s.HandleRequest != nil {
			s.HandleRequest(w, auth, r, body)
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

// matchedCase is one fixture accept case whose Jack-Auth header parses, whose
// kid is derivable from keys.json, and whose body/nonce decode cleanly.
type matchedCase struct {
	ID     string
	Auth   jack.RequestAuth
	Signer *InMemorySigner
	Body   []byte
	Nonce  []byte
}

// fixtureHeader extracts the Jack-Auth header value from a fixture request,
// returning "" when the case carries none.
func fixtureHeader(req spec.FixtureRequest) string {
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Jack-Auth") {
			return h.Value
		}
	}
	return ""
}

// matchedAcceptCases loads the request vectors and returns the accept cases
// that are fully reproducible: parseable header, known kid, decodable nonce.
func matchedAcceptCases(t *testing.T) ([]spec.RequestCase, []matchedCase) {
	t.Helper()
	vecs, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("spec.LoadRequestVectors: %v", err)
	}
	keys, _ := fixtureKeys(t)
	var cases []spec.RequestCase
	var matched []matchedCase
	for _, tc := range vecs.Cases {
		if tc.Expect.Result != "accept" {
			continue
		}
		hv := fixtureHeader(tc.Request)
		if hv == "" {
			t.Logf("%s: no Jack-Auth header, skipping", tc.ID)
			continue
		}
		auth, err := jack.ParseRequestAuth([]string{hv})
		if err != nil {
			t.Fatalf("%s: jack.ParseRequestAuth: %v", tc.ID, err)
		}
		if _, ok := keys[auth.Kid]; !ok {
			t.Logf("%s: kid %q not in keys.json, skipping", tc.ID, auth.Kid)
			continue
		}
		nonce, err := jack.DecodeBase64URLFixed(auth.Nonce, 16)
		if err != nil {
			t.Fatalf("%s: decode nonce: %v", tc.ID, err)
		}
		body, err := tc.Request.Body()
		if err != nil {
			t.Fatalf("%s: tc.Request.Body: %v", tc.ID, err)
		}
		signer := seedSignerByKid(t, auth.Kid)
		cases = append(cases, tc)
		matched = append(matched, matchedCase{ID: tc.ID, Auth: auth, Signer: signer, Body: body, Nonce: nonce})
	}
	return cases, matched
}

// TestSignRequestReproducesFixtureHeaders proves the client header builder
// byte-for-byte reproduces each fixture accept case's Jack-Auth header.
func TestSignRequestReproducesFixtureHeaders(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases matched")
	}
	for i, tc := range cases {
		mc := matched[i]
		t.Run(tc.ID, func(t *testing.T) {
			header, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, mc.Body, mc.Nonce, time.Unix(mc.Auth.TS, 0))
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			want := fixtureHeader(tc.Request)
			if header != want {
				t.Fatalf("header mismatch:\n got: %s\nwant: %s", header, want)
			}
		})
	}
	t.Logf("matched %d derivable accept cases, 0 skipped", len(matched))
}

// TestSigningStringMatchesFixtureDebug asserts the canonical signing string of
// each matched accept case equals the fixture's debug signing string lines.
func TestSigningStringMatchesFixtureDebug(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases checked")
	}
	for i, tc := range cases {
		mc := matched[i]
		want := strings.Join(tc.Debug.SigningStringLines, "\n")
		got := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, mc.Auth.Kid, mc.Auth.TS, mc.Auth.Nonce, mc.Body)
		if got != want {
			t.Fatalf("%s: signing string mismatch:\n got: %q\nwant: %q", tc.ID, got, want)
		}
	}
}

// TestSignRequestTamperDetection checks fixture signature validity, body
// tampering sensitivity, and that derivable reject cases do not reproduce.
func TestSignRequestTamperDetection(t *testing.T) {
	cases, matched := matchedAcceptCases(t)
	if len(matched) == 0 {
		t.Fatalf("no derivable accept cases")
	}
	// The fixture signature must verify over the recomputed signing string.
	for i, tc := range cases {
		mc := matched[i]
		str := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, mc.Auth.Kid, mc.Auth.TS, mc.Auth.Nonce, mc.Body)
		sigBytes, err := jack.DecodeBase64URLFixed(mc.Auth.Sig, 64)
		if err != nil {
			t.Fatalf("%s: decode sig: %v", tc.ID, err)
		}
		if !jack.Verify(mc.Signer.PublicKey(), []byte(str), sigBytes) {
			t.Fatalf("%s: fixture sig does not verify over recomputed string", tc.ID)
		}
	}
	// Tampering one body byte must change the produced header.
	{
		tc := cases[0]
		mc := matched[0]
		if len(mc.Body) == 0 {
			t.Fatalf("%s: first matched case has an empty body; the tamper check needs a body byte", tc.ID)
		}
		body2 := make([]byte, len(mc.Body))
		copy(body2, mc.Body)
		body2[len(body2)-1] ^= 0x01
		header, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, mc.Body, mc.Nonce, time.Unix(mc.Auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest: %v", tc.ID, err)
		}
		header2, err := SignRequest(mc.Signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, body2, mc.Nonce, time.Unix(mc.Auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest tampered: %v", tc.ID, err)
		}
		if header2 == header {
			t.Fatalf("%s: tampered body produced identical header", tc.ID)
		}
	}
	// A reject case with a valid-looking, derivable header must NOT reproduce.
	vecs, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("spec.LoadRequestVectors: %v", err)
	}
	keys, _ := fixtureKeys(t)
	for _, tc := range vecs.Cases {
		// Only signature rejections: a header-form rejection (for example a
		// duplicate header) still carries a valid signature.
		if tc.Expect.Result != "reject" || tc.Expect.Code != "bad_signature" {
			continue
		}
		hv := fixtureHeader(tc.Request)
		if hv == "" {
			continue
		}
		auth, err := jack.ParseRequestAuth([]string{hv})
		if err != nil {
			continue
		}
		if _, ok := keys[auth.Kid]; !ok {
			continue
		}
		nonce, err := jack.DecodeBase64URLFixed(auth.Nonce, 16)
		if err != nil {
			continue
		}
		body, err := tc.Request.Body()
		if err != nil {
			continue
		}
		signer := seedSignerByKid(t, auth.Kid)
		header, err := SignRequest(signer, tc.State.Aud, tc.Request.Method, tc.Request.Target, body, nonce, time.Unix(auth.TS, 0))
		if err != nil {
			t.Fatalf("%s: SignRequest: %v", tc.ID, err)
		}
		str := jack.RequestSigningString(tc.Request.Method, tc.Request.Target, tc.State.Aud, auth.Kid, auth.TS, auth.Nonce, body)
		sigBytes, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
		if err != nil {
			t.Fatalf("%s: decode sig: %v", tc.ID, err)
		}
		if header == hv && jack.Verify(signer.PublicKey(), []byte(str), sigBytes) {
			t.Fatalf("%s: reject case unexpectedly reproducible", tc.ID)
		}
		t.Logf("reject case %s not reproducible (as expected)", tc.ID)
		return
	}
	t.Fatalf("no derivable bad_signature reject case found in the request vectors")
}

// delayedClock returns fixtureNow on its first call (consumed by RotateKey)
// and fixtureNow+3600 on every later call (a response arriving "later").
func delayedClock() func() time.Time {
	var mu sync.Mutex
	calls := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return time.Unix(fixtureNow, 0)
		}
		return time.Unix(fixtureNow+3600, 0)
	}
}

// rotateFreshnessRun performs RotateKey against a server answering with
// response ts respTS and asserts the proof/header ts binding.
func rotateFreshnessRun(t *testing.T, respTS int64) (KidResult, error) {
	t.Helper()
	c := adminCase(t, "rotate-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case rotate-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	srv.Now = respTS
	var mu sync.Mutex
	var gotAuth jack.RequestAuth
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		mu.Lock()
		gotAuth = auth
		gotBody = body
		mu.Unlock()
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(step.Expect.Structured))
	}

	alice := seedSignerByName(t, "alice")
	newbie := seedSignerByName(t, "newbie")
	nonce := fixtureNonce(t, fixtureHeaderValue(t, step.Request, "Jack-Auth"))

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u.Path = "/mcp"
	client, err := NewClient(Config{
		BaseURL:   u.String(),
		Aud:       fixtureAud,
		Signer:    alice,
		ServerKey: srv.Pub,
		Now:       delayedClock(),
		Window:    30 * time.Second,
		Nonce:     queuedNonce(t, nonce),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, rotErr := client.RotateKey(context.Background(), newbie)

	mu.Lock()
	auth, body := gotAuth, gotBody
	mu.Unlock()
	if auth.TS != fixtureNow {
		t.Errorf("header ts = %d, want %d", auth.TS, fixtureNow)
	}
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("captured body does not decode: %v", err)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		t.Fatalf("arguments do not decode: %v", err)
	}
	proof, ok := args["proof"].(string)
	if !ok {
		t.Fatalf("arguments[proof] = %v, want a string", args["proof"])
	}
	proofBytes, err := jack.DecodeBase64URLFixed(proof, 64)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(proof): %v", err)
	}
	msg := []byte(jack.RotateProofString(fixtureAud, alice.KID(), newbie.KID(), fixtureNow))
	if !jack.Verify(newbie.PublicKey(), msg, proofBytes) {
		t.Errorf("rotate proof ts differs from header ts %d", fixtureNow)
	}
	return res, rotErr
}

func TestRotateKeyRefusesDelayedStaleResponse(t *testing.T) {
	res, err := rotateFreshnessRun(t, fixtureNow)
	if err == nil {
		t.Fatalf("RotateKey accepted a stale response, result %+v", res)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) || jErr.Code != jack.CodeTimestampOutOfWindow {
		t.Fatalf("err = %v, want *jack.Error with code %v", err, jack.CodeTimestampOutOfWindow)
	}
	if res != (KidResult{}) {
		t.Errorf("result = %+v, want zero KidResult", res)
	}
}

func TestRotateKeyAcceptsFreshLaterResponse(t *testing.T) {
	res, err := rotateFreshnessRun(t, fixtureNow+3600)
	if err != nil {
		t.Fatalf("RotateKey refused a fresh response: %v", err)
	}
	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KidResult.KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
}

func newValidTestProfile(t *testing.T) (Profile, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(pub),
		KID:             jack.KeyID(pub),
		Name:            "alice-laptop",
	}
	return p, pub
}

func newValidProfileDoc(t *testing.T) string {
	t.Helper()
	p, _ := newValidTestProfile(t)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	return string(b)
}

func TestProfileRoundTrip(t *testing.T) {
	p, pub := newValidTestProfile(t)
	var buf bytes.Buffer
	if err := SaveProfile(&buf, p); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("SaveProfile output does not end with newline: %q", buf.String())
	}
	got, err := LoadProfile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	want, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(want) != string(gotJSON) {
		t.Fatalf("round trip mismatch: got %s want %s", gotJSON, want)
	}
	key, err := got.ServerKeyBytes()
	if err != nil {
		t.Fatalf("ServerKeyBytes: %v", err)
	}
	if !bytes.Equal(key, pub) {
		t.Fatalf("ServerKeyBytes mismatch: got %x want %x", key, pub)
	}
}

func TestProfileJSONHasNoPrivateKey(t *testing.T) {
	p, _ := newValidTestProfile(t)
	var buf bytes.Buffer
	if err := SaveProfile(&buf, p); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	s := buf.String()
	if strings.Contains(s, "private") {
		t.Fatalf("profile JSON contains 'private': %s", s)
	}
	if strings.Contains(s, "seed") {
		t.Fatalf("profile JSON contains 'seed': %s", s)
	}
}

func TestLoadProfileRejects(t *testing.T) {
	shortKey := jack.EncodeBase64URL(make([]byte, 16))
	p, pub := newValidTestProfile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	// One key for every case: the Replace calls below must find it in base.
	base := string(raw)
	paddedKey := jack.EncodeBase64URL(pub) + "="
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "unknown field",
			doc:  strings.TrimSuffix(base, "}") + `,"extra":1}`,
		},
		{
			name: "server key wrong length",
			doc:  strings.Replace(base, jack.EncodeBase64URL(pub), shortKey, 1),
		},
		{
			name: "padded server key",
			doc:  strings.Replace(base, jack.EncodeBase64URL(pub), paddedKey, 1),
		},
		{
			name: "kid not 32-byte base64url",
			doc:  strings.Replace(base, `"kid":"`+jack.KeyID(pub)+`"`, `"kid":"short"`, 1),
		},
		{
			name: "url missing host",
			doc:  strings.Replace(base, `"url":"https://svc.example.test/mcp"`, `"url":"https:///mcp"`, 1),
		},
		{
			name: "aud empty",
			doc:  strings.Replace(base, `"aud":"https://svc.example.test"`, `"aud":""`, 1),
		},
		{
			name: "trailing data",
			doc:  base + " {}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadProfile(strings.NewReader(tc.doc)); err == nil {
				t.Fatalf("LoadProfile accepted invalid document %q", tc.doc)
			}
		})
	}
}

func TestNewClientFromProfile(t *testing.T) {
	p, _ := newValidTestProfile(t)
	c, err := NewClientFromProfile(p, seedSignerByName(t, "alice"), nil)
	if err != nil {
		t.Fatalf("NewClientFromProfile: %v", err)
	}
	if c == nil {
		t.Fatal("NewClientFromProfile returned nil client")
	}

	if _, err := NewClientFromProfile(Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(make([]byte, 16)),
	}, seedSignerByName(t, "alice"), nil); err == nil {
		t.Fatal("expected error for invalid server public key")
	}
}

func TestLocalKeyValidationHasNoHTTPStatus(t *testing.T) {
	// The identity-point encoding {1,0,...,0} decodes to exactly 32 bytes but
	// fails the spec 03 section 2 key rules, exercising the local pinned-key
	// rejection path of LoadProfile, NewClientFromProfile and NewClient.
	identity := make([]byte, 32)
	identity[0] = 1

	// assertClientSide requires err to be a *jack.Error coded key_rejected
	// with HTTPStatus 0: a client-side code never becomes an HTTP response
	// (Error.HTTPStatus contract), so the validator's wire 400 must not leak.
	assertClientSide := func(t *testing.T, err error) {
		t.Helper()
		var je *jack.Error
		if !errors.As(err, &je) {
			t.Fatalf("got error %v, not a *jack.Error", err)
		}
		if je.Code != jack.CodeKeyRejected {
			t.Fatalf("got code %q, want %q", je.Code, jack.CodeKeyRejected)
		}
		if je.HTTPStatus != 0 {
			t.Fatalf("HTTPStatus = %d, want 0", je.HTTPStatus)
		}
	}

	p := Profile{
		URL:             "https://svc.example.test/mcp",
		Aud:             "https://svc.example.test",
		ServerPublicKey: jack.EncodeBase64URL(identity),
	}
	doc, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}

	_, err = LoadProfile(bytes.NewReader(doc))
	assertClientSide(t, err)

	_, err = NewClientFromProfile(p, seedSignerByName(t, "alice"), nil)
	assertClientSide(t, err)

	_, err = NewClient(Config{
		BaseURL:   p.URL,
		Aud:       p.Aud,
		Signer:    seedSignerByName(t, "alice"),
		ServerKey: identity,
	})
	assertClientSide(t, err)
}

// TestAudControlCharsRejected pins the spec 01 section 3.1 aud rules on the
// client side: NewClient and LoadProfile must reject a non-empty audience
// containing control characters (bytes below 0x20 or 0x7f) and still accept
// an ordinary value.
func TestAudControlCharsRejected(t *testing.T) {
	p, pub := newValidTestProfile(t)
	signer := seedSignerByName(t, "alice")

	if _, err := NewClient(Config{BaseURL: p.URL, Aud: p.Aud, Signer: signer, ServerKey: pub}); err != nil {
		t.Fatalf("NewClient rejected an ordinary aud: %v", err)
	}

	for _, aud := range []string{"a\nb", "a\rb", "a\x00b", "a\tb", "a\x7fb"} {
		_, err := NewClient(Config{BaseURL: p.URL, Aud: aud, Signer: signer, ServerKey: pub})
		if err == nil {
			t.Fatalf("NewClient accepted aud with control character %q", aud)
		}
		doc := strings.Replace(newValidProfileDoc(t), `"aud":"https://svc.example.test"`, `"aud":"`+aud+`"`, 1)
		if _, err := LoadProfile(strings.NewReader(doc)); err == nil {
			t.Fatalf("LoadProfile accepted aud with control character %q", aud)
		}
	}

	if _, err := NewClient(Config{BaseURL: p.URL, Aud: "", Signer: signer, ServerKey: pub}); err == nil {
		t.Fatal("NewClient accepted an empty aud")
	}
}

// Pinned public-key literals from spec/fixtures/keys.json (the same oracle
// values used by the userkey transfer tests), so the seed profile's
// server_public_key passes jack.ValidatePublicKey deterministically.
const (
	fuzzServerPubB64 = "kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"
	fuzzServerKid    = "TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs"
)

var fuzzValidProfile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"` +
	fuzzServerPubB64 + `","kid":"` + fuzzServerKid + `","name":"alice-laptop"}`)

var fuzzUnknownFieldProfile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"` +
	fuzzServerPubB64 + `","kid":"` + fuzzServerKid + `","name":"x","extra":1}`)

var fuzzBadBase64Profile = []byte(`{"url":"https://svc.example.test/mcp","aud":"https://svc.example.test","server_public_key":"not base64"}`)

var fuzzTrailingDocsProfile = append(append([]byte{}, fuzzValidProfile...), fuzzValidProfile...)

// FuzzLoadProfile checks that the strict profile loader never panics, refuses
// trailing data, unknown fields and invalid keys, and that every accepted
// profile is an absolute http/https URL with a non-empty aud and a 32-byte
// server key that survive a save/load round trip unchanged (spec 01 section 6).
func FuzzLoadProfile(f *testing.F) {
	f.Add(fuzzValidProfile)
	f.Add(fuzzUnknownFieldProfile)
	f.Add([]byte(`{"url":"https://svc.example.test/mcp","server_public_key":"` + fuzzServerPubB64 + `"}`))
	f.Add(fuzzBadBase64Profile)
	f.Add([]byte(`[]`))
	f.Add(fuzzTrailingDocsProfile)
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := LoadProfile(bytes.NewReader(data))
		if bytes.Equal(data, fuzzValidProfile) && err != nil {
			t.Fatalf("acceptance witness: the valid profile seed must load, got %v", err)
		}
		// Rejection witnesses: unknown fields, malformed keys and trailing
		// documents must fail; a loader that accepts everything would
		// otherwise pass every invariant below.
		for _, invalid := range [][]byte{fuzzUnknownFieldProfile, fuzzBadBase64Profile, fuzzTrailingDocsProfile} {
			if bytes.Equal(data, invalid) && err == nil {
				t.Fatalf("rejection witness: invalid profile seed accepted")
			}
		}
		if err != nil {
			return
		}
		u, err := url.Parse(p.URL)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			t.Fatalf("accepted a profile whose URL does not parse to an absolute http/https URL with a host")
		}
		if p.Aud == "" {
			t.Fatalf("accepted a profile with an empty aud")
		}
		key, err := p.ServerKeyBytes()
		if err != nil || len(key) != 32 {
			t.Fatalf("accepted profile server key does not decode to 32 bytes: %v", err)
		}
		if err := jack.ValidatePublicKey(key); err != nil {
			t.Fatalf("accepted an invalid server public key: %v", err)
		}
		if p.KID != "" {
			if _, err := jack.DecodeBase64URLFixed(p.KID, 32); err != nil {
				t.Fatalf("accepted kid does not decode to 32 bytes: %v", err)
			}
		}
		var buf bytes.Buffer
		if err := SaveProfile(&buf, p); err != nil {
			t.Fatalf("SaveProfile: %v", err)
		}
		again, err := LoadProfile(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("round-tripped profile failed to load: %v", err)
		}
		if again != p {
			t.Fatalf("profile round trip changed it")
		}
	})
}
