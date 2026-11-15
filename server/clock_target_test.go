package server

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const clockBase int64 = 1_000_000

type clockRig struct {
	v     *Verifier
	key   ed25519.PrivateKey
	kid   string
	clock int64
}

func newClockRig(t *testing.T) *clockRig {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	rig := &clockRig{key: key, kid: jack.KeyID(public), clock: clockBase}
	state := NewMemoryState()
	if err := state.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: rig.kid, PublicKey: jack.EncodeBase64URL(public), Name: "clock-fixture"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(), Window: 30,
		Now: func() int64 { return rig.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.v = v
	return rig
}

func (r *clockRig) request(ts int64, nonceByte byte) Request {
	nonce := jack.EncodeBase64URL(bytes.Repeat([]byte{nonceByte}, 16))
	signing := jack.RequestSigningString("GET", "/mcp", "svc", r.kid, ts, nonce, nil)
	sig := jack.EncodeBase64URL(ed25519.Sign(r.key, []byte(signing)))
	auth := jack.RequestAuth{Kid: r.kid, TS: ts, Nonce: nonce, Sig: sig}
	return Request{Method: "GET", Target: "/mcp", AuthValues: []string{jack.FormatRequestAuth(auth)}}
}

func expectCode(t *testing.T, label string, res Result, code string) {
	t.Helper()
	defer res.Done()
	if code == "" {
		if !res.Accepted {
			t.Fatalf("%s: rejected with %s, want accepted", label, res.Code)
		}
		return
	}
	if res.Accepted || res.Code != code {
		t.Fatalf("%s: accepted=%v code=%q, want %q", label, res.Accepted, res.Code, code)
	}
}

func TestClockStepBackRefusesReplayOfForwardRequest(t *testing.T) {
	rig := newClockRig(t)
	rig.clock = clockBase + 1000
	req := rig.request(clockBase+1000, 1)
	expectCode(t, "first use", rig.v.Verify(req), "")

	rig.clock = clockBase
	expectCode(t, "replay after step back", rig.v.Verify(req), jack.CodeReplayedNonce)
}

func TestClockStepBackCannotReviveAPurgedNonce(t *testing.T) {
	rig := newClockRig(t)
	old := rig.request(clockBase, 1)
	expectCode(t, "old request", rig.v.Verify(old), "")

	// The step forward purges the old nonce from the volatile store.
	rig.clock = clockBase + 1000
	expectCode(t, "forward request", rig.v.Verify(rig.request(clockBase+1000, 2)), "")

	// Without the monotonic rule this replay would be fresh and unseen.
	rig.clock = clockBase
	expectCode(t, "replay of purged nonce", rig.v.Verify(old), jack.CodeTimestampOutOfWindow)
}

func TestClockStepBackJudgesAgainstHighWaterMark(t *testing.T) {
	rig := newClockRig(t)
	rig.clock = clockBase + 1000
	expectCode(t, "prime", rig.v.Verify(rig.request(clockBase+1000, 1)), "")

	rig.clock = clockBase
	expectCode(t, "ts at raw time", rig.v.Verify(rig.request(clockBase, 2)), jack.CodeTimestampOutOfWindow)
	expectCode(t, "ts at high-water mark", rig.v.Verify(rig.request(clockBase+1000, 3)), "")
}

func TestClockMovingForwardStillWorks(t *testing.T) {
	rig := newClockRig(t)
	for i, step := range []int64{0, 10, 20, 500} {
		rig.clock = clockBase + step
		expectCode(t, "forward", rig.v.Verify(rig.request(rig.clock, byte(i+1))), "")
	}
	rig.clock = clockBase + 500
	expectCode(t, "stale ts", rig.v.Verify(rig.request(clockBase+10, 9)), jack.CodeTimestampOutOfWindow)
}

func TestMiddlewareRefusesNonOriginFormTargets(t *testing.T) {
	for _, target := range []string{"http://host.example/mcp", "*", "host.example:443", "/a b", "/mcp?q=\xc3\xa9"} {
		h := newHarness(t, 0, okHandler)
		req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
		req.RequestURI = target
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != jack.CodeInvalidRequest {
			t.Fatalf("%q: got %d %s", target, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Jack-Auth") != "" {
			t.Fatalf("%q: refusal must be unsigned", target)
		}
		if h.next.Load() != 0 || h.native.calls.Load() != 0 {
			t.Fatalf("%q: nothing downstream may be reached", target)
		}
	}
}

func TestMiddlewareDropsTheFragmentBeforeVerifying(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	req.RequestURI = "/mcp#x"
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fragment request: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareSignsOverRawPercentEncodedTarget(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp?q=%C3%A9", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestOriginFormTarget(t *testing.T) {
	cases := map[string]bool{
		"/": true, "/mcp?q=%C3%A9": true, "": false, "*": false,
		"http://h/p": false, "h:1": false, "/p#f": true,
		"/mcp?q=é": false, "/a b": false, "/a\x7fb": false, "/a\tb": false,
	}
	for raw, want := range cases {
		if got := originFormTarget(raw); got != want {
			t.Fatalf("originFormTarget(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestSignedTargetDropsTheFragment(t *testing.T) {
	for raw, want := range map[string]string{"/p": "/p", "/p?q=1": "/p?q=1", "/p#f": "/p", "/p?q=1#f#g": "/p?q=1", "/#": "/"} {
		if got := signedTarget(raw); got != want {
			t.Fatalf("signedTarget(%q) = %q, want %q", raw, got, want)
		}
	}
}
