package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// testPrivateKey loads a fixture signing key by name (same body as the root
// helper; the fixtures are shared through the spec package).
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

func signedVerifierRequest(t *testing.T, key ed25519.PrivateKey, aud, method, target string, ts int64, nonceByte byte, body []byte) Request {
	t.Helper()
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonce := jack.EncodeBase64URL(bytes.Repeat([]byte{nonceByte}, 16))
	signing := jack.RequestSigningString(method, target, aud, kid, ts, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	auth := jack.RequestAuth{Kid: kid, TS: ts, Nonce: nonce, Sig: sig}
	return Request{Method: method, Target: target, AuthValues: []string{jack.FormatRequestAuth(auth)}, Body: body}
}

// TestNewVerifierAudControlChars pins the spec 01 section 3.1 aud rules: the
// configured audience must be non-empty and must not contain control
// characters (bytes below 0x20 or 0x7f), while an ordinary value is accepted.
func TestNewVerifierAudControlChars(t *testing.T) {
	newCfg := func(aud string) Config {
		return Config{Aud: aud, State: NewMemoryState(), Nonces: NewNonceStore()}
	}
	if _, err := NewVerifier(newCfg("https://svc.example.test")); err != nil {
		t.Fatalf("NewVerifier rejected an ordinary aud: %v", err)
	}
	for _, aud := range []string{"a\nb", "a\rb", "a\x00b", "a\tb", "a\x7fb"} {
		_, err := NewVerifier(newCfg(aud))
		if err == nil {
			t.Fatalf("NewVerifier accepted aud with control character %q", aud)
		}
		if !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("NewVerifier error for aud %q = %v, want a control-character rejection", aud, err)
		}
	}
	if _, err := NewVerifier(newCfg("")); err == nil {
		t.Fatal("NewVerifier accepted an empty aud")
	}
}

// TestVolatileWindowValidationAndDefault pins the volatile request window to
// the spec 01 section 4 Request time bounds (task 165).
func TestVolatileWindowValidationAndDefault(t *testing.T) {
	const wantError = "server: window must be 0 (default 30) or an integer between 1 and 120 seconds"
	newConfig := func() Config {
		return Config{Aud: "svc", State: NewMemoryState(), Nonces: NewNonceStore()}
	}
	for _, window := range []int64{-1, 121} {
		cfg := newConfig()
		cfg.Window = window
		if _, err := NewVerifier(cfg); err == nil || err.Error() != wantError {
			t.Fatalf("Window=%d error = %v, want %q", window, err, wantError)
		}
	}
	for _, tc := range []struct {
		name   string
		window int64
		set    bool
		want   int64
	}{
		{name: "zero defaults", window: 0, set: true, want: DefaultWindow},
		{name: "omitted defaults", want: DefaultWindow},
		{name: "minimum", window: 1, set: true, want: 1},
		{name: "maximum", window: 120, set: true, want: 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig()
			if tc.set {
				cfg.Window = tc.window
			}
			v, err := NewVerifier(cfg)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if v.cfg.Window != tc.want {
				t.Fatalf("effective Window = %d, want %d", v.cfg.Window, tc.want)
			}
		})
	}
}

func TestClockStepBackKeepsExpiredKeyInactive(t *testing.T) {
	key := testPrivateKey(t, "alice")
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	high := testNow + 10
	// TS matches both samples; expiration between them distinguishes raw from effective time.
	expires := testNow + 5
	state := NewMemoryState()
	if err := state.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "alice", NotAfter: &expires})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clock := high
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(),
		Now: func() int64 { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}

	first := v.Verify(signedVerifierRequest(t, key, "svc", "GET", "/mcp", high, 1, nil))
	if first.Accepted || first.Code != jack.CodeKeyInactive {
		t.Fatalf("high-time request = %+v, want key_inactive", first)
	}
	clock = testNow
	// Task 165 / spec 01 section 4 Request time: a lower clock sample cannot reactivate a key expired at the high-water time.
	lower := v.Verify(signedVerifierRequest(t, key, "svc", "GET", "/mcp", testNow, 2, nil))
	if lower.Accepted || lower.Code != jack.CodeKeyInactive {
		t.Fatalf("lower-time request = %+v, want key_inactive", lower)
	}
}

type verifierTestNativeFunc func(*NativeCall) (NativeResult, *jack.Error)

func (f verifierTestNativeFunc) Call(call *NativeCall) (NativeResult, *jack.Error) {
	return f(call)
}

func TestClockStepBackUsesEffectiveTimeForNativeCallAndAudit(t *testing.T) {
	key := testPrivateKey(t, "root")
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := NewMemoryState()
	if err := state.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "root", Admin: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	high := testNow + 10
	clock := high
	var callNow int64
	audit := NewMemoryAuditSink()
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(), Window: 30,
		Native: verifierTestNativeFunc(func(call *NativeCall) (NativeResult, *jack.Error) {
			callNow = call.Now
			call.Target = "clock-target"
			return NativeResult{}, nil
		}),
		Audit: audit, Now: func() int64 { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	prime := v.Verify(signedVerifierRequest(t, key, "svc", "GET", "/mcp", high, 1, nil))
	if !prime.Accepted {
		t.Fatalf("high-time priming request = %+v, want accepted", prime)
	}
	clock = testNow
	body := toolCallBody(ToolAdminInviteList)
	// Task 165 / spec 01 section 4 Request time: native operations and their audit events use effective time after a backward step.
	res := v.Verify(signedVerifierRequest(t, key, "svc", "POST", "/mcp", testNow, 2, body))
	defer res.Done()
	if !res.Accepted || !res.Native || callNow != high || res.Audit == nil || res.Audit.Time != high {
		t.Fatalf("native result = %+v, NativeCall.Now=%d; want accepted call/audit at %d", res, callNow, high)
	}
	events := audit.Events()
	if len(events) != 1 || events[0].Time != high {
		t.Fatalf("audit events = %+v, want one event at %d", events, high)
	}
}

// countingNative counts calls and returns a fixed structured result.
type countingNative struct {
	calls      int
	structured any
}

func (n *countingNative) Call(call *NativeCall) (NativeResult, *jack.Error) {
	n.calls++
	return NativeResult{Structured: n.structured}, nil
}

// registeredAlice returns a memory state holding alice's active key and the
// key's id.
func registeredAlice(t *testing.T, key ed25519.PrivateKey) (*MemoryState, string) {
	t.Helper()
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := NewMemoryState()
	if err := state.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "alice"})
		return nil
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return state, kid
}

// TestClassifyOnlyDefersNativeDispatch pins the two-phase verification: a
// ClassifyOnly Verify authenticates and classifies a valid signed jack.whoami
// POST without calling the native tool, and Dispatch runs it exactly once.
func TestClassifyOnlyDefersNativeDispatch(t *testing.T) {
	key := testPrivateKey(t, "alice")
	state, kid := registeredAlice(t, key)
	native := &countingNative{structured: map[string]any{"kid": kid}}
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(), Native: native,
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	req := signedVerifierRequest(t, key, "svc", "POST", "/mcp", testNow, 7, toolCallBody(ToolWhoAmI))
	req.ClassifyOnly = true
	res := v.Verify(req)
	defer res.Done()

	if res.Accepted || !res.Pending || res.HTTPStatus != 0 {
		t.Fatalf("pending result = %+v, want Accepted=false Pending=true HTTPStatus=0", res)
	}
	if res.Kid != kid || res.Identity == nil || res.RequestSig == "" || !res.Native || res.Tool != ToolWhoAmI {
		t.Fatalf("classified result = %+v, want identity, sig, native jack.whoami for %s", res, kid)
	}
	if native.calls != 0 {
		t.Fatalf("native calls after Verify = %d, want 0", native.calls)
	}
	if res.Audit != nil {
		t.Fatalf("audit = %+v before dispatch, want none (whoami is not audited)", res.Audit)
	}

	out := v.Dispatch(res)
	if !out.Accepted || out.Pending || native.calls != 1 || out.Structured == nil {
		t.Fatalf("dispatched result = %+v, native calls=%d; want accepted with one call and structured content", out, native.calls)
	}
	if out.Kid != kid || out.Identity == nil || out.RequestSig != res.RequestSig {
		t.Fatalf("dispatched result = %+v, want the authenticated identity, kid and sig preserved", out)
	}

	// A second Dispatch is a no-op; the deferred step already ran.
	again := v.Dispatch(out)
	if !again.Accepted || native.calls != 1 {
		t.Fatalf("second dispatch = %+v, native calls=%d; want a no-op", again, native.calls)
	}
}

// TestClassifyOnlyAuditsAtDispatch pins that the audit event of an audited
// native tool is written by Dispatch, not by the classifying Verify.
func TestClassifyOnlyAuditsAtDispatch(t *testing.T) {
	key := testPrivateKey(t, "alice")
	state, _ := registeredAlice(t, key)
	native := &countingNative{}
	audit := NewMemoryAuditSink()
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(), Native: native,
		Audit: audit, Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	req := signedVerifierRequest(t, key, "svc", "POST", "/mcp", testNow, 8, toolCallBody(ToolAdminUserList))
	req.ClassifyOnly = true
	res := v.Verify(req)
	defer res.Done()
	if !res.Pending || res.Accepted || res.Audit != nil || len(audit.Events()) != 0 {
		t.Fatalf("pending result = %+v, events=%d; want pending with no audit event yet", res, len(audit.Events()))
	}

	out := v.Dispatch(res)
	events := audit.Events()
	if !out.Accepted || out.Audit == nil || len(events) != 1 || events[0].Tool != ToolAdminUserList {
		t.Fatalf("dispatched result = %+v, events=%+v; want one %s audit event", out, events, ToolAdminUserList)
	}
	if events[0].Outcome != AuditSuccess {
		t.Fatalf("audit outcome = %q, want %q", events[0].Outcome, AuditSuccess)
	}
}
