package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/rpcbody"
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
// POST without calling the native tool, and dispatch runs it exactly once.
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

	out := v.dispatch(res)
	if !out.Accepted || out.Pending || native.calls != 1 || out.Structured == nil {
		t.Fatalf("dispatched result = %+v, native calls=%d; want accepted with one call and structured content", out, native.calls)
	}
	if out.Kid != kid || out.Identity == nil || out.RequestSig != res.RequestSig {
		t.Fatalf("dispatched result = %+v, want the authenticated identity, kid and sig preserved", out)
	}

	// A second dispatch has nothing pending; the deferred step already ran.
	again := v.dispatch(out)
	if !again.Accepted || native.calls != 1 {
		t.Fatalf("second dispatch = %+v, native calls=%d; want a no-op", again, native.calls)
	}
}

// TestClassifyOnlyAuditsAtDispatch pins that the audit event of an audited
// native tool is written by dispatch, not by the classifying Verify.
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

	out := v.dispatch(res)
	events := audit.Events()
	if !out.Accepted || out.Audit == nil || len(events) != 1 || events[0].Tool != ToolAdminUserList {
		t.Fatalf("dispatched result = %+v, events=%+v; want one %s audit event", out, events, ToolAdminUserList)
	}
	if events[0].Outcome != AuditSuccess {
		t.Fatalf("audit outcome = %q, want %q", events[0].Outcome, AuditSuccess)
	}
}

// TestPendingDispatchIsExclusive pins the binding of a Pending Result: it is
// single-use, only its issuing Verifier may dispatch it, and it is unusable
// after Done released the request. A refused dispatch runs no native tool.
func TestPendingDispatchIsExclusive(t *testing.T) {
	newVerifier := func(t *testing.T, key ed25519.PrivateKey) (*Verifier, *countingNative) {
		t.Helper()
		state, _ := registeredAlice(t, key)
		native := &countingNative{}
		v, err := NewVerifier(Config{
			Aud: "svc", State: state, Nonces: NewNonceStore(), Native: native,
			Now: func() int64 { return testNow },
		})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		return v, native
	}
	pending := func(t *testing.T, v *Verifier, key ed25519.PrivateKey, nonce byte) Result {
		t.Helper()
		req := signedVerifierRequest(t, key, "svc", "POST", "/mcp", testNow, nonce, toolCallBody(ToolWhoAmI))
		req.ClassifyOnly = true
		res := v.Verify(req)
		if !res.Pending || res.Accepted {
			t.Fatalf("pending result = %+v, want a Pending result", res)
		}
		return res
	}
	wantRefusal := func(t *testing.T, out Result) {
		t.Helper()
		if out.HTTPStatus != 500 || out.Code != "internal_error" || out.Accepted || out.Pending {
			t.Fatalf("refused dispatch = %+v, want 500 internal_error", out)
		}
	}

	t.Run("a second dispatch of the same result fails", func(t *testing.T) {
		key := testPrivateKey(t, "alice")
		v, native := newVerifier(t, key)
		res := pending(t, v, key, 21)
		defer res.Done()

		if out := v.dispatch(res); !out.Accepted || native.calls != 1 {
			t.Fatalf("first dispatch = %+v, native calls=%d; want one accepted call", out, native.calls)
		}
		wantRefusal(t, v.dispatch(res))
		if native.calls != 1 {
			t.Fatalf("native calls after a refused second dispatch = %d, want 1", native.calls)
		}
	})

	t.Run("another verifier cannot dispatch the result", func(t *testing.T) {
		key := testPrivateKey(t, "alice")
		issuer, issued := newVerifier(t, key)
		other, foreign := newVerifier(t, key)
		res := pending(t, issuer, key, 22)
		defer res.Done()

		wantRefusal(t, other.dispatch(res))
		if foreign.calls != 0 || issued.calls != 0 {
			t.Fatalf("native calls after a foreign dispatch = %d/%d, want 0/0", foreign.calls, issued.calls)
		}
		if out := issuer.dispatch(res); !out.Accepted || issued.calls != 1 {
			t.Fatalf("issuer dispatch = %+v, native calls=%d; want the pending call to remain usable", out, issued.calls)
		}
	})

	t.Run("dispatch after Done fails", func(t *testing.T) {
		key := testPrivateKey(t, "alice")
		v, native := newVerifier(t, key)
		res := pending(t, v, key, 23)
		res.Done()
		wantRefusal(t, v.dispatch(res))
		if native.calls != 0 {
			t.Fatalf("native calls after dispatch of a released result = %d, want 0", native.calls)
		}
	})
}

// blockingNative blocks in Call until release is closed and reports that it
// started, so a test can hold a claimed dispatch in flight. finished records
// that Call actually returned, which lets a lease observe whether it was
// released before or after the native call ended.
type blockingNative struct {
	started  chan struct{}
	release  chan struct{}
	finished atomic.Bool
}

func (n *blockingNative) Call(*NativeCall) (NativeResult, *jack.Error) {
	close(n.started)
	<-n.release
	n.finished.Store(true)
	return NativeResult{}, nil
}

// orderingLease records the order of the durable nonce release against the
// native call: early stays false only when Release runs after the native call
// reported finished, which is exactly what Done must guarantee.
type orderingLease struct {
	native   *atomic.Bool
	releases atomic.Int32
	early    atomic.Bool
}

func (l *orderingLease) Valid() bool { return true }

func (l *orderingLease) Release() {
	if !l.native.Load() {
		l.early.Store(true)
	}
	l.releases.Add(1)
}

// TestDoneWaitsForClaimedDispatchLease pins the lease ordering: a claimed
// dispatch keeps its request alive, so Done waits for the native call to return
// before the durable lease is released. The block is proven without any timer:
// markReleased sets pending.released under pending.mu before it blocks on the
// dispatch channel, so observing that flag means the Done goroutine is already
// waiting, and the lease ordering itself is checked by orderingLease.early.
func TestDoneWaitsForClaimedDispatchLease(t *testing.T) {
	key := testPrivateKey(t, "alice")
	state, _ := registeredAlice(t, key)
	native := &blockingNative{started: make(chan struct{}), release: make(chan struct{})}
	v, err := NewVerifier(Config{
		Aud: "svc", State: state, Nonces: NewNonceStore(), Native: native,
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// A hand-built pending result: this test drives the dispatch and the lease
	// directly, without the authentication pipeline.
	lease := &orderingLease{native: &native.finished}
	res := Result{
		Kid: "kid", RequestSig: "sig", NonceRecorded: true,
		admission: &admissionLease{lease: lease},
		pending: &pendingDispatch{
			issuer: v,
			now:    testNow,
			msg:    rpcbody.RPCMessage{Kind: rpcbody.KindRequest, Method: "tools/call", Tool: ToolWhoAmI, HasTool: true},
		},
	}

	dispatched := make(chan Result, 1)
	go func() { dispatched <- v.dispatch(res) }()
	<-native.started
	pending := res.pending

	done := make(chan struct{})
	go func() {
		res.Done()
		close(done)
	}()

	// Poll the handshake flag instead of sleeping: once markReleased has set
	// released, the Done goroutine is blocked on the dispatch channel, so the
	// checks below run after the wait is reached rather than merely soon after
	// Done was started. Gosched bounds the loop in iterations, not in time.
	reached := false
	for i := 0; i < 10000; i++ {
		pending.mu.Lock()
		reached = pending.released
		pending.mu.Unlock()
		if reached {
			break
		}
		runtime.Gosched()
	}
	if !reached {
		t.Fatal("Done never marked the pending result released")
	}

	select {
	case <-done:
		t.Fatal("Done released the request while the claimed native call was still running")
	default:
	}
	if got := lease.releases.Load(); got != 0 {
		t.Fatalf("lease releases = %d while the native call runs, want 0", got)
	}

	close(native.release)
	if out := <-dispatched; !out.Accepted {
		t.Fatalf("dispatch result = %+v, want accepted", out)
	}
	<-done
	if lease.early.Load() {
		t.Fatal("Done released the lease before the native call returned")
	}
	if got := lease.releases.Load(); got != 1 {
		t.Fatalf("lease releases = %d after Done returned, want 1", got)
	}
}
