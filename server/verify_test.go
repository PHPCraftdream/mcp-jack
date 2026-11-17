package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// registryFromFixture loads the default fixture registry into a MemoryState.
func registryFromFixture(t *testing.T, doc spec.RegistryDocument) *MemoryState {
	t.Helper()
	return stateFromEntries(t, doc.Keys)
}

func stateFromEntries(t *testing.T, entries []spec.RegistryEntry) *MemoryState {
	t.Helper()
	st := NewMemoryState()
	err := st.Update(func(e *StateEdit) error {
		for _, entry := range entries {
			// The fixture registry omits admin for non-admin keys, so a nil
			// pointer is false.
			e.PutKey(RegistryEntry{
				Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name,
				Admin:     entry.Admin != nil && *entry.Admin,
				NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return st
}

func jackAuthValues(headers []spec.HeaderPair) []string {
	var values []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Jack-Auth") {
			values = append(values, h.Value)
		}
	}
	return values
}

// matchValue compares decoded JSON values; the string "<b64u43>" in want
// matches any canonical base64url encoding of 32 bytes (invite codes and ids
// are random in real servers, so fixtures cannot contain them).
func matchValue(want, got any) bool {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		if !ok {
			return false
		}
		if w == "<b64u43>" {
			_, err := jack.DecodeBase64URLFixed(g, 32)
			return err == nil
		}
		return w == g
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !matchValue(w[i], g[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present || !matchValue(wv, gv) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(want, got)
	}
}

// checkOutcome compares a verifier result with a fixture expectation.
func checkOutcome(t *testing.T, label string, res Result, want spec.Expect) {
	t.Helper()
	if (want.Result == "accept") != res.Accepted {
		t.Fatalf("%s: Accepted = %v (%d %s), want result %q", label, res.Accepted, res.HTTPStatus, res.Code, want.Result)
	}
	if res.Accepted {
		if res.Kid != want.Kid {
			t.Fatalf("%s: Kid = %q, want %q", label, res.Kid, want.Kid)
		}
	} else if res.HTTPStatus != want.HTTPStatus || res.Code != want.Code {
		t.Fatalf("%s: rejection = %d %s, want %d %s", label, res.HTTPStatus, res.Code, want.HTTPStatus, want.Code)
	}
	if res.NonceRecorded != want.NonceRecorded {
		t.Fatalf("%s: NonceRecorded = %v, want %v", label, res.NonceRecorded, want.NonceRecorded)
	}

	switch {
	case want.Audit == nil && res.Audit != nil:
		t.Fatalf("%s: unexpected audit event %+v", label, *res.Audit)
	case want.Audit != nil && res.Audit == nil:
		t.Fatalf("%s: missing audit event, want %+v", label, *want.Audit)
	case want.Audit != nil:
		wantCode := ""
		if want.Audit.Code != nil {
			wantCode = *want.Audit.Code
		}
		a := res.Audit
		if a.Tool != want.Audit.Tool || a.Outcome != want.Audit.Outcome || a.Code != wantCode || a.ActorKid != want.Audit.ActorKid {
			t.Fatalf("%s: audit = %+v, want %+v (code %q)", label, *a, *want.Audit, wantCode)
		}
	}

	if want.Identity != nil {
		if res.Identity == nil || res.Identity.Kid() != want.Identity.Kid || res.Identity.Name() != want.Identity.Name || res.Identity.Admin() != want.Identity.Admin {
			t.Fatalf("%s: identity = %+v, want %s/%s/%v", label, res.Identity, want.Identity.Kid, want.Identity.Name, want.Identity.Admin)
		}
	}

	if len(want.Structured) > 0 {
		gotJSON, err := json.Marshal(res.Structured)
		if err != nil {
			t.Fatalf("%s: marshal structured result: %v", label, err)
		}
		var wantValue, gotValue any
		if err := json.Unmarshal(want.Structured, &wantValue); err != nil {
			t.Fatalf("%s: decode expected structured result: %v", label, err)
		}
		if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
			t.Fatalf("%s: decode structured result: %v", label, err)
		}
		if !matchValue(wantValue, gotValue) {
			t.Fatalf("%s: structured result\n got %s\nwant %s", label, gotJSON, want.Structured)
		}
	}
}

// summarize mirrors the "after" expectation of the sequence vectors. Users
// are sorted by name; invites are every stored invite — durable state, not
// the live listing — sorted by invite id, ties by created_at.
func summarize(st StateStore, now int64) spec.AfterState {
	view := st.View()
	keys := append([]RegistryEntry(nil), view.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	users := make([]spec.UserSummary, 0, len(keys))
	for _, k := range keys {
		users = append(users, spec.UserSummary{
			Kid: k.Kid, PublicKey: k.PublicKey, Name: k.Name, Admin: k.Admin,
			NotBefore: k.NotBefore, NotAfter: k.NotAfter,
		})
	}
	invites := append([]InviteRecord(nil), view.Invites...)
	sort.Slice(invites, func(i, j int) bool {
		if invites[i].InviteID != invites[j].InviteID {
			return invites[i].InviteID < invites[j].InviteID
		}
		return invites[i].CreatedAt < invites[j].CreatedAt
	})
	summaries := make([]spec.InviteSummary, 0, len(invites))
	for _, inv := range invites {
		summaries = append(summaries, spec.InviteSummary{
			InviteID: inv.InviteID, Admin: inv.Admin, CreatedBy: inv.CreatedBy,
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt, KeyTTLSeconds: inv.KeyTTLSeconds,
		})
	}
	return spec.AfterState{Users: users, Invites: summaries}
}

// afterMatches compares the post-step state with the fixture expectation,
// "<b64u43>" wildcards included. Users are matched positionally (sorted by
// name on both sides); invites are matched as an unordered multiset because
// an implementation-created invite id sorts by an unknown text.
func afterMatches(t *testing.T, label string, want spec.AfterState, st StateStore, now int64) bool {
	t.Helper()
	got := summarize(st, now)
	if len(got.Users) != len(want.Users) {
		t.Fatalf("%s: users after the step: %d entries, want %d\n got %+v\nwant %+v", label, len(got.Users), len(want.Users), got.Users, want.Users)
	}
	for i := range want.Users {
		gotJSON, err := json.Marshal(got.Users[i])
		if err != nil {
			t.Fatalf("%s: marshal user: %v", label, err)
		}
		wantJSON, err := json.Marshal(want.Users[i])
		if err != nil {
			t.Fatalf("%s: marshal expected user: %v", label, err)
		}
		var gotVal, wantVal any
		if err := json.Unmarshal(gotJSON, &gotVal); err != nil {
			t.Fatalf("%s: decode user: %v", label, err)
		}
		if err := json.Unmarshal(wantJSON, &wantVal); err != nil {
			t.Fatalf("%s: decode expected user: %v", label, err)
		}
		if !matchValue(wantVal, gotVal) {
			t.Fatalf("%s: user %d after the step\n got %s\nwant %s", label, i, gotJSON, wantJSON)
		}
	}
	if len(got.Invites) != len(want.Invites) {
		t.Fatalf("%s: invites after the step: %d records, want %d\n got %+v\nwant %+v", label, len(got.Invites), len(want.Invites), got.Invites, want.Invites)
	}
	consumed := make([]bool, len(got.Invites))
	for _, w := range want.Invites {
		wantJSON, err := json.Marshal(w)
		if err != nil {
			t.Fatalf("%s: marshal expected invite: %v", label, err)
		}
		var wantVal any
		if err := json.Unmarshal(wantJSON, &wantVal); err != nil {
			t.Fatalf("%s: decode expected invite: %v", label, err)
		}
		found := false
		for i, g := range got.Invites {
			if consumed[i] {
				continue
			}
			gotJSON, err := json.Marshal(g)
			if err != nil {
				t.Fatalf("%s: marshal invite: %v", label, err)
			}
			var gotVal any
			if err := json.Unmarshal(gotJSON, &gotVal); err != nil {
				t.Fatalf("%s: decode invite: %v", label, err)
			}
			if matchValue(wantVal, gotVal) {
				consumed[i] = true
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: no stored invite matches %+v\n got %+v", label, w, got.Invites)
		}
	}
	return true
}

// identityFromWrappedHandler runs an accepted fixture case through the real
// middleware stack in front of a probe and returns the identity the wrapped
// handler read from its request context. The plain Verify comparison proves
// the verifier computes the identity; this proves the middleware injects that
// snapshot into the forwarded request (spec 02 section 3).
func identityFromWrappedHandler(t *testing.T, c spec.RequestCase, body []byte, st StateStore, now int64) (Identity, bool) {
	t.Helper()
	nonces := NewNonceStore()
	for _, n := range c.State.NonceCache {
		nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
	}
	v, err := NewVerifier(Config{
		Aud: c.State.Aud, State: st, Nonces: nonces,
		Native: NewNativeTools(NativeOptions{}),
		Window: int64(c.State.WindowSeconds), Now: func() int64 { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	var captured Identity
	var ok bool
	probe := func(w http.ResponseWriter, r *http.Request) {
		captured, ok = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")}, http.HandlerFunc(probe))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(c.Request.Method, c.Request.Target, bytes.NewReader(body))
	for _, hd := range c.Request.Headers {
		req.Header.Add(hd.Name, hd.Value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrapped-handler run: status = %d, body %s, want a forwarded accept", rec.Code, rec.Body.String())
	}
	return captured, ok
}

// TestRequestVectors runs every single-request fixture case through the
// verifier, protocol-native tools included.
func TestRequestVectors(t *testing.T) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no request vectors")
	}

	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			body, err := c.Request.Body()
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			st := registryFromFixture(t, registry)
			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: st, Nonces: nonces,
				Native: NewNativeTools(NativeOptions{}),
				Window: int64(c.State.WindowSeconds), Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			res := v.Verify(Request{
				Method: c.Request.Method, Target: c.Request.Target,
				AuthValues: jackAuthValues(c.Request.Headers), Body: body,
			})
			checkOutcome(t, c.ID, res, c.Expect)
			if c.Expect.Identity != nil {
				id, ok := identityFromWrappedHandler(t, c, body, st, now)
				if !ok {
					t.Fatalf("%s: the wrapped handler saw no identity", c.ID)
				}
				if id.Kid() != c.Expect.Identity.Kid || id.Name() != c.Expect.Identity.Name || id.Admin() != c.Expect.Identity.Admin {
					t.Fatalf("%s: wrapped-handler identity = %s/%s/%v, want %s/%s/%v", c.ID,
						id.Kid(), id.Name(), id.Admin(), c.Expect.Identity.Kid, c.Expect.Identity.Name, c.Expect.Identity.Admin)
				}
			}
		})
	}
}

func inviteFromFixture(i spec.InviteRecord) InviteRecord {
	return InviteRecord{
		InviteID: i.InviteID, Admin: i.Admin != nil && *i.Admin, CreatedBy: i.CreatedBy,
		CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt, KeyTTLSeconds: i.KeyTTLSeconds,
	}
}

// TestAdminSequences replays the state-changing sequences: enrollment, key
// rotation, user and invite administration. Each step runs against the state
// left by the previous one and is compared with its expectation and with the
// state summary recorded after it.
func TestAdminSequences(t *testing.T) {
	vectors, err := spec.LoadAdminVectors()
	if err != nil {
		t.Fatalf("LoadAdminVectors: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no admin vectors")
	}

	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			st := stateFromEntries(t, c.State.Registry)
			if err := st.Update(func(e *StateEdit) error {
				for _, i := range c.State.Invites {
					e.PutInvite(inviteFromFixture(i))
				}
				return nil
			}); err != nil {
				t.Fatalf("seed invites: %v", err)
			}
			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: st, Nonces: nonces,
				Native: NewNativeTools(NativeOptions{}), Window: int64(c.State.WindowSeconds),
				Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			for i, step := range c.Steps {
				body, err := step.Request.Body()
				if err != nil {
					t.Fatalf("step %d: Body: %v", i, err)
				}
				label := fmt.Sprintf("%s step %d", c.ID, i)
				res := v.Verify(Request{
					Method: step.Request.Method, Target: step.Request.Target,
					AuthValues: jackAuthValues(step.Request.Headers), Body: body,
				})
				checkOutcome(t, label, res, step.Expect)
				if step.Expect.After != nil {
					afterMatches(t, label, *step.Expect.After, st, now)
				}
			}
		})
	}
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

func signedVerifierRequest(t *testing.T, key ed25519.PrivateKey, aud, method, target string, ts int64, nonceByte byte, body []byte) Request {
	t.Helper()
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonce := jack.EncodeBase64URL(bytes.Repeat([]byte{nonceByte}, 16))
	signing := jack.RequestSigningString(method, target, aud, kid, ts, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	auth := jack.RequestAuth{Kid: kid, TS: ts, Nonce: nonce, Sig: sig}
	return Request{Method: method, Target: target, AuthValues: []string{jack.FormatRequestAuth(auth)}, Body: body}
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

func TestClockStepBackDoesNotReviveExpiredEnrollmentInvite(t *testing.T) {
	rawCode, codeJSON := gateCode()
	high := testNow + 10
	state, nonces := NewMemoryState(), NewNonceStore()
	gateInvite(t, state, rawCode, high)
	clock := high
	v, err := NewVerifier(Config{
		Aud: gateAud, State: state, Nonces: nonces, Native: NewNativeTools(NativeOptions{}),
		Now: func() int64 { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := gateEnrollRequest(t, codeJSON)
	// This valid timestamp is within the window at both samples; invite liveness is decisive.
	request = signedVerifierRequest(t, testPrivateKey(t, "newbie"), gateAud, "POST", "/mcp", high, 1, request.Body)
	first := v.Verify(request)
	if first.Accepted || first.Code != jack.CodeUnknownKey {
		t.Fatalf("high-time enrollment = %+v, want unknown_key", first)
	}
	clock = testNow
	// Task 165 / spec 01 section 4 Request time: step 4 must use effective time, not revive or consume this invite at the lower sample.
	request = signedVerifierRequest(t, testPrivateKey(t, "newbie"), gateAud, "POST", "/mcp", testNow, 2, request.Body)
	lower := v.Verify(request)
	if lower.Accepted || lower.Code != jack.CodeUnknownKey {
		t.Fatalf("lower-time enrollment = %+v, want unknown_key", lower)
	}
	if _, ok := state.LookupInvite(inviteIDOf(rawCode)); !ok || nonces.Len() != 0 {
		t.Fatalf("expired invite was consumed or nonce recorded: invite remains=%v, nonces=%d", ok, nonces.Len())
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
