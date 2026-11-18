package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	auditimpl "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	"github.com/PHPCraftdream/mcp-jack/server/internal/native"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

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

// TestMiddlewareSignsAdminGateRejection checks a non-admin calling an admin
// tool through the REAL native implementation: the native gate rejects before
// argument parsing with admin_required, the rejection is signed, the wrapped
// handler is not reached, the gate rejection reaches the tool layer and is
// audited (spec 03 section 8), and the durable state is unchanged.
func TestMiddlewareSignsAdminGateRejection(t *testing.T) {
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	st := registryFromFixture(t, registry)
	audit := auditimpl.NewMemoryAuditSink()
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: st, Nonces: nonceimpl.NewNonceStore(),
		Audit: audit, Native: native.NewNativeTools(native.NativeOptions{}),
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	serverKey := testPrivateKey(t, "svc")
	nextCalls := 0
	handler, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: serverKey},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalls++
			okHandler(w, r)
		}))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	aliceKey := testPrivateKey(t, "alice")
	before := st.View()
	req, sig := signedRequest(t, aliceKey, "POST", "/mcp", toolCallBody("jack.admin.user.list"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || errorCode(t, rec) != jack.CodeAdminRequired {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, serverKey, sig)
	if nextCalls != 0 {
		t.Fatal("the wrapped handler must not be reached")
	}
	events := audit.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	e := events[0]
	wantKid := jack.KeyID(aliceKey.Public().(ed25519.PublicKey))
	if e.Tool != "jack.admin.user.list" || e.Outcome != verify.AuditFailure || e.Code != jack.CodeAdminRequired || e.ActorName != "alice" || e.ActorKid != wantKid {
		t.Fatalf("audit event = %+v, want the audited admin_required gate rejection", e)
	}
	if !reflect.DeepEqual(st.View(), before) {
		t.Fatal("the rejected admin tool call mutated the durable state")
	}
}

// TestMiddlewareSignsUndefinedNativeToolRejection checks a call for an
// undefined jack.* tool: operation_denied, signed, no forwarding, and no
// audit event (it is not a tool call the protocol knows).
func TestMiddlewareSignsUndefinedNativeToolRejection(t *testing.T) {
	h := newHarness(t, 0, okHandler)
	req, sig := signedRequest(t, testPrivateKey(t, "root"), "POST", "/mcp", toolCallBody("jack.nonsense"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || errorCode(t, rec) != jack.CodeOperationDenied {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if h.next.Load() != 0 {
		t.Fatal("the wrapped handler must not be reached")
	}
	if events := h.audit.Events(); len(events) != 0 {
		t.Fatalf("audit events = %d, want none for an undefined jack.* tool", len(events))
	}
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
	if e.Tool != "jack.admin.user.list" || e.Outcome != verify.AuditSuccess || e.ActorName != "root" || e.Target != "target-1" || e.Time != testNow {
		t.Fatalf("audit event = %+v", e)
	}
}

func TestVerifierDeniesNativeToolsWithoutAnImplementation(t *testing.T) {
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req, _ := signedRequest(t, testPrivateKey(t, "root"), "POST", "/mcp", toolCallBody("jack.whoami"))
	res := v.Verify(verify.Request{Method: req.Method, Target: req.RequestURI, AuthValues: req.Header.Values("Jack-Auth"), Body: toolCallBody("jack.whoami")})
	if res.Accepted || res.HTTPStatus != 403 || res.Code != jack.CodeOperationDenied {
		t.Fatalf("result = %+v", res)
	}
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

// TestMiddlewareHandsIdentityToWrappedHandler checks the only public
// injection path: a forwarded accepted request carries the verified
// {kid, name, admin} of the caller's registry entry into the wrapped
// handler's context, exactly, for admins and non-admins (spec 02 section 3).
func TestMiddlewareHandsIdentityToWrappedHandler(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin bool
	}{{"root", true}, {"alice", false}} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &identityProbe{}
			h := newHarness(t, 0, probe.handle)
			key := testPrivateKey(t, tc.name)
			body := toolCallBody("svc.status")
			req, _ := signedRequest(t, key, "POST", "/mcp", body)
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			got, ok := probe.identity(0)
			if !ok {
				t.Fatal("the wrapped handler saw no identity in its context")
			}
			wantKid := jack.KeyID(key.Public().(ed25519.PublicKey))
			if got.Kid() != wantKid || got.Name() != tc.name || got.Admin() != tc.admin {
				t.Fatalf("identity = %s/%s/%v, want %s/%s/%v", got.Kid(), got.Name(), got.Admin(), wantKid, tc.name, tc.admin)
			}
			if !bytes.Equal(*h.seen, body) {
				t.Fatalf("the wrapped handler saw %q, want the exact signed body", *h.seen)
			}
		})
	}
}

// TestMiddlewareIdentityIgnoresSpoofedRequestData checks that the identity
// comes only from verification: headers, query parameters and body members
// that look like identity data cannot change it (spec 02 section 3).
func TestMiddlewareIdentityIgnoresSpoofedRequestData(t *testing.T) {
	rootPub := testPrivateKey(t, "root").Public().(ed25519.PublicKey)
	rootKid := jack.KeyID(rootPub)
	probe := &identityProbe{}
	h := newHarness(t, 0, probe.handle)
	aliceKey := testPrivateKey(t, "alice")
	// The spoofing data is inside the signed body: it is authenticated data,
	// yet it must not influence the identity.
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"admin":true}}`)
	req, _ := signedRequest(t, aliceKey, "POST", "/mcp", body)
	req.Header.Set("X-Jack-Kid", rootKid)
	req.Header.Set("X-Jack-Name", "root")
	req.Header.Set("X-Jack-Admin", "true")
	req.URL.RawQuery = "admin=true&kid=" + rootKid
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	got, ok := probe.identity(0)
	if !ok {
		t.Fatal("the wrapped handler saw no identity in its context")
	}
	wantKid := jack.KeyID(aliceKey.Public().(ed25519.PublicKey))
	if got.Kid() != wantKid || got.Name() != "alice" || got.Admin() != false {
		t.Fatalf("identity = %s/%s/%v, want %s/%s/%v", got.Kid(), got.Name(), got.Admin(), wantKid, "alice", false)
	}
}

// TestMiddlewareIdentitySnapshotSurvivesInFlightRegistryChange checks the
// snapshot lifecycle: an in-flight forwarded request keeps the identity that
// authentication and the gate saw, even if the registry changes while the
// handler runs; only subsequent requests see the change (spec 02 section 3).
func TestMiddlewareIdentitySnapshotSurvivesInFlightRegistryChange(t *testing.T) {
	st := identityState(t)
	aliceKey := testPrivateKey(t, "alice")
	aliceKid := jack.KeyID(aliceKey.Public().(ed25519.PublicKey))
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: st, Nonces: nonceimpl.NewNonceStore(),
		Native: native.NewNativeTools(native.NativeOptions{}), Now: func() int64 { return testfixture.Now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	inHandler := make(chan struct{})
	demoted := make(chan struct{})
	var demotedOnce sync.Once
	releaseDemoted := func() { demotedOnce.Do(func() { close(demoted) }) }
	var inFlight1, inFlight2 verify.Identity
	var inFlight2Seen bool
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id1, ok := verify.IdentityFromContext(r.Context())
			if !ok {
				t.Error("the wrapped handler saw no identity")
			} else {
				inFlight1 = id1
			}
			close(inHandler)
			select {
			case <-demoted:
			case <-r.Context().Done():
				return
			}
			id2, ok2 := verify.IdentityFromContext(r.Context())
			if !ok2 {
				t.Error("the in-flight re-read saw no identity")
			} else {
				inFlight2, inFlight2Seen = id2, true
			}
			okHandler(w, r)
		}))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := signedRequest(t, aliceKey, "POST", "/mcp", toolCallBody("svc.status"))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	t.Cleanup(func() {
		releaseDemoted()
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for the in-flight HTTP handler during cleanup")
		}
	})
	go func() {
		defer close(done)
		h.ServeHTTP(rec, req)
	}()
	select {
	case <-inHandler:
		select {
		case <-done:
			t.Fatalf("request ended before handler handoff: status %d, body %s", rec.Code, rec.Body.String())
		default:
		}
	case <-done:
		t.Fatalf("request ended before handler handoff: status %d, body %s", rec.Code, rec.Body.String())
	case <-ctx.Done():
		select {
		case <-done:
			t.Fatalf("request ended before handler handoff: status %d, body %s", rec.Code, rec.Body.String())
		default:
			t.Fatal("timed out waiting for handler handoff")
		}
	}

	// Demote alice exactly the way jack.admin.user.set_admin would.
	if err := st.Update(func(e *stateimpl.StateEdit) error {
		entry, ok := e.Key(aliceKid)
		if !ok {
			t.Fatalf("demote: alice (%s) not in state", aliceKid)
		}
		entry.Admin = false
		e.PutKey(entry)
		return nil
	}); err != nil {
		t.Fatalf("demote: %v", err)
	}

	releaseDemoted()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		default:
			t.Fatal("timed out waiting for the in-flight request")
		}
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if inFlight1 == nil {
		t.Fatal("the wrapped handler saw no identity")
	}
	if inFlight1.Admin() != true || inFlight1.Kid() != aliceKid || inFlight1.Name() != "alice" {
		t.Fatalf("in-flight identity = %s/%s/%v, want alice's admin snapshot", inFlight1.Kid(), inFlight1.Name(), inFlight1.Admin())
	}
	if !inFlight2Seen {
		t.Fatal("the in-flight handler never re-read the identity")
	}
	if inFlight2 == nil {
		t.Fatal("the in-flight re-read saw no identity")
	}
	if inFlight2.Kid() != inFlight1.Kid() || inFlight2.Name() != inFlight1.Name() || inFlight2.Admin() != inFlight1.Admin() {
		t.Fatalf("in-flight re-read after the registry change = %s/%s/%v, want the unchanged verification snapshot %s/%s/%v", inFlight2.Kid(), inFlight2.Name(), inFlight2.Admin(), inFlight1.Kid(), inFlight1.Name(), inFlight1.Admin())
	}

	// A request started after the demotion must see the new state.
	after := &identityProbe{}
	h2, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")}, http.HandlerFunc(after.handle))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req2, _ := signedRequest(t, aliceKey, "POST", "/mcp", toolCallBody("svc.status"))
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec2.Code, rec2.Body.String())
	}
	got, ok := after.identity(0)
	if !ok {
		t.Fatal("the wrapped handler saw no identity in its context")
	}
	if got.Admin() || got.Kid() != aliceKid || got.Name() != "alice" {
		t.Fatalf("identity after demotion = %s/%s/%v, want {alice, alice, admin false}", got.Kid(), got.Name(), got.Admin())
	}
}

// TestMiddlewareConcurrentIdentityForwarding checks that concurrent forwarded
// requests each carry a coherent alice snapshot: never a mixed identity, and
// every request started after a completed demotion sees admin false.
func TestMiddlewareConcurrentIdentityForwarding(t *testing.T) {
	st := identityState(t)
	aliceKey := testPrivateKey(t, "alice")
	aliceKid := jack.KeyID(aliceKey.Public().(ed25519.PublicKey))
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: st, Nonces: nonceimpl.NewNonceStore(),
		Native: native.NewNativeTools(native.NativeOptions{}), Now: func() int64 { return testfixture.Now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	probe := &identityProbe{}
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")}, http.HandlerFunc(probe.handle))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	send := func(n int) {
		t.Helper()
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := signedRequest(t, aliceKey, "POST", "/mcp", toolCallBody("svc.status"))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("status = %d, body %s", rec.Code, rec.Body.String())
				}
			}()
		}
		wg.Wait()
	}

	send(4)
	if got := probe.count(); got != 4 {
		t.Fatalf("first batch captured %d identities, want 4", got)
	}

	// Overlap phase: readers race the demotion — the order of close(start)
	// and st.Update is deliberately nondeterministic, so only coherence
	// (never a mixed or fabricated identity) is asserted per read.
	start := make(chan struct{})
	var overlap sync.WaitGroup
	for i := 0; i < 4; i++ {
		overlap.Add(1)
		go func() {
			defer overlap.Done()
			<-start
			req, _ := signedRequest(t, aliceKey, "POST", "/mcp", toolCallBody("svc.status"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, body %s", rec.Code, rec.Body.String())
			}
		}()
	}
	close(start)
	if err := st.Update(func(e *stateimpl.StateEdit) error {
		entry, ok := e.Key(aliceKid)
		if !ok {
			t.Fatalf("demote: alice (%s) not in state", aliceKid)
		}
		entry.Admin = false
		e.PutKey(entry)
		return nil
	}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	overlap.Wait()

	send(4)

	for i := 0; i < 4; i++ {
		got, ok := probe.identity(i)
		if !ok {
			t.Fatalf("request %d: no identity captured", i)
		}
		if got.Kid() != aliceKid || got.Name() != "alice" {
			t.Fatalf("request %d: identity = %s/%s/%v, want alice's kid and name", i, got.Kid(), got.Name(), got.Admin())
		}
		if !got.Admin() {
			t.Fatalf("request %d: identity = %s/%s/%v, want admin true before the demotion", i, got.Kid(), got.Name(), got.Admin())
		}
	}
	for i := 4; i < 8; i++ {
		got, ok := probe.identity(i)
		if !ok {
			t.Fatalf("request %d: no identity captured", i)
		}
		// The demotion overlaps these reads, so only coherence holds:
		// every capture is alice's own identity, whichever side of the
		// change its verification landed on.
		if got.Kid() != aliceKid || got.Name() != "alice" {
			t.Fatalf("request %d: identity = %s/%s/%v, want alice's kid and name", i, got.Kid(), got.Name(), got.Admin())
		}
	}
	for i := 8; i < 12; i++ {
		got, ok := probe.identity(i)
		if !ok {
			t.Fatalf("request %d: no identity captured", i)
		}
		if got.Kid() != aliceKid || got.Name() != "alice" {
			t.Fatalf("request %d: identity = %s/%s/%v, want alice's kid and name", i, got.Kid(), got.Name(), got.Admin())
		}
		if got.Admin() {
			t.Fatalf("request %d: identity = %s/%s/%v, want admin false after the completed demotion", i, got.Kid(), got.Name(), got.Admin())
		}
	}
	if got := probe.count(); got != 12 {
		t.Fatalf("captured %d identities total, want 12", got)
	}
}
