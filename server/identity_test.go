package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// identityState builds a MemoryState with the fixture root and alice keys,
// both admin, so tests can demote alice the way the protocol would.
func identityState(t *testing.T) *MemoryState {
	t.Helper()
	st := NewMemoryState()
	err := st.Update(func(e *StateEdit) error {
		for _, name := range []string{"root", "alice"} {
			pub := testPrivateKey(t, name).Public().(ed25519.PublicKey)
			e.PutKey(RegistryEntry{
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
	ids    []Identity
	okSeen bool
}

func (p *identityProbe) handle(w http.ResponseWriter, r *http.Request) {
	id, ok := IdentityFromContext(r.Context())
	p.mu.Lock()
	p.ids = append(p.ids, id)
	p.okSeen = p.okSeen || ok
	p.mu.Unlock()
	okHandler(w, r)
}

func (p *identityProbe) identity(i int) (Identity, bool) {
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
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: st, Nonces: NewNonceStore(),
		Native: NewNativeTools(NativeOptions{}), Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	inHandler := make(chan struct{})
	demoted := make(chan struct{})
	var demotedOnce sync.Once
	releaseDemoted := func() { demotedOnce.Do(func() { close(demoted) }) }
	var inFlight1, inFlight2 Identity
	var inFlight2Seen bool
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id1, ok := IdentityFromContext(r.Context())
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
			id2, ok2 := IdentityFromContext(r.Context())
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
	if err := st.Update(func(e *StateEdit) error {
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
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: st, Nonces: NewNonceStore(),
		Native: NewNativeTools(NativeOptions{}), Now: func() int64 { return testNow },
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
	if err := st.Update(func(e *StateEdit) error {
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
