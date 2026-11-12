package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

type admissionSpy struct {
	calls   int
	fences  int
	lease   *leaseSpy
	hook    func(NonceAdmission)
	change  func(*NonceReceipt)
	failure *jack.Error
	last    NonceAdmission
}

type leaseSpy struct {
	valid    bool
	releases int
}

func (l *leaseSpy) Valid() bool { return l.valid }
func (l *leaseSpy) Release()    { l.releases++ }
func (s *admissionSpy) Fence()  { s.fences++ }

func (s *admissionSpy) Reserve(request NonceAdmission) (NonceReceipt, NonceLease, *jack.Error) {
	s.calls++
	s.last = request
	if s.failure != nil {
		return NonceReceipt{}, nil, s.failure
	}
	now := request.Now()
	if !request.Validate(now) {
		return NonceReceipt{}, nil, &jack.Error{HTTPStatus: 503, Code: "state_changed"}
	}
	if s.hook != nil {
		s.hook(request)
	}
	receipt := NonceReceipt{
		Version: 1, DeploymentID: "public-test-deployment", StoreGeneration: 1, OwnerGeneration: 1,
		KID: request.KID, Nonce: request.Nonce, Signature: request.Signature,
		RequestHash: jack.BodyHash([]byte(request.SigningBytes)), Timestamp: request.Timestamp,
		RetainUntil: request.Timestamp + request.Window, HighWater: now,
	}
	receipt.OperationID[0] = 1
	receipt.IntentID, _ = NonceIntentID(receipt.DeploymentID, request, receipt.OperationID)
	if s.change != nil {
		s.change(&receipt)
	}
	if s.lease == nil {
		s.lease = &leaseSpy{valid: true}
	}
	return receipt, s.lease, nil
}

func admissionRequest(t *testing.T, store StateStore, now int64) Request {
	t.Helper()
	seed := sha256.Sum256([]byte("mcp-jack public durable admission test"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	if err := store.Update(func(edit *StateEdit) error {
		edit.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "durable-test"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	nonce := jack.EncodeBase64URL(make([]byte, 16))
	signing := jack.RequestSigningString("GET", "/mcp", "test-audience", kid, now, nonce, nil)
	signature := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	header := jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: now, Nonce: nonce, Sig: signature})
	return Request{Method: "GET", Target: "/mcp", AuthValues: []string{header}}
}

func durableVerifier(t *testing.T, state StateStore, storage *admissionSpy, now func() int64) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(Config{Aud: "test-audience", State: state, DurableNonces: storage, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestDurableAdmissionInvalidSignatureNeverCallsStorage(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	request.Target = "/tampered"
	storage := &admissionSpy{}
	result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
	defer result.Done()
	if result.Code != jack.CodeBadSignature || storage.calls != 0 || result.NonceRecorded {
		t.Fatalf("unexpected admission: %+v, calls=%d", result, storage.calls)
	}
}

func TestDurableAdmissionReceiptAndLease(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	storage := &admissionSpy{hook: func(NonceAdmission) {
		if state.mu.TryLock() {
			state.mu.Unlock()
			t.Fatal("reservation did not hold the registry writer gate")
		}
	}}
	result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
	if !result.Accepted || !result.NonceRecorded || storage.calls != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if storage.lease.releases != 0 {
		t.Fatal("lease released before request completion")
	}
	if storage.last.Validate(100) {
		t.Fatal("backend retained an active validation callback")
	}
	if !state.mu.TryLock() {
		t.Fatal("registry gate held across handler execution")
	}
	state.mu.Unlock()
	copy := result
	result.Done()
	copy.Done()
	if storage.lease.releases != 1 {
		t.Fatalf("release count: %d", storage.lease.releases)
	}
}

func TestDurableAdmissionMismatchedReceiptFences(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	storage := &admissionSpy{change: func(receipt *NonceReceipt) { receipt.RequestHash = jack.BodyHash([]byte("other request")) }}
	result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
	defer result.Done()
	if result.Accepted || result.Code != "durability_unavailable" || result.NonceRecorded || storage.fences != 1 || storage.lease.releases != 1 {
		t.Fatalf("receipt mismatch was not fenced: %+v", result)
	}
}

func TestDurableAdmissionUnknownNeverDispatchesOrLeaksDetail(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	storage := &admissionSpy{failure: &jack.Error{HTTPStatus: 503, Code: "durability_unavailable", Message: "sensitive backend detail"}}
	verifier := durableVerifier(t, state, storage, func() int64 { return 100 })
	seed := sha256.Sum256([]byte("mcp-jack public response signer test"))
	dispatched := false
	handler, err := NewHandler(HandlerConfig{Verifier: verifier, ServerKey: ed25519.NewKeyFromSeed(seed[:])}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { dispatched = true }))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("GET", "/mcp", nil)
	httpRequest.Header.Set("Jack-Auth", request.AuthValues[0])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if dispatched || response.Code != 503 || response.Header().Get("Jack-Auth") != "" || storage.fences != 1 || strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("unknown outcome exposed authority: %d %s", response.Code, response.Body.String())
	}
}

func TestDurableAdmissionLateCommitConsumesButDoesNotAuthorize(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	now := int64(100)
	storage := &admissionSpy{hook: func(NonceAdmission) { now = 131 }}
	result := durableVerifier(t, state, storage, func() int64 { return now }).Verify(request)
	defer result.Done()
	if result.Accepted || !result.NonceRecorded || result.Code != jack.CodeTimestampOutOfWindow {
		t.Fatalf("late durable ACK incorrectly authorized: %+v", result)
	}
}

func TestDurableAdmissionRollbackAfterReceiptFences(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	now := int64(100)
	storage := &admissionSpy{hook: func(NonceAdmission) { now = 99 }}
	result := durableVerifier(t, state, storage, func() int64 { return now }).Verify(request)
	defer result.Done()
	if result.Accepted || !result.NonceRecorded || result.Code != "durability_unavailable" || storage.fences != 1 {
		t.Fatalf("rollback after receipt was not fenced: %+v", result)
	}
}

func TestDurableHandlerOwnsLeaseUntilForwardCompletes(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	storage := &admissionSpy{}
	verifier := durableVerifier(t, state, storage, func() int64 { return 100 })
	seed := sha256.Sum256([]byte("mcp-jack public response signer test"))
	handler, err := NewHandler(HandlerConfig{Verifier: verifier, ServerKey: ed25519.NewKeyFromSeed(seed[:])}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if storage.lease.releases != 0 {
			t.Fatal("lease released inside handler")
		}
		w.WriteHeader(200)
	}))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("GET", "/mcp", nil)
	httpRequest.Header.Set("Jack-Auth", request.AuthValues[0])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != 200 || response.Header().Get("Jack-Auth") == "" || storage.lease.releases != 1 {
		t.Fatalf("handler lifecycle: status=%d releases=%d", response.Code, storage.lease.releases)
	}
}

func TestDurableClockPanicReleasesCommittedLease(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	storage := &admissionSpy{}
	calls := 0
	verifier := durableVerifier(t, state, storage, func() int64 {
		calls++
		if calls == 3 {
			panic("public clock test panic")
		}
		return 100
	})
	defer func() {
		if recover() != "public clock test panic" {
			t.Fatal("expected clock panic")
		}
		if storage.lease == nil || storage.lease.releases != 1 {
			t.Fatal("committed lease leaked on clock panic")
		}
		if !state.mu.TryLock() {
			t.Fatal("registry gate leaked on panic")
		}
		state.mu.Unlock()
	}()
	verifier.Verify(request)
}

type uncoordinatedState struct{ StateStore }

func TestDurableAdmissionRequiresExplicitProfileAndCoordination(t *testing.T) {
	storage := &admissionSpy{}
	for _, config := range []Config{
		{Aud: "test", State: uncoordinatedState{NewMemoryState()}, DurableNonces: storage},
		{Aud: "test", State: NewMemoryState(), Nonces: NewNonceStore(), DurableNonces: storage},
		{Aud: "test", State: NewMemoryState(), DurableNonces: storage, Window: 121},
		{Aud: "test", State: NewMemoryState(), DurableNonces: storage, Window: -1},
	} {
		if _, err := NewVerifier(config); err == nil {
			t.Fatal("unsafe durable configuration accepted")
		}
	}
}
