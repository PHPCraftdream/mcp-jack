package server

import (
	"crypto/ed25519"
	"errors"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

type admissionStateHook struct {
	*MemoryState
	withAdmission func(string, func(RegistryEntry, bool) error) error
}

func (state admissionStateHook) WithAdmission(kid string, check func(RegistryEntry, bool) error) error {
	return state.withAdmission(kid, check)
}

type admissionErrorLeaseStore struct {
	*admissionSpy
	lease *leaseSpy
}

func (store *admissionErrorLeaseStore) Reserve(NonceAdmission) (NonceReceipt, NonceLease, *jack.Error) {
	store.admissionSpy.calls++
	return NonceReceipt{}, store.lease, store.admissionSpy.failure
}

type admissionNilLeaseStore struct {
	*admissionSpy
}

func (store admissionNilLeaseStore) Reserve(request NonceAdmission) (NonceReceipt, NonceLease, *jack.Error) {
	receipt, _, err := store.admissionSpy.Reserve(request)
	return receipt, nil, err
}

func TestNonceIntentIDRejectsMalformedIdentityComponents(t *testing.T) {
	admission := NonceAdmission{
		KID:          jack.EncodeBase64URL(make([]byte, ed25519.PublicKeySize)),
		Nonce:        jack.EncodeBase64URL(make([]byte, 16)),
		Signature:    jack.EncodeBase64URL(make([]byte, ed25519.SignatureSize)),
		SigningBytes: "signed request",
	}
	var operation [16]byte
	operation[0] = 1

	// admission.go:NonceIntentID rejects deployment identities outside UTF-8/length bounds before decoding key material.
	if _, err := NonceIntentID("", admission, operation); err == nil || err.Error() != "server: invalid deployment identity" {
		t.Fatalf("empty deployment error = %v", err)
	}
	if _, err := NonceIntentID(string([]byte{0xff}), admission, operation); err == nil || err.Error() != "server: invalid deployment identity" {
		t.Fatalf("invalid UTF-8 deployment error = %v", err)
	}
	if _, err := NonceIntentID(string(make([]byte, 1025)), admission, operation); err == nil || err.Error() != "server: invalid deployment identity" {
		t.Fatalf("oversized deployment error = %v", err)
	}
	for _, malformed := range []struct {
		field string
		set   func(*NonceAdmission)
	}{
		{field: "kid", set: func(value *NonceAdmission) { value.KID = "!" }},
		{field: "nonce", set: func(value *NonceAdmission) { value.Nonce = "!" }},
		{field: "signature", set: func(value *NonceAdmission) { value.Signature = "!" }},
	} {
		invalid := admission
		malformed.set(&invalid)
		_, err := NonceIntentID("deployment", invalid, operation)
		if !errors.Is(err, jack.ErrBadBase64URL) {
			t.Errorf("malformed %s error = %v, want jack.ErrBadBase64URL", malformed.field, err)
		}
	}
	// admission.go:NonceIntentID decodes KID, Nonce, and Signature at their fixed byte widths and propagates jack's canonical base64url error.
	first, err := NonceIntentID("deployment", admission, operation)
	if err != nil {
		t.Fatal(err)
	}
	otherOperation := operation
	otherOperation[1] = 1
	second, err := NonceIntentID("deployment", admission, otherOperation)
	if err != nil || first == second {
		t.Fatalf("operation identity was not bound: %q %q %v", first, second, err)
	}
}

func TestDurableAdmissionStateGateRejectsChangedRepeatedAndMissingCallbacks(t *testing.T) {
	for _, scenario := range []string{"changed", "repeated", "missing", "plain-error"} {
		t.Run(scenario, func(t *testing.T) {
			base := NewMemoryState()
			request := admissionRequest(t, base, 100)
			calls := 0
			state := admissionStateHook{MemoryState: base}
			switch scenario {
			case "changed":
				state.withAdmission = func(kid string, check func(RegistryEntry, bool) error) error {
					if err := base.Update(func(edit *StateEdit) error {
						entry, ok := edit.Key(kid)
						if !ok {
							t.Fatal("seeded caller disappeared")
						}
						entry.Name = "changed-before-reservation"
						edit.PutKey(entry)
						return nil
					}); err != nil {
						return err
					}
					entry, known := base.Lookup(kid)
					return check(entry, known)
				}
			case "repeated":
				state.withAdmission = func(kid string, check func(RegistryEntry, bool) error) error {
					calls++
					entry, known := base.Lookup(kid)
					if err := check(entry, known); err != nil {
						return err
					}
					return check(entry, known)
				}
			case "missing":
				state.withAdmission = func(string, func(RegistryEntry, bool) error) error { return nil }
			case "plain-error":
				state.withAdmission = func(string, func(RegistryEntry, bool) error) error { return errors.New("private state detail") }
			}

			storage := &admissionSpy{}
			result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
			defer result.Done()
			// admission.go:reserveDurable rechecks sameEntry under WithAdmission before it invokes storage.
			if scenario == "changed" {
				if result.HTTPStatus != 503 || result.Code != "state_changed" || result.Accepted || storage.calls != 0 || storage.fences != 0 {
					t.Fatalf("changed caller was not refused before reserve: %+v storage=%+v", result, storage)
				}
				return
			}
			if result.HTTPStatus != 503 || result.Code != "durability_unavailable" || result.Accepted {
				t.Fatalf("unsafe admission callback result: %+v", result)
			}
			// admission.go:reserveDurable's called flag rejects the second callback; a receipt from the first call is fenced and released.
			if scenario == "repeated" {
				if calls != 1 || storage.calls != 1 || storage.fences != 1 || storage.lease == nil || storage.lease.releases != 1 {
					t.Fatalf("repeated callback did not fence/release once: calls=%d storage=%+v", calls, storage)
				}
				return
			}
			// No receipt exists in either case, so storage is never reserved.
			if storage.calls != 0 {
				t.Fatalf("pre-reservation callback error reached storage: storage=%+v", storage)
			}
			// admission.go:reserveDurable normalizes a plain pre-receipt state error (storageRejection) without fencing.
			if scenario == "plain-error" && storage.fences != 0 {
				t.Fatalf("plain pre-reservation error fenced the store: storage=%+v", storage)
			}
			// A missing callback violates AdmissionStateStore's synchronous exactly-once contract: the `!called.Load()` branch fences.
			if scenario == "missing" && storage.fences != 1 {
				t.Fatalf("missing callback did not fence: storage=%+v", storage)
			}
		})
	}
}

func TestDurableAdmissionStateGateErrorAfterReceiptFencesAndReleases(t *testing.T) {
	base := NewMemoryState()
	request := admissionRequest(t, base, 100)
	state := admissionStateHook{MemoryState: base}
	state.withAdmission = func(kid string, check func(RegistryEntry, bool) error) error {
		entry, known := base.Lookup(kid)
		if err := check(entry, known); err != nil {
			return err
		}
		return errors.New("private post-reservation state failure")
	}
	storage := &admissionSpy{}
	result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
	defer result.Done()
	if result.HTTPStatus != 503 || result.Code != "durability_unavailable" || result.Accepted || storage.fences != 1 || storage.lease == nil || storage.lease.releases != 1 {
		t.Fatalf("state gate failure after receipt did not fence/release: %+v storage=%+v", result, storage)
	}
}

func TestDurableAdmissionCallbackErrorAfterSuccessFencesDiscardedReceipt(t *testing.T) {
	base := NewMemoryState()
	request := admissionRequest(t, base, 100)
	state := admissionStateHook{MemoryState: base}
	state.withAdmission = func(kid string, check func(RegistryEntry, bool) error) error {
		entry, known := base.Lookup(kid)
		if err := check(entry, known); err != nil {
			return err
		}
		return errors.New("state writer failed")
	}
	storage := &admissionSpy{}
	result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
	defer result.Done()
	// admission.go:reserveDurable: a WithAdmission error after a successful callback fences the durable store and returns a fresh
	// rejectionFrom(durableFailure()), discarding the receipt, so the result does not claim NonceRecorded.
	if result.HTTPStatus != 503 || result.Code != "durability_unavailable" || result.Message != "durable admission is unavailable" || result.Accepted || result.NonceRecorded {
		t.Fatalf("post-callback callback error did not reject durably: %+v", result)
	}
	if storage.fences != 1 || storage.lease == nil || storage.lease.releases != 1 {
		t.Fatalf("discarded receipt was not fenced/released: storage=%+v", storage)
	}
}

func TestDurableAdmissionNilLeaseFencesReceipt(t *testing.T) {
	state := NewMemoryState()
	request := admissionRequest(t, state, 100)
	base := &admissionSpy{}
	storage := admissionNilLeaseStore{admissionSpy: base}
	verifier, err := NewVerifier(Config{Aud: "test-audience", State: state, DurableNonces: storage, Now: func() int64 { return 100 }})
	if err != nil {
		t.Fatal(err)
	}
	result := verifier.Verify(request)
	defer result.Done()
	// admission.go:reserveDurable treats a confirmed receipt without its serving lease as uncertain and fences the durable store.
	if result.HTTPStatus != 503 || result.Code != "durability_unavailable" || result.Accepted || base.calls != 1 || base.fences != 1 || base.lease == nil {
		t.Fatalf("nil lease receipt was not fenced: %+v storage=%+v", result, base)
	}
}

func TestDurableAdmissionStorageRefusalAndErrorLeaseLifecycle(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        *jack.Error
		wantStatus int
		wantCode   string
		wantFence  int
	}{
		{name: "replay", err: &jack.Error{HTTPStatus: 401, Code: jack.CodeReplayedNonce, Message: "backend detail"}, wantStatus: 401, wantCode: jack.CodeReplayedNonce},
		{name: "timestamp-refusal", err: &jack.Error{HTTPStatus: 401, Code: jack.CodeTimestampOutOfWindow, Message: "backend detail"}, wantStatus: 401, wantCode: jack.CodeTimestampOutOfWindow},
		{name: "changed-state-refusal", err: &jack.Error{HTTPStatus: 503, Code: "state_changed", Message: "backend detail"}, wantStatus: 503, wantCode: "state_changed"},
		{name: "known-capacity-refusal", err: &jack.Error{HTTPStatus: 503, Code: "capacity_exhausted", Message: "backend detail"}, wantStatus: 503, wantCode: "capacity_exhausted"},
		{name: "unknown-error", err: &jack.Error{HTTPStatus: 500, Code: "private", Message: "backend detail"}, wantStatus: 503, wantCode: "durability_unavailable", wantFence: 1},
		{name: "unknown-503-code", err: &jack.Error{HTTPStatus: 503, Code: "backend_unknown", Message: "backend detail"}, wantStatus: 503, wantCode: "durability_unavailable", wantFence: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := NewMemoryState()
			request := admissionRequest(t, state, 100)
			lease := &leaseSpy{valid: true}
			storage := &admissionErrorLeaseStore{admissionSpy: &admissionSpy{failure: test.err}, lease: lease}
			verifier, err := NewVerifier(Config{Aud: "test-audience", State: state, DurableNonces: storage, Now: func() int64 { return 100 }})
			if err != nil {
				t.Fatal(err)
			}
			result := verifier.Verify(request)
			defer result.Done()
			// admission.go:definiteStorageRefusal and storageRejection preserve the recognized replay/state/timestamp/capacity codes and collapse unknown 503 codes.
			if result.HTTPStatus != test.wantStatus || result.Code != test.wantCode || result.Accepted || storage.admissionSpy.fences != test.wantFence {
				t.Fatalf("storage refusal classification: %+v fences=%d", result, storage.admissionSpy.fences)
			}
			if lease.releases != 1 {
				t.Fatalf("error-path lease releases=%d, want exactly one", lease.releases)
			}
			if result.Message == "backend detail" {
				t.Fatal("storage error detail escaped the admission boundary")
			}
		})
	}
}

func TestDurableAdmissionBoundsTimestampBeforeReserveAndRechecksLease(t *testing.T) {
	t.Run("reserved-timestamp-domain", func(t *testing.T) {
		state := NewMemoryState()
		request := admissionRequest(t, state, maxDurableTimestamp)
		storage := &admissionSpy{}
		result := durableVerifier(t, state, storage, func() int64 { return maxDurableTimestamp }).Verify(request)
		defer result.Done()
		// admission.go:reserveDurable rejects timestamps above maxDurableTimestamp-window before calling Reserve.
		if result.HTTPStatus != 401 || result.Code != jack.CodeTimestampOutOfWindow || storage.calls != 0 || storage.fences != 0 {
			t.Fatalf("timestamp domain refusal: %+v storage=%+v", result, storage)
		}
	})

	t.Run("registry-window-invalid-at-final-check", func(t *testing.T) {
		state := NewMemoryState()
		request := admissionRequest(t, state, 100)
		notAfter := int64(101)
		kid := state.View().Keys[0].Kid
		if err := state.Update(func(edit *StateEdit) error {
			entry, ok := edit.Key(kid)
			if !ok {
				return errors.New("test caller missing")
			}
			entry.NotAfter = &notAfter
			edit.PutKey(entry)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		storage := &admissionSpy{lease: &leaseSpy{valid: true}}
		clockCalls := 0
		verifier := durableVerifier(t, state, storage, func() int64 {
			clockCalls++
			if clockCalls == 3 {
				return 101
			}
			return 100
		})
		result := verifier.Verify(request)
		// admission.go:reserveDurable evaluates request.Validate inside WithAdmission, using the entry snapshot held by that gate.
		// Request.Validate invokes entryActive, whose not_after comparison is strict; now==101 is outside [not_before,not_after).
		if result.HTTPStatus != 503 || result.Code != "state_changed" || !result.NonceRecorded || result.Accepted || storage.fences != 0 {
			t.Fatalf("final registry interval check: %+v fences=%d", result, storage.fences)
		}
		result.Done()
		if storage.lease.releases != 1 {
			t.Fatalf("final registry interval lease releases=%d", storage.lease.releases)
		}
	})

	t.Run("lease-invalid-at-final-check", func(t *testing.T) {
		state := NewMemoryState()
		request := admissionRequest(t, state, 100)
		storage := &admissionSpy{lease: &leaseSpy{valid: false}}
		result := durableVerifier(t, state, storage, func() int64 { return 100 }).Verify(request)
		// admission.go:reserveDurable requires lease.Valid and request.Validate while WithAdmission holds the registry snapshot.
		if result.HTTPStatus != 503 || result.Code != "state_changed" || !result.NonceRecorded || result.Accepted || storage.fences != 0 {
			t.Fatalf("invalid serving lease authorized request: %+v storage=%+v", result, storage)
		}
		// The serving lease is released by Result.Done (the middleware's deferred call).
		result.Done()
		if storage.lease.releases != 1 {
			t.Fatalf("invalid serving lease releases=%d, want exactly one", storage.lease.releases)
		}
	})
}
