//go:build linux

package durable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

func testOwner(t *testing.T, now *int64) (*Store, string, Options) {
	t.Helper()
	path := filepath.Join(testfixture.PrivateDirectory(t), "admission.db")
	opts := testOptions(now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner, path, opts
}

func signedStorageRequest(t *testing.T, state *server.MemoryState, ts int64, nonceValue byte) server.Request {
	t.Helper()
	seed := sha256.Sum256([]byte("mcp-jack public actual durable admission"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	if _, known := state.Lookup(kid); !known {
		if err := state.Update(func(edit *server.StateEdit) error {
			edit.PutKey(server.RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "actual-durable-test"})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var nonceBytes [16]byte
	nonceBytes[0] = nonceValue
	nonce := jack.EncodeBase64URL(nonceBytes[:])
	signing := jack.RequestSigningString("GET", "/mcp", "public-durable-test", kid, ts, nonce, nil)
	signature := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	return server.Request{Method: "GET", Target: "/mcp", AuthValues: []string{jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: ts, Nonce: nonce, Sig: signature})}}
}

func actualVerifier(t *testing.T, owner *Store, state *server.MemoryState, now *int64) *server.Verifier {
	t.Helper()
	verifier, err := server.NewVerifier(server.Config{Aud: "public-durable-test", State: state, DurableNonces: owner, Now: func() int64 { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestActualDurableReceiptReplayAndCleanRestart(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-second", true: "future-timestamp"}[future], func(t *testing.T) {
			now := int64(100)
			owner, path, opts := testOwner(t, &now)
			state := server.NewMemoryState()
			ts := int64(100)
			if future {
				ts = 130
			}
			request := signedStorageRequest(t, state, ts, 1)
			first := actualVerifier(t, owner, state, &now).Verify(request)
			if !first.Accepted || !first.NonceRecorded {
				first.Done()
				t.Fatalf("final commit refused: %+v", first)
			}
			first.Done()
			if owner.meta.Live != 1 || owner.meta.Intents != 0 {
				t.Fatal("intent was not atomically converted")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			now = 101
			reopened, err := Open(path, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			replay := actualVerifier(t, reopened, state, &now).Verify(request)
			defer replay.Done()
			if replay.Accepted || replay.NonceRecorded || replay.Code != jack.CodeReplayedNonce {
				t.Fatalf("restart replay accepted: %+v", replay)
			}
		})
	}
}

func TestActualExpiryEqualityAndFreshPairReuse(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	state := server.NewMemoryState()
	verifier := actualVerifier(t, owner, state, &now)
	old := signedStorageRequest(t, state, 100, 2)
	first := verifier.Verify(old)
	if !first.Accepted {
		first.Done()
		t.Fatalf("initial commit: %+v", first)
	}
	first.Done()
	now = 130
	equal := verifier.Verify(old)
	equal.Done()
	if equal.Code != jack.CodeReplayedNonce {
		t.Fatalf("equality expired reservation: %+v", equal)
	}
	now = 131
	fresh := verifier.Verify(signedStorageRequest(t, state, 131, 2))
	defer fresh.Done()
	if !fresh.Accepted || !fresh.NonceRecorded || owner.meta.Live != 1 || owner.meta.HighWater != 131 {
		t.Fatalf("fresh reuse after safe expiry: %+v", fresh)
	}
}

func TestActualConcurrentDuplicateHasOneWinner(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	state := server.NewMemoryState()
	verifier := actualVerifier(t, owner, state, &now)
	request := signedStorageRequest(t, state, 100, 3)
	start := make(chan struct{})
	results := make(chan server.Result, 2)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result := verifier.Verify(request)
			result.Done()
			results <- result
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	accepted, replayed := 0, 0
	for result := range results {
		if result.Accepted {
			accepted++
		} else if result.Code == jack.CodeReplayedNonce {
			replayed++
		}
	}
	if accepted != 1 || replayed != 1 || owner.meta.Live != 1 {
		t.Fatalf("winners=%d replays=%d live=%d", accepted, replayed, owner.meta.Live)
	}
}

func TestFinalFreshnessFailureCleansIntentWithoutReservation(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 5)
	original := owner.transact
	calls := 0
	owner.transact = func(apply func(*bolt.Tx) error) error {
		calls++
		err := original(apply)
		if calls == 1 && err == nil {
			now = 131
		}
		return err
	}
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Accepted || result.NonceRecorded || result.Code != jack.CodeTimestampOutOfWindow || calls != 2 || owner.meta.Live != 0 || owner.meta.Intents != 0 || owner.meta.HighWater != 100 {
		t.Fatalf("stale final intent was consumed or dispatched: %+v calls=%d", result, calls)
	}
}

func TestUnknownIntentCreationAbsentStillFencesRestart(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 6)
	calls := 0
	owner.transact = func(func(*bolt.Tx) error) error {
		calls++
		return errors.New("public injected unknown intent creation")
	}
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Accepted || result.NonceRecorded || result.Code != "durability_unavailable" || calls != 1 || owner.meta.Live != 0 || owner.meta.Intents != 0 || !owner.fenced.Load() {
		t.Fatalf("unknown absent intent admitted: %+v", result)
	}
	claim := testRecord(t, owner.meta, intentRecord).receipt
	_ = owner.Close()
	snapshot, err := InspectRecovery(path, opts)
	if err != nil || !snapshot.Dirty || len(snapshot.Live)+len(snapshot.Intents)+len(snapshot.Tombstones) != 0 {
		t.Fatalf("absent unknown operation lost dirty gate: %+v %v", snapshot, err)
	}
	if err := ReconcileUnknown(path, opts, snapshot.Hash, claim); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("empty unknown history was treated as abort: %v", err)
	}
	if reopened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if reopened != nil {
			reopened.Fence()
			_ = reopened.Close()
		}
		t.Fatalf("absence cleared unknown creation fence: %v", err)
	}
}

func TestInvalidSignatureNeverInvokesActualTransaction(t *testing.T) {
	now := int64(100)
	owner, _, _ := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 7)
	request.Target = "/tampered"
	original := owner.transact
	calls := 0
	owner.transact = func(apply func(*bolt.Tx) error) error { calls++; return original(apply) }
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Code != jack.CodeBadSignature || calls != 0 || owner.meta.Live != 0 || owner.meta.Intents != 0 {
		t.Fatalf("pre-auth transaction: %+v calls=%d", result, calls)
	}
}

func TestActualRollbackAfterIntentPersistsUnsafeLatch(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 10)
	original := owner.transact
	calls := 0
	owner.transact = func(apply func(*bolt.Tx) error) error {
		calls++
		err := original(apply)
		if calls == 1 && err == nil {
			now = 99
		}
		return err
	}
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Accepted || result.NonceRecorded || result.Code != "clock_unsafe" || calls != 2 || !owner.meta.Unsafe || !owner.fenced.Load() || owner.meta.Intents != 0 || owner.meta.Live != 0 || owner.meta.HighWater != 100 {
		t.Fatalf("rollback lost unsafe latch or dispatched: %+v calls=%d", result, calls)
	}
	if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("unsafe close: %v", err)
	}
	now = 100
	if reopened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if reopened != nil {
			reopened.Fence()
			_ = reopened.Close()
		}
		t.Fatalf("catch-up cleared unsafe latch: %v", err)
	}
}

func TestUnknownStaleIntentCleanupNeverRetriesOrAuthorizes(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup-rolled-back", true: "cleanup-committed"}[committed], func(t *testing.T) {
			now := int64(100)
			owner, path, opts := testOwner(t, &now)
			state := server.NewMemoryState()
			request := signedStorageRequest(t, state, 100, 11)
			original := owner.transact
			calls := 0
			injected := errors.New("public injected cleanup uncertainty")
			owner.transact = func(apply func(*bolt.Tx) error) error {
				calls++
				if calls == 1 {
					err := original(apply)
					if err == nil {
						now = 131
					}
					return err
				}
				if committed {
					if err := original(apply); err != nil {
						return err
					}
					return injected
				}
				return original(func(tx *bolt.Tx) error {
					if err := apply(tx); err != nil {
						return err
					}
					return injected
				})
			}
			result := actualVerifier(t, owner, state, &now).Verify(request)
			result.Done()
			if result.Accepted || result.NonceRecorded || result.Code != "durability_unavailable" || calls != 2 || !owner.fenced.Load() {
				t.Fatalf("uncertain cleanup was retried or authorized: %+v calls=%d", result, calls)
			}
			if err := owner.db.View(func(tx *bolt.Tx) error {
				m, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
				if err != nil {
					return err
				}
				wantIntents := uint32(1)
				if committed {
					wantIntents = 0
				}
				if m.Live != 0 || m.Intents != wantIntents || !m.Dirty {
					return errors.New("actual cleanup disposition differs from injection")
				}
				return validateRows(tx, m)
			}); err != nil {
				t.Fatal(err)
			}
			_ = owner.Close()
			if reopened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
				if reopened != nil {
					reopened.Fence()
					_ = reopened.Close()
				}
				t.Fatalf("cleanup absence cleared recovery fence: %v", err)
			}
		})
	}
}

func TestUnknownFinalOutcomeNeverRetriesOrAuthorizes(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation-absent", true: "reservation-present"}[committed], func(t *testing.T) {
			now := int64(100)
			owner, path, opts := testOwner(t, &now)
			state := server.NewMemoryState()
			verifier := actualVerifier(t, owner, state, &now)
			request := signedStorageRequest(t, state, 100, 4)
			original := owner.transact
			calls := 0
			injected := errors.New("public injected commit uncertainty")
			owner.transact = func(apply func(*bolt.Tx) error) error {
				calls++
				if calls != 2 {
					return original(apply)
				}
				if committed {
					if err := original(apply); err != nil {
						return err
					}
					return injected
				}
				return original(func(tx *bolt.Tx) error {
					if err := apply(tx); err != nil {
						return err
					}
					return injected
				})
			}
			result := verifier.Verify(request)
			result.Done()
			if result.Accepted || result.NonceRecorded || result.Code != "durability_unavailable" || !owner.fenced.Load() || calls != 2 {
				t.Fatalf("unknown authorized or retried: %+v calls=%d", result, calls)
			}
			if err := owner.db.View(func(tx *bolt.Tx) error {
				live, _ := tx.Bucket([]byte("live")).Cursor().First()
				intent, _ := tx.Bucket([]byte("intent")).Cursor().First()
				if (live != nil) != committed || (intent != nil) == committed {
					return errors.New("injected disposition was not observed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			again := verifier.Verify(request)
			again.Done()
			if again.Accepted || calls != 2 {
				t.Fatal("fenced operation was redelivered")
			}
			_ = owner.Close()
			report, err := InspectRecovery(path, opts)
			if err != nil || !report.Dirty || (len(report.Live) == 1) != committed || (len(report.Intents) == 1) == committed || len(report.Live)+len(report.Intents) != 1 || len(report.Tombstones) != 0 {
				t.Fatalf("inspection lost actual unknown disposition: %+v %v", report, err)
			}
		})
	}
}

// A store that was fenced while it drained (for example by a request that
// arrived during Close) stays dirty, so Close must say so and the next open
// must be refused.
func TestCloseOfFencedStoreReportsRecoveryRequired(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	owner.Fence()
	if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("close of a fenced store: %v", err)
	}
	if reopened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if reopened != nil {
			reopened.Fence()
			_ = reopened.Close()
		}
		t.Fatalf("open after a fenced close: %v", err)
	}
}

type httpFixtureResponseSigner struct {
	key   ed25519.PrivateKey
	mode  string
	calls int
}

func (provider *httpFixtureResponseSigner) PublicKey() []byte {
	return provider.key.Public().(ed25519.PublicKey)
}

func (provider *httpFixtureResponseSigner) Sign(message []byte) ([]byte, error) {
	provider.calls++
	switch provider.mode {
	case "signer-error":
		return nil, errors.New("private response provider detail")
	case "signer-panic":
		panic("private response provider detail")
	case "signer-bad-signature":
		return make([]byte, ed25519.SignatureSize), nil
	case "signer-message-mutation":
		message[0] ^= 1
	}
	return ed25519.Sign(provider.key, message), nil
}

func TestActualHTTPOutcomesKeepNonceConsumedAcrossCleanRestart(t *testing.T) {
	for _, outcome := range []string{"success", "handler-error", "response-overflow", "streaming-refusal", "handler-panic", "opaque-success", "signer-error", "signer-panic", "signer-bad-signature", "signer-message-mutation"} {
		t.Run(outcome, func(t *testing.T) {
			now := int64(100)
			owner, path, opts := testOwner(t, &now)
			state := server.NewMemoryState()
			request := signedStorageRequest(t, state, 100, 13)
			auth, err := jack.ParseRequestAuth(request.AuthValues)
			if err != nil {
				t.Fatal(err)
			}
			seed := sha256.Sum256([]byte("mcp-jack public HTTP durable server fixture"))
			serverKey := ed25519.NewKeyFromSeed(seed[:])
			provider := &httpFixtureResponseSigner{key: serverKey, mode: outcome}
			opaque := outcome == "opaque-success" || strings.HasPrefix(outcome, "signer-")
			calls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if outcome == "handler-panic" {
					panic("public handler panic")
				}
				if outcome == "streaming-refusal" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: x\n\n"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if outcome == "handler-error" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				body := []byte("{}")
				if outcome == "response-overflow" {
					body = []byte("123456789")
				}
				_, _ = w.Write(body)
			})
			wrap := func(storage *Store) http.Handler {
				config := server.HandlerConfig{Verifier: actualVerifier(t, storage, state, &now), ServerKey: serverKey, MaxResponseBytes: 8}
				if opaque {
					config.ServerKey = nil
					config.ResponseSigner = provider
				}
				handler, err := server.NewHandler(config, next)
				if err != nil {
					t.Fatal(err)
				}
				return handler
			}
			invoke := func(handler http.Handler, target string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, target, nil)
				for _, value := range request.AuthValues {
					r.Header.Add("Jack-Auth", value)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				return response
			}
			handler := wrap(owner)
			bad := invoke(handler, "/tampered")
			if bad.Code != http.StatusUnauthorized || calls != 0 || owner.meta.Live != 0 || provider.calls != 0 {
				t.Fatal("HTTP pre-auth refusal consumed nonce or dispatched")
			}
			var response *httptest.ResponseRecorder
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				response = invoke(handler, "/mcp")
			}()
			if outcome == "handler-panic" {
				if recovered != "public handler panic" {
					t.Fatalf("handler panic changed: %v", recovered)
				}
			} else {
				if recovered != nil {
					t.Fatalf("unexpected HTTP panic: %v", recovered)
				}
				verification := client.VerifyResponse(serverKey.Public().(ed25519.PublicKey), response.Code, response.Header().Values("Jack-Auth"), auth.Sig, response.Body.Bytes(), time.Unix(now, 0), 30*time.Second)
				if strings.HasPrefix(outcome, "signer-") {
					if response.Code != 503 || len(response.Header().Values("Jack-Auth")) != 0 || verification == nil || bytes.Contains(response.Body.Bytes(), []byte("private response provider detail")) || bytes.Equal(response.Body.Bytes(), []byte("{}")) {
						t.Fatal("signing failure emitted unsigned success, leaked detail or was trusted")
					}
				} else {
					want := map[string]int{"success": 200, "opaque-success": 200, "handler-error": 500, "response-overflow": 502, "streaming-refusal": 501}[outcome]
					if response.Code != want || verification != nil {
						t.Fatalf("HTTP outcome=%d want=%d signature=%v", response.Code, want, verification)
					}
				}
			}
			if calls != 1 || owner.meta.Live != 1 || owner.meta.Intents != 0 || (opaque && provider.calls != 1) {
				t.Fatal("post-reservation HTTP outcome undid or duplicated admission")
			}
			// Close drains the real request lease, including panic/error branches.
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			now = 101
			reopened, err := Open(path, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			replay := invoke(wrap(reopened), "/mcp")
			if replay.Code != http.StatusUnauthorized || calls != 1 || !bytes.Contains(replay.Body.Bytes(), []byte(jack.CodeReplayedNonce)) || len(replay.Header().Values("Jack-Auth")) != 0 || (opaque && provider.calls != 1) {
				t.Fatalf("restart redelivered HTTP operation: status=%d calls=%d", replay.Code, calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Seeding: fresh store + scripted clock + direct bucket writes.
// ---------------------------------------------------------------------------

// vectorRowHighWater picks a receipt HighWater satisfying validateRecord:
// 0 <= Hw <= metadata.HighWater and |Hw - ts| <= W.
func vectorRowHighWater(metadataHighWater, ts int64) int64 {
	if metadataHighWater > 0 {
		return metadataHighWater
	}
	return ts
}

func vectorSeedRowRecord(t *testing.T, m metadata, kind byte, kidName, nonceName string, ts, retainUntil, highWater int64) nonceRecord {
	t.Helper()
	var key [48]byte
	kidRaw := vectorKidRaw(kidName)
	nonceRaw := vectorNonceRaw(nonceName)
	copy(key[:32], kidRaw[:])
	copy(key[32:], nonceRaw[:])
	signing := jack.RequestSigningString("GET", "/mcp", vectorAud, vectorKid(kidName), ts, vectorNonce(nonceName), nil)
	requestHash, err := jack.DecodeBase64URLFixed(jack.BodyHash([]byte(signing)), 32)
	if err != nil {
		t.Fatalf("seed row %s/%s request hash: %v", kidName, nonceName, err)
	}
	operation := vectorOperation(kidName + "/" + nonceName)
	sigRaw := vectorSigRaw(kidName + ":" + nonceName)
	row := nonceRecord{
		kind: kind, storeID: m.StoreID, key: key,
		receipt: server.NonceReceipt{
			Version:         formatVersion,
			DeploymentID:    m.Deployment,
			StoreGeneration: m.Generation,
			OwnerGeneration: m.Owner,
			IntentID:        storageIntentID(m, key, sigRaw[:], requestHash, operation),
			OperationID:     operation,
			KID:             vectorKid(kidName),
			Nonce:           vectorNonce(nonceName),
			Signature:       vectorSig(kidName + ":" + nonceName),
			RequestHash:     jack.BodyHash([]byte(signing)),
			Timestamp:       ts,
			RetainUntil:     retainUntil,
			HighWater:       highWater,
		},
	}
	if err := validateRecord(row, m); err != nil {
		t.Fatalf("seed row %s/%s invalid: %v", kidName, nonceName, err)
	}
	return row
}

// vectorSplitRowKey derives the deterministic identity names of a seed row.
// Pair rows are written "kid:nonce"; generated capacity rows ("seed-N") carry
// a single name, so the nonce name falls back to a whole-key derivative.
func vectorSplitRowKey(key string) (string, string) {
	for index := 0; index < len(key); index++ {
		if key[index] == ':' {
			return key[:index], key[index+1:]
		}
	}
	return key, key + "/nonce"
}

// vectorCaseRows builds every seed row of a case; encodeRecord (via
// validateRecord) already rejects any row inconsistent with the metadata.
func vectorCaseRows(t *testing.T, fc vectorCase, m metadata) []nonceRecord {
	t.Helper()
	var rows []nonceRecord
	for _, row := range fc.State.Live {
		kidName, nonceName := vectorSplitRowKey(row.Key)
		rows = append(rows, vectorSeedRowRecord(t, m, liveRecord, kidName, nonceName,
			row.TS, row.RetainUntil, vectorRowHighWater(m.HighWater, row.TS)))
	}
	for _, row := range fc.State.Intents {
		kidName, nonceName := vectorSplitRowKey(row.Key)
		rows = append(rows, vectorSeedRowRecord(t, m, intentRecord, kidName, nonceName,
			row.TS, row.RetainUntil, vectorRowHighWater(m.HighWater, row.TS)))
	}
	for _, row := range fc.State.Tombstones {
		rows = append(rows, vectorSeedRowRecord(t, m, tombstoneRecord, row.IntentID, row.IntentID+"-pair",
			100, 130, vectorRowHighWater(m.HighWater, 100)))
	}
	return rows
}

// seedVectorState writes the rows, their operation index, the live expiry
// index, and matching metadata in one transaction, then re-checks the exact
// graph invariants the loader itself uses (validateRows) and syncs the
// in-memory metadata the transaction layer compares against.
func seedVectorState(t *testing.T, owner *Store, fc vectorCase, highWater int64) {
	t.Helper()
	if fc.State == nil {
		return // sequence cases start from a fresh empty store
	}
	seedMeta := owner.meta
	seedMeta.HighWater = highWater
	rows := vectorCaseRows(t, fc, seedMeta)
	m := seedMeta
	err := owner.db.Update(func(tx *bolt.Tx) error {
		for _, row := range rows {
			encoded, err := encodeRecord(row, seedMeta)
			if err != nil {
				return err
			}
			bucket := "intent"
			switch row.kind {
			case liveRecord:
				bucket = "live"
			case tombstoneRecord:
				bucket = "tombstone"
			}
			if err := tx.Bucket([]byte(bucket)).Put(row.key[:], encoded); err != nil {
				return err
			}
			if err := tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], row.key[:]); err != nil {
				return err
			}
			if row.kind == liveRecord {
				index := expiryKey(row)
				if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil {
					return err
				}
			}
			switch row.kind {
			case liveRecord:
				m.Live++
			case intentRecord:
				m.Intents++
			case tombstoneRecord:
				m.Tombstones++
			}
		}
		if err := validateRows(tx, m); err != nil {
			return err
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	})
	if err != nil {
		t.Fatalf("%s: seed state: %v", fc.ID, err)
	}
	owner.meta = m
}

// ---------------------------------------------------------------------------
// Driving: full-path Verifier, store-direct, counters.
// ---------------------------------------------------------------------------

type vectorCounters struct {
	transactCalls int
	nativeCalls   int
	accepted      int
	eventCalls    int
	eventAccepted int
}

func countTransact(owner *Store, counters *vectorCounters) {
	original := owner.transact
	owner.transact = func(apply func(*bolt.Tx) error) error {
		counters.transactCalls++
		counters.eventCalls++
		return original(apply)
	}
}

func resetEventCounters(counters *vectorCounters) {
	counters.eventCalls = 0
	counters.eventAccepted = 0
}

type refusingNative struct {
	counters *vectorCounters
}

func (n refusingNative) Call(*server.NativeCall) (server.NativeResult, *jack.Error) {
	n.counters.nativeCalls++
	return server.NativeResult{}, &jack.Error{HTTPStatus: 403, Code: "authorization_refused", Message: "authorization refused"}
}

func vectorRegisteredKey(t *testing.T, state *server.MemoryState, kidName string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("candidate-vector/key/" + kidName))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{
			Kid:       vectorKid(kidName),
			PublicKey: jack.EncodeBase64URL(public),
			Name:      "candidate-vector-" + kidName,
		})
		return nil
	}); err != nil {
		t.Fatalf("register vector key %s: %v", kidName, err)
	}
	return key
}

func vectorToolBody(tool string) []byte {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": map[string]any{}},
	})
	if err != nil {
		panic(err) // constant-shaped body; marshal cannot fail
	}
	return body
}

func vectorRequest(t *testing.T, state *server.MemoryState, ev vectorEvent, target string, body []byte) server.Request {
	t.Helper()
	key := vectorRegisteredKey(t, state, ev.KID)
	kid, nonce := vectorKid(ev.KID), vectorNonce(ev.Nonce)
	method := "GET"
	if body != nil {
		method = "POST"
	}
	signing := jack.RequestSigningString(method, target, vectorAud, kid, ev.TS, nonce, body)
	signature := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	if !ev.Authenticated {
		// Tamper after signing so signature verification must fail pre-admission.
		target += "/tampered"
	}
	return server.Request{
		Method:     method,
		Target:     target,
		AuthValues: []string{jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: ev.TS, Nonce: nonce, Sig: signature})},
		Body:       body,
	}
}

func vectorVerifier(t *testing.T, owner *Store, state *server.MemoryState, clock *testfixture.ScriptedClock, counters *vectorCounters, window int64, refuseNative bool) *server.Verifier {
	t.Helper()
	cfg := server.Config{Aud: vectorAud, State: state, DurableNonces: owner, Now: clock.Now, Window: window}
	if refuseNative {
		cfg.Native = refusingNative{counters: counters}
	}
	verifier, err := server.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

// driveVectorEvent runs one full-path event: the Verifier consumes the entry
// clock sample, the store consumes entry/intent/final samples, and the
// Verifier consumes the post-commit sample (5 pushes per event).
func driveVectorEvent(t *testing.T, owner *Store, state *server.MemoryState, clock *testfixture.ScriptedClock, counters *vectorCounters, ev vectorEvent, target string) server.Result {
	t.Helper()
	clock.Push(ev.EntryNow, ev.EntryNow, ev.IntentNow, ev.FinalNow, ev.FinalNow)
	var body []byte
	refuseNative := ev.Authorization == "refused"
	if refuseNative {
		body = vectorToolBody(vectorToolName)
	}
	request := vectorRequest(t, state, ev, target, body)
	verifier := vectorVerifier(t, owner, state, clock, counters, ev.Window, refuseNative)
	result := verifier.Verify(request)
	result.Done()
	if result.Accepted {
		counters.accepted++
		counters.eventAccepted++
	}
	return result
}

// vectorEffects derives the harness-local effect counters:
// authorization = post-commit authorization gate reached (native call entered
// or accepted forward); handler = dispatch permission observed;
// stateMutation = 0 (the Verifier harness never runs a wrapped handler).
func vectorEffects(counters *vectorCounters) (int, int, int) {
	return counters.nativeCalls + counters.accepted, counters.accepted, 0
}
