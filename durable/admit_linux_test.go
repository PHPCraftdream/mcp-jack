//go:build linux

package durable

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

func testOwner(t *testing.T, now *int64) (*Store, string, Options) {
	t.Helper()
	path := filepath.Join(privateTestDirectory(t), "admission.db")
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
	_ = owner.Close()
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

func TestUnknownFinalOutcomeNeverRetriesOrAuthorizes(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation-absent", true: "reservation-present"}[committed], func(t *testing.T) {
			now := int64(100)
			owner, _, _ := testOwner(t, &now)
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
		})
	}
}
