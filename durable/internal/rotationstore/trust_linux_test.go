//go:build linux

package rotationstore

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

type trustTestSigner struct{ key ed25519.PrivateKey }

func (signer trustTestSigner) PublicKey() []byte { return signer.key.Public().(ed25519.PublicKey) }
func (signer trustTestSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, message), nil
}

func trustTestOptions(now *atomic.Int64) (TrustOptions, trustTestSigner) {
	signer := trustTestSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(signer.PublicKey())}
	copy(checkpoint.PublicKey[:], signer.PublicKey())
	return TrustOptions{Binding: rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "public-trust-test"}, Window: 30, Checkpoint: checkpoint, Now: now.Load}, signer
}

func testTrustOwner(t *testing.T) (*TrustStore, string, TrustOptions, *atomic.Int64, trustTestSigner) {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(1000)
	options, signer := trustTestOptions(now)
	path := filepath.Join(testfixture.PrivateDirectory(t), "trust.db")
	if err := InitializeTrustUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := OpenTrust(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path, options, now, signer
}

func extendTrust(t *testing.T, snapshot rotation.TrustSnapshot, clock rotation.ClockTuple, signer trustTestSigner) rotation.TrustSnapshot {
	t.Helper()
	previous := snapshot.Checkpoint
	if len(snapshot.Records) != 0 {
		wires := make([][]byte, len(snapshot.Records))
		for index, wire := range snapshot.Records {
			wires[index] = []byte(wire)
		}
		records, err := rotation.VerifyChain(wires, snapshot.Binding, snapshot.Checkpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		last := records[len(records)-1]
		previous = rotation.Checkpoint{Ordinal: last.Ordinal, Hash: last.Hash, KID: last.NewKID, PublicKey: last.PublicKey, PublishedAt: last.PublishedAt}
	}
	if previous.Ordinal > 1 {
		t.Fatal("test fixture only provisions two successors")
	}
	seed := byte(73 + previous.Ordinal)
	next := trustTestSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))}
	record, err := rotation.CreateRecord(snapshot.Binding, previous, signer, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	desired := snapshot
	desired.Records = append(append([]string{}, snapshot.Records...), record.Wire)
	desired.Keys = append([]rotation.TrustKey(nil), snapshot.Keys...)
	cutoff := record.ActivatesAt
	desired.Keys[len(desired.Keys)-1].KnownCutoff = &cutoff
	desired.Keys = append(desired.Keys, rotation.TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt})
	desired.Head = rotation.ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}
	desired.Revision++
	desired.Clock = clock
	return desired
}

func trustRows(t *testing.T, store *TrustStore) ([]byte, []byte) {
	t.Helper()
	var guard, snapshot []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		var err error
		guard, snapshot, err = readTrustRows(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return guard, snapshot
}

func TestTrustStoreExplicitInitOwnershipAndCleanReopen(t *testing.T) {
	now := &atomic.Int64{}
	now.Store(1000)
	options, _ := trustTestOptions(now)
	path := filepath.Join(testfixture.PrivateDirectory(t), "trust.db")
	if owner, err := OpenTrust(path, options); err == nil || owner != nil {
		t.Fatal("missing store created or served")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("open created missing DB")
	}
	if err := InitializeTrustUnused(path, options); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeTrustUnused(path, options); err == nil {
		t.Fatal("existing binding reset")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated initialization changed bytes")
	}
	wrong := options
	wrong.Window++
	if owner, err := OpenTrust(path, wrong); err == nil || owner != nil {
		t.Fatal("immutable W mismatch served")
	}
	owner, err := OpenTrust(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if duplicate, err := OpenTrust(path, options); err == nil || duplicate != nil {
		t.Fatal("second lifetime owner admitted")
	}
	snapshot, clock, err := owner.Snapshot()
	if err != nil || snapshot.Head.Ordinal != 0 || clock.HighWater != 1000 || !rotation.TrustClockCompatible(snapshot, clock) {
		t.Fatal("initial public snapshot unavailable")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenTrust(path, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTrustFinalClockGateAtomicallyChecksExpectedSnapshot(t *testing.T) {
	store, _, _, now, signer := testTrustOwner(t)
	expected, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendTrust(t, expected, clock, signer)
	if err := store.CompareAndSwap(expected, desired, clock); err != nil {
		t.Fatal(err)
	}
	now.Store(1001)
	if _, err := store.CheckSnapshotClock(expected); err == nil {
		t.Fatal("final clock gate ignored concurrent committed trust")
	} else {
		var refusal *rotation.Error
		if !errors.As(err, &refusal) || refusal.Code != "rotation_state_changed" {
			t.Fatal("definite trust conflict misclassified")
		}
	}
	retained, advanced, err := store.Snapshot()
	if err != nil || retained.Head != desired.Head || advanced.HighWater != 1001 {
		t.Fatal("conflict rolled back clock or changed trust")
	}
	now.Store(1000)
	if _, err := store.CheckSnapshotClock(expected); err == nil {
		t.Fatal("stale trust rescued rollback")
	} else {
		var refusal *rotation.Error
		if !errors.As(err, &refusal) || refusal.Code != "rotation_clock_unsafe" {
			t.Fatal("rollback did not dominate final conflict")
		}
	}
}

func TestTrustClockAdvanceIsSeparateAndRollbackNeverClears(t *testing.T) {
	store, path, options, now, _ := testTrustOwner(t)
	originalGuard, originalTrust := trustRows(t, store)
	same, err := store.AdvanceAndCheck()
	if err != nil || same.HighWater != 1000 || same.Revision != 1 {
		t.Fatal("equal clock changed tuple")
	}
	guard, data := trustRows(t, store)
	if !bytes.Equal(guard, originalGuard) || !bytes.Equal(data, originalTrust) {
		t.Fatal("equal operation changed logical records")
	}
	now.Store(1001)
	advanced, err := store.AdvanceAndCheck()
	if err != nil || advanced.HighWater != 1001 || advanced.Revision != 2 {
		t.Fatal("advance not acknowledged exactly once")
	}
	_, data = trustRows(t, store)
	if !bytes.Equal(data, originalTrust) {
		t.Fatal("clock operation mutated trust snapshot")
	}
	now.Store(1000)
	for _, sample := range []int64{1000, 2000} {
		now.Store(sample)
		_, err := store.AdvanceAndCheck()
		var refusal *rotation.Error
		if !errors.As(err, &refusal) || refusal.Code != "rotation_clock_unsafe" {
			t.Fatal("rollback/catch-up did not remain unsafe")
		}
	}
	guard, _ = trustRows(t, store)
	loaded, err := decodeTrustGuard(guard, options, store.identity.Profile)
	if err != nil || !loaded.Clock.Unsafe || loaded.Clock.HighWater != 1001 || loaded.Clock.Revision != 3 {
		t.Fatal("durable rollback latch changed H or incremented twice")
	}
	if err := store.Close(); err == nil {
		t.Fatal("unsafe owner reported healthy close")
	}
	if owner, err := OpenTrust(path, options); err == nil || owner != nil {
		t.Fatal("unsafe binding revived on restart")
	}
}

func TestTrustClockInvalidSamplesAndProviderPanicFailClosed(t *testing.T) {
	for _, name := range []string{"negative", "overflow", "panic"} {
		t.Run(name, func(t *testing.T) {
			store, path, options, _, _ := testTrustOwner(t)
			store.options.Now = func() int64 {
				switch name {
				case "negative":
					return -1
				case "overflow":
					return rotation.MaxTimestamp + 1
				default:
					panic("private provider detail")
				}
			}
			if _, err := store.AdvanceAndCheck(); err == nil {
				t.Fatal("invalid clock authorized response time")
			}
			if err := store.Close(); err == nil {
				t.Fatal("invalid clock owner reported clean close")
			}
			if owner, err := OpenTrust(path, options); err == nil || owner != nil {
				t.Fatal("invalid clock fence disappeared on restart")
			}
		})
	}
}

func TestTrustClockPostTransactionFenceRejectsAuthority(t *testing.T) {
	store, _, _, now, _ := testTrustOwner(t)
	base := store.transact
	store.transact = func(apply func(*bolt.Tx) error) error {
		err := base(apply)
		store.Fence()
		return err
	}
	now.Store(1001)
	if clock, err := store.AdvanceAndCheck(); err == nil || clock != (rotation.ClockTuple{}) {
		t.Fatal("post-commit fence exposed time authority")
	}
	store.transact = base
}

func TestTrustCASComparesWholeStateAndClockWithoutClockMutation(t *testing.T) {
	store, _, _, now, signer := testTrustOwner(t)
	expected, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendTrust(t, expected, clock, signer)
	guard, _ := trustRows(t, store)
	if err := store.CompareAndSwap(expected, desired, clock); err != nil {
		t.Fatal(err)
	}
	afterGuard, _ := trustRows(t, store)
	if !bytes.Equal(guard, afterGuard) {
		t.Fatal("trust CAS changed ClockGuard bytes")
	}
	loaded, loadedClock, err := store.Snapshot()
	if err != nil || loaded.Revision != 2 || loaded.Head != desired.Head || loadedClock != clock {
		t.Fatal("exact whole-state ACK not installed")
	}
	if err := store.CompareAndSwap(expected, desired, clock); err == nil {
		t.Fatal("stale trust snapshot silently adopted")
	}
	currentSigner := trustTestSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, 32))}
	next := extendTrust(t, loaded, loadedClock, currentSigner)
	now.Store(1001)
	if _, err := store.AdvanceAndCheck(); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwap(loaded, next, loadedClock); err == nil {
		t.Fatal("stale clock tuple silently adopted")
	}
	retained, _, err := store.Snapshot()
	if err != nil || retained.Head != desired.Head {
		t.Fatal("definite clock conflict fenced owner or adopted extension")
	}
}

func TestUnknownTrustAndClockWritesFenceCommittedAndRolledBackOutcomes(t *testing.T) {
	for _, operation := range []string{"trust", "clock"} {
		for _, committed := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "-rolled-back", true: "-committed"}[committed], func(t *testing.T) {
				store, path, options, now, signer := testTrustOwner(t)
				expected, clock, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				desired := extendTrust(t, expected, clock, signer)
				base := store.transact
				attempts := 0
				store.transact = func(apply func(*bolt.Tx) error) error {
					attempts++
					if committed {
						if err := base(apply); err != nil {
							return err
						}
					} else {
						tx, err := store.db.Begin(true)
						if err != nil {
							return err
						}
						defer tx.Rollback()
						if err := apply(tx); err != nil {
							return err
						}
						if err := tx.Rollback(); err != nil {
							return err
						}
					}
					return errors.New("public injected unknown outcome")
				}
				if operation == "trust" {
					err = store.CompareAndSwap(expected, desired, clock)
				} else {
					now.Store(1001)
					_, err = store.AdvanceAndCheck()
				}
				if err == nil || attempts != 1 {
					t.Fatal("unknown write accepted or retried")
				}
				if _, _, err := store.Snapshot(); err == nil {
					t.Fatal("unknown owner exposed success")
				}
				guardBytes, data := trustRows(t, store)
				guard, err := decodeTrustGuard(guardBytes, options, store.identity.Profile)
				if err != nil || !guard.Dirty {
					t.Fatal("unknown outcome lost startup gate")
				}
				actual, err := rotation.DecodeTrustSnapshot(data, options.Binding, options.Window, options.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "trust" && ((actual.Head.Ordinal == 1) != committed) {
					t.Fatal("fault did not simulate actual requested trust outcome")
				}
				if operation == "clock" && ((guard.Clock.HighWater == 1001) != committed) {
					t.Fatal("fault did not simulate actual requested clock outcome")
				}
				store.transact = base
				if err := store.Close(); err == nil {
					t.Fatal("unknown binding cleared fence on close")
				}
				if owner, err := OpenTrust(path, options); err == nil || owner != nil {
					t.Fatal("dirty unknown binding served after restart")
				}
			})
		}
	}
}

func requireTrustOperationCode(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *rotation.Error
	if !errors.As(err, &refusal) || refusal.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestTrustOperationsRejectUnavailableAndInvalidClockRequests(t *testing.T) {
	store, _, _, _, _ := testTrustOwner(t)
	store.Fence()
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("fenced RawClock returned %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("fenced trust owner close = %v", err)
	}

	store, _, _, _, _ = testTrustOwner(t)
	store.options.Now = func() int64 {
		store.Fence()
		return 1000
	}
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("RawClock exposed a sample after concurrent fence: %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("fenced RawClock owner close = %v", err)
	}

	store, _, _, _, _ = testTrustOwner(t)
	store.options.Now = func() int64 { panic("provider detail") }
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("panicking RawClock returned %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("failed clock owner close = %v", err)
	}

	store, _, _, _, _ = testTrustOwner(t)
	expected, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	invalid := expected
	invalid.Revision = 0
	_, err = store.CheckSnapshotClock(invalid)
	requireTrustOperationCode(t, err, "rotation_state_unknown")
	store.Fence()
	_, err = store.AdvanceAndCheck()
	requireTrustOperationCode(t, err, "rotation_clock_unavailable")
	if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
		t.Fatalf("fenced clock owner close = %v", err)
	}
}

func TestTrustOperationsClockStorageFailuresFailClosed(t *testing.T) {
	t.Run("invalid snapshot checksum", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		expected, _, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(trustBucket).Put(trustSnapshotKey, []byte("bad checksum"))
		}); err != nil {
			t.Fatal(err)
		}
		// trust_operations.go treats a checksum failure in the atomic snapshot check as unavailable authority.
		_, err = store.CheckSnapshotClock(expected)
		requireTrustOperationCode(t, err, "rotation_clock_unavailable")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("unknown clock state close = %v", err)
		}
	})

	t.Run("revision exhausted", func(t *testing.T) {
		store, _, _, now, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			guard, err := decodeTrustGuard(tx.Bucket(trustBucket).Get(trustGuardKey), store.options, store.identity.Profile)
			if err != nil {
				return err
			}
			guard.Clock.Revision = rotation.MaxOrdinal
			return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard))
		}); err != nil {
			t.Fatal(err)
		}
		now.Store(1001)
		_, err := store.AdvanceAndCheck()
		requireTrustOperationCode(t, err, "rotation_clock_unavailable")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("exhausted clock owner close = %v", err)
		}
	})

	t.Run("post-transaction stat failure", func(t *testing.T) {
		store, _, _, now, _ := testTrustOwner(t)
		store.transact = func(func(*bolt.Tx) error) error { return nil }
		if err := store.file.Close(); err != nil {
			t.Fatal(err)
		}
		now.Store(1001)
		_, err := store.AdvanceAndCheck()
		requireTrustOperationCode(t, err, "rotation_clock_unavailable")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("stat-failed clock owner close = %v", err)
		}
	})
}

func TestTrustOperationsSnapshotValidationFailuresFenceOwner(t *testing.T) {
	t.Run("row checksum", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(trustBucket).Put(trustSnapshotKey, []byte("bad checksum"))
		}); err != nil {
			t.Fatal(err)
		}
		// Snapshot returns only unavailable after readTrustRows or snapshot validation fails.
		if _, _, err := store.Snapshot(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("corrupt trust rows returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("corrupt trust owner close = %v", err)
		}
	})

	t.Run("guard owner mismatch", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			guard, err := decodeTrustGuard(tx.Bucket(trustBucket).Get(trustGuardKey), store.options, store.identity.Profile)
			if err != nil {
				return err
			}
			guard.Owner++
			return tx.Bucket(trustBucket).Put(trustGuardKey, encodeTrustGuard(guard))
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Snapshot(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign owner snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign owner close = %v", err)
		}
	})

	t.Run("snapshot clock ahead of guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(trustBucket)
			payload, err := ownedfile.CheckedPayload(bucket.Get(trustSnapshotKey))
			if err != nil {
				return err
			}
			snapshot, err := rotation.DecodeTrustSnapshot(payload, store.options.Binding, store.options.Window, store.options.Checkpoint)
			if err != nil {
				return err
			}
			snapshot.Clock.HighWater++
			snapshot.Clock.Revision++
			encoded, err := rotation.EncodeTrustSnapshot(snapshot, store.options.Binding, store.options.Window, store.options.Checkpoint)
			if err != nil {
				return err
			}
			return bucket.Put(trustSnapshotKey, ownedfile.SealPayload(encoded))
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Snapshot(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("incompatible committed clock returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("incompatible clock owner close = %v", err)
		}
	})
}

func TestTrustOperationsSnapshotDecodeAndOwnedGuardFailures(t *testing.T) {
	t.Run("valid checksum invalid snapshot", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(trustBucket).Put(trustSnapshotKey, ownedfile.SealPayload([]byte("not trust JSON")))
		}); err != nil {
			t.Fatal(err)
		}
		// Snapshot must fence when checksummed bytes fail strict snapshot decoding.
		if _, _, err := store.Snapshot(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("invalid decoded snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("invalid snapshot owner close = %v", err)
		}
	})

	t.Run("advance foreign owner guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		store.identity.Owner++
		_, err := store.AdvanceAndCheck()
		requireTrustOperationCode(t, err, "rotation_clock_unavailable")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign guard owner close = %v", err)
		}
	})

	t.Run("snapshot foreign owner guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		store.identity.Owner++
		if _, _, err := store.Snapshot(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign guard snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign guard owner close = %v", err)
		}
	})
}

func forkTrustSnapshot(t *testing.T, base rotation.TrustSnapshot, clock rotation.ClockTuple, signer trustTestSigner, seed byte) (rotation.TrustSnapshot, trustTestSigner) {
	t.Helper()
	nextSigner := trustTestSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))}
	record, err := rotation.CreateRecord(base.Binding, base.Checkpoint, signer, nextSigner, clock.HighWater)
	if err != nil {
		t.Fatal(err)
	}
	fork := base
	fork.Records = []string{record.Wire}
	fork.Keys = append([]rotation.TrustKey(nil), base.Keys...)
	cutoff := record.ActivatesAt
	fork.Keys[0].KnownCutoff = &cutoff
	fork.Keys = append(fork.Keys, rotation.TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt})
	fork.Head = rotation.ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}
	fork.Revision++
	fork.Clock = clock
	return fork, nextSigner
}

func TestTrustOperationsCompareAndSwapRejectsAlteredStateAndUnknownWrites(t *testing.T) {
	t.Run("invalid expected encoding", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		invalid := expected
		invalid.Revision = 0
		requireTrustOperationCode(t, store.CompareAndSwap(invalid, expected, clock), "rotation_state_unknown")
		if err := store.Close(); err != nil {
			t.Fatalf("invalid CAS input fenced owner: %v", err)
		}
	})

	t.Run("invalid desired encoding", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := expected
		desired.FormatVersion = 0
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		if err := store.Close(); err != nil {
			t.Fatalf("invalid desired state fenced owner: %v", err)
		}
	})

	t.Run("invalid desired state", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		desired.Revision = expected.Revision
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_changed")
		if err := store.Close(); err != nil {
			t.Fatalf("definite CAS refusal fenced owner: %v", err)
		}
	})

	t.Run("changed existing record prefix", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		base, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := forkTrustSnapshot(t, base, clock, signer, 83)
		fork, nextSigner := forkTrustSnapshot(t, base, clock, signer, 84)
		desired := extendTrust(t, fork, clock, nextSigner)
		// Both values are individually valid chains; CAS must retain the exact accepted prefix.
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_changed")
		if err := store.Close(); err != nil {
			t.Fatalf("prefix conflict fenced owner: %v", err)
		}
	})

	t.Run("fenced before transaction", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		store.Fence()
		if err := store.CompareAndSwap(expected, desired, clock); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("CAS on fenced owner = %v", err)
		}
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("fenced CAS owner close = %v", err)
		}
	})

	t.Run("CAS transaction foreign guard", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		store.identity.Owner++
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("foreign CAS owner close = %v", err)
		}
	})

	t.Run("corrupt snapshot in transaction", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(trustBucket).Put(trustSnapshotKey, []byte("bad checksum"))
		}); err != nil {
			t.Fatal(err)
		}
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("unknown CAS owner close = %v", err)
		}
	})

	t.Run("post-transaction stat failure", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		store.transact = func(func(*bolt.Tx) error) error { return nil }
		if err := store.file.Close(); err != nil {
			t.Fatal(err)
		}
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("stat-failed CAS owner close = %v", err)
		}
	})

	t.Run("fenced after commit", func(t *testing.T) {
		store, _, _, _, signer := testTrustOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendTrust(t, expected, clock, signer)
		base := store.transact
		store.transact = func(apply func(*bolt.Tx) error) error {
			err := base(apply)
			store.Fence()
			return err
		}
		requireTrustOperationCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		store.transact = base
		if err := store.Close(); !errors.Is(err, ownedfile.ErrUnavailable) {
			t.Fatalf("post-commit fenced owner close = %v", err)
		}
	})
}
