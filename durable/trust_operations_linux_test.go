//go:build linux

package durable

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

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
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fenced RawClock returned %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fenced trust owner close = %v", err)
	}

	store, _, _, _, _ = testTrustOwner(t)
	store.options.Now = func() int64 {
		store.Fence()
		return 1000
	}
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("RawClock exposed a sample after concurrent fence: %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fenced RawClock owner close = %v", err)
	}

	store, _, _, _, _ = testTrustOwner(t)
	store.options.Now = func() int64 { panic("provider detail") }
	if now, err := store.RawClock(); now != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("panicking RawClock returned %d, %v", now, err)
	}
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("corrupt trust rows returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("foreign owner snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("foreign owner close = %v", err)
		}
	})

	t.Run("snapshot clock ahead of guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(trustBucket)
			payload, err := checkedPayload(bucket.Get(trustSnapshotKey))
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
			return bucket.Put(trustSnapshotKey, sealPayload(encoded))
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("incompatible committed clock returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("incompatible clock owner close = %v", err)
		}
	})
}

func TestTrustOperationsSnapshotDecodeAndOwnedGuardFailures(t *testing.T) {
	t.Run("valid checksum invalid snapshot", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(trustBucket).Put(trustSnapshotKey, sealPayload([]byte("not trust JSON")))
		}); err != nil {
			t.Fatal(err)
		}
		// Snapshot must fence when checksummed bytes fail strict snapshot decoding.
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid decoded snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid snapshot owner close = %v", err)
		}
	})

	t.Run("advance foreign owner guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		store.identity.Owner++
		_, err := store.AdvanceAndCheck()
		requireTrustOperationCode(t, err, "rotation_clock_unavailable")
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("foreign guard owner close = %v", err)
		}
	})

	t.Run("snapshot foreign owner guard", func(t *testing.T) {
		store, _, _, _, _ := testTrustOwner(t)
		store.identity.Owner++
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("foreign guard snapshot returned %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.CompareAndSwap(expected, desired, clock); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("CAS on fenced owner = %v", err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
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
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("post-commit fenced owner close = %v", err)
		}
	})
}
