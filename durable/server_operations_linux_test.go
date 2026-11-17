//go:build linux

package durable

import (
	"errors"
	"os"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

func mutateServerGuard(t *testing.T, store *ServerStore, mutate func(*trustGuard)) {
	t.Helper()
	if err := store.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(serverBucket)
		guard, err := decodeServerGuard(bucket.Get(serverGuardKey), store.options.TrustOptions, store.identity.Profile)
		if err != nil {
			return err
		}
		mutate(&guard)
		return bucket.Put(serverGuardKey, encodeServerGuard(guard))
	}); err != nil {
		t.Fatal(err)
	}
}

// server_operations.go: a same-time clock does not revise rows; rollback latches unsafe at the old H.
func TestServerClockNoOpKeepsTuple(t *testing.T) {
	store, _, _, _, _ := testServerOwner(t)
	beforeGuard, beforeSnapshot, beforeIntent := serverRows(t, store)
	clock, err := store.AdvanceAndCheck()
	if err != nil || clock.HighWater != 1000 || clock.Revision != 1 {
		t.Fatalf("same-time clock tuple = %+v, %v", clock, err)
	}
	afterGuard, afterSnapshot, afterIntent := serverRows(t, store)
	if string(beforeGuard) != string(afterGuard) || string(beforeSnapshot) != string(afterSnapshot) || string(beforeIntent) != string(afterIntent) {
		t.Fatal("same-time sample rewrote durable rows")
	}
}

// server_operations.go: an invalid owned guard fails snapshot validation and latches unavailable.
func TestServerSnapshotRejectsChangedOwnedGuard(t *testing.T) {
	store, _, _, _, _ := testServerOwner(t)
	mutateServerGuard(t, store, func(guard *trustGuard) { guard.Owner++ })
	if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) || !store.fenced.Load() {
		t.Fatalf("snapshot accepted changed owner: %v", err)
	}
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fenced close: %v", err)
	}
}

// server_operations.go: no operation on a closed owner returns authority or a clean second lease.
func TestServerRawClockAndClosedOperationGates(t *testing.T) {
	store, _, _, now, _ := testServerOwner(t)
	guardBefore, snapshotBefore, intentBefore := serverRows(t, store)
	clock, err := store.RawClock()
	if err != nil || clock != now.Load() {
		t.Fatalf("RawClock = %d, %v", clock, err)
	}
	guardAfter, snapshotAfter, intentAfter := serverRows(t, store)
	if string(guardBefore) != string(guardAfter) || string(snapshotBefore) != string(snapshotAfter) || string(intentBefore) != string(intentAfter) {
		t.Fatal("RawClock changed durable server rows")
	}
	store.options.Now = func() int64 {
		store.Fence()
		return now.Load()
	}
	if raw, err := store.RawClock(); raw != 0 || !errors.Is(err, ErrUnavailable) || !store.fenced.Load() {
		t.Fatalf("post-sample fence exposed clock: %d %v", raw, err)
	}
	if err := store.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fenced close: %v", err)
	}
	closed, _, _, _, signer := testServerOwner(t)
	expected, tuple, err := closed.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, expected, tuple, signer)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := closed.RawClock(); raw != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed RawClock = %d, %v", raw, err)
	}
	requireServerCode(t, func() error { _, err := closed.AdvanceAndCheck(); return err }(), "rotation_clock_unavailable")
	if _, _, err := closed.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed Snapshot: %v", err)
	}
	requireServerCode(t, func() error { _, err := closed.CheckSnapshotClock(expected); return err }(), "rotation_clock_unavailable")
	if err := closed.CompareAndSwap(expected, desired, tuple); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed CompareAndSwap: %v", err)
	}
	leaseStore, _, _, _, _ := testServerOwner(t)
	lease, err := leaseStore.AcquireServingLease()
	if err != nil {
		t.Fatal(err)
	}
	lease()
	lease()
	if err := leaseStore.Close(); err != nil {
		t.Fatalf("released lease close: %v", err)
	}
	if _, err := leaseStore.AcquireServingLease(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed serving lease: %v", err)
	}
}

// server_operations.go: provider panics never unwind through raw or authoritative clock APIs.
func TestServerClockProviderPanicsFailClosed(t *testing.T) {
	t.Run("raw clock", func(t *testing.T) {
		store, _, _, _, _ := testServerOwner(t)
		store.options.Now = func() int64 { panic("injected raw server clock panic") }
		if raw, err := store.RawClock(); raw != 0 || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("RawClock panic result: %d, %v", raw, err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
	t.Run("advance clock", func(t *testing.T) {
		store, _, _, _, _ := testServerOwner(t)
		store.options.Now = func() int64 { panic("injected authoritative server clock panic") }
		if _, err := store.AdvanceAndCheck(); err == nil {
			t.Fatal("AdvanceAndCheck panic result was accepted")
		} else {
			requireServerCode(t, err, "rotation_clock_unavailable")
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
}

// server_operations.go: invalid expected/desired snapshots and clock mismatch get exact refusal codes.
func TestServerSnapshotAndPublicationInputRefusals(t *testing.T) {
	store, _, _, _, signer := testServerOwner(t)
	expected, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, expected, clock, signer)
	invalid := expected
	invalid.FormatVersion++
	requireServerCode(t, func() error { _, err := store.CheckSnapshotClock(invalid); return err }(), "rotation_state_unavailable")
	requireServerCode(t, store.CompareAndSwap(invalid, desired, clock), "rotation_state_unavailable")
	requireServerCode(t, store.CompareAndSwap(expected, invalid, clock), "rotation_state_unavailable")
	wrongClock := clock
	wrongClock.Revision++
	requireServerCode(t, store.CompareAndSwap(expected, desired, wrongClock), "rotation_state_changed")
	requireServerCode(t, store.CompareAndSwap(expected, expected, clock), "rotation_state_unavailable")
	changedReferences := desired
	changedReferences.SignerReferences = append([]rotation.SignerReference(nil), desired.SignerReferences...)
	changedReferences.SignerReferences[0].Reference += "/changed"
	requireServerCode(t, store.CompareAndSwap(expected, changedReferences, clock), "rotation_state_unavailable")
	if store.fenced.Load() {
		t.Fatal("definite input refusal fenced a healthy store")
	}
}

// server_operations.go: invalid owned guards and corrupt payloads fail closed.
func TestServerOwnedGuardAndCorruptSnapshotFailures(t *testing.T) {
	t.Run("owned guard", func(t *testing.T) {
		store, _, _, _, signer := testServerOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendServer(t, expected, clock, signer)
		mutateServerGuard(t, store, func(guard *trustGuard) { guard.Owner++ })
		requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Snapshot with changed owner: %v", err)
		}
		if _, err := store.AdvanceAndCheck(); !errors.Is(err, ErrUnavailable) || !store.fenced.Load() {
			t.Fatal("owned guard failure did not deny clock authority")
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
	for _, operation := range []string{"clock", "snapshot", "publication"} {
		t.Run(operation, func(t *testing.T) {
			store, _, _, _, signer := testServerOwner(t)
			expected, clock, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			desired := extendServer(t, expected, clock, signer)
			if err := store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverSnapshotKey, []byte{1}) }); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "clock":
				_, err = store.CheckSnapshotClock(expected)
				requireServerCode(t, err, "rotation_clock_unavailable")
			case "snapshot":
				if _, _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("corrupt snapshot read: %v", err)
				}
			case "publication":
				requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
			}
			if !store.fenced.Load() {
				t.Fatal("corrupt durable state did not fence owner")
			}
			if err := store.Close(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
}

// server_operations.go: unsafe samples preserve H, and revision exhaustion cannot advance it.
func TestServerUnsafeClockAndRevisionExhaustion(t *testing.T) {
	for _, sample := range []struct {
		name string
		now  int64
	}{
		{name: "negative", now: -1},
		{name: "above maximum", now: rotation.MaxTimestamp + 1},
	} {
		t.Run(sample.name, func(t *testing.T) {
			store, _, _, now, _ := testServerOwner(t)
			now.Store(sample.now)
			_, err := store.AdvanceAndCheck()
			requireServerCode(t, err, "rotation_clock_unsafe")
			guard, _, _ := serverRows(t, store)
			persisted, err := decodeServerGuard(guard, store.options.TrustOptions, store.identity.Profile)
			if err != nil || !persisted.Clock.Unsafe || persisted.Clock.HighWater != 1000 || persisted.Clock.Revision != 2 {
				t.Fatalf("unsafe clock tuple = %+v, %v", persisted.Clock, err)
			}
			if err := store.Close(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe close: %v", err)
			}
		})
	}
	t.Run("rollback and catch-up", func(t *testing.T) {
		store, _, _, now, _ := testServerOwner(t)
		now.Store(999)
		_, err := store.AdvanceAndCheck()
		requireServerCode(t, err, "rotation_clock_unsafe")
		now.Store(2000)
		_, err = store.AdvanceAndCheck()
		requireServerCode(t, err, "rotation_clock_unsafe")
		guard, _, _ := serverRows(t, store)
		persisted, err := decodeServerGuard(guard, store.options.TrustOptions, store.identity.Profile)
		if err != nil || !persisted.Clock.Unsafe || persisted.Clock.HighWater != 1000 || persisted.Clock.Revision != 2 {
			t.Fatalf("rollback latch = %+v, %v", persisted.Clock, err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unsafe close: %v", err)
		}
	})
	t.Run("revision exhausted", func(t *testing.T) {
		store, _, _, now, _ := testServerOwner(t)
		mutateServerGuard(t, store, func(guard *trustGuard) { guard.Clock.Revision = rotation.MaxOrdinal })
		now.Store(1001)
		_, err := store.AdvanceAndCheck()
		requireServerCode(t, err, "rotation_clock_unavailable")
		guard, _, _ := serverRows(t, store)
		persisted, err := decodeServerGuard(guard, store.options.TrustOptions, store.identity.Profile)
		if err != nil || persisted.Clock.Revision != rotation.MaxOrdinal || persisted.Clock.HighWater != 1000 {
			t.Fatalf("exhausted clock changed: %+v, %v", persisted.Clock, err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
}

// server_operations.go: clock-provider panics become unavailable and exact CAS clock mismatch stays definite.
func TestServerClockPanicAndCASClockConflict(t *testing.T) {
	t.Run("clock panic", func(t *testing.T) {
		store, _, _, _, _ := testServerOwner(t)
		store.options.Now = func() int64 { panic("injected server clock panic") }
		if _, err := store.AdvanceAndCheck(); err == nil {
			t.Fatal("clock panic authorized time")
		} else {
			requireServerCode(t, err, "rotation_clock_unavailable")
		}
		if !store.fenced.Load() {
			t.Fatal("clock panic failed to fence owner")
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("panic close: %v", err)
		}
	})
	t.Run("clock tuple changed", func(t *testing.T) {
		store, _, _, now, signer := testServerOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendServer(t, expected, clock, signer)
		now.Store(1001)
		advanced, err := store.AdvanceAndCheck()
		if err != nil || advanced.HighWater != 1001 || advanced.Revision != clock.Revision+1 {
			t.Fatalf("clock advance = %+v, %v", advanced, err)
		}
		requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_changed")
		if store.fenced.Load() {
			t.Fatal("definite guard-clock conflict fenced the owner")
		}
		if err := store.Close(); err != nil {
			t.Fatalf("healthy close after conflict: %v", err)
		}
	})
}

// server_operations.go: post-transaction fencing suppresses ACK after a committed write.
func TestServerClockAndPublicationRejectPostTransactionFence(t *testing.T) {
	t.Run("clock", func(t *testing.T) {
		store, _, _, now, _ := testServerOwner(t)
		base := store.transact
		store.transact = func(apply func(*bolt.Tx) error) error {
			err := base(apply)
			store.Fence()
			return err
		}
		now.Store(1001)
		_, err := store.AdvanceAndCheck()
		requireServerCode(t, err, "rotation_clock_unavailable")
		guard, _, _ := serverRows(t, store)
		persisted, err := decodeServerGuard(guard, store.options.TrustOptions, store.identity.Profile)
		if err != nil || persisted.Clock.HighWater != 1001 || persisted.Clock.Revision != 2 {
			t.Fatalf("committed clock not observed: %+v, %v", persisted.Clock, err)
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
	t.Run("publication", func(t *testing.T) {
		store, _, _, _, signer := testServerOwner(t)
		expected, clock, err := store.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		desired := extendServer(t, expected, clock, signer)
		base := store.transact
		store.transact = func(apply func(*bolt.Tx) error) error {
			err := base(apply)
			store.Fence()
			return err
		}
		requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
		_, persisted, intent := serverRows(t, store)
		wanted, err := rotation.EncodeServerSnapshot(desired, store.options.Binding, store.options.Window, store.options.Checkpoint)
		if err != nil || string(persisted) != string(wanted) || len(intent) == 0 {
			t.Fatal("post-commit fence did not preserve publication and intent")
		}
		if err := store.Close(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("fenced close: %v", err)
		}
	})
}

// server_operations.go: callback Put errors are unknown, not definite conflicts.
func TestServerReadonlyTransactionsFailClosed(t *testing.T) {
	for _, operation := range []string{"clock", "publication"} {
		t.Run(operation, func(t *testing.T) {
			store, _, _, now, signer := testServerOwner(t)
			expected, clock, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			desired := extendServer(t, expected, clock, signer)
			store.transact = func(apply func(*bolt.Tx) error) error { return store.db.View(apply) }
			if operation == "clock" {
				now.Store(1001)
				_, err = store.AdvanceAndCheck()
				requireServerCode(t, err, "rotation_clock_unavailable")
			} else {
				requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
				_, persisted, intent := serverRows(t, store)
				wanted, encodeErr := rotation.EncodeServerSnapshot(expected, store.options.Binding, store.options.Window, store.options.Checkpoint)
				if encodeErr != nil || string(persisted) != string(wanted) || len(intent) != 0 {
					t.Fatal("readonly transaction changed publication rows")
				}
			}
			if !store.fenced.Load() {
				t.Fatal("readonly transaction error did not fence store")
			}
			if err := store.Close(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("fenced close: %v", err)
			}
		})
	}
}

// server_operations.go: post-commit Stat failures suppress ACK but preserve the committed disposition.
func TestServerPostCommitFileStatFailuresFenceAcknowledgment(t *testing.T) {
	for _, operation := range []string{"clock", "publication"} {
		for _, fixture := range []string{"stat error", "oversized file"} {
			t.Run(operation+"/"+fixture, func(t *testing.T) {
				store, _, _, now, signer := testServerOwner(t)
				expected, clock, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				desired := extendServer(t, expected, clock, signer)
				original := store.file
				fake, err := os.CreateTemp(t.TempDir(), "server-stat-")
				if err != nil {
					t.Fatal(err)
				}
				defer fake.Close()
				if fixture == "oversized file" {
					if err := fake.Truncate(maxFileBytes + pageBytes); err != nil {
						t.Fatal(err)
					}
				} else if err := fake.Close(); err != nil {
					t.Fatal(err)
				}
				store.file = fake
				if operation == "clock" {
					now.Store(1001)
					_, err = store.AdvanceAndCheck()
					requireServerCode(t, err, "rotation_clock_unavailable")
					guard, _, _ := serverRows(t, store)
					persisted, decodeErr := decodeServerGuard(guard, store.options.TrustOptions, store.identity.Profile)
					if decodeErr != nil || persisted.Clock.HighWater != 1001 || persisted.Clock.Revision != 2 {
						t.Fatalf("clock transaction was not committed: %+v, %v", persisted.Clock, decodeErr)
					}
				} else {
					requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_unknown")
					_, persisted, intent := serverRows(t, store)
					wanted, encodeErr := rotation.EncodeServerSnapshot(desired, store.options.Binding, store.options.Window, store.options.Checkpoint)
					if encodeErr != nil || string(persisted) != string(wanted) || len(intent) == 0 {
						t.Fatal("publication transaction was not committed")
					}
				}
				store.file = original
				if !store.fenced.Load() {
					t.Fatal("invalid backing-file stat did not fence owner")
				}
				if err := store.Close(); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("fenced close: %v", err)
				}
			})
		}
	}
}

// server_operations.go: a durable clock tuple changed outside the CAS expectation is a definite conflict.
func TestServerCASRejectsChangedGuardClock(t *testing.T) {
	store, _, _, _, signer := testServerOwner(t)
	expected, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, expected, clock, signer)
	mutateServerGuard(t, store, func(guard *trustGuard) {
		guard.Clock.HighWater++
		guard.Clock.Revision++
	})
	requireServerCode(t, store.CompareAndSwap(expected, desired, clock), "rotation_state_changed")
	if store.fenced.Load() {
		t.Fatal("definite guard-clock conflict fenced the owner")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close after definite guard-clock conflict: %v", err)
	}
}

// server_operations.go: definite stale-state conflict leaves the owner usable.
func TestServerDefiniteSnapshotConflictDoesNotFence(t *testing.T) {
	store, _, _, _, signer := testServerOwner(t)
	previous, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, previous, clock, signer)
	if err := store.CompareAndSwap(previous, desired, clock); err != nil {
		t.Fatal(err)
	}
	requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_changed")
	_, err = store.CheckSnapshotClock(previous)
	requireServerCode(t, err, "rotation_state_changed")
	current, _, err := store.Snapshot()
	if err != nil || current.Public.Head != desired.Public.Head || store.fenced.Load() {
		t.Fatalf("definite conflict damaged current state: %v", err)
	}
}
