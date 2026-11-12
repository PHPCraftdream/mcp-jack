//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

func unknownFinalSnapshot(t *testing.T, committed bool) (string, Options, RecoverySnapshot, server.NonceReceipt) {
	t.Helper()
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	state := server.NewMemoryState()
	request := signedStorageRequest(t, state, 100, 12)
	original := owner.transact
	calls := 0
	injected := errors.New("public recovery fixture uncertainty")
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
	result := actualVerifier(t, owner, state, &now).Verify(request)
	result.Done()
	if result.Accepted || result.NonceRecorded || calls != 2 || !owner.fenced.Load() {
		t.Fatalf("unknown fixture admitted or retried: %+v", result)
	}
	_ = owner.Close()
	opts.Now = func() int64 { panic("reconciliation must not sample clock") }
	snapshot, err := InspectRecovery(path, opts)
	if err != nil || !snapshot.Dirty || len(snapshot.Live)+len(snapshot.Intents) != 1 {
		t.Fatalf("unknown fixture lost persisted outcome: %+v %v", snapshot, err)
	}
	if committed {
		return path, opts, snapshot, snapshot.Live[0]
	}
	return path, opts, snapshot, snapshot.Intents[0]
}

func TestExactUnknownReconciliationCreatesTerminalTombstoneWithoutReopen(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "final-absent", true: "final-present"}[committed], func(t *testing.T) {
			path, opts, before, receipt := unknownFinalSnapshot(t, committed)
			if err := ReconcileUnknown(path, opts, before.Hash, receipt); err != nil {
				t.Fatal(err)
			}
			after, err := InspectRecovery(path, opts)
			if err != nil || !after.Dirty || after.Unsafe != before.Unsafe || after.HighWater != before.HighWater || after.StoreGeneration != before.StoreGeneration || after.OwnerGeneration != before.OwnerGeneration || after.StoreID != before.StoreID || after.Hash == before.Hash || len(after.Live) != 0 || len(after.Intents) != 0 || len(after.Tombstones) != 1 || after.Tombstones[0] != receipt {
				t.Fatalf("terminal reconciliation changed identity or cleared fence: %+v %v", after, err)
			}
			if err := ReconcileUnknown(path, opts, before.Hash, receipt); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("stale snapshot was accepted: %v", err)
			}
			if err := ReconcileUnknown(path, opts, after.Hash, receipt); err != nil {
				t.Fatal("explicit exact terminal recheck was not idempotent:", err)
			}
			again, err := InspectRecovery(path, opts)
			if err != nil || again.Hash != after.Hash {
				t.Fatalf("terminal recheck rewrote logical history: %v", err)
			}
			opts.Now = func() int64 { return 2000 }
			if opened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
				if opened != nil {
					opened.Fence()
					_ = opened.Close()
				}
				t.Fatalf("reconciliation or expiry authorized serving: %v", err)
			}
		})
	}
}

func TestReconciliationRejectsInexactReceiptAndAbsentOperationWithoutWrites(t *testing.T) {
	path, opts, snapshot, receipt := unknownFinalSnapshot(t, false)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*server.NonceReceipt){
		func(r *server.NonceReceipt) { r.OperationID[0] ^= 1 },
		func(r *server.NonceReceipt) { r.IntentID = "wrong" },
		func(r *server.NonceReceipt) { r.HighWater++ },
		func(r *server.NonceReceipt) { r.OwnerGeneration++ },
	} {
		wrong := receipt
		mutate(&wrong)
		if err := ReconcileUnknown(path, opts, snapshot.Hash, wrong); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("inexact operation was reconciled: %v", err)
		}
	}
	// Canonical, но отсутствующая pair; отсутствие не разрешает reset/reopen.
	missing := receipt
	missing.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
	if err := ReconcileUnknown(path, opts, snapshot.Hash, missing); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("absent operation cleared unknown: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("definite reconciliation rejection changed database bytes")
	}
}

func TestReconciliationRefusesCleanStore(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	seedLiveHistory(t, owner, 1, func(int) int64 { return 100 })
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectRecovery(path, opts)
	if err != nil || snapshot.Dirty || len(snapshot.Live) != 1 {
		t.Fatalf("clean fixture: %+v %v", snapshot, err)
	}
	if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("normal committed operation was marked unknown: %v", err)
	}
}

func TestReconciliationTombstoneCapacityNeverEvictsHistory(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	seedLiveHistory(t, owner, 65, func(int) int64 { return 100 })
	owner.Fence()
	_ = owner.Close()
	snapshot, err := InspectRecovery(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 64; count++ {
		if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); err != nil {
			t.Fatal(err)
		}
		snapshot, err = InspectRecovery(path, opts)
		if err != nil || len(snapshot.Tombstones) != count+1 || len(snapshot.Live) != 64-count {
			t.Fatalf("capacity conversion lost history: %+v %v", snapshot, err)
		}
	}
	if err := ReconcileUnknown(path, opts, snapshot.Hash, snapshot.Live[0]); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("tombstone capacity exceeded: %v", err)
	}
	after, err := InspectRecovery(path, opts)
	if err != nil || after.Hash != snapshot.Hash || len(after.Tombstones) != 64 || len(after.Live) != 1 || !after.Dirty {
		t.Fatalf("capacity refusal evicted or changed history: %+v %v", after, err)
	}
}

func TestUnknownReconciliationCommitNeverRetriesOrClearsDirty(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "tombstone-absent", true: "tombstone-present"}[committed], func(t *testing.T) {
			path, opts, before, receipt := unknownFinalSnapshot(t, false)
			calls := 0
			injected := errors.New("public unknown reconciliation commit")
			err := reconcileUnknown(path, opts, before.Hash, receipt, func(db *bolt.DB, apply func(*bolt.Tx) error) error {
				calls++
				if committed {
					if err := db.Update(apply); err != nil {
						return err
					}
					return injected
				}
				return db.Update(func(tx *bolt.Tx) error {
					if err := apply(tx); err != nil {
						return err
					}
					return injected
				})
			})
			if !errors.Is(err, ErrUnavailable) || calls != 1 {
				t.Fatalf("unknown reconciliation retried or reported success: %v calls=%d", err, calls)
			}
			after, err := InspectRecovery(path, opts)
			if err != nil || !after.Dirty || (len(after.Tombstones) == 1) != committed || (len(after.Intents) == 1) == committed || len(after.Tombstones)+len(after.Intents) != 1 {
				t.Fatalf("unknown recovery outcome lost exact disposition: %+v %v", after, err)
			}
		})
	}
}
