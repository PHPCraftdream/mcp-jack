//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestRecoveryInspectionIsExactOwnedAndNonMutating(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	rows := seedLiveHistory(t, owner, 2, func(int) int64 { return 100 })
	owner.Fence()
	_ = owner.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inspection := opts
	inspection.Now = func() int64 { panic("inspection must not sample clock") }
	report, err := InspectRecovery(path, inspection)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Dirty || report.Unsafe || report.HighWater != 100 || report.Window != 30 || report.OwnerGeneration != owner.meta.Owner || report.StoreGeneration != owner.meta.Generation || report.DeploymentID != opts.DeploymentID || report.StoreID == "" || report.Hash == "" || len(report.Live) != 2 || len(report.Intents) != 0 || len(report.Tombstones) != 0 {
		t.Fatalf("inexact recovery snapshot: %+v", report)
	}
	for index, row := range rows {
		if !reflect.DeepEqual(report.Live[index], row.receipt) {
			t.Fatal("inspection reconstructed or changed receipt")
		}
	}
	originalHash := report.Hash
	report.Live[0].KID = "caller mutation"
	again, err := InspectRecovery(path, inspection)
	if err != nil || again.Hash != originalHash || !reflect.DeepEqual(again.Live[0], rows[0].receipt) {
		t.Fatalf("inspection retained caller-owned report data: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed actual database bytes")
	}
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil {
		t.Fatal(err)
	}
	changeErr := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("metadata"))
		m, err := decodeMetadata(bucket.Get(headerKey))
		if err != nil {
			return err
		}
		m.HighWater++
		return bucket.Put(headerKey, encodeMetadata(m))
	})
	closeErr := db.Close()
	if changeErr != nil || closeErr != nil {
		t.Fatalf("snapshot change fixture: %v %v", changeErr, closeErr)
	}
	changed, err := InspectRecovery(path, inspection)
	if err != nil || changed.Hash == originalHash || changed.HighWater != 101 || changed.StoreID != again.StoreID {
		t.Fatalf("fingerprint did not bind actual metadata: %+v %v", changed, err)
	}
	if reopened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if reopened != nil {
			reopened.Fence()
			_ = reopened.Close()
		}
		t.Fatalf("inspection authorized serving reopen: %v", err)
	}
}

func TestRecoveryInspectionValidatesDirtyGraphInsteadOfRepairing(t *testing.T) {
	path, opts, _ := preparedSnapshot(t, func(tx *bolt.Tx, m *metadata, row nonceRecord) error {
		m.Dirty = true
		index := expiryKey(row)
		return tx.Bucket([]byte("expiry")).Delete(index[:])
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Now = func() int64 { panic("invalid recovery graph must not sample clock") }
	if _, err := InspectRecovery(path, opts); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("dirty bypass skipped graph validation: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid recovery graph was repaired or rewritten")
	}
}

func TestRecoveryInspectionPreservesUnsafeLatch(t *testing.T) {
	now := int64(100)
	owner, path, opts := testOwner(t, &now)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	now = 99
	if opened, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if opened != nil {
			opened.Fence()
			_ = opened.Close()
		}
		t.Fatalf("rollback was not latched: %v", err)
	}
	opts.Now = func() int64 { panic("inspection cannot establish clock safety") }
	report, err := InspectRecovery(path, opts)
	if err != nil || !report.Unsafe || !report.Dirty || report.HighWater != 100 {
		t.Fatalf("inspection cleared unsafe latch: %+v %v", report, err)
	}
}

func TestRecoveryInspectionRequiresExclusiveExistingStore(t *testing.T) {
	now := int64(100)
	_, path, opts := testOwner(t, &now)
	opts.Now = func() int64 { panic("inspection must not sample clock") }
	if _, err := InspectRecovery(path, opts); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inspection bypassed live owner lock: %v", err)
	}
	missing := filepath.Join(privateTestDirectory(t), "missing.db")
	if _, err := InspectRecovery(missing, opts); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing recovery store accepted: %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection created missing store: %v", err)
	}
}
