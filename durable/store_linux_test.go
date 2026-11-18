//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable/internal/testfixture"
	bolt "go.etcd.io/bbolt"
)

func testOptions(now *int64) Options {
	return Options{DeploymentID: "public-test-deployment", Window: 30, Now: func() int64 { return *now }}
}

func TestOpenMissingNeverCreates(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	if _, err := Open(path, testOptions(&now)); err == nil {
		t.Fatal("missing store opened")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("serving-open created a missing store")
	}
}

func TestInitializeRefusesReplacementAndCleanRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeUnused(path, opts); err == nil {
		t.Fatal("existing store replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed initialization changed existing bytes")
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.meta.Dirty || owner.meta.HighWater != 100 {
		t.Fatal("owner exposed before dirty/H receipt")
	}
	generation := owner.meta.Owner
	if _, err := Open(path, opts); err == nil {
		t.Fatal("second owner admitted")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("close is not idempotent")
	}
	now = 101
	reopened, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.meta.Owner != generation+1 || reopened.meta.HighWater != 101 {
		t.Fatal("restart did not preserve owner/H ordering")
	}
}

func TestDirectorySyncFailureLeavesInitializationFenced(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	opts := testOptions(&now)
	calls := 0
	err := initializeUnused(path, opts, func(directory string) error {
		calls++
		if directory != filepath.Dir(path) {
			t.Fatal("wrong directory sync target")
		}
		return errors.New("public injected directory sync failure")
	})
	if err == nil || calls != 1 {
		t.Fatal("initialization did not report failed sync")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("uncertain initialization file was removed")
	}
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil {
			owner.Fence()
			_ = owner.Close()
		}
		t.Fatalf("uncertain initialization admitted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal silently repaired/reset uncertain initialization")
	}
}

func TestUnsafePermissionsRefuseBeforeCreation(t *testing.T) {
	now := int64(100)
	directory := testfixture.PrivateDirectory(t)
	path := filepath.Join(directory, "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if owner, err := Open(path, opts); err == nil {
		_ = owner.Close()
		t.Fatal("public-readable database admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "new.db")
	if err := InitializeUnused(missing, opts); err == nil {
		t.Fatal("unsafe directory admitted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe initialization created a file")
	}
}

func TestFenceRemainsDirtyAcrossRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	owner.Fence()
	if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("close of a fenced store: %v", err)
	}
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("fenced store reopened: %v", err)
	}
}

func TestStartupClockPanicClosesActualOwnedFile(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	options := dbOptions(false)
	originalOpen := options.OpenFile
	var owned *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		file, err := originalOpen(name, flags, mode)
		if err == nil {
			owned = file
			t.Cleanup(func() { _ = file.Close() })
		}
		return file, err
	}
	broken := opts
	broken.Now = func() int64 { panic("public startup clock panic") }
	var observed any
	func() {
		defer func() { observed = recover() }()
		_, _ = openStore(path, broken, options)
	}()
	if observed != "public startup clock panic" || owned == nil {
		t.Fatal("startup clock panic was not exercised")
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("actual owned file was not closed: %v", err)
	}
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil {
			owner.Fence()
			_ = owner.Close()
		}
		t.Fatalf("dirty startup after panic was not fenced: %v", err)
	}
}

func TestStartupRollbackDoesNotClearAtCatchUp(t *testing.T) {
	now := int64(100)
	path := filepath.Join(testfixture.PrivateDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	now = 99
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("rollback admitted: %v", err)
	}
	now = 100
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("clock catch-up cleared rollback fence")
	}
}

func TestEmptyOversizedAndSymlinkStoresRefused(t *testing.T) {
	now := int64(100)
	directory := testfixture.PrivateDirectory(t)
	opts := testOptions(&now)
	for _, size := range []int64{0, maxFileBytes + pageBytes} {
		path := filepath.Join(directory, "size.db")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, opts); err == nil {
			t.Fatal("uninitialized/oversized store opened")
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() != size {
			t.Fatal("refusal changed file size")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, "original.db")
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "alias.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, opts); err == nil {
		t.Fatal("symlink store opened")
	}
}

func preparedSnapshot(t *testing.T, change func(*bolt.Tx, *metadata, nonceRecord) error) (string, Options, nonceRecord) {
	t.Helper()
	now := int64(100)
	opts := testOptions(&now)
	path := filepath.Join(testfixture.PrivateDirectory(t), "history.db")
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var m metadata
	if err := db.View(func(tx *bolt.Tx) error {
		var err error
		m, err = decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	row := testRecord(t, m, liveRecord)
	encoded, err := encodeRecord(row, m)
	if err != nil {
		t.Fatal(err)
	}
	index := expiryKey(row)
	if err := db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("live")).Put(row.key[:], encoded); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], row.key[:]); err != nil {
			return err
		}
		m.Live = 1
		if change != nil {
			if err := change(tx, &m, row); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path, opts, row
}

func TestPopulatedHistoryValidatedWithoutImplicitExpiry(t *testing.T) {
	path, opts, row := preparedSnapshot(t, nil)
	opts.Now = func() int64 { return 200 }
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if owner.meta.Live != 1 || owner.meta.HighWater != 200 {
		t.Fatal("loader discarded history or skipped H")
	}
	if err := owner.db.View(func(tx *bolt.Tx) error {
		got, err := decodeRecord(tx.Bucket([]byte("live")).Get(row.key[:]), owner.meta)
		if err != nil {
			return err
		}
		if got != row {
			return errors.New("startup rewrote historical receipt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBrokenHistoryGraphRejected(t *testing.T) {
	cases := map[string]func(*bolt.Tx, *metadata, nonceRecord) error{
		"missing-expiry": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			return tx.Bucket([]byte("expiry")).Delete(index[:])
		},
		"extra-expiry": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			index[7] ^= 1
			return tx.Bucket([]byte("expiry")).Put(index[:], []byte{})
		},
		"nonempty-expiry-value": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			index := expiryKey(row)
			return tx.Bucket([]byte("expiry")).Put(index[:], []byte{1})
		},
		"missing-operation": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			return tx.Bucket([]byte("operation")).Delete(row.receipt.OperationID[:])
		},
		"wrong-operation-target": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			return tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], make([]byte, 48))
		},
		"extra-operation": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			id := row.receipt.OperationID
			id[0] ^= 2
			return tx.Bucket([]byte("operation")).Put(id[:], row.key[:])
		},
		"wrong-counter": func(_ *bolt.Tx, m *metadata, _ nonceRecord) error { m.Live++; return nil },
		"damaged-receipt": func(tx *bolt.Tx, _ *metadata, row nonceRecord) error {
			data := append([]byte(nil), tx.Bucket([]byte("live")).Get(row.key[:])...)
			data[20] ^= 1
			return tx.Bucket([]byte("live")).Put(row.key[:], data)
		},
		"extra-bucket": func(tx *bolt.Tx, _ *metadata, _ nonceRecord) error {
			_, err := tx.CreateBucket([]byte("extra"))
			return err
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			path, opts, _ := preparedSnapshot(t, change)
			if owner, err := Open(path, opts); !errors.Is(err, ErrInvalidStore) {
				if owner != nil {
					owner.Fence()
					_ = owner.Close()
				}
				t.Fatalf("invalid graph admitted: %v", err)
			}
		})
	}
}

func TestUnsettledIntentCannotBecomeReadyThroughCleanHeader(t *testing.T) {
	path, opts, _ := preparedSnapshot(t, func(tx *bolt.Tx, m *metadata, row nonceRecord) error {
		index := expiryKey(row)
		if err := tx.Bucket([]byte("live")).Delete(row.key[:]); err != nil {
			return err
		}
		if err := tx.Bucket([]byte("expiry")).Delete(index[:]); err != nil {
			return err
		}
		row.kind = intentRecord
		encoded, err := encodeRecord(row, *m)
		if err != nil {
			return err
		}
		m.Live, m.Intents = 0, 1
		return tx.Bucket([]byte("intent")).Put(row.key[:], encoded)
	})
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil {
			owner.Fence()
			_ = owner.Close()
		}
		t.Fatalf("unsettled intent admitted: %v", err)
	}
}

func TestExpiryIndexHasExactBigEndianDeadlineAndPair(t *testing.T) {
	m := validTestMetadata()
	row := testRecord(t, m, liveRecord)
	index := expiryKey(row)
	if !bytes.Equal(index[:8], []byte{0, 0, 0, 0, 0, 0, 0, 130}) || !bytes.Equal(index[8:], row.key[:]) {
		t.Fatal("expiry key changed from uint64be(retainUntil)||kid||nonce")
	}
}

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
	missing := filepath.Join(testfixture.PrivateDirectory(t), "missing.db")
	if _, err := InspectRecovery(missing, opts); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing recovery store accepted: %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection created missing store: %v", err)
	}
}

func TestRecoveryInspectionOptionAndOpenFailuresAreSpecific(t *testing.T) {
	now := int64(100)
	_, path, options := testOwner(t, &now)

	invalid := options
	invalid.Window = 0
	// recovery_inspect.go propagates normalized option validation before opening the DB.
	if report, err := InspectRecovery(path, invalid); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, RecoverySnapshot{}) {
		t.Fatalf("invalid recovery options returned %+v, %v", report, err)
	}
	if report, err := InspectRecovery("relative.db", options); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, RecoverySnapshot{}) {
		t.Fatalf("relative recovery path returned %+v, %v", report, err)
	}

	corrupt := filepath.Join(testfixture.PrivateDirectory(t), "not-a-database.db")
	if err := os.WriteFile(corrupt, []byte("not a bbolt database"), 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := InspectRecovery(corrupt, options); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, RecoverySnapshot{}) {
		t.Fatalf("failed recovery open returned %+v, %v", report, err)
	}
}

func TestRecoveryInspectionRejectsMalformedExistingRows(t *testing.T) {
	now := int64(100)
	owner, path, options := testOwner(t, &now)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0600, dbOptions(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("metadata")).Put(headerKey, []byte("bad metadata"))
	}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	options.Now = func() int64 { panic("inspection must not sample clock") }
	// recovery_inspect.go returns readStoreSnapshot validation errors and never samples Now.
	if report, err := InspectRecovery(path, options); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, RecoverySnapshot{}) {
		t.Fatalf("malformed recovery rows returned %+v, %v", report, err)
	}
}
