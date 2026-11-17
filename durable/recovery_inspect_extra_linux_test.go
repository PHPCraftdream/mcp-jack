//go:build linux

package durable

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

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

	corrupt := filepath.Join(privateTestDirectory(t), "not-a-database.db")
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
