//go:build linux

package durable

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

func TestServerInspectionRejectsInvalidOptionsAndOpenFailures(t *testing.T) {
	store, path, options, _, _ := testServerOwner(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	invalid := options
	invalid.Window = 0
	// server_inspect.go rejects invalid normalized options before the DB open.
	if report, err := InspectServer(path, invalid); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("invalid server options returned %+v, %v", report, err)
	}
	if report, err := InspectServer("relative.db", options); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("relative server path returned %+v, %v", report, err)
	}
	corrupt := filepath.Join(privateTestDirectory(t), "not-a-server-database.db")
	if err := os.WriteFile(corrupt, []byte("not a bbolt database"), 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := InspectServer(corrupt, options); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("failed server open returned %+v, %v", report, err)
	}
}

func mutateClosedServer(t *testing.T, path string, mutate func(*bolt.Bucket) error) {
	t.Helper()
	db, _, err := openTrustDB(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { return mutate(tx.Bucket(serverBucket)) }); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerInspectionRejectsMalformedRowsAndGuard(t *testing.T) {
	t.Run("incomplete rows", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error { return bucket.Delete(serverIntentKey) })
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("incomplete server rows returned %+v, %v", report, err)
		}
	})

	t.Run("invalid guard checksum", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error { return bucket.Put(serverGuardKey, []byte("bad checksum")) })
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("invalid server guard returned %+v, %v", report, err)
		}
	})
}

func TestServerInspectionRejectsInvalidSnapshotAndIncompatibleClock(t *testing.T) {
	t.Run("invalid snapshot", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error {
			return bucket.Put(serverSnapshotKey, sealPayload([]byte("not a server snapshot")))
		})
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("invalid server snapshot returned %+v, %v", report, err)
		}
	})

	t.Run("snapshot clock ahead of guard", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error {
			payload, err := checkedPayload(bucket.Get(serverSnapshotKey))
			if err != nil {
				return err
			}
			snapshot, err := rotation.DecodeServerSnapshot(payload, options.Binding, options.Window, options.Checkpoint)
			if err != nil {
				return err
			}
			snapshot.Public.Clock.HighWater++
			snapshot.Public.Clock.Revision++
			encoded, err := rotation.EncodeServerSnapshot(snapshot, options.Binding, options.Window, options.Checkpoint)
			if err != nil {
				return err
			}
			return bucket.Put(serverSnapshotKey, sealPayload(encoded))
		})
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("incompatible server clock returned %+v, %v", report, err)
		}
	})
}
