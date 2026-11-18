//go:build linux

package rotationstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

func testServerOwner(t *testing.T) (*ServerStore, string, ServerOptions, *atomic.Int64, trustTestSigner) {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(1000)
	base, signer := trustTestOptions(now)
	options := ServerOptions{TrustOptions: base, AnchorReference: "protected/anchor"}
	path := filepath.Join(testfixture.PrivateDirectory(t), "server.db")
	if err := InitializeServerUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := OpenServer(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path, options, now, signer
}

func extendServer(t *testing.T, snapshot rotation.ServerSnapshot, clock rotation.ClockTuple, signer trustTestSigner) rotation.ServerSnapshot {
	t.Helper()
	desired := snapshot
	desired.Public = extendTrust(t, snapshot.Public, clock, signer)
	last := desired.Public.Keys[len(desired.Public.Keys)-1]
	desired.SignerReferences = append(append([]rotation.SignerReference{}, snapshot.SignerReferences...), rotation.SignerReference{KID: last.KID, Reference: "protected/" + last.KID})
	return desired
}

func serverRows(t *testing.T, store *ServerStore) ([]byte, []byte, []byte) {
	t.Helper()
	var guard, snapshot, intent []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		var err error
		guard, snapshot, intent, err = readServerRows(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return guard, snapshot, intent
}

func requireServerCode(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *rotation.Error
	if !errors.As(err, &refusal) || refusal.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestServerStoreExactPublicationIntentAndCleanReopen(t *testing.T) {
	store, path, options, _, signer := testServerOwner(t)
	if other, err := OpenServer(path, options); err == nil || other != nil {
		t.Fatal("second owner admitted")
	}
	if err := InitializeServerUnused(path, options); err == nil {
		t.Fatal("existing server store replaced")
	}
	previous, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, previous, clock, signer)
	guardBefore, encodedBefore, empty := serverRows(t, store)
	if len(empty) != 0 {
		t.Fatal("unused store has publication intent")
	}
	if err := store.CompareAndSwap(previous, desired, clock); err != nil {
		t.Fatal(err)
	}
	guardAfter, encodedAfter, intent := serverRows(t, store)
	if !bytes.Equal(guardBefore, guardAfter) {
		t.Fatal("publication mutated authoritative clock or owner")
	}
	expectedBytes, desiredBytes, err := decodeServerIntent(intent)
	if err != nil || !bytes.Equal(expectedBytes, encodedBefore) || !bytes.Equal(desiredBytes, encodedAfter) {
		t.Fatal("intent did not retain exact expected/desired bytes")
	}
	loaded, _, err := store.Snapshot()
	if err != nil || !reflect.DeepEqual(loaded, desired) {
		t.Fatalf("ACK not persisted: %v", err)
	}
	requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_changed")
	_, err = store.CheckSnapshotClock(previous)
	requireServerCode(t, err, "rotation_state_changed")
	if store.fenced.Load() {
		t.Fatal("definite conflict fenced healthy owner")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenServer(path, options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, _, err = reopened.Snapshot()
	if err != nil || !reflect.DeepEqual(loaded, desired) {
		t.Fatal("clean reopen lost ring or references")
	}
}

func TestServerStoreSeparateClockConflictAndRollbackLatch(t *testing.T) {
	store, path, options, now, signer := testServerOwner(t)
	previous, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, previous, clock, signer)
	_, before, intentBefore := serverRows(t, store)
	now.Store(1001)
	advanced, err := store.CheckSnapshotClock(previous)
	if err != nil || advanced.HighWater != 1001 || advanced.Revision != clock.Revision+1 {
		t.Fatal("server guard did not advance separately")
	}
	requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_changed")
	_, after, intentAfter := serverRows(t, store)
	if !bytes.Equal(before, after) || !bytes.Equal(intentBefore, intentAfter) {
		t.Fatal("clock conflict mutated ring")
	}
	now.Store(1000)
	_, err = store.CheckSnapshotClock(previous)
	requireServerCode(t, err, "rotation_clock_unsafe")
	now.Store(1002)
	_, err = store.AdvanceAndCheck()
	requireServerCode(t, err, "rotation_clock_unsafe")
	if store.Close() == nil {
		t.Fatal("unsafe store closed healthy")
	}
	if reopened, err := OpenServer(path, options); err == nil || reopened != nil {
		t.Fatal("catch-up cleared durable rollback latch")
	}
}

func TestServerStoreUnknownWritesFenceBothCommittedAndAbsentOutcomes(t *testing.T) {
	for _, operation := range []string{"publication", "clock"} {
		for _, committed := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "-absent", true: "-committed"}[committed], func(t *testing.T) {
				store, path, options, now, signer := testServerOwner(t)
				previous, clock, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				desired := extendServer(t, previous, clock, signer)
				attempts := 0
				store.transact = func(fn func(*bolt.Tx) error) error {
					attempts++
					if committed {
						if err := store.db.Update(fn); err != nil {
							t.Fatal(err)
						}
					} else {
						injected := errors.New("definite fixture rollback")
						err := store.db.Update(func(tx *bolt.Tx) error {
							if err := fn(tx); err != nil {
								return err
							}
							return injected
						})
						if !errors.Is(err, injected) {
							t.Fatal(err)
						}
					}
					return errors.New("unknown storage result")
				}
				if operation == "publication" {
					requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_unknown")
				} else {
					now.Store(1001)
					_, err := store.AdvanceAndCheck()
					requireServerCode(t, err, "rotation_clock_unavailable")
				}
				if attempts != 1 || !store.fenced.Load() {
					t.Fatal("unknown outcome retried or served")
				}
				_, persisted, intent := serverRows(t, store)
				if operation == "publication" {
					wanted := previous
					if committed {
						wanted = desired
					}
					encoded, err := rotation.EncodeServerSnapshot(wanted, options.Binding, options.Window, options.Checkpoint)
					if err != nil || !bytes.Equal(encoded, persisted) || (len(intent) != 0) != committed {
						t.Fatal("fixture did not exercise claimed commit outcome")
					}
				}
				if _, _, err := store.Snapshot(); err == nil {
					t.Fatal("fenced state exposed")
				}
				if store.Close() == nil || attempts != 1 {
					t.Fatal("close cleared or retried unknown operation")
				}
				if reopened, err := OpenServer(path, options); err == nil || reopened != nil {
					t.Fatal("unknown dirty startup admitted")
				}
			})
		}
	}
}

func TestServerStoreRejectsClientDomainAndChangedAnchorReference(t *testing.T) {
	store, path, options, _, _ := testServerOwner(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	changed := options
	changed.AnchorReference = "replacement"
	if owner, err := OpenServer(path, changed); err == nil || owner != nil {
		t.Fatal("protected OOB profile silently replaced")
	}
	if owner, err := OpenTrust(path, options.TrustOptions); err == nil || owner != nil {
		t.Fatal("server DB accepted as client DB")
	}
	clientPath := filepath.Join(testfixture.PrivateDirectory(t), "client.db")
	if err := InitializeTrustUnused(clientPath, options.TrustOptions); err != nil {
		t.Fatal(err)
	}
	if owner, err := OpenServer(clientPath, options); err == nil || owner != nil {
		t.Fatal("client DB accepted as server DB")
	}
	missing := filepath.Join(testfixture.PrivateDirectory(t), "missing.db")
	if owner, err := OpenServer(missing, options); err == nil || owner != nil {
		t.Fatal("missing server store created")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("open created path")
	}
}

func inspectionOptions(t *testing.T, options ServerOptions) ServerOptions {
	t.Helper()
	options.Now = func() int64 { t.Error("offline inspection invoked clock"); return -1 }
	return options
}

func TestServerInspectionExclusivePublicOnlyAndNoMutation(t *testing.T) {
	store, path, options, _, signer := testServerOwner(t)
	offline := inspectionOptions(t, options)
	if report, err := InspectServer(path, offline); err == nil || report != (ServerInspection{}) {
		t.Fatal("offline inspection bypassed serving owner")
	}
	previous, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	desired := extendServer(t, previous, clock, signer)
	if err := store.CompareAndSwap(previous, desired, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectServer(path, offline)
	if err != nil || report.Dirty || report.Unsafe || report.Fenced || report.HighWater != 1000 || report.Window != 30 || report.ClockRevision != clock.Revision || report.StateRevision != 2 || report.HeadOrdinal != 1 || report.HeadHash != desired.Public.Head.Hash || report.RetainedKeys != 2 || !report.PublicationPresent || report.StoreID == "" {
		t.Fatal("inspection did not describe committed public metadata", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil || bytes.Contains(encoded, []byte("protected/")) || bytes.Contains(encoded, []byte("reference")) || bytes.Contains(encoded, []byte("private")) || bytes.Contains(encoded, []byte(path)) {
		t.Fatal("inspection disclosed protected locator/path")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection rewrote existing store")
	}
	repeated, err := InspectServer(path, offline)
	if err != nil || !reflect.DeepEqual(report, repeated) {
		t.Fatal("inspection advanced owner/clock or changed report", err)
	}
	reopened, err := OpenServer(path, options)
	if err != nil {
		t.Fatal("healthy inspected store could not reopen", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerInspectionPreservesDirtyAndUnsafeRecoveryGates(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "dirty-unknown", true: "unsafe"}[unsafe], func(t *testing.T) {
			store, path, options, now, _ := testServerOwner(t)
			if unsafe {
				now.Store(999)
				if _, err := store.AdvanceAndCheck(); err == nil {
					t.Fatal("fixture did not latch rollback")
				}
			} else {
				store.Fence()
			}
			if err := store.Close(); err == nil {
				t.Fatal("fixture closed uncertain owner healthy")
			}
			now.Store(2000)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			report, err := InspectServer(path, inspectionOptions(t, options))
			if err != nil || !report.Dirty || report.Unsafe != unsafe || report.HighWater != 1000 || report.StateRevision != 1 || report.PublicationPresent || report.RetainedKeys != 1 {
				t.Fatal("inspection repaired/rejected diagnostic recovery flags", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("inspection changed recovery evidence")
			}
			if owner, err := OpenServer(path, options); err == nil || owner != nil {
				t.Fatal("inspection authorized recovery or catch-up cleared fence")
			}
		})
	}
}

func TestServerInspectionRejectsLostIntentAndNeverCreatesMissingStore(t *testing.T) {
	store, path, options, _, signer := testServerOwner(t)
	previous, clock, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwap(previous, extendServer(t, previous, clock, signer), clock); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, _, err := ownedfile.OpenDB(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(serverBucket).Put(serverIntentKey, []byte{}) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if report, err := InspectServer(path, inspectionOptions(t, options)); err == nil || report != (ServerInspection{}) {
		t.Fatal("incomplete publication journal exposed diagnostic success")
	}
	missing := filepath.Join(testfixture.PrivateDirectory(t), "missing-server.db")
	if report, err := InspectServer(missing, inspectionOptions(t, options)); err == nil || report != (ServerInspection{}) {
		t.Fatal("missing store inspected successfully")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("inspection created missing store")
	}
}

func TestServerInspectionRejectsInvalidOptionsAndOpenFailures(t *testing.T) {
	store, path, options, _, _ := testServerOwner(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	invalid := options
	invalid.Window = 0
	// server_inspect.go rejects invalid normalized options before the DB open.
	if report, err := InspectServer(path, invalid); !errors.Is(err, ownedfile.ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("invalid server options returned %+v, %v", report, err)
	}
	if report, err := InspectServer("relative.db", options); !errors.Is(err, ownedfile.ErrUnavailable) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("relative server path returned %+v, %v", report, err)
	}
	corrupt := filepath.Join(testfixture.PrivateDirectory(t), "not-a-server-database.db")
	if err := os.WriteFile(corrupt, []byte("not a bbolt database"), 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := InspectServer(corrupt, options); !errors.Is(err, ownedfile.ErrUnavailable) || !reflect.DeepEqual(report, ServerInspection{}) {
		t.Fatalf("failed server open returned %+v, %v", report, err)
	}
}

func mutateClosedServer(t *testing.T, path string, mutate func(*bolt.Bucket) error) {
	t.Helper()
	db, _, err := ownedfile.OpenDB(path, false)
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
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ownedfile.ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("incomplete server rows returned %+v, %v", report, err)
		}
	})

	t.Run("invalid guard checksum", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error { return bucket.Put(serverGuardKey, []byte("bad checksum")) })
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ownedfile.ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
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
			return bucket.Put(serverSnapshotKey, ownedfile.SealPayload([]byte("not a server snapshot")))
		})
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ownedfile.ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("invalid server snapshot returned %+v, %v", report, err)
		}
	})

	t.Run("snapshot clock ahead of guard", func(t *testing.T) {
		store, path, options, _, _ := testServerOwner(t)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		mutateClosedServer(t, path, func(bucket *bolt.Bucket) error {
			payload, err := ownedfile.CheckedPayload(bucket.Get(serverSnapshotKey))
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
			return bucket.Put(serverSnapshotKey, ownedfile.SealPayload(encoded))
		})
		if report, err := InspectServer(path, inspectionOptions(t, options)); !errors.Is(err, ownedfile.ErrInvalidStore) || !reflect.DeepEqual(report, ServerInspection{}) {
			t.Fatalf("incompatible server clock returned %+v, %v", report, err)
		}
	})
}
