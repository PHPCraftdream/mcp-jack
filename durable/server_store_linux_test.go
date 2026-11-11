//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

func testServerOwner(t *testing.T) (*ServerStore, string, ServerOptions, *atomic.Int64, trustTestSigner) {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(1000)
	base, signer := trustTestOptions(now)
	options := ServerOptions{TrustOptions: base, AnchorReference: "protected/anchor"}
	path := filepath.Join(privateTestDirectory(t), "server.db")
	if err := InitializeServerUnused(path, options); err != nil { t.Fatal(err) }
	store, err := OpenServer(path, options)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = store.Close() })
	return store, path, options, now, signer
}

func extendServer(t *testing.T, snapshot rotation.ServerSnapshot, clock rotation.ClockTuple, signer trustTestSigner) rotation.ServerSnapshot {
	t.Helper()
	desired := snapshot
	desired.Public = extendTrust(t, snapshot.Public, clock, signer)
	last := desired.Public.Keys[len(desired.Public.Keys)-1]
	desired.SignerReferences = append(append([]rotation.SignerReference{}, snapshot.SignerReferences...), rotation.SignerReference{KID: last.KID, Reference: "protected/"+last.KID})
	return desired
}

func serverRows(t *testing.T, store *ServerStore) ([]byte, []byte, []byte) {
	t.Helper()
	var guard, snapshot, intent []byte
	if err := store.db.View(func(tx *bolt.Tx) error {
		var err error
		guard, snapshot, intent, err = readServerRows(tx)
		return err
	}); err != nil { t.Fatal(err) }
	return guard, snapshot, intent
}

func requireServerCode(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *rotation.Error
	if !errors.As(err, &refusal) || refusal.Code != code { t.Fatalf("wanted %s, got %v", code, err) }
}

func TestServerStoreExactPublicationIntentAndCleanReopen(t *testing.T) {
	store, path, options, _, signer := testServerOwner(t)
	if other, err := OpenServer(path, options); err == nil || other != nil { t.Fatal("second owner admitted") }
	if err := InitializeServerUnused(path, options); err == nil { t.Fatal("existing server store replaced") }
	previous, clock, err := store.Snapshot()
	if err != nil { t.Fatal(err) }
	desired := extendServer(t, previous, clock, signer)
	guardBefore, encodedBefore, empty := serverRows(t, store)
	if len(empty) != 0 { t.Fatal("unused store has publication intent") }
	if err := store.CompareAndSwap(previous, desired, clock); err != nil { t.Fatal(err) }
	guardAfter, encodedAfter, intent := serverRows(t, store)
	if !bytes.Equal(guardBefore, guardAfter) { t.Fatal("publication mutated authoritative clock or owner") }
	expectedBytes, desiredBytes, err := decodeServerIntent(intent)
	if err != nil || !bytes.Equal(expectedBytes, encodedBefore) || !bytes.Equal(desiredBytes, encodedAfter) { t.Fatal("intent did not retain exact expected/desired bytes") }
	loaded, _, err := store.Snapshot()
	if err != nil || !reflect.DeepEqual(loaded, desired) { t.Fatalf("ACK not persisted: %v", err) }
	requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_changed")
	_, err = store.CheckSnapshotClock(previous)
	requireServerCode(t, err, "rotation_state_changed")
	if store.fenced.Load() { t.Fatal("definite conflict fenced healthy owner") }
	if err := store.Close(); err != nil { t.Fatal(err) }
	reopened, err := OpenServer(path, options)
	if err != nil { t.Fatal(err) }
	defer reopened.Close()
	loaded, _, err = reopened.Snapshot()
	if err != nil || !reflect.DeepEqual(loaded, desired) { t.Fatal("clean reopen lost ring or references") }
}

func TestServerStoreSeparateClockConflictAndRollbackLatch(t *testing.T) {
	store, path, options, now, signer := testServerOwner(t)
	previous, clock, err := store.Snapshot()
	if err != nil { t.Fatal(err) }
	desired := extendServer(t, previous, clock, signer)
	_, before, intentBefore := serverRows(t, store)
	now.Store(1001)
	advanced, err := store.CheckSnapshotClock(previous)
	if err != nil || advanced.HighWater != 1001 || advanced.Revision != clock.Revision+1 { t.Fatal("server guard did not advance separately") }
	requireServerCode(t, store.CompareAndSwap(previous, desired, clock), "rotation_state_changed")
	_, after, intentAfter := serverRows(t, store)
	if !bytes.Equal(before, after) || !bytes.Equal(intentBefore, intentAfter) { t.Fatal("clock conflict mutated ring") }
	now.Store(1000)
	_, err = store.CheckSnapshotClock(previous)
	requireServerCode(t, err, "rotation_clock_unsafe")
	now.Store(1002)
	_, err = store.AdvanceAndCheck()
	requireServerCode(t, err, "rotation_clock_unsafe")
	if store.Close() == nil { t.Fatal("unsafe store closed healthy") }
	if reopened, err := OpenServer(path, options); err == nil || reopened != nil { t.Fatal("catch-up cleared durable rollback latch") }
}

func TestServerStoreUnknownWritesFenceBothCommittedAndAbsentOutcomes(t *testing.T) {
	for _, operation := range []string{"publication", "clock"} {
		for _, committed := range []bool{false, true} {
			t.Run(operation+map[bool]string{false:"-absent",true:"-committed"}[committed], func(t *testing.T) {
				store, path, options, now, signer := testServerOwner(t)
				previous, clock, err := store.Snapshot()
				if err != nil { t.Fatal(err) }
				desired := extendServer(t, previous, clock, signer)
				attempts := 0
				store.transact = func(fn func(*bolt.Tx) error) error {
					attempts++
					if committed {
						if err := store.db.Update(fn); err != nil { t.Fatal(err) }
					} else {
						injected := errors.New("definite fixture rollback")
						err := store.db.Update(func(tx *bolt.Tx) error { if err := fn(tx); err != nil { return err }; return injected })
						if !errors.Is(err, injected) { t.Fatal(err) }
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
				if attempts != 1 || !store.fenced.Load() { t.Fatal("unknown outcome retried or served") }
				_, persisted, intent := serverRows(t, store)
				if operation == "publication" {
					wanted := previous
					if committed { wanted = desired }
					encoded, err := rotation.EncodeServerSnapshot(wanted, options.Binding, options.Window, options.Checkpoint)
					if err != nil || !bytes.Equal(encoded, persisted) || (len(intent) != 0) != committed { t.Fatal("fixture did not exercise claimed commit outcome") }
				}
				if _, _, err := store.Snapshot(); err == nil { t.Fatal("fenced state exposed") }
				if store.Close() == nil || attempts != 1 { t.Fatal("close cleared or retried unknown operation") }
				if reopened, err := OpenServer(path, options); err == nil || reopened != nil { t.Fatal("unknown dirty startup admitted") }
			})
		}
	}
}

func TestServerStoreRejectsClientDomainAndChangedAnchorReference(t *testing.T) {
	store, path, options, _, _ := testServerOwner(t)
	if err := store.Close(); err != nil { t.Fatal(err) }
	changed := options
	changed.AnchorReference = "replacement"
	if owner, err := OpenServer(path, changed); err == nil || owner != nil { t.Fatal("protected OOB profile silently replaced") }
	if owner, err := OpenTrust(path, options.TrustOptions); err == nil || owner != nil { t.Fatal("server DB accepted as client DB") }
	clientPath := filepath.Join(privateTestDirectory(t), "client.db")
	if err := InitializeTrustUnused(clientPath, options.TrustOptions); err != nil { t.Fatal(err) }
	if owner, err := OpenServer(clientPath, options); err == nil || owner != nil { t.Fatal("client DB accepted as server DB") }
	missing := filepath.Join(privateTestDirectory(t), "missing.db")
	if owner, err := OpenServer(missing, options); err == nil || owner != nil { t.Fatal("missing server store created") }
	if _, err := os.Lstat(missing); !os.IsNotExist(err) { t.Fatal("open created path") }
}
