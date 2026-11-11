//go:build linux

package durable

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
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
	path := filepath.Join(privateTestDirectory(t), "trust.db")
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
	path := filepath.Join(privateTestDirectory(t), "trust.db")
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
