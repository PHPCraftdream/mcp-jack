//go:build linux

package rotationserver_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

func TestAnnouncePendingTailAndSingleFixedPublicationSample(t *testing.T) {
	samples := &atomic.Int64{}
	f := setupWithClock(t, func(source func() int64) func() int64 {
		return func() int64 { samples.Add(1); return source() }
	})
	signs := [3]int{}
	for index := range f.inventory {
		f.inventory[index].Signer = signingHook{testSigner: f.keys[index], onSign: func() { signs[index]++ }}
	}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	samples.Store(0)
	first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil || first.Record.PublishedAt != 1000 || first.Revision != 2 || samples.Load() != 1 {
		t.Fatalf("first authorization: sample=%d err=%v", samples.Load(), err)
	}
	second, err := provider.Announce("tail", jack.KeyID(f.keys[2].PublicKey()))
	if err != nil || second.Record.PublishedAt != 1000 || second.Revision != 3 || second.Record.OldKID != first.Record.NewKID || samples.Load() != 2 {
		t.Fatal("pending tail could not authorize overlapping successor", err)
	}
	if signs != [3]int{1, 2, 1} {
		t.Fatalf("unexpected proof/authorization calls: %v", signs)
	}
	if _, err := provider.Announce("next", first.Record.NewKID); err == nil || samples.Load() != 2 || signs != [3]int{1, 2, 1} {
		t.Fatal("retained-key reuse reached clock or signers")
	}
	if _, err := provider.Announce("unknown", first.Record.NewKID); err == nil || samples.Load() != 2 {
		t.Fatal("unknown inventory entry sampled time")
	}
	loaded, _, err := f.store.Snapshot()
	if err != nil || loaded.Public.Revision != 3 || len(loaded.Public.Records) != 2 || loaded.Public.Records[0] != first.Record.Wire || loaded.Public.Records[1] != second.Record.Wire {
		t.Fatal("exact publication ACK not persisted")
	}
}

func TestAnnounceDelayedProofDoesNotResampleOrMoveP(t *testing.T) {
	samples := &atomic.Int64{}
	f := setupWithClock(t, func(source func() int64) func() int64 {
		return func() int64 { samples.Add(1); return source() }
	})
	f.inventory[1].Signer = signingHook{testSigner: f.keys[1], onSign: func() { f.now.Store(1100) }}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	samples.Store(0)
	publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil || publication.Record.PublishedAt != 1000 || publication.Record.ActivatesAt != 1000+rotation.GraceSeconds || samples.Load() != 1 {
		t.Fatal("publication resampled or shifted fixed P", err)
	}
}

func TestAnnounceConcurrentClockConflictDoesNotRetryOrPublish(t *testing.T) {
	f := setup(t)
	proofs, authorizations := 0, 0
	f.inventory[0].Signer = signingHook{testSigner: f.keys[0], onSign: func() { authorizations++ }}
	f.inventory[1].Signer = signingHook{testSigner: f.keys[1], onSign: func() {
		proofs++
		f.now.Store(1001)
		if _, err := f.store.AdvanceAndCheck(); err != nil {
			t.Fatal(err)
		}
	}}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	var refusal *rotation.Error
	if !errors.As(err, &refusal) || refusal.Code != "rotation_state_changed" || publication.Record.Wire != "" || proofs != 1 || authorizations != 1 {
		t.Fatal("conflict retried or exposed tentative record", err)
	}
	snapshot, _, err := f.store.Snapshot()
	if err != nil || snapshot.Public.Revision != 1 || len(snapshot.Public.Records) != 0 {
		t.Fatal("definite conflict changed ring or fenced healthy owner")
	}
}

func setupCapacityFixture(t *testing.T, count int) fixture {
	t.Helper()
	keys := make([]testSigner, count)
	for index := range keys {
		keys[index] = makeSigner(byte(31 + index))
	}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(keys[0].PublicKey())}
	copy(checkpoint.PublicKey[:], keys[0].PublicKey())
	now := &atomic.Int64{}
	now.Store(1000)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	options := durable.ServerOptions{TrustOptions: durable.TrustOptions{Binding: rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "provider-test"}, Window: 30, Checkpoint: checkpoint, Now: now.Load}, AnchorReference: "anchor"}
	path := filepath.Join(directory, "server.db")
	if err := durable.InitializeServerUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := durable.OpenServer(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	inventory := make([]rotationserver.Key, count)
	inventory[0] = rotationserver.Key{Reference: "anchor", Signer: keys[0]}
	for index := 1; index < count; index++ {
		inventory[index] = rotationserver.Key{Reference: "next", Signer: keys[index]}
	}
	return fixture{store: store, now: now, keys: keys, inventory: inventory}
}

func TestAnnounceRefusesRingBeyondServableRetiredCapacity(t *testing.T) {
	if rotationserver.MaxAnnounceRingKeysForTest() != rotationserver.ServedRetiredKeysForTest()+1 {
		t.Fatal("announce bound does not match serving retired limit")
	}
	restore := rotationserver.SetMaxAnnounceRingKeysForTest(4)
	t.Cleanup(restore)
	f := setupCapacityFixture(t, 5)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	for step := 1; step <= 3; step++ {
		publication, err := provider.Announce("next", jack.KeyID(f.keys[step].PublicKey()))
		if err != nil || publication.Record.ActivatesAt != f.now.Load()+rotation.GraceSeconds {
			t.Fatalf("announce %d refused: err=%v", step, err)
		}
	}
	before, _, err := f.store.Snapshot()
	if err != nil || len(before.Public.Keys) != 4 {
		t.Fatalf("ring after 3 announces: keys=%d err=%v", len(before.Public.Keys), err)
	}
	if _, err := provider.Announce("next", jack.KeyID(f.keys[4].PublicKey())); !errors.Is(err, rotationserver.ErrUnavailable) {
		t.Fatalf("announce with 4-key ring not refused: err=%v", err)
	}
	after, _, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Public.Revision != before.Public.Revision || after.Public.Head != before.Public.Head || !reflect.DeepEqual(before.Public.Keys, after.Public.Keys) || !reflect.DeepEqual(before.Public.Records, after.Public.Records) {
		t.Fatal("refused announcement mutated committed ring")
	}
}

type faultyProof struct {
	testSigner
	panicInstead bool
}

func (signer faultyProof) Sign([]byte) ([]byte, error) {
	if signer.panicInstead {
		panic("private signer failure must not escape")
	}
	return make([]byte, 64), nil
}

func TestAnnounceInvalidOrPanickingProofNeverInvokesOldAuthorization(t *testing.T) {
	for _, panicInstead := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-proof", true: "panic"}[panicInstead], func(t *testing.T) {
			f := setup(t)
			oldCalls := 0
			f.inventory[0].Signer = signingHook{testSigner: f.keys[0], onSign: func() { oldCalls++ }}
			f.inventory[1].Signer = faultyProof{testSigner: f.keys[1], panicInstead: panicInstead}
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
			if !errors.Is(err, rotationserver.ErrUnavailable) || publication.Record.Wire != "" || oldCalls != 0 {
				t.Fatal("failed proof authorized/exposed successor", err)
			}
			snapshot, _, err := f.store.Snapshot()
			if err != nil || snapshot.Public.Revision != 1 || len(snapshot.Public.Records) != 0 {
				t.Fatal("proof failure mutated committed ring")
			}
			if err := f.store.Close(); err != nil {
				t.Fatal("failed proof leaked lease", err)
			}
		})
	}
}
