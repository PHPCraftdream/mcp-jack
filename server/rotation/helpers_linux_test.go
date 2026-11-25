//go:build linux

package rotationserver_test

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type testSigner struct{ key ed25519.PrivateKey }

func makeSigner(seed byte) testSigner {
	return testSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))}
}
func (key testSigner) PublicKey() []byte { return key.key.Public().(ed25519.PublicKey) }
func (key testSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(key.key, message), nil
}

type fixture struct {
	store     *durable.ServerStore
	now       *atomic.Int64
	keys      []testSigner
	inventory []rotationserver.Key
}

func setup(t *testing.T) fixture {
	t.Helper()
	return setupWithClock(t, nil)
}

func setupWithClock(t *testing.T, wrap func(func() int64) func() int64) fixture {
	t.Helper()
	return setupWithEndpoint(t, "https://public.invalid/mcp", wrap)
}

func setupWithEndpoint(t *testing.T, endpoint string, wrap func(func() int64) func() int64) fixture {
	t.Helper()
	keys := []testSigner{makeSigner(31), makeSigner(32), makeSigner(33)}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(keys[0].PublicKey())}
	copy(checkpoint.PublicKey[:], keys[0].PublicKey())
	now := &atomic.Int64{}
	now.Store(1000)
	source := now.Load
	if wrap != nil {
		source = wrap(source)
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	options := durable.ServerOptions{TrustOptions: durable.TrustOptions{Binding: rotation.Binding{Endpoint: endpoint, Audience: "provider-test"}, Window: 30, Checkpoint: checkpoint, Now: source}, AnchorReference: "anchor"}
	path := filepath.Join(directory, "server.db")
	if err := durable.InitializeServerUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := durable.OpenServer(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return fixture{store: store, now: now, keys: keys, inventory: []rotationserver.Key{{Reference: "anchor", Signer: keys[0]}, {Reference: "next", Signer: keys[1]}, {Reference: "tail", Signer: keys[2]}}}
}

func publish(t *testing.T, f fixture, index int) rotation.Record {
	t.Helper()
	previous, _, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	clock, err := f.store.CheckSnapshotClock(previous)
	if err != nil {
		// Context for the next occurrence: which state the snapshot and the clock were in.
		t.Fatalf("publish %d: CheckSnapshotClock: %v (now=%d, revision=%d, records=%d, clock=%+v)", index, err, f.now.Load(), previous.Public.Revision, len(previous.Public.Records), previous.Public.Clock)
	}
	checkpoint := previous.Public.Checkpoint
	if len(previous.Public.Records) != 0 {
		last, err := rotation.VerifyChain([][]byte{[]byte(previous.Public.Records[0])}, previous.Public.Binding, checkpoint, nil)
		if err != nil || len(previous.Public.Records) != 1 {
			t.Fatal("fixture supports two publications")
		}
		value := last[0]
		checkpoint = rotation.Checkpoint{Ordinal: value.Ordinal, Hash: value.Hash, KID: value.NewKID, PublicKey: value.PublicKey, PublishedAt: value.PublishedAt}
	}
	record, err := rotation.CreateRecord(previous.Public.Binding, checkpoint, f.keys[index-1], f.keys[index], clock.HighWater)
	if err != nil {
		t.Fatal(err)
	}
	desired := previous
	desired.Public.Records = append(append([]string{}, previous.Public.Records...), record.Wire)
	desired.Public.Keys = append([]rotation.TrustKey{}, previous.Public.Keys...)
	cutoff := record.ActivatesAt
	desired.Public.Keys[len(desired.Public.Keys)-1].KnownCutoff = &cutoff
	desired.Public.Keys = append(desired.Public.Keys, rotation.TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt})
	desired.Public.Revision++
	desired.Public.Clock = clock
	desired.Public.Head = rotation.ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}
	desired.SignerReferences = append(append([]rotation.SignerReference{}, previous.SignerReferences...), rotation.SignerReference{KID: record.NewKID, Reference: f.inventory[index].Reference})
	if err := f.store.CompareAndSwap(previous, desired, clock); err != nil {
		t.Fatal(err)
	}
	return record
}

type signingHook struct {
	testSigner
	onSign func()
}

func (key signingHook) Sign(message []byte) ([]byte, error) {
	if key.onSign != nil {
		key.onSign()
	}
	return key.testSigner.Sign(message)
}
