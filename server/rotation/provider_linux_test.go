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
	"github.com/PHPCraftdream/mcp-jack/server"
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
	options := durable.ServerOptions{TrustOptions: durable.TrustOptions{Binding: rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "provider-test"}, Window: 30, Checkpoint: checkpoint, Now: source}, AnchorReference: "anchor"}
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
		t.Fatal(err)
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

func expectIdentity(t *testing.T, provider *rotationserver.Provider, key testSigner, timestamp int64) {
	t.Helper()
	authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{Body: []byte("untrusted selector"), Tool: "not-a-key-authority"})
	if err != nil {
		t.Fatal(err)
	}
	defer authorization.Release()
	if authorization.Timestamp != timestamp || !bytes.Equal(authorization.Signer.PublicKey(), key.PublicKey()) {
		t.Fatal("wrong scheduled identity/time")
	}
	message := jack.ResponseSigningString(200, "request-signature", jack.KeyID(key.PublicKey()), timestamp, []byte("exact body"))
	signature, err := authorization.Signer.Sign([]byte(message))
	if err != nil || !jack.Verify(key.PublicKey(), []byte(message), signature) {
		t.Fatal("pinned signer did not sign exact response")
	}
	if err := authorization.Final(); err != nil {
		t.Fatal(err)
	}
	if err := authorization.Final(); err == nil {
		t.Fatal("final authority reused")
	}
}

func TestProviderOverlappingPendingTailAndEqualActivationOrdinal(t *testing.T) {
	f := setup(t)
	first := publish(t, f, 1)
	second := publish(t, f, 2)
	if first.ActivatesAt != second.ActivatesAt {
		t.Fatal("fixture is not equal-time overlap")
	}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	f.inventory[0].Reference = "mutated caller slice"
	expectIdentity(t, provider, f.keys[0], 1000)
	f.now.Store(first.ActivatesAt - 1)
	expectIdentity(t, provider, f.keys[0], first.ActivatesAt-1)
	f.now.Store(first.ActivatesAt)
	expectIdentity(t, provider, f.keys[2], first.ActivatesAt)
}

func TestProviderMissingPendingOrCurrentSignerNeverFallsBack(t *testing.T) {
	f := setup(t)
	first := publish(t, f, 1)
	if provider, err := rotationserver.New(f.store, f.inventory[:1]); err == nil || provider != nil {
		t.Fatal("missing pending signer ignored")
	}
	f.now.Store(first.ActivatesAt)
	if provider, err := rotationserver.New(f.store, f.inventory[:1]); err == nil || provider != nil {
		t.Fatal("missing current signer fell back to old")
	}
	provider, err := rotationserver.New(f.store, f.inventory[1:2])
	if err != nil {
		t.Fatal("retired old signer unnecessarily required", err)
	}
	expectIdentity(t, provider, f.keys[1], first.ActivatesAt)
}

func TestProviderFinalCutoffFreshnessRollbackAndStateChange(t *testing.T) {
	for _, scenario := range []string{"cutoff", "freshness", "rollback", "publication", "released"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			first := publish(t, f, 1)
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "cutoff" {
				f.now.Store(first.ActivatesAt - 1)
			}
			authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
			if err != nil {
				t.Fatal(err)
			}
			defer authorization.Release()
			switch scenario {
			case "cutoff":
				f.now.Store(first.ActivatesAt)
			case "freshness":
				f.now.Store(1031)
			case "rollback":
				f.now.Store(999)
			case "publication":
				publish(t, f, 2)
			case "released":
				authorization.Release()
			}
			if err := authorization.Final(); err == nil {
				t.Fatal("late gate exposed stale authority")
			}
		})
	}
}

func TestProviderFinalFreshnessEqualityAndReleaseIdempotence(t *testing.T) {
	f := setup(t)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f.now.Store(1030)
	if err := authorization.Final(); err != nil {
		t.Fatal("inclusive freshness equality refused", err)
	}
	authorization.Release()
	authorization.Release()
	if err := f.store.Close(); err != nil {
		t.Fatal("lease leaked or double-released", err)
	}
	if _, err := provider.AuthorizeResponse(server.ResponseKeyRequest{}); err == nil {
		t.Fatal("closed owner served")
	}
}
