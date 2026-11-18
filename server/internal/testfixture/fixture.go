// Package testfixture holds shared server test fixtures: the fixed
// fixture clock, the fixture signing keys and a registry loader.
// It imports only leaf packages (spec, internal/state), so any internal
// test package can use it without creating an import cycle.
package testfixture

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// Now is the fixed clock of the fixtures (2026-01-01T00:00:00Z).
const Now int64 = 1767225600

// PrivateKey returns the fixture signing key with the given name.
func PrivateKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	keys, err := spec.LoadKeys()
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	for _, k := range keys.Keys {
		if k.Name == name {
			seed, err := hex.DecodeString(k.SeedHex)
			if err != nil {
				t.Fatalf("seed of %s: %v", name, err)
			}
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	t.Fatalf("no test key %q", name)
	return nil
}

// Registry loads the default fixture registry into an in-memory state store.
// It is the neutral, package-independent equivalent of the root tests'
// registryFromFixture helper.
func Registry(t *testing.T, doc spec.RegistryDocument) *stateimpl.MemoryState {
	t.Helper()
	st := stateimpl.NewMemoryState()
	err := st.Update(func(e *stateimpl.StateEdit) error {
		for _, entry := range doc.Keys {
			// The fixture registry omits admin for non-admin keys, so a nil
			// pointer is false.
			e.PutKey(stateimpl.RegistryEntry{
				Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name,
				Admin:     entry.Admin != nil && *entry.Admin,
				NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return st
}
