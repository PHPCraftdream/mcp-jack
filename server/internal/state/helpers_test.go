package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
)

// stateTestKey builds a registry entry with a real Ed25519 public key derived
// from id, and kid = base64url(SHA-256(public_key)), so state seeded with it
// passes the strict file-load validation (which includes the curve checks of
// spec 03 section 2). Keep ids unique within a test.
func stateTestKey(id, name string) RegistryEntry {
	seed := sha256.Sum256([]byte(id))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return RegistryEntry{
		Kid:       base64.RawURLEncoding.EncodeToString(sum[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Name:      name,
	}
}

// stateTestIntPtr returns a pointer to v.
func stateTestIntPtr(v int64) *int64 { return &v }

// fileTestRead reads a file, failing the test on error. Defined once for the
// package.
func fileTestRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
