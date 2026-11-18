package testfixture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"

	"github.com/PHPCraftdream/mcp-jack/server/internal/state"
)

// StateTestKey builds a registry entry with a real Ed25519 public key derived
// from id, and kid = base64url(SHA-256(public_key)), so state seeded with it
// passes the strict file-load validation (which includes the curve checks of
// spec 03 section 2). Keep ids unique within a test.
func StateTestKey(id, name string) state.RegistryEntry {
	seed := sha256.Sum256([]byte(id))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return state.RegistryEntry{
		Kid:       base64.RawURLEncoding.EncodeToString(sum[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Name:      name,
	}
}
