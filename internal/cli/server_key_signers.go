package cli

import (
	"crypto/ed25519"
	"path/filepath"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type serverKeySignerConfig struct {
	Reference string `json:"reference"`
	KID       string `json:"kid"`
	SeedFile  string `json:"seed_file"`
}

// Только metadata validation; init/status не проверяют существование seed files.
func validServerKeyInventory(entries []serverKeySignerConfig) bool {
	if len(entries) > rotation.MaxRetainedKeys {
		return false
	}
	seen := make(map[[2]string]bool, len(entries))
	for _, entry := range entries {
		if entry.Reference == "" || !utf8.ValidString(entry.Reference) || len(entry.Reference) > rotation.MaxSignerReferenceBytes ||
			!filepath.IsAbs(entry.SeedFile) || filepath.Clean(entry.SeedFile) != entry.SeedFile {
			return false
		}
		if _, err := jack.DecodeBase64URLFixed(entry.KID, 32); err != nil {
			return false
		}
		identity := [2]string{entry.Reference, entry.KID}
		if seen[identity] {
			return false
		}
		seen[identity] = true
	}
	return true
}

type localServerKeySigner struct{ private ed25519.PrivateKey }

func (signer *localServerKeySigner) PublicKey() []byte {
	return signer.private.Public().(ed25519.PublicKey)
}

func (signer *localServerKeySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, message), nil
}

// Caller освобождает private buffers только после drain/Close server store.
func loadServerKeyInventory(entries []serverKeySignerConfig) ([]rotationserver.Key, func(), error) {
	if len(entries) == 0 || !validServerKeyInventory(entries) {
		return nil, nil, errConfig
	}
	owned := make([]*localServerKeySigner, 0, len(entries))
	cleanup := func() {
		for _, signer := range owned {
			clear(signer.private)
		}
	}
	keys := make([]rotationserver.Key, 0, len(entries))
	for _, entry := range entries {
		seed, err := readPrivate(entry.SeedFile, ed25519.SeedSize)
		if err != nil || len(seed) != ed25519.SeedSize {
			clear(seed)
			cleanup()
			return nil, nil, errConfig
		}
		private := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		if jack.KeyID(private.Public().(ed25519.PublicKey)) != entry.KID {
			clear(private)
			cleanup()
			return nil, nil, errConfig
		}
		signer := &localServerKeySigner{private: private}
		owned = append(owned, signer)
		keys = append(keys, rotationserver.Key{Reference: entry.Reference, Signer: signer})
	}
	return keys, cleanup, nil
}
