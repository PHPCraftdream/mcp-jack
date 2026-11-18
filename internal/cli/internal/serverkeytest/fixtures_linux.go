//go:build linux

// Package serverkeytest provides shared server-key test fixtures.
package serverkeytest

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
)

func CLIProfile(t *testing.T) (string, serverkey.ServerKeyConfig) {
	t.Helper()
	directory := clitest.PrivateDir(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	public := key.Public().(ed25519.PublicKey)
	config := serverkey.ServerKeyConfig{Version: 1, StoreFile: filepath.Join(directory, "ring.db"), Endpoint: "https://server-key.example.invalid/mcp", Aud: "public-server-key-cli", Window: 30, AnchorKID: jack.KeyID(public), AnchorPublicKey: jack.EncodeBase64URL(public), AnchorReference: "protected-reference-not-a-seed-file"}
	return clitest.SaveJSON(t, directory, "server-key.json", config), config
}

func SigningProfile(t *testing.T) (string, serverkey.ServerKeyConfig) {
	t.Helper()
	path, config := CLIProfile(t)
	for index := 0; index < 4; index++ {
		seed := bytes.Repeat([]byte{byte(44 + index)}, 32)
		private := ed25519.NewKeyFromSeed(seed)
		kid := jack.KeyID(private.Public().(ed25519.PublicKey))
		seedPath := filepath.Join(filepath.Dir(path), "server-"+string(rune('a'+index))+".seed")
		if err := os.WriteFile(seedPath, seed, 0600); err != nil {
			t.Fatal(err)
		}
		reference := "pending/" + kid
		if index == 0 {
			reference = config.AnchorReference
		}
		config.Signers = append(config.Signers, serverkey.ServerKeySignerConfig{Reference: reference, KID: kid, SeedFile: seedPath})
	}
	return clitest.SaveJSON(t, filepath.Dir(path), "signing-profile.json", config), config
}

func InitArgs(path string, config serverkey.ServerKeyConfig) []string {
	return []string{"server-key-init-unused", "--config", path, "--confirm-unused-endpoint", config.Endpoint, "--confirm-unused-aud", config.Aud}
}

func AnnounceArgs(path string, entry serverkey.ServerKeySignerConfig) []string {
	return []string{"server-key-announce", "--config", path, "--reference", entry.Reference, "--kid", entry.KID}
}
