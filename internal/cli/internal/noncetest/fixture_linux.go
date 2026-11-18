//go:build linux

// Package noncetest builds a fenced, dirty durable nonce store with an
// authenticated live receipt, shared by offline nonce recovery CLI tests.
package noncetest

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func RecoveryFixture(t *testing.T) (string, string, durable.Options, durable.RecoverySnapshot) {
	t.Helper()
	directory := clitest.PrivateDir(t)
	path := directory + "/nonces.db"
	options := durable.Options{DeploymentID: "public-terminal-cli", Window: 30, Now: func() int64 { return 100 }}
	config := clitest.SaveJSON(t, directory, "gateway.json", gatewayconfig.Config{Version: 1, Aud: "operator-test", MaxConcurrent: 4,
		DurableNonces: &gatewayconfig.DurableConfig{Path: path, DeploymentID: options.DeploymentID, Window: options.Window}})
	if err := durable.InitializeUnused(path, options); err != nil {
		t.Fatal(err)
	}
	owner, err := durable.Open(path, options)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	public := private.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "operator-client"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	verifier, err := server.NewVerifier(server.Config{Aud: "operator-test", State: state, DurableNonces: owner, Now: options.Now})
	if err != nil {
		t.Fatal(err)
	}
	auth := jack.RequestAuth{Kid: kid, TS: 100, Nonce: jack.EncodeBase64URL(bytes.Repeat([]byte{7}, 16))}
	auth.Sig = jack.EncodeBase64URL(ed25519.Sign(private, []byte(jack.RequestSigningString("GET", "/mcp", "operator-test", kid, auth.TS, auth.Nonce, nil))))
	result := verifier.Verify(server.Request{Method: "GET", Target: "/mcp", AuthValues: []string{jack.FormatRequestAuth(auth)}})
	result.Done()
	if !result.Accepted {
		t.Fatal("fixture did not reserve an actual authenticated request")
	}
	owner.Fence()
	// A fenced store closes physically but reports that it needs recovery.
	if err := owner.Close(); err != nil && !errors.Is(err, durable.ErrRecoveryRequired) {
		t.Fatal("fixture physical owner close failed", err)
	}
	snapshot, err := durable.InspectRecovery(path, options)
	if err != nil || !snapshot.Dirty || len(snapshot.Live) != 1 {
		t.Fatal("closed dirty fixture missing exact receipt", err)
	}
	receiptPath := clitest.SaveJSON(t, directory, "receipt.json", snapshot.Live[0])
	return config, receiptPath, options, snapshot
}
