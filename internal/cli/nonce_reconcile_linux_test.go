//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func nonceRecoveryCLIFixture(t *testing.T) (string, string, durable.Options, durable.RecoverySnapshot) {
	t.Helper()
	directory := privateDir(t)
	path := filepath.Join(directory, "nonces.db")
	options := durable.Options{DeploymentID: "public-terminal-cli", Window: 30, Now: func() int64 { return 100 }}
	config := saveJSON(t, directory, "gateway.json", gatewayConfig{Version: 1, Aud: "operator-test", MaxConcurrent: 4,
		DurableNonces: &gatewayDurableConfig{Path: path, DeploymentID: options.DeploymentID, Window: options.Window}})
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
	if err := owner.Close(); err != nil {
		t.Fatal("fixture physical owner close failed", err)
	}
	snapshot, err := durable.InspectRecovery(path, options)
	if err != nil || !snapshot.Dirty || len(snapshot.Live) != 1 {
		t.Fatal("closed dirty fixture missing exact receipt", err)
	}
	receiptPath := saveJSON(t, directory, "receipt.json", snapshot.Live[0])
	return config, receiptPath, options, snapshot
}

func TestNonceTerminalReconcileRequiresExactEvidenceAndNeverEnablesServing(t *testing.T) {
	configPath, receiptPath, options, before := nonceRecoveryCLIFixture(t)
	profile, err := offlineNonceProfile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt := before.Live[0]
	wrong := sha256.Sum256([]byte("not the closed nonce graph"))
	var diagnostics bytes.Buffer
	invoke := func(hash, confirmation string) int {
		return Run(context.Background(), []string{"nonce-reconcile-terminal", "--config", configPath, "--expected-hash", hash,
			"--receipt-file", receiptPath, "--confirm-no-redelivery", confirmation}, IO{Err: &diagnostics})
	}
	for _, evidence := range [][2]string{{before.Hash, ""}, {before.Hash, "wrong"}, {jack.EncodeBase64URL(wrong[:]), receipt.IntentID}} {
		if invoke(evidence[0], evidence[1]) == 0 {
			t.Fatal("inexact/unconfirmed terminal evidence accepted")
		}
		after, err := durable.InspectRecovery(profile.Path, options)
		if err != nil || after.Hash != before.Hash {
			t.Fatal("refused evidence mutated durable history")
		}
	}
	if invoke(before.Hash, receipt.IntentID) != 0 {
		t.Fatal("exact terminal reconciliation failed", diagnostics.String())
	}
	after, err := durable.InspectRecovery(profile.Path, options)
	if err != nil || !after.Dirty || after.Unsafe != before.Unsafe || after.HighWater != before.HighWater || len(after.Live) != 0 || len(after.Tombstones) != 1 || after.Tombstones[0] != receipt {
		t.Fatal("terminal reconciliation changed gate/time or redelivered receipt", err)
	}
	if invoke(before.Hash, receipt.IntentID) == 0 {
		t.Fatal("stale graph evidence reused")
	}
	if reopened, err := durable.Open(profile.Path, options); err == nil || reopened != nil {
		t.Fatal("terminal CLI authorized serving restart")
	}
	if bytes.Contains(diagnostics.Bytes(), []byte(profile.Path)) || bytes.Contains(diagnostics.Bytes(), []byte(receipt.IntentID)) {
		t.Fatal("terminal diagnostics leaked supplied evidence/path")
	}
}

func TestNonceRecoveryReceiptRejectsMissingNullAndTruncatedArrayEvidence(t *testing.T) {
	_, receiptPath, _, snapshot := nonceRecoveryCLIFixture(t)
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := readNonceRecoveryReceipt(receiptPath); err != nil || loaded != snapshot.Live[0] {
		t.Fatal("exact receipt positive control failed", err)
	}
	var original map[string]json.RawMessage
	if json.Unmarshal(data, &original) != nil {
		t.Fatal("fixture receipt malformed")
	}
	for index, mutate := range []func(map[string]json.RawMessage){
		func(m map[string]json.RawMessage) { delete(m, "HighWater") },
		func(m map[string]json.RawMessage) { m["HighWater"] = json.RawMessage("null") },
		func(m map[string]json.RawMessage) { m["unknown"] = json.RawMessage("0") },
		func(m map[string]json.RawMessage) { m["OperationID"] = json.RawMessage("null") },
		func(m map[string]json.RawMessage) { m["OperationID"] = json.RawMessage("[]") },
		func(m map[string]json.RawMessage) {
			var values []json.RawMessage
			_ = json.Unmarshal(m["OperationID"], &values)
			m["OperationID"], _ = json.Marshal(append(values, json.RawMessage("0")))
		},
		func(m map[string]json.RawMessage) {
			var values []json.RawMessage
			_ = json.Unmarshal(m["OperationID"], &values)
			values[0] = json.RawMessage("null")
			m["OperationID"], _ = json.Marshal(values)
		},
	} {
		changed := make(map[string]json.RawMessage, len(original))
		for name, value := range original {
			changed[name] = value
		}
		mutate(changed)
		path := saveJSON(t, filepath.Dir(receiptPath), "bad-receipt-"+string(rune('a'+index))+".json", changed)
		if _, err := readNonceRecoveryReceipt(path); err == nil {
			t.Fatal("ambiguous/partial receipt file accepted")
		}
	}
}

func TestProcessNonceTerminalReconciliationNeverOpensServing(t *testing.T) {
	configPath, receiptPath, options, before := nonceRecoveryCLIFixture(t)
	process, in, out, diagnostics := childArgs(t, "nonce-reconcile-terminal", "--config", configPath,
		"--expected-hash", before.Hash, "--receipt-file", receiptPath, "--confirm-no-redelivery", before.Live[0].IntentID)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(io.LimitReader(out, maxBody+1))
	waitErr := process.Wait()
	if err != nil || len(reply) != 0 || waitErr != nil {
		t.Fatal("terminal CLI child failed or disclosed output", diagnostics.String())
	}
	profile, err := offlineNonceProfile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := durable.InspectRecovery(profile.Path, options)
	if err != nil || !after.Dirty || len(after.Live) != 0 || len(after.Tombstones) != 1 || after.Tombstones[0] != before.Live[0] {
		t.Fatal("shipping terminal reconciliation changed serving gate or receipt", err)
	}
}
