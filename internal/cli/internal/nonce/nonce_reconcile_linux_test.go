//go:build linux

package nonce_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/nonce"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/noncetest"
)

func TestNonceTerminalReconcileRequiresExactEvidenceAndNeverEnablesServing(t *testing.T) {
	configPath, receiptPath, options, before := noncetest.RecoveryFixture(t)
	profile, err := nonce.OfflineNonceProfile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt := before.Live[0]
	wrong := sha256.Sum256([]byte("not the closed nonce graph"))
	var diagnostics bytes.Buffer
	invoke := func(hash, confirmation string) int {
		return cli.Run(context.Background(), []string{"nonce-reconcile-terminal", "--config", configPath, "--expected-hash", hash,
			"--receipt-file", receiptPath, "--confirm-no-redelivery", confirmation}, cli.IO{Err: &diagnostics})
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
	_, receiptPath, _, snapshot := noncetest.RecoveryFixture(t)
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := nonce.ReadNonceRecoveryReceipt(receiptPath); err != nil || loaded != snapshot.Live[0] {
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
		path := clitest.SaveJSON(t, filepath.Dir(receiptPath), "bad-receipt-"+string(rune('a'+index))+".json", changed)
		if _, err := nonce.ReadNonceRecoveryReceipt(path); err == nil {
			t.Fatal("ambiguous/partial receipt file accepted")
		}
	}
}
