package nonce

import (
	"bytes"
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// The receipt file uses the exact public fields of NonceReceipt from nonce-inspect.
// Null/missing/unknown/extra array entries must not become zero-value evidence.
func ReadNonceRecoveryReceipt(path string) (server.NonceReceipt, error) {
	data, err := storage.ReadPrivate(path, 16384)
	if err != nil {
		return server.NonceReceipt{}, command.ErrConfig
	}
	fields, err := wire.Object(data)
	required := []string{"Version", "DeploymentID", "StoreGeneration", "OwnerGeneration", "IntentID", "OperationID", "KID", "Nonce", "Signature", "RequestHash", "Timestamp", "RetainUntil", "HighWater"}
	if err != nil || len(fields) != len(required) {
		return server.NonceReceipt{}, command.ErrConfig
	}
	for _, name := range required {
		value, exists := fields[name]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return server.NonceReceipt{}, command.ErrConfig
		}
	}
	var operation []json.RawMessage
	if json.Unmarshal(fields["OperationID"], &operation) != nil || len(operation) != 16 {
		return server.NonceReceipt{}, command.ErrConfig
	}
	for _, value := range operation {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return server.NonceReceipt{}, command.ErrConfig
		}
	}
	var receipt server.NonceReceipt
	if json.Unmarshal(data, &receipt) != nil {
		return server.NonceReceipt{}, command.ErrConfig
	}
	return receipt, nil
}

// Only an explicit terminal no-redelivery; the startup/unsafe gate stays closed.
func NonceReconcileTerminal(configPath, expectedHash, receiptPath, confirmedIntent string) error {
	if _, err := jack.DecodeBase64URLFixed(expectedHash, 32); err != nil {
		return command.ErrConfig
	}
	profile, err := OfflineNonceProfile(configPath)
	if err != nil {
		return command.ErrConfig
	}
	receipt, err := ReadNonceRecoveryReceipt(receiptPath)
	if err != nil || confirmedIntent == "" || confirmedIntent != receipt.IntentID {
		return command.ErrConfig
	}
	if err := durable.ReconcileUnknown(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}, expectedHash, receipt); err != nil {
		return command.ErrConfig
	}
	return nil
}
