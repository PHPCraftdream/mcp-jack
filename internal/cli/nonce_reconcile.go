package cli

import (
	"bytes"
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// Receipt file использует точные public поля NonceReceipt из nonce-inspect.
// Null/missing/unknown/extra array entries не превращаются в zero-value evidence.
func readNonceRecoveryReceipt(path string) (server.NonceReceipt, error) {
	data, err := readPrivate(path, 16384)
	if err != nil {
		return server.NonceReceipt{}, errConfig
	}
	fields, err := object(data)
	required := []string{"Version", "DeploymentID", "StoreGeneration", "OwnerGeneration", "IntentID", "OperationID", "KID", "Nonce", "Signature", "RequestHash", "Timestamp", "RetainUntil", "HighWater"}
	if err != nil || len(fields) != len(required) {
		return server.NonceReceipt{}, errConfig
	}
	for _, name := range required {
		value, exists := fields[name]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return server.NonceReceipt{}, errConfig
		}
	}
	var operation []json.RawMessage
	if json.Unmarshal(fields["OperationID"], &operation) != nil || len(operation) != 16 {
		return server.NonceReceipt{}, errConfig
	}
	for _, value := range operation {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return server.NonceReceipt{}, errConfig
		}
	}
	var receipt server.NonceReceipt
	if json.Unmarshal(data, &receipt) != nil {
		return server.NonceReceipt{}, errConfig
	}
	return receipt, nil
}

// Только явный terminal no-redelivery; startup/unsafe gate остаётся закрытым.
func nonceReconcileTerminal(configPath, expectedHash, receiptPath, confirmedIntent string) error {
	if _, err := jack.DecodeBase64URLFixed(expectedHash, 32); err != nil {
		return errConfig
	}
	profile, err := offlineNonceProfile(configPath)
	if err != nil {
		return errConfig
	}
	receipt, err := readNonceRecoveryReceipt(receiptPath)
	if err != nil || confirmedIntent == "" || confirmedIntent != receipt.IntentID {
		return errConfig
	}
	if err := durable.ReconcileUnknown(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}, expectedHash, receipt); err != nil {
		return errConfig
	}
	return nil
}
