// Package nonce implements the offline nonce recovery operations, which read
// only the private config and nonce store, not seed/state/socket.
package nonce

import (
	"encoding/json"
	"io"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
)

// Offline operations read only the private config and nonce store, not seed/state/socket.
func OfflineNonceProfile(path string) (*gatewayconfig.DurableConfig, error) {
	var config gatewayconfig.Config
	if storage.DecodeConfig(path, &config) != nil || config.Version != 1 || config.Aud == "" || config.DurableNonces == nil || config.DurableNonces.Validate(config.MaxConcurrent) != nil {
		return nil, command.ErrConfig
	}
	return config.DurableNonces, nil
}

// Confirm is the operator's assertion of a never-used deployment, not migration/recovery proof.
func NonceInitializeUnused(configPath, confirmedDeployment string) error {
	profile, err := OfflineNonceProfile(configPath)
	if err != nil {
		return command.ErrConfig
	}
	if confirmedDeployment != profile.DeploymentID {
		return command.ErrConfig
	}
	if err := durable.InitializeUnused(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}); err != nil {
		return command.ErrConfig
	}
	return nil
}

func NonceInspect(configPath string, output io.Writer) error {
	if output == nil {
		return command.ErrConfig
	}
	profile, err := OfflineNonceProfile(configPath)
	if err != nil {
		return command.ErrConfig
	}
	report, err := durable.InspectRecovery(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window})
	if err != nil {
		return command.ErrConfig
	}
	// Only public operation/receipt data; key seeds and private paths are not printed.
	return json.NewEncoder(output).Encode(report)
}
