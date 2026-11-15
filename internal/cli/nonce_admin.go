package cli

import (
	"encoding/json"
	"io"

	"github.com/PHPCraftdream/mcp-jack/durable"
)

// Offline operations read only the private config and nonce store, not seed/state/socket.
func offlineNonceProfile(path string) (*gatewayDurableConfig, error) {
	var config gatewayConfig
	if decodeConfig(path, &config) != nil || config.Version != 1 || config.Aud == "" || config.DurableNonces == nil || config.DurableNonces.validate(config.MaxConcurrent) != nil {
		return nil, errConfig
	}
	return config.DurableNonces, nil
}

// Confirm is the operator's assertion of a never-used deployment, not migration/recovery proof.
func nonceInitializeUnused(configPath, confirmedDeployment string) error {
	profile, err := offlineNonceProfile(configPath)
	if err != nil {
		return errConfig
	}
	if confirmedDeployment != profile.DeploymentID {
		return errConfig
	}
	if err := durable.InitializeUnused(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}); err != nil {
		return errConfig
	}
	return nil
}

func nonceInspect(configPath string, output io.Writer) error {
	if output == nil {
		return errConfig
	}
	profile, err := offlineNonceProfile(configPath)
	if err != nil {
		return errConfig
	}
	report, err := durable.InspectRecovery(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window})
	if err != nil {
		return errConfig
	}
	// Only public operation/receipt data; key seeds and private paths are not printed.
	return json.NewEncoder(output).Encode(report)
}
