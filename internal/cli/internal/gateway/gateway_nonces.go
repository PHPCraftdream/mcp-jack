package gateway

import (
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// The returned owner is closed only after the HTTP server has stopped and handlers drained.
func selectGatewayNonces(c gatewayconfig.Config, verifier *server.Config) (func() error, error) {
	if verifier == nil || verifier.Nonces != nil || verifier.DurableNonces != nil || c.DurableNonces.Validate(c.MaxConcurrent) != nil {
		return nil, command.ErrConfig
	}
	if c.DurableNonces == nil {
		verifier.Nonces = server.NewNonceStore()
		return func() error { return nil }, nil
	}
	profile := c.DurableNonces
	owner, err := durable.Open(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window})
	if err != nil {
		return nil, command.ErrConfig
	}
	verifier.DurableNonces = owner
	verifier.Window = profile.Window
	return owner.Close, nil
}
