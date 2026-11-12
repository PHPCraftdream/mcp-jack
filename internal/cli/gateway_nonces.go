package cli

import (
	"path/filepath"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// Профиль выбирается явно; gateway никогда не создаёт и не сбрасывает store.
type gatewayDurableConfig struct {
	Path         string `json:"path"`
	DeploymentID string `json:"deployment_id"`
	Window       int64  `json:"window"`
}

func (c *gatewayDurableConfig) validate(maxConcurrent int) error {
	if c == nil {
		return nil
	}
	if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || !utf8.ValidString(c.DeploymentID) || len(c.DeploymentID) == 0 || len(c.DeploymentID) > 1024 || c.Window < 1 || c.Window > 120 || maxConcurrent < 1 || maxConcurrent > 32 {
		return errConfig
	}
	return nil
}

// Возвращённый owner закрывается только после остановки HTTP и drain handlers.
func selectGatewayNonces(c gatewayConfig, verifier *server.Config) (func() error, error) {
	if verifier == nil || verifier.Nonces != nil || verifier.DurableNonces != nil || c.DurableNonces.validate(c.MaxConcurrent) != nil {
		return nil, errConfig
	}
	if c.DurableNonces == nil {
		verifier.Nonces = server.NewNonceStore()
		return func() error { return nil }, nil
	}
	profile := c.DurableNonces
	owner, err := durable.Open(profile.Path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window})
	if err != nil {
		return nil, errConfig
	}
	verifier.DurableNonces = owner
	verifier.Window = profile.Window
	return owner.Close, nil
}
