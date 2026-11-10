package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestGatewayNonceProfileIsExplicitAndValidated(t *testing.T) {
	legacy := server.Config{}
	closeLegacy, err := selectGatewayNonces(gatewayConfig{}, &legacy)
	if err != nil || closeLegacy == nil || legacy.Nonces == nil || legacy.DurableNonces != nil {
		t.Fatalf("legacy profile changed: %v", err)
	}
	if err := closeLegacy(); err != nil {
		t.Fatal(err)
	}
	valid := gatewayDurableConfig{Path: filepath.Join(t.TempDir(), "nonces.db"), DeploymentID: "test-deployment", Window: 30}
	if err := valid.validate(32); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*gatewayDurableConfig){
		"relative-path":        func(c *gatewayDurableConfig) { c.Path = "nonces.db" },
		"empty-deployment":     func(c *gatewayDurableConfig) { c.DeploymentID = "" },
		"invalid-utf8":         func(c *gatewayDurableConfig) { c.DeploymentID = string([]byte{0xff}) },
		"oversized-deployment": func(c *gatewayDurableConfig) { c.DeploymentID = string(make([]byte, 1025)) },
		"zero-window":          func(c *gatewayDurableConfig) { c.Window = 0 },
		"oversized-window":     func(c *gatewayDurableConfig) { c.Window = 121 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			mutate(&invalid)
			verification := server.Config{}
			closeStore, err := selectGatewayNonces(gatewayConfig{DurableNonces: &invalid, MaxConcurrent: 32}, &verification)
			if !errors.Is(err, errConfig) || closeStore != nil || verification.Nonces != nil || verification.DurableNonces != nil {
				t.Fatalf("invalid profile silently fell back: %v", err)
			}
		})
	}
	if valid.validate(33) == nil || valid.validate(0) == nil {
		t.Fatal("durable concurrency bound not enforced")
	}
	if _, err := selectGatewayNonces(gatewayConfig{}, &legacy); !errors.Is(err, errConfig) {
		t.Fatal("existing nonce profile was replaced")
	}
}
