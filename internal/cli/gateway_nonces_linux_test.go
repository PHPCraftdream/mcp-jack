//go:build linux

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestGatewayDurableBootstrapEnrollmentHTTP(t *testing.T) {
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayConfig) {
		path := filepath.Join(privateDir(t), "nonces.db")
		opts := durable.Options{DeploymentID: "public-http-gateway-test", Window: 30}
		if err := durable.InitializeUnused(path, opts); err != nil {
			t.Fatal(err)
		}
		config.DurableNonces = &gatewayDurableConfig{Path: path, DeploymentID: opts.DeploymentID, Window: opts.Window}
		// Cleanup helper останавливает gateway раньше этой проверки.
		t.Cleanup(func() {
			owner, err := durable.Open(path, opts)
			if err != nil {
				t.Error("gateway did not cleanly drain durable owner:", err)
				return
			}
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		})
	})
}

func TestGatewaySelectsExistingDurableOwnerWithoutFallback(t *testing.T) {
	path := filepath.Join(privateDir(t), "nonces.db")
	profile := &gatewayDurableConfig{Path: path, DeploymentID: "public-gateway-test", Window: 30}
	config := gatewayConfig{DurableNonces: profile, MaxConcurrent: 32}
	verification := server.Config{Aud: "test", State: boundedState{server.NewMemoryState()}}
	if closeStore, err := selectGatewayNonces(config, &verification); !errors.Is(err, errConfig) || closeStore != nil || verification.Nonces != nil || verification.DurableNonces != nil {
		t.Fatalf("missing store created or volatile fallback selected: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("serving open created a database: %v", err)
	}
	if err := durable.InitializeUnused(path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []gatewayDurableConfig{
		{Path: path, DeploymentID: "wrong-deployment", Window: 30},
		{Path: path, DeploymentID: profile.DeploymentID, Window: 31},
	} {
		candidate := verification
		closeStore, err := selectGatewayNonces(gatewayConfig{DurableNonces: &wrong, MaxConcurrent: 32}, &candidate)
		if !errors.Is(err, errConfig) || closeStore != nil || candidate.Nonces != nil || candidate.DurableNonces != nil {
			t.Fatalf("mismatched store accepted: %v", err)
		}
	}
	closeStore, err := selectGatewayNonces(config, &verification)
	if err != nil || closeStore == nil {
		t.Fatalf("initialized profile refused: %v", err)
	}
	t.Cleanup(func() { _ = closeStore() })
	if verification.Nonces != nil || verification.DurableNonces == nil || verification.Window != 30 {
		t.Fatal("durable profile was not selected exclusively")
	}
	if _, err := server.NewVerifier(verification); err != nil {
		t.Fatal("gateway registry wrapper lost coordinated gate:", err)
	}
	if err := closeStore(); err != nil {
		t.Fatal(err)
	}
	verification.DurableNonces = nil
	closeReopened, err := selectGatewayNonces(config, &verification)
	if err != nil {
		t.Fatal("clean gateway close did not permit restart:", err)
	}
	verification.DurableNonces.Fence()
	_ = closeReopened()
	verification.DurableNonces = nil
	if closeDirty, err := selectGatewayNonces(config, &verification); !errors.Is(err, errConfig) || closeDirty != nil || verification.Nonces != nil || verification.DurableNonces != nil {
		t.Fatalf("dirty store silently reopened or fell back: %v", err)
	}
}
