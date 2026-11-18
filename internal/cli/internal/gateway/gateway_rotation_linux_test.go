//go:build linux

package gateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkeytest"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestGatewayRotationSelectorRejectsNullAndWrongJSONTypes(t *testing.T) {
	for _, value := range []string{"null", "true", "1", "{}", "[]"} {
		var config gatewayconfig.Config
		if json.Unmarshal([]byte(`{"server_seed_file":"unused","server_rotation_file":`+value+`}`), &config) == nil {
			t.Fatal("malformed rotation selector silently selected static mode")
		}
	}
	var config gatewayconfig.Config
	if json.Unmarshal([]byte(`{"server_seed_file":"unused","server_rotation_file":""}`), &config) != nil || config.ServerSeedFile != "unused" || config.ServerRotationFile != "" {
		t.Fatal("legacy selector positive control changed")
	}
}

func TestGatewaySelectsExplicitRotationWithoutStaticOrNonceFallback(t *testing.T) {
	path, profile := serverkeytest.SigningProfile(t)
	config := gatewayconfig.Config{Aud: profile.Aud, ServerRotationFile: gatewayconfig.RotationProfilePath(path), MaxConcurrent: 4,
		DurableNonces: &gatewayconfig.DurableConfig{Path: filepath.Join(clitest.PrivateDir(t), "nonces.db"), DeploymentID: "public-gateway-rotation", Window: profile.Window}}
	if selected, err := selectGatewaySigning(config); err == nil || selected != nil {
		t.Fatal("missing rotation store created or fallback selected")
	}
	if _, err := os.Lstat(profile.StoreFile); !os.IsNotExist(err) {
		t.Fatal("serving selection created missing rotation store")
	}
	if err := serverkey.ServerKeyInitializeUnused(path, profile.Endpoint, profile.Aud); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(profile.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*gatewayconfig.Config){
		func(c *gatewayconfig.Config) { c.ServerSeedFile = profile.Signers[0].SeedFile },
		func(c *gatewayconfig.Config) { c.ServerRotationFile = "" },
		func(c *gatewayconfig.Config) { c.DurableNonces = nil },
		func(c *gatewayconfig.Config) { c.Aud = "different" },
		func(c *gatewayconfig.Config) { value := *c.DurableNonces; value.Window++; c.DurableNonces = &value },
		func(c *gatewayconfig.Config) {
			value := *c.DurableNonces
			value.Path = profile.StoreFile
			c.DurableNonces = &value
		},
		func(c *gatewayconfig.Config) { c.StateFile = profile.StoreFile },
	} {
		bad := config
		mutate(&bad)
		if selected, err := selectGatewaySigning(bad); err == nil || selected != nil {
			t.Fatal("mixed/mismatched rotation configuration admitted")
		}
	}
	after, err := os.ReadFile(profile.StoreFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid selection mutated protected store")
	}
	selected, err := selectGatewaySigning(config)
	if err != nil || selected.provider == nil || selected.key != nil || selected.anchorKID != profile.AnchorKID {
		t.Fatal("rotation profile not selected exclusively", err)
	}
	defer selected.close()
	for _, entry := range profile.Signers {
		if !selected.serverKIDs[entry.KID] {
			t.Fatal("configured response identity absent from native exclusion")
		}
	}
	if err := selected.close(); err != nil {
		t.Fatal(err)
	}
	_, options, err := serverkey.OfflineServerKeyProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := durable.InspectServer(profile.StoreFile, options)
	if err != nil || report.Dirty || report.Unsafe {
		t.Fatal("selected rotation owner did not drain cleanly", err)
	}
	owner, err := durable.OpenServer(profile.StoreFile, options)
	if err != nil {
		t.Fatal(err)
	}
	owner.Fence()
	_ = owner.Close()
	if selected, err := selectGatewaySigning(config); err == nil || selected != nil {
		t.Fatal("dirty rotation store silently reopened or fell back")
	}
}

func TestGatewayStaticSigningStillSelectedAndPrivateBufferClearedAfterClose(t *testing.T) {
	_, profile := serverkeytest.SigningProfile(t)
	selected, err := selectGatewaySigning(gatewayconfig.Config{ServerSeedFile: profile.Signers[0].SeedFile})
	if err != nil || selected.provider != nil || len(selected.key) != ed25519.PrivateKeySize || !selected.serverKIDs[profile.AnchorKID] {
		t.Fatal("legacy static profile changed", err)
	}
	key := selected.key
	if err := selected.close(); err != nil || !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("static owner failed to release its private buffer")
	}
}

type gatewayServerKeySpy struct{ calls int }

func (spy *gatewayServerKeySpy) Call(*server.NativeCall) (server.NativeResult, *jack.Error) {
	spy.calls++
	return server.NativeResult{}, nil
}

func TestGatewayNativeExcludesAllResponseIdentitiesOnBothRoutes(t *testing.T) {
	_, profile := serverkeytest.SigningProfile(t)
	identities := make(map[string]bool)
	for _, entry := range profile.Signers {
		identities[entry.KID] = true
	}
	spy := &gatewayServerKeySpy{}
	policy := gatewayNative{native: server.NewNativeTools(server.NativeOptions{}), serverKID: profile.AnchorKID,
		serverKIDs: identities, serverKeys: spy, adminEnabled: true}
	for kid := range identities {
		for _, tool := range []string{server.ToolEnroll, server.ToolAdminInviteList, server.ToolServerKey} {
			if _, refusal := policy.Call(&server.NativeCall{Tool: tool, Kid: kid}); refusal == nil || refusal.HTTPStatus != 403 {
				t.Fatal("response signer reached native route")
			}
		}
	}
	if spy.calls != 0 {
		t.Fatal("response identity reached candidate provider")
	}
	clientPublic := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, 32)).Public().(ed25519.PublicKey)
	if _, refusal := policy.Call(&server.NativeCall{Tool: server.ToolServerKey, Kid: jack.KeyID(clientPublic)}); refusal != nil || spy.calls != 1 {
		t.Fatal("non-response caller positive control did not reach selected candidate route")
	}
}

func TestGatewaySelectsExistingDurableOwnerWithoutFallback(t *testing.T) {
	path := filepath.Join(clitest.PrivateDir(t), "nonces.db")
	profile := &gatewayconfig.DurableConfig{Path: path, DeploymentID: "public-gateway-test", Window: 30}
	config := gatewayconfig.Config{DurableNonces: profile, MaxConcurrent: 32}
	verification := server.Config{Aud: "test", State: boundedState{server.NewMemoryState()}}
	if closeStore, err := selectGatewayNonces(config, &verification); !errors.Is(err, command.ErrConfig) || closeStore != nil || verification.Nonces != nil || verification.DurableNonces != nil {
		t.Fatalf("missing store created or volatile fallback selected: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("serving open created a database: %v", err)
	}
	if err := durable.InitializeUnused(path, durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []gatewayconfig.DurableConfig{
		{Path: path, DeploymentID: "wrong-deployment", Window: 30},
		{Path: path, DeploymentID: profile.DeploymentID, Window: 29},
	} {
		candidate := verification
		closeStore, err := selectGatewayNonces(gatewayconfig.Config{DurableNonces: &wrong, MaxConcurrent: 32}, &candidate)
		if !errors.Is(err, command.ErrConfig) || closeStore != nil || candidate.Nonces != nil || candidate.DurableNonces != nil {
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
	if closeDirty, err := selectGatewayNonces(config, &verification); !errors.Is(err, command.ErrConfig) || closeDirty != nil || verification.Nonces != nil || verification.DurableNonces != nil {
		t.Fatalf("dirty store silently reopened or fell back: %v", err)
	}
}
