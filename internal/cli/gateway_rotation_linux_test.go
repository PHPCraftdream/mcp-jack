//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestGatewayRotationSelectorRejectsNullAndWrongJSONTypes(t *testing.T) {
	for _, value := range []string{"null", "true", "1", "{}", "[]"} {
		var config gatewayConfig
		if json.Unmarshal([]byte(`{"server_seed_file":"unused","server_rotation_file":`+value+`}`), &config) == nil {
			t.Fatal("malformed rotation selector silently selected static mode")
		}
	}
	var config gatewayConfig
	if json.Unmarshal([]byte(`{"server_seed_file":"unused","server_rotation_file":""}`), &config) != nil || config.ServerSeedFile != "unused" || config.ServerRotationFile != "" {
		t.Fatal("legacy selector positive control changed")
	}
}

func TestGatewaySelectsExplicitRotationWithoutStaticOrNonceFallback(t *testing.T) {
	path, profile := serverKeySigningProfile(t)
	config := gatewayConfig{Aud: profile.Aud, ServerRotationFile: rotationProfilePath(path), MaxConcurrent: 4,
		DurableNonces: &gatewayDurableConfig{Path: filepath.Join(privateDir(t), "nonces.db"), DeploymentID: "public-gateway-rotation", Window: profile.Window}}
	if selected, err := selectGatewaySigning(config); err == nil || selected != nil {
		t.Fatal("missing rotation store created or fallback selected")
	}
	if _, err := os.Lstat(profile.StoreFile); !os.IsNotExist(err) {
		t.Fatal("serving selection created missing rotation store")
	}
	if err := serverKeyInitializeUnused(path, profile.Endpoint, profile.Aud); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(profile.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*gatewayConfig){
		func(c *gatewayConfig) { c.ServerSeedFile = profile.Signers[0].SeedFile },
		func(c *gatewayConfig) { c.ServerRotationFile = "" },
		func(c *gatewayConfig) { c.DurableNonces = nil },
		func(c *gatewayConfig) { c.Aud = "different" },
		func(c *gatewayConfig) { value := *c.DurableNonces; value.Window++; c.DurableNonces = &value },
		func(c *gatewayConfig) { value := *c.DurableNonces; value.Path = profile.StoreFile; c.DurableNonces = &value },
		func(c *gatewayConfig) { c.StateFile = profile.StoreFile },
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
	_, options, err := offlineServerKeyProfile(path)
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
	_, profile := serverKeySigningProfile(t)
	selected, err := selectGatewaySigning(gatewayConfig{ServerSeedFile: profile.Signers[0].SeedFile})
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
	_, profile := serverKeySigningProfile(t)
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

func TestGatewayRotationBootstrapEnrollmentAndNativePage(t *testing.T) {
	var gatewayConfigPath, profilePath string
	var publication serverKeyPublication
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayConfig) {
		directory := privateDir(t)
		seed, err := readPrivate(config.ServerSeedFile, 32)
		if err != nil {
			t.Fatal(err)
		}
		anchor := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		clear(seed)
		nextSeed := bytes.Repeat([]byte{71}, 32)
		next := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
		profile := serverKeyConfig{Version: 1, StoreFile: filepath.Join(directory, "ring.db"), Endpoint: "http://" + config.Listen + "/mcp",
			Aud: config.Aud, Window: 30, AnchorKID: jack.KeyID(anchor), AnchorPublicKey: jack.EncodeBase64URL(anchor), AnchorReference: "gateway-anchor",
			Signers: []serverKeySignerConfig{{Reference: "gateway-anchor", KID: jack.KeyID(anchor), SeedFile: config.ServerSeedFile},
				{Reference: "gateway-next", KID: jack.KeyID(next), SeedFile: save(t, directory, "next.seed", nextSeed)}}}
		profilePath = saveJSON(t, directory, "rotation.json", profile)
		if err := serverKeyInitializeUnused(profilePath, profile.Endpoint, profile.Aud); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := serverKeyAnnounce(profilePath, profile.Signers[1].Reference, profile.Signers[1].KID, &output); err != nil || json.Unmarshal(output.Bytes(), &publication) != nil {
			t.Fatal("offline publication fixture failed", err)
		}
		noncePath := filepath.Join(directory, "nonces.db")
		nonceOptions := durable.Options{DeploymentID: "public-rotating-gateway", Window: 30}
		if err := durable.InitializeUnused(noncePath, nonceOptions); err != nil {
			t.Fatal(err)
		}
		config.ServerSeedFile = ""
		config.ServerRotationFile = rotationProfilePath(profilePath)
		config.DurableNonces = &gatewayDurableConfig{Path: noncePath, DeploymentID: nonceOptions.DeploymentID, Window: nonceOptions.Window}
		gatewayConfigPath = filepath.Join(filepath.Dir(config.StateFile), "client.json")
		t.Cleanup(func() {
			_, options, err := offlineServerKeyProfile(profilePath)
			if err != nil {
				t.Error(err)
				return
			}
			report, err := durable.InspectServer(profile.StoreFile, options)
			if err != nil || report.Dirty || report.HeadOrdinal != 1 {
				t.Error("gateway rotation owner did not close cleanly", err)
			}
		})
	})
	connection, err := loadConnection(gatewayConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.server.key","arguments":{"after_ordinal":0,"after_hash":"-"}}}`)
	response, status, err := connection.post(ctx, body)
	if err != nil || status != 200 {
		t.Fatal("explicit rotating gateway native call refused", err)
	}
	page, err := rotation.DecodeResult(response, json.RawMessage(`1`))
	if err != nil || len(page.Records) != 1 || page.Records[0] != publication.Record || page.Head.Hash != publication.Hash || !page.Complete {
		t.Fatal("rotating gateway did not return exact committed page", err)
	}
	_, options, err := offlineServerKeyProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotation.VerifyChain([][]byte{[]byte(page.Records[0])}, options.Binding, options.Checkpoint, nil); err != nil {
		t.Fatal("gateway page binding/authorization invalid", err)
	}
}
