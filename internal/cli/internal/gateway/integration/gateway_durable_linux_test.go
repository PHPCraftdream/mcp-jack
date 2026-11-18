//go:build linux

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestGatewayRotationBootstrapEnrollmentAndNativePage(t *testing.T) {
	var gatewayConfigPath, profilePath string
	var publication serverkey.ServerKeyPublication
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayconfig.Config) {
		directory := clitest.PrivateDir(t)
		seed, err := storage.ReadPrivate(config.ServerSeedFile, 32)
		if err != nil {
			t.Fatal(err)
		}
		anchor := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		clear(seed)
		nextSeed := bytes.Repeat([]byte{71}, 32)
		next := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
		profile := serverkey.ServerKeyConfig{Version: 1, StoreFile: filepath.Join(directory, "ring.db"), Endpoint: "http://" + config.Listen + "/mcp",
			Aud: config.Aud, Window: 30, AnchorKID: jack.KeyID(anchor), AnchorPublicKey: jack.EncodeBase64URL(anchor), AnchorReference: "gateway-anchor",
			Signers: []serverkey.ServerKeySignerConfig{{Reference: "gateway-anchor", KID: jack.KeyID(anchor), SeedFile: config.ServerSeedFile},
				{Reference: "gateway-next", KID: jack.KeyID(next), SeedFile: clitest.Save(t, directory, "next.seed", nextSeed)}}}
		profilePath = clitest.SaveJSON(t, directory, "rotation.json", profile)
		if err := serverkey.ServerKeyInitializeUnused(profilePath, profile.Endpoint, profile.Aud); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := serverkey.ServerKeyAnnounce(profilePath, profile.Signers[1].Reference, profile.Signers[1].KID, &output); err != nil || json.Unmarshal(output.Bytes(), &publication) != nil {
			t.Fatal("offline publication fixture failed", err)
		}
		noncePath := filepath.Join(directory, "nonces.db")
		nonceOptions := durable.Options{DeploymentID: "public-rotating-gateway", Window: 30}
		if err := durable.InitializeUnused(noncePath, nonceOptions); err != nil {
			t.Fatal(err)
		}
		config.ServerSeedFile = ""
		config.ServerRotationFile = gatewayconfig.RotationProfilePath(profilePath)
		config.DurableNonces = &gatewayconfig.DurableConfig{Path: noncePath, DeploymentID: nonceOptions.DeploymentID, Window: nonceOptions.Window}
		gatewayConfigPath = filepath.Join(filepath.Dir(config.StateFile), "client.json")
		t.Cleanup(func() {
			_, options, err := serverkey.OfflineServerKeyProfile(profilePath)
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
	connection, err := transport.LoadConnection(gatewayConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.server.key","arguments":{"after_ordinal":0,"after_hash":"-"}}}`)
	response, status, err := connection.Post(ctx, body)
	if err != nil || status != 200 {
		t.Fatal("explicit rotating gateway native call refused", err)
	}
	page, err := rotation.DecodeResult(response, json.RawMessage(`1`))
	if err != nil || len(page.Records) != 1 || page.Records[0] != publication.Record || page.Head.Hash != publication.Hash || !page.Complete {
		t.Fatal("rotating gateway did not return exact committed page", err)
	}
	_, options, err := serverkey.OfflineServerKeyProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotation.VerifyChain([][]byte{[]byte(page.Records[0])}, options.Binding, options.Checkpoint, nil); err != nil {
		t.Fatal("gateway page binding/authorization invalid", err)
	}
}

func TestGatewayDurableBootstrapEnrollmentHTTP(t *testing.T) {
	testGatewayDurableNativeHTTP(t, false)
}

func TestGatewayDurableNativeAdminHTTP(t *testing.T) {
	testGatewayDurableNativeHTTP(t, true)
}

func testGatewayDurableNativeHTTP(t *testing.T, admin bool) {
	t.Helper()
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayconfig.Config) {
		config.NativeAdmin = gatewayconfig.NativeAdminFlag(admin)
		path := filepath.Join(clitest.PrivateDir(t), "nonces.db")
		opts := durable.Options{DeploymentID: "public-http-gateway-test", Window: 30}
		if err := durable.InitializeUnused(path, opts); err != nil {
			t.Fatal(err)
		}
		config.DurableNonces = &gatewayconfig.DurableConfig{Path: path, DeploymentID: opts.DeploymentID, Window: opts.Window}
		// The cleanup helper stops the gateway before this check.
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
