//go:build linux

package nonce_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
)

func TestOfflineNonceCommandsRequireExplicitUnusedDeploymentAndNeverReplace(t *testing.T) {
	directory := clitest.PrivateDir(t)
	path := filepath.Join(directory, "nonces.db")
	profile := &gatewayconfig.DurableConfig{Path: path, DeploymentID: "public-admin-cli-test", Window: 30}
	config := clitest.SaveJSON(t, directory, "gateway.json", gatewayconfig.Config{
		Version: 1, Aud: "test", MaxConcurrent: 32, DurableNonces: profile,
		ServerSeedFile: "not-read", StateFile: "not-read", UpstreamSocket: "not-read",
	})
	var diagnostics bytes.Buffer
	for _, args := range [][]string{
		{"nonce-init-unused", "--config", config},
		{"nonce-init-unused", "--config", config, "--confirm-unused-deployment", "wrong"},
	} {
		if cli.Run(context.Background(), args, cli.IO{Err: &diagnostics}) == 0 {
			t.Fatal("missing or wrong operator confirmation accepted")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unconfirmed initialization touched store: %v", err)
		}
	}
	initialize := []string{"nonce-init-unused", "--config", config, "--confirm-unused-deployment", profile.DeploymentID}
	if cli.Run(context.Background(), initialize, cli.IO{Err: &diagnostics}) != 0 {
		t.Fatal("explicit unused initialization failed")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cli.Run(context.Background(), initialize, cli.IO{Err: &diagnostics}) == 0 {
		t.Fatal("existing database was initialized again")
	}
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), []string{"nonce-inspect", "--config", config}, cli.IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("offline inspection failed")
	}
	var report durable.RecoverySnapshot
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.DeploymentID != profile.DeploymentID || report.Window != 30 || report.Dirty || report.Unsafe || report.Hash == "" {
		t.Fatalf("inexact CLI report: %+v %v", report, err)
	}
	if output.Closed {
		t.Fatal("non-bridge command took output ownership")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeat init or inspection rewrote database")
	}
	if bytes.Contains(diagnostics.Bytes(), []byte(path)) || bytes.Contains(diagnostics.Bytes(), []byte(profile.DeploymentID)) {
		t.Fatal("diagnostics leaked supplied values")
	}
}

func TestOfflineNonceInspectionDoesNotClearDirtyGate(t *testing.T) {
	directory := clitest.PrivateDir(t)
	path := filepath.Join(directory, "nonces.db")
	profile := &gatewayconfig.DurableConfig{Path: path, DeploymentID: "public-dirty-cli-test", Window: 30}
	config := clitest.SaveJSON(t, directory, "gateway.json", gatewayconfig.Config{Version: 1, Aud: "test", MaxConcurrent: 32, DurableNonces: profile})
	opts := durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}
	if err := durable.InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	owner, err := durable.Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	owner.Fence()
	_ = owner.Close()
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), []string{"nonce-inspect", "--config", config}, cli.IO{Out: output}) != 0 {
		t.Fatal("dirty inspection failed")
	}
	var report durable.RecoverySnapshot
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || !report.Dirty {
		t.Fatalf("dirty CLI report: %+v %v", report, err)
	}
	if opened, err := durable.Open(path, opts); !errors.Is(err, durable.ErrRecoveryRequired) {
		if opened != nil {
			opened.Fence()
			_ = opened.Close()
		}
		t.Fatalf("inspection authorized startup: %v", err)
	}
	if cli.Run(context.Background(), []string{"nonce-inspect", "--config", config}, cli.IO{}) == 0 {
		t.Fatal("missing output accepted")
	}
}
