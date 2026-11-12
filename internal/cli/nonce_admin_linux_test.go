//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
)

type nonceTestOutput struct {
	bytes.Buffer
	closed bool
}

func (output *nonceTestOutput) Close() error { output.closed = true; return nil }

func TestOfflineNonceCommandsRequireExplicitUnusedDeploymentAndNeverReplace(t *testing.T) {
	directory := privateDir(t)
	path := filepath.Join(directory, "nonces.db")
	profile := &gatewayDurableConfig{Path: path, DeploymentID: "public-admin-cli-test", Window: 30}
	config := saveJSON(t, directory, "gateway.json", gatewayConfig{
		Version: 1, Aud: "test", MaxConcurrent: 32, DurableNonces: profile,
		ServerSeedFile: "not-read", StateFile: "not-read", UpstreamSocket: "not-read",
	})
	var diagnostics bytes.Buffer
	for _, args := range [][]string{
		{"nonce-init-unused", "--config", config},
		{"nonce-init-unused", "--config", config, "--confirm-unused-deployment", "wrong"},
	} {
		if Run(context.Background(), args, IO{Err: &diagnostics}) == 0 {
			t.Fatal("missing or wrong operator confirmation accepted")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unconfirmed initialization touched store: %v", err)
		}
	}
	initialize := []string{"nonce-init-unused", "--config", config, "--confirm-unused-deployment", profile.DeploymentID}
	if Run(context.Background(), initialize, IO{Err: &diagnostics}) != 0 {
		t.Fatal("explicit unused initialization failed")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if Run(context.Background(), initialize, IO{Err: &diagnostics}) == 0 {
		t.Fatal("existing database was initialized again")
	}
	output := &nonceTestOutput{}
	if Run(context.Background(), []string{"nonce-inspect", "--config", config}, IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("offline inspection failed")
	}
	var report durable.RecoverySnapshot
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.DeploymentID != profile.DeploymentID || report.Window != 30 || report.Dirty || report.Unsafe || report.Hash == "" {
		t.Fatalf("inexact CLI report: %+v %v", report, err)
	}
	if output.closed {
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
	directory := privateDir(t)
	path := filepath.Join(directory, "nonces.db")
	profile := &gatewayDurableConfig{Path: path, DeploymentID: "public-dirty-cli-test", Window: 30}
	config := saveJSON(t, directory, "gateway.json", gatewayConfig{Version: 1, Aud: "test", MaxConcurrent: 32, DurableNonces: profile})
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
	output := &nonceTestOutput{}
	if Run(context.Background(), []string{"nonce-inspect", "--config", config}, IO{Out: output}) != 0 {
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
	if Run(context.Background(), []string{"nonce-inspect", "--config", config}, IO{}) == 0 {
		t.Fatal("missing output accepted")
	}
}
