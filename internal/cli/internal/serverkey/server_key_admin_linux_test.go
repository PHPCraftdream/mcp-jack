//go:build linux

package serverkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
	cli "github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkeytest"
)

func TestOfflineServerKeyInitAndStatusConfirmBindingNeverReplace(t *testing.T) {
	path, config := serverkeytest.CLIProfile(t)
	var diagnostics bytes.Buffer
	for _, args := range [][]string{
		{"server-key-init-unused", "--config", path},
		{"server-key-init-unused", "--config", path, "--confirm-unused-endpoint", config.Endpoint},
		{"server-key-init-unused", "--config", path, "--confirm-unused-endpoint", "wrong", "--confirm-unused-aud", config.Aud},
		{"server-key-init-unused", "--config", path, "--confirm-unused-endpoint", config.Endpoint, "--confirm-unused-aud", "wrong"},
		{"server-key-status", "--config", path},
	} {
		if cli.Run(context.Background(), args, cli.IO{Out: &clitest.NonceTestOutput{}, Err: &diagnostics}) == 0 {
			t.Fatal("missing confirmation/store accepted")
		}
		if _, err := os.Lstat(config.StoreFile); !os.IsNotExist(err) {
			t.Fatal("failed offline command touched missing store")
		}
	}
	if cli.Run(context.Background(), serverkeytest.InitArgs(path, config), cli.IO{Err: &diagnostics}) != 0 {
		t.Fatal("explicit unused binding init failed", diagnostics.String())
	}
	before, err := os.ReadFile(config.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	if cli.Run(context.Background(), serverkeytest.InitArgs(path, config), cli.IO{Err: &diagnostics}) == 0 {
		t.Fatal("existing server store replaced")
	}
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), []string{"server-key-status", "--config", path}, cli.IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("offline server status failed", diagnostics.String())
	}
	var report durable.ServerInspection
	if json.Unmarshal(output.Bytes(), &report) != nil || report.Dirty || report.Unsafe || report.Fenced || report.HeadOrdinal != 0 || report.HeadHash != "-" || report.StateRevision != 1 || report.RetainedKeys != 1 || report.StoreID == "" {
		t.Fatal("incorrect public status")
	}
	if output.Closed || bytes.Contains(output.Bytes(), []byte(config.AnchorReference)) || bytes.Contains(output.Bytes(), []byte(config.StoreFile)) || bytes.Contains(diagnostics.Bytes(), []byte(config.StoreFile)) || bytes.Contains(diagnostics.Bytes(), []byte(config.Aud)) {
		t.Fatal("output ownership or private diagnostic leak")
	}
	after, err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeat init/status rewrote store")
	}
}

func TestOfflineServerKeyStatusDoesNotClearDirtyOrOpenServing(t *testing.T) {
	path, config := serverkeytest.CLIProfile(t)
	var diagnostics bytes.Buffer
	if cli.Run(context.Background(), serverkeytest.InitArgs(path, config), cli.IO{Err: &diagnostics}) != 0 {
		t.Fatal("fixture init failed")
	}
	_, options, err := serverkey.OfflineServerKeyProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := durable.OpenServer(config.StoreFile, options)
	if err != nil {
		t.Fatal(err)
	}
	if output := (&clitest.NonceTestOutput{}); cli.Run(context.Background(), []string{"server-key-status", "--config", path}, cli.IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("status bypassed lifetime owner")
	}
	owner.Fence()
	if owner.Close() == nil {
		t.Fatal("fixture failed to preserve dirty epoch")
	}
	before, err := os.ReadFile(config.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), []string{"server-key-status", "--config", path}, cli.IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("dirty status unreadable")
	}
	var report durable.ServerInspection
	if json.Unmarshal(output.Bytes(), &report) != nil || !report.Dirty {
		t.Fatal("CLI repaired/hidden dirty flag")
	}
	after, err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("dirty status changed evidence")
	}
	if reopened, err := durable.OpenServer(config.StoreFile, options); err == nil || reopened != nil {
		t.Fatal("status authorized serving recovery")
	}
}

func TestOfflineServerKeyProfileValidationBeforeStoreCreation(t *testing.T) {
	path, config := serverkeytest.CLIProfile(t)
	var diagnostics bytes.Buffer
	for index, mutate := range []func(*serverkey.ServerKeyConfig){
		func(c *serverkey.ServerKeyConfig) { c.Version = 2 },
		func(c *serverkey.ServerKeyConfig) { c.Window = 0 },
		func(c *serverkey.ServerKeyConfig) { c.Window = 121 },
		func(c *serverkey.ServerKeyConfig) { c.Window = gatewayconfig.MaxDurableWindow + 1 },
		func(c *serverkey.ServerKeyConfig) { c.AnchorKID = "wrong" },
		func(c *serverkey.ServerKeyConfig) { c.AnchorPublicKey += "=" },
		func(c *serverkey.ServerKeyConfig) { c.AnchorReference = "" },
		func(c *serverkey.ServerKeyConfig) { c.Endpoint = "relative/path" },
		func(c *serverkey.ServerKeyConfig) { c.Endpoint = "https://user:secret@example.invalid/mcp" },
		func(c *serverkey.ServerKeyConfig) { c.Endpoint = "https://example.invalid/mcp#fragment" },
		func(c *serverkey.ServerKeyConfig) { c.Aud = "" },
		func(c *serverkey.ServerKeyConfig) { c.StoreFile = "" },
	} {
		bad := config
		mutate(&bad)
		badPath := clitest.SaveJSON(t, filepath.Dir(path), "bad-"+string(rune('a'+index))+".json", bad)
		if cli.Run(context.Background(), serverkeytest.InitArgs(badPath, bad), cli.IO{Err: &diagnostics}) == 0 {
			t.Fatal("invalid protected profile accepted")
		}
		if _, err := os.Lstat(config.StoreFile); !os.IsNotExist(err) {
			t.Fatal("invalid profile touched store")
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for index, extra := range []string{`"version":1,"version":1`, `"version":1,"private_key":"forbidden"`} {
		changed := bytes.Replace(encoded, []byte(`"version":1`), []byte(extra), 1)
		if bytes.Equal(changed, encoded) {
			t.Fatal("negative config token missing")
		}
		badPath := filepath.Join(filepath.Dir(path), "ambiguous-"+string(rune('a'+index))+".json")
		if err := os.WriteFile(badPath, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if cli.Run(context.Background(), serverkeytest.InitArgs(badPath, config), cli.IO{Err: &diagnostics}) == 0 {
			t.Fatal("duplicate/unknown private config field accepted")
		}
	}
	if serverkey.ServerKeyStatus(path, nil) == nil {
		t.Fatal("missing output accepted")
	}
	if bytes.Contains(diagnostics.Bytes(), []byte("secret")) || bytes.Contains(diagnostics.Bytes(), []byte(config.StoreFile)) {
		t.Fatal("profile refusal leaked supplied values")
	}
}
