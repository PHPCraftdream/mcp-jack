//go:build linux

package cli

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/nonce"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/noncetest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkeytest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

func TestProcessOfflineServerKeyCommands(t *testing.T) {
	path, config := serverkeytest.CLIProfile(t)
	invoke := func(success bool, args ...string) []byte {
		t.Helper()
		process, in, out, diagnostics := clitest.ChildArgs(t, args...)
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
		reply, err := io.ReadAll(io.LimitReader(out, wire.MaxBody+1))
		if err != nil || len(reply) > wire.MaxBody {
			t.Fatal("child output unreadable or unbounded")
		}
		waitErr := process.Wait()
		if success && waitErr != nil || !success && waitErr == nil {
			t.Fatal("unexpected offline CLI process outcome", diagnostics.String())
		}
		return reply
	}
	if reply := invoke(true, serverkeytest.InitArgs(path, config)...); len(reply) != 0 {
		t.Fatal("init child disclosed output")
	}
	invoke(false, serverkeytest.InitArgs(path, config)...)
	var report durable.ServerInspection
	if json.Unmarshal(invoke(true, "server-key-status", "--config", path), &report) != nil || report.Dirty || report.HeadHash != "-" || report.StateRevision != 1 {
		t.Fatal("shipping process status invalid")
	}
}

func TestProcessOfflineServerKeyAnnouncement(t *testing.T) {
	path, config := serverkeytest.SigningProfile(t)
	invoke := func(success bool, args ...string) []byte {
		t.Helper()
		process, in, out, diagnostics := clitest.ChildArgs(t, args...)
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
		reply, err := io.ReadAll(io.LimitReader(out, wire.MaxBody+1))
		if err != nil || len(reply) > wire.MaxBody {
			t.Fatal("child output unreadable or unbounded")
		}
		waitErr := process.Wait()
		if success && waitErr != nil || !success && waitErr == nil {
			t.Fatal("unexpected offline publication process outcome", diagnostics.String())
		}
		return reply
	}
	invoke(true, serverkeytest.InitArgs(path, config)...)
	for _, entry := range config.Signers[1:3] {
		var result serverkey.ServerKeyPublication
		if json.Unmarshal(invoke(true, serverkeytest.AnnounceArgs(path, entry)...), &result) != nil || result.Record == "" {
			t.Fatal("shipping announce did not expose confirmed public record")
		}
	}
	invoke(false, serverkeytest.AnnounceArgs(path, config.Signers[2])...)
	var report durable.ServerInspection
	if json.Unmarshal(invoke(true, "server-key-status", "--config", path), &report) != nil || report.HeadOrdinal != 2 || report.StateRevision != 3 || report.Dirty {
		t.Fatal("shipping announcement lifecycle status invalid")
	}
}

func TestProcessNonceTerminalReconciliationNeverOpensServing(t *testing.T) {
	configPath, receiptPath, options, before := noncetest.RecoveryFixture(t)
	process, in, out, diagnostics := clitest.ChildArgs(t, "nonce-reconcile-terminal", "--config", configPath,
		"--expected-hash", before.Hash, "--receipt-file", receiptPath, "--confirm-no-redelivery", before.Live[0].IntentID)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(io.LimitReader(out, wire.MaxBody+1))
	waitErr := process.Wait()
	if err != nil || len(reply) != 0 || waitErr != nil {
		t.Fatal("terminal CLI child failed or disclosed output", diagnostics.String())
	}
	profile, err := nonce.OfflineNonceProfile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := durable.InspectRecovery(profile.Path, options)
	if err != nil || !after.Dirty || len(after.Live) != 0 || len(after.Tombstones) != 1 || after.Tombstones[0] != before.Live[0] {
		t.Fatal("shipping terminal reconciliation changed serving gate or receipt", err)
	}
}
