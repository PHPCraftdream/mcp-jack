package gateway

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// One request holds a nonce slot until ts+window, and ts may be up to window
// seconds in the future: occupancy rate*(2*window+1) must stay strictly below
// capacity. The test fails if any of the three constants drifts.
func TestGatewayAdmissionBudget(t *testing.T) {
	occupancy := gatewayAdmissionRate * (2*gatewayconfig.MaxDurableWindow + 1)
	if occupancy >= gatewayNonceCapacity {
		t.Fatalf("admission occupancy %d*(2*%d+1)=%d must stay below nonce capacity %d",
			gatewayAdmissionRate, gatewayconfig.MaxDurableWindow, occupancy, gatewayNonceCapacity)
	}
}

func TestGatewayNativeAdminFlagRequiresExplicitBoolean(t *testing.T) {
	for _, input := range []string{`{}`, `{"native_admin":false}`, `{"native_admin":true}`} {
		var config gatewayconfig.Config
		if json.Unmarshal([]byte(input), &config) != nil || bool(config.NativeAdmin) != (input == `{"native_admin":true}`) {
			t.Fatal("explicit opt-in or closed default changed")
		}
	}
	for _, value := range []string{`null`, `0`, `1`, `"true"`, `[]`, `{}`} {
		var config gatewayconfig.Config
		if json.Unmarshal([]byte(`{"native_admin":`+value+`}`), &config) == nil {
			t.Fatal("non-boolean native admin policy accepted")
		}
	}
}

func TestGatewayNativeAdminPolicyKeepsFixedAllowlist(t *testing.T) {
	native := server.NewNativeTools(server.NativeOptions{})
	for _, enabled := range []bool{false, true} {
		policy := gatewayNative{native: native, serverKID: "server", adminEnabled: enabled}
		for _, tool := range []string{
			server.ToolAdminUserList, server.ToolAdminUserGet, server.ToolAdminUserCreate,
			server.ToolAdminUserSetAdmin, server.ToolAdminUserRevoke,
			server.ToolAdminInviteCreate, server.ToolAdminInviteList, server.ToolAdminInviteRevoke,
		} {
			_, refusal := policy.Call(&server.NativeCall{Tool: tool, Kid: "caller"})
			want := jack.CodeOperationDenied
			if enabled {
				want = jack.CodeUnknownKey
			}
			if refusal == nil || refusal.Code != want {
				t.Fatalf("tool %s bypassed opt-in or native authorization: %v", tool, refusal)
			}
			_, refusal = policy.Call(&server.NativeCall{Tool: tool, Kid: "server"})
			if refusal == nil || refusal.Code != jack.CodeOperationDenied {
				t.Fatal("server response identity admitted as native client")
			}
		}
		for _, tool := range []string{server.ToolWhoAmI, server.ToolRotateKey, "jack.server.key", "jack.admin.unknown", "external.tool"} {
			_, refusal := policy.Call(&server.NativeCall{Tool: tool, Kid: "caller"})
			if refusal == nil || refusal.Code != jack.CodeOperationDenied {
				t.Fatal("opt-in expanded beyond fixed admin allowlist")
			}
		}
	}
}

func TestGatewayNonceProfileIsExplicitAndValidated(t *testing.T) {
	legacy := server.Config{}
	closeLegacy, err := selectGatewayNonces(gatewayconfig.Config{}, &legacy)
	if err != nil || closeLegacy == nil || legacy.Nonces == nil || legacy.DurableNonces != nil {
		t.Fatalf("legacy profile changed: %v", err)
	}
	if err := closeLegacy(); err != nil {
		t.Fatal(err)
	}
	valid := gatewayconfig.DurableConfig{Path: filepath.Join(t.TempDir(), "nonces.db"), DeploymentID: "test-deployment", Window: 30}
	if err := valid.Validate(32); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*gatewayconfig.DurableConfig){
		"relative-path":        func(c *gatewayconfig.DurableConfig) { c.Path = "nonces.db" },
		"empty-deployment":     func(c *gatewayconfig.DurableConfig) { c.DeploymentID = "" },
		"invalid-utf8":         func(c *gatewayconfig.DurableConfig) { c.DeploymentID = string([]byte{0xff}) },
		"oversized-deployment": func(c *gatewayconfig.DurableConfig) { c.DeploymentID = string(make([]byte, 1025)) },
		"zero-window":          func(c *gatewayconfig.DurableConfig) { c.Window = 0 },
		"oversized-window":     func(c *gatewayconfig.DurableConfig) { c.Window = 121 },
		"window-above-cap":     func(c *gatewayconfig.DurableConfig) { c.Window = 31 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			mutate(&invalid)
			verification := server.Config{}
			closeStore, err := selectGatewayNonces(gatewayconfig.Config{DurableNonces: &invalid, MaxConcurrent: 32}, &verification)
			if !errors.Is(err, command.ErrConfig) || closeStore != nil || verification.Nonces != nil || verification.DurableNonces != nil {
				t.Fatalf("invalid profile silently fell back: %v", err)
			}
		})
	}
	if valid.Validate(33) == nil || valid.Validate(0) == nil {
		t.Fatal("durable concurrency bound not enforced")
	}
	if _, err := selectGatewayNonces(gatewayconfig.Config{}, &legacy); !errors.Is(err, command.ErrConfig) {
		t.Fatal("existing nonce profile was replaced")
	}
}

func TestBoundedGatewayStatePreservesAdmissionGate(t *testing.T) {
	state := server.NewMemoryState()
	expires := int64(130)
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "test-kid", Name: "caller", NotAfter: &expires})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bounded := boundedState{state}
	rejected := errors.New("public admission refusal")
	calls := 0
	err := bounded.WithAdmission("test-kid", func(entry server.RegistryEntry, known bool) error {
		calls++
		if !known || entry.Kid != "test-kid" || entry.Name != "caller" || entry.NotAfter == nil || *entry.NotAfter != 130 {
			t.Fatal("gateway lost coordinated registry snapshot")
		}
		*entry.NotAfter = 1
		return rejected
	})
	if !errors.Is(err, rejected) || calls != 1 {
		t.Fatalf("admission result was replaced: %v calls=%d", err, calls)
	}
	entry, known := state.Lookup("test-kid")
	if !known || entry.NotAfter == nil || *entry.NotAfter != 130 {
		t.Fatal("admission snapshot aliased registry")
	}
}

func TestBoundedGatewayStateKeepsAtomicInviteLimit(t *testing.T) {
	state := server.NewMemoryState()
	bounded := boundedState{state}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		for index := 0; index < 1024; index++ {
			edit.PutInvite(server.InviteRecord{InviteID: strconv.Itoa(index)})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "must-not-commit"})
		edit.PutInvite(server.InviteRecord{InviteID: "overflow"})
		return nil
	}); !errors.Is(err, command.ErrConfig) {
		t.Fatalf("invite capacity not enforced: %v", err)
	}
	if len(state.View().Invites) != 1024 || len(state.View().Keys) != 0 {
		t.Fatal("overflow partially committed registry edits")
	}
}

func TestBoundedGatewayStateKeepsAtomicKeyLimit(t *testing.T) {
	state := server.NewMemoryState()
	bounded := boundedState{state}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		for index := 0; index < 1024; index++ {
			edit.PutKey(server.RegistryEntry{Kid: strconv.Itoa(index)})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "overflow"})
		return nil
	}); !errors.Is(err, command.ErrConfig) {
		t.Fatalf("key capacity not enforced: %v", err)
	}
	if len(state.View().Keys) != 1024 {
		t.Fatal("failed bounded update partially committed")
	}
	if err := bounded.WithAdmission("overflow", func(_ server.RegistryEntry, known bool) error {
		if known {
			t.Fatal("rejected key became visible to admission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedGatewayStateCountsInvitesAfterPurge(t *testing.T) {
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "admin-kid", Name: "admin", Admin: true})
		for index := 0; index < 1024; index++ {
			edit.PutInvite(server.InviteRecord{InviteID: strconv.Itoa(index), CreatedBy: "old", ExpiresAt: 1})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bounded := boundedState{state}
	n := server.NewNativeTools(server.NativeOptions{})
	caller := server.RegistryEntry{Kid: "admin-kid", Name: "admin", Admin: true}
	if _, jerr := n.Call(&server.NativeCall{
		Tool: server.ToolAdminInviteCreate, Arguments: json.RawMessage("{}"),
		Caller: &caller, Kid: caller.Kid, Now: 1767225600, State: bounded,
	}); jerr != nil {
		t.Fatalf("invite.create at the cap with only expired invites: %v", jerr)
	}
	if got := len(state.View().Invites); got != 1 {
		t.Fatalf("stored invites = %d, want 1: the expired invites must be purged before the cap counts", got)
	}
}
