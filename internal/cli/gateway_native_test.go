package cli

import (
	"encoding/json"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestGatewayNativeAdminFlagRequiresExplicitBoolean(t *testing.T) {
	for _, input := range []string{`{}`, `{"native_admin":false}`, `{"native_admin":true}`} {
		var config gatewayConfig
		if json.Unmarshal([]byte(input), &config) != nil || bool(config.NativeAdmin) != (input == `{"native_admin":true}`) {
			t.Fatal("explicit opt-in or closed default changed")
		}
	}
	for _, value := range []string{`null`, `0`, `1`, `"true"`, `[]`, `{}`} {
		var config gatewayConfig
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
