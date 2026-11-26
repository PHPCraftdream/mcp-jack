package transport

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/client/modern"
)

func TestNativeBodyEra(t *testing.T) {
	for _, era := range []string{"", "auto", "legacy", "modern"} {
		t.Run(era, func(t *testing.T) {
			c := &Connection{Era: era}
			arguments := map[string]string{"key": "value"}
			body, err := c.NativeBody("jack.example", arguments)
			if err != nil {
				t.Fatal(err)
			}
			old, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "jack.example", "arguments": arguments},
			})
			if err != nil {
				t.Fatal(err)
			}
			if era != "modern" && string(body) != string(old) {
				t.Fatalf("legacy body differs: %s != %s", body, old)
			}
			if era == "modern" {
				var message map[string]any
				if json.Unmarshal(body, &message) != nil {
					t.Fatal("invalid native body")
				}
				params := message["params"].(map[string]any)
				meta := params["_meta"].(map[string]any)
				if meta[modern.MetaVersionKey] != modern.ModernMin || params["name"] != "jack.example" || message["jsonrpc"] != "2.0" || message["method"] != "tools/call" || message["id"] != float64(1) {
					t.Fatal("modern body fields invalid")
				}
				capabilities, ok := meta[modern.MetaClientCapabilitiesKey].(map[string]any)
				if !ok || len(capabilities) != 0 {
					t.Fatal("modern client capabilities missing or non-empty")
				}
				var gotArguments map[string]string
				arguments, err := json.Marshal(params["arguments"])
				if err != nil || json.Unmarshal(arguments, &gotArguments) != nil || gotArguments["key"] != "value" {
					t.Fatal("modern arguments changed")
				}
				header := make(http.Header)
				if err := c.setModernMirrors(header, body); err != nil {
					t.Fatal(err)
				}
				if header.Get("MCP-Protocol-Version") != modern.ModernMin || header.Get("Mcp-Method") != "tools/call" || header.Get("Mcp-Name") != "jack.example" {
					t.Fatalf("modern mirrors missing: %v", header)
				}
			}
		})
	}
}
