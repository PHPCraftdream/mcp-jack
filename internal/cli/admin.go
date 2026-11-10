package cli

import (
	"context"
	"encoding/json"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

func userSetAdmin(ctx context.Context, configPath, kid, value string, out io.Writer) error {
	if out == nil {
		return errConfig
	}
	if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
		return errConfig
	}
	var admin bool
	switch value {
	case "true":
		admin = true
	case "false":
	default:
		return errConfig
	}
	conn, err := loadConnection(configPath)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      client.ToolAdminUserSetAdmin,
			"arguments": map[string]any{"kid": kid, "admin": admin},
		},
	})
	if err != nil {
		return errConfig
	}
	ctx, cancel := context.WithTimeout(ctx, conn.timeout)
	defer cancel()
	reply, status, err := conn.post(ctx, body)
	if err != nil {
		return err
	}
	if status != 200 {
		return errRemote
	}
	message, err := responseObject(reply, json.RawMessage("1"))
	if err != nil || len(message["error"]) != 0 {
		return errRemote
	}
	var result struct {
		IsError    bool `json:"isError"`
		Structured *struct {
			KID   string `json:"kid"`
			Admin *bool `json:"admin"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(message["result"], &result) != nil || result.IsError || result.Structured == nil || result.Structured.KID != kid || result.Structured.Admin == nil || *result.Structured.Admin != admin {
		return errRemote
	}
	return json.NewEncoder(out).Encode(result.Structured)
}
