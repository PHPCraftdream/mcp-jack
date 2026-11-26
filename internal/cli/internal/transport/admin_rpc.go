package transport

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/PHPCraftdream/mcp-jack/client/modern"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

// NativeBody builds a native tools/call request, adding the modern version mirror when needed.
func (c *Connection) NativeBody(tool string, arguments any) ([]byte, error) {
	params := map[string]any{"name": tool, "arguments": arguments}
	if c.Era == "modern" {
		mirrors, err := modern.BuildRequestMirrors(modern.ModernMin, "tools/call", params, nil)
		if err != nil {
			return nil, command.ErrConfig
		}
		params["_meta"] = mirrors.Meta
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params,
	})
}

func (c *Connection) NativeResult(ctx context.Context, tool string, arguments any) (json.RawMessage, error) {
	body, err := c.NativeBody(tool, arguments)
	if err != nil {
		return nil, command.ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	reply, status, err := c.Post(ctx, body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, command.ErrRemote
	}
	message, err := wire.ResponseObject(reply, json.RawMessage("1"))
	if err != nil || len(message["error"]) != 0 {
		return nil, command.ErrRemote
	}
	var result struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if json.Unmarshal(message["result"], &result) != nil || result.IsError || len(result.Structured) == 0 || bytes.Equal(bytes.TrimSpace(result.Structured), []byte("null")) {
		return nil, command.ErrRemote
	}
	return result.Structured, nil
}
