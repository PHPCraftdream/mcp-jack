package cli

import (
	"bytes"
	"context"
	"encoding/json"
)

func (c *connection) nativeResult(ctx context.Context, tool string, arguments any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	if err != nil {
		return nil, errConfig
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	reply, status, err := c.post(ctx, body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errRemote
	}
	message, err := responseObject(reply, json.RawMessage("1"))
	if err != nil || len(message["error"]) != 0 {
		return nil, errRemote
	}
	var result struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if json.Unmarshal(message["result"], &result) != nil || result.IsError || len(result.Structured) == 0 || bytes.Equal(bytes.TrimSpace(result.Structured), []byte("null")) {
		return nil, errRemote
	}
	return result.Structured, nil
}
