package cli

import (
	"context"
	"encoding/json"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

func userCommand(ctx context.Context, command, configPath, kid string, out io.Writer) error {
	if out == nil {
		return errConfig
	}
	var tool string
	switch command {
	case "user-list":
		tool = client.ToolAdminUserList
	case "user-get":
		tool = client.ToolAdminUserGet
	case "user-revoke":
		tool = client.ToolAdminUserRevoke
	default:
		return errConfig
	}
	arguments := map[string]string{}
	if command != "user-list" {
		if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
			return errConfig
		}
		arguments["kid"] = kid
	}
	conn, err := loadConnection(configPath)
	if err != nil {
		return err
	}
	payload, err := conn.nativeResult(ctx, tool, arguments)
	if err != nil {
		return err
	}
	switch command {
	case "user-list":
		var result struct {
			Users []client.Entry `json:"users"`
		}
		if json.Unmarshal(payload, &result) != nil || result.Users == nil {
			return errRemote
		}
		return json.NewEncoder(out).Encode(result.Users)
	case "user-get":
		var entry client.Entry
		if json.Unmarshal(payload, &entry) != nil || entry.KID != kid {
			return errRemote
		}
		return json.NewEncoder(out).Encode(entry)
	default:
		var ack client.KidResult
		if json.Unmarshal(payload, &ack) != nil || ack.KID != kid {
			return errRemote
		}
		return json.NewEncoder(out).Encode(ack)
	}
}
