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
	payload, err := conn.nativeResult(ctx, client.ToolAdminUserSetAdmin, map[string]any{"kid": kid, "admin": admin})
	if err != nil {
		return err
	}
	var ack struct {
		KID   string `json:"kid"`
		Admin *bool  `json:"admin"`
	}
	if json.Unmarshal(payload, &ack) != nil || ack.KID != kid || ack.Admin == nil || *ack.Admin != admin {
		return errRemote
	}
	return json.NewEncoder(out).Encode(ack)
}
