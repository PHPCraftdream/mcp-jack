package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

func inviteCreate(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("invite-create", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "")
	path := f.String("invite-file", "", "")
	admin := f.String("admin", "", "")
	ttl := f.Int64("ttl-seconds", 3600, "")
	keyTTL := f.Int64("key-ttl-seconds", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || *path == "" || (*admin != "true" && *admin != "false") || *ttl < 1 || *ttl > 604800 || out == nil {
		return errConfig
	}
	keyTTLSet := false
	f.Visit(func(option *flag.Flag) {
		if option.Name == "key-ttl-seconds" {
			keyTTLSet = true
		}
	})
	if keyTTLSet && (*keyTTL < 1 || *keyTTL > 31536000) {
		return errConfig
	}
	conn, err := loadConnection(*config)
	if err != nil {
		return err
	}
	file, err := reserveInviteOutput(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	arguments := map[string]any{"admin": *admin == "true", "ttl_seconds": *ttl}
	if keyTTLSet {
		arguments["key_ttl_seconds"] = *keyTTL
	}
	payload, err := conn.nativeResult(ctx, client.ToolAdminInviteCreate, arguments)
	if err != nil {
		return err
	}
	defer clear(payload)
	var result client.InviteCreateResult
	if json.Unmarshal(payload, &result) != nil || result.ExpiresAt <= 0 {
		return errRemote
	}
	code, err := jack.DecodeBase64URLFixed(result.Code, 32)
	if err != nil {
		return errRemote
	}
	defer clear(code)
	digest := sha256.Sum256(code)
	if result.InviteID != jack.EncodeBase64URL(digest[:]) {
		return errRemote
	}
	encoded := []byte(result.Code)
	defer clear(encoded)
	if n, err := file.Write(encoded); err != nil || n != len(encoded) {
		return errConfig
	}
	if file.Sync() != nil || file.Close() != nil {
		return errConfig
	}
	return json.NewEncoder(out).Encode(struct {
		InviteID  string `json:"invite_id"`
		ExpiresAt int64  `json:"expires_at"`
	}{result.InviteID, result.ExpiresAt})
}

func inviteCommand(ctx context.Context, command, configPath, inviteID string, out io.Writer) error {
	if out == nil {
		return errConfig
	}
	arguments := map[string]string{}
	var tool string
	switch command {
	case "invite-list":
		tool = client.ToolAdminInviteList
	case "invite-revoke":
		if _, err := jack.DecodeBase64URLFixed(inviteID, 32); err != nil {
			return errConfig
		}
		tool = client.ToolAdminInviteRevoke
		arguments["invite_id"] = inviteID
	default:
		return errConfig
	}
	conn, err := loadConnection(configPath)
	if err != nil {
		return err
	}
	payload, err := conn.nativeResult(ctx, tool, arguments)
	if err != nil {
		return err
	}
	if command == "invite-list" {
		var result struct {
			Invites []client.InviteListEntry `json:"invites"`
		}
		if json.Unmarshal(payload, &result) != nil || result.Invites == nil {
			return errRemote
		}
		return json.NewEncoder(out).Encode(result.Invites)
	}
	var ack client.InviteRevokeResult
	if json.Unmarshal(payload, &ack) != nil || ack.InviteID != inviteID {
		return errRemote
	}
	return json.NewEncoder(out).Encode(ack)
}
