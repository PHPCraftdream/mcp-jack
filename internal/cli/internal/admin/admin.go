package admin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	clicommand "github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// The empty reservation remains even when the remote call result is unknown.
func reserveInviteOutput(path string) (*os.File, error) {
	if storage.PrivateParent(path) != nil {
		return nil, clicommand.ErrConfig
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, clicommand.ErrConfig
	}
	ready := false
	defer func() {
		if !ready {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !storage.Owned(info) || file.Sync() != nil {
		return nil, clicommand.ErrConfig
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, clicommand.ErrConfig
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return nil, clicommand.ErrConfig
	}
	ready = true
	return file, nil
}

func InviteCreate(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("invite-create", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "")
	path := f.String("invite-file", "", "")
	admin := f.String("admin", "", "")
	ttl := f.Int64("ttl-seconds", 3600, "")
	keyTTL := f.Int64("key-ttl-seconds", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || *path == "" || (*admin != "true" && *admin != "false") || *ttl < 1 || *ttl > 604800 || out == nil {
		return clicommand.ErrConfig
	}
	keyTTLSet := false
	f.Visit(func(option *flag.Flag) {
		if option.Name == "key-ttl-seconds" {
			keyTTLSet = true
		}
	})
	if keyTTLSet && (*keyTTL < 1 || *keyTTL > 31536000) {
		return clicommand.ErrConfig
	}
	conn, err := transport.LoadConnection(*config)
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
	payload, err := conn.NativeResult(ctx, client.ToolAdminInviteCreate, arguments)
	if err != nil {
		return err
	}
	defer clear(payload)
	var result client.InviteCreateResult
	if json.Unmarshal(payload, &result) != nil || result.ExpiresAt <= 0 {
		return clicommand.ErrRemote
	}
	code, err := jack.DecodeBase64URLFixed(result.Code, 32)
	if err != nil {
		return clicommand.ErrRemote
	}
	defer clear(code)
	digest := sha256.Sum256(code)
	if result.InviteID != jack.EncodeBase64URL(digest[:]) {
		return clicommand.ErrRemote
	}
	encoded := []byte(result.Code)
	defer clear(encoded)
	if n, err := file.Write(encoded); err != nil || n != len(encoded) {
		return clicommand.ErrConfig
	}
	if file.Sync() != nil || file.Close() != nil {
		return clicommand.ErrConfig
	}
	return json.NewEncoder(out).Encode(struct {
		InviteID  string `json:"invite_id"`
		ExpiresAt int64  `json:"expires_at"`
	}{result.InviteID, result.ExpiresAt})
}

func InviteCommand(ctx context.Context, command, configPath, inviteID string, out io.Writer) error {
	if out == nil {
		return clicommand.ErrConfig
	}
	arguments := map[string]string{}
	var tool string
	switch command {
	case "invite-list":
		tool = client.ToolAdminInviteList
	case "invite-revoke":
		if _, err := jack.DecodeBase64URLFixed(inviteID, 32); err != nil {
			return clicommand.ErrConfig
		}
		tool = client.ToolAdminInviteRevoke
		arguments["invite_id"] = inviteID
	default:
		return clicommand.ErrConfig
	}
	conn, err := transport.LoadConnection(configPath)
	if err != nil {
		return err
	}
	payload, err := conn.NativeResult(ctx, tool, arguments)
	if err != nil {
		return err
	}
	if command == "invite-list" {
		var result struct {
			Invites []client.InviteListEntry `json:"invites"`
		}
		if json.Unmarshal(payload, &result) != nil || result.Invites == nil {
			return clicommand.ErrRemote
		}
		return json.NewEncoder(out).Encode(result.Invites)
	}
	var ack client.InviteRevokeResult
	if json.Unmarshal(payload, &ack) != nil || ack.InviteID != inviteID {
		return clicommand.ErrRemote
	}
	return json.NewEncoder(out).Encode(ack)
}

func UserCreate(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("user-create", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "")
	publicPath := f.String("public", "", "")
	name := f.String("name", "", "")
	admin := f.String("admin", "", "")
	before := f.Int64("not-before", 0, "")
	after := f.Int64("not-after", 0, "")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || *publicPath == "" || !jack.ValidName(*name) || (*admin != "true" && *admin != "false") || out == nil {
		return clicommand.ErrConfig
	}
	beforeSet, afterSet := false, false
	f.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "not-before":
			beforeSet = true
		case "not-after":
			afterSet = true
		}
	})
	if *before < 0 || *before > 999999999999 || *after < 0 || *after > 999999999999 || (beforeSet && afterSet && *before >= *after) {
		return clicommand.ErrConfig
	}
	data, err := storage.ReadPrivate(*publicPath, 4096)
	if err != nil {
		return err
	}
	defer clear(data)
	public, err := userkey.ImportServerPublicEnvelope(data)
	if err != nil {
		return clicommand.ErrConfig
	}
	conn, err := transport.LoadConnection(*config)
	if err != nil {
		return err
	}
	isAdmin := *admin == "true"
	arguments := client.UserCreateParams{Name: *name, PublicKey: jack.EncodeBase64URL(public.PublicKey()), Admin: &isAdmin}
	if beforeSet {
		arguments.NotBefore = before
	}
	if afterSet {
		arguments.NotAfter = after
	}
	payload, err := conn.NativeResult(ctx, client.ToolAdminUserCreate, arguments)
	if err != nil {
		return err
	}
	var ack client.KidResult
	if json.Unmarshal(payload, &ack) != nil || ack.KID != public.KID() {
		return clicommand.ErrRemote
	}
	return json.NewEncoder(out).Encode(ack)
}

func UserCommand(ctx context.Context, command, configPath, kid string, out io.Writer) error {
	if out == nil {
		return clicommand.ErrConfig
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
		return clicommand.ErrConfig
	}
	arguments := map[string]string{}
	if command != "user-list" {
		if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
			return clicommand.ErrConfig
		}
		arguments["kid"] = kid
	}
	conn, err := transport.LoadConnection(configPath)
	if err != nil {
		return err
	}
	payload, err := conn.NativeResult(ctx, tool, arguments)
	if err != nil {
		return err
	}
	switch command {
	case "user-list":
		var result struct {
			Users []client.Entry `json:"users"`
		}
		if json.Unmarshal(payload, &result) != nil || result.Users == nil {
			return clicommand.ErrRemote
		}
		return json.NewEncoder(out).Encode(result.Users)
	case "user-get":
		var entry client.Entry
		if json.Unmarshal(payload, &entry) != nil || entry.KID != kid {
			return clicommand.ErrRemote
		}
		return json.NewEncoder(out).Encode(entry)
	default:
		var ack client.KidResult
		if json.Unmarshal(payload, &ack) != nil || ack.KID != kid {
			return clicommand.ErrRemote
		}
		return json.NewEncoder(out).Encode(ack)
	}
}

func UserSetAdmin(ctx context.Context, configPath, kid, value string, out io.Writer) error {
	if out == nil {
		return clicommand.ErrConfig
	}
	if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
		return clicommand.ErrConfig
	}
	var admin bool
	switch value {
	case "true":
		admin = true
	case "false":
	default:
		return clicommand.ErrConfig
	}
	conn, err := transport.LoadConnection(configPath)
	if err != nil {
		return err
	}
	payload, err := conn.NativeResult(ctx, client.ToolAdminUserSetAdmin, map[string]any{"kid": kid, "admin": admin})
	if err != nil {
		return err
	}
	var ack struct {
		KID   string `json:"kid"`
		Admin *bool  `json:"admin"`
	}
	if json.Unmarshal(payload, &ack) != nil || ack.KID != kid || ack.Admin == nil || *ack.Admin != admin {
		return clicommand.ErrRemote
	}
	return json.NewEncoder(out).Encode(ack)
}
