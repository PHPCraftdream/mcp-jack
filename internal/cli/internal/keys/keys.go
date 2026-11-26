package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// EnrollUnauthorizedError replaces the generic authenticated-status text for a
// 401 from jack.enroll: the usual cause is the invite or an unknown key, not
// the transport.
type EnrollUnauthorizedError struct{}

func (e *EnrollUnauthorizedError) Error() string {
	return "enroll rejected with HTTP 401; the invite may be invalid, expired or already used, or the key unknown"
}

func (e *EnrollUnauthorizedError) Unwrap() error { return command.ErrRemote }

func Keygen(role, secretPath, publicPath string) error {
	if secretPath == publicPath || storage.PrivateParent(secretPath) != nil || storage.PrivateParent(publicPath) != nil {
		return command.ErrConfig
	}
	var secret, public []byte
	switch role {
	case "server":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return command.ErrConfig
		}
		secret = priv.Seed()
		public, _ = json.Marshal(struct {
			Public string `json:"server_public_key"`
			KID    string `json:"server_kid"`
		}{jack.EncodeBase64URL(pub), jack.KeyID(pub)})
	case "user":
		issued, retained, err := userkey.IssueLocalPair()
		if err != nil {
			return command.ErrConfig
		}
		secret = issued.Secret()
		public, err = userkey.ExportPublicEnvelope(retained)
		if err != nil {
			return command.ErrConfig
		}
	default:
		return command.ErrConfig
	}
	defer clear(secret)
	return storage.CreateFiles([]string{publicPath, secretPath}, [][]byte{public, secret})
}

func Bootstrap(statePath, invitePath string) error {
	if statePath == invitePath || storage.PrivateParent(statePath) != nil || storage.PrivateParent(invitePath) != nil {
		return command.ErrConfig
	}
	unlock, err := storage.LockState(statePath)
	if err != nil {
		return err
	}
	defer unlock()
	state := server.NewMemoryState()
	code, err := server.BootstrapAdmin(state, time.Now().Unix(), 900, server.NativeOptions{})
	if err != nil {
		return command.ErrConfig
	}
	view := state.View()
	data, err := json.Marshal(struct {
		Version int                    `json:"version"`
		Keys    []server.RegistryEntry `json:"keys"`
		Invites []server.InviteRecord  `json:"invites"`
	}{1, view.Keys, view.Invites})
	if err != nil {
		return command.ErrConfig
	}
	return storage.CreateFiles([]string{statePath, invitePath}, [][]byte{data, []byte(code)})
}

func Enroll(ctx context.Context, configPath, invitePath, name string) error {
	if !jack.ValidName(name) {
		return command.ErrConfig
	}
	conn, err := transport.LoadConnection(configPath)
	if err != nil {
		return err
	}
	code, err := storage.ReadPrivate(invitePath, 43)
	if err != nil {
		return err
	}
	defer clear(code)
	if _, err := jack.DecodeBase64URLFixed(string(code), 32); err != nil {
		return command.ErrConfig
	}
	body, err := conn.NativeBody(server.ToolEnroll, map[string]string{
		"code": string(code), "name": name, "public_key": jack.EncodeBase64URL(conn.Signer.PublicKey()),
	})
	if err != nil {
		return command.ErrConfig
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(ctx, conn.Timeout)
	defer cancel()
	reply, status, err := conn.Post(ctx, body)
	var verified *transport.VerifiedStatusError
	if errors.As(err, &verified) && verified.Status == http.StatusUnauthorized {
		// 401 from enroll: point at the invite/key instead of the transport.
		return &EnrollUnauthorizedError{}
	}
	if err != nil {
		return err
	}
	if status != 200 {
		return command.ErrRemote
	}
	m, err := wire.ResponseObject(reply, json.RawMessage("1"))
	if err != nil || len(m["error"]) != 0 {
		return command.ErrRemote
	}
	var result struct {
		IsError    bool `json:"isError"`
		Structured struct {
			KID  string `json:"kid"`
			Name string `json:"name"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(m["result"], &result) != nil || result.IsError || result.Structured.KID != conn.Signer.KID() || result.Structured.Name != name {
		return command.ErrRemote
	}
	return nil
}
