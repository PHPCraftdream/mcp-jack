package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func keygen(role, secretPath, publicPath string) error {
	if secretPath == publicPath || privateParent(secretPath) != nil || privateParent(publicPath) != nil {
		return errConfig
	}
	var secret, public []byte
	switch role {
	case "server":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errConfig
		}
		secret = priv.Seed()
		public, _ = json.Marshal(struct {
			Public string `json:"server_public_key"`
			KID    string `json:"server_kid"`
		}{jack.EncodeBase64URL(pub), jack.KeyID(pub)})
	case "user":
		issued, retained, err := userkey.IssueLocalPair()
		if err != nil {
			return errConfig
		}
		secret = issued.Secret()
		public, err = userkey.ExportPublicEnvelope(retained)
		if err != nil {
			return errConfig
		}
	default:
		return errConfig
	}
	defer clear(secret)
	return createFiles([]string{publicPath, secretPath}, [][]byte{public, secret})
}

func bootstrap(statePath, invitePath string) error {
	if statePath == invitePath || privateParent(statePath) != nil || privateParent(invitePath) != nil {
		return errConfig
	}
	unlock, err := lockState(statePath)
	if err != nil {
		return err
	}
	defer unlock()
	state := server.NewMemoryState()
	code, err := server.BootstrapAdmin(state, time.Now().Unix(), 900, server.NativeOptions{})
	if err != nil {
		return errConfig
	}
	view := state.View()
	data, err := json.Marshal(struct {
		Version int                    `json:"version"`
		Keys    []server.RegistryEntry `json:"keys"`
		Invites []server.InviteRecord  `json:"invites"`
	}{1, view.Keys, view.Invites})
	if err != nil {
		return errConfig
	}
	return createFiles([]string{statePath, invitePath}, [][]byte{data, []byte(code)})
}

func enroll(ctx context.Context, configPath, invitePath, name string) error {
	if !jack.ValidName(name) {
		return errConfig
	}
	conn, err := loadConnection(configPath)
	if err != nil {
		return err
	}
	code, err := readPrivate(invitePath, 43)
	if err != nil {
		return err
	}
	defer clear(code)
	if _, err := jack.DecodeBase64URLFixed(string(code), 32); err != nil {
		return errConfig
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": server.ToolEnroll, "arguments": map[string]string{
			"code": string(code), "name": name, "public_key": jack.EncodeBase64URL(conn.signer.PublicKey()),
		}},
	})
	if err != nil {
		return errConfig
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(ctx, conn.timeout)
	defer cancel()
	reply, status, err := conn.post(ctx, body)
	if err != nil {
		return err
	}
	if status != 200 {
		return errRemote
	}
	m, err := responseObject(reply, json.RawMessage("1"))
	if err != nil || len(m["error"]) != 0 {
		return errRemote
	}
	var result struct {
		IsError    bool `json:"isError"`
		Structured struct {
			KID  string `json:"kid"`
			Name string `json:"name"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(m["result"], &result) != nil || result.IsError || result.Structured.KID != conn.signer.KID() || result.Structured.Name != name {
		return errRemote
	}
	return nil
}
