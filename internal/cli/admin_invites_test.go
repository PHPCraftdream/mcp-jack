//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestCLIInvitesCreateListRevokeKeepCodePrivate(t *testing.T) {
	var forwarded atomic.Int32
	config, _, state := signedFixtureWithNative(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(500)
	}), server.NewNativeTools(server.NativeOptions{}))
	caller := state.View().Keys[0]
	caller.Admin = true
	if err := state.Update(func(e *server.StateEdit) error { e.PutKey(caller); return nil }); err != nil {
		t.Fatal(err)
	}
	directory := privateDir(t)
	var ids []string
	var codes [][]byte
	for index, admin := range []string{"false", "true"} {
		path := filepath.Join(directory, admin+".invite")
		args := []string{"invite-create", "--config", config, "--invite-file", path, "--admin", admin}
		if index == 1 {
			args = append(args, "--ttl-seconds", "120", "--key-ttl-seconds", "60")
		}
		var out adminTestOutput
		var diagnostics bytes.Buffer
		if Run(context.Background(), args, IO{Out: &out, Err: &diagnostics}) != 0 {
			t.Fatalf("invite creation failed: %s", diagnostics.String())
		}
		code, err := readPrivate(path, 43)
		if err != nil || len(code) != 43 {
			t.Fatal("private code file missing or malformed")
		}
		decoded, err := jack.DecodeBase64URLFixed(string(code), 32)
		if err != nil {
			t.Fatal("code is not canonical")
		}
		digest := sha256.Sum256(decoded)
		var ack struct {
			InviteID  string `json:"invite_id"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if json.Unmarshal(out.Bytes(), &ack) != nil || ack.InviteID != jack.EncodeBase64URL(digest[:]) || out.closed || bytes.Contains(out.Bytes(), code) || bytes.Contains(diagnostics.Bytes(), code) || bytes.Contains(diagnostics.Bytes(), []byte(path)) {
			t.Fatal("public receipt invalid, output closed or code/path disclosed")
		}
		found := false
		for _, invite := range state.View().Invites {
			if invite.InviteID != ack.InviteID {
				continue
			}
			found = true
			ttl := int64(3600)
			if index == 1 {
				ttl = 120
			}
			if invite.Admin != (admin == "true") || invite.CreatedBy != caller.Kid || invite.ExpiresAt != ack.ExpiresAt || invite.ExpiresAt-invite.CreatedAt != ttl {
				t.Fatal("invite policy not preserved")
			}
			if index == 0 && invite.KeyTTLSeconds != nil || index == 1 && (invite.KeyTTLSeconds == nil || *invite.KeyTTLSeconds != 60) {
				t.Fatal("unset and explicit key TTL confused")
			}
		}
		if !found {
			t.Fatal("acknowledged invite not stored")
		}
		before := len(state.View().Invites)
		if Run(context.Background(), args, IO{Out: &out}) == 0 || len(state.View().Invites) != before {
			t.Fatal("existing output allowed replacement or another invitation")
		}
		after, err := readPrivate(path, 43)
		if err != nil || !bytes.Equal(after, code) {
			t.Fatal("existing code overwritten")
		}
		ids = append(ids, ack.InviteID)
		codes = append(codes, code)
	}
	var listing adminTestOutput
	if Run(context.Background(), []string{"invite-list", "--config", config}, IO{Out: &listing}) != 0 {
		t.Fatal("invite list failed")
	}
	var entries []client.InviteListEntry
	if json.Unmarshal(listing.Bytes(), &entries) != nil || len(entries) != 2 {
		t.Fatal("wrong invite list")
	}
	for _, code := range codes {
		if bytes.Contains(listing.Bytes(), code) {
			t.Fatal("invite list disclosed code")
		}
	}
	for _, id := range ids {
		var out adminTestOutput
		args := []string{"invite-revoke", "--config", config, "--invite-id", id}
		if Run(context.Background(), args, IO{Out: &out}) != 0 {
			t.Fatal("invite revoke failed")
		}
		var ack client.InviteRevokeResult
		if json.Unmarshal(out.Bytes(), &ack) != nil || ack.InviteID != id {
			t.Fatal("wrong revoke acknowledgement")
		}
	}
	var empty adminTestOutput
	if Run(context.Background(), []string{"invite-list", "--config", config}, IO{Out: &empty}) != 0 || empty.String() != "[]\n" || len(state.View().Invites) != 0 || forwarded.Load() != 0 {
		t.Fatal("revoked invites remain, empty list malformed or native tool forwarded")
	}
}

func TestCLIInviteUnknownOutcomeKeepsReservationAndNeverRetries(t *testing.T) {
	_, cfg, _ := signedFixture(t, http.NotFoundHandler())
	var calls atomic.Int32
	unsigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer unsigned.Close()
	cfg.Endpoint = unsigned.URL + "/mcp"
	config := saveJSON(t, privateDir(t), "client.json", cfg)
	path := filepath.Join(privateDir(t), "unknown.invite")
	args := []string{"invite-create", "--config", config, "--invite-file", path, "--admin", "false"}
	for attempt := 0; attempt < 2; attempt++ {
		var out adminTestOutput
		if Run(context.Background(), args, IO{Out: &out}) == 0 || out.Len() != 0 || calls.Load() != 1 {
			t.Fatal("unknown create succeeded or repeated network operation")
		}
		content, err := readPrivate(path, 43)
		if err != nil || len(content) != 0 {
			t.Fatal("reservation lost or populated after unverified outcome")
		}
	}
}

func TestCLIInviteValidatesAuthenticatedCodeIdentityBeforeWriting(t *testing.T) {
	_, cfg, _ := signedFixture(t, http.NotFoundHandler())
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerPublicKey, cfg.ServerKID = jack.EncodeBase64URL(public), jack.KeyID(public)
	code := jack.EncodeBase64URL(make([]byte, 32))
	digest := sha256.Sum256(make([]byte, 32))
	id := jack.EncodeBase64URL(digest[:])
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrong-id", true: "valid-control"}[valid], func(t *testing.T) {
			resultID := id
			if !valid {
				resultID = jack.EncodeBase64URL(bytes.Repeat([]byte{1}, 32))
			}
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
				if err != nil {
					t.Error("missing signed request")
					w.WriteHeader(400)
					return
				}
				body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"isError": false, "structuredContent": client.InviteCreateResult{InviteID: resultID, Code: code, ExpiresAt: 999999999999}}})
				if err != nil {
					t.Error(err)
					return
				}
				ts := time.Now().Unix()
				message := jack.ResponseSigningString(200, auth.Sig, cfg.ServerKID, ts, body)
				w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: cfg.ServerKID, TS: ts, Sig: jack.EncodeBase64URL(ed25519.Sign(private, []byte(message)))}))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer remote.Close()
			cfgCopy := cfg
			cfgCopy.Endpoint = remote.URL + "/mcp"
			config := saveJSON(t, privateDir(t), "client.json", cfgCopy)
			path := filepath.Join(privateDir(t), "receipt.invite")
			var out adminTestOutput
			status := Run(context.Background(), []string{"invite-create", "--config", config, "--invite-file", path, "--admin", "false"}, IO{Out: &out})
			stored, err := readPrivate(path, 43)
			if err != nil || calls.Load() != 1 || bytes.Contains(out.Bytes(), []byte(code)) {
				t.Fatal("private receipt handling failed")
			}
			if valid && (status != 0 || string(stored) != code) || !valid && (status == 0 || out.Len() != 0 || len(stored) != 0) {
				t.Fatal("authenticated code identity was not enforced")
			}
		})
	}
}

func TestCLIInviteInvalidPolicyDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(privateDir(t), "unused.invite")
	for _, extra := range [][]string{
		nil,
		{"--admin", "0"},
		{"--admin", "false", "--ttl-seconds", "0"},
		{"--admin", "false", "--ttl-seconds", "604801"},
		{"--admin", "false", "--key-ttl-seconds", "0"},
		{"--admin", "false", "--key-ttl-seconds", "31536001"},
		{"--admin", "false", "--unknown", "value"},
	} {
		args := append([]string{"invite-create", "--config", "not-read", "--invite-file", path}, extra...)
		var out adminTestOutput
		if Run(context.Background(), args, IO{Out: &out}) == 0 || out.Len() != 0 {
			t.Fatal("invalid invite policy accepted")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("invalid policy reached file reservation")
		}
	}
}
