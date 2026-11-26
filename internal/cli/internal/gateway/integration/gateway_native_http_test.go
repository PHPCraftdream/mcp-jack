//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gateway"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestGatewayNativeAdminOptInHTTP(t *testing.T) {
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayconfig.Config) { config.NativeAdmin = true })
}

func testGatewayNativeAdminLifecycle(t *testing.T, config string) {
	t.Helper()
	invoke := func(args ...string) []byte {
		t.Helper()
		var out clitest.AdminTestOutput
		var diagnostics bytes.Buffer
		if cli.Run(context.Background(), args, cli.IO{Out: &out, Err: &diagnostics}) != 0 {
			t.Fatalf("gateway admin CLI failed: %s", diagnostics.String())
		}
		return append([]byte(nil), out.Bytes()...)
	}
	issued, public, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	document, err := userkey.ExportPublicEnvelope(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := clitest.Save(t, clitest.PrivateDir(t), "member.public", document)
	created := invoke("user-create", "--config", config, "--public", publicPath, "--name", "member", "--admin", "false")
	var ack client.KidResult
	if json.Unmarshal(created, &ack) != nil || ack.KID != public.KID() {
		t.Fatal("gateway created wrong public identity")
	}
	var memberConfig transport.Config
	if storage.DecodeConfig(config, &memberConfig) != nil {
		t.Fatal("client fixture configuration invalid")
	}
	memberConfig.KeyFile = clitest.Save(t, clitest.PrivateDir(t), "member.seed", issued.Secret())
	memberConfig.KeyFormat = "raw-seed"
	memberPath := clitest.SaveJSON(t, clitest.PrivateDir(t), "member.json", memberConfig)
	var memberOut clitest.AdminTestOutput
	var memberDiagnostics bytes.Buffer
	if cli.Run(context.Background(), []string{"user-list", "--config", memberPath}, cli.IO{Out: &memberOut, Err: &memberDiagnostics}) == 0 || memberOut.Len() != 0 || memberDiagnostics.String() != "jack: authenticated HTTP 403; no retry performed\n" {
		t.Fatal("gateway native opt-in bypassed non-admin authorization")
	}
	for _, value := range []string{"true", "false"} {
		invoke("user-set-admin", "--config", config, "--kid", ack.KID, "--admin", value)
	}
	var entry client.Entry
	if json.Unmarshal(invoke("user-get", "--config", config, "--kid", ack.KID), &entry) != nil || entry.Admin || entry.KID != ack.KID {
		t.Fatal("gateway lost explicit admin=false")
	}
	invoke("user-list", "--config", config)
	invitePath := filepath.Join(clitest.PrivateDir(t), "issued.invite")
	var invitation client.InviteCreateResult
	if json.Unmarshal(invoke("invite-create", "--config", config, "--invite-file", invitePath, "--admin", "false"), &invitation) != nil || invitation.InviteID == "" || invitation.Code != "" {
		t.Fatal("gateway invite receipt invalid or secret-bearing")
	}
	invoke("invite-list", "--config", config)
	invoke("invite-revoke", "--config", config, "--invite-id", invitation.InviteID)
	invoke("user-revoke", "--config", config, "--kid", ack.KID)
	conn, err := transport.LoadConnection(config)
	if err != nil {
		t.Fatal(err)
	}
	var refused clitest.AdminTestOutput
	var diagnostics bytes.Buffer
	if cli.Run(context.Background(), []string{"user-revoke", "--config", config, "--kid", conn.Signer.KID()}, cli.IO{Out: &refused, Err: &diagnostics}) == 0 || refused.Len() != 0 || diagnostics.String() != "jack: authenticated HTTP 409; no retry performed\n" {
		t.Fatal("gateway bypassed last-admin guard")
	}
	for _, tool := range []string{"jack.whoami", "jack.key.rotate", "jack.server.key", "jack.admin.future"} {
		if _, err := conn.NativeResult(context.Background(), tool, map[string]string{}); err == nil {
			t.Fatal("native admin opt-in expanded unrelated tools")
		}
	}
}

func TestGatewayModernNativeEnrollAndAdmin(t *testing.T) {
	d := clitest.PrivateDir(t)
	var upstreamCalls atomic.Int32
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	listen := modernFreeLoopbackAddress(t)
	gatewayPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, invite := filepath.Join(d, "state.json"), filepath.Join(d, "invite")
	if err := keys.Bootstrap(state, invite); err != nil {
		t.Fatal(err)
	}
	path := clitest.SaveJSON(t, d, "gateway-modern.json", gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, d, "server.seed", serverKey.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, Profile: "modern", NativeAdmin: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway.Run(ctx, path, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gateway did not stop")
		}
	})
	waitForModernGateway(t, listen)

	issued, signer, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPath := clitest.SaveJSON(t, d, "client-modern.json", transport.Config{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(gatewayPublic), ServerKID: jack.KeyID(gatewayPublic), KeyFile: clitest.Save(t, d, "client.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000, Era: "modern"})
	if err := keys.Enroll(ctx, clientPath, invite, "first-admin"); err != nil {
		t.Fatal(err)
	}
	store, err := server.OpenFileState(state)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := store.Lookup(signer.KID())
	if !ok || entry.Name != "first-admin" || entry.PublicKey != jack.EncodeBase64URL(signer.PublicKey()) {
		t.Fatalf("enrolled registry entry = %+v, found=%v", entry, ok)
	}
	conn, err := transport.LoadConnection(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := conn.NativeResult(ctx, server.ToolAdminInviteList, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Invites []client.InviteListEntry `json:"invites"`
	}
	if err := json.Unmarshal(result, &listed); err != nil {
		t.Fatal(err)
	}
	freshIssued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	freshPath := clitest.SaveJSON(t, d, "client-modern-fresh.json", transport.Config{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(gatewayPublic), ServerKID: jack.KeyID(gatewayPublic), KeyFile: clitest.Save(t, d, "fresh.seed", freshIssued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000, Era: "modern"})
	if err := keys.Enroll(ctx, freshPath, invite, "again"); err == nil {
		t.Fatal("consumed invite accepted for a fresh key")
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("native enrollment/admin reached upstream")
	}
}

func TestGatewayBootstrapEnrollNoNativeForward(t *testing.T) {
	testGatewayBootstrapEnrollNoNativeForward(t, nil)
}

func testGatewayBootstrapEnrollNoNativeForward(t *testing.T, configure func(*gatewayconfig.Config)) {
	t.Helper()
	d := clitest.PrivateDir(t)
	var upstreamCalls atomic.Int32
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(200) }))
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := port.Addr().String()
	_ = port.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state, invite := filepath.Join(d, "state.json"), filepath.Join(d, "invite")
	if keys.Bootstrap(state, invite) != nil {
		t.Fatal("bootstrap failed")
	}
	cfg := gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, d, "server.seed", priv.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4}
	if configure != nil {
		configure(&cfg)
	}
	path := clitest.SaveJSON(t, d, "gateway.json", cfg)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway.Run(ctx, path, io.Discard) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("gateway did not stop")
		}
	})
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ready := false
	for !ready {
		c, err := net.DialTimeout("tcp", listen, 20*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("gateway did not listen")
		case <-time.After(10 * time.Millisecond):
		}
	}
	issued, _, _ := userkey.IssueLocalPair()
	clientPath := clitest.SaveJSON(t, d, "client.json", transport.Config{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: clitest.Save(t, d, "user.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000})
	code, err := storage.ReadPrivate(invite, 43)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, err := storage.ReadPrivate(state, wire.MaxBody)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := userkey.ImportClientKey(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": server.ToolEnroll, "arguments": map[string]string{
			"code": string(code), "name": "first-admin", "public_key": jack.EncodeBase64URL(signer.PublicKey()),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, versions := range [][]string{{"2026-07-28"}, {wire.ProtocolVersion, wire.ProtocolVersion}, {wire.ProtocolVersion, "2026-07-28"}} {
		callCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, err := http.NewRequestWithContext(callCtx, http.MethodPost, "http://"+listen+"/mcp", bytes.NewReader(body))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		for _, version := range versions {
			r.Header.Add("MCP-Protocol-Version", version)
		}
		nonce, err := client.RandomNonce()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		auth, err := client.SignRequest(signer, "svc", r.Method, r.URL.RequestURI(), body, nonce, time.Now())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		r.Header.Set("Jack-Auth", auth)
		r.Header.Set("Content-Type", "application/json")
		network := transport.DirectTransport(time.Second)
		resp, err := (transport.NewOneShot(network)).RoundTrip(r)
		if err != nil {
			network.CloseIdleConnections()
			cancel()
			t.Fatal("native version control failed to reach gateway")
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		network.CloseIdleConnections()
		cancel()
		afterState, stateErr := storage.ReadPrivate(state, wire.MaxBody)
		if readErr != nil || stateErr != nil || resp.StatusCode != 400 || len(resp.Header.Values("Jack-Auth")) != 0 || !bytes.Equal(beforeState, afterState) {
			t.Fatal("invalid native version consumed invite or changed state")
		}
	}
	if err := keys.Enroll(context.Background(), clientPath, invite, "first-admin"); err != nil {
		t.Fatal(err)
	}
	if err := keys.Enroll(context.Background(), clientPath, invite, "again"); err == nil {
		t.Fatal("invite reused")
	}
	c, _ := transport.LoadConnection(clientPath)
	adminBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": server.ToolAdminInviteList}})
	if cfg.NativeAdmin {
		if _, status, err := c.Post(context.Background(), adminBody); err != nil || status != 200 {
			t.Fatal("explicit native admin opt-in failed")
		}
		testGatewayNativeAdminLifecycle(t, clientPath)
	} else if _, status, err := c.Post(context.Background(), adminBody); err == nil || status != 403 {
		t.Fatal("excluded native admin enabled")
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("native enrollment/admin reached upstream")
	}
	if _, err := storage.LockState(state); err == nil {
		t.Fatal("gateway owner lock missing")
	}
}
