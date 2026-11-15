//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// auditEvents parses the audit JSON lines the gateway wrote into buf.
func auditEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	data := strings.TrimSuffix(buf.String(), "\n")
	if data == "" {
		return nil
	}
	events := make([]map[string]any, 0, len(strings.Split(data, "\n")))
	for i, line := range strings.Split(data, "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("audit line %d is not a JSON object: %v (%q)", i, err, line)
		}
		events = append(events, event)
	}
	return events
}

// checkAuditEvent asserts the exact key set and the core fields of one event.
func checkAuditEvent(t *testing.T, event map[string]any, wantKeys []string, tool, outcome, code, target string) {
	t.Helper()
	if len(event) != len(wantKeys) {
		t.Fatalf("audit event keys = %v, want exactly %v", event, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := event[key]; !ok {
			t.Fatalf("audit event missing key %q: %v", key, event)
		}
	}
	if event["tool"] != tool || event["outcome"] != outcome {
		t.Fatalf("audit tool/outcome = %v/%v, want %s/%s", event["tool"], event["outcome"], tool, outcome)
	}
	if code == "" {
		if _, ok := event["code"]; ok {
			t.Fatalf("unexpected code in audit event: %v", event)
		}
	} else if event["code"] != code {
		t.Fatalf("audit code = %v, want %s", event["code"], code)
	}
	if target == "" {
		if _, ok := event["target"]; ok {
			t.Fatalf("unexpected target in audit event: %v", event)
		}
	} else if event["target"] != target {
		t.Fatalf("audit target = %v, want %s", event["target"], target)
	}
}

// TestGatewayAuditEventsOnStderr checks spec 03 section 8 on the shipped
// gateway: every jack.enroll and jack.admin.* call that reaches the tool
// records exactly one audit JSON line on the process standard error stream,
// successful or not, a call rejected before reaching a tool records none, and
// no line carries the invite code or key material.
func TestGatewayAuditEventsOnStderr(t *testing.T) {
	d := privateDir(t)
	var upstreamCalls atomic.Int32
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(200) }))
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := port.Addr().String()
	_ = port.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state, invite := filepath.Join(d, "state.json"), filepath.Join(d, "invite")
	if bootstrap(state, invite) != nil {
		t.Fatal("bootstrap failed")
	}
	cfg := gatewayConfig{Version: 1, Aud: "svc", ServerSeedFile: save(t, d, "server.seed", priv.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4}
	path := saveJSON(t, d, "gateway.json", cfg)
	var audit bytes.Buffer
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway(ctx, path, &audit) }()
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
	for {
		c, dialErr := net.DialTimeout("tcp", listen, 20*time.Millisecond)
		if dialErr == nil {
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
	clientPath := saveJSON(t, d, "client.json", clientConfig{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: save(t, d, "user.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000})
	code, err := readPrivate(invite, 43)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := userkey.ImportClientKey(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	kid := signer.KID()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": server.ToolEnroll, "arguments": map[string]string{
			"code": string(code), "name": "first-admin", "public_key": jack.EncodeBase64URL(signer.PublicKey()),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// A request the gateway refuses before any tool (wrong protocol version)
	// must not produce an audit line.
	callCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	r, err := http.NewRequestWithContext(callCtx, http.MethodPost, "http://"+listen+"/mcp", bytes.NewReader(body))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	r.Header.Set("MCP-Protocol-Version", "2026-07-28")
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
	network := directTransport(time.Second)
	resp, err := (oneShot{network}).RoundTrip(r)
	network.CloseIdleConnections()
	if err != nil {
		cancel()
		t.Fatal("refused request failed to reach the gateway")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	cancel()
	if resp.StatusCode != 400 {
		t.Fatalf("invalid protocol version = %d, want 400", resp.StatusCode)
	}
	if events := auditEvents(t, &audit); len(events) != 0 {
		t.Fatalf("a pre-tool rejection wrote audit lines: %v", events)
	}

	// A successful jack.enroll: exactly one success line.
	if err := enroll(context.Background(), clientPath, invite, "first-admin"); err != nil {
		t.Fatal(err)
	}
	events := auditEvents(t, &audit)
	if len(events) != 1 {
		t.Fatalf("audit lines = %d, want 1 after a successful enroll: %v", len(events), events)
	}
	checkAuditEvent(t, events[0], []string{"time", "tool", "outcome", "actor_kid", "target"}, server.ToolEnroll, server.AuditSuccess, "", "first-admin")
	if events[0]["actor_kid"] != kid {
		t.Fatalf("audit actor_kid = %v, want %s", events[0]["actor_kid"], kid)
	}
	if ts, ok := events[0]["time"].(float64); !ok || ts <= 0 {
		t.Fatalf("audit time = %v, want a positive unix timestamp", events[0]["time"])
	}

	// An enrollment attempt with an invite that is already used is no longer
	// live: the unregistered key is an ordinary unsigned 401 unknown_key before
	// the tool, so no new audit line is written.
	reuse, _, _ := userkey.IssueLocalPair()
	reusePath := saveJSON(t, d, "reuse.json", clientConfig{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: save(t, d, "reuse.seed", reuse.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000})
	if err := enroll(context.Background(), reusePath, invite, "again"); err == nil {
		t.Fatal("invite reused")
	}
	events = auditEvents(t, &audit)
	if len(events) != 1 {
		t.Fatalf("audit lines = %d, want 1 after an enroll refused before the tool: %v", len(events), events)
	}

	// A failed admin call (native admin is disabled): exactly one failure
	// line naming the caller, with no target.
	c, err := loadConnection(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	adminBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": server.ToolAdminInviteList}})
	if err != nil {
		t.Fatal(err)
	}
	if _, status, postErr := c.post(context.Background(), adminBody); postErr == nil || status != 403 {
		t.Fatalf("admin call = %d, %v, want a signed 403", status, postErr)
	}
	events = auditEvents(t, &audit)
	if len(events) != 2 {
		t.Fatalf("audit lines = %d, want 2 after a failed admin call: %v", len(events), events)
	}
	checkAuditEvent(t, events[1], []string{"time", "tool", "outcome", "code", "actor_kid", "actor_name"}, server.ToolAdminInviteList, server.AuditFailure, jack.CodeOperationDenied, "")
	if events[1]["actor_kid"] != kid || events[1]["actor_name"] != "first-admin" {
		t.Fatalf("audit actor = %v/%v, want %s/first-admin", events[1]["actor_kid"], events[1]["actor_name"], kid)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("native enrollment/admin reached upstream")
	}

	// No line may carry the invite code or any key material.
	for _, secret := range []string{
		string(code),
		jack.EncodeBase64URL(signer.PublicKey()),
		jack.EncodeBase64URL(issued.Secret()),
		jack.EncodeBase64URL(priv.Seed()),
		jack.EncodeBase64URL(pub),
	} {
		if strings.Contains(audit.String(), secret) {
			t.Fatal("the audit stream leaked secret material")
		}
	}
}
