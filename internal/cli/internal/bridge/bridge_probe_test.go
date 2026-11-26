//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package bridge

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
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client/modern"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gateway"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

type bridgeProbeUpstreamRequest struct {
	method          string
	accept          string
	mcpMethod       string
	protocolVersion string
	jackAccept      string
}

func TestBridgeEraProbeSelectsEraThroughStrictGateway(t *testing.T) {
	for _, test := range []struct {
		name     string
		typeName string
		expected string
	}{
		{name: "strict-json", typeName: "application/json", expected: "modern"},
		{name: "strict-sse", typeName: "text/event-stream", expected: "modern"},
		{name: "strict-legacy", typeName: "legacy", expected: "legacy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := clitest.PrivateDir(t)
			var recordsMu sync.Mutex
			var records []bridgeProbeUpstreamRequest
			socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request: %v", err)
					return
				}
				request, err := wire.Object(body)
				if err != nil {
					t.Errorf("parse request: %v", err)
					return
				}
				method := wire.Text(request["method"])
				record := bridgeProbeUpstreamRequest{
					method: method, accept: r.Header.Get("Accept"),
					mcpMethod: r.Header.Get("Mcp-Method"), protocolVersion: r.Header.Get("MCP-Protocol-Version"),
					jackAccept: r.Header.Get("Jack-Accept"),
				}
				recordsMu.Lock()
				records = append(records, record)
				recordsMu.Unlock()
				hasJSON, hasSSE := false, false
				for _, value := range strings.Split(record.accept, ",") {
					switch strings.TrimSpace(value) {
					case "application/json":
						hasJSON = true
					case "text/event-stream":
						hasSSE = true
					}
				}
				if !hasJSON || !hasSSE {
					t.Errorf("Accept=%q does not contain both required media types", record.accept)
					http.Error(w, "Accept must contain both 'application/json' and 'text/event-stream'", http.StatusBadRequest)
					return
				}
				var id json.RawMessage
				id = request["id"]
				if method == "notifications/initialized" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				if method == "initialize" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"stub","version":"1"}}}`)
					return
				}
				if method == "server/discover" && test.typeName == "legacy" {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, "not found")
					return
				}
				var response []byte
				if method == "tools/call" {
					response = []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"structuredContent":{"value":"probe"}}}`)
				} else {
					response = []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"serverInfo":{"name":"stub","version":"1"}}}`)
				}
				w.Header().Set("Content-Type", test.typeName)
				w.WriteHeader(http.StatusOK)
				if test.typeName == "text/event-stream" {
					_, _ = io.WriteString(w, "event: message\ndata: "+string(response)+"\n\n")
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					return
				}
				_, _ = w.Write(response)
			}))
			listen := bridgeProbeFreeLoopbackAddress(t)
			gatewayPublic, gatewayPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			state, invite := filepath.Join(dir, "state.json"), filepath.Join(dir, "invite")
			if err := keys.Bootstrap(state, invite); err != nil {
				t.Fatal(err)
			}
			issued, retained, err := userkey.IssueLocalPair()
			if err != nil {
				t.Fatal(err)
			}
			store, err := server.OpenFileState(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Update(func(e *server.StateEdit) error {
				e.PutKey(server.RegistryEntry{Kid: retained.KID(), PublicKey: jack.EncodeBase64URL(retained.PublicKey()), Name: "probe-client"})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			path := clitest.SaveJSON(t, dir, "gateway.json", gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, dir, "gateway.seed", gatewayPrivate.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, Profile: "both"})
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
			waitForBridgeProbeGateway(t, listen)
			signer, err := userkey.ImportClientKey(issued.Secret())
			if err != nil {
				t.Fatal(err)
			}
			conn := &transport.Connection{Endpoint: "http://" + listen + "/mcp", Aud: "svc", Pin: gatewayPublic, Signer: signer, Timeout: 2 * time.Second, Era: "auto"}
			if err := probeBridgeEra(context.Background(), conn); err != nil {
				t.Fatalf("probeBridgeEra: %v", err)
			}
			if conn.Era != test.expected {
				t.Fatalf("conn.Era=%q, want %q", conn.Era, test.expected)
			}
			assertBridgeProbeRecords(t, &recordsMu, &records, []string{"server/discover"})
			if test.expected == "modern" {
				body := modernBridgeBody(2, "tools/call", `{"name":"echo","arguments":{"value":"probe"}}`)
				var out bytes.Buffer
				if err := RelayModernFrame(context.Background(), conn, &out, io.Discard, body); err != nil {
					t.Fatalf("RelayModernFrame: %v", err)
				}
				if !bytes.Contains(out.Bytes(), []byte(`"id":2`)) {
					t.Fatalf("modern relay output=%q, want id 2", out.String())
				}
				assertBridgeProbeRecords(t, &recordsMu, &records, []string{"server/discover", "tools/call"})
			} else {
				var out bytes.Buffer
				state := 0
				initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bridge-probe-test","version":"1"}}}`)
				if err := RelayFrame(context.Background(), conn, &out, initialize, &state); err != nil {
					t.Fatalf("RelayFrame initialize: %v", err)
				}
				initialized := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
				if err := RelayFrame(context.Background(), conn, &out, initialized, &state); err != nil {
					t.Fatalf("RelayFrame initialized: %v", err)
				}
				if state != 2 || !bytes.Contains(out.Bytes(), []byte(`"id":1`)) {
					t.Fatalf("legacy relay state=%d output=%q", state, out.String())
				}
				assertBridgeProbeRecords(t, &recordsMu, &records, []string{"server/discover", "initialize", "notifications/initialized"})
			}
		})
	}
}

func assertBridgeProbeRecords(t *testing.T, mu *sync.Mutex, records *[]bridgeProbeUpstreamRequest, methods []string) {
	t.Helper()
	mu.Lock()
	got := append([]bridgeProbeUpstreamRequest(nil), (*records)...)
	mu.Unlock()
	if len(got) != len(methods) {
		t.Fatalf("upstream request count=%d, want %d: %+v", len(got), len(methods), got)
	}
	for i, method := range methods {
		record := got[i]
		if record.method != method {
			t.Errorf("upstream request %d method=%q, want %q", i, record.method, method)
		}
		parts := strings.Split(record.accept, ",")
		hasJSON, hasSSE := false, false
		for _, part := range parts {
			switch strings.TrimSpace(part) {
			case "application/json":
				hasJSON = true
			case "text/event-stream":
				hasSSE = true
			}
		}
		if !hasJSON || !hasSSE {
			t.Errorf("upstream request %d Accept=%q lacks both media types", i, record.accept)
		}
		if method == "server/discover" || method == "tools/call" {
			if record.mcpMethod != method || record.jackAccept != "s1" {
				t.Errorf("upstream request %d mirrors=%q Jack-Accept=%q", i, record.mcpMethod, record.jackAccept)
			}
			if record.protocolVersion != modern.ModernMin {
				t.Errorf("upstream request %d protocol version=%q", i, record.protocolVersion)
			}
		} else if record.mcpMethod != "" || record.jackAccept != "" {
			t.Errorf("legacy upstream request %d unexpectedly has modern mirrors: %+v", i, record)
		}
	}
}

func bridgeProbeFreeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForBridgeProbeGateway(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/mcp", nil)
		if err == nil {
			resp, roundTripErr := http.DefaultTransport.RoundTrip(req)
			if roundTripErr == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				cancel()
				return
			}
		}
		cancel()
		select {
		case <-time.After(10 * time.Millisecond):
		case <-time.After(time.Until(deadline)):
			t.Fatal("gateway did not answer GET")
		}
	}
	t.Fatal("gateway did not answer GET")
}
