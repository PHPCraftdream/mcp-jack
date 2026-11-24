//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gateway"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestGatewayModernProfileStartsWithoutStreamClaim(t *testing.T) {
	dir := clitest.PrivateDir(t)
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	listen := modernFreeLoopbackAddress(t)
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, invite := filepath.Join(dir, "state.json"), filepath.Join(dir, "invite")
	if err := keys.Bootstrap(state, invite); err != nil {
		t.Fatal(err)
	}
	path := clitest.SaveJSON(t, dir, "gateway.json", gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, dir, "server.seed", serverKey.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, Profile: "modern"})
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
}

func TestGatewayModernProfileSignsUpstreamEventStream(t *testing.T) {
	dir := clitest.PrivateDir(t)
	const event = `{"jsonrpc":"2.0","method":"notifications/event","params":{"name":"incident.created"}}`
	requestBody := `{"jsonrpc":"2.0","id":42,"method":"events/stream","params":{"name":"incident.created","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"mcp-jack-test","version":"1"}}}}`
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Jack-Accept") != "s1" || r.Header.Get("MCP-Protocol-Version") != "2026-07-28" || r.Header.Get("Mcp-Method") != "events/stream" || r.Header.Get("Mcp-Name") != "incident.created" {
			t.Errorf("modern stream metadata missing: %v", r.Header)
			http.Error(w, "metadata missing", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != requestBody {
			t.Errorf("upstream request body=%q err=%v", body, err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: "+event+"\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	listen := modernFreeLoopbackAddress(t)
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
		e.PutKey(server.RegistryEntry{Kid: retained.KID(), PublicKey: jack.EncodeBase64URL(retained.PublicKey()), Name: "stream-client"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := clitest.SaveJSON(t, dir, "gateway-modern.json", gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, dir, "gateway.seed", gatewayPrivate.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, Profile: "modern"})
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
	signer, err := client.NewInMemorySigner(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	tr := client.NewTransport(nil, "svc", signer, gatewayPublic)
	tr.Stream = &clientstream.ClientConfig{Consumer: clientstream.ConsumerMCP}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+listen+"/mcp", bytes.NewReader([]byte(requestBody)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "events/stream")
	request.Header.Set("Mcp-Name", "incident.created")
	stream, verified, err := tr.OpenStream(request)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if stream == nil || verified != nil {
		t.Fatalf("OpenStream stream=%v verified=%v", stream, verified)
	}
	defer stream.Close()
	if got, err := stream.Next(); err != nil || got != event {
		t.Fatalf("stream message=%q err=%v", got, err)
	}
	if _, err := stream.Next(); err != io.EOF {
		t.Fatalf("stream terminal=%v, want EOF", err)
	}
	if stream.FramesVerified() != 2 {
		t.Fatalf("verified frames=%d, want 2", stream.FramesVerified())
	}
}

func TestGatewayModernProfileRefusesUnoptedUpstreamEventStream(t *testing.T) {
	dir := clitest.PrivateDir(t)
	upstreamReached := make(chan struct{}, 1)
	upstreamAccept := make(chan string, 1)
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReached <- struct{}{}
		upstreamAccept <- r.Header.Get("Jack-Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/event\"}\n\n")
	}))
	listen := modernFreeLoopbackAddress(t)
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
		e.PutKey(server.RegistryEntry{Kid: retained.KID(), PublicKey: jack.EncodeBase64URL(retained.PublicKey()), Name: "refusal-client"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := clitest.SaveJSON(t, dir, "gateway-modern.json", gatewayconfig.Config{Version: 1, Aud: "svc", ServerSeedFile: clitest.Save(t, dir, "gateway.seed", gatewayPrivate.Seed()), StateFile: state, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, Profile: "modern"})
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
	signer, err := client.NewInMemorySigner(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	callerAccept := make(chan string, 1)
	c, err := client.NewClient(client.Config{BaseURL: "http://" + listen + "/mcp", Aud: "svc", Signer: signer, ServerKey: gatewayPublic, Era: client.EraModern, HTTP: &http.Client{Transport: &modernRequestRecorder{base: http.DefaultTransport, accept: callerAccept}}})
	if err != nil {
		t.Fatal(err)
	}
	err = c.CallTool(context.Background(), "events.stream", map[string]any{"name": "incident.created"}, nil)
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("CallTool error = %v, want verified *client.HTTPError", err)
	}
	if httpErr.Status != http.StatusNotImplemented || httpErr.Code != "streaming_unsupported" {
		t.Fatalf("verified HTTP error = %+v, want signed 501 streaming_unsupported", httpErr)
	}
	select {
	case got := <-callerAccept:
		if got != "" {
			t.Fatalf("caller Jack-Accept = %q, want no opt-in", got)
		}
	default:
		t.Fatal("caller request was not recorded")
	}
	select {
	case <-upstreamReached:
	default:
		t.Fatal("upstream was not reached")
	}
	select {
	case got := <-upstreamAccept:
		if got != "" {
			t.Fatalf("upstream Jack-Accept = %q, want no opt-in", got)
		}
	default:
		t.Fatal("upstream did not report Jack-Accept")
	}
}

type modernRequestRecorder struct {
	base   http.RoundTripper
	accept chan<- string
}

func (r *modernRequestRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.accept <- req.Header.Get("Jack-Accept")
	return r.base.RoundTrip(req)
}

func modernFreeLoopbackAddress(t *testing.T) string {
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
func waitForModernGateway(t *testing.T, address string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		conn, err := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("gateway did not listen")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
