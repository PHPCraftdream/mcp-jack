//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func unixDial(socket string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(socket) != nil {
			return nil, command.ErrConfig
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
}

// gatewayCoverageSocket listens on a Unix socket in a short private directory: sockaddr_un paths are limited
// to about 104 bytes on macOS, which the long t.TempDir path would exceed (as in clitest.UnixUpstream).
func gatewayCoverageSocket(t *testing.T, _ string) string {
	t.Helper()
	short, err := os.MkdirTemp("", "jack-cov-")
	if err != nil {
		t.Fatal(err)
	}
	short, err = filepath.EvalSymlinks(short)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	if err := os.Chmod(short, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(short, "coverage.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("could not create Unix socket fixture: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return path
}

func gatewayCoverageConfig(t *testing.T, dir, socket, listen string) gatewayconfig.Config {
	t.Helper()
	statePath, invitePath := filepath.Join(dir, "state.json"), filepath.Join(dir, "invite")
	if err := keys.Bootstrap(statePath, invitePath); err != nil {
		t.Fatal("could not create gateway state fixture")
	}
	return gatewayconfig.Config{
		Version: 1, Aud: "coverage-service", ServerSeedFile: clitest.Save(t, dir, "server.seed", bytes.Repeat([]byte{17}, ed25519.SeedSize)),
		StateFile: statePath, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp",
		CallTimeoutMS: 750, MaxConcurrent: 4,
	}
}

func TestGatewayFixedUnixHopAndSignedRefusals(t *testing.T) {
	requests := make(chan *http.Request, 10)
	bodies := make(chan []byte, 10)
	var mode atomic.Int32
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case requests <- r.Clone(context.Background()):
		default:
			t.Error("unexpected extra upstream request")
			w.WriteHeader(500)
			return
		}
		select {
		case bodies <- b:
		default:
			t.Error("unexpected extra upstream body")
			w.WriteHeader(500)
			return
		}
		switch mode.Load() {
		case 1:
			w.Header().Set("Location", "http://127.0.0.1:1/never")
			w.WriteHeader(307)
		case 2:
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "data: forbidden\n\n")
		case 3:
			w.Header().Set("Mcp-Session-Id", "untrusted-session")
			w.WriteHeader(200)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		}
	}))
	base := transport.DirectTransport(time.Second)
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(socket) != nil {
			return nil, command.ErrConfig
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	t.Cleanup(base.CloseIdleConnections)
	h := upstreamHandler(gatewayconfig.Config{UpstreamSocket: socket, UpstreamURL: "http://upstream/fixed%2Fpath"}, base)
	path, cfg, _ := clitest.SignedFixture(t, h)
	c, err := transport.LoadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(` {"jsonrpc":"2.0", "id":3,"method":"tools/list"} `)
	request := func(method string) (*http.Response, error) {
		r, _ := http.NewRequestWithContext(context.Background(), method, strings.Replace(cfg.Endpoint, "/mcp", "/caller/ignored?q=ignored", 1), bytes.NewReader(body))
		r.Host = "caller.invalid"
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("MCP-Protocol-Version", wire.ProtocolVersion)
		r.Header.Add("X-Jack-Kid", "forged")
		r.Header.Add("X-Jack-Kid", "forged-again")
		r.Header.Add("X-Jack-Admin", "true")
		r.Header.Add("X-Jack-Admin", "true")
		r.Header.Set("Authorization", "Bearer not-forwarded")
		r.Header.Set("Cookie", "identity=not-forwarded")
		r.Header.Set("X-Forwarded-Host", "not-forwarded")
		network := transport.DirectTransport(time.Second)
		defer network.CloseIdleConnections()
		return client.NewHTTPClient(client.NewTransport(transport.NewOneShot(network), cfg.Aud, c.Signer, c.Pin)).Do(r)
	}
	resp, err := request("POST")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(b, body) || !bytes.Equal(clitest.Receive(t, bodies), body) {
		t.Fatal("exact signed bytes changed")
	}
	r := clitest.Receive(t, requests)
	if r.URL.RequestURI() != "/fixed%2Fpath" || r.Host != "upstream" || r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("MCP-Protocol-Version") != wire.ProtocolVersion {
		t.Fatal("caller selected routing or metadata changed")
	}
	if len(r.Header.Values("X-Jack-Kid")) != 1 || r.Header.Get("X-Jack-Kid") != c.Signer.KID() || r.Header.Get("X-Jack-Name") != "alice" || r.Header.Get("X-Jack-Admin") != "false" || len(r.Header.Values("X-Jack-Admin")) != 1 {
		t.Fatal("identity spoof survived")
	}
	for _, name := range []string{"Jack-Auth", "Authorization", "Cookie", "X-Forwarded-Host"} {
		if r.Header.Get(name) != "" {
			t.Fatal("non-allowlisted header survived")
		}
	}
	for _, tc := range []struct {
		mode   int32
		method string
		status int
	}{{1, "POST", 502}, {2, "POST", 501}, {3, "POST", 502}, {0, "GET", 405}, {0, "DELETE", 0}} {
		mode.Store(tc.mode)
		resp, err := request(tc.method)
		if tc.status == 0 {
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("unsigned unsupported-method refusal verified")
			}
			continue
		}
		if err != nil || resp.StatusCode != tc.status {
			t.Fatal("signed refusal missing or wrong status")
		}
		_ = resp.Body.Close()
	}
	if len(requests) != 3 {
		t.Fatal("GET/DELETE reached upstream or redirect retried")
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	if socketOK(socket) == nil {
		t.Fatal("unprotected socket accepted")
	}
	resp, err = request("POST")
	if err != nil || resp.StatusCode != 502 {
		t.Fatal("socket permissions not rechecked at dial")
	}
	_ = resp.Body.Close()
}

func TestExactAndPlusOneBodyCaps(t *testing.T) {
	var calls atomic.Int32
	var responsePlusOne atomic.Bool
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		if responsePlusOne.Load() {
			_, _ = io.WriteString(w, " ")
		}
	}))
	base := transport.DirectTransport(3 * time.Second)
	base.DialContext = unixDial(socket)
	defer base.CloseIdleConnections()
	path, _, _ := clitest.SignedFixture(t, upstreamHandler(gatewayconfig.Config{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := transport.LoadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 3 * time.Second
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body = append(body, bytes.Repeat([]byte(" "), wire.MaxBody-len(body))...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, status, err := c.Post(ctx, body)
	if err != nil || status != 200 || !bytes.Equal(reply, body) || len(reply) != wire.MaxBody || calls.Load() != 1 {
		t.Fatal("exact request/response cap baseline refused or changed")
	}
	responsePlusOne.Store(true)
	if _, status, err := c.Post(ctx, body); err == nil || status != 502 || calls.Load() != 2 {
		t.Fatal("response cap+1 did not produce a verified refusal")
	}
	tooLarge := append(append([]byte(nil), body...), ' ')
	if _, _, err := c.Post(ctx, tooLarge); err == nil || calls.Load() != 2 {
		t.Fatal("local request cap+1 reached upstream")
	}
	// Bypass the CLI's local size check to discriminate the SDK HTTP ingress cap.
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(tooLarge))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := client.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.SignRequest(c.Signer, c.Aud, r.Method, r.URL.RequestURI(), tooLarge, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Jack-Auth", auth)
	r.Header.Set("Content-Type", "application/json")
	network := transport.DirectTransport(3 * time.Second)
	defer network.CloseIdleConnections()
	resp, err := (transport.NewOneShot(network)).RoundTrip(r)
	if err != nil {
		t.Fatal("ingress cap control failed to reach gateway")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 413 || len(resp.Header.Values("Jack-Auth")) != 0 || calls.Load() != 2 {
		t.Fatal("oversized HTTP ingress was forwarded or described as signed")
	}
}

func TestGatewayRequestAndResponseCapsAndDeadline(t *testing.T) {
	socket := clitest.UnixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m, _ := wire.Object(b)
		if wire.Text(m["method"]) == "slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
				t.Error("slow fixture cancellation timed out")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", wire.MaxBody+1))
	}))
	base := transport.DirectTransport(200 * time.Millisecond)
	base.DialContext = unixDial(socket)
	t.Cleanup(base.CloseIdleConnections)
	path, _, _ := clitest.SignedFixture(t, upstreamHandler(gatewayconfig.Config{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := transport.LoadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"tools/list", "slow"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		_, status, err := c.Post(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
		cancel()
		if err == nil || status != 502 || time.Since(start) > 2*time.Second {
			t.Fatal("cap/deadline failed")
		}
	}
	if _, _, err := c.Post(context.Background(), bytes.Repeat([]byte("x"), wire.MaxBody+1)); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestLoadGatewayPinsConfigBoundsAndUpstreamPolicy(t *testing.T) {
	dir := clitest.PrivateDir(t)
	socket := gatewayCoverageSocket(t, dir)
	config := gatewayCoverageConfig(t, dir, socket, "127.0.0.1:1")
	path := clitest.SaveJSON(t, dir, "valid-gateway.json", config)
	loaded, duration, err := loadGateway(path)
	if err != nil || duration != 750*time.Millisecond || loaded.Aud != "coverage-service" || loaded.UpstreamURL != "http://upstream/mcp" {
		t.Fatalf("valid bounded gateway config = %#v, %s, %v", loaded, duration, err)
	}

	cases := []struct {
		name   string
		mutate func(*gatewayconfig.Config)
	}{
		{"version", func(c *gatewayconfig.Config) { c.Version = 2 }},
		{"empty-audience", func(c *gatewayconfig.Config) { c.Aud = "" }},
		{"zero-concurrency", func(c *gatewayconfig.Config) { c.MaxConcurrent = 0 }},
		{"excess-concurrency", func(c *gatewayconfig.Config) { c.MaxConcurrent = 65 }},
		{"invalid-durable-profile", func(c *gatewayconfig.Config) {
			c.DurableNonces = &gatewayconfig.DurableConfig{Path: "relative.db", DeploymentID: "deployment", Window: 1}
		}},
		{"short-timeout", func(c *gatewayconfig.Config) { c.CallTimeoutMS = 99 }},
		{"long-timeout", func(c *gatewayconfig.Config) { c.CallTimeoutMS = 30001 }},
		{"non-ip-listener", func(c *gatewayconfig.Config) { c.Listen = "localhost:1234" }},
		{"wildcard-listener", func(c *gatewayconfig.Config) { c.Listen = "0.0.0.0:1234" }},
		{"zero-listener-port", func(c *gatewayconfig.Config) { c.Listen = "127.0.0.1:0" }},
		{"out-of-range-listener-port", func(c *gatewayconfig.Config) { c.Listen = "127.0.0.1:65536" }},
		{"malformed-listener", func(c *gatewayconfig.Config) { c.Listen = "127.0.0.1" }},
		{"malformed-upstream", func(c *gatewayconfig.Config) { c.UpstreamURL = "://" }},
		{"non-http-upstream", func(c *gatewayconfig.Config) { c.UpstreamURL = "https://upstream/mcp" }},
		{"upstream-credentials", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://user@upstream/mcp" }},
		{"upstream-query", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://upstream/mcp?x=1" }},
		{"upstream-fragment", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://upstream/mcp#fragment" }},
		{"wrong-upstream-host", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://other/mcp" }},
		{"upstream-backslash", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://upstream/a\\b" }},
		{"upstream-newline", func(c *gatewayconfig.Config) { c.UpstreamURL = "http://upstream/mcp\n" }},
		{"missing-socket", func(c *gatewayconfig.Config) { c.UpstreamSocket = filepath.Join(dir, "missing.sock") }},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := config
			tc.mutate(&bad)
			badPath := clitest.SaveJSON(t, dir, "invalid-"+strings.ReplaceAll(tc.name, "-", "_")+"-"+string(rune('a'+index))+".json", bad)
			if got, gotDuration, err := loadGateway(badPath); err != command.ErrConfig || gotDuration != 0 {
				t.Fatalf("invalid config accepted or wrong refusal: duration=%s err=%v config=%#v", gotDuration, err, got)
			}
		})
	}
}

func TestGatewaySetupRefusalsReleaseOnlyOwnedLock(t *testing.T) {
	for _, name := range []string{"preexisting-owner", "missing-state", "response-key-collision", "occupied-listener"} {
		t.Run(name, func(t *testing.T) {
			dir := clitest.PrivateDir(t)
			socket := gatewayCoverageSocket(t, dir)
			listen := "127.0.0.1:1"
			var occupied net.Listener
			if name == "occupied-listener" {
				var err error
				occupied, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = occupied.Close() })
				listen = occupied.Addr().String()
			}
			config := gatewayCoverageConfig(t, dir, socket, listen)
			switch name {
			case "preexisting-owner":
				if err := storage.Exclusive(config.StateFile+".owner", []byte("other owner\n")); err != nil {
					t.Fatal(err)
				}
			case "missing-state":
				config.StateFile = filepath.Join(dir, "absent-state.json")
			case "response-key-collision":
				seed, err := storage.ReadPrivate(config.ServerSeedFile, ed25519.SeedSize)
				if err != nil {
					t.Fatal(err)
				}
				public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
				clear(seed)
				state, err := server.OpenFileState(config.StateFile)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Update(func(edit *server.StateEdit) error {
					edit.PutKey(server.RegistryEntry{Kid: jack.KeyID(public), PublicKey: jack.EncodeBase64URL(public), Name: "response-key"})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			configPath := clitest.SaveJSON(t, dir, "gateway.json", config)
			err := Run(context.Background(), configPath, nil)
			if err != command.ErrConfig {
				t.Fatalf("gateway setup refusal = %v, want %q", err, command.ErrConfig)
			}
			ownerPath := config.StateFile + ".owner"
			if name == "preexisting-owner" {
				owner, readErr := storage.ReadPrivate(ownerPath, 64)
				if readErr != nil || string(owner) != "other owner\n" {
					t.Fatalf("preexisting owner changed: %q err=%v", owner, readErr)
				}
			} else if _, statErr := os.Lstat(ownerPath); !os.IsNotExist(statErr) {
				t.Fatalf("gateway did not release its owner lock: %v", statErr)
			}
		})
	}
}

func TestGatewayUpstreamHandlerRejectsMalformedAndUnsafeExchange(t *testing.T) {
	identityContexts := make(chan context.Context, 1)
	clientPath, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityContexts <- context.WithoutCancel(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	connection, err := transport.LoadConnection(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := connection.Post(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); err != nil || status != http.StatusOK {
		t.Fatalf("signed identity fixture call = %d, %v", status, err)
	}
	identityContext := <-identityContexts
	if _, ok := server.IdentityFromContext(identityContext); !ok {
		t.Fatal("signed positive control did not capture a verified identity")
	}

	mode := "json"
	var exchangeMu sync.Mutex
	var forwarded *http.Request
	var forwardedBody []byte
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("upstream request body read: %v", readErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		exchangeMu.Lock()
		forwarded = r.Clone(context.Background())
		forwardedBody = body
		selectedMode := mode
		exchangeMu.Unlock()
		switch selectedMode {
		case "redirect":
			w.Header().Set("Location", "http://127.0.0.1:1/not-followed")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "metadata":
			w.Header().Set("Mcp-Session-Id", "untrusted")
			w.WriteHeader(http.StatusOK)
		case "encoding":
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
		case "duplicate-content-type":
			w.Header().Add("Content-Type", "application/json")
			w.Header().Add("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
		case "bad-version":
			w.Header().Set("MCP-Protocol-Version", "wrong-version")
			w.WriteHeader(http.StatusOK)
		case "duplicate-version":
			w.Header().Add("MCP-Protocol-Version", wire.ProtocolVersion)
			w.Header().Add("MCP-Protocol-Version", wire.ProtocolVersion)
			w.WriteHeader(http.StatusOK)
		case "event-stream":
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "data: must-not-forward\\n\\n")
		case "truncated":
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "x")
		case "oversize":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, wire.MaxBody+1))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("MCP-Protocol-Version", wire.ProtocolVersion)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
	defer remote.Close()
	base := transport.DirectTransport(time.Second)
	defer base.CloseIdleConnections()
	config := gatewayconfig.Config{UpstreamURL: remote.URL + "/fixed%2Fpath"}
	handler := upstreamHandler(config, base)
	call := func(method string, body string, headers http.Header, ctx context.Context) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, "http://gateway/caller/path?ignored=yes", strings.NewReader(body))
		request.Header = headers.Clone()
		if ctx != nil {
			request = request.WithContext(ctx)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	setMode := func(value string) {
		exchangeMu.Lock()
		mode = value
		exchangeMu.Unlock()
	}
	lastForwarded := func() (*http.Request, []byte) {
		exchangeMu.Lock()
		defer exchangeMu.Unlock()
		return forwarded, append([]byte(nil), forwardedBody...)
	}
	if response := call(http.MethodGet, "", nil, nil); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), `"code":"method_not_allowed"`) {
		t.Fatalf("GET refusal = %d %q %v", response.Code, response.Body.String(), response.Header())
	}
	if response := call(http.MethodPost, `{}`, nil, nil); response.Code != http.StatusInternalServerError {
		t.Fatalf("request without verified identity = %d, want 500", response.Code)
	}
	for _, tc := range []struct {
		name   string
		body   string
		header string
		want   int
	}{
		{"malformed-json", "{", "", http.StatusBadRequest},
		{"cancel-notification", `{"jsonrpc":"2.0","method":"notifications/cancelled"}`, "", http.StatusBadRequest},
		{"bad-protocol-version", `{"jsonrpc":"2.0","method":"tools/list"}`, "wrong-version", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			if tc.header != "" {
				headers.Set("MCP-Protocol-Version", tc.header)
			}
			response := call(http.MethodPost, tc.body, headers, identityContext)
			if response.Code != tc.want {
				t.Fatalf("refusal status = %d, want %d", response.Code, tc.want)
			}
		})
	}

	validBody := ` {"jsonrpc":"2.0","id":3,"method":"tools/list"} `
	headers := make(http.Header)
	headers.Set("MCP-Protocol-Version", wire.ProtocolVersion)
	response := call(http.MethodPost, validBody, headers, identityContext)
	forwardedRequest, requestBody := lastForwarded()
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":1`) || forwardedRequest == nil || forwardedRequest.URL.RequestURI() != "/fixed%2Fpath" || string(requestBody) != validBody {
		t.Fatalf("forwarded positive control = %d %q request=%#v body=%q", response.Code, response.Body.String(), forwardedRequest, requestBody)
	}
	if forwardedRequest.Header.Get("X-Jack-Kid") != connection.Signer.KID() || forwardedRequest.Header.Get("X-Jack-Name") != "alice" || forwardedRequest.Header.Get("X-Jack-Admin") != "false" {
		t.Fatalf("verified identity forwarding headers = %v", forwardedRequest.Header)
	}
	if response.Header().Get("MCP-Protocol-Version") != wire.ProtocolVersion {
		t.Fatalf("valid upstream protocol version was not retained: %v", response.Header())
	}

	for _, tc := range []struct {
		mode string
		want int
	}{
		{"redirect", http.StatusBadGateway},
		{"metadata", http.StatusBadGateway},
		{"encoding", http.StatusBadGateway},
		{"duplicate-content-type", http.StatusBadGateway},
		{"bad-version", http.StatusBadGateway},
		{"duplicate-version", http.StatusBadGateway},
		{"event-stream", http.StatusOK},
		{"truncated", http.StatusBadGateway},
		{"oversize", http.StatusOK},
	} {
		setMode(tc.mode)
		response := call(http.MethodPost, validBody, headers, identityContext)
		if response.Code != tc.want {
			t.Fatalf("upstream mode %s status = %d, want %d body=%q", tc.mode, response.Code, tc.want, response.Body.String())
		}
		if tc.mode == "event-stream" && (response.Header().Get("Content-Type") != "text/event-stream" || response.Body.Len() != 0) {
			t.Fatalf("event stream was not refused without forwarding bytes: %v %q", response.Header(), response.Body.String())
		}
		if tc.mode == "oversize" && response.Body.Len() != wire.MaxBody+1 {
			t.Fatalf("bounded upstream read returned %d bytes, want its wire.MaxBody+1 sentinel", response.Body.Len())
		}
	}
	setMode("json")
	badURL := upstreamHandler(gatewayconfig.Config{UpstreamURL: "http://%zz"}, base)
	badRequest := httptest.NewRequest(http.MethodPost, "http://gateway/mcp", strings.NewReader(validBody)).WithContext(identityContext)
	badResponse := httptest.NewRecorder()
	badURL.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadGateway {
		t.Fatalf("invalid upstream request target status = %d, want 502", badResponse.Code)
	}

	failedTransport := transport.DirectTransport(time.Second)
	failedTransport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("controlled dial refusal")
	}
	defer failedTransport.CloseIdleConnections()
	transportHandler := upstreamHandler(gatewayconfig.Config{UpstreamURL: remote.URL + "/fixed"}, failedTransport)
	transportRequest := httptest.NewRequest(http.MethodPost, "http://gateway/mcp", strings.NewReader(validBody)).WithContext(identityContext)
	transportResponse := httptest.NewRecorder()
	transportHandler.ServeHTTP(transportResponse, transportRequest)
	if transportResponse.Code != http.StatusBadGateway {
		t.Fatalf("upstream transport refusal status = %d, want 502", transportResponse.Code)
	}
}

func TestGatewaySocketRequiresOwnedPrivateSocket(t *testing.T) {
	dir := clitest.PrivateDir(t)
	socket := gatewayCoverageSocket(t, dir)
	if err := socketOK(socket); err != nil {
		t.Fatalf("owned 0600 Unix socket refused: %v", err)
	}
	regular := clitest.Save(t, dir, "regular", []byte("not a socket"))
	if err := socketOK(regular); err != command.ErrConfig {
		t.Fatalf("regular-file socket refusal = %v, want command.ErrConfig", err)
	}
	link := filepath.Join(dir, "socket-link")
	if err := os.Symlink(socket, link); err != nil {
		t.Fatal(err)
	}
	if err := socketOK(link); err != command.ErrConfig {
		t.Fatalf("symlink socket refusal = %v, want command.ErrConfig", err)
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	if err := socketOK(socket); err != command.ErrConfig {
		t.Fatalf("public socket refusal = %v, want command.ErrConfig", err)
	}
}
