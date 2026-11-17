//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"syscall"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// gatewayCoverageSocket listens on a Unix socket in a short private directory: sockaddr_un paths are limited
// to about 104 bytes on macOS, which the long t.TempDir path would exceed (as in unixUpstream).
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

func gatewayCoverageConfig(t *testing.T, dir, socket, listen string) gatewayConfig {
	t.Helper()
	statePath, invitePath := filepath.Join(dir, "state.json"), filepath.Join(dir, "invite")
	if err := bootstrap(statePath, invitePath); err != nil {
		t.Fatal("could not create gateway state fixture")
	}
	return gatewayConfig{
		Version: 1, Aud: "coverage-service", ServerSeedFile: save(t, dir, "server.seed", bytes.Repeat([]byte{17}, ed25519.SeedSize)),
		StateFile: statePath, Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp",
		CallTimeoutMS: 750, MaxConcurrent: 4,
	}
}

func TestLoadGatewayPinsConfigBoundsAndUpstreamPolicy(t *testing.T) {
	dir := privateDir(t)
	socket := gatewayCoverageSocket(t, dir)
	config := gatewayCoverageConfig(t, dir, socket, "127.0.0.1:1")
	path := saveJSON(t, dir, "valid-gateway.json", config)
	loaded, duration, err := loadGateway(path)
	if err != nil || duration != 750*time.Millisecond || loaded.Aud != "coverage-service" || loaded.UpstreamURL != "http://upstream/mcp" {
		t.Fatalf("valid bounded gateway config = %#v, %s, %v", loaded, duration, err)
	}

	cases := []struct {
		name   string
		mutate func(*gatewayConfig)
	}{
		{"version", func(c *gatewayConfig) { c.Version = 2 }},
		{"empty-audience", func(c *gatewayConfig) { c.Aud = "" }},
		{"zero-concurrency", func(c *gatewayConfig) { c.MaxConcurrent = 0 }},
		{"excess-concurrency", func(c *gatewayConfig) { c.MaxConcurrent = 65 }},
		{"invalid-durable-profile", func(c *gatewayConfig) {
			c.DurableNonces = &gatewayDurableConfig{Path: "relative.db", DeploymentID: "deployment", Window: 1}
		}},
		{"short-timeout", func(c *gatewayConfig) { c.CallTimeoutMS = 99 }},
		{"long-timeout", func(c *gatewayConfig) { c.CallTimeoutMS = 30001 }},
		{"non-ip-listener", func(c *gatewayConfig) { c.Listen = "localhost:1234" }},
		{"wildcard-listener", func(c *gatewayConfig) { c.Listen = "0.0.0.0:1234" }},
		{"zero-listener-port", func(c *gatewayConfig) { c.Listen = "127.0.0.1:0" }},
		{"out-of-range-listener-port", func(c *gatewayConfig) { c.Listen = "127.0.0.1:65536" }},
		{"malformed-listener", func(c *gatewayConfig) { c.Listen = "127.0.0.1" }},
		{"malformed-upstream", func(c *gatewayConfig) { c.UpstreamURL = "://" }},
		{"non-http-upstream", func(c *gatewayConfig) { c.UpstreamURL = "https://upstream/mcp" }},
		{"upstream-credentials", func(c *gatewayConfig) { c.UpstreamURL = "http://user@upstream/mcp" }},
		{"upstream-query", func(c *gatewayConfig) { c.UpstreamURL = "http://upstream/mcp?x=1" }},
		{"upstream-fragment", func(c *gatewayConfig) { c.UpstreamURL = "http://upstream/mcp#fragment" }},
		{"wrong-upstream-host", func(c *gatewayConfig) { c.UpstreamURL = "http://other/mcp" }},
		{"upstream-backslash", func(c *gatewayConfig) { c.UpstreamURL = "http://upstream/a\\b" }},
		{"upstream-newline", func(c *gatewayConfig) { c.UpstreamURL = "http://upstream/mcp\n" }},
		{"missing-socket", func(c *gatewayConfig) { c.UpstreamSocket = filepath.Join(dir, "missing.sock") }},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := config
			tc.mutate(&bad)
			badPath := saveJSON(t, dir, "invalid-"+strings.ReplaceAll(tc.name, "-", "_")+"-"+string(rune('a'+index))+".json", bad)
			if got, gotDuration, err := loadGateway(badPath); err != errConfig || gotDuration != 0 {
				t.Fatalf("invalid config accepted or wrong refusal: duration=%s err=%v config=%#v", gotDuration, err, got)
			}
		})
	}
}

func TestGatewaySetupRefusalsReleaseOnlyOwnedLock(t *testing.T) {
	for _, name := range []string{"preexisting-owner", "missing-state", "response-key-collision", "occupied-listener"} {
		t.Run(name, func(t *testing.T) {
			dir := privateDir(t)
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
				if err := exclusive(config.StateFile+".owner", []byte("other owner\n")); err != nil {
					t.Fatal(err)
				}
			case "missing-state":
				config.StateFile = filepath.Join(dir, "absent-state.json")
			case "response-key-collision":
				seed, err := readPrivate(config.ServerSeedFile, ed25519.SeedSize)
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
			configPath := saveJSON(t, dir, "gateway.json", config)
			err := gateway(context.Background(), configPath, nil)
			if err != errConfig {
				t.Fatalf("gateway setup refusal = %v, want %q", err, errConfig)
			}
			ownerPath := config.StateFile + ".owner"
			if name == "preexisting-owner" {
				owner, readErr := readPrivate(ownerPath, 64)
				if readErr != nil || string(owner) != "other owner\n" {
					t.Fatalf("preexisting owner changed: %q err=%v", owner, readErr)
				}
			} else if _, statErr := os.Lstat(ownerPath); !os.IsNotExist(statErr) {
				t.Fatalf("gateway did not release its owner lock: %v", statErr)
			}
		})
	}
}

func TestPrivateStorageRejectsMalformedBoundsAndRollsBackReservations(t *testing.T) {
	dir := privateDir(t)
	path := save(t, dir, "secret", []byte("0123456789"))
	if got, err := readPrivate(path, 10); err != nil || string(got) != "0123456789" {
		t.Fatalf("exact-bound private read = %q, %v", got, err)
	}
	if got, err := readPrivate(path, 9); err != errConfig || got != nil {
		t.Fatalf("oversized private read = %q, %v; want errConfig", got, err)
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"directory", dir},
		{"relative-path", "relative-secret"},
		{"unclean-path", dir + string(os.PathSeparator) + "sub" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "secret"},
	} {
		if got, err := readPrivate(tc.path, 100); err != errConfig || got != nil {
			t.Errorf("%s read = %q, %v; want errConfig", tc.name, got, err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path, 10); err != errConfig {
		t.Fatalf("group-readable secret refusal = %v, want errConfig", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secret-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(link, 10); err != errConfig {
		t.Fatalf("symlink read refusal = %v, want errConfig", err)
	}

	newPath := filepath.Join(dir, "reserved-before-conflict")
	existingPath := save(t, dir, "already-exists", []byte("preserve"))
	if err := createFiles([]string{newPath, existingPath}, [][]byte{[]byte("new"), []byte("overwrite")}); err != errConfig {
		t.Fatalf("existing target refusal = %v, want errConfig", err)
	}
	if _, err := os.Lstat(newPath); !os.IsNotExist(err) {
		t.Fatalf("partial reservation survived rollback: %v", err)
	}
	if got, err := readPrivate(existingPath, 32); err != nil || string(got) != "preserve" {
		t.Fatalf("existing target changed: %q err=%v", got, err)
	}
	invalidParentPath := filepath.Join(dir, "missing-parent", "second")
	if err := createFiles([]string{newPath, invalidParentPath}, [][]byte{[]byte("new"), []byte("second")}); err != errConfig {
		t.Fatalf("invalid-parent refusal = %v, want errConfig", err)
	}
	if _, err := os.Lstat(newPath); !os.IsNotExist(err) {
		t.Fatalf("reservation survived invalid-parent rollback: %v", err)
	}
	if err := createFiles([]string{newPath}, [][]byte{}); err != errConfig {
		t.Fatalf("path/content count mismatch = %v, want errConfig", err)
	}
}

func TestPrivateStorageConfigDecoderAndParentMode(t *testing.T) {
	dir := privateDir(t)
	type config struct {
		Value string `json:"value"`
	}
	valid := save(t, dir, "valid.json", []byte(`{"value":"accepted"}`))
	var got config
	if err := decodeConfig(valid, &got); err != nil || got.Value != "accepted" {
		t.Fatalf("valid private config = %#v, %v", got, err)
	}
	for index, raw := range []string{
		`null`, `[]`, `{"unknown":true}`, `{"value":"first"}{"value":"second"}`, `{"value":`,
	} {
		path := save(t, dir, "bad-"+string(rune('a'+index))+".json", []byte(raw))
		var decoded config
		if err := decodeConfig(path, &decoded); err != errConfig {
			t.Errorf("malformed config %q refusal = %v, want errConfig", raw, err)
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := privateParent(valid); err != errConfig {
		t.Fatalf("non-private parent refusal = %v, want errConfig", err)
	}
	if _, err := readPrivate(valid, 100); err != errConfig {
		t.Fatalf("read through non-private parent = %v, want errConfig", err)
	}
}

type storageUnixFileInfo struct {
	os.FileInfo
	sys any
}

func (info storageUnixFileInfo) Sys() any { return info.sys }

func TestUnixStorageOwnershipAndAncestorRefusals(t *testing.T) {
	dir := privateDir(t)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !owned(info) {
		t.Fatal("current effective user did not own its private test directory")
	}
	if owned(storageUnixFileInfo{FileInfo: info, sys: "not a Unix stat record"}) {
		t.Fatal("unknown ownership metadata was accepted")
	}
	foreignUID := uint32(0)
	if uint32(os.Geteuid()) == foreignUID {
		foreignUID = 1
	}
	if owned(storageUnixFileInfo{FileInfo: info, sys: &syscall.Stat_t{Uid: foreignUID}}) {
		t.Fatal("foreign owner was accepted")
	}
	if privateParent("relative/file") != errConfig {
		t.Fatal("relative private path was accepted")
	}
	unclean := dir + string(os.PathSeparator) + "child" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "secret"
	if privateParent(unclean) != errConfig {
		t.Fatal("unclean private path was accepted")
	}
	link := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if privateParent(filepath.Join(link, "secret")) != errConfig {
		t.Fatal("symlink parent was accepted")
	}
}

func TestGatewayUpstreamHandlerRejectsMalformedAndUnsafeExchange(t *testing.T) {
	identityContexts := make(chan context.Context, 1)
	clientPath, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityContexts <- context.WithoutCancel(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	connection, err := loadConnection(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := connection.post(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); err != nil || status != http.StatusOK {
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
			w.Header().Add("MCP-Protocol-Version", protocolVersion)
			w.Header().Add("MCP-Protocol-Version", protocolVersion)
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
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxBody+1))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("MCP-Protocol-Version", protocolVersion)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
	defer remote.Close()
	base := directTransport(time.Second)
	defer base.CloseIdleConnections()
	config := gatewayConfig{UpstreamURL: remote.URL + "/fixed%2Fpath"}
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
	headers.Set("MCP-Protocol-Version", protocolVersion)
	response := call(http.MethodPost, validBody, headers, identityContext)
	forwardedRequest, requestBody := lastForwarded()
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":1`) || forwardedRequest == nil || forwardedRequest.URL.RequestURI() != "/fixed%2Fpath" || string(requestBody) != validBody {
		t.Fatalf("forwarded positive control = %d %q request=%#v body=%q", response.Code, response.Body.String(), forwardedRequest, requestBody)
	}
	if forwardedRequest.Header.Get("X-Jack-Kid") != connection.signer.KID() || forwardedRequest.Header.Get("X-Jack-Name") != "alice" || forwardedRequest.Header.Get("X-Jack-Admin") != "false" {
		t.Fatalf("verified identity forwarding headers = %v", forwardedRequest.Header)
	}
	if response.Header().Get("MCP-Protocol-Version") != protocolVersion {
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
		if tc.mode == "oversize" && response.Body.Len() != maxBody+1 {
			t.Fatalf("bounded upstream read returned %d bytes, want its maxBody+1 sentinel", response.Body.Len())
		}
	}
	setMode("json")
	badURL := upstreamHandler(gatewayConfig{UpstreamURL: "http://%zz"}, base)
	badRequest := httptest.NewRequest(http.MethodPost, "http://gateway/mcp", strings.NewReader(validBody)).WithContext(identityContext)
	badResponse := httptest.NewRecorder()
	badURL.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadGateway {
		t.Fatalf("invalid upstream request target status = %d, want 502", badResponse.Code)
	}

	failedTransport := directTransport(time.Second)
	failedTransport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("controlled dial refusal")
	}
	defer failedTransport.CloseIdleConnections()
	transportHandler := upstreamHandler(gatewayConfig{UpstreamURL: remote.URL + "/fixed"}, failedTransport)
	transportRequest := httptest.NewRequest(http.MethodPost, "http://gateway/mcp", strings.NewReader(validBody)).WithContext(identityContext)
	transportResponse := httptest.NewRecorder()
	transportHandler.ServeHTTP(transportResponse, transportRequest)
	if transportResponse.Code != http.StatusBadGateway {
		t.Fatalf("upstream transport refusal status = %d, want 502", transportResponse.Code)
	}
}

func TestKeyAndEnrollmentRefusalsAreSpecificAndNoWrite(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "same-path")
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"unknown-role", func() error { return keygen("root", filepath.Join(dir, "secret"), filepath.Join(dir, "public")) }},
		{"same-keygen-path", func() error { return keygen("user", path, path) }},
		{"relative-keygen-path", func() error { return keygen("user", "relative-secret", filepath.Join(dir, "public")) }},
		{"same-bootstrap-path", func() error { return bootstrap(path, path) }},
		{"relative-bootstrap-path", func() error { return bootstrap("relative-state", filepath.Join(dir, "invite")) }},
	} {
		if err := tc.call(); err != errConfig {
			t.Errorf("%s refusal = %v, want errConfig", tc.name, err)
		}
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("preflight refusals created output: %v", err)
	}

	statePath := filepath.Join(dir, "locked-state")
	unlock, err := lockState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap(statePath, filepath.Join(dir, "locked-invite")); err != errConfig {
		t.Fatalf("preexisting owner refusal = %v, want errConfig", err)
	}
	unlock()
	if _, err := os.Lstat(filepath.Join(dir, "locked-invite")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap wrote invite despite owner conflict: %v", err)
	}

	var upstreamCalls atomic.Int32
	clientPath, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	validCode := save(t, dir, "valid-shaped-invite", []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	for _, tc := range []struct {
		name       string
		configPath string
		invitePath string
		nameArg    string
		want       error
	}{
		{"invalid-name-before-config", "not-read", validCode, "bad/name", errConfig},
		{"unreadable-config", filepath.Join(dir, "absent-config"), validCode, "alice", errConfig},
		{"missing-invite", clientPath, filepath.Join(dir, "absent-invite"), "alice", errConfig},
	} {
		if err := enroll(context.Background(), tc.configPath, tc.invitePath, tc.nameArg); err != tc.want {
			t.Errorf("%s refusal = %v, want %v", tc.name, err, tc.want)
		}
	}
	malformed := save(t, dir, "malformed-invite", []byte("not-base64"))
	if err := enroll(context.Background(), clientPath, malformed, "alice"); err != errConfig {
		t.Fatalf("malformed invite refusal = %v, want errConfig", err)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("invalid enrollment reached upstream %d times", upstreamCalls.Load())
	}
}

func TestEnrollSignedNativeRefusalsRemainDistinct(t *testing.T) {
	clientPath, _, _ := signedFixtureWithNative(t, http.NotFoundHandler(), server.NewNativeTools(server.NativeOptions{}))
	dir := filepath.Dir(clientPath)
	var config clientConfig
	if err := decodeConfig(clientPath, &config); err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKID := jack.KeyID(serverPublic)
	var requests atomic.Int32
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil {
			t.Error("401 fixture received no signed request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body := []byte(`{"error":"invite rejected"}`)
		ts := time.Now().Unix()
		signature := ed25519.Sign(serverPrivate, []byte(jack.ResponseSigningString(http.StatusUnauthorized, auth.Sig, serverKID, ts, body)))
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: serverKID, TS: ts, Sig: jack.EncodeBase64URL(signature)}))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(body)
	}))
	defer unauthorized.Close()
	config.Endpoint = unauthorized.URL + "/mcp"
	config.ServerPublicKey, config.ServerKID = jack.EncodeBase64URL(serverPublic), serverKID
	unauthorizedConfig := saveJSON(t, dir, "signed-401-client.json", config)
	code := save(t, dir, "unused-code", []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err := enroll(context.Background(), unauthorizedConfig, code, "new-user"); err == nil || err.Error() != "enroll rejected with HTTP 401; the invite may be invalid, expired or already used, or the key unknown" || requests.Load() != 1 {
		t.Fatalf("signed 401 enrollment refusal = %T %v requests=%d", err, err, requests.Load())
	}

	// The fixture identity is already registered, so native enrollment rejects
	// it with authenticated HTTP 409 before invite validation.
	err = enroll(context.Background(), clientPath, code, "another-user")
	var statusErr *verifiedStatusError
	if !errors.As(err, &statusErr) || statusErr.status != http.StatusConflict || err.Error() != "authenticated HTTP 409; no retry performed" {
		t.Fatalf("registered-key enrollment refusal = %T %v, want authenticated HTTP 409", err, err)
	}
}
func TestUnixProcessIORejectsInvalidDescriptorsWithoutClosingCaller(t *testing.T) {
	if _, err := interruptiblePipe(nil, true); err != errConfig {
		t.Fatalf("nil input refusal = %v, want errConfig", err)
	}
	if _, err := interruptiblePipe(nil, false); err != errConfig {
		t.Fatalf("nil output refusal = %v, want errConfig", err)
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if _, err := interruptiblePipe(regular, true); err != errConfig {
		t.Fatalf("regular descriptor refusal = %v, want errConfig", err)
	}
	if n, err := regular.Write([]byte("caller-still-owns-it")); err != nil || n != len("caller-still-owns-it") {
		t.Fatalf("failed preparation changed caller descriptor ownership: n=%d err=%v", n, err)
	}
	if err := regular.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := interruptiblePipe(regular, false); err != errConfig {
		t.Fatalf("closed descriptor refusal = %v, want errConfig", err)
	}
	input, peer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer peer.Close()
	if _, err := prepareProcessIO(input, regular); err != errConfig {
		t.Fatalf("invalid output descriptor refusal = %v, want errConfig", err)
	}
	if n, err := peer.Write([]byte("original pipe remains open")); err != nil || n != len("original pipe remains open") {
		t.Fatalf("failed output preparation damaged caller pipe: n=%d err=%v", n, err)
	}
	buf := make([]byte, len("original pipe remains open"))
	if n, err := io.ReadFull(input, buf); err != nil || string(buf) != "original pipe remains open" || n != len(buf) {
		t.Fatalf("failed output preparation changed caller pipe data: n=%d data=%q err=%v", n, buf, err)
	}
}

func TestGatewaySocketRequiresOwnedPrivateSocket(t *testing.T) {
	dir := privateDir(t)
	socket := gatewayCoverageSocket(t, dir)
	if err := socketOK(socket); err != nil {
		t.Fatalf("owned 0600 Unix socket refused: %v", err)
	}
	regular := save(t, dir, "regular", []byte("not a socket"))
	if err := socketOK(regular); err != errConfig {
		t.Fatalf("regular-file socket refusal = %v, want errConfig", err)
	}
	link := filepath.Join(dir, "socket-link")
	if err := os.Symlink(socket, link); err != nil {
		t.Fatal(err)
	}
	if err := socketOK(link); err != errConfig {
		t.Fatalf("symlink socket refusal = %v, want errConfig", err)
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	if err := socketOK(socket); err != errConfig {
		t.Fatalf("public socket refusal = %v, want errConfig", err)
	}
}
