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
	"net/http/httptest"
	"os"
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

func unixDial(socket string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(socket) != nil {
			return nil, errConfig
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
}

func unixUpstream(t *testing.T, h http.Handler) string {
	t.Helper()
	d, err := os.MkdirTemp("", "jack-cli-")
	if err != nil {
		t.Fatal(err)
	}
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "mcp.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { _ = s.Serve(l); close(done) }()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Unix fixture server did not stop")
		}
	})
	return p
}

func TestGatewayFixedUnixHopAndSignedRefusals(t *testing.T) {
	requests := make(chan *http.Request, 10)
	bodies := make(chan []byte, 10)
	var mode atomic.Int32
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	base := directTransport(time.Second)
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(socket) != nil {
			return nil, errConfig
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	t.Cleanup(base.CloseIdleConnections)
	h := upstreamHandler(gatewayConfig{UpstreamSocket: socket, UpstreamURL: "http://upstream/fixed%2Fpath"}, base)
	path, cfg, _ := signedFixture(t, h)
	c, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(` {"jsonrpc":"2.0", "id":3,"method":"tools/list"} `)
	request := func(method string) (*http.Response, error) {
		r, _ := http.NewRequestWithContext(context.Background(), method, strings.Replace(cfg.Endpoint, "/mcp", "/caller/ignored?q=ignored", 1), bytes.NewReader(body))
		r.Host = "caller.invalid"
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("MCP-Protocol-Version", protocolVersion)
		r.Header.Add("X-Jack-Kid", "forged")
		r.Header.Add("X-Jack-Kid", "forged-again")
		r.Header.Add("X-Jack-Admin", "true")
		r.Header.Add("X-Jack-Admin", "true")
		r.Header.Set("Authorization", "Bearer not-forwarded")
		r.Header.Set("Cookie", "identity=not-forwarded")
		r.Header.Set("X-Forwarded-Host", "not-forwarded")
		network := directTransport(time.Second)
		defer network.CloseIdleConnections()
		return client.NewHTTPClient(client.NewTransport(oneShot{network}, cfg.Aud, c.signer, c.pin)).Do(r)
	}
	resp, err := request("POST")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(b, body) || !bytes.Equal(receiveTest(t, bodies), body) {
		t.Fatal("exact signed bytes changed")
	}
	r := receiveTest(t, requests)
	if r.URL.RequestURI() != "/fixed%2Fpath" || r.Host != "upstream" || r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("MCP-Protocol-Version") != protocolVersion {
		t.Fatal("caller selected routing or metadata changed")
	}
	if len(r.Header.Values("X-Jack-Kid")) != 1 || r.Header.Get("X-Jack-Kid") != c.signer.KID() || r.Header.Get("X-Jack-Name") != "alice" || r.Header.Get("X-Jack-Admin") != "false" || len(r.Header.Values("X-Jack-Admin")) != 1 {
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

func TestGatewayBootstrapEnrollNoNativeForward(t *testing.T) {
	testGatewayBootstrapEnrollNoNativeForward(t, nil)
}

func testGatewayBootstrapEnrollNoNativeForward(t *testing.T, configure func(*gatewayConfig)) {
	t.Helper()
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
	if configure != nil {
		configure(&cfg)
	}
	path := saveJSON(t, d, "gateway.json", cfg)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway(ctx, path) }()
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
	clientPath := saveJSON(t, d, "client.json", clientConfig{Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: save(t, d, "user.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000})
	code, err := readPrivate(invite, 43)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, err := readPrivate(state, maxBody)
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
	for _, versions := range [][]string{{"2026-07-28"}, {protocolVersion, protocolVersion}, {protocolVersion, "2026-07-28"}} {
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
		network := directTransport(time.Second)
		resp, err := (oneShot{network}).RoundTrip(r)
		if err != nil {
			network.CloseIdleConnections()
			cancel()
			t.Fatal("native version control failed to reach gateway")
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		network.CloseIdleConnections()
		cancel()
		afterState, stateErr := readPrivate(state, maxBody)
		if readErr != nil || stateErr != nil || resp.StatusCode != 400 || len(resp.Header.Values("Jack-Auth")) != 0 || !bytes.Equal(beforeState, afterState) {
			t.Fatal("invalid native version consumed invite or changed state")
		}
	}
	if err := enroll(context.Background(), clientPath, invite, "first-admin"); err != nil {
		t.Fatal(err)
	}
	if err := enroll(context.Background(), clientPath, invite, "again"); err == nil {
		t.Fatal("invite reused")
	}
	c, _ := loadConnection(clientPath)
	adminBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": server.ToolAdminInviteList}})
	if _, status, err := c.post(context.Background(), adminBody); err == nil || status != 403 {
		t.Fatal("excluded native admin enabled")
	}
	if upstreamCalls.Load() != 0 {
		t.Fatal("native enrollment/admin reached upstream")
	}
	if _, err := lockState(state); err == nil {
		t.Fatal("gateway owner lock missing")
	}
}

func TestProcessSignedResponseAndRequestTampering(t *testing.T) {
	var upstreamCalls atomic.Int32
	_, cfg, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, initializeReply)
	}))
	var mode atomic.Int32
	var proxyCalls atomic.Int32
	var fixtureError atomic.Bool
	base := directTransport(time.Second)
	defer base.CloseIdleConnections()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		selected := mode.Load()
		if selected == 4 {
			body = bytes.Replace(body, []byte(`"test"`), []byte(`"evil"`), 1)
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := (oneShot{base}).RoundTrip(req)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = append([]string(nil), v...)
		}
		w.Header().Del("Content-Length")
		status := resp.StatusCode
		switch selected {
		case 1:
			b = bytes.Replace(b, []byte("fixture"), []byte("tampered"), 1)
		case 2:
			status = http.StatusMethodNotAllowed
		case 3:
			auth, err := jack.ParseResponseAuth(resp.Header.Values("Jack-Auth"))
			if err != nil {
				fixtureError.Store(true)
				w.WriteHeader(500)
				return
			}
			sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
			if err != nil {
				fixtureError.Store(true)
				w.WriteHeader(500)
				return
			}
			sig[0] ^= 1
			auth.Sig = jack.EncodeBase64URL(sig)
			w.Header().Set("Jack-Auth", jack.FormatResponseAuth(auth))
		case 5, 6:
			w.Header().Del("Jack-Auth")
			status = http.StatusMethodNotAllowed
			if selected == 6 {
				status = http.StatusNotImplemented
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(b)
	}))
	defer proxy.Close()
	proxyConfig := cfg
	proxyConfig.Endpoint = proxy.URL + "/mcp"
	configPath := saveJSON(t, privateDir(t), "proxy-client.json", proxyConfig)
	for _, tc := range []struct {
		name string
		mode int32
	}{
		{"valid-baseline", 0},
		{"response-body", 1},
		{"response-status-to-405", 2},
		{"response-signature", 3},
		{"request-body", 4},
		{"unsigned-405", 5},
		{"unsigned-501", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			beforeUpstream := upstreamCalls.Load()
			beforeProxy := proxyCalls.Load()
			cmd, in, out, stderr := child(t, configPath)
			writeInput(t, in, initializeFrame+"\n")
			if tc.mode == 0 {
				line, err := out.ReadString('\n')
				if err != nil || line != initializeReply+"\n" {
					t.Fatal("positive network/process baseline failed")
				}
				_ = in.Close()
				rest, _ := io.ReadAll(out)
				if cmd.Wait() != nil || len(rest) != 0 || stderr.Len() != 0 {
					t.Fatal("positive baseline shutdown failed")
				}
			} else {
				stdout, _ := io.ReadAll(out)
				if cmd.Wait() == nil || len(stdout) != 0 || stderr.String() != "jack: remote call failed; no retry performed\n" {
					t.Fatal("tampering emitted bytes or was described as authenticated")
				}
			}
			wantUpstream := int32(1)
			if tc.mode == 4 {
				wantUpstream = 0
			}
			if fixtureError.Load() || upstreamCalls.Load()-beforeUpstream != wantUpstream || proxyCalls.Load()-beforeProxy != 1 {
				t.Fatal("fixture failed, request tamper reached upstream, or call retried")
			}
		})
	}
}
