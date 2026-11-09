package cli

import (
	"context"
	"crypto/ed25519"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

type gatewayConfig struct {
	Version        int    `json:"version"`
	Aud            string `json:"aud"`
	ServerSeedFile string `json:"server_seed_file"`
	StateFile      string `json:"state_file"`
	Listen         string `json:"listen"`
	UpstreamSocket string `json:"upstream_socket"`
	UpstreamURL    string `json:"upstream_url"`
	CallTimeoutMS  int    `json:"call_timeout_ms"`
	MaxConcurrent  int    `json:"max_concurrent"`
}

type enrollmentOnly struct {
	native    *server.Native
	serverKID string
}

func (n enrollmentOnly) Call(c *server.NativeCall) (server.NativeResult, *jack.Error) {
	if c.Tool != server.ToolEnroll || c.Kid == n.serverKID {
		return server.NativeResult{}, &jack.Error{HTTPStatus: 403, Code: jack.CodeOperationDenied, Message: "operation is not enabled"}
	}
	return n.native.Call(c)
}

type boundedState struct{ server.StateStore }

func (s boundedState) Update(update server.StateUpdate) error {
	return s.StateStore.Update(func(e *server.StateEdit) error {
		if err := update(e); err != nil {
			return err
		}
		if len(e.Keys()) > 1024 {
			return errConfig
		}
		return nil
	})
}

func socketOK(path string) error {
	if privateParent(path) != nil {
		return errConfig
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || !owned(info) {
		return errConfig
	}
	return nil
}

func loadGateway(path string) (gatewayConfig, time.Duration, error) {
	var c gatewayConfig
	if decodeConfig(path, &c) != nil || c.Version != 1 || c.Aud == "" || c.MaxConcurrent < 1 || c.MaxConcurrent > 64 {
		return c, 0, errConfig
	}
	d, err := callDuration(c.CallTimeoutMS)
	if err != nil {
		return c, 0, err
	}
	host, port, err := net.SplitHostPort(c.Listen)
	ip := net.ParseIP(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || p < 1 || p > 65535 {
		return c, 0, errConfig
	}
	u, err := url.Parse(c.UpstreamURL)
	if err != nil || u.Scheme != "http" || u.Host != "upstream" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Path == "" || strings.ContainsAny(c.UpstreamURL, "\r\n\\") {
		return c, 0, errConfig
	}
	if socketOK(c.UpstreamSocket) != nil {
		return c, 0, errConfig
	}
	return c, d, nil
}

func gateway(ctx context.Context, path string) error {
	c, timeout, err := loadGateway(path)
	if err != nil {
		return err
	}
	seed, err := readPrivate(c.ServerSeedFile, 32)
	if err != nil || len(seed) != 32 {
		return errConfig
	}
	defer clear(seed)
	unlock, err := lockState(c.StateFile)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := readPrivate(c.StateFile, maxBody); err != nil {
		return err
	}
	state, err := server.OpenFileState(c.StateFile)
	if err != nil || len(state.View().Keys) > 1024 || len(state.View().Invites) > 1024 {
		return errConfig
	}
	serverKey := ed25519.NewKeyFromSeed(seed)
	serverKID := jack.KeyID(serverKey.Public().(ed25519.PublicKey))
	for _, entry := range state.View().Keys {
		if entry.Kid == serverKID {
			return errConfig
		}
	}
	base := directTransport(timeout)
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(c.UpstreamSocket) != nil {
			return nil, errConfig
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", c.UpstreamSocket)
	}
	defer base.CloseIdleConnections()
	nonces := server.NewNonceStore()
	v, err := server.NewVerifier(server.Config{
		Aud: c.Aud, State: boundedState{state}, Nonces: nonces,
		Native: enrollmentOnly{native: server.NewNativeTools(server.NativeOptions{}), serverKID: serverKID},
	})
	if err != nil {
		return errConfig
	}
	h, err := server.NewHandler(server.HandlerConfig{
		Verifier: v, ServerKey: serverKey, MaxBodyBytes: maxBody, MaxResponseBytes: maxBody,
	}, upstreamHandler(c, base))
	if err != nil {
		return errConfig
	}
	var connections sync.WaitGroup
	slots := make(chan struct{}, c.MaxConcurrent)
	// A fixed global admission rate also bounds the SDK's in-memory nonce growth.
	var rateMu sync.Mutex
	var second int64
	var admitted int
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 503)
			return
		}
		rateMu.Lock()
		now := time.Now().Unix()
		if now != second {
			second, admitted = now, 0
		}
		admitted++
		allowed := admitted <= 64
		rateMu.Unlock()
		if !allowed {
			http.Error(w, "busy", 503)
			return
		}
		nonces.Purge(now)
		if nonces.Len() >= 4096 {
			http.Error(w, "busy", 503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(timeout))
		_ = controller.SetWriteDeadline(time.Now().Add(timeout))
		if !validProtocolVersion(r.Header) || unsupportedMetadata(r.Header) || len(r.Header.Values("Content-Encoding")) != 0 {
			http.Error(w, "unsupported metadata", 400)
			return
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errConfig
	}
	limited := &boundedListener{Listener: listener, slots: make(chan struct{}, c.MaxConcurrent*2), timeout: timeout}
	srv := &http.Server{
		Handler: outer, ReadHeaderTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
		IdleTimeout: timeout, MaxHeaderBytes: 16384, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				connections.Add(1)
			case http.StateClosed, http.StateHijacked:
				connections.Done()
			}
		},
	}
	srv.SetKeepAlivesEnabled(false)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(limited) }()
	select {
	case err = <-done:
		_ = srv.Close()
		connections.Wait()
		if err == http.ErrServerClosed {
			return nil
		}
		return errRemote
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), timeout)
		_ = srv.Shutdown(stop)
		cancel()
		_ = srv.Close()
		<-done
		connections.Wait()
		return nil
	}
}

func validProtocolVersion(h http.Header) bool {
	values := h.Values("MCP-Protocol-Version")
	return len(values) == 0 || (len(values) == 1 && values[0] == protocolVersion)
}

func upstreamHandler(c gatewayConfig, base *http.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(405)
			_, _ = io.WriteString(w, `{"error":{"code":"method_not_allowed","message":"no GET stream"}}`)
			return
		}
		id, ok := server.IdentityFromContext(r.Context())
		if !ok {
			w.WriteHeader(500)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		m, parseErr := object(body)
		if err != nil || len(body) > maxBody || parseErr != nil || text(m["method"]) == "notifications/cancelled" {
			w.WriteHeader(400)
			return
		}
		if !validProtocolVersion(r.Header) {
			w.WriteHeader(400)
			return
		}
		u, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.UpstreamURL, strings.NewReader(string(body)))
		if err != nil {
			w.WriteHeader(502)
			return
		}
		for _, name := range []string{"Accept", "Content-Type", "MCP-Protocol-Version"} {
			if values := r.Header.Values(name); len(values) != 0 {
				u.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
			}
		}
		u.Header.Set("X-Jack-Kid", id.Kid())
		u.Header.Set("X-Jack-Name", id.Name())
		u.Header.Set("X-Jack-Admin", strconv.FormatBool(id.Admin()))
		resp, err := (oneShot{base}).RoundTrip(u)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 || unsupportedMetadata(resp.Header) || len(resp.Header.Values("Content-Encoding")) != 0 {
			w.WriteHeader(502)
			return
		}
		ct := resp.Header.Get("Content-Type")
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]), "text/event-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			return
		}
		if len(resp.Header.Values("Content-Type")) > 1 {
			w.WriteHeader(502)
			return
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			w.WriteHeader(502)
			return
		}
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if values := resp.Header.Values("MCP-Protocol-Version"); len(values) != 0 {
			if len(values) != 1 || values[0] != protocolVersion {
				w.WriteHeader(502)
				return
			}
			w.Header().Set("MCP-Protocol-Version", values[0])
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
	})
}

type boundedListener struct {
	net.Listener
	slots   chan struct{}
	timeout time.Duration
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			_ = c.SetDeadline(time.Now().Add(l.timeout))
			return &countedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
