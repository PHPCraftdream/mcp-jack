package gateway

import (
	"context"
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

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// Pre-auth admission bounds. The admission budget relation with
// gatewayconfig.MaxDurableWindow: rate*(2*W+1) must stay below capacity.
const (
	gatewayAdmissionRate = 64
	gatewayNonceCapacity = 4096
)

type boundedState struct{ server.AdmissionStateStore }

var _ server.AdmissionStateStore = boundedState{}

func (s boundedState) Update(update server.StateUpdate) error {
	return s.AdmissionStateStore.Update(func(e *server.StateEdit) error {
		if err := update(e); err != nil {
			return err
		}
		if len(e.Keys()) > 1024 || len(e.Invites()) > 1024 {
			return command.ErrConfig
		}
		return nil
	})
}

func socketOK(path string) error {
	if storage.PrivateParent(path) != nil {
		return command.ErrConfig
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || !storage.Owned(info) {
		return command.ErrConfig
	}
	return nil
}

func loadGateway(path string) (gatewayconfig.Config, time.Duration, error) {
	return loadGatewayWithProfile(path, "")
}

func loadGatewayWithProfile(path, override string) (gatewayconfig.Config, time.Duration, error) {
	if override != "" && override != "legacy" && override != "modern" && override != "both" {
		return gatewayconfig.Config{}, 0, command.ErrConfig
	}
	var c gatewayconfig.Config
	if storage.DecodeConfig(path, &c) != nil || c.Version != 1 || c.Aud == "" || c.MaxConcurrent < 1 || c.MaxConcurrent > 64 || c.DurableNonces.Validate(c.MaxConcurrent) != nil || (c.Profile != "" && c.Profile != "legacy" && c.Profile != "modern" && c.Profile != "both") {
		return c, 0, command.ErrConfig
	}
	d, err := command.CallDuration(c.CallTimeoutMS)
	if err != nil {
		return c, 0, err
	}
	if override != "" {
		c.Profile = override
	}
	if err := validateGatewayStreams(c.Streams); err != nil || (c.Streams != nil && c.Profile != "modern" && c.Profile != "both") {
		return c, 0, command.ErrConfig
	}
	host, port, err := net.SplitHostPort(c.Listen)
	ip := net.ParseIP(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || p < 1 || p > 65535 {
		return c, 0, command.ErrConfig
	}
	u, err := url.Parse(c.UpstreamURL)
	if err != nil || u.Scheme != "http" || u.Host != "upstream" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Path == "" || strings.ContainsAny(c.UpstreamURL, "\r\n\\") {
		return c, 0, command.ErrConfig
	}
	if socketOK(c.UpstreamSocket) != nil {
		return c, 0, command.ErrConfig
	}
	return c, d, nil
}

func validateGatewayStreams(stream *gatewayconfig.StreamConfig) error {
	if stream == nil {
		return nil
	}
	const maxStreamDurationMS = int64(time.Hour / time.Millisecond)
	if stream.FrameMaxBytes < 0 || stream.FrameMaxBytes > wire.MaxBody || (stream.FrameMaxBytes != 0 && stream.FrameMaxBytes < 1024) || stream.MaxConcurrentStreams < 0 || stream.MaxConcurrentStreams > 64 || stream.MaxStreamDurationMS < 0 || stream.MaxStreamDurationMS > maxStreamDurationMS || stream.HeartbeatMS < 0 || stream.HeartbeatMS > maxStreamDurationMS {
		return command.ErrConfig
	}
	return nil
}

// Run loads and validates config, acquires resources in a fixed order, serves until done, and releases in reverse order; deferred releases only replace a nil result.
func Run(ctx context.Context, path string, audit io.Writer) (result error) {
	return RunWithProfile(ctx, path, "", audit)
}

// RunWithProfile applies a validated CLI profile override after strict config decoding.
func RunWithProfile(ctx context.Context, path, profile string, audit io.Writer) (result error) {
	if profile != "" && profile != "legacy" && profile != "modern" && profile != "both" {
		return command.ErrConfig
	}
	if audit == nil {
		audit = io.Discard
	}
	c, timeout, err := loadGatewayWithProfile(path, profile)
	if err != nil {
		return err
	}
	if profile != "" && profile == "legacy" && c.Streams != nil {
		return command.ErrConfig
	}
	signing, err := selectGatewaySigning(c)
	if err != nil {
		return command.ErrConfig
	}
	defer func() {
		if err := signing.close(); err != nil && result == nil {
			result = command.ErrConfig
		}
	}()
	unlock, err := storage.LockState(c.StateFile)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := verifyGatewayState(c, signing)
	if err != nil {
		return err
	}
	base := dialGatewayTransport(c, timeout)
	defer base.CloseIdleConnections()
	nonces, closeNonces, h, err := buildGatewayHandler(c, signing, state, timeout, base, audit)
	if err != nil {
		return command.ErrConfig
	}
	defer func() {
		if err := closeNonces(); err != nil && result == nil {
			result = command.ErrConfig
		}
	}()
	return serveGateway(ctx, c, timeout, nonces, h)
}

// verifyGatewayState reads the locked state file and rejects key IDs that
// collide with the server's signing key IDs.
func verifyGatewayState(c gatewayconfig.Config, signing *gatewaySigning) (*server.FileState, error) {
	if _, err := storage.ReadPrivate(c.StateFile, wire.MaxBody); err != nil {
		return nil, err
	}
	state, err := server.OpenFileState(c.StateFile)
	if err != nil || len(state.View().Keys) > 1024 || len(state.View().Invites) > 1024 {
		return nil, command.ErrConfig
	}
	for _, entry := range state.View().Keys {
		if signing.serverKIDs[entry.Kid] {
			return nil, command.ErrConfig
		}
	}
	return state, nil
}

// dialGatewayTransport builds the unix-socket transport to the upstream,
// re-checking the socket on every dial.
func dialGatewayTransport(c gatewayconfig.Config, timeout time.Duration) *http.Transport {
	base := transport.DirectTransport(timeout)
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if socketOK(c.UpstreamSocket) != nil {
			return nil, command.ErrConfig
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", c.UpstreamSocket)
	}
	return base
}

// buildGatewayHandler assembles native policy, verifier, and MCP handler. It
// returns the active nonce store, its release function, and the handler.
func ptrStreamOptions(options server.StreamOptions) *server.StreamOptions { return &options }

func buildGatewayHandler(c gatewayconfig.Config, signing *gatewaySigning, state *server.FileState, timeout time.Duration, base *http.Transport, audit io.Writer) (*server.NonceStore, func() error, http.Handler, error) {
	policy := gatewayNative{
		native: server.NewNativeTools(server.NativeOptions{}), serverKID: signing.anchorKID,
		serverKIDs: signing.serverKIDs, adminEnabled: bool(c.NativeAdmin),
	}
	if len(c.WebhookKeys) != 0 || len(c.WebhookEgressIPRanges) != 0 {
		keys := make([]server.WebhookKey, len(c.WebhookKeys))
		for i, key := range c.WebhookKeys {
			keys[i] = server.WebhookKey{KID: key.KID, PublicKey: key.PublicKey}
		}
		webhookKeys, err := server.NewWebhookKeyTool(server.WebhookKeyConfig{
			Keys: keys, EgressIPRanges: append([]string(nil), c.WebhookEgressIPRanges...),
		})
		if err != nil {
			return nil, nil, nil, command.ErrConfig
		}
		policy.webhookKeys = webhookKeys
	}
	// Audit events are written as JSON lines to the process stderr; write errors are ignored.
	verification := server.Config{Aud: c.Aud, State: boundedState{state}, Native: policy, Audit: server.NewJSONLAuditSink(audit)}
	if policy.webhookKeys != nil {
		verification.WebhookKeys = policy
	}
	if signing.provider != nil {
		policy.serverKeys = signing.provider
		verification.Native = policy
		verification.ServerKeys = policy
	}
	closeNonces, err := selectGatewayNonces(c, &verification)
	if err != nil {
		return nil, nil, nil, command.ErrConfig
	}
	fail := func() (*server.NonceStore, func() error, http.Handler, error) {
		// Mirror the original unwind: the release runs before returning.
		_ = closeNonces()
		return nil, nil, nil, command.ErrConfig
	}
	nonces := verification.Nonces
	v, err := server.NewVerifier(verification)
	if err != nil {
		return fail()
	}
	handlerConfig := server.HandlerConfig{Verifier: v, ServerKey: signing.key, MaxBodyBytes: wire.MaxBody, MaxResponseBytes: wire.MaxBody}
	if c.Profile == "modern" || c.Profile == "both" {
		switch c.Profile {
		case "modern":
			handlerConfig.Profile = server.ProfileModern
		case "both":
			handlerConfig.Profile = server.ProfileBoth
		}
		stream := c.Streams
		if stream != nil {
			handlerConfig.Streams = &server.StreamOptions{
				FrameMaxBytes: stream.FrameMaxBytes, MaxConcurrentStreams: stream.MaxConcurrentStreams,
				MaxStreamDuration: time.Duration(stream.MaxStreamDurationMS) * time.Millisecond,
				Heartbeat:         time.Duration(stream.HeartbeatMS) * time.Millisecond,
			}
		} else {
			handlerConfig.Streams = ptrStreamOptions(server.DefaultStreamOptions())
		}
	} else if c.Streams != nil {
		return fail()
	}
	if signing.provider != nil {
		handlerConfig.ServerKey = nil
		handlerConfig.ResponseKeys = signing.provider
	}
	h, err := server.NewHandler(handlerConfig, upstreamHandler(c, base))
	if err != nil {
		return fail()
	}
	return nonces, closeNonces, h, nil
}

// gatewayAdmissionHandler builds the outer handler applying the concurrency
// slot, per-second admission, and nonce capacity limits before delegation.
func gatewayAdmissionHandler(c gatewayconfig.Config, timeout time.Duration, nonces *server.NonceStore, h http.Handler) http.Handler {
	slots := make(chan struct{}, c.MaxConcurrent)
	// General transport limit applies before auth; the backend enforces durable capacity.
	var rateMu sync.Mutex
	var second int64
	var admitted int
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		allowed := admitted <= gatewayAdmissionRate
		rateMu.Unlock()
		if !allowed {
			http.Error(w, "busy", 503)
			return
		}
		if nonces != nil {
			nonces.Purge(now)
			if nonces.Len() >= gatewayNonceCapacity {
				http.Error(w, "busy", 503)
				return
			}
		}
		requestTimeout := timeout
		streamRequest := (c.Profile == "modern" || c.Profile == "both") && acceptsS1(r.Header.Values("Jack-Accept"))
		if streamRequest {
			streamTimeout := gatewayStreamDuration(c.Streams)
			requestTimeout = streamTimeout + timeout
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(timeout))
		_ = controller.SetWriteDeadline(time.Now().Add(requestTimeout))
		if (c.Profile != "modern" && c.Profile != "both" && !validGatewayProtocolVersion(r.Header, c.Profile)) || (c.Profile != "modern" && c.Profile != "both" && transport.UnsupportedMetadata(r.Header)) || len(r.Header.Values("Content-Encoding")) != 0 {
			http.Error(w, "unsupported metadata", 400)
			return
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// serveGateway builds the admission-limited outer handler and runs the HTTP
// server until it fails or the context is cancelled.
func serveGateway(ctx context.Context, c gatewayconfig.Config, timeout time.Duration, nonces *server.NonceStore, h http.Handler) error {
	var connections sync.WaitGroup
	outer := gatewayAdmissionHandler(c, timeout, nonces, h)
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return command.ErrConfig
	}
	maxRequestLifetime := timeout
	if c.Profile == "modern" || c.Profile == "both" {
		maxRequestLifetime += gatewayStreamDuration(c.Streams)
	}
	limited := &boundedListener{Listener: listener, slots: make(chan struct{}, c.MaxConcurrent*2), timeout: maxRequestLifetime}
	srv := &http.Server{
		Handler: outer, ReadHeaderTimeout: timeout, ReadTimeout: timeout, WriteTimeout: maxRequestLifetime,
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
		return command.ErrRemote
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

func acceptsS1(values []string) bool {
	for _, line := range values {
		tokens, valid := parseAcceptLine(line)
		if !valid {
			continue
		}
		for _, token := range tokens {
			if token == "s1" {
				return true
			}
		}
	}
	return false
}

func parseAcceptLine(line string) ([]string, bool) {
	line = strings.Trim(line, " ")
	if line == "" {
		return nil, false
	}
	parts := strings.Split(line, ",")
	for i, part := range parts {
		token := strings.Trim(part, " ")
		if token == "" {
			return nil, false
		}
		for _, r := range token {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return nil, false
			}
		}
		parts[i] = token
	}
	return parts, true
}

func gatewayStreamDuration(stream *gatewayconfig.StreamConfig) time.Duration {
	if stream == nil || stream.MaxStreamDurationMS == 0 {
		return time.Hour
	}
	return time.Duration(stream.MaxStreamDurationMS) * time.Millisecond
}

func validGatewayProtocolVersion(h http.Header, profile string) bool {
	if profile == "" || profile == "legacy" {
		values := h.Values("MCP-Protocol-Version")
		return len(values) == 0 || (len(values) == 1 && values[0] == wire.ProtocolVersion)
	}
	return validProtocolVersion(h)
}

// validUpstreamProtocolVersion checks an optional response version without
// widening legacy's historical exact-version contract. Modern profiles accept
// the modern date range; both also allow the two supported legacy versions.
func validUpstreamProtocolVersion(values []string, profile string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	value := values[0]
	if profile == "" || profile == "legacy" {
		return value == wire.ProtocolVersion
	}
	if profile == "both" && (value == wire.ProtocolVersion || value == "2025-06-18") {
		return true
	}
	return validModernVersion(value)
}

func validProtocolVersion(h http.Header) bool {
	values := h.Values("MCP-Protocol-Version")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	value := values[0]
	if value == wire.ProtocolVersion || value == "2025-06-18" {
		return true
	}
	return validModernVersion(value)
}

func validModernVersion(value string) bool {
	if len(value) != 10 || value[4] != '-' || value[7] != '-' {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value {
		return false
	}
	return value >= "2026-07-28"
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func upstreamHandler(c gatewayconfig.Config, base *http.Transport) http.Handler {
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
		body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBody+1))
		m, parseErr := wire.Object(body)
		if err != nil || len(body) > wire.MaxBody || parseErr != nil || wire.Text(m["method"]) == "notifications/cancelled" {
			w.WriteHeader(400)
			return
		}
		if !validGatewayProtocolVersion(r.Header, c.Profile) {
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
		if c.Profile == "modern" || c.Profile == "both" {
			for _, name := range []string{"Jack-Accept", "Mcp-Method", "Mcp-Name"} {
				if values := r.Header.Values(name); len(values) != 0 {
					u.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
				}
			}
			const paramPrefix = "Mcp-Param-"
			for name, values := range r.Header {
				if len(name) <= len(paramPrefix) || !strings.EqualFold(name[:len(paramPrefix)], paramPrefix) || !validHeaderName(name) {
					continue
				}
				canonicalName := http.CanonicalHeaderKey(name)
				u.Header[canonicalName] = append(u.Header[canonicalName], values...)
			}
		}
		u.Header.Set("X-Jack-Kid", id.Kid())
		u.Header.Set("X-Jack-Name", id.Name())
		u.Header.Set("X-Jack-Admin", strconv.FormatBool(id.Admin()))
		resp, err := (transport.NewOneShot(base)).RoundTrip(u)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 || transport.UnsupportedMetadata(resp.Header) || len(resp.Header.Values("Content-Encoding")) != 0 {
			w.WriteHeader(502)
			return
		}
		ct := resp.Header.Get("Content-Type")
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]), "text/event-stream") {
			if c.Profile != "modern" && c.Profile != "both" || !acceptsS1(r.Header.Values("Jack-Accept")) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				return
			}
			w.Header().Set("Content-Type", ct)
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		if len(resp.Header.Values("Content-Type")) > 1 {
			w.WriteHeader(502)
			return
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxBody+1))
		if err != nil {
			w.WriteHeader(502)
			return
		}
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if values := resp.Header.Values("MCP-Protocol-Version"); len(values) != 0 {
			if !validUpstreamProtocolVersion(values, c.Profile) {
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
