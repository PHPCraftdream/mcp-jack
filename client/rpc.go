// Package client is the mcp-jack client SDK.
//
// Every outgoing request is signed with an Ed25519 signer (Signer) and every
// response is verified against the pinned server public key before its body is
// returned (spec 01 sections 4 and 5). The package speaks the protocol-native
// jack.* tools for user management, including enrollment and key rotation
// (spec 03 sections 3.1-3.3).
//
// # Generic tool calls
//
// Client.CallTool performs one signed, response-verified tools/call for any
// tool name and decodes the verified structuredContent into out (a pointer
// given to json.Unmarshal; nil discards the payload, but a result without
// structuredContent is still an error). structuredContent is the only result
// model, and there is no streaming support.
//
// Config.Era selects the request era of CallTool and Call (spec 04 section 6): the
// EraLegacy zero value sends the 0.1.x bytes through the legacy single-request
// helper, EraModern uses the same tools/list + x-mcp-header projection and C10
// resync as CallModernTool, and EraAuto probes the modern era first, runs the
// legacy initialize handshake once on a verified legacy signal and falls back
// to the legacy request, and settles the client era from the verified answer.
// Call sends a raw arbitrary JSON-RPC method with object params and returns the
// exact verified response bytes, adding modern mirrors/_meta without tool schema
// projection.
// The era is cached per client (one origin); only a verified response selects
// it, and ResetEra re-probes.
//
//	var res struct {
//		OK bool `json:"ok"`
//	}
//	err := c.CallTool(ctx, "svc.restart", map[string]any{"name": "web"}, &res)
//	// raw, err := c.Call(ctx, "resources/read", map[string]any{"uri": "file://x"})
//	// raw contains the exact verified JSON-RPC response body.
//
// # Destination policy
//
// Spec 01 section 1 requires HTTPS for non-loopback connections. The raw
// destination URL string is checked (docs/design/interop.md section 9) by
// NewClient, by profile loading and validation, and by every Transport
// request before signing: https is accepted for any host, http only for a
// literal canonical 127.x.y.z or [::1]; localhost aliases, userinfo and
// percent escapes in the authority (zone IDs included), and backslashes are
// refused; percent-encoded path/query is accepted and signed as given.
// Nothing is resolved. SDK-built HTTP clients never follow redirects and a
// 301, 302, 303, 307 or 308 answer to a signed request is refused before
// verification (ErrRedirectRefused); its Location is never surfaced. This is
// a no-follow/no-downgrade guard, not TLS enforcement. Other 3xx statuses
// (e.g. a signed 304) are verified normally.
//
// A caller-supplied http.Client or base http.RoundTripper (Config.HTTP,
// Transport.Base) is outside the SDK's control: it must use TLS for https
// URLs, connect to exactly the URL it is given and not follow redirects. The
// SDK cannot police it; the policy is applied before a request reaches it.
// Signing and response verification are mandatory regardless: NewClient always
// wraps Config.HTTP's base round tripper in its own signing/verifying
// Transport (a prewrapped *Transport is collapsed, never mutated).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client/internal/modern"
	"github.com/PHPCraftdream/mcp-jack/client/internal/urlpolicy"
)

// Era selects the request era of the client (spec 04 section 6).
type Era string

const (
	// EraLegacy sends 2025-11-25/2025-06-18 requests: no _meta and no mirror
	// headers. It is the zero value and byte-identical to 0.1.x.
	EraLegacy Era = "legacy"
	// EraModern sends MCP 2026-07-28 requests: params._meta plus the
	// MCP-Protocol-Version, Mcp-Method and Mcp-Name mirror headers (C1/C2).
	EraModern Era = "modern"
	// EraAuto tries the modern era first and falls back to legacy once when a
	// verified response proves a legacy server (C9).
	EraAuto Era = "auto"
)

// The legacy-era protocol versions the client implements (spec 04 section 6).
// An EraAuto client falls back to legacyProtocolVersion and retries a -32022
// with the first version of the -32022 supported list that it also implements.
const (
	// legacyProtocolVersion is the current legacy-era protocol version.
	legacyProtocolVersion = "2025-11-25"
	// legacyProtocolVersionOld is the previous legacy-era protocol version,
	// kept implemented for older servers.
	legacyProtocolVersionOld = "2025-06-18"
)

// Config carries everything NewClient needs to reach and trust one server.
type Config struct {
	// BaseURL is the absolute MCP endpoint. It must satisfy the client URL
	// policy (docs/design/interop.md section 9), checked on the raw string:
	// https for any host; http only for a literal canonical 127.x.y.z or
	// [::1] (no localhost aliases); no userinfo or percent escapes in the
	// authority (zone IDs included), no backslashes or non-ASCII/control
	// bytes; percent-encoded path/query is accepted and signed as given. Nothing is resolved or rewritten.
	BaseURL string
	// Aud is the audience bound into the signing string.
	Aud string
	// Signer is the client's Ed25519 signer.
	Signer Signer
	// ServerKey is the pinned 32-byte raw server public key.
	ServerKey []byte
	// HTTP is an optional caller-supplied client that supplies the timeout,
	// Jar, base RoundTripper and other ordinary options. The SDK ALWAYS wraps
	// it in its own signing/verifying *Transport built from Aud, Signer and
	// ServerKey, so requests are always signed and responses always verified.
	// Neither the caller's http.Client nor any caller *Transport is mutated:
	// the Client uses a shallow copy of the http.Client and one freshly
	// allocated Transport. A nil HTTP.Transport means http.DefaultTransport; an
	// opaque RoundTripper becomes the Base; a prewrapped *Transport (possibly
	// nested through Base) is collapsed to a single new Transport over its
	// innermost non-*Transport Base, and its Aud, Signer and ServerKey are
	// silently overridden by the Config values. A cyclic chain, a nil *Transport
	// in the chain or an excessively deep chain makes NewClient fail.
	// Now, Nonce and Window: the Config field wins when set; otherwise the
	// value is inherited from the prewrapped *Transport chain, outermost
	// non-zero first; otherwise the defaults apply.
	// Redirects are never followed: the copy always uses a no-follow
	// CheckRedirect even if the caller's was permissive, and a
	// 301/302/303/307/308 answer is refused with ErrRedirectRefused (a
	// no-follow guard, not TLS enforcement).
	// An opaque base RoundTripper must use TLS for https URLs, connect to
	// exactly the URL it is given, not follow redirects, and perform exactly
	// one round trip per request; the SDK cannot police that. In particular a
	// *Transport hidden inside an opaque wrapper is not detected and would
	// sign twice. NewClient checks BaseURL once at construction and the
	// *Transport re-checks every request.
	HTTP *http.Client
	// Now overrides the signing/verification clock; it is also the clock used
	// for rotation proof timestamps. nil inherits, then defaults to time.Now.
	Now func() time.Time
	// Nonce overrides the nonce source; nil inherits, then RandomNonce.
	Nonce NonceSource
	// Window overrides the response timestamp tolerance; <= 0 inherits, then
	// DefaultWindow.
	Window time.Duration
	// The era is the request era of CallTool and Call (spec 04 section 6). The zero value
	// ("" and EraLegacy) sends legacy-era requests, EraModern sends
	// 2026-07-28 requests with params._meta and the mirror headers, and
	// EraAuto probes modern first and settles per C9. No other value is
	// accepted.
	Era Era
}

// Client performs signed, response-verified MCP tool calls over JSON-RPC.
type Client struct {
	base      *url.URL
	aud       string
	signer    Signer
	serverKey []byte
	hc        *http.Client
	now       func() time.Time
	nonce     NonceSource
	window    time.Duration

	mu     sync.Mutex
	nextID int64
	// mode is the configured era of CallTool (never ""): the era an EraAuto
	// client probes first and the era an explicit configuration keeps. mu
	// guards both fields.
	mode Era
	// settled is the era a verified response selected on this client, or ""
	// when the era is not settled yet. The era is cached per client (one
	// origin), and only a verified response may set it.
	settled Era
	// negotiated is the legacy protocol version the initialize handshake
	// negotiated and sessionID the Mcp-Session-Id the server assigned. They
	// are cached with the era state and cleared by ResetEra; both are empty
	// for an explicit legacy client that never ran the handshake, so its
	// requests stay the 0.1.x bytes. mu guards both.
	negotiated string
	sessionID  string
	// recoveries holds the in-flight legacy session recovery per rejected
	// session id. Concurrent 404s for the same session share one handshake
	// instead of racing to install and invalidate sessions. mu guards it.
	recoveries map[string]*legacyRecovery
}

// audHasControl reports whether aud contains a byte below 0x20 or the byte
// 0x7f (spec 01 section 3.1 aud rules).
func audHasControl(aud string) bool {
	for i := 0; i < len(aud); i++ {
		if aud[i] < 0x20 || aud[i] == 0x7f {
			return true
		}
	}
	return false
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg Config) (*Client, error) {
	era := cfg.Era
	switch era {
	case "":
		// The zero value is the legacy era.
		era = EraLegacy
	case EraLegacy, EraModern, EraAuto:
	default:
		return nil, fmt.Errorf("jack client: era must be legacy, modern or auto")
	}
	if err := urlpolicy.CheckDestination(cfg.BaseURL); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("jack client: base url must be an absolute http/https URL with a host")
	}
	if cfg.Aud == "" {
		return nil, fmt.Errorf("jack client: aud must be non-empty")
	}
	if audHasControl(cfg.Aud) {
		return nil, fmt.Errorf("jack client: aud must not contain control characters")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("jack client: signer must be non-nil")
	}
	if len(cfg.ServerKey) != 32 {
		return nil, fmt.Errorf("jack client: server key must be exactly 32 bytes, got %d", len(cfg.ServerKey))
	}
	if err := jack.ValidatePublicKey(cfg.ServerKey); err != nil {
		// Local validation never becomes an HTTP response: zero the
		// validator's wire admission status (400) per the Error.HTTPStatus
		// contract, matching VerifyResponse's client-side remap.
		var jErr *jack.Error
		if errors.As(err, &jErr) {
			return nil, &jack.Error{HTTPStatus: 0, Code: jErr.Code, Message: jErr.Message}
		}
		return nil, err
	}
	hc, tn, err := newSecuredHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	now := tn.now
	if now == nil {
		now = time.Now
	}
	nonce := tn.nonce
	if nonce == nil {
		nonce = RandomNonce
	}
	window := tn.window
	if window <= 0 {
		window = DefaultWindow
	}
	return &Client{
		base:      u,
		aud:       cfg.Aud,
		signer:    cfg.Signer,
		serverKey: cfg.ServerKey,
		hc:        hc,
		now:       now,
		nonce:     nonce,
		window:    window,
		nextID:    1,
		mode:      era,
	}, nil
}

const maxTransportChain = 16

// tuning is the effective Now/Nonce/Window; zero values mean the defaults.
type tuning struct {
	now    func() time.Time
	nonce  NonceSource
	window time.Duration
}

// newSecuredHTTPClient builds the client NewClient uses: a shallow copy of
// cfg.HTTP (or a fresh client) whose Transport is exactly one new SDK
// *Transport, plus the effective tuning shared with the Client.
func newSecuredHTTPClient(cfg Config) (*http.Client, tuning, error) {
	tn := tuning{now: cfg.Now, nonce: cfg.Nonce, window: cfg.Window}
	var cp http.Client
	var rt http.RoundTripper
	if cfg.HTTP != nil {
		cp = *cfg.HTTP
		rt = cfg.HTTP.Transport
	}
	visited := make(map[*Transport]struct{})
	var base http.RoundTripper
	for depth := 0; ; depth++ {
		t, ok := rt.(*Transport)
		if !ok {
			base = rt
			break
		}
		if t == nil {
			return nil, tuning{}, fmt.Errorf("jack client: http transport chain contains a nil *Transport")
		}
		if _, seen := visited[t]; seen {
			return nil, tuning{}, fmt.Errorf("jack client: http transport chain is cyclic")
		}
		if depth >= maxTransportChain {
			return nil, tuning{}, fmt.Errorf("jack client: http transport chain deeper than %d", maxTransportChain)
		}
		visited[t] = struct{}{}
		if tn.now == nil {
			tn.now = t.Now
		}
		if tn.nonce == nil {
			tn.nonce = t.Nonce
		}
		if tn.window <= 0 {
			tn.window = t.Window
		}
		rt = t.Base
	}
	tr := NewTransport(base, cfg.Aud, cfg.Signer, cfg.ServerKey)
	tr.Now = tn.now
	tr.Nonce = tn.nonce
	tr.Window = tn.window
	cp.Transport = tr
	cp.CheckRedirect = noFollowRedirects
	return &cp, tn, nil
}

// jsonrpcRequest is a JSON-RPC 2.0 request; field order jsonrpc,id,method,params
// matches the wire order, params holds name then arguments.
type jsonrpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int64         `json:"id"`
	Method  string        `json:"method"`
	Params  jsonrpcParams `json:"params"`
}

type jsonrpcParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// jsonrpcModernRequest is the 2026-07-28 tools/call request: params carries
// the C1 _meta object. Its field order is not part of any wire contract.
type jsonrpcModernRequest struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      int64               `json:"id"`
	Method  string              `json:"method"`
	Params  jsonrpcModernParams `json:"params"`
}

// jsonrpcModernParams is name, arguments and _meta in the modern era (C1).
type jsonrpcModernParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      map[string]any  `json:"_meta"`
}

// jsonrpcResponse is the subset of the MCP JSON-RPC result/error shapes the
// client needs; structuredContent is the data contract (spec 02).
type jsonrpcResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int64          `json:"id"`
	Result  *jsonrpcResult `json:"result"`
	Error   *jsonrpcError  `json:"error"`
}

type jsonrpcResult struct {
	Content           []jsonrpcContent `json:"content"`
	IsError           bool             `json:"isError"`
	StructuredContent json.RawMessage  `json:"structuredContent"`
}

type jsonrpcContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type jsonrpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// modernClientInfo is the io.modelcontextprotocol/clientInfo object sent with
// every modern-era request (C1).
func modernClientInfo() map[string]any {
	return map[string]any{"name": "mcp-jack", "version": "0.1.0"}
}

// marshalCallArguments renders arguments as the raw JSON of params.arguments;
// nil sends "{}".
func marshalCallArguments(arguments any) ([]byte, error) {
	if arguments == nil {
		return []byte("{}"), nil
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, fmt.Errorf("jack client: marshal arguments: %w", err)
	}
	return raw, nil
}

// nextRequestID reserves and returns the next JSON-RPC request id.
func (c *Client) nextRequestID() int64 {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()
	return id
}

// currentEra returns the era CallTool uses: the era a verified response
// settled on, else the configured mode. The era is cached per client, which
// serves exactly one origin.
func (c *Client) currentEra() Era {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.settled != "" {
		return c.settled
	}
	if c.mode == "" {
		return EraLegacy
	}
	return c.mode
}

// CurrentEra reports the era selected by a verified response, or the configured
// mode while an EraAuto client has not settled yet. It is safe for concurrent use.
func (c *Client) CurrentEra() Era { return c.currentEra() }

// setEra records the era a verified response selected. It is the only way the
// settled era changes.
func (c *Client) setEra(era Era) {
	c.mu.Lock()
	c.settled = era
	c.mu.Unlock()
}

// legacyState returns the negotiated legacy protocol version and the session id
// the server assigned; either may be empty.
func (c *Client) legacyState() (negotiated, sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.negotiated, c.sessionID
}

// ResetEra clears the era an EraAuto client settled on, together with the
// negotiated legacy version and session id, so the next CallTool probes the
// modern era again and a later fallback starts a fresh legacy session. It is
// the explicit re-probe path of spec 04 section 6 C9; an explicit EraLegacy or
// EraModern configuration keeps that configured era.
func (c *Client) ResetEra() {
	c.mu.Lock()
	c.settled = ""
	c.negotiated = ""
	c.sessionID = ""
	c.mu.Unlock()
}

// implementedVersions lists the protocol versions this client speaks, modern
// first: it is the client side of the C9 -32022 supported-version overlap.
func (c *Client) implementedVersions() []string {
	return []string{modern.ModernMin, legacyProtocolVersion, legacyProtocolVersionOld}
}

// buildLegacyCallBody marshals the legacy-era tools/call request. The
// jsonrpcRequest/jsonrpcParams structs keep the 0.1.x wire bytes: field order
// jsonrpc,id,method,params and params name then arguments.
func buildLegacyCallBody(id int64, tool string, args []byte) ([]byte, error) {
	return json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  jsonrpcParams{Name: tool, Arguments: args},
	})
}

// buildModernCallBody marshals the 2026-07-28 tools/call request: params._meta
// from BuildRequestMirrors (C1) and its mirror headers in emit order. The
// returned slice is the C2 order; Go's HTTP stack stores headers in a map, so
// the wire order is not guaranteed.
func buildModernCallBody(id int64, tool string, args []byte, version string) ([]byte, []modern.Header, error) {
	rm, err := modern.BuildRequestMirrors(version, "tools/call", map[string]any{
		"name":      tool,
		"arguments": json.RawMessage(args),
	}, modernClientInfo())
	if err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(jsonrpcModernRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params: jsonrpcModernParams{
			Name:      tool,
			Arguments: json.RawMessage(args),
			Meta:      rm.Meta,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return body, rm.Headers, nil
}

// roundTrip performs one signed POST of body: it sets Content-Type and then
// adds each extra header, and returns the verified status, the response header
// and the verified body. The legacy handshake reads the Mcp-Session-Id the
// server assigns from the response header. HTTP header order is not preserved:
// net/http stores them in a map, so wire header order and canonical spelling
// are not guaranteed; the C2 order is the order of the modern.Header slice.
// Transport and verification errors, redirects included, are returned
// unchanged.
func (c *Client) roundTrip(ctx context.Context, signer Signer, body []byte, headers []modern.Header) (int, http.Header, []byte, error) {
	httpReq, err := http.NewRequestWithContext(WithRequestSigner(ctx, signer), http.MethodPost, c.base.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for _, h := range headers {
		httpReq.Header.Set(h.Name, h.Value)
	}

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		// Transport errors (refused streams, unauthenticated 401s, failed
		// verification) pass through unchanged for errors.Is / errors.As.
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if isRedirectStatus(resp.StatusCode) {
		return 0, nil, nil, &RedirectRefusedError{Status: resp.StatusCode}
	}

	raw, err := readCapped(resp.Body, maxBodyBytes)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("jack client: reading response body: %w", err)
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// decodeVerifiedCall turns one verified answer into out: a non-2xx status is
// an *HTTPError built by parseErrorBody, anything else is decoded by
// decodeCallResponse.
func decodeVerifiedCall(status int, raw []byte, out any) error {
	if status < 200 || status > 299 {
		code, message := parseErrorBody(raw)
		return &HTTPError{Status: status, Code: code, Message: message}
	}
	return decodeCallResponse(raw, out)
}

// decodeCallResponse decodes a verified 2xx JSON-RPC tools/call answer into out
// (which may be nil when the caller ignores the payload).
func decodeCallResponse(raw []byte, out any) error {
	var wire jsonrpcResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return fmt.Errorf("jack client: decoding json-rpc response: %w", err)
	}
	if wire.Error != nil {
		return &RPCError{Code: wire.Error.Code, Message: wire.Error.Message, Data: wire.Error.Data}
	}
	if wire.Result == nil {
		return fmt.Errorf("jack client: json-rpc response has neither result nor error")
	}
	if wire.Result.IsError {
		message := ""
		for _, content := range wire.Result.Content {
			if content.Text != "" {
				message = content.Text
				break
			}
		}
		return &ToolError{Message: message, Structured: wire.Result.StructuredContent}
	}
	if len(wire.Result.StructuredContent) == 0 {
		return fmt.Errorf("jack client: missing structuredContent")
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(wire.Result.StructuredContent, out)
}

// call performs one signed, verified legacy-era tool call and decodes
// structuredContent into out (which may be nil when the caller ignores the
// payload). The native helpers use it unchanged.
func (c *Client) call(ctx context.Context, signer Signer, tool string, arguments any, out any) error {
	if signer == nil {
		signer = c.signer
	}
	args, err := marshalCallArguments(arguments)
	if err != nil {
		return err
	}
	return c.callWithArgs(ctx, signer, tool, args, out)
}

// callWithArgs performs one signed, verified legacy-era tool call whose
// params.arguments are already marshalled, and decodes structuredContent into
// out. It is the shared tail of call and of the C9 legacy fallback: the same
// request bytes and error behaviour, plus the unsigned MCP-Protocol-Version and
// Mcp-Session-Id headers once the legacy handshake negotiated a session.
//
// A 404 for a known session id means the session is gone (2025-11-25
// transport). When the 404 answers the session that is still current, the
// legacy session is recovered through recoverLegacySession, which runs at most
// one handshake per rejected session id: concurrent 404s for the same session
// wait for the single in-flight handshake instead of each starting one, so no
// handshake can clear or overwrite a session a newer one installed. The
// operation itself is never replayed: the 404 is returned to the caller. A
// failed recovery handshake is returned as the call's error. A 404 for a
// session that was replaced while the request was in flight changes nothing.
func (c *Client) callWithArgs(ctx context.Context, signer Signer, tool string, args []byte, out any) error {
	reqBody, err := buildLegacyCallBody(c.nextRequestID(), tool, args)
	if err != nil {
		return err
	}
	negotiated, sentSessionID := c.legacyState()
	status, _, raw, err := c.roundTrip(ctx, signer, reqBody, legacySessionHeaders(negotiated, sentSessionID))
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		version := negotiated
		if version == "" {
			version = legacyProtocolVersion
		}
		if herr := c.recoverLegacySession(ctx, signer, sentSessionID, version); herr != nil {
			return fmt.Errorf("jack client: legacy session recovery: %w", herr)
		}
	}
	return decodeVerifiedCall(status, raw, out)
}

// probeEra sends the modern server/discover request at version: it is the
// deterministic C9 probe because legacy servers do not implement it. The
// request carries only params._meta and the C2 mirrors. Only a verified
// response is returned.
func (c *Client) probeEra(ctx context.Context, signer Signer, version string) (int, []byte, error) {
	rm, err := modern.BuildRequestMirrors(version, "server/discover", nil, modernClientInfo())
	if err != nil {
		return 0, nil, err
	}
	body, err := marshalModernWireRequest(c.nextRequestID(), "server/discover", map[string]any{"_meta": rm.Meta})
	if err != nil {
		return 0, nil, err
	}
	status, _, raw, err := c.roundTrip(ctx, signer, body, rm.Headers)
	return status, raw, err
}

// callAuto implements EraAuto: the first modern request is the deterministic
// C9 server/discover probe, never the user operation. finishAuto decides from
// the verified answer whether to stay modern, fall back to legacy once
// (initialize plus the operation), retry once with a mutually implemented
// version, or fail normally.
func (c *Client) callAuto(ctx context.Context, signer Signer, tool string, args []byte, out any) error {
	if signer == nil {
		signer = c.signer
	}
	status, raw, err := c.probeEra(ctx, signer, modern.ModernMin)
	if err != nil {
		// A transport or verification error proves no era and is returned
		// unchanged.
		return err
	}
	return c.finishAuto(ctx, signer, modern.ModernMin, status, raw, tool, args, out)
}

// finishAuto applies the C9 decision to the verified probe answer at attempted
// and runs the operation in the era it selects.
func (c *Client) finishAuto(ctx context.Context, signer Signer, attempted string, status int, raw []byte, tool string, args []byte, out any) error {
	if status >= 200 && status <= 299 {
		c.setEra(EraModern)
		return c.runModernOperation(ctx, signer, attempted, tool, args, out)
	}
	// roundTrip verifies every response, so only a verified response reaches
	// this point and the decision may select an era.
	decision := modern.DetectEraAttempt(status, true, raw, c.implementedVersions(), attempted)
	switch decision.Action {
	case modern.ActionStayModern:
		c.setEra(EraModern)
		return c.runModernOperation(ctx, signer, attempted, tool, args, out)
	case modern.ActionFallbackInitialize:
		return c.legacyFallback(ctx, signer, legacyProtocolVersion, tool, args, out)
	case modern.ActionRetryWithSupported:
		if len(decision.Supported) > 0 {
			v := decision.Supported[0]
			if v == modern.ModernMin {
				// Probe the mutually implemented modern version once: only
				// that verified answer may select (or unselect) the era.
				status, raw, err := c.probeEra(ctx, signer, v)
				if err != nil {
					return err
				}
				retry := modern.DetectEraAttempt(status, true, raw, c.implementedVersions(), v)
				if (status >= 200 && status <= 299) || retry.Action == modern.ActionStayModern {
					c.setEra(EraModern)
					return c.runModernOperation(ctx, signer, v, tool, args, out)
				}
				if retry.Action == modern.ActionFallbackInitialize {
					return c.legacyFallback(ctx, signer, legacyProtocolVersion, tool, args, out)
				}
				// No further retry: the second answer is the ordinary error.
				return decodeVerifiedCall(status, raw, out)
			}
			return c.legacyFallback(ctx, signer, v, tool, args, out)
		}
	}
	// ActionAbort and ActionRetryWithSupported with no usable version are
	// handled as ordinary errors.
	return decodeVerifiedCall(status, raw, out)
}

// runModernOperation runs the projected tools/call operation at version.
func (c *Client) runModernOperation(ctx context.Context, signer Signer, version, tool string, args []byte, out any) error {
	status, raw, err := c.callProjected(ctx, signer, modernToolsPlan, version, tool, args)
	if err != nil {
		return err
	}
	return decodeVerifiedCall(status, raw, out)
}

// CallTool performs one signed, response-verified `tools/call` for the named
// tool and decodes the verified structuredContent into out. It uses the
// client's default signer and the verified pinned-key path the native helpers
// also use (WhoAmI, Enroll, ...), which are unchanged.
//
// arguments is any JSON-serializable value; nil sends `{}`. It should marshal
// to a JSON object: the server decides validity and the client performs no
// schema check. out is a pointer passed to json.Unmarshal over the verified
// structuredContent: use *json.RawMessage for the raw JSON, or a pointer to
// any typed struct or map otherwise. out == nil verifies and discards the
// payload; a result lacking structuredContent is still an error, as for the
// native helpers.
//
// Errors: a marshal failure is returned as "jack client: marshal arguments:
// %w"; a non-2xx answer is a *HTTPError; a JSON-RPC error is a *RPCError; a
// result with isError is a *ToolError; transport and verification errors pass
// through for errors.Is / errors.As; decode errors from json.Unmarshal are
// returned as-is. In the modern era a tool whose definition is missing from
// tools/list is an error naming it (no request is sent), and a projection
// mismatch is returned unwrapped, so
// errors.Is(err, modern.ErrHeaderProjectionInvalidValue) holds.
//
// structuredContent is the only result model: content-block results are not
// interpreted, and there is no streaming support.
//
// The request era follows Config.Era, and the era is cached per client, which
// serves one origin; only a verified response selects it.
//
//   - EraLegacy sends the 0.1.x request unchanged: one signed tools/call with
//     no params._meta, no mirror headers, no tools/list and no initialize.
//   - EraModern runs the projected modern flow of CallModernTool: fetch
//     tools/list, drop invalid definitions (C5), project the arguments into
//     Mcp-Param-* headers after the C2 mirrors (C6), send the call, and after
//     a verified -32020 refusal refetch, re-project and retry once (C10). The
//     jack.* native tools skip the projection (they are not in tools/list and
//     have no annotations) and are sent with the mirrors only.
//   - EraAuto sends a `server/discover` probe first: that request makes era
//     detection deterministic (C9), because legacy servers do not implement
//     it, and the probe never executes the user operation. The C9 decision is
//     applied to the verified answer: a 2xx, a recognised 400 modern error
//     (-32020/-32021/-32022) or a 404 with -32601 selects the modern era
//     (settling EraModern) and then runs the projected operation; a legacy
//     signal runs initialize plus notifications/initialized once and then the
//     legacy operation, settling EraLegacy; a -32022 retries once with the
//     first mutually implemented version other than the attempted one (a
//     modern version re-probes once at that version and then runs the
//     projected operation, a legacy version runs the legacy handshake and the
//     legacy operation); anything else is reported as the ordinary error.
//     Only verified responses select an era.
//
// A transport or verification error proves no era and is returned unchanged.
// ResetEra re-probes: it clears the settled era so the next CallTool runs the
// configured era again.
func (c *Client) CallTool(ctx context.Context, tool string, arguments any, out any) error {
	era := c.currentEra()
	if era == EraLegacy {
		return c.call(ctx, nil, tool, arguments, out)
	}
	args, err := marshalCallArguments(arguments)
	if err != nil {
		return err
	}
	if era == EraModern {
		status, raw, err := c.callProjected(ctx, nil, modernToolsPlan, modern.ModernMin, tool, args)
		if err != nil {
			return err
		}
		return decodeVerifiedCall(status, raw, out)
	}
	return c.callAuto(ctx, nil, tool, args, out)
}

// readCapped reads at most cap bytes, detecting larger bodies.
func readCapped(r io.Reader, capBytes int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(capBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > capBytes {
		return nil, fmt.Errorf("jack client: response body exceeds %d bytes", capBytes)
	}
	return raw, nil
}

// Profile is a client configuration file holding ONLY public data: it
// deliberately has no private-key field, since private keys must never live
// in config files (spec 01 section 6, README principle 5).
type Profile struct {
	URL string `json:"url"`
	Aud string `json:"aud"`
	// ServerPublicKey is the unpadded base64url of the 32-byte server key.
	ServerPublicKey string `json:"server_public_key"`
	// KID is the client key's identifier (kid), never a private key.
	KID string `json:"kid,omitempty"`
	// Name is the client key's label.
	Name string `json:"name,omitempty"`
}

// LoadProfile reads and validates a profile from r.
func LoadProfile(r io.Reader) (Profile, error) {
	if r == nil {
		return Profile{}, fmt.Errorf("jack client: nil profile reader")
	}
	var p Profile
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("jack client: profile: %w", err)
	}
	// Trailing data would silently hide a second document.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Profile{}, fmt.Errorf("jack client: profile: trailing data after JSON object")
	}
	if err := validateProfile(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// validateProfile enforces spec 01 sections 3 and 6 field rules.
func validateProfile(p Profile) error {
	// The client URL policy decides acceptance on the raw string (percent
	// escapes are refused in the authority only; percent-encoded path/query
	// is accepted); the parse checks below are extra and reject only what
	// net/url cannot parse, with a generic non-policy error.
	if err := urlpolicy.CheckDestination(p.URL); err != nil {
		return err
	}
	u, err := url.Parse(p.URL)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("jack client: profile url must be an absolute http/https URL with a host")
	}
	if p.Aud == "" {
		return fmt.Errorf("jack client: profile aud must be non-empty")
	}
	if audHasControl(p.Aud) {
		return fmt.Errorf("jack client: profile aud must not contain control characters")
	}
	serverKey, err := jack.DecodeBase64URLFixed(p.ServerPublicKey, 32)
	if err != nil {
		return fmt.Errorf("jack client: profile server_public_key: %w", jack.ErrBadBase64URL)
	}
	if err := jack.ValidatePublicKey(serverKey); err != nil {
		// Local validation never becomes an HTTP response: zero the
		// validator's wire admission status (400) per the Error.HTTPStatus
		// contract, matching VerifyResponse's client-side remap.
		var jErr *jack.Error
		if errors.As(err, &jErr) {
			return &jack.Error{HTTPStatus: 0, Code: jErr.Code, Message: jErr.Message}
		}
		return err
	}
	if p.KID != "" {
		if _, err := jack.DecodeBase64URLFixed(p.KID, 32); err != nil {
			return fmt.Errorf("jack client: profile kid: %w", jack.ErrBadBase64URL)
		}
	}
	return nil
}

// SaveProfile writes p as indented JSON with a trailing newline.
func SaveProfile(w io.Writer, p Profile) error {
	if w == nil {
		return fmt.Errorf("jack client: nil profile writer")
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// ServerKeyBytes returns the decoded 32-byte server public key.
func (p Profile) ServerKeyBytes() ([]byte, error) {
	return jack.DecodeBase64URLFixed(p.ServerPublicKey, 32)
}

// NewClientFromProfile validates p and builds a Client for it. httpc is the
// optional caller-supplied HTTP client (Config.HTTP); it supplies timeout, Jar and
// the base RoundTripper, while the SDK always adds its own signing and
// verifying Transport (see Config.HTTP). nil selects the built-in one. The Rust
// and TS SDKs expose the same constructor (Client::from_profile /
// clientFromProfile).
func NewClientFromProfile(p Profile, signer Signer, httpc *http.Client) (*Client, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	serverKey, err := p.ServerKeyBytes()
	if err != nil {
		// validateProfile already accepted this key, so this is unreachable
		// in practice; kept so a decode failure can never pass a short key on.
		return nil, fmt.Errorf("jack client: profile server_public_key: %w", err)
	}
	return NewClient(Config{
		BaseURL:   p.URL,
		Aud:       p.Aud,
		Signer:    signer,
		ServerKey: serverKey,
		HTTP:      httpc,
	})
}
