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
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg Config) (*Client, error) {
	if err := checkDestination(cfg.BaseURL); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("jack client: base url must be an absolute http/https URL with a host")
	}
	if cfg.Aud == "" {
		return nil, fmt.Errorf("jack client: aud must be non-empty")
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

// call performs one signed, verified tool call and decodes structuredContent
// into out (which may be nil when the caller ignores the payload).
func (c *Client) call(ctx context.Context, signer Signer, tool string, arguments any, out any) error {
	if signer == nil {
		signer = c.signer
	}
	args := []byte("{}")
	if arguments != nil {
		raw, err := json.Marshal(arguments)
		if err != nil {
			return fmt.Errorf("jack client: marshal arguments: %w", err)
		}
		args = raw
	}
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()

	reqBody, err := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  jsonrpcParams{Name: tool, Arguments: args},
	})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(WithRequestSigner(ctx, signer), http.MethodPost, c.base.String(), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		// Transport errors (refused streams, unauthenticated 401s, failed
		// verification) pass through unchanged for errors.Is / errors.As.
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if isRedirectStatus(resp.StatusCode) {
		return &RedirectRefusedError{Status: resp.StatusCode}
	}

	raw, err := readCapped(resp.Body, maxBodyBytes)
	if err != nil {
		return fmt.Errorf("jack client: reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		code, message := parseErrorBody(raw)
		return &HTTPError{Status: resp.StatusCode, Code: code, Message: message}
	}

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

// CallTool performs one signed, response-verified `tools/call` for the named
// tool and decodes the verified structuredContent into out. It uses the
// client's default signer and the verified pinned-key path shared with the
// native helpers (WhoAmI, Enroll, ...), which are unchanged.
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
// returned as-is.
//
// This is a single-request signed tool caller, NOT a full MCP session client:
// there is no initialize, tools/list, notification or streaming support, and
// content-block results are not interpreted; structuredContent is the only
// result model.
func (c *Client) CallTool(ctx context.Context, tool string, arguments any, out any) error {
	return c.call(ctx, nil, tool, arguments, out)
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
