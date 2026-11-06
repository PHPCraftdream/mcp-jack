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
	// HTTP is an optional caller-supplied client; it MUST itself use a
	// configured *Transport, otherwise requests are unsigned and responses
	// unverified. Its transport must use TLS for https URLs, connect to
	// exactly the URL it is given and not follow redirects; the SDK cannot
	// police that. NewClient checks BaseURL once at construction, and a
	// *Transport re-checks every request, but a custom transport is outside
	// that control. The caller's client is never mutated: when its
	// CheckRedirect is nil the Client uses a shallow copy that does not follow
	// redirects, and a 301/302/303/307/308 answer is refused with
	// ErrRedirectRefused (a no-follow guard, not TLS enforcement).
	HTTP *http.Client
	// Now, Nonce and Window are optional tuning fields carried onto the
	// built-in Transport when HTTP is nil.
	Now    func() time.Time
	Nonce  NonceSource
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
	hc := cfg.HTTP
	if hc == nil {
		// A caller-supplied HTTP client must itself use a configured
		// *Transport; only the built-in one is signed and verified by default.
		tr := NewTransport(nil, cfg.Aud, cfg.Signer, cfg.ServerKey)
		tr.Now = cfg.Now
		tr.Nonce = cfg.Nonce
		tr.Window = cfg.Window
		hc = NewHTTPClient(tr)
	} else if hc.CheckRedirect == nil {
		// Shallow copy: the caller's client is left untouched.
		cp := *hc
		cp.CheckRedirect = noFollowRedirects
		hc = &cp
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base:      u,
		aud:       cfg.Aud,
		signer:    cfg.Signer,
		serverKey: cfg.ServerKey,
		hc:        hc,
		now:       now,
		nonce:     cfg.Nonce,
		window:    cfg.Window,
		nextID:    1,
	}, nil
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
