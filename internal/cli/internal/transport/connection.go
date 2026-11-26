package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/client/modern"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

type Config struct {
	Version         int    `json:"version"`
	Endpoint        string `json:"endpoint"`
	Aud             string `json:"aud"`
	ServerPublicKey string `json:"server_public_key"`
	ServerKID       string `json:"server_kid"`
	KeyFile         string `json:"key_file"`
	KeyFormat       string `json:"key_format"`
	CallTimeoutMS   int    `json:"call_timeout_ms"`
	Era             string `json:"era,omitempty"`
}

type Connection struct {
	Endpoint string
	Aud      string
	Pin      []byte
	Signer   *userkey.ClientKey
	Timeout  time.Duration
	Era      string
}

func LoadConnection(path string) (*Connection, error) {
	var c Config
	if storage.DecodeConfig(path, &c) != nil || c.Version != 1 || (c.Era != "" && c.Era != "legacy" && c.Era != "modern" && c.Era != "auto") {
		return nil, command.ErrConfig
	}
	timeout, err := command.CallDuration(c.CallTimeoutMS)
	if err != nil {
		return nil, err
	}
	pub, err := jack.DecodeBase64URLFixed(c.ServerPublicKey, 32)
	if err != nil || jack.ValidatePublicKey(pub) != nil || c.ServerKID != jack.KeyID(pub) || c.Aud == "" {
		return nil, command.ErrConfig
	}
	b, err := storage.ReadPrivate(c.KeyFile, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	var signer *userkey.ClientKey
	switch c.KeyFormat {
	case "raw-seed":
		signer, err = userkey.ImportClientKey(b)
	case "private-envelope":
		signer, err = userkey.ImportClientPrivateEnvelope(b)
	case "credential":
		var imported *userkey.ImportedCredential
		imported, err = userkey.ImportCredential(b, userkey.ExpectedIdentity{
			URL: c.Endpoint, Aud: c.Aud, ServerPublicKey: pub, ServerKID: c.ServerKID,
		})
		if err == nil {
			signer = imported.Signer
		}
	default:
		return nil, command.ErrConfig
	}
	if err != nil || signer == nil || signer.KID() == c.ServerKID {
		return nil, command.ErrConfig
	}
	// Public constructor applies the SDK's exact URL policy without I/O.
	if _, err := client.NewClient(client.Config{BaseURL: c.Endpoint, Aud: c.Aud, Signer: signer, ServerKey: pub}); err != nil {
		return nil, command.ErrConfig
	}
	return &Connection{Endpoint: c.Endpoint, Aud: c.Aud, Pin: pub, Signer: signer, Timeout: timeout, Era: c.Era}, nil
}

func DirectTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16384,
	}
}

// A fresh HTTP/1 transport per call cannot replay a request on a reused socket.
// The SDK installs GetBody; remove it at the final network boundary as well.
type OneShot struct{ base *http.Transport }

// NewOneShot wraps a transport so each request is sent exactly once.
func NewOneShot(base *http.Transport) OneShot { return OneShot{base: base} }

func (o OneShot) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.GetBody = nil
	clone.Close = true
	clone.Header.Del("Idempotency-Key")
	clone.Header.Del("X-Idempotency-Key")
	return o.base.RoundTrip(clone)
}

func (c *Connection) OpenStream(ctx context.Context, body []byte) (*clientstream.Stream, *clientstream.VerifiedResponse, error) {
	return c.openStream(ctx, body, false)
}

// OpenEraProbe sends the auto-era discovery probe through the same signed
// path as OpenStream, with the modern protocol version and mirror headers
// taken from the probe request itself while the connection era is still auto.
func (c *Connection) OpenEraProbe(ctx context.Context, body []byte) (*clientstream.Stream, *clientstream.VerifiedResponse, error) {
	return c.openStream(ctx, body, true)
}

func (c *Connection) openStream(ctx context.Context, body []byte, probe bool) (*clientstream.Stream, *clientstream.VerifiedResponse, error) {
	base := DirectTransport(c.Timeout)
	t := client.NewTransport(OneShot{base}, c.Aud, c.Signer, c.Pin)
	t.Stream = &clientstream.ClientConfig{Consumer: clientstream.ConsumerStdio}
	defer base.CloseIdleConnections()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, command.ErrConfig
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if probe {
		r.Header.Set("MCP-Protocol-Version", modern.ModernMin)
	} else {
		r.Header.Set("MCP-Protocol-Version", c.protocolVersion())
	}
	if probe {
		if err := c.buildModernMirrors(r.Header, body); err != nil {
			return nil, nil, err
		}
	} else if c.Era == "modern" {
		if err := c.setModernMirrors(r.Header, body); err != nil {
			return nil, nil, err
		}
	}
	s, reply, err := t.OpenStream(r)
	if err != nil {
		return nil, nil, command.ErrRemote
	}
	return s, reply, nil
}

func (c *Connection) protocolVersion() string {
	if c.Era == "modern" {
		return "2026-07-28"
	}
	return wire.ProtocolVersion
}

func (c *Connection) setModernMirrors(header http.Header, body []byte) error {
	if c.Era != "modern" {
		return nil
	}
	return c.buildModernMirrors(header, body)
}

// buildModernMirrors derives the modern mirror headers from the request body
// alone; the era probe needs it while the connection era is still auto.
func (c *Connection) buildModernMirrors(header http.Header, body []byte) error {
	message, err := wire.Object(body)
	if err != nil {
		return command.ErrProtocol
	}
	method := wire.Text(message["method"])
	if method == "" {
		return command.ErrProtocol
	}
	paramsRaw, exists := message["params"]
	if !exists {
		return command.ErrProtocol
	}
	var params map[string]any
	if err := json.Unmarshal(paramsRaw, &params); err != nil || params == nil {
		return command.ErrProtocol
	}
	meta, ok := params["_meta"].(map[string]any)
	if !ok || meta[modern.MetaVersionKey] != modern.ModernMin {
		return command.ErrProtocol
	}
	mirrors, err := modern.BuildRequestMirrors(modern.ModernMin, method, params, nil)
	if err != nil {
		return command.ErrProtocol
	}
	for _, item := range mirrors.Headers {
		header.Set(item.Name, item.Value)
	}
	return nil
}

func (c *Connection) Post(ctx context.Context, body []byte) ([]byte, int, error) {
	if len(body) > wire.MaxBody {
		return nil, 0, command.ErrProtocol
	}
	base := DirectTransport(c.Timeout)
	defer base.CloseIdleConnections()
	t := client.NewTransport(OneShot{base}, c.Aud, c.Signer, c.Pin)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, command.ErrConfig
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", c.protocolVersion())
	if err := c.setModernMirrors(r.Header, body); err != nil {
		return nil, 0, err
	}
	resp, err := client.NewHTTPClient(t).Do(r)
	if err != nil {
		return nil, 0, command.ErrRemote
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, resp.StatusCode, &VerifiedStatusError{Status: resp.StatusCode}
	}
	if (c.Era != "modern" && UnsupportedMetadata(resp.Header)) || len(resp.Header.Values("Content-Encoding")) != 0 {
		return nil, 0, command.ErrProtocol
	}
	if vs := resp.Header.Values("MCP-Protocol-Version"); len(vs) > 1 || (len(vs) == 1 && ((c.Era == "modern" && vs[0] != "2026-07-28") || (c.Era != "modern" && vs[0] != wire.ProtocolVersion))) {
		return nil, 0, command.ErrProtocol
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxBody+1))
	if err != nil || len(b) > wire.MaxBody {
		return nil, 0, command.ErrRemote
	}
	if resp.StatusCode == 202 && len(b) == 0 {
		return b, 202, nil
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, command.ErrProtocol
	}
	if len(resp.Header.Values("Content-Type")) != 1 {
		return nil, 0, command.ErrProtocol
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, 0, command.ErrProtocol
	}
	return b, resp.StatusCode, nil
}

func UnsupportedMetadata(h http.Header) bool {
	for _, name := range []string{"Mcp-Session-Id", "Last-Event-ID", "Mcp-Method", "Mcp-Name"} {
		if len(h.Values(name)) != 0 {
			return true
		}
	}
	return false
}

type VerifiedStatusError struct {
	Status int
}

func (e *VerifiedStatusError) Error() string {
	return "authenticated HTTP " + strconv.Itoa(e.Status) + "; no retry performed"
}

func (e *VerifiedStatusError) Unwrap() error { return command.ErrRemote }
