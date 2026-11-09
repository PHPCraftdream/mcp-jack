package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

type clientConfig struct {
	Version         int    `json:"version"`
	Endpoint        string `json:"endpoint"`
	Aud             string `json:"aud"`
	ServerPublicKey string `json:"server_public_key"`
	ServerKID       string `json:"server_kid"`
	KeyFile         string `json:"key_file"`
	KeyFormat       string `json:"key_format"`
	CallTimeoutMS   int    `json:"call_timeout_ms"`
}

type connection struct {
	endpoint string
	aud      string
	pin      []byte
	signer   *userkey.ClientKey
	timeout  time.Duration
}

func loadConnection(path string) (*connection, error) {
	var c clientConfig
	if decodeConfig(path, &c) != nil || c.Version != 1 {
		return nil, errConfig
	}
	timeout, err := callDuration(c.CallTimeoutMS)
	if err != nil {
		return nil, err
	}
	pub, err := jack.DecodeBase64URLFixed(c.ServerPublicKey, 32)
	if err != nil || jack.ValidatePublicKey(pub) != nil || c.ServerKID != jack.KeyID(pub) || c.Aud == "" {
		return nil, errConfig
	}
	b, err := readPrivate(c.KeyFile, 4096)
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
		return nil, errConfig
	}
	if err != nil || signer == nil || signer.KID() == c.ServerKID {
		return nil, errConfig
	}
	// Public constructor applies the SDK's exact URL policy without I/O.
	if _, err := client.NewClient(client.Config{BaseURL: c.Endpoint, Aud: c.Aud, Signer: signer, ServerKey: pub}); err != nil {
		return nil, errConfig
	}
	return &connection{c.Endpoint, c.Aud, pub, signer, timeout}, nil
}

func directTransport(timeout time.Duration) *http.Transport {
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
type oneShot struct{ base *http.Transport }

func (o oneShot) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.GetBody = nil
	clone.Close = true
	clone.Header.Del("Idempotency-Key")
	clone.Header.Del("X-Idempotency-Key")
	return o.base.RoundTrip(clone)
}

func (c *connection) post(ctx context.Context, body []byte) ([]byte, int, error) {
	if len(body) > maxBody {
		return nil, 0, errProtocol
	}
	base := directTransport(c.timeout)
	defer base.CloseIdleConnections()
	t := client.NewTransport(oneShot{base}, c.aud, c.signer, c.pin)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errConfig
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", protocolVersion)
	resp, err := client.NewHTTPClient(t).Do(r)
	if err != nil {
		return nil, 0, errRemote
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, resp.StatusCode, &verifiedStatusError{status: resp.StatusCode}
	}
	if unsupportedMetadata(resp.Header) || len(resp.Header.Values("Content-Encoding")) != 0 {
		return nil, 0, errProtocol
	}
	if vs := resp.Header.Values("MCP-Protocol-Version"); len(vs) > 1 || (len(vs) == 1 && vs[0] != protocolVersion) {
		return nil, 0, errProtocol
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return nil, 0, errRemote
	}
	if resp.StatusCode == 202 && len(b) == 0 {
		return b, 202, nil
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, errProtocol
	}
	if len(resp.Header.Values("Content-Type")) != 1 {
		return nil, 0, errProtocol
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, 0, errProtocol
	}
	return b, resp.StatusCode, nil
}

func unsupportedMetadata(h http.Header) bool {
	for _, name := range []string{"Mcp-Session-Id", "Last-Event-ID", "Mcp-Method", "Mcp-Name"} {
		if len(h.Values(name)) != 0 {
			return true
		}
	}
	return false
}
