package rotationclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

var ErrRequestUnavailable = errors.New("rotation client: request outcome unavailable; no retry performed")

// HTTPClient не владеет store; transport создаётся заново для каждой попытки.
type HTTPClient struct {
	controller *Controller
	signer client.Signer
	endpoint *url.URL
	timeout time.Duration
}

// Reply содержит только authenticated status/body после final gate.
type Reply struct {
	Status int
	Body []byte
}

func NewHTTP(store *durable.TrustStore, signer client.Signer, timeout time.Duration) (*HTTPClient, error) {
	if timeout <= 0 || timeout > 30*time.Second { return nil, localError("rotation_state_unknown") }
	controller, err := New(store)
	if err != nil { return nil, err }
	if _, err := client.NewClient(client.Config{BaseURL: controller.binding.Endpoint, Aud: controller.binding.Audience, Signer: signer, ServerKey: controller.checkpoint.PublicKey[:]}); err != nil {
		return nil, localError("rotation_state_unknown")
	}
	endpoint, err := url.Parse(controller.binding.Endpoint)
	if err != nil { return nil, localError("rotation_state_unknown") }
	return &HTTPClient{controller: controller, signer: signer, endpoint: endpoint, timeout: timeout}, nil
}

func (sender *HTTPClient) exchange(ctx context.Context, body []byte, limit int, expected *rotation.TrustSnapshot) (Response, error) {
	if ctx == nil || len(body) > 1<<20 { return Response{}, localError("rotation_result_invalid") }
	if err := ctx.Err(); err != nil { return Response{}, err }
	owned := append([]byte(nil), body...)
	snapshot, err := sender.controller.state()
	if err != nil { return Response{}, err }
	if expected != nil && !sender.controller.equal(snapshot, *expected) { return Response{}, localError("rotation_state_changed") }
	clock, err := sender.controller.store.CheckSnapshotClock(snapshot)
	if err != nil { return Response{}, mappedError(err, "rotation_clock_unavailable") }
	nonce, err := client.RandomNonce()
	if err != nil { return Response{}, localError("rotation_state_unknown") }
	header, err := client.SignRequest(sender.signer, sender.controller.binding.Audience, "POST", sender.endpoint.RequestURI(), owned, nonce, time.Unix(clock.HighWater, 0))
	if err != nil { return Response{}, localError("rotation_state_unknown") }
	auth, err := jack.ParseRequestAuth([]string{header})
	if err != nil { return Response{}, localError("rotation_state_unknown") }
	request, err := http.NewRequestWithContext(ctx, "POST", sender.endpoint.String(), bytes.NewReader(owned))
	if err != nil { return Response{}, localError("rotation_state_unknown") }
	request.GetBody = nil
	request.Close = true
	request.Header.Set("Jack-Auth", header)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: sender.timeout}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ForceAttemptHTTP2: false,
		DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: sender.timeout, ResponseHeaderTimeout: sender.timeout, MaxResponseHeaderBytes: 16384,
	}
	defer transport.CloseIdleConnections()
	network := &http.Client{Transport: transport, Timeout: sender.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := network.Do(request)
	if err != nil {
		if ctx.Err() != nil { return Response{}, ctx.Err() }
		if errors.Is(err, context.DeadlineExceeded) { return Response{}, context.DeadlineExceeded }
		return Response{}, ErrRequestUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode <= 399 { return Response{}, client.ErrRedirectRefused }
	if len(response.Header.Values("Content-Encoding")) != 0 { return Response{}, localError("rotation_result_invalid") }
	reply, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		if ctx.Err() != nil { return Response{}, ctx.Err() }
		if errors.Is(err, context.DeadlineExceeded) { return Response{}, context.DeadlineExceeded }
		return Response{}, ErrRequestUnavailable
	}
	if len(reply) > limit { return Response{}, localError("rotation_result_invalid") }
	return Response{Status: response.StatusCode, Headers: append([]string(nil), response.Header.Values("Jack-Auth")...), RequestSignature: auth.Sig, Body: reply}, nil
}

// Call отправляет ровно один POST; response никогда не расширяет trust автоматически.
func (sender *HTTPClient) Call(ctx context.Context, body []byte) (Reply, error) {
	if ctx == nil { return Reply{}, localError("rotation_state_unknown") }
	ctx, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	response, err := sender.exchange(ctx, body, 1<<20, nil)
	if err != nil { return Reply{}, err }
	if ctx.Err() != nil { return Reply{}, ctx.Err() }
	verified, err := sender.controller.VerifyResponse(response)
	if err != nil { return Reply{}, err }
	if ctx.Err() != nil { return Reply{}, ctx.Err() }
	return Reply{Status: response.Status, Body: verified}, nil
}

// Refresh явно запрашивает одну страницу от текущего ACKed cursor, без retries/pagination.
func (sender *HTTPClient) Refresh(ctx context.Context) (RefreshResult, error) {
	if ctx == nil { return RefreshResult{}, localError("rotation_state_unknown") }
	ctx, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	snapshot, err := sender.controller.state()
	if err != nil { return RefreshResult{}, err }
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "jack.server.key", "arguments": map[string]any{"after_ordinal": snapshot.Head.Ordinal, "after_hash": snapshot.Head.Hash}},
	})
	if err != nil { return RefreshResult{}, localError("rotation_state_unknown") }
	response, err := sender.exchange(ctx, body, rotation.MaxResultBodyBytes, &snapshot)
	if err != nil { return RefreshResult{}, err }
	if ctx.Err() != nil { return RefreshResult{}, ctx.Err() }
	result, err := sender.controller.acceptRefresh(response, json.RawMessage("1"), snapshot.Head, &snapshot)
	if err != nil { return result, err }
	if ctx.Err() != nil { return result, ctx.Err() }
	return result, nil
}
