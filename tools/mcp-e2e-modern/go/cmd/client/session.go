package main

// SDK client/session construction for direct and jack modes, plus the
// per-request _meta builder used by scenario 3.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const clientName = "e2e-modern-go-client"

type session struct {
	client  *mcp.Client
	sess    *mcp.ClientSession
	direct  bool
	bridge  *bridgeProc
	rec     *recorder
	updated chan string // notifications/resources/updated URIs
}

// newClient builds the official SDK client with progress and resource-updated
// notification handling.
func newClient(rec *recorder) (*mcp.Client, chan string) {
	updated := make(chan string, 8)
	client := mcp.NewClient(
		&mcp.Implementation{Name: clientName, Version: sdkVer},
		&mcp.ClientOptions{
			// Mirrors the SDK default so request_meta can be reconstructed exactly.
			Capabilities: &mcp.ClientCapabilities{RootsV2: &mcp.RootCapabilities{ListChanged: true}},
			ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
				p := req.Params
				total := &p.Total
				rec.add(progressObs{Progress: p.Progress, Total: total})
			},
			ResourceUpdatedHandler: func(_ context.Context, req *mcp.ResourceUpdatedNotificationRequest) {
				select {
				case updated <- req.Params.URI:
				default:
				}
			},
		},
	)
	return client, updated
}

// connectDirect connects over the modern streamable HTTP transport.
func connectDirect(ctx context.Context, endpoint string, rec *recorder) (*session, error) {
	client, updated := newClient(rec)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	return &session{client: client, sess: sess, direct: true, rec: rec, updated: updated}, nil
}

// connectBridge connects over the jack bridge stdio transport with the
// modern protocol, so Connect uses the SDK's own modern flow (server/discover
// first, never initialize).
func connectBridge(ctx context.Context, b *bridgeProc, rec *recorder) (*session, error) {
	client, updated := newClient(rec)
	opts := &mcp.ClientSessionOptions{ProtocolVersion: modernProtocol}
	sess, err := client.Connect(ctx, b.transport(), opts)
	if err != nil {
		return nil, err
	}
	return &session{client: client, sess: sess, bridge: b, rec: rec, updated: updated}, nil
}

func (s *session) close() {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.bridge != nil {
		s.bridge.stop()
	}
}

// requestMetaFor reproduces the exact _meta the SDK puts on the wire for a
// tools/call so the client-reported request_meta matches every hop. The SDK
// injects protocolVersion/clientInfo/clientCapabilities under
// io.modelcontextprotocol/* keys (mcp/client.go injectRequestMeta) only when
// absent, so pre-populating them makes injection a no-op.
func requestMetaFor(protocolVersion string) mcp.Meta {
	return mcp.Meta{
		"e2e.example.com/request":  "modern-e2e-meta",
		mcp.MetaKeyProtocolVersion: protocolVersion,
		mcp.MetaKeyClientInfo:      map[string]any{"name": clientName, "version": sdkVer},
		mcp.MetaKeyClientCapabilities: map[string]any{
			"roots": map[string]any{"listChanged": true},
		},
	}
}

// requestMeta uses the negotiated protocol version (default modern).
func (s *session) requestMeta() mcp.Meta {
	pv := modernProtocol
	if ir := s.sess.InitializeResult(); ir != nil && ir.ProtocolVersion != "" {
		pv = ir.ProtocolVersion
	}
	return requestMetaFor(pv)
}
