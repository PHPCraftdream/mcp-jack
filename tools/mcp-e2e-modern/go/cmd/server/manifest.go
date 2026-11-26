package main

// Ready-line schema and capability manifest (CONTRACT.md server ready record).

type sdkIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type capability struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

type readyRecord struct {
	Address        string       `json:"address"`
	ControlAddress string       `json:"control_address"`
	SDK            sdkIdentity  `json:"sdk"`
	Capabilities   []capability `json:"capabilities"`
}

// manifest answers every harness capability ID exactly once with API evidence.
func manifest() []capability {
	return []capability{
		{
			ID:     "stdio_client",
			Status: "unknown",
			Evidence: "client-side capability, evidenced by the client fixture result; the server ready line has " +
				"no SDK client to evidence it (SDK stdio transport is mcp.IOTransport, mcp/transport.go:149)",
		},
		{
			ID:       "streamable_http_server",
			Status:   "supported",
			Evidence: "mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server, *mcp.StreamableHTTPOptions) (mcp/streamable.go:231) served over net/http",
		},
		{
			ID:       "stateless",
			Status:   "supported",
			Evidence: "mcp.StreamableHTTPOptions.Stateless uses a temporary session per request (mcp/streamable.go:129-146); enabled by this fixture",
		},
		{
			ID:       "progress",
			Status:   "supported",
			Evidence: "mcp.ServerSession.NotifyProgress(ctx, *mcp.ProgressNotificationParams) (mcp/server.go:1520) with token from CallToolParamsRaw.GetProgressToken (mcp/protocol.go:416)",
		},
		{
			ID:     "cancellation",
			Status: "supported",
			Evidence: "mcp.StreamableHTTPOptions.PropagateRequestCancellation=true ties the tool handler context to " +
				"the HTTP request/stream (mcp/streamable.go:221); the fixture tracks ctx.Done() per call_id, no synthetic POST",
		},
		{
			ID:       "subscriptions_listen",
			Status:   "supported",
			Evidence: "mcp.ClientSession.Subscribe opens subscriptions/listen for a resource and Unsubscribe cancels it (mcp/client.go:1379-1435); the server acknowledges and retains the stream until cancellation (mcp/server.go:1256-1320)",
		},
		{
			ID:       "server_discover",
			Status:   "supported",
			Evidence: "Server.discover SEP-2575 server/discover handler (mcp/server.go:926)",
		},
		{
			ID:       "protocol_2026_07_28",
			Status:   "supported",
			Evidence: "HTTP supports protocol >= 2026-07-28 only when StreamableHTTPOptions.Stateless is true (mcp/streamable.go:1505-1506); server/discover advertises configured supported versions (mcp/streamable.go:1520-1523)",
		},
	}
}
