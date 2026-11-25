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
			ID:     "stateless",
			Status: "supported",
			Evidence: "SDK API mcp.StreamableHTTPOptions.Stateless (mcp/streamable.go:129) exists; this fixture " +
				"deliberately runs STATEFUL (Stateless not set) because scenario 7 subscriptions/listen needs " +
				"cross-request session affinity — stateless mode is offered but not exercised here",
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
			ID:     "subscriptions_listen",
			Status: "supported",
			Evidence: "Server.subscriptionsListen SEP-2575 handler (mcp/server.go:1256) with Server.ResourceUpdated " +
				"notifications delivered on the listen stream (mcp/server.go:1183)",
		},
		{
			ID:       "server_discover",
			Status:   "supported",
			Evidence: "Server.discover SEP-2575 server/discover handler (mcp/server.go:926)",
		},
		{
			ID:     "protocol_2026_07_28",
			Status: "supported",
			Evidence: "SDK v1.8.0 SupportedProtocolVersions starts at 2026-07-28 (docs/protocol.md:138); negotiated " +
				"by mcp client/server protocolVersion20260728",
		},
	}
}
