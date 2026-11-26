package main

// Scenario 7 exercises a resource subscriptions/listen stream.

import "context"

func scenario7(ctx context.Context, s *session, now func() int64, server string) runOut {
	return runOut{outcome: "unsupported", capabilityEvidence: "the official Go client cannot observe the subscriptions/listen lifecycle the driver requires: ClientSession.Subscribe issues the listen call without awaiting its JSON-RPC response (mcp/shared.go:159-167 via callSubscriptionsListen; mcp/transport.go:274-289: 'the caller has nothing useful to block on'; cancellation is only ctx-driven, mcp/transport.go:280-289), so the client can never observe notification delivery followed by a stream end; go-client scenario-7 pairs are therefore capability SKIPs"}
}
