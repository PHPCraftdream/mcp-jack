package main

// Scenario 7: official SEP-2575 subscriptions/listen lifecycle. Subscribe
// opens the subscriptions/listen stream (new protocol only), the `updated`
// tool triggers Server.ResourceUpdated, and Unsubscribe closes the stream.

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	resourceURI = "e2e://fixtures/resource" // must match the server fixture resource

	subscribeTimeoutMs  = 5000
	triggerRetryCount   = 5
	triggerRetryDelayMs = 400
)

// scenario7 requires a modern-protocol session (usesNewProtocol), so callers
// connect with the default (latest) protocol version.
func scenario7(ctx context.Context, s *session, now func() int64) runOut {
	listed, err := s.sess.ListResources(ctx, nil)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("resources/list: %v", err)}
	}
	found := false
	for _, r := range listed.Resources {
		if r.URI == resourceURI {
			found = true
			break
		}
	}
	if !found {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("resources/list: %s not found", resourceURI)}
	}

	subErr := make(chan error, 1)
	go func() { subErr <- s.sess.Subscribe(ctx, &mcp.SubscribeParams{URI: resourceURI}) }()

	// The listen stream must be established server-side before the trigger.
	notified := false
	for i := 0; i < triggerRetryCount && !notified; i++ {
		if _, err := s.sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "updated",
			Arguments: map[string]any{},
		}); err != nil {
			return runOut{outcome: "fail", sdkErr: fmt.Sprintf("tools/call updated: %v", err)}
		}
		select {
		case uri := <-s.updated:
			if uri == resourceURI {
				notified = true
			}
		case <-after(triggerRetryDelayMs):
		}
	}
	if !notified {
		_ = s.sess.Unsubscribe(ctx, &mcp.UnsubscribeParams{URI: resourceURI})
		return runOut{outcome: "fail", sdkErr: "notifications/resources/updated not observed on listen stream"}
	}

	if err := s.sess.Unsubscribe(ctx, &mcp.UnsubscribeParams{URI: resourceURI}); err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("resources/unsubscribe: %v", err)}
	}
	// Modern Unsubscribe cancels the listen context (mcp/client.go:1421-1436),
	// so Subscribe's stream ends with a cancellation-flavored error.
	select {
	case err := <-subErr:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, mcp.ErrConnectionClosed) {
			return runOut{outcome: "fail", sdkErr: fmt.Sprintf("resources/subscribe: %v", err)}
		}
	case <-after(subscribeTimeoutMs):
		return runOut{outcome: "fail", sdkErr: "subscribe stream did not end cleanly after unsubscribe"}
	}
	done := now()
	return runOut{outcome: "ok", completedMs: &done}
}
