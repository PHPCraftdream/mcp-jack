package main

// Scenario 7 exercises a resource subscriptions/listen stream.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const listenResourceURI = "e2e://fixtures/resource"

func scenario7(ctx context.Context, s *session, now func() int64, server string) runOut {
	if server == "ts" {
		return runOut{outcome: "unsupported", capabilityEvidence: "Go SDK v1.8.0 exposes subscriptions/listen only via resource ClientSession.Subscribe (mcp/client.go:1379-1412) and its only notification trigger is a resource update; the ts server fixture registers no resource or updated tool (ts/server.mjs registers echo/progress), and the Go client has no tools-list listen API, so the go-client x ts-server scenario-7 pair has no official-API trigger"}
	}
	ack := make(chan struct{}, 1)
	s.client.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if method == "notifications/subscriptions/acknowledged" {
				select {
				case ack <- struct{}{}:
				default:
				}
			}
			return res, err
		}
	})

	listenCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	listenDone := make(chan error, 1)
	go func() {
		listenDone <- s.sess.Subscribe(listenCtx, &mcp.SubscribeParams{URI: listenResourceURI})
	}()
	select {
	case <-ack:
	case err := <-listenDone:
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("subscriptions/listen ended before acknowledgement: %v", err)}
	case <-ctx.Done():
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("waiting for subscriptions/listen acknowledgement: %v", ctx.Err())}
	case <-time.After(10 * time.Second):
		return runOut{outcome: "fail", sdkErr: "timed out waiting for subscriptions/listen acknowledgement"}
	}

	result, err := s.sess.CallTool(ctx, &mcp.CallToolParams{Name: "updated", Arguments: map[string]any{}})
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("trigger resource update: %v", err)}
	}
	if result.IsError {
		return runOut{outcome: "fail", sdkErr: "updated tool returned an error"}
	}
	select {
	case uri := <-s.updated:
		if uri != listenResourceURI {
			return runOut{outcome: "fail", sdkErr: fmt.Sprintf("resource update URI %q, want %q", uri, listenResourceURI)}
		}
	case <-ctx.Done():
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("waiting for resource update: %v", ctx.Err())}
	case <-time.After(10 * time.Second):
		return runOut{outcome: "fail", sdkErr: "timed out waiting for resource update"}
	}

	if err := s.sess.Unsubscribe(ctx, &mcp.UnsubscribeParams{URI: listenResourceURI}); err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("unsubscribe subscriptions/listen: %v", err)}
	}
	select {
	case err := <-listenDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			return runOut{outcome: "fail", sdkErr: fmt.Sprintf("closing subscriptions/listen: %v", err)}
		}
	case <-time.After(10 * time.Second):
		return runOut{outcome: "fail", sdkErr: "timed out waiting for subscriptions/listen to end"}
	}
	done := now()
	// end:graceful is the documented close path; the SDK exposes no richer end signal.
	return runOut{outcome: "ok", toolResult: []byte(`{"notification":"notifications/resources/updated","end":"graceful"}`), completedMs: &done}
}
