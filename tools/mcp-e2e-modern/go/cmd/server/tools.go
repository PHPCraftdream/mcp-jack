package main

// Tool registration: echo, progress, updated. Cancellation is tracked from
// the real tool-call context only; the control endpoints never cancel.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// echoArgs/echoOut: deterministic echo, no registered parameter mirror.
type echoArgs struct {
	Value string `json:"value" jsonschema:"value returned unchanged"`
}

type echoOut struct {
	Value string `json:"value"`
}

func echo(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, echoOut, error) {
	return nil, echoOut{Value: args.Value}, nil
}

type progressArgs struct {
	Count  int    `json:"count" jsonschema:"number of progress notifications to emit"`
	Hold   bool   `json:"hold,omitempty" jsonschema:"keep the call live after notifications"`
	CallID string `json:"call_id,omitempty" jsonschema:"identifier for control release/cancelled"`
}

type progressOut struct {
	Count int  `json:"count"`
	Held  bool `json:"held"`
}

// progressTool emits exactly Count notifications with progress 1..Count, then
// a deterministic terminal result. When held, it parks until released via the
// control endpoint or the call context is cancelled.
func progressTool(reg *callRegistry) mcp.ToolHandlerFor[progressArgs, progressOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, args progressArgs) (*mcp.CallToolResult, progressOut, error) {
		if args.Count < 1 {
			args.Count = 1
		}
		sess, _ := req.GetSession().(*mcp.ServerSession)
		token := req.Params.GetProgressToken()
		// Register the hold before any notification so the driver's release
		// (fired on the first captured event) can never 404, and a
		// cancellation during emission still lands after registration.
		var released <-chan struct{}
		if args.Hold && args.CallID != "" {
			var done func()
			released, done = reg.hold(args.CallID)
			defer done()
		}
		if sess != nil && token != nil {
			for i := 1; i <= args.Count; i++ {
				err := sess.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      float64(i),
					Total:         float64(args.Count),
				})
				if err != nil {
					return nil, progressOut{}, err
				}
			}
		}
		if released != nil {
			select {
			case <-released:
			case <-ctx.Done():
				reg.markCancelled(args.CallID)
				return nil, progressOut{}, ctx.Err()
			}
		}
		return nil, progressOut{Count: args.Count, Held: args.Hold && args.CallID != ""}, nil
	}
}

// newServer builds the MCP server with tools, the fixture resource, and the
// resource-subscription capability required by subscriptions/listen.
func newServer(reg *callRegistry) *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "e2e-modern-go-server", Version: sdkVer},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{
				Tools:     &mcp.ToolCapabilities{ListChanged: true},
				Resources: &mcp.ResourceCapabilities{Subscribe: true, ListChanged: true},
			},
			SubscribeHandler: func(context.Context, *mcp.SubscribeRequest) error {
				// SDK registers the subscription after this handler returns (server.go:1219-1228).
				return nil
			},
			UnsubscribeHandler: func(context.Context, *mcp.UnsubscribeRequest) error { return nil },
		},
	)
	srv.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil {
				return result, err
			}
			if method != "notifications/subscriptions/acknowledged" {
				return result, nil
			}
			params, ok := req.GetParams().(*mcp.SubscriptionsAcknowledgedParams)
			if !ok {
				return result, nil
			}
			notifications := params.Notifications
			go func() {
				// Run after the ack write path so notifications cannot block it.
				for _, uri := range notifications.ResourceSubscriptions {
					if uri != "" {
						_ = srv.ResourceUpdated(context.Background(), &mcp.ResourceUpdatedNotificationParams{URI: uri})
					}
				}
				if notifications.ToolsListChanged {
					// Re-adding the same tool emits the SDK's tool-list-changed notification.
					mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "Return the supplied value unchanged"}, echo)
				}
			}()
			return result, nil
		}
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "Return the supplied value unchanged"}, echo)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "progress",
		Description: "Emit count progress notifications (1..count), then a deterministic result",
	}, progressTool(reg))
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "updated",
		Description: "Trigger a notifications/resources/updated for the fixture resource",
	}, updatedTool(srv))
	srv.AddResource(fixtureResource(), readFixtureResource)
	return srv
}
