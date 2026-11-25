package main

// Fixture resource plus the `updated` tool used to exercise the official
// SEP-2575 subscriptions/listen lifecycle end to end.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const resourceURI = "e2e://fixtures/resource"

func fixtureResource() *mcp.Resource {
	return &mcp.Resource{
		URI:      resourceURI,
		Name:     "fixture-resource",
		MIMEType: "text/plain",
		Description: "deterministic fixture resource for resources/subscribe and " +
			"subscriptions/listen lifecycle",
	}
}

func readFixtureResource(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	_ = req
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
		{URI: resourceURI, MIMEType: "text/plain", Text: "fixture-resource-v1"},
	}}, nil
}

type updatedArgs struct{}

type updatedOut struct {
	Updated bool `json:"updated"`
}

// updatedTool notifies every subscriber of the fixture resource via the
// official Server.ResourceUpdated API (mcp/server.go:1183).
func updatedTool(srv *mcp.Server) mcp.ToolHandlerFor[updatedArgs, updatedOut] {
	return func(ctx context.Context, req *mcp.CallToolRequest, _ updatedArgs) (*mcp.CallToolResult, updatedOut, error) {
		_ = req
		err := srv.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: resourceURI})
		if err != nil {
			return nil, updatedOut{}, err
		}
		return nil, updatedOut{Updated: true}, nil
	}
}
