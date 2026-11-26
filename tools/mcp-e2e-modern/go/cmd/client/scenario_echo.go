package main

// Scenarios 1, 2, 3 and 8: deterministic echo through the official SDK.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type runOut struct {
	outcome            string
	toolResult         json.RawMessage
	sdkErr             string
	meta               any
	completedMs        *int64
	cancelledMs        *int64
	capabilityEvidence string
}

// echoParams builds tools/call params with optional _meta.
func echoParams(value string, meta mcp.Meta) *mcp.CallToolParams {
	params := &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"value": value},
	}
	if meta != nil {
		params.Meta = meta
	}
	return params
}

// callEcho invokes echo and translates the SDK result into runOut.
func callEcho(ctx context.Context, s *session, value string, meta mcp.Meta, now func() int64) runOut {
	res, err := s.sess.CallTool(ctx, echoParams(value, meta))
	if err != nil {
		return runOut{outcome: "fail", sdkErr: err.Error()}
	}
	body, err := json.Marshal(res)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("marshal tool result: %v", err)}
	}
	if res.IsError {
		return runOut{outcome: "fail", toolResult: body, sdkErr: "echo returned error result"}
	}
	done := now()
	return runOut{outcome: "ok", toolResult: body, meta: meta, completedMs: &done}
}

// scenario1: echo via auto-era bridge; the client handshake toward the bridge
// is legacy 2025-11-25 so the bridge handles modern discovery/traffic upstream.
func scenario1(ctx context.Context, s *session, now func() int64) runOut {
	tools, err := s.sess.ListTools(ctx, nil)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("tools/list: %v", err)}
	}
	found := false
	for _, t := range tools.Tools {
		if t.Name == "echo" {
			found = true
			break
		}
	}
	if !found {
		return runOut{outcome: "fail", sdkErr: "tools/list: echo tool not found"}
	}
	return callEcho(ctx, s, echoValue, nil, now)
}

// scenario3: echo with deterministic value and _meta preserved on all hops.
func scenario3(ctx context.Context, s *session, now func() int64) runOut {
	return callEcho(ctx, s, echoValue, s.requestMeta(), now)
}

// scenario8: echo through the tamper proxy; SDK/bridge errors surface as fail.
func scenario8(ctx context.Context, s *session, now func() int64) runOut {
	return callEcho(ctx, s, echoValue, nil, now)
}
