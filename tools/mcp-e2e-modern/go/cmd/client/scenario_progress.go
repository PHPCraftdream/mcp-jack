package main

// Scenarios 4 and 6: held progress stream and live cancellation through the
// SDK's own context cancellation of the in-flight call.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const progressToken = "e2e-progress-token"

// scenario4: held progress; ordered notifications then terminal result.
func scenario4(ctx context.Context, s *session, now func() int64) runOut {
	params := &mcp.CallToolParams{
		Name: "progress",
		Arguments: map[string]any{
			"count":   3,
			"hold":    true,
			"call_id": "s4-progress",
		},
	}
	params.SetProgressToken(progressToken)
	res, err := s.sess.CallTool(ctx, params)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("tools/call progress: %v", err)}
	}
	body, err := json.Marshal(res)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("marshal tool result: %v", err)}
	}
	if res.IsError {
		return runOut{outcome: "fail", toolResult: body, sdkErr: "progress returned error result"}
	}
	done := now()
	return runOut{outcome: "ok", toolResult: body, completedMs: &done}
}

// scenario6: wait for the driver's `cancel` line on stdin, then cancel the
// in-flight call via the SDK call context (HTTP request/stream closure).
func scenario6(ctx context.Context, s *session, stdin *bufio.Scanner, now func() int64) runOut {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	params := &mcp.CallToolParams{
		Name: "progress",
		Arguments: map[string]any{
			"count":   3,
			"hold":    true,
			"call_id": "s6-progress",
		},
	}
	params.SetProgressToken(progressToken)
	errc := make(chan error, 1)
	go func() {
		_, err := s.sess.CallTool(callCtx, params)
		errc <- err
	}()

	cancelled := false
	for stdin.Scan() {
		if strings.TrimSpace(stdin.Text()) == "cancel" {
			cancelled = true
			cancel()
			break
		}
	}
	if !cancelled {
		// stdin closed without the driver command; stop the call anyway.
		cancel()
	}
	err := <-errc
	ms := now()
	if !cancelled {
		return runOut{outcome: "fail", sdkErr: "stdin closed before cancel command"}
	}
	if err == nil {
		return runOut{outcome: "fail", sdkErr: "call completed despite cancellation", cancelledMs: &ms}
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("tools/call progress: %v", err), cancelledMs: &ms}
	}
	return runOut{outcome: "ok", cancelledMs: &ms}
}
