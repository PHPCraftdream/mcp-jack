package main

// Scenarios 4 and 6: held progress stream and live cancellation through the
// SDK's own context cancellation of the in-flight call.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const progressToken = "e2e-progress-token"

// scenario4 releases the held call asynchronously after the first SDK callback.
func scenario4(ctx context.Context, s *session, now func() int64, releaseURL string) runOut {
	params := &mcp.CallToolParams{
		Name:      "progress",
		Arguments: map[string]any{"count": 3, "hold": true, "call_id": "s4"},
	}
	params.SetProgressToken(progressToken)
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	releaseCh := make(chan releaseEvidence, 1)
	s.rec.releaseSignal = make(chan struct{}, 1)
	go func() {
		select {
		case <-s.rec.releaseSignal:
			release := postRelease(callCtx, releaseURL, "s4")
			if !release.Observed || release.Status != 200 {
				cancel()
			}
			releaseCh <- release
		case <-callCtx.Done():
			releaseCh <- releaseEvidence{Body: json.RawMessage(`"context canceled"`)}
		}
	}()
	res, err := s.sess.CallTool(callCtx, params)
	if err != nil {
		cancel()
		release := <-releaseCh
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("tools/call progress: %v", err), release: &release}
	}
	release := <-releaseCh
	if !release.Observed || release.Status != 200 {
		cancel()
	}
	body, err := json.Marshal(res)
	if err != nil {
		return runOut{outcome: "fail", sdkErr: fmt.Sprintf("marshal tool result: %v", err), release: &release}
	}
	if !release.Observed || release.Status != 200 {
		return runOut{outcome: "fail", sdkErr: "scenario 4 release not confirmed", release: &release}
	}
	if res.IsError {
		return runOut{outcome: "fail", toolResult: body, sdkErr: "progress returned error result", release: &release}
	}
	done := now()
	return runOut{outcome: "ok", toolResult: body, completedMs: &done, release: &release}
}

func postRelease(ctx context.Context, endpoint, callID string) releaseEvidence {
	var out releaseEvidence
	data, _ := json.Marshal(map[string]string{"call_id": callID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		out.Body = json.RawMessage(strconv.Quote(err.Error()))
		return out
	}
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		out.Body = json.RawMessage(strconv.Quote(err.Error()))
		return out
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	out.Status = resp.StatusCode
	out.Body = append(json.RawMessage(nil), payload...)
	var decoded struct {
		Released bool `json:"released"`
	}
	if json.Unmarshal(payload, &decoded) == nil {
		out.Observed = resp.StatusCode == 200 && decoded.Released
	}
	return out
}

// scenario6 waits for the driver's cancel line, then cancels through context.
func scenario6(ctx context.Context, s *session, stdin *bufio.Scanner, now func() int64) runOut {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	params := &mcp.CallToolParams{
		Name:      "progress",
		Arguments: map[string]any{"count": 3, "hold": true, "call_id": "s6-progress"},
	}
	params.SetProgressToken(progressToken)
	errC := make(chan error, 1)
	go func() {
		_, err := s.sess.CallTool(callCtx, params)
		errC <- err
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
		cancel()
	}
	err := <-errC
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
