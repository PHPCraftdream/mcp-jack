package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/client/modern"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/stdio"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

const modernBridgeWorkers = 8
const modernBridgeMaxDuration = time.Hour

func isBridgeStreamMethod(method string) bool {
	switch method {
	case "events/stream", "subscriptions/listen", "tools/call":
		return true
	default:
		return false
	}
}

type modernStreamAbort struct{ cause error }

func (e *modernStreamAbort) Error() string { return "modern stream aborted: " + e.cause.Error() }
func (e *modernStreamAbort) Unwrap() error { return e.cause }

type modernCall struct {
	cancel    context.CancelFunc
	cancelled bool
	requestID string
	method    string
}

type modernCompletion struct {
	key string
	err error
}

type modernOutput struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *modernOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := 0
	for written < len(p) {
		n, err := w.w.Write(p[written:])
		if n < 0 || n > len(p)-written {
			return written, command.ErrProtocol
		}
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, command.ErrProtocol
		}
	}
	return written, nil
}

func writeModernFrame(ctx context.Context, out io.Writer, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame := make([]byte, len(body)+1)
	copy(frame, body)
	frame[len(body)] = '\n'
	n, err := out.Write(frame)
	if err != nil || n != len(frame) {
		return command.ErrProtocol
	}
	return nil
}

func probeBridgeEra(ctx context.Context, c *transport.Connection) error {
	probeCtx, cancel := context.WithTimeout(ctx, 3*c.Timeout)
	defer cancel()
	attempted := modern.ModernMin
	for range 2 {
		rm, err := modern.BuildRequestMirrors(attempted, "server/discover", nil,
			map[string]any{"name": "mcp-jack", "version": "0.2.0"})
		if err != nil {
			return command.ErrConfig
		}
		body, err := json.Marshal(bridgeProbeRequest{JSONRPC: "2.0", ID: 1, Method: "server/discover", Params: map[string]any{"_meta": rm.Meta}})
		if err != nil {
			return command.ErrProtocol
		}
		stream, reply, err := c.OpenEraProbe(probeCtx, body)
		if err != nil {
			return err
		}
		if stream != nil {
			message, nextErr := stream.Next()
			_ = stream.Close()
			if nextErr != nil {
				return command.ErrRemote
			}
			data := []byte(message)
			if len(data) > wire.MaxBody || bytes.ContainsAny(data, "\r\n") {
				return command.ErrProtocol
			}
			m, parseErr := wire.Object(data)
			if parseErr != nil || wire.Text(m["jsonrpc"]) != "2.0" || len(m["result"]) == 0 && len(m["error"]) == 0 {
				return command.ErrProtocol
			}
			c.Era = string(client.EraModern)
			return nil
		}
		if reply == nil {
			return command.ErrProtocol
		}
		decision := modern.DetectEraAttempt(reply.Status, true, reply.Body,
			[]string{modern.ModernMin, wire.ProtocolVersion, "2025-06-18"}, attempted)
		switch decision.Action {
		case modern.ActionStayModern:
			c.Era = string(client.EraModern)
			return nil
		case modern.ActionFallbackInitialize:
			c.Era = string(client.EraLegacy)
			return nil
		case modern.ActionRetryWithSupported:
			if len(decision.Supported) > 0 {
				v := decision.Supported[0]
				if v == modern.ModernMin {
					attempted = v
					continue
				}
				c.Era = string(client.EraLegacy)
				return nil
			}
		}
		return command.ErrRemote
	}
	return command.ErrRemote
}

// bridgeProbeRequest is the wire shape of the auto-era discovery probe.
type bridgeProbeRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int64          `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}

type modernBridge struct {
	conn    *transport.Connection
	streams stdio.IO
}

func runModernBridge(ctx context.Context, conn *transport.Connection, streams stdio.IO) error {
	return (&modernBridge{conn: conn, streams: streams}).run(ctx)
}

func (b *modernBridge) run(ctx context.Context) error {
	conn, streams := b.conn, b.streams
	root, cancel := context.WithCancel(ctx)
	frames := make(chan Frame)
	cancellations := make(chan json.RawMessage, modernBridgeWorkers)
	terminal := make(chan error, 1)
	completed := make(chan modernCompletion, modernBridgeWorkers)
	var readerDone sync.WaitGroup
	readerDone.Add(1)
	go func() {
		defer readerDone.Done()
		readModernFrames(root, streams.In, frames, cancellations, terminal)
	}()
	var wg sync.WaitGroup
	out := &modernOutput{w: streams.Out}
	active := make(map[string]*modernCall)
	byID := make(map[string]string)
	pending := make([]Frame, 0, modernBridgeWorkers)
	var closeInOnce, closeOutOnce sync.Once
	closeInput := func() { closeInOnce.Do(func() { _ = streams.In.Close() }) }
	closeOutput := func() { closeOutOnce.Do(func() { _ = streams.Out.Close() }) }
	defer func() {
		cancel()
		for _, call := range active {
			call.cancel()
		}
		closeInput()
		closeOutput()
		readerDone.Wait()
		wg.Wait()
	}()

	launch := func(f Frame) error {
		requestID, hasID := modernRequestKey(f.Body)
		request, err := wire.Object(f.Body)
		if err != nil {
			return command.ErrProtocol
		}
		method := wire.Text(request["method"])
		if method == "initialize" {
			return command.ErrProtocol
		}
		jobID := requestID
		if !hasID {
			jobID = "notification:" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		callTimeout := conn.Timeout
		if isBridgeStreamMethod(method) {
			callTimeout = modernBridgeMaxDuration
		}
		callCtx, stop := context.WithTimeout(root, callTimeout)
		call := &modernCall{cancel: stop, requestID: requestID, method: method}
		active[jobID] = call
		if hasID {
			byID[requestID] = jobID
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := RelayModernFrame(callCtx, conn, out, streams.Err, f.Body)
			stop()
			completed <- modernCompletion{key: jobID, err: err}
		}()
		return nil
	}
	startPending := func() error {
		for len(active) < modernBridgeWorkers && len(pending) > 0 {
			next, err := wire.Object(pending[0].Body)
			if err != nil {
				return command.ErrProtocol
			}
			method := wire.Text(next["method"])
			if method == "initialize" {
				return command.ErrProtocol
			}
			f := pending[0]
			pending = pending[1:]
			if err := launch(f); err != nil {
				return err
			}
		}
		return nil
	}
	removeCall := func(jobID string) *modernCall {
		call := active[jobID]
		delete(active, jobID)
		if call != nil && call.requestID != "" {
			delete(byID, call.requestID)
		}
		return call
	}
	cancelActive := func() {
		for _, call := range active {
			call.cancelled = true
			call.cancel()
		}
	}
	for {
		if err := startPending(); err != nil {
			return err
		}
		select {
		case <-root.Done():
			return root.Err()
		case err := <-terminal:
			if err != io.EOF {
				return command.ErrProtocol
			}
			// EOF ends admission and cancels all accepted streams. Queued
			// frames have not been sent, so they are discarded rather than
			// starting new work after input has terminated.
			pending = nil
			cancelActive()
			for len(active) > 0 {
				done := <-completed
				removeCall(done.key)
			}
			return nil
		case id := <-cancellations:
			key := modernIDKey(id)
			if jobID := byID[key]; jobID != "" {
				if call := active[jobID]; call != nil {
					call.cancelled = true
					call.cancel()
				}
				continue
			}
			for i := 0; i < len(pending); i++ {
				pendingID, ok := modernRequestKey(pending[i].Body)
				if ok && pendingID == key {
					pending = append(pending[:i], pending[i+1:]...)
					break
				}
			}
		case f := <-frames:
			_, parseErr := wire.Object(f.Body)
			if parseErr != nil {
				return command.ErrProtocol
			}
			key, hasID := modernRequestKey(f.Body)
			if hasID && (byID[key] != "" || pendingHasID(pending, key)) {
				return command.ErrProtocol
			}
			if len(active) < modernBridgeWorkers && len(pending) == 0 {
				if err := launch(f); err != nil {
					return err
				}
				continue
			}
			if len(pending) == modernBridgeWorkers {
				return command.ErrProtocol
			}
			pending = append(pending, f)
			if err := startPending(); err != nil {
				return err
			}
		case done := <-completed:
			call := removeCall(done.key)
			if call != nil {
				call.cancel()
				var aborted *modernStreamAbort
				if done.err != nil && errors.As(done.err, &aborted) {
					if err := startPending(); err != nil {
						return err
					}
					continue
				}
				if done.err != nil && !call.cancelled {
					return done.err
				}
			} else if done.err != nil {
				return done.err
			}
			if err := startPending(); err != nil {
				return err
			}
		}
	}
}

func pendingHasID(pending []Frame, key string) bool {
	for _, frame := range pending {
		if candidate, ok := modernRequestKey(frame.Body); ok && candidate == key {
			return true
		}
	}
	return false
}

func modernRequestKey(body []byte) (string, bool) {
	m, err := wire.Object(body)
	if err != nil || len(m["id"]) == 0 || !wire.ValidID(m["id"]) {
		return "", false
	}
	return modernIDKey(m["id"]), true
}

func modernIDKey(id json.RawMessage) string {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) != 0 && trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil {
			return "s:" + s
		}
	}
	var n int64
	if json.Unmarshal(trimmed, &n) == nil {
		return "n:" + strconv.FormatInt(n, 10)
	}
	return ""
}

func readModernFrames(ctx context.Context, in io.Reader, frames chan<- Frame, cancellations chan<- json.RawMessage, terminal chan<- error) {
	r := bufio.NewReaderSize(in, wire.MaxBody+1)
	for {
		b, err := r.ReadSlice('\n')
		if err != nil {
			if err == io.EOF && len(b) == 0 {
				select {
				case terminal <- io.EOF:
				case <-ctx.Done():
				}
				return
			}
			select {
			case terminal <- command.ErrProtocol:
			case <-ctx.Done():
			}
			return
		}
		if len(b)-1 > wire.MaxBody {
			select {
			case terminal <- command.ErrProtocol:
			case <-ctx.Done():
			}
			return
		}
		body := append([]byte(nil), b[:len(b)-1]...)
		m, parseErr := wire.Object(body)
		if parseErr != nil || wire.Text(m["jsonrpc"]) != "2.0" || wire.Text(m["method"]) == "" {
			select {
			case terminal <- command.ErrProtocol:
			case <-ctx.Done():
			}
			return
		}
		method := wire.Text(m["method"])
		if method == "notifications/cancelled" {
			p, e := wire.Object(m["params"])
			if e != nil || len(m["id"]) != 0 || !wire.ValidID(p["requestId"]) {
				select {
				case terminal <- command.ErrProtocol:
				case <-ctx.Done():
				}
				return
			}
			select {
			case cancellations <- append(json.RawMessage(nil), p["requestId"]...):
			case <-ctx.Done():
			}
			continue
		}
		if id, request := m["id"]; request && !wire.ValidID(id) || !request && !strings.HasPrefix(method, "notifications/") {
			select {
			case terminal <- command.ErrProtocol:
			case <-ctx.Done():
			}
			return
		}
		select {
		case frames <- Frame{Body: body}:
		case <-ctx.Done():
			return
		}
	}
}

// RelayModernFrame sends one modern request through the signed transport and
// exposes only a fully verified JSON-RPC reply or signed-stream frame.
func RelayModernFrame(ctx context.Context, c *transport.Connection, out io.Writer, stderr io.Writer, body []byte) error {
	m, err := wire.Object(body)
	method := wire.Text(m["method"])
	if err != nil || len(body) > wire.MaxBody || wire.Text(m["jsonrpc"]) != "2.0" || method == "" || len(m["result"]) != 0 || len(m["error"]) != 0 || method == "notifications/cancelled" {
		return command.ErrProtocol
	}
	id, request := m["id"]
	if request && !wire.ValidID(id) {
		return command.ErrProtocol
	}
	if !request && !strings.HasPrefix(method, "notifications/") {
		return command.ErrProtocol
	}
	if request && method == "initialize" {
		return command.ErrProtocol
	}
	if request && method == "tools/call" && strings.HasPrefix(nativeToolName(m), bridgeNativePrefix) {
		return writeModernFrame(ctx, out, bridgeNativeDenial(id))
	}
	if !request {
		_, status, err := c.Post(ctx, body)
		if err != nil {
			return err
		}
		if status != http.StatusAccepted {
			return command.ErrProtocol
		}
		return nil
	}
	stream, reply, err := c.OpenStream(ctx, body)
	if err != nil {
		return err
	}
	if stream != nil {
		defer stream.Close()
		for {
			message, nextErr := stream.Next()
			if nextErr == io.EOF {
				return nil
			}
			if nextErr != nil {
				var streamErr *clientstream.Error
				if errors.As(nextErr, &streamErr) && streamErr.Code == clientstream.BadFrame && strings.Contains(streamErr.Message, "raw CR or LF") {
					if stderr != nil {
						_, _ = io.WriteString(stderr, "jack: stream was aborted\n")
					}
					return &modernStreamAbort{cause: nextErr}
				}
				return nextErr
			}
			data := []byte(message)
			if len(data) > wire.MaxBody || bytes.ContainsAny(data, "\r\n") {
				if stderr != nil {
					_, _ = io.WriteString(stderr, "jack: stream was aborted\n")
				}
				return &modernStreamAbort{cause: command.ErrProtocol}
			}
			if _, err := wire.Object(data); err != nil {
				return command.ErrProtocol
			}
			if err := writeModernFrame(ctx, out, data); err != nil {
				return err
			}
		}
	}
	if reply == nil || reply.Status < 200 || reply.Status > 599 || bytes.ContainsRune(reply.Body, '\n') || len(reply.Body) > wire.MaxBody {
		return command.ErrProtocol
	}
	if _, err := wire.ResponseObject(reply.Body, id); err != nil {
		return err
	}
	if request && method == "initialize" {
		if reply.Status != http.StatusOK {
			return command.ErrProtocol
		}
		response, err := wire.Object(reply.Body)
		result, resultErr := wire.Object(response["result"])
		info, infoErr := wire.Object(result["serverInfo"])
		if err != nil || resultErr != nil || infoErr != nil || len(response["error"]) != 0 || wire.Text(result["protocolVersion"]) != "2026-07-28" || wire.Text(info["name"]) == "" || wire.Text(info["version"]) == "" {
			return command.ErrProtocol
		}
		if _, err := wire.Object(result["capabilities"]); err != nil {
			return command.ErrProtocol
		}
	}
	return writeModernFrame(ctx, out, reply.Body)
}
