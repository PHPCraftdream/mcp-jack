package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

type frame struct {
	body []byte
}

// bridgeAdmission is owned only by the main loop, never by the reader or worker.
// A full pending slot disables normal input, not completion or terminal input.
type bridgeAdmission struct {
	busy    bool
	pending *frame
}

func (a *bridgeAdmission) input(frames <-chan frame) <-chan frame {
	if a.pending != nil {
		return nil
	}
	return frames
}

// accept is called only through input. A busy worker leaves one pending frame;
// otherwise the caller launches the returned frame.
func (a *bridgeAdmission) accept(f frame) *frame {
	if a.busy {
		a.pending = &f
		return nil
	}
	return &f
}

func readFrames(ctx context.Context, in io.Reader, frames chan<- frame, terminal chan<- error) {
	r := bufio.NewReaderSize(in, maxBody+1)
	for {
		b, err := r.ReadSlice('\n')
		if err == nil {
			if len(b)-1 > maxBody {
				err = errProtocol
			} else {
				b = append([]byte(nil), b[:len(b)-1]...)
				m, parseErr := object(b)
				if parseErr != nil || text(m["method"]) == "notifications/cancelled" {
					err = errProtocol
				}
			}
		} else if err != io.EOF || len(b) != 0 {
			err = errProtocol
		}
		if err != nil {
			// Exactly one terminal event, independently of normal admission.
			select {
			case terminal <- err:
			case <-ctx.Done():
			}
			return
		}
		// Hold at most this ordinary frame. Later controls remain unread until
		// it is admitted; the existing bufio capacity is unchanged.
		select {
		case frames <- frame{body: b}:
		case <-ctx.Done():
			return
		}
	}
}

func bridge(ctx context.Context, configPath string, streams IO) error {
	return bridgeWithObserver(ctx, configPath, streams, nil)
}

// bridgeRuntime holds the mutable state shared by the relay loop and its
// launched workers. Owned only by the loop goroutine.
type bridgeRuntime struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      *connection
	streams   IO
	completed chan error
	workers   sync.WaitGroup
	admission bridgeAdmission
	state     int
	timer     *time.Timer
}

// startBridgeReader spawns the frame reader and returns the channels it feeds.
func startBridgeReader(ctx context.Context, in io.Reader, workers *sync.WaitGroup) (<-chan frame, <-chan error) {
	frames := make(chan frame)
	terminal := make(chan error)
	workers.Add(1)
	go func() {
		defer workers.Done()
		readFrames(ctx, in, frames, terminal)
	}()
	return frames, terminal
}

// reset restarts the idle timer, draining any pending tick first.
func (r *bridgeRuntime) reset() {
	if !r.timer.Stop() {
		select {
		case <-r.timer.C:
		default:
		}
	}
	r.timer.Reset(r.conn.timeout)
}

// launch marks admission busy and relays one frame in a tracked worker.
func (r *bridgeRuntime) launch(b []byte) {
	r.admission.busy = true
	r.reset()
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		callCtx, stop := context.WithTimeout(r.ctx, r.conn.timeout)
		defer stop()
		r.completed <- relayFrame(callCtx, r.conn, r.streams.Out, b, &r.state)
	}()
}

// relayLoop admits input and dispatches workers until a terminal event, the
// idle timer, or cancellation ends the bridge. The observer, when present, sees
// the ordinary-input candidate immediately before each select and must not
// block or mutate admission.
func (r *bridgeRuntime) relayLoop(frames <-chan frame, terminal <-chan error, observe func(<-chan frame, bridgeAdmission)) error {
	for {
		if !r.admission.busy && r.admission.pending != nil {
			r.launch(r.admission.pending.body)
			r.admission.pending = nil
		}
		input := r.admission.input(frames)
		if observe != nil {
			observe(input, r.admission)
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-r.timer.C:
			return context.DeadlineExceeded
		case err := <-terminal:
			if err != io.EOF || r.admission.pending != nil {
				return errProtocol
			}
			if r.admission.busy {
				// A finished write may beat EOF, but EOF with an accepted
				// pending frame must fail even if the worker returns nil.
				select {
				case err := <-r.completed:
					return err
				default:
				}
				r.cancel()
				_ = r.streams.Out.Close()
				return <-r.completed
			}
			return nil
		case f := <-input:
			if next := r.admission.accept(f); next != nil {
				r.launch(next.body)
			}
		case err := <-r.completed:
			r.admission.busy = false
			if err != nil {
				return err
			}
			r.reset()
		}
	}
}

// bridgeWithObserver runs the same loop as bridge. The optional internal observer
// sees the evaluated ordinary-input candidate immediately before the select;
// it must not block or mutate admission. Production callers pass nil.
func bridgeWithObserver(ctx context.Context, configPath string, streams IO, observe func(<-chan frame, bridgeAdmission)) error {
	if streams.In == nil || streams.Out == nil {
		return errConfig
	}
	defer streams.In.Close()
	defer streams.Out.Close()
	conn, err := loadConnection(configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &bridgeRuntime{ctx: ctx, cancel: cancel, conn: conn, streams: streams, completed: make(chan error, 1), timer: time.NewTimer(conn.timeout)}
	defer func() {
		cancel()
		_ = streams.In.Close()
		_ = streams.Out.Close()
		r.workers.Wait()
	}()
	defer r.timer.Stop()
	frames, terminal := startBridgeReader(ctx, streams.In, &r.workers)
	return r.relayLoop(frames, terminal, observe)
}

func relayFrame(ctx context.Context, c *connection, out io.Writer, b []byte, state *int) error {
	m, err := object(b)
	method := text(m["method"])
	if err != nil || text(m["jsonrpc"]) != "2.0" || method == "" || len(m["result"]) != 0 || len(m["error"]) != 0 || method == "notifications/cancelled" {
		return errProtocol
	}
	id, request := m["id"]
	if request && !validID(id) {
		return errProtocol
	}
	if !request && !bytes.HasPrefix([]byte(method), []byte("notifications/")) {
		return errProtocol
	}
	if *state == 0 {
		params, e := object(m["params"])
		if !request || method != "initialize" || e != nil || text(params["protocolVersion"]) != protocolVersion {
			return errProtocol
		}
		if _, e := object(params["capabilities"]); e != nil {
			return errProtocol
		}
		info, e := object(params["clientInfo"])
		if e != nil || text(info["name"]) == "" || text(info["version"]) == "" {
			return errProtocol
		}
	} else if *state == 1 {
		if request || method != "notifications/initialized" {
			return errProtocol
		}
	} else if method == "initialize" || method == "notifications/initialized" {
		return errProtocol
	}
	// Native jack.* tools are answered locally: a stdio client must not gain
	// signed access to enrollment or administration through the bridge.
	if request && method == "tools/call" && strings.HasPrefix(nativeToolName(m), bridgeNativePrefix) {
		return writeReply(ctx, out, bridgeNativeDenial(id))
	}
	reply, status, err := c.post(ctx, b)
	if err != nil {
		return err
	}
	if !request {
		if status != 202 || len(reply) != 0 {
			return errProtocol
		}
		if *state == 1 {
			*state = 2
		}
		return nil
	}
	if status != 200 || bytes.ContainsRune(reply, '\n') {
		return errProtocol
	}
	resp, err := responseObject(reply, id)
	if err != nil {
		return err
	}
	if *state == 0 {
		result, e := object(resp["result"])
		if e != nil || text(result["protocolVersion"]) != protocolVersion || len(resp["error"]) != 0 {
			return errProtocol
		}
		if _, e := object(result["capabilities"]); e != nil {
			return errProtocol
		}
		info, e := object(result["serverInfo"])
		if e != nil || text(info["name"]) == "" || text(info["version"]) == "" {
			return errProtocol
		}
		*state = 1
	}
	return writeReply(ctx, out, reply)
}

// writeReply appends the framing LF and writes the whole frame. Every reply,
// relayed or produced locally, uses this path while its worker owns admission.
func writeReply(ctx context.Context, out io.Writer, reply []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame := append(append([]byte(nil), reply...), '\n')
	for len(frame) != 0 {
		n, err := out.Write(frame)
		if err != nil || n <= 0 {
			return errProtocol
		}
		frame = frame[n:]
	}
	return nil
}

// Native jack.* tools belong to the dedicated CLI commands, not to the bridge.
const (
	bridgeNativePrefix        = "jack."
	bridgeNativeDenialCode    = -32602
	bridgeNativeDenialMessage = "native jack tools are not available through the bridge"
)

// nativeToolName extracts params.name only when params is an object and the
// name is a JSON string; any other shape is forwarded unchanged so the gateway
// keeps rejecting it exactly as before.
func nativeToolName(m map[string]json.RawMessage) string {
	params, err := object(m["params"])
	if err != nil {
		return ""
	}
	return text(params["name"])
}

// bridgeNativeDenial builds the single-line local error response with the
// original id. Arguments are never echoed.
func bridgeNativeDenial(id json.RawMessage) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + string(bytes.TrimSpace(id)) +
		`,"error":{"code":` + strconv.Itoa(bridgeNativeDenialCode) +
		`,"message":` + strconv.Quote(bridgeNativeDenialMessage) + `}}`)
}
