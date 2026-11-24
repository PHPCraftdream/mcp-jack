package bridge

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

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/stdio"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

type Frame struct {
	Body []byte
}

// Admission is owned only by the main loop, never by the reader or worker.
// A full Pending slot disables normal Input, not completion or terminal Input.
type Admission struct {
	Busy    bool
	Pending *Frame
}

func (a *Admission) Input(frames <-chan Frame) <-chan Frame {
	if a.Pending != nil {
		return nil
	}
	return frames
}

// Accept is called only through Input. A Busy worker leaves one Pending Frame;
// otherwise the caller launches the returned Frame.
func (a *Admission) Accept(f Frame) *Frame {
	if a.Busy {
		a.Pending = &f
		return nil
	}
	return &f
}

func ReadFrames(ctx context.Context, in io.Reader, frames chan<- Frame, terminal chan<- error) {
	r := bufio.NewReaderSize(in, wire.MaxBody+1)
	for {
		b, err := r.ReadSlice('\n')
		if err == nil {
			if len(b)-1 > wire.MaxBody {
				err = command.ErrProtocol
			} else {
				b = append([]byte(nil), b[:len(b)-1]...)
				m, parseErr := wire.Object(b)
				if parseErr != nil || wire.Text(m["method"]) == "notifications/cancelled" {
					err = command.ErrProtocol
				}
			}
		} else if err != io.EOF || len(b) != 0 {
			err = command.ErrProtocol
		}
		if err != nil {
			// Exactly one terminal event, independently of normal admission.
			select {
			case terminal <- err:
			case <-ctx.Done():
			}
			return
		}
		// Hold at most this ordinary Frame. Later controls remain unread until
		// it is admitted; the existing bufio capacity is unchanged.
		select {
		case frames <- Frame{Body: b}:
		case <-ctx.Done():
			return
		}
	}
}

func Run(ctx context.Context, configPath string, streams stdio.IO) error {
	return RunWithObserver(ctx, configPath, streams, nil)
}

// bridgeRuntime holds the mutable state shared by the relay loop and its
// launched workers. Owned only by the loop goroutine.
type bridgeRuntime struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      *transport.Connection
	streams   stdio.IO
	completed chan error
	workers   sync.WaitGroup
	admission Admission
	state     int
	timer     *time.Timer
}

// startBridgeReader spawns the Frame reader and returns the channels it feeds.
func startBridgeReader(ctx context.Context, in io.Reader, workers *sync.WaitGroup) (<-chan Frame, <-chan error) {
	frames := make(chan Frame)
	terminal := make(chan error)
	workers.Add(1)
	go func() {
		defer workers.Done()
		ReadFrames(ctx, in, frames, terminal)
	}()
	return frames, terminal
}

// reset restarts the idle timer, draining any Pending tick first.
func (r *bridgeRuntime) reset() {
	if !r.timer.Stop() {
		select {
		case <-r.timer.C:
		default:
		}
	}
	r.timer.Reset(r.conn.Timeout)
}

// launch marks admission Busy and relays one Frame in a tracked worker.
func (r *bridgeRuntime) launch(b []byte) {
	r.admission.Busy = true
	r.reset()
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		callCtx, stop := context.WithTimeout(r.ctx, r.conn.Timeout)
		defer stop()
		r.completed <- RelayFrame(callCtx, r.conn, r.streams.Out, b, &r.state)
	}()
}

// relayLoop admits Input and dispatches workers until a terminal event, the
// idle timer, or cancellation ends the bridge. The observer, when present, sees
// the ordinary-Input candidate immediately before each select and must not
// block or mutate admission.
func (r *bridgeRuntime) relayLoop(frames <-chan Frame, terminal <-chan error, observe func(<-chan Frame, Admission)) error {
	for {
		if !r.admission.Busy && r.admission.Pending != nil {
			r.launch(r.admission.Pending.Body)
			r.admission.Pending = nil
		}
		Input := r.admission.Input(frames)
		if observe != nil {
			observe(Input, r.admission)
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-r.timer.C:
			return context.DeadlineExceeded
		case err := <-terminal:
			if err != io.EOF || r.admission.Pending != nil {
				return command.ErrProtocol
			}
			if r.admission.Busy {
				// A finished write may beat EOF, but EOF with an accepted
				// Pending Frame must fail even if the worker returns nil.
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
		case f := <-Input:
			if next := r.admission.Accept(f); next != nil {
				r.launch(next.Body)
			}
		case err := <-r.completed:
			r.admission.Busy = false
			if err != nil {
				return err
			}
			r.reset()
		}
	}
}

// RunWithObserver runs the same loop as bridge. The optional internal observer
// sees the evaluated ordinary-Input candidate immediately before the select;
// it must not block or mutate admission. Production callers pass nil.
func RunWithObserver(ctx context.Context, configPath string, streams stdio.IO, observe func(<-chan Frame, Admission)) error {
	if streams.In == nil || streams.Out == nil {
		return command.ErrConfig
	}
	defer streams.In.Close()
	defer streams.Out.Close()
	conn, err := transport.LoadConnection(configPath)
	if err != nil {
		return err
	}
	if conn.Era == "auto" {
		if err := probeBridgeEra(ctx, conn); err != nil {
			return err
		}
	}
	if conn.Era == "modern" {
		return runModernBridge(ctx, conn, streams)
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &bridgeRuntime{ctx: ctx, cancel: cancel, conn: conn, streams: streams, completed: make(chan error, 1), timer: time.NewTimer(conn.Timeout)}
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

func RelayFrame(ctx context.Context, c *transport.Connection, out io.Writer, b []byte, state *int) error {
	m, err := wire.Object(b)
	method := wire.Text(m["method"])
	if err != nil || wire.Text(m["jsonrpc"]) != "2.0" || method == "" || len(m["result"]) != 0 || len(m["error"]) != 0 || method == "notifications/cancelled" {
		return command.ErrProtocol
	}
	id, request := m["id"]
	if request && !wire.ValidID(id) {
		return command.ErrProtocol
	}
	if !request && !bytes.HasPrefix([]byte(method), []byte("notifications/")) {
		return command.ErrProtocol
	}
	if *state == 0 {
		params, e := wire.Object(m["params"])
		if !request || method != "initialize" || e != nil || wire.Text(params["protocolVersion"]) != wire.ProtocolVersion {
			return command.ErrProtocol
		}
		if _, e := wire.Object(params["capabilities"]); e != nil {
			return command.ErrProtocol
		}
		info, e := wire.Object(params["clientInfo"])
		if e != nil || wire.Text(info["name"]) == "" || wire.Text(info["version"]) == "" {
			return command.ErrProtocol
		}
	} else if *state == 1 {
		if request || method != "notifications/initialized" {
			return command.ErrProtocol
		}
	} else if method == "initialize" || method == "notifications/initialized" {
		return command.ErrProtocol
	}
	// Native jack.* tools are answered locally: a stdio client must not gain
	// signed access to enrollment or administration through the bridge.
	if request && method == "tools/call" && strings.HasPrefix(nativeToolName(m), bridgeNativePrefix) {
		return writeReply(ctx, out, bridgeNativeDenial(id))
	}
	reply, status, err := c.Post(ctx, b)
	if err != nil {
		return err
	}
	if !request {
		if status != 202 || len(reply) != 0 {
			return command.ErrProtocol
		}
		if *state == 1 {
			*state = 2
		}
		return nil
	}
	if status != 200 || bytes.ContainsRune(reply, '\n') {
		return command.ErrProtocol
	}
	resp, err := wire.ResponseObject(reply, id)
	if err != nil {
		return err
	}
	if *state == 0 {
		result, e := wire.Object(resp["result"])
		if e != nil || wire.Text(result["protocolVersion"]) != wire.ProtocolVersion || len(resp["error"]) != 0 {
			return command.ErrProtocol
		}
		if _, e := wire.Object(result["capabilities"]); e != nil {
			return command.ErrProtocol
		}
		info, e := wire.Object(result["serverInfo"])
		if e != nil || wire.Text(info["name"]) == "" || wire.Text(info["version"]) == "" {
			return command.ErrProtocol
		}
		*state = 1
	}
	return writeReply(ctx, out, reply)
}

// writeReply appends the framing LF and writes the whole Frame. Every reply,
// relayed or produced locally, uses this path while its worker owns admission.
func writeReply(ctx context.Context, out io.Writer, reply []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	frame := append(append([]byte(nil), reply...), '\n')
	for len(frame) != 0 {
		n, err := out.Write(frame)
		if err != nil || n <= 0 {
			return command.ErrProtocol
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
	params, err := wire.Object(m["params"])
	if err != nil {
		return ""
	}
	return wire.Text(params["name"])
}

// bridgeNativeDenial builds the single-line local error response with the
// original id. Arguments are never echoed.
func bridgeNativeDenial(id json.RawMessage) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + string(bytes.TrimSpace(id)) +
		`,"error":{"code":` + strconv.Itoa(bridgeNativeDenialCode) +
		`,"message":` + strconv.Quote(bridgeNativeDenialMessage) + `}}`)
}
