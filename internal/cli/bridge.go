package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
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
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = streams.In.Close()
		_ = streams.Out.Close()
		workers.Wait()
	}()
	frames := make(chan frame)
	terminal := make(chan error)
	workers.Add(1)
	go func() {
		defer workers.Done()
		readFrames(ctx, streams.In, frames, terminal)
	}()
	completed := make(chan error, 1)
	admission := bridgeAdmission{}
	state := 0
	timer := time.NewTimer(conn.timeout)
	defer timer.Stop()
	reset := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(conn.timeout)
	}
	launch := func(b []byte) {
		admission.busy = true
		reset()
		workers.Add(1)
		go func() {
			defer workers.Done()
			callCtx, stop := context.WithTimeout(ctx, conn.timeout)
			defer stop()
			completed <- relayFrame(callCtx, conn, streams.Out, b, &state)
		}()
	}
	for {
		if !admission.busy && admission.pending != nil {
			launch(admission.pending.body)
			admission.pending = nil
		}
		input := admission.input(frames)
		if observe != nil {
			observe(input, admission)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return context.DeadlineExceeded
		case err := <-terminal:
			if err != io.EOF || admission.pending != nil {
				return errProtocol
			}
			if admission.busy {
				// A finished write may beat EOF, but EOF with an accepted
				// pending frame must fail even if the worker returns nil.
				select {
				case err := <-completed:
					return err
				default:
				}
				cancel()
				_ = streams.Out.Close()
				return <-completed
			}
			return nil
		case f := <-input:
			if next := admission.accept(f); next != nil {
				launch(next.body)
			}
		case err := <-completed:
			admission.busy = false
			if err != nil {
				return err
			}
			reset()
		}
	}
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
