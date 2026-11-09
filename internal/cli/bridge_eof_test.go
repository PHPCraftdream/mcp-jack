//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pendingEOFReader struct {
	step        int
	terminal    string
	terminalErr error
	writing     <-chan struct{}
	closed      chan struct{}
	once        sync.Once
}

func (r *pendingEOFReader) Read(p []byte) (int, error) {
	r.step++
	switch r.step {
	case 1:
		return copy(p, initializeFrame+"\n"), nil
	case 2:
		return copy(p, initializedFrame+"\n"), nil
	default:
		select {
		case <-r.writing:
			if r.step > 3 {
				return 0, io.EOF
			}
			if r.terminal != "" {
				return copy(p, r.terminal), nil
			}
			if r.terminalErr != nil {
				return 0, r.terminalErr
			}
			return 0, io.EOF
		case <-r.closed:
			return 0, io.ErrClosedPipe
		}
	}
}

func (r *pendingEOFReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

type successfulCloseWriter struct {
	writing   chan struct{}
	closed    chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
}

func (w *successfulCloseWriter) Write(p []byte) (int, error) {
	w.writeOnce.Do(func() { close(w.writing) })
	<-w.closed
	return len(p), nil
}

func (w *successfulCloseWriter) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

func TestBridgePendingEOFEvenIfWorkerReturnsNil(t *testing.T) {
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, initializeReply)
	}))
	out := &successfulCloseWriter{writing: make(chan struct{}), closed: make(chan struct{})}
	in := &pendingEOFReader{writing: out.writing, closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bridge(ctx, path, IO{In: in, Out: out, Err: io.Discard}) }()
	select {
	case err := <-done:
		if !errors.Is(err, errProtocol) {
			t.Fatal("pending frame was discarded with successful worker EOF")
		}
	case <-ctx.Done():
		_ = in.Close()
		_ = out.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("pending EOF worker failed to join")
		}
		t.Fatal("pending EOF cleanup exceeded deadline")
	}
}

// This unit check covers admission transitions, not production select wiring.
// TestBridgeAdmissionSelectCheckpointSignedHTTP checks the actual loop candidate.
func TestBridgeAdmissionFullPendingDisablesOnlyNormalInput(t *testing.T) {
	frames := make(chan frame)
	a := bridgeAdmission{busy: true}
	if a.input(frames) != frames {
		t.Fatal("empty pending slot must admit input")
	}
	if next := a.accept(frame{body: []byte(initializedFrame)}); next != nil || a.pending == nil || string(a.pending.body) != initializedFrame {
		t.Fatal("initialized must occupy the pending slot while initialize completes")
	}
	if a.input(frames) != nil {
		t.Fatal("full pending slot must disable the ordinary receive, not reject read-ahead")
	}
	// Both candidates are ready without scheduling another goroutine. The
	// production channel gate must leave only completion selectable. Buffers
	// here supply deterministic test events, not a production input queue.
	ready := make(chan frame, 1)
	ready <- frame{body: []byte(admissionToolsFrame)}
	completed := make(chan error, 1)
	completed <- nil
	select {
	case <-a.input(ready):
		t.Fatal("normal input selected with full pending slot")
	case <-completed:
	default:
		t.Fatal("worker completion was not serviceable")
	}
	if len(ready) != 1 || string(a.pending.body) != initializedFrame {
		t.Fatal("completion lost or reordered the bounded read-ahead")
	}
	terminal := make(chan error, 1)
	terminal <- io.EOF
	select {
	case <-a.input(ready):
		t.Fatal("normal input bypassed pending before terminal observation")
	case err := <-terminal:
		if err != io.EOF {
			t.Fatal("terminal input changed")
		}
	default:
		t.Fatal("terminal input was not serviceable")
	}
	// Even a consumed completion cannot reopen input ahead of pending dispatch.
	a.busy = false
	if a.input(frames) != nil {
		t.Fatal("completion must not let tools/list overtake pending initialized")
	}
	a.pending = nil
	if a.input(frames) != frames {
		t.Fatal("dispatch must restore ordinary admission")
	}
}

type admissionReadAheadReader struct {
	step      int
	observed  <-chan struct{}
	readAhead chan struct{}
	closed    chan struct{}
	once      sync.Once
}

const admissionToolsFrame = ` {"jsonrpc":"2.0","id":2,"method":"tools/list"} `
const admissionToolsReply = `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`

func (r *admissionReadAheadReader) Read(p []byte) (int, error) {
	r.step++
	switch r.step {
	case 1:
		return copy(p, initializeFrame+"\n"), nil
	case 2:
		// The peer has consumed every initialize response byte before sending
		// either subsequent frame; the output Write has NOT returned yet.
		select {
		case <-r.observed:
		case <-r.closed:
			return 0, io.ErrClosedPipe
		}
		return copy(p, initializedFrame+"\n"), nil
	case 3:
		// readFrames cannot call Read again until its unbuffered initialized
		// send is received by main. Copy the complete tools frame into bufio's
		// supplied buffer before signaling. This is a raw-read checkpoint,
		// not evidence that Read has returned or tools has been parsed/sent.
		n := copy(p, admissionToolsFrame+"\n")
		close(r.readAhead)
		return n, nil
	default:
		<-r.closed
		return 0, io.EOF
	}
}

func (r *admissionReadAheadReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

type admissionHeldOutput struct {
	frames  chan string
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *admissionHeldOutput) Write(p []byte) (int, error) {
	select {
	case w.frames <- string(p):
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	if string(p) == initializeReply+"\n" {
		select {
		case <-w.release:
		case <-w.closed:
			return 0, io.ErrClosedPipe
		}
	}
	return len(p), nil
}

func (w *admissionHeldOutput) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

func TestBridgeAdmissionReadAheadSignedHTTP(t *testing.T) {
	testBridgeAdmissionReadAheadSignedHTTP(t, false)
}

func TestBridgeAdmissionSelectCheckpointSignedHTTP(t *testing.T) {
	testBridgeAdmissionReadAheadSignedHTTP(t, true)
}

func testBridgeAdmissionReadAheadSignedHTTP(t *testing.T, observeSelect bool) {
	var mu sync.Mutex
	var calls []string
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("request body read failed")
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		calls = append(calls, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch string(b) {
		case initializeFrame:
			_, _ = io.WriteString(w, initializeReply)
		case initializedFrame:
			w.WriteHeader(202)
		case admissionToolsFrame:
			_, _ = io.WriteString(w, admissionToolsReply)
		default:
			t.Error("unexpected request bytes")
			w.WriteHeader(400)
		}
	}))
	observed := make(chan struct{})
	in := &admissionReadAheadReader{observed: observed, readAhead: make(chan struct{}), closed: make(chan struct{})}
	out := &admissionHeldOutput{frames: make(chan string, 4), release: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	type checkpoint struct {
		input   <-chan frame
		busy    bool
		pending string
	}
	// One event, buffered once: observing main must never hold up its select
	// or the worker. No production queue or public IO/API hook is introduced.
	checkpoints := make(chan checkpoint, 1)
	type result struct {
		code   int
		stderr string
		err    error
	}
	done := make(chan result, 1)
	joined := false
	defer func() {
		cancel()
		_ = in.Close()
		_ = out.Close()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("read-ahead Run cleanup did not join")
			}
		}
	}()
	go func() {
		if observeSelect {
			reported := false
			observe := func(input <-chan frame, a bridgeAdmission) {
				if !reported && a.pending != nil {
					reported = true
					checkpoints <- checkpoint{input: input, busy: a.busy, pending: string(a.pending.body)}
				}
			}
			done <- result{err: bridgeWithObserver(ctx, path, IO{In: in, Out: out, Err: io.Discard}, observe)}
			return
		}
		var stderr bytes.Buffer
		code := Run(ctx, []string{"bridge", "--config", path}, IO{In: in, Out: out, Err: &stderr})
		done <- result{code: code, stderr: stderr.String()}
	}()
	if got := receiveTest(t, out.frames); got != initializeReply+"\n" {
		t.Fatalf("initialize output=%q", got)
	}
	close(observed)
	receiveTest(t, in.readAhead)
	if observeSelect {
		c := receiveTest(t, checkpoints)
		if !c.busy || c.pending != initializedFrame || c.input != nil {
			t.Fatalf("held initialize select: busy=%v pending=%q input=%v; want full pending and nil input", c.busy, c.pending, c.input)
		}
		// This is the actual candidate computed by main and used by its next
		// select, not admission.input tested in isolation. Replacing that
		// candidate with unconditional frames makes input nonnil regardless
		// of scheduling or any old inline-completion path. Both this full-slot
		// checkpoint and the copied tools bytes precede releasing Write.
	}
	// The default Run case retains its production nil-observer path. Neither
	// case claims that the raw-read signal proves tools has been parsed.
	close(out.release)
	if got := receiveTest(t, out.frames); got != admissionToolsReply+"\n" {
		t.Fatalf("tools output=%q", got)
	}
	_ = in.Close()
	r := receiveTest(t, done)
	joined = true
	if r.err != nil || r.code != 0 || r.stderr != "" || len(out.frames) != 0 {
		t.Fatalf("bridge err=%v Run code=%d stderr=%q extra responses=%d", r.err, r.code, r.stderr, len(out.frames))
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{initializeFrame, initializedFrame, admissionToolsFrame}
	if len(calls) != len(want) {
		t.Fatalf("calls=%q; expected exactly three, no retry", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("HTTP call %d=%q want=%q", i, calls[i], want[i])
		}
	}
}

func TestBridgeReaderReadAheadCancellationJoins(t *testing.T) {
	// After receiving initialize and initialized, leave tools/list unreceived
	// and cancel: readFrames must join without an abandoned ordinary send.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan struct{})
	close(observed)
	in := &admissionReadAheadReader{observed: observed, readAhead: make(chan struct{}), closed: make(chan struct{})}
	defer in.Close()
	frames := make(chan frame)
	terminal := make(chan error)
	done := make(chan struct{})
	defer func() {
		cancel()
		_ = in.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("read-ahead reader cleanup failed to join")
		}
	}()
	go func() {
		readFrames(ctx, in, frames, terminal)
		close(done)
	}()
	if f := receiveTest(t, frames); string(f.body) != initializeFrame {
		t.Fatal("first reader frame changed")
	}
	if f := receiveTest(t, frames); string(f.body) != initializedFrame {
		t.Fatal("second reader frame changed")
	}
	receiveTest(t, in.readAhead)
	cancel()
	receiveTest(t, done)
}

func TestBridgeFullPendingContextCancellationJoins(t *testing.T) {
	var calls atomic.Int32
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, initializeReply)
	}))
	out := &successfulCloseWriter{writing: make(chan struct{}), closed: make(chan struct{})}
	in := &admissionReadAheadReader{observed: out.writing, readAhead: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		_ = in.Close()
		_ = out.Close()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("full pending cancellation cleanup failed to join")
			}
		}
	}()
	go func() { done <- bridge(ctx, path, IO{In: in, Out: out}) }()
	// Initialized has been received by main; the writer cannot complete until
	// bridge cleanup closes it. No EOF/control is sent by this reader here.
	receiveTest(t, in.readAhead)
	cancel()
	err := receiveTest(t, done)
	joined = true
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("full pending cancellation err=%v calls=%d", err, calls.Load())
	}
}

func TestBridgePendingControlsWhileWriterHeld(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		err         error
	}{
		{"malformed", "[]\n", nil},
		{"truncated", "{", nil},
		{"read-error", "", io.ErrUnexpectedEOF},
		{"unsupported-cancellation", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"init"}}` + "\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, initializeReply)
			}))
			out := &successfulCloseWriter{writing: make(chan struct{}), closed: make(chan struct{})}
			in := &pendingEOFReader{writing: out.writing, terminal: tc.input, terminalErr: tc.err, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			joined := false
			defer func() {
				cancel()
				_ = in.Close()
				_ = out.Close()
				if !joined {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("pending control cleanup failed to join")
					}
				}
			}()
			go func() { done <- bridge(ctx, path, IO{In: in, Out: out}) }()
			err := receiveTest(t, done)
			joined = true
			if !errors.Is(err, errProtocol) || calls.Load() != 1 {
				t.Fatalf("pending control err=%v calls=%d", err, calls.Load())
			}
		})
	}
}
