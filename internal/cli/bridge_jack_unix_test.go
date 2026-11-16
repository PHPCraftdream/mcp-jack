//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// denialScriptReader feeds a fixed frame script, then blocks until Close so
// the run loop sees a clean EOF only when the test chooses.
type denialScriptReader struct {
	frames []string
	step   int
	closed chan struct{}
	once   sync.Once
}

func (r *denialScriptReader) Read(p []byte) (int, error) {
	if r.step < len(r.frames) {
		n := copy(p, r.frames[r.step])
		r.step++
		return n, nil
	}
	<-r.closed
	return 0, io.EOF
}

func (r *denialScriptReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

// denialRecordingWriter hands every written frame to the test in order.
type denialRecordingWriter struct {
	frames chan string
	closed chan struct{}
	once   sync.Once
}

func (w *denialRecordingWriter) Write(p []byte) (int, error) {
	select {
	case w.frames <- string(p):
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (w *denialRecordingWriter) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

// The full run loop must answer a native jack.* tool locally without breaking
// admission, ordering or the terminal path: exactly initialize reply, local
// refusal, ordinary reply on stdout, and only the ordinary frames forwarded.
func TestBridgeRefusesNativeJackToolThroughRunLoop(t *testing.T) {
	const enrollCall = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jack.enroll","arguments":{"code":"QUI","name":"ghost","public_key":"AA"}}}`
	const echoCall = `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	const echoReply = `{"jsonrpc":"2.0","id":4,"result":{"ok":true}}`
	var mu sync.Mutex
	var calls []string
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("request body read failed")
			w.WriteHeader(http.StatusBadRequest)
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
			w.WriteHeader(http.StatusAccepted)
		case echoCall:
			_, _ = io.WriteString(w, echoReply)
		default:
			t.Errorf("unexpected forwarded frame %q", b)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	in := &denialScriptReader{frames: []string{
		initializeFrame + "\n",
		initializedFrame + "\n",
		enrollCall + "\n",
		echoCall + "\n",
	}, closed: make(chan struct{})}
	out := &denialRecordingWriter{frames: make(chan string, 4), closed: make(chan struct{})}
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
				t.Error("native refusal run failed to join")
			}
		}
	}()
	go func() { done <- bridge(ctx, path, IO{In: in, Out: out, Err: io.Discard}) }()
	if got := receiveTest(t, out.frames); got != initializeReply+"\n" {
		t.Fatalf("initialize output=%q", got)
	}
	assertLocalDenial(t, "enroll", enrollCall, receiveTest(t, out.frames))
	if got := receiveTest(t, out.frames); got != echoReply+"\n" {
		t.Fatalf("echo output=%q", got)
	}
	_ = in.Close()
	if err := receiveTest(t, done); err != nil {
		t.Fatalf("bridge err=%v", err)
	}
	joined = true
	mu.Lock()
	defer mu.Unlock()
	want := []string{initializeFrame, initializedFrame, echoCall}
	if len(calls) != len(want) {
		t.Fatalf("calls=%q; expected exactly three forwarded frames", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("HTTP call %d=%q want=%q", i, calls[i], want[i])
		}
	}
}
