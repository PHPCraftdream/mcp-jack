//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

type pendingEOFReader struct {
	step    int
	writing <-chan struct{}
	closed  chan struct{}
	once    sync.Once
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
