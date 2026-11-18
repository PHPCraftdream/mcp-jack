//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Package clitest provides shared POSIX stream, socket, and frame helpers for
// the internal/cli tests.
package clitest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const InitializeFrame = ` {"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}} `
const InitializeReply = `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`
const InitializedFrame = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

type AdminTestOutput struct {
	bytes.Buffer
	Closed bool
}

func (output *AdminTestOutput) Close() error { output.Closed = true; return nil }

func WriteInput(t *testing.T, in io.Writer, value string) {
	t.Helper()
	if n, err := io.WriteString(in, value); err != nil || n != len(value) {
		t.Fatal("lifecycle input write failed")
	}
}

func Receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatal("parent fixture synchronization timed out")
		var zero T
		return zero
	}
}

func WouldBlock(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}
func UnixUpstream(t *testing.T, h http.Handler) string {
	t.Helper()
	d, err := os.MkdirTemp("", "jack-cli-")
	if err != nil {
		t.Fatal(err)
	}
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "mcp.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { _ = s.Serve(l); close(done) }()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Unix fixture server did not stop")
		}
	})
	return p
}
