package main

// Jack bridge child process: spawn `jack bridge --config <path>`, pass
// stdio through the SDK transport, count bridge stdout bytes, keep a
// bounded (2000 char) stderr tail, and record the exit code (null if killed).

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	stderrTailLimit = 2000
	bridgeWaitQuit  = 5 * time.Second
)

type tailBuffer struct {
	mu   sync.Mutex
	tail []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.tail = append(t.tail, p...)
	if len(t.tail) > stderrTailLimit {
		t.tail = t.tail[len(t.tail)-stderrTailLimit:]
	}
	t.mu.Unlock()
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.tail)
}

type countingReader struct {
	r     io.ReadCloser
	bytes int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.bytes += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }

type bridgeProc struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *countingReader
	stderr  tailBuffer
	mu      sync.Mutex
	exit    *int
	waitErr error
	done    chan struct{}
}

// startBridge spawns exactly `jack bridge --config <path>`.
func startBridge(bin, configPath string) (*bridgeProc, error) {
	cmd := exec.Command(bin, "bridge", "--config", configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	b := &bridgeProc{done: make(chan struct{})}
	cmd.Stderr = &b.stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn jack bridge: %w", err)
	}
	b.cmd = cmd
	b.stdin = stdin
	b.stdout = &countingReader{r: stdout}
	go func() {
		err := cmd.Wait()
		b.mu.Lock()
		b.waitErr = err
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			code := cmd.ProcessState.ExitCode()
			b.exit = &code
		}
		b.mu.Unlock()
		close(b.done)
	}()
	return b, nil
}

// transport wraps the child stdio pipes as the official SDK IOTransport.
func (b *bridgeProc) transport() mcp.Transport {
	return &mcp.IOTransport{Reader: b.stdout, Writer: b.stdin}
}

// stop closes the child stdin and reaps it, recording the exit code.
func (b *bridgeProc) stop() {
	_ = b.stdin.Close()
	select {
	case <-b.done:
	case <-time.After(bridgeWaitQuit):
		if b.cmd.Process != nil {
			_ = b.cmd.Process.Kill()
		}
		<-b.done
	}
}

// info reports the bridge fields required in the result record.
func (b *bridgeProc) info() bridgeInfo {
	b.mu.Lock()
	exit := b.exit
	b.mu.Unlock()
	return bridgeInfo{
		Spawned:     true,
		ExitCode:    exit,
		StdoutBytes: b.stdout.bytes,
		StderrTail:  b.stderr.String(),
	}
}

func noBridge() bridgeInfo {
	return bridgeInfo{Spawned: false, ExitCode: nil, StdoutBytes: 0, StderrTail: ""}
}

// scanLines exposes a line scanner over the fixture's own stdin (scenario 6).
func scanLines(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), 1<<20)
	return s
}
