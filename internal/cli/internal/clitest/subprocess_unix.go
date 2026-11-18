//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Package clitest provides the shared subprocess harness used by CLI process
// tests that spawn the compiled binary (or the test helper) as a child.
package clitest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type ChildProcess struct {
	*exec.Cmd
	t    *testing.T
	Ctx  context.Context
	once sync.Once
	err  error
}

func (c *ChildProcess) Reap() error {
	c.once.Do(func() { c.err = c.Cmd.Wait() })
	return c.err
}

func (c *ChildProcess) Wait() error {
	c.t.Helper()
	err := c.Reap()
	if c.Ctx.Err() != nil {
		c.t.Fatal("child watchdog expired; not an expected CLI failure")
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			c.t.Fatal("child did not exit with the expected CLI status 1")
		}
	}
	return err
}

func Child(t *testing.T, config string) (*ChildProcess, io.WriteCloser, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	return ChildArgs(t, "bridge", "--config", config)
}

// JACK_CLI_EXECUTABLE optionally selects an absolute, parent-built artifact.
func ChildArgs(t *testing.T, args ...string) (*ChildProcess, io.WriteCloser, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	executable := os.Getenv("JACK_CLI_EXECUTABLE")
	helper := executable == ""
	if helper {
		executable = os.Args[0]
		args = append([]string{"-test.run=^TestCLIProcessHelper$", "--"}, args...)
	} else if !filepath.IsAbs(executable) {
		t.Fatal("JACK_CLI_EXECUTABLE must be an absolute artifact path")
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "JACK_CLI_CHILD=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	if helper {
		cmd.Env = append(cmd.Env, "JACK_CLI_CHILD=1")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &ChildProcess{Cmd: cmd, t: t, Ctx: ctx}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = process.Reap()
	})
	return process, in, bufio.NewReader(out), &stderr
}

func ProcessResult(t *testing.T, args ...string) ([]byte, []byte, error) {
	t.Helper()
	cmd, in, out, stderr := ChildArgs(t, args...)
	_ = in.Close()
	stdout, err := io.ReadAll(out)
	if err != nil {
		t.Fatal("reading child stdout failed")
	}
	waitErr := cmd.Wait()
	return stdout, append([]byte(nil), stderr.Bytes()...), waitErr
}

func AssertNoProcessLeak(t *testing.T, stdout, stderr []byte, forbidden ...[]byte) {
	t.Helper()
	for _, value := range forbidden {
		if len(value) != 0 && (bytes.Contains(stdout, value) || bytes.Contains(stderr, value)) {
			t.Fatal("child output disclosed supplied sensitive data")
		}
	}
}
