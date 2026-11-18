//go:build linux

package clitest

import "bytes"

type NonceTestOutput struct {
	bytes.Buffer
	Closed bool
}

func (output *NonceTestOutput) Close() error { output.Closed = true; return nil }
