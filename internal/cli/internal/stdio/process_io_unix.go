//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package stdio

import (
	"os"
	"syscall"
	"time"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

func interruptiblePipe(original *os.File, input bool) (*os.File, error) {
	if original == nil {
		return nil, command.ErrConfig
	}
	info, err := original.Stat()
	// Pipe/FIFO or UNIX socket: Node child_process hands stdio to the child process via a socketpair.
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return nil, command.ErrConfig
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, command.ErrConfig
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(originalFD uintptr) {
		fd, dupErr = syscall.Dup(int(originalFD))
	}); err != nil || dupErr != nil || fd < 0 {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return nil, command.ErrConfig
	}
	syscall.CloseOnExec(fd)
	if syscall.SetNonblock(fd, true) != nil {
		_ = syscall.Close(fd)
		return nil, command.ErrConfig
	}
	// NewFile sees O_NONBLOCK and enrolls the duplicate in Go's poller.
	// Never call File.Fd afterward: it can switch the shared description to blocking.
	f := os.NewFile(uintptr(fd), "jack-bridge-pipe")
	if f == nil {
		_ = syscall.Close(fd)
		return nil, command.ErrConfig
	}
	if input {
		err = f.SetReadDeadline(time.Time{})
	} else {
		err = f.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		_ = f.Close()
		return nil, command.ErrConfig
	}
	return f, nil
}

func PrepareProcessIO(in, out *os.File) (IO, error) {
	reader, err := interruptiblePipe(in, true)
	if err != nil {
		return IO{}, err
	}
	writer, err := interruptiblePipe(out, false)
	if err != nil {
		_ = reader.Close()
		return IO{}, err
	}
	return IO{In: reader, Out: writer, Err: os.Stderr}, nil
}
