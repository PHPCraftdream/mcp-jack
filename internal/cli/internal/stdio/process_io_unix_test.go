//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package stdio

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
)

func blockingInheritedCopy(t *testing.T, source *os.File) *os.File {
	t.Helper()
	raw, err := source.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(original uintptr) { fd, dupErr = syscall.Dup(int(original)) }); err != nil || dupErr != nil || fd < 0 {
		t.Fatal("could not construct inherited descriptor fixture")
	}
	syscall.CloseOnExec(fd)
	if syscall.SetNonblock(fd, false) != nil {
		_ = syscall.Close(fd)
		t.Fatal("could not set inherited fixture blocking")
	}
	f := os.NewFile(uintptr(fd), "inherited-fixture")
	if f == nil {
		_ = syscall.Close(fd)
		t.Fatal("could not wrap inherited descriptor fixture")
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func preparedProcessPipes(t *testing.T) (reader, inPeer, outPeer, writer *os.File) {
	t.Helper()
	in, inPeer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = inPeer.Close() })
	outPeer, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outPeer.Close(); _ = out.Close() })
	streams, err := PrepareProcessIO(blockingInheritedCopy(t, in), blockingInheritedCopy(t, out))
	if err != nil {
		t.Fatal("blocking inherited pipes were not prepared")
	}
	t.Cleanup(func() { _ = streams.In.Close(); _ = streams.Out.Close() })
	return streams.In.(*os.File), inPeer, outPeer, streams.Out.(*os.File)
}

func TestPrepareBlockingInheritedPipes(t *testing.T) {
	reader, _, _, writer := preparedProcessPipes(t)
	if reader.SetReadDeadline(time.Now().Add(50*time.Millisecond)) != nil || writer.SetWriteDeadline(time.Time{}) != nil {
		t.Fatal("prepared inherited pipes lack deadline support")
	}
	var b [1]byte
	if n, err := reader.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("prepared File.Read did not honor deadline: n=%d err=%T %v", n, err, err)
	}
	if reader.SetReadDeadline(time.Time{}) != nil {
		t.Fatal("read deadline reset failed")
	}
}

func preparedRawConn(t *testing.T, f *os.File) syscall.RawConn {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	var flagErr syscall.Errno
	// Inspect, do not repair: raw syscalls must never block, even if production
	// preparation regresses. Control holds fd valid; File.Fd would change mode.
	if err := raw.Control(func(fd uintptr) {
		flags, _, flagErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	}); err != nil || flagErr != 0 || flags&syscall.O_NONBLOCK == 0 {
		t.Fatal("prepared descriptor is not nonblocking")
	}
	return raw
}

func fillPreparedPipe(t *testing.T, raw syscall.RawConn) int64 {
	t.Helper()
	var fillErr error
	written := 0
	err := raw.Control(func(fd uintptr) {
		block := make([]byte, 4096)
		// No reader drains this pipe. Bound fixture work even for a broken setup.
		for attempts := 0; attempts < 16*wire.MaxBody && written < 16*wire.MaxBody; attempts++ {
			n, err := syscall.Write(int(fd), block)
			if err == syscall.EINTR {
				continue
			}
			if clitest.WouldBlock(err) {
				if len(block) == 1 {
					return
				}
				// A large atomic write can fail while one byte still fits.
				block = block[:1]
				continue
			}
			if err != nil {
				fillErr = err
				return
			}
			if n <= 0 {
				fillErr = errors.New("pipe fill made no progress")
				return
			}
			written += n
		}
		fillErr = errors.New("pipe fill never reached would-block")
	})
	if err != nil || fillErr != nil {
		t.Fatal("could not fill prepared pipe to actual one-byte EAGAIN")
	}
	return int64(written)
}

// closedPreparedRawError captures the closed-operation error through public APIs
// on an independent prepared pipe. Keep the RawConn acquired before File.Close:
// RawConn forwards poll errors, unlike File.Read/Write's public error conversion.
func closedPreparedRawError(t *testing.T, input bool) error {
	t.Helper()
	reader, _, _, writer := preparedProcessPipes(t)
	f := writer
	if input {
		f = reader
	}
	raw := preparedRawConn(t, f)
	closed := make(chan struct{})
	var closeErr error
	go func() { closeErr = f.Close(); close(closed) }()
	clitest.Receive(t, closed)
	if closeErr != nil {
		t.Fatalf("reference File.Close: err=%T %v", closeErr, closeErr)
	}
	callbacks := 0
	callback := func(uintptr) bool {
		callbacks++
		return true
	}
	var reference error
	if input {
		reference = raw.Read(callback)
	} else {
		reference = raw.Write(callback)
	}
	if reference == nil || callbacks != 0 {
		t.Fatalf("closed reference RawConn: err=%T %v callbacks=%d; want nonnil error before callback", reference, reference, callbacks)
	}
	var errno syscall.Errno
	if errors.As(reference, &errno) {
		t.Fatalf("closed reference RawConn returned syscall error: err=%T %v errno=%v callbacks=%d", reference, reference, errno, callbacks)
	}
	// A bad descriptor, readiness result, deadline, or invalid File must not
	// satisfy the oracle in either direction. Do not identify errors by text.
	for _, bad := range []error{syscall.EBADF, syscall.EAGAIN, syscall.EWOULDBLOCK, os.ErrDeadlineExceeded, os.ErrInvalid, io.EOF, syscall.EPIPE} {
		if errors.Is(bad, reference) || errors.Is(reference, bad) {
			t.Fatalf("closed reference RawConn matched bad oracle: reference=%T %v bad=%T %v callbacks=%d", reference, reference, bad, bad, callbacks)
		}
	}
	return reference
}

func TestPreparedPipeRawPollInterruption(t *testing.T) {
	for _, input := range []bool{true, false} {
		for _, closeFile := range []bool{true, false} {
			name := "output"
			if input {
				name = "input"
			}
			if closeFile {
				name += "-close"
			} else {
				name += "-peer-readiness"
			}
			t.Run(name, func(t *testing.T) {
				var reference error
				if closeFile {
					reference = closedPreparedRawError(t, input)
				}
				reader, inPeer, outPeer, writer := preparedProcessPipes(t)
				f := writer
				if input {
					f = reader
				}
				raw := preparedRawConn(t, f)
				var filled int64
				if !input {
					filled = fillPreparedPipe(t, raw)
				}
				blocked := make(chan struct{})
				done := make(chan struct{})
				var opErr, syscallErr error
				var callbacks, n int
				b := [1]byte{'x'}
				go func() {
					defer close(done)
					signaled := false
					callback := func(fd uintptr) bool {
						callbacks++
						for attempts := 0; attempts < 100; attempts++ {
							if input {
								n, syscallErr = syscall.Read(int(fd), b[:])
							} else {
								n, syscallErr = syscall.Write(int(fd), b[:])
							}
							if syscallErr != syscall.EINTR {
								break
							}
						}
						if clitest.WouldBlock(syscallErr) {
							if !signaled {
								signaled = true
								close(blocked)
							}
							// RawConn contract: false requests readiness wait and
							// callback retry; never wait inside the callback itself.
							return false
						}
						return true
					}
					if input {
						opErr = raw.Read(callback)
					} else {
						opErr = raw.Write(callback)
					}
				}()
				// Close can itself wait for the raw operation. Bound both joins,
				// including cleanup after a failed precondition; expiry only fails.
				closeDone := make(chan struct{})
				var closeOnce sync.Once
				var closeErr error
				closePrepared := func() {
					closeOnce.Do(func() {
						go func() { closeErr = f.Close(); close(closeDone) }()
					})
				}
				t.Cleanup(func() {
					closePrepared()
					clitest.Receive(t, closeDone)
					clitest.Receive(t, done)
				})
				select {
				case <-blocked:
				case <-done:
					t.Fatalf("raw operation returned before observing EAGAIN: err=%T %v syscallErr=%T %v n=%d callbacks=%d", opErr, opErr, syscallErr, syscallErr, n, callbacks)
				case <-time.After(3 * time.Second):
					t.Fatal("raw operation never established would-block precondition")
				}
				// The operation has already executed a real syscall on the open
				// prepared fd. This does not assert it is parked in the poller yet.
				if closeFile {
					closePrepared()
					clitest.Receive(t, closeDone)
					if closeErr != nil {
						t.Fatalf("prepared descriptor close failed: err=%T %v", closeErr, closeErr)
					}
				} else if input {
					if inPeer.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
						t.Fatal("peer write deadline unavailable")
					}
					clitest.WriteInput(t, inPeer, "x")
				} else {
					if outPeer.SetReadDeadline(time.Now().Add(time.Second)) != nil {
						t.Fatal("peer read deadline unavailable")
					}
					// Drain the entire original fill, not a platform-specific
					// guessed poller low-water mark. The callback adds at most one byte.
					if n, err := io.CopyN(io.Discard, outPeer, filled); err != nil || n != filled {
						t.Fatal("peer could not drain full pipe")
					}
				}
				clitest.Receive(t, done)
				if closeFile {
					var errno syscall.Errno
					if opErr == nil || !errors.Is(opErr, reference) || errors.As(opErr, &errno) ||
						!clitest.WouldBlock(syscallErr) || (n != -1 && n != 0) || callbacks < 1 {
						t.Fatalf("raw close mismatch: err=%T %v reference=%T %v syscallErr=%T %v n=%d callbacks=%d; want reference match and final syscall EAGAIN without progress", opErr, opErr, reference, reference, syscallErr, syscallErr, n, callbacks)
					}
					// Separately exercise the public File error conversion after
					// verified Close. This is not an in-flight File.Read/Write hook.
					var fileN int
					var fileErr error
					if input {
						fileN, fileErr = f.Read(b[:])
					} else {
						fileN, fileErr = f.Write(b[:])
					}
					if fileN != 0 || !errors.Is(fileErr, os.ErrClosed) {
						t.Fatalf("post-close File I/O: n=%d err=%T %v; raw err=%T %v reference=%T %v syscallErr=%T %v n=%d callbacks=%d; want zero bytes and os.ErrClosed", fileN, fileErr, fileErr, opErr, opErr, reference, reference, syscallErr, syscallErr, n, callbacks)
					}
				} else if opErr != nil || syscallErr != nil || n != 1 || callbacks < 2 || b[0] != 'x' {
					t.Fatalf("peer readiness did not re-enter callback and complete real I/O: err=%T %v syscallErr=%T %v n=%d callbacks=%d byte=%q", opErr, opErr, syscallErr, syscallErr, n, callbacks, b[0])
				}
			})
		}
	}
}

func socketPair(t *testing.T) (child, peer *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	child = os.NewFile(uintptr(fds[0]), "socket-child")
	peer = os.NewFile(uintptr(fds[1]), "socket-peer")
	t.Cleanup(func() { _ = child.Close(); _ = peer.Close() })
	return child, peer
}

// Node child_process hands stdio to the child process as a UNIX socketpair.
func TestPrepareProcessIOAcceptsUnixSocketpairs(t *testing.T) {
	in, inPeer := socketPair(t)
	out, outPeer := socketPair(t)
	streams, err := PrepareProcessIO(in, out)
	if err != nil {
		t.Fatalf("socketpair stdio was not prepared: %v", err)
	}
	t.Cleanup(func() { _ = streams.In.Close(); _ = streams.Out.Close() })
	reader := streams.In.(*os.File)
	writer := streams.Out.(*os.File)
	if _, err := inPeer.Write([]byte("frame\n")); err != nil {
		t.Fatal(err)
	}
	if reader.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("prepared socket stdin lacks read deadline support")
	}
	var frame [6]byte
	if _, err := io.ReadFull(reader, frame[:]); err != nil || string(frame[:]) != "frame\n" {
		t.Fatalf("prepared socket stdin read: %q %v", frame, err)
	}
	if _, err := writer.Write([]byte("reply\n")); err != nil {
		t.Fatal(err)
	}
	var reply [6]byte
	if _, err := io.ReadFull(outPeer, reply[:]); err != nil || string(reply[:]) != "reply\n" {
		t.Fatalf("prepared socket stdout write: %q %v", reply, err)
	}
	if reader.SetReadDeadline(time.Now().Add(50*time.Millisecond)) != nil {
		t.Fatal("read deadline reset failed")
	}
	var b [1]byte
	if n, err := reader.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle prepared socket read did not honor deadline: n=%d err=%v", n, err)
	}
}

func TestPrepareProcessIORejectsRegularFiles(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := PrepareProcessIO(f, f); err == nil {
		t.Fatal("regular file stdio accepted")
	}
	if _, err := f.Write([]byte("still-owned")); err != nil {
		t.Fatal("failed preparation closed caller file")
	}
}

func TestUnixProcessIORejectsInvalidDescriptorsWithoutClosingCaller(t *testing.T) {
	if _, err := interruptiblePipe(nil, true); err != command.ErrConfig {
		t.Fatalf("nil input refusal = %v, want command.ErrConfig", err)
	}
	if _, err := interruptiblePipe(nil, false); err != command.ErrConfig {
		t.Fatalf("nil output refusal = %v, want command.ErrConfig", err)
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if _, err := interruptiblePipe(regular, true); err != command.ErrConfig {
		t.Fatalf("regular descriptor refusal = %v, want command.ErrConfig", err)
	}
	if n, err := regular.Write([]byte("caller-still-owns-it")); err != nil || n != len("caller-still-owns-it") {
		t.Fatalf("failed preparation changed caller descriptor ownership: n=%d err=%v", n, err)
	}
	if err := regular.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := interruptiblePipe(regular, false); err != command.ErrConfig {
		t.Fatalf("closed descriptor refusal = %v, want command.ErrConfig", err)
	}
	input, peer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer peer.Close()
	if _, err := PrepareProcessIO(input, regular); err != command.ErrConfig {
		t.Fatalf("invalid output descriptor refusal = %v, want command.ErrConfig", err)
	}
	if n, err := peer.Write([]byte("original pipe remains open")); err != nil || n != len("original pipe remains open") {
		t.Fatalf("failed output preparation damaged caller pipe: n=%d err=%v", n, err)
	}
	buf := make([]byte, len("original pipe remains open"))
	if n, err := io.ReadFull(input, buf); err != nil || string(buf) != "original pipe remains open" || n != len(buf) {
		t.Fatalf("failed output preparation changed caller pipe data: n=%d data=%q err=%v", n, buf, err)
	}
}
