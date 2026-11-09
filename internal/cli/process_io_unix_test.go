//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
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
	streams, err := prepareProcessIO(blockingInheritedCopy(t, in), blockingInheritedCopy(t, out))
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
	if _, err := reader.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("prepared File.Read did not honor deadline")
	}
	if reader.SetReadDeadline(time.Time{}) != nil {
		t.Fatal("read deadline reset failed")
	}
}

func wouldBlock(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
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
		for attempts := 0; attempts < 16*maxBody && written < 16*maxBody; attempts++ {
			n, err := syscall.Write(int(fd), block)
			if err == syscall.EINTR {
				continue
			}
			if wouldBlock(err) {
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
						if wouldBlock(syscallErr) {
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
					receiveTest(t, closeDone)
					receiveTest(t, done)
				})
				select {
				case <-blocked:
				case <-done:
					t.Fatal("raw operation returned before observing EAGAIN")
				case <-time.After(3 * time.Second):
					t.Fatal("raw operation never established would-block precondition")
				}
				// The operation has already executed a real syscall on the open
				// prepared fd. This does not assert it is parked in the poller yet.
				if closeFile {
					closePrepared()
					receiveTest(t, closeDone)
					if closeErr != nil {
						t.Fatal("prepared descriptor close failed")
					}
				} else if input {
					if inPeer.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
						t.Fatal("peer write deadline unavailable")
					}
					writeInput(t, inPeer, "x")
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
				receiveTest(t, done)
				if closeFile {
					if !errors.Is(opErr, os.ErrClosed) {
						t.Fatal("in-flight raw poll operation did not return closed error")
					}
				} else if opErr != nil || syscallErr != nil || n != 1 || callbacks < 2 || b[0] != 'x' {
					t.Fatal("peer readiness did not re-enter callback and complete real I/O")
				}
			})
		}
	}
}

func TestPrepareProcessIORejectsRegularFiles(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := prepareProcessIO(f, f); err == nil {
		t.Fatal("regular file stdio accepted")
	}
	if _, err := f.Write([]byte("still-owned")); err != nil {
		t.Fatal("failed preparation closed caller file")
	}
}
