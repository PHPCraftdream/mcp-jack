//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
)

type ownedPipeAttempt struct {
	frame      string
	n          int
	syscallErr error
	controlErr error
}

type ownedPipeWriteResult struct {
	n   int
	err error
}

type observedPipeOutput struct {
	*os.File
	raw       syscall.RawConn
	expected  string
	armed     atomic.Bool
	writes    atomic.Int32
	attempted chan ownedPipeAttempt
	returned  chan ownedPipeWriteResult
}

func (w *observedPipeOutput) Write(p []byte) (int, error) {
	if !w.armed.Load() {
		return w.File.Write(p)
	}
	w.writes.Add(1)
	a := ownedPipeAttempt{frame: string(p), n: -1}
	if a.frame == w.expected {
		// Control never waits for readiness. This syscall establishes the cause
		// for this exact verified response, not merely for the earlier filler.
		a.controlErr = w.raw.Control(func(fd uintptr) {
			for tries := 0; tries < 100; tries++ {
				a.n, a.syscallErr = syscall.Write(int(fd), p)
				if a.syscallErr != syscall.EINTR {
					break
				}
			}
		})
	}
	select {
	case w.attempted <- a:
	default:
	}
	var n int
	var err error
	if a.frame != w.expected {
		err = errors.New("unexpected terminal output bytes")
	} else if a.controlErr != nil {
		err = a.controlErr
	} else if a.n > 0 || a.syscallErr == nil {
		// Never write a successful probe's bytes twice. Any progress invalidates
		// the saturated/broken precondition and must fail, not become output.
		if a.n > 0 {
			n = a.n
		}
		err = fmt.Errorf("terminal syscall unexpectedly progressed: n=%d err=%T %v", a.n, a.syscallErr, a.syscallErr)
	} else if wouldBlock(a.syscallErr) || errors.Is(a.syscallErr, syscall.EPIPE) {
		// The real owned pollable File, not a channel, supplies the blocking or
		// broken-peer behavior. Close can interrupt its actual Write.
		n, err = w.File.Write(p)
	} else {
		err = a.syscallErr
	}
	select {
	case w.returned <- ownedPipeWriteResult{n, err}:
	default:
	}
	return n, err
}

func ownedOutputRaw(f *os.File) (syscall.RawConn, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var flags uintptr
	var flagErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		flags, _, flagErr = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	})
	if err != nil || flagErr != 0 || flags&syscall.O_NONBLOCK == 0 {
		return nil, fmt.Errorf("output flags=%#x controlErr=%T %v fcntlErr=%T %v", flags, err, err, flagErr, flagErr)
	}
	return raw, nil
}

func saturateOwnedOutput(raw syscall.RawConn) (int64, error) {
	var written int64
	var fillErr error
	err := raw.Control(func(fd uintptr) {
		block := make([]byte, 4096)
		for tries := 0; tries < 16*maxBody && written < 16*maxBody; tries++ {
			n, err := syscall.Write(int(fd), block)
			if err == syscall.EINTR {
				continue
			}
			if wouldBlock(err) {
				if len(block) == 1 && n <= 0 {
					return
				}
				block = block[:1]
				continue
			}
			if err != nil || n <= 0 {
				fillErr = fmt.Errorf("filler n=%d err=%T %v", n, err, err)
				return
			}
			written += int64(n)
		}
		fillErr = errors.New("filler did not reach actual one-byte EAGAIN within work bound")
	})
	if err != nil {
		return written, err
	}
	return written, fillErr
}

func TestOwnedPipeBrokenOutputAndBackpressure(t *testing.T) {
	const terminalFrame = `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}` + "\n"
	type runResult struct {
		code   int
		stderr string
	}
	type ioResult struct {
		n   int64
		b   []byte
		err error
	}
	for _, mode := range []string{"broken", "blocked", "peer-drain"} {
		t.Run(mode, func(t *testing.T) {
			var calls [3]atomic.Int32
			var sequence, unexpected atomic.Int32
			path, cfg, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, readErr := io.ReadAll(r.Body)
				m, parseErr := object(b)
				methods := [...]string{"initialize", "notifications/initialized", "tools/list"}
				index := -1
				for i, method := range methods {
					if text(m["method"]) == method {
						index = i
					}
				}
				if readErr != nil || parseErr != nil || index < 0 {
					unexpected.Add(1)
					w.WriteHeader(400)
					return
				}
				calls[index].Add(1)
				if sequence.Add(1) != int32(index+1) {
					unexpected.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				switch index {
				case 0:
					_, _ = io.WriteString(w, initializeReply)
				case 1:
					w.WriteHeader(202)
				case 2:
					_, _ = io.WriteString(w, strings.TrimSuffix(terminalFrame, "\n"))
				}
			}))
			cfg.CallTimeoutMS = 2000
			path = saveJSON(t, privateDir(t), "bounded.json", cfg)
			inRead, inWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			outRead, outWrite, err := os.Pipe()
			if err != nil {
				_ = inRead.Close()
				_ = inWrite.Close()
				t.Fatal(err)
			}
			var closeOnce sync.Once
			closed := make(chan struct{})
			closePipes := func() {
				closeOnce.Do(func() {
					go func() {
						_ = inRead.Close()
						_ = inWrite.Close()
						_ = outWrite.Close()
						_ = outRead.Close()
						close(closed)
					}()
				})
			}
			defer func() {
				closePipes()
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					t.Error("stage=pipe-cleanup close join exceeded failure guard")
				}
			}()
			// Inspect without File.Fd or changing flags; retain os.Pipe's owned,
			// pollable File for both the probe and the delegated Write.
			raw, err := ownedOutputRaw(outWrite)
			if err != nil {
				t.Fatalf("stage=output-nonblocking err=%T %v", err, err)
			}
			if err := outWrite.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatalf("stage=output-pollable err=%T %v", err, err)
			}
			observed := &observedPipeOutput{
				File: outWrite, raw: raw, expected: terminalFrame,
				attempted: make(chan ownedPipeAttempt, 1), returned: make(chan ownedPipeWriteResult, 1),
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan runResult, 1)
			var result *runResult
			var pendingIO <-chan ioResult
			var attempt *ownedPipeAttempt
			var returned *ownedPipeWriteResult
			var filled int64
			stage := "run-started"
			stopAndJoin := func() error {
				cancel()
				closePipes()
				guard := time.NewTimer(3 * time.Second)
				defer guard.Stop()
				closeWait := (<-chan struct{})(closed)
				for closeWait != nil || result == nil || pendingIO != nil {
					select {
					case <-closeWait:
						closeWait = nil
					case r := <-done:
						result = &r
						done = nil
					case <-pendingIO:
						pendingIO = nil
					case <-guard.C:
						return errors.New("cleanup close/Run/IO join exceeded failure guard")
					}
				}
				return nil
			}
			fail := func(err error) {
				t.Helper()
				joinErr := stopAndJoin()
				if attempt == nil {
					select {
					case a := <-observed.attempted:
						attempt = &a
					default:
					}
				}
				if returned == nil {
					select {
					case r := <-observed.returned:
						returned = &r
					default:
					}
				}
				runInfo := "unavailable (Run not joined; stderr not read)"
				if result != nil {
					runInfo = fmt.Sprintf("code=%d stderr=%q", result.code, result.stderr)
				}
				attemptInfo, returnInfo := "not observed", "not observed"
				if attempt != nil {
					attemptInfo = fmt.Sprintf("frame=%q exact=%t n=%d syscallErr=%T %v controlErr=%T %v", attempt.frame, attempt.frame == terminalFrame, attempt.n, attempt.syscallErr, attempt.syscallErr, attempt.controlErr, attempt.controlErr)
				}
				if returned != nil {
					returnInfo = fmt.Sprintf("n=%d err=%T %v", returned.n, returned.err, returned.err)
				}
				t.Fatalf("stage=%s err=%T %v; Run %s; attempt={%s}; File.Write={%s}; filler=%d writes=%d calls=[%d %d %d] unexpected=%d; joinErr=%T %v", stage, err, err, runInfo, attemptInfo, returnInfo, filled, observed.writes.Load(), calls[0].Load(), calls[1].Load(), calls[2].Load(), unexpected.Load(), joinErr, joinErr)
			}
			defer func() {
				if err := stopAndJoin(); err != nil {
					t.Errorf("stage=%s cleanup err=%T %v", stage, err, err)
				}
			}()
			runDone := done
			go func() {
				var stderr bytes.Buffer
				code := Run(ctx, []string{"bridge", "--config", path}, IO{In: inRead, Out: observed, Err: &stderr})
				// Only this goroutine accesses Buffer; publish immutable diagnostics
				// after Run has joined its workers and finished writing stderr.
				runDone <- runResult{code, stderr.String()}
			}()
			stepIO := func(name string, op func() ioResult) ioResult {
				t.Helper()
				stage = name
				ch := make(chan ioResult, 1)
				pendingIO = ch
				go func() { ch <- op() }()
				guard := time.NewTimer(3 * time.Second)
				defer guard.Stop()
				for {
					select {
					case r := <-ch:
						pendingIO = nil
						if r.err != nil {
							fail(r.err)
						}
						return r
					case r := <-done:
						result, done = &r, nil
						// IO can complete before its result sender is scheduled.
						// Keep the Run verdict, collect IO, then validate both.
					case <-guard.C:
						fail(context.DeadlineExceeded)
					}
				}
			}
			writeFrame := func(name, frame string) {
				t.Helper()
				r := stepIO(name, func() ioResult {
					if err := inWrite.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
						return ioResult{err: err}
					}
					n, err := io.WriteString(inWrite, frame)
					return ioResult{n: int64(n), err: err}
				})
				if r.n != int64(len(frame)) {
					fail(fmt.Errorf("input short write: n=%d want=%d", r.n, len(frame)))
				}
			}
			readFrame := func(name, frame string) {
				t.Helper()
				r := stepIO(name, func() ioResult {
					if err := outRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						return ioResult{err: err}
					}
					b := make([]byte, len(frame))
					n, err := io.ReadFull(outRead, b)
					return ioResult{n: int64(n), b: b[:n], err: err}
				})
				if string(r.b) != frame {
					fail(fmt.Errorf("output frame=%q want=%q", r.b, frame))
				}
			}
			waitRun := func() {
				t.Helper()
				stage = "Run-result"
				if result != nil {
					return
				}
				guard := time.NewTimer(3 * time.Second)
				defer guard.Stop()
				select {
				case r := <-done:
					result, done = &r, nil
				case <-guard.C:
					fail(context.DeadlineExceeded)
				}
			}
			writeFrame("initialize-input", initializeFrame+"\n")
			readFrame("initialize-frame", initializeReply+"\n")
			writeFrame("initialized-input", initializedFrame+"\n")
			if mode == "broken" {
				stage = "reader-close"
				if err := outRead.Close(); err != nil {
					fail(err)
				}
			} else {
				stage = "pipe-saturation"
				filled, err = saturateOwnedOutput(raw)
				if err != nil || filled <= 0 {
					fail(fmt.Errorf("saturation filled=%d err=%T %v", filled, err, err))
				}
			}
			observed.armed.Store(true)
			writeFrame("tools-list-input", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n")
			stage = "exact-response-syscall"
			guard := time.NewTimer(3 * time.Second)
			for attempt == nil {
				if result != nil {
					// A fast broken-peer return can race this receive. Run's join
					// guarantees any earlier attempt is already buffered.
					select {
					case a := <-observed.attempted:
						attempt = &a
					default:
						guard.Stop()
						fail(errors.New("Run returned without terminal syscall stage"))
					}
					break
				}
				select {
				case a := <-observed.attempted:
					attempt = &a
				case r := <-done:
					result, done = &r, nil
				case <-guard.C:
					fail(context.DeadlineExceeded)
				}
			}
			guard.Stop()
			if attempt.frame != terminalFrame || attempt.controlErr != nil || attempt.n > 0 {
				fail(errors.New("exact-response syscall precondition failed"))
			}
			if mode == "broken" {
				if !errors.Is(attempt.syscallErr, syscall.EPIPE) {
					fail(errors.New("terminal syscall did not observe real broken peer"))
				}
			} else if !wouldBlock(attempt.syscallErr) {
				fail(errors.New("terminal syscall did not observe actual response EAGAIN"))
			}
			if mode == "peer-drain" {
				if result != nil {
					fail(errors.New("Run completed before peer-drain action"))
				}
				// No reader has drained anything since saturation. Remove exactly
				// the accounted zero filler, then read only the exact terminal frame.
				r := stepIO("peer-drain-filler", func() ioResult {
					if err := outRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						return ioResult{err: err}
					}
					b := make([]byte, int(filled))
					n, err := io.ReadFull(outRead, b)
					return ioResult{n: int64(n), b: b[:n], err: err}
				})
				if r.n != filled || !bytes.Equal(r.b, make([]byte, int(filled))) {
					fail(errors.New("peer drain did not consume exactly the zero filler"))
				}
				readFrame("terminal-frame", terminalFrame)
				stage = "File.Write-return"
				guard := time.NewTimer(3 * time.Second)
				select {
				case r := <-observed.returned:
					returned = &r
				case r := <-done:
					result, done = &r, nil
					guard.Stop()
					fail(errors.New("Run returned before peer-drain write result"))
				case <-guard.C:
					fail(context.DeadlineExceeded)
				}
				guard.Stop()
				if returned.n != len(terminalFrame) || returned.err != nil {
					fail(errors.New("peer drain did not complete real File.Write"))
				}
				stage = "stdin-eof-after-complete-reply"
				if err := inWrite.Close(); err != nil {
					fail(err)
				}
			}
			waitRun()
			stage = "Run-verdict"
			wantCode, wantStderr := 1, "jack: operation cancelled or deadline exceeded\n"
			if mode == "broken" {
				wantStderr = "jack: unsupported or invalid protocol message\n"
			} else if mode == "peer-drain" {
				wantCode, wantStderr = 0, ""
			}
			if result.code != wantCode || result.stderr != wantStderr {
				fail(fmt.Errorf("want code=%d stderr=%q", wantCode, wantStderr))
			}
			if returned == nil {
				select {
				case r := <-observed.returned:
					returned = &r
				default:
					fail(errors.New("Run joined without File.Write return event"))
				}
			}
			stage = "File.Write-verdict"
			if mode == "broken" {
				if returned.n != 0 || !(errors.Is(returned.err, syscall.EPIPE) || errors.Is(returned.err, os.ErrClosed)) {
					fail(errors.New("broken output did not return real EPIPE/closed File error"))
				}
			} else if mode == "blocked" {
				if returned.n != 0 || !errors.Is(returned.err, os.ErrClosed) {
					fail(errors.New("undrained File.Write did not return closed after bridge deadline"))
				}
			}
			if mode == "peer-drain" {
				r := stepIO("extra-output-eof", func() ioResult {
					if err := outRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						return ioResult{err: err}
					}
					b, err := io.ReadAll(io.LimitReader(outRead, maxBody+1))
					return ioResult{n: int64(len(b)), b: b, err: err}
				})
				if r.n != 0 {
					fail(fmt.Errorf("extra output=%q", r.b))
				}
			}
			stage = "lifecycle-counts"
			if observed.writes.Load() != 1 || sequence.Load() != 3 || unexpected.Load() != 0 || calls[0].Load() != 1 || calls[1].Load() != 1 || calls[2].Load() != 1 {
				fail(errors.New("expected exactly initialize, initialized, tools/list and one terminal Write; no retry"))
			}
		})
	}
}

func TestExactAndPlusOneBodyCaps(t *testing.T) {
	var calls atomic.Int32
	var responsePlusOne atomic.Bool
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		if responsePlusOne.Load() {
			_, _ = io.WriteString(w, " ")
		}
	}))
	base := directTransport(3 * time.Second)
	base.DialContext = unixDial(socket)
	defer base.CloseIdleConnections()
	path, _, _ := signedFixture(t, upstreamHandler(gatewayConfig{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	c.timeout = 3 * time.Second
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body = append(body, bytes.Repeat([]byte(" "), maxBody-len(body))...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, status, err := c.post(ctx, body)
	if err != nil || status != 200 || !bytes.Equal(reply, body) || len(reply) != maxBody || calls.Load() != 1 {
		t.Fatal("exact request/response cap baseline refused or changed")
	}
	responsePlusOne.Store(true)
	if _, status, err := c.post(ctx, body); err == nil || status != 502 || calls.Load() != 2 {
		t.Fatal("response cap+1 did not produce a verified refusal")
	}
	tooLarge := append(append([]byte(nil), body...), ' ')
	if _, _, err := c.post(ctx, tooLarge); err == nil || calls.Load() != 2 {
		t.Fatal("local request cap+1 reached upstream")
	}
	// Bypass the CLI's local size check to discriminate the SDK HTTP ingress cap.
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(tooLarge))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := client.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.SignRequest(c.signer, c.aud, r.Method, r.URL.RequestURI(), tooLarge, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Jack-Auth", auth)
	r.Header.Set("Content-Type", "application/json")
	network := directTransport(3 * time.Second)
	defer network.CloseIdleConnections()
	resp, err := (oneShot{network}).RoundTrip(r)
	if err != nil {
		t.Fatal("ingress cap control failed to reach gateway")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 413 || len(resp.Header.Values("Jack-Auth")) != 0 || calls.Load() != 2 {
		t.Fatal("oversized HTTP ingress was forwarded or described as signed")
	}
}

func TestGatewayRequestAndResponseCapsAndDeadline(t *testing.T) {
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m, _ := object(b)
		if text(m["method"]) == "slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
				t.Error("slow fixture cancellation timed out")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", maxBody+1))
	}))
	base := directTransport(200 * time.Millisecond)
	base.DialContext = unixDial(socket)
	t.Cleanup(base.CloseIdleConnections)
	path, _, _ := signedFixture(t, upstreamHandler(gatewayConfig{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"tools/list", "slow"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		_, status, err := c.post(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
		cancel()
		if err == nil || status != 502 || time.Since(start) > 2*time.Second {
			t.Fatal("cap/deadline failed")
		}
	}
	if _, _, err := c.post(context.Background(), bytes.Repeat([]byte("x"), maxBody+1)); err == nil {
		t.Fatal("oversized request accepted")
	}
}
