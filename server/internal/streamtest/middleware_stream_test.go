package streamtest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/server/internal/transport"
)

// TestStreamDurationCloseWritesFinalResponse covers spec 05 3.4 and 6.3: the
// duration close writes the final response of the opening request and then
// the end frame.
func TestStreamDurationCloseWritesFinalResponse(t *testing.T) {
	var once sync.Once
	handlerDone := make(chan struct{})
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		once.Do(func() {
			_, _ = w.Write([]byte(progressFrame))
			<-r.Context().Done()
			close(handlerDone)
		})
	})
	h, clk := newHarness(t, modern.ProfileModern, &transport.StreamOptions{MaxStreamDuration: 20 * time.Millisecond}, sse)
	req, sig := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(7), 50, "s1")
	modernMirrors(req, "email.received")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handler.ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the middleware did not return after the stream duration")
	}
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was not cancelled by the duration close")
	}

	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) != 3 {
		t.Fatalf("frames = %+v, want progress, final response and end", frames)
	}
	if frames[0].event != "message" || frames[0].data != progressEvent {
		t.Fatalf("frame 0 = %+v, want the progress notification", frames[0])
	}
	if frames[1].event != "message" || frames[1].data != finalEvent {
		t.Fatalf("frame 1 = %+v, want the final response %s", frames[1], finalEvent)
	}
	if frames[2].event != "jack-end" {
		t.Fatalf("frame 2 = %+v, want jack-end", frames[2])
	}

	result := verifyStream(t, rec, clk, sig, h.server.Public().(ed25519.PublicKey), 0)
	if !result.Complete {
		t.Fatal("the end frame was not verified")
	}
	if len(result.Messages) != 2 || result.Messages[0] != progressEvent || result.Messages[1] != finalEvent {
		t.Fatalf("messages = %q, want [progress, final]", result.Messages)
	}
	// mcp_complete: the last verified message is the JSON-RPC response of the
	// opening request id 7.
	mcpComplete := false
	last := result.Messages[len(result.Messages)-1]
	var msg struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Method  *json.RawMessage `json:"method"`
		Result  *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(last), &msg); err == nil && msg.JSONRPC == "2.0" &&
		msg.Method == nil && msg.Result != nil && string(msg.ID) == "7" {
		mcpComplete = true
	}
	if !mcpComplete {
		t.Fatalf("last message %q is not the final response of id 7", last)
	}
}

// TestStreamHandlerCanceledOnClientDisconnect covers spec 05 3.7: the handler
// context ends when the client disconnects.
func TestStreamHandlerCanceledOnClientDisconnect(t *testing.T) {
	handlerDone := make(chan struct{})
	h, clk := newHarness(t, modern.ProfileModern, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
		close(handlerDone)
	}))
	srv := httptest.NewServer(h.handler)

	// signedPost signs the origin-form target the server verifies; the client
	// request is a fresh one so its wire fields are a normal client request.
	signed, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(11), 40, "s1")
	modernMirrors(signed, "email.received")
	req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader(modernStreamBody(11)))
	if err != nil {
		srv.Close()
		t.Fatalf("build client request: %v", err)
	}
	req.Header = signed.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		srv.Close()
		t.Fatalf("send signed POST: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		srv.Close()
		t.Fatalf("status = %d, want the open stream", resp.StatusCode)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, one); err != nil {
		_ = resp.Body.Close()
		srv.Close()
		t.Fatalf("read stream bytes: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		srv.Close()
		<-handlerDone
		t.Fatal("the handler context did not end when the client disconnected")
	}
	srv.Close()
}

// responseKeysFunc adapts a function to the ResponseKeyProvider interface.
type responseKeysFunc func(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error)

func (f responseKeysFunc) AuthorizeResponse(req transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
	return f(req)
}

// fixedSigner is a ResponseSigner over one fixed private key.
type fixedSigner struct {
	key ed25519.PrivateKey
}

func (s fixedSigner) PublicKey() []byte {
	return append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)
}

func (s fixedSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func TestStreamHandlerPanicRunsFinalAndReleasesLease(t *testing.T) {
	finals, releases := atomic.Int32{}, atomic.Int32{}
	key := testfixture.PrivateKey(t, "svc")
	provider := responseKeysFunc(func(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
		return transport.ResponseKeyAuthorization{
			Signer: fixedSigner{key: key}, Timestamp: testfixture.Now,
			Final:   func() error { finals.Add(1); return nil },
			Release: func() { releases.Add(1) },
		}, nil
	})
	h, clk := newResponseKeysHarness(t, modern.ProfileModern, provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
		panic("handler panic")
	}))
	req, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(12), 59, "s1")
	modernMirrors(req, "email.received")
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		h.handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	if recovered != "handler panic" {
		t.Fatalf("handler panic = %v", recovered)
	}
	if finals.Load() != 1 || releases.Load() != 1 {
		t.Fatalf("Final calls=%d lease releases=%d, want one each", finals.Load(), releases.Load())
	}
}

// TestStreamRotationCutoffEndsBeforeActivation covers spec 05 5.1: once the
// clock reaches the guard before the successor activation no further frame is
// legal, so the stream closes strictly before the activation. Every frame ts
// is below the activation, the end frame is last and still legal, and the
// provider lease is released only after the end frame is already on the wire.
func TestStreamRotationCutoffEndsBeforeActivation(t *testing.T) {
	const activation = int64(2010)
	var released atomic.Bool
	var releasedAt int
	var rec *httptest.ResponseRecorder
	var secondErr error
	var secondTried bool
	var clk *clock
	provider := responseKeysFunc(func(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
		return transport.ResponseKeyAuthorization{
			Signer:    fixedSigner{key: testfixture.PrivateKey(t, "svc")},
			Timestamp: 2000,
			Cutoff:    ptr(activation),
			Final:     func() error { return nil },
			Release: func() {
				// finish releases the lease only after the end frame; the body
				// length of that moment must be the final one.
				releasedAt = rec.Body.Len()
				released.Store(true)
			},
		}, nil
	})
	// The handler needs the harness clock, which newResponseKeysHarness
	// returns; the handler is only called after the pointer is assigned.
	h, clockRef := newResponseKeysHarness(t, modern.ProfileModern, provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := w.Write([]byte(progressFrame)); err != nil {
			return
		}
		// One second before the successor activation: inside the guard, so no
		// further frame may be signed.
		clk.Set(activation - 1)
		secondTried = true
		_, secondErr = w.Write([]byte(progressFrame))
	}))
	clk = clockRef
	clk.Set(2000)
	req, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(13), 60, "s1")
	modernMirrors(req, "email.received")
	rec = httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if !secondTried {
		t.Fatal("the handler did not attempt the second write inside the guard")
	}
	if secondErr == nil {
		t.Fatal("the second write inside the guard succeeded")
	}
	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) < 2 {
		t.Fatalf("frames = %+v, want at least the message and the end frame", frames)
	}
	end := frames[len(frames)-1]
	if end.event != "jack-end" {
		t.Fatalf("frames do not end with jack-end: %+v", frames)
	}
	for _, frame := range frames {
		if frame.ts >= activation {
			t.Fatalf("frame %+v carries ts %d at or past the successor activation %d", frame, frame.ts, activation)
		}
	}
	if end.ts < 2000 {
		t.Fatalf("end frame ts = %d, want at least the open ts 2000", end.ts)
	}
	if !released.Load() {
		t.Fatal("the provider lease was never released")
	}
	if releasedAt != len(rec.Body.Bytes()) {
		t.Fatalf("lease released after %d body bytes, want the final %d: the end frame was not yet on the wire", releasedAt, len(rec.Body.Bytes()))
	}
	if !bytes.Contains(rec.Body.Bytes()[:releasedAt], []byte("event: jack-end")) {
		t.Fatalf("body at release carried no end frame: %q", rec.Body.String())
	}
}

// TestStreamTimeoutInterruptsBlockedWriteReleasesIdentity proves a timer can
// interrupt a physical response write and release its identity lease even
// while the wrapped handler ignores cancellation.
func TestStreamTimeoutInterruptsBlockedWriteReleasesIdentity(t *testing.T) {
	var clockMu sync.Mutex
	timerClock := time.Unix(testfixture.Now, 0)
	timers := make(chan *controlledStreamTimer, 4)
	firstWriteEntered := make(chan struct{})
	writeInterrupted := make(chan struct{})
	releaseHandler := make(chan struct{})
	firstHandlerReturned := make(chan struct{})
	var requestCount atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(progressFrame))
			close(firstHandlerReturned)
			<-releaseHandler // deliberately ignore request cancellation
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
	})
	handler, err := transport.NewHandler(transport.HandlerConfig{
		Verifier:  fixtureVerifier(t, &clock{ts: testfixture.Now}),
		ServerKey: testfixture.PrivateKey(t, "svc"),
		Profile:   modern.ProfileModern,
		Streams:   &transport.StreamOptions{MaxStreamDuration: time.Second},
		TimerNow:  func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return timerClock },
		TimerAfterFunc: func(_ time.Duration, callback func()) transport.StreamTimer {
			timer := &controlledStreamTimer{callback: callback}
			timers <- timer
			return timer
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) }))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	writer := &blockedResponseWriter{header: make(http.Header), entered: firstWriteEntered, interrupted: writeInterrupted}
	first, _ := signedPost(t, &clock{ts: testfixture.Now}, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(21), 71, "s1")
	modernMirrors(first, "email.received")
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); handler.ServeHTTP(writer, first) }()
	cleanup := func() {
		select {
		case <-releaseHandler:
		default:
			close(releaseHandler)
		}
		writer.unblock()
	}
	t.Cleanup(cleanup)
	select {
	case <-firstWriteEntered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first physical stream write did not block")
	}
	var timer *controlledStreamTimer
	select {
	case timer = <-timers:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("stream timer was not armed")
	}
	clockMu.Lock()
	timerClock = timerClock.Add(2 * time.Second)
	clockMu.Unlock()
	timer.callback()
	select {
	case <-writeInterrupted:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timeout did not interrupt the blocked physical write")
	}
	select {
	case <-firstHandlerReturned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("handler did not return from its failed write")
	}
	second, _ := signedPost(t, &clock{ts: testfixture.Now}, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(22), 72, "s1")
	modernMirrors(second, "email.received")
	secondWriter := &blockedResponseWriter{header: make(http.Header)}
	secondDone := make(chan struct{})
	go func() { defer close(secondDone); handler.ServeHTTP(secondWriter, second) }()
	select {
	case <-secondDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("second same-identity stream did not complete")
	}
	if secondWriter.status != http.StatusOK {
		t.Fatalf("second stream status = %d, want admitted 200 (not 429)", secondWriter.status)
	}
	select {
	case <-firstDone:
		t.Fatal("first handler returned before explicit release")
	default:
	}
	cleanup()
	select {
	case <-firstDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first handler did not finish after release")
	}
	if bytes.Contains(writer.body.Bytes(), []byte(progressEvent)) {
		t.Fatal("a post-timeout message frame reached the response writer")
	}
}

type blockedResponseWriter struct {
	mu          sync.Mutex
	header      http.Header
	status      int
	body        bytes.Buffer
	entered     chan struct{}
	interrupted chan struct{}
	blocked     bool
	unblockOnce sync.Once
}

func (w *blockedResponseWriter) Header() http.Header    { return w.header }
func (w *blockedResponseWriter) WriteHeader(status int) { w.status = status }
func (w *blockedResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	block := w.entered != nil && !w.blocked
	if block {
		w.blocked = true
	}
	w.mu.Unlock()
	if block {
		close(w.entered)
		<-w.interrupted
		return 0, io.ErrClosedPipe
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}
func (w *blockedResponseWriter) SetWriteDeadline(time.Time) error {
	if w.interrupted != nil {
		w.unblock()
	}
	return nil
}
func (w *blockedResponseWriter) unblock() {
	if w.interrupted != nil {
		w.unblockOnce.Do(func() { close(w.interrupted) })
	}
}

// TestStreamLateSuccessorCutoffPollWritesEndBeforeActivation covers a successor
// otherwise idle stream before the activation.
func TestStreamLateSuccessorCutoffPollWritesEndBeforeActivation(t *testing.T) {
	const (
		openTS     = int64(2000)
		activation = int64(3000)
	)
	clk := &clock{ts: openTS}
	var successorKnown atomic.Bool
	provider := lateSuccessorProvider{
		key:    fixedSigner{key: testfixture.PrivateKey(t, "svc")},
		known:  &successorKnown,
		cutoff: activation,
	}
	timerClock := time.Unix(openTS, 0)
	timers := make(chan *controlledStreamTimer, 4)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	handler, err := transport.NewHandler(transport.HandlerConfig{
		Verifier:     fixtureVerifier(t, clk),
		ResponseKeys: provider,
		Profile:      modern.ProfileModern,
		Streams:      &transport.StreamOptions{MaxStreamDuration: time.Hour},
		TimerNow:     func() time.Time { return timerClock },
		TimerAfterFunc: func(_ time.Duration, callback func()) transport.StreamTimer {
			timer := &controlledStreamTimer{callback: callback}
			timers <- timer
			return timer
		},
	}, next)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(14), 61, "s1")
	modernMirrors(req, "email.received")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(rec, req)
	}()

	var timer *controlledStreamTimer
	select {
	case timer = <-timers:
	case <-done:
		t.Fatalf("stream returned before its polling timer was armed: status=%d body=%q", rec.Code, rec.Body.String())
	}
	// An early poll with no successor must rearm the timer. This is essential:
	// without the recurring poll, a successor announced later is never observed.
	timer.callback()
	select {
	case timer = <-timers:
	default:
		t.Fatal("timer callback did not rearm polling while no successor was known")
	}
	if !successorKnown.CompareAndSwap(false, true) {
		t.Fatal("successor was known before the stream opened")
	}
	// The stream opened without a cutoff; make the provider announce one only
	// after the first poll, then drive both injected clocks to the last legal second.
	clk.Set(activation - 1)
	timerClock = time.Unix(activation-1, 0)
	if timer.callback == nil {
		t.Fatal("polling timer has no callback")
	}
	timer.callback()
	<-done

	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) != 1 || frames[0].event != "jack-end" {
		t.Fatalf("frames = %+v, want exactly one jack-end and no handler message", frames)
	}
	if frames[0].ts < openTS {
		t.Fatalf("quiet-stream end timestamp = %d, want at least open timestamp %d", frames[0].ts, openTS)
	}
	if clk.Now() >= activation {
		t.Fatalf("injected verifier clock = %d, want below cutoff %d", clk.Now(), activation)
	}
	if frames[0].ts >= activation {
		t.Fatalf("end frame ts = %d, want below cutoff %d", frames[0].ts, activation)
	}
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("event: jack-end")) {
		t.Fatalf("response did not physically write the end frame after open: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

type lateSuccessorProvider struct {
	key    fixedSigner
	known  *atomic.Bool
	cutoff int64
}

func (p lateSuccessorProvider) AuthorizeResponse(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
	return transport.ResponseKeyAuthorization{
		Signer: p.key, Timestamp: 2000, Final: func() error { return nil }, Release: func() {},
	}, nil
}

func (p lateSuccessorProvider) StreamCutoff(string) (int64, bool, error) {
	if !p.known.Load() {
		return 0, false, nil
	}
	return p.cutoff, true, nil
}

type controlledStreamTimer struct {
	callback func()
}

func (t *controlledStreamTimer) Stop() bool { return true }

// ptr returns a pointer to v.
func ptr(v int64) *int64 { return &v }
