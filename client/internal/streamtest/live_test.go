// Package streamtest exercises the live signed-stream (s1) client end to end
// over real HTTP, against an httptest server (spec 05 section 4).
package streamtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	streamimpl "github.com/PHPCraftdream/mcp-jack/client/internal/stream"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
)

const (
	// testAud is the audience string bound into every request signing string.
	testAud = "https://svc.example.test"
	// testTS is the fixed signing clock of every test: time.Unix(1000, 0).
	testTS int64 = 1000
	// testRequestBody is the exact body every streaming request signs and sends.
	testRequestBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	// testMessage is the verified data value the message frame carries.
	testMessage = `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	// nonStreamReply is the exact signed body of a 501 refusal (1.4).
	nonStreamReply = `{"error":{"code":"streaming_unsupported","message":"x"}}`
	// signalFrame is the signed 2.18 transport signal of a frame-cap abort.
	signalFrame = `{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1048576}}`
	// guard is how long a test waits on a channel before it fails.
	guard = 10 * time.Second
)

// testSID is the base64url 16-byte stream id of every test.
var testSID = jack.EncodeBase64URL(bytes.Repeat([]byte{3}, 16))

// openAuth is the Jack-Auth open header the stream handlers answer with. Each
// test assigns it once, before it sends its request, and the handler only reads
// it afterwards.
var openAuth string

// acceptRecorder collects every Jack-Accept value a handler received.
type acceptRecorder struct {
	mu     sync.Mutex
	values []string
}

// record appends one received Jack-Accept value.
func (r *acceptRecorder) record(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, value)
}

// Values returns a copy of the recorded values in arrival order.
func (r *acceptRecorder) Values() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.values...)
}

// servedBody is the body one handler writes: the test stores the signed bytes
// before it sends the request and the handler only loads them afterwards.
type servedBody struct{ body atomic.Value } // []byte

// set stores the bytes the handler writes.
func (s *servedBody) set(body []byte) { s.body.Store(body) }

// get returns the stored bytes, or nil before set.
func (s *servedBody) get() []byte {
	body, _ := s.body.Load().([]byte)
	return body
}

// newStreamServer starts a 200 text/event-stream server that answers with the
// open header in openAuth and the bytes of bodyFn, then flushes. When block is
// true the handler then waits for the request context and closes the returned
// channel, once, before it returns: that signal means the server saw the
// connection end (1.4, 3.7).
func newStreamServer(t *testing.T, bodyFn func() []byte, block bool) (*httptest.Server, *acceptRecorder, chan struct{}) {
	t.Helper()
	recorder := &acceptRecorder{}
	done := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r.Header.Get("Jack-Accept"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Jack-Auth", openAuth)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(bodyFn()); err != nil {
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if !block {
			return
		}
		<-r.Context().Done()
		once.Do(func() { close(done) })
	}))
	return srv, recorder, done
}

// newTestSigner returns the deterministic signer of every test and its private
// key, so the test both signs and verifies with the same seed.
func newTestSigner(t *testing.T) (*client.InMemorySigner, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{1}, 32)
	signer, err := client.NewInMemorySigner(seed)
	if err != nil {
		t.Fatalf("NewInMemorySigner: %v", err)
	}
	return signer, ed25519.NewKeyFromSeed(seed)
}

// newTestTransport returns the transport every test opens its stream with.
func newTestTransport(signer *client.InMemorySigner) *client.Transport {
	pub := signer.PublicKey()
	tr := client.NewTransport(nil, testAud, signer, pub)
	tr.Now = func() time.Time { return time.Unix(testTS, 0) }
	tr.Nonce = func() ([]byte, error) { return bytes.Repeat([]byte{2}, 16), nil }
	return tr
}

// newStreamRequest builds the streaming request for srv.
func newStreamRequest(t *testing.T, srv *httptest.Server) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), "POST",
		srv.URL+"/mcp", bytes.NewReader([]byte(testRequestBody)))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	return req
}

// requestSignature returns base64url(sig) over the request signing string of
// req (spec 01 section 3.1), with the fixed test clock and nonce. The open
// header binds exactly this value as its requestSig line (spec 05 2.5).
func requestSignature(signer *client.InMemorySigner, priv ed25519.PrivateKey, req *http.Request) string {
	nonce := bytes.Repeat([]byte{2}, 16)
	message := jack.RequestSigningString(req.Method, req.URL.RequestURI(), testAud,
		signer.KID(), testTS, jack.EncodeBase64URL(nonce), []byte(testRequestBody))
	return jack.EncodeBase64URL(ed25519.Sign(priv, []byte(message)))
}

// openHeader returns the s1 open header value for requestSig and the sig
// parameter that roots the frame chain; the signature covers
// OpenSigningString(200, requestSig, kid, 1000, sid).
func openHeader(priv ed25519.PrivateKey, kid, requestSig string) (value, sig string) {
	sig = jack.EncodeBase64URL(ed25519.Sign(priv,
		[]byte(streamimpl.OpenSigningString(http.StatusOK, requestSig, kid, testTS, testSID))))
	return "s1 kid=" + kid + ",ts=" + strconv.FormatInt(testTS, 10) +
		",sid=" + testSID + ",sig=" + sig, sig
}

// responseAuth returns the v1 response Jack-Auth value over status and body for
// requestSig, signed by the test key at testTS (spec 01 section 5).
func responseAuth(priv ed25519.PrivateKey, kid, requestSig string, status int, body []byte) string {
	sig := jack.EncodeBase64URL(ed25519.Sign(priv,
		[]byte(jack.ResponseSigningString(status, requestSig, kid, testTS, body))))
	return jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: testTS, Sig: sig})
}

// messageFrameAt returns one signed message frame at seq chained from prevSig,
// and its sig. The signature covers the data value signed while the frame
// carries wire, so a test can serve a frame tampered after signing (spec 05
// 4.3 step 6) or a signed 2.18 transport signal.
func messageFrameAt(priv ed25519.PrivateKey, seq uint64, prevSig, signed, wire string) (frame, sig string) {
	sig = jack.EncodeBase64URL(ed25519.Sign(priv,
		[]byte(streamimpl.FrameSigningString(testSID, seq, testTS, prevSig,
			streamimpl.DataHash([]byte(signed))))))
	return "event: message\ndata: " + wire + "\njack: seq=" +
		strconv.FormatUint(seq, 10) + ",ts=" + strconv.FormatInt(testTS, 10) +
		",sig=" + sig + "\n\n", sig
}

// messageFrame returns the first signed message frame (seq 0) and its sig.
func messageFrame(priv ed25519.PrivateKey, openSig, signed, wire string) (frame, sig string) {
	return messageFrameAt(priv, 0, openSig, signed, wire)
}

// endFrame returns the signed end frame (seq 1) chained from prevSig, the sig
// of the preceding frame.
func endFrame(priv ed25519.PrivateKey, prevSig string) string {
	sig := jack.EncodeBase64URL(ed25519.Sign(priv,
		[]byte(streamimpl.FrameSigningString(testSID, 1, testTS, prevSig,
			streamimpl.DataHash([]byte(nil))))))
	return "event: jack-end\ndata:\njack: seq=1,ts=" +
		strconv.FormatInt(testTS, 10) + ",sig=" + sig + "\n\n"
}

// TestOpenStreamDeliversVerifiedMessages verifies the happy path: the open
// header, one message frame and the end frame all verify, the unsigned
// Jack-Accept opt-in arrives once, Next ends with io.EOF and Close is
// idempotent.
func TestOpenStreamDeliversVerifiedMessages(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, recorder, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, msgSig := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message + endFrame(priv, msgSig)))

	s, verified, err := newTestTransport(signer).OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	if msg, err := s.Next(); err != io.EOF || msg != "" {
		t.Fatalf("second Next() = %q, %v; want \"\", io.EOF", msg, err)
	}
	if got := recorder.Values(); len(got) != 1 || got[0] != "s1" {
		t.Fatalf("Jack-Accept values = %v, want [s1]", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestOpenStreamCallerCloseClosesTheConnection verifies 3.7: Close ends the
// request on the server and the next Next reports ErrClosed.
func TestOpenStreamCallerCloseClosesTheConnection(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, done := newStreamServer(t, served.get, true)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, _ := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message))

	s, verified, err := newTestTransport(signer).OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(guard):
		t.Fatalf("the server did not see the closed connection within %s", guard)
	}
	if _, err := s.Next(); !errors.Is(err, clientstream.ErrClosed) {
		t.Fatalf("Next after Close = %v, want %v", err, clientstream.ErrClosed)
	}
}

// TestOpenStreamIdleTimeout verifies 4.5: a stream that stops delivering frames
// fails with Idle, after the one frame that did verify.
func TestOpenStreamIdleTimeout(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, done := newStreamServer(t, served.get, true)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, _ := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message))

	tr := newTestTransport(signer)
	tr.Stream = &clientstream.ClientConfig{Idle: 100 * time.Millisecond}
	s, verified, err := tr.OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	nexted := make(chan error, 1)
	go func() {
		_, err := s.Next()
		nexted <- err
	}()
	var nextErr error
	select {
	case nextErr = <-nexted:
	case <-time.After(guard):
		t.Fatalf("the idling Next did not return within %s", guard)
	}
	var streamErr *clientstream.Error
	if !errors.As(nextErr, &streamErr) {
		t.Fatalf("Next after the idle timeout = %v, want *clientstream.Error", nextErr)
	}
	if streamErr.Code != clientstream.Idle {
		t.Fatalf("idle code = %q, want %q", streamErr.Code, clientstream.Idle)
	}
	if streamErr.FramesVerified != 1 {
		t.Fatalf("idle FramesVerified = %d, want 1", streamErr.FramesVerified)
	}
	select {
	case <-done:
	case <-time.After(guard):
		t.Fatalf("the server did not see the closed connection within %s", guard)
	}
	_ = s.Close()
}

// TestOpenStreamRejectsTamperedFrame verifies 4.3 step 6: a data value changed
// after signing fails with BadSignature and nothing is delivered.
func TestOpenStreamRejectsTamperedFrame(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, _ := messageFrame(priv, openSig, testMessage, testMessage+`,"tampered":true}`)
	served.set([]byte(message))

	s, verified, err := newTestTransport(signer).OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	_, nextErr := s.Next()
	var streamErr *clientstream.Error
	if !errors.As(nextErr, &streamErr) {
		t.Fatalf("Next on a tampered frame = %v, want *clientstream.Error", nextErr)
	}
	if streamErr.Code != clientstream.BadSignature {
		t.Fatalf("tampered code = %q, want %q", streamErr.Code, clientstream.BadSignature)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestOpenStreamVerifiesANonStreamReply verifies 1.4 and 4.1 both ways: a 501
// answer to an opted-in request is verified as a v1 response, so a signed one
// is returned as a *VerifiedResponse and an unsigned one is the missing-auth
// verification error, never a bare status.
func TestOpenStreamVerifiesANonStreamReply(t *testing.T) {
	signer, priv := newTestSigner(t)

	t.Run("signed", func(t *testing.T) {
		var headerValue atomic.Value // string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if value, _ := headerValue.Load().(string); value != "" {
				w.Header().Set("Jack-Auth", value)
			}
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(nonStreamReply))
		}))
		defer srv.Close()
		req := newStreamRequest(t, srv)
		requestSig := requestSignature(signer, priv, req)
		headerValue.Store(responseAuth(priv, signer.KID(), requestSig,
			http.StatusNotImplemented, []byte(nonStreamReply)))

		s, verified, err := newTestTransport(signer).OpenStream(req)
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		if s != nil {
			t.Fatalf("OpenStream stream = %v, want nil", s)
		}
		if verified == nil {
			t.Fatalf("OpenStream verified response = nil, want the 501 answer")
		}
		if verified.Status != http.StatusNotImplemented {
			t.Fatalf("verified status = %d, want %d", verified.Status, http.StatusNotImplemented)
		}
		if string(verified.Body) != nonStreamReply {
			t.Fatalf("verified body = %q, want %q", verified.Body, nonStreamReply)
		}
		if verified.Header.Get("Jack-Auth") == "" {
			t.Fatalf("verified headers carry no Jack-Auth: %v", verified.Header)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(nonStreamReply))
		}))
		defer srv.Close()

		s, verified, err := newTestTransport(signer).OpenStream(newStreamRequest(t, srv))
		if s != nil {
			t.Fatalf("OpenStream stream = %v, want nil", s)
		}
		if verified != nil {
			t.Fatalf("OpenStream verified response = %+v, want nil", verified)
		}
		var jackErr *jack.Error
		if !errors.As(err, &jackErr) {
			t.Fatalf("OpenStream on an unsigned 501 = %v, want *jack.Error", err)
		}
		if jackErr.Code != jack.CodeMissingAuth {
			t.Fatalf("unsigned 501 code = %q, want %q", jackErr.Code, jack.CodeMissingAuth)
		}
	})
}

// TestOpenStreamDeliversBeforeTerminalErrorInOneRead verifies 4.4 across a read
// boundary: when one read carries a good message frame and then a tampered one,
// the verified message is delivered before the terminal BadSignature.
func TestOpenStreamDeliversBeforeTerminalErrorInOneRead(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	first, firstSig := messageFrame(priv, openSig, testMessage, testMessage)
	tampered, _ := messageFrameAt(priv, 1, firstSig, testMessage,
		testMessage+`,"tampered":true}`)
	served.set([]byte(first + tampered))

	s, verified, err := newTestTransport(signer).OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	_, nextErr := s.Next()
	var streamErr *clientstream.Error
	if !errors.As(nextErr, &streamErr) {
		t.Fatalf("Next after the tampered frame = %v, want *clientstream.Error", nextErr)
	}
	if streamErr.Code != clientstream.BadSignature {
		t.Fatalf("tampered code = %q, want %q", streamErr.Code, clientstream.BadSignature)
	}
	if streamErr.FramesVerified != 1 {
		t.Fatalf("tampered FramesVerified = %d, want 1", streamErr.FramesVerified)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestOpenStreamDeliversBeforeSignalInOneRead verifies 4.4 and 2.18 in one
// read: a valid signed transport signal that follows a good message frame is
// not delivered, but it ends the stream after both frames verified.
func TestOpenStreamDeliversBeforeSignalInOneRead(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	first, firstSig := messageFrame(priv, openSig, testMessage, testMessage)
	signal, _ := messageFrameAt(priv, 1, firstSig, signalFrame, signalFrame)
	served.set([]byte(first + signal))

	s, verified, err := newTestTransport(signer).OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	_, nextErr := s.Next()
	var streamErr *clientstream.Error
	if !errors.As(nextErr, &streamErr) {
		t.Fatalf("Next after the signal = %v, want *clientstream.Error", nextErr)
	}
	if streamErr.Code != clientstream.FrameTooLarge {
		t.Fatalf("signal code = %q, want %q", streamErr.Code, clientstream.FrameTooLarge)
	}
	if streamErr.FramesVerified != 2 {
		t.Fatalf("signal FramesVerified = %d, want 2", streamErr.FramesVerified)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestOpenStreamIdleIgnoresCommentTrickle verifies 4.5: the idle deadline runs
// from the last verified frame, so comment bytes that keep arriving never keep
// the stream alive.
func TestOpenStreamIdleIgnoresCommentTrickle(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Jack-Auth", openAuth)
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if _, err := w.Write(served.get()); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				<-r.Context().Done()
				return
			case <-ticker.C:
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
	}))
	defer srv.Close()
	req := newStreamRequest(t, srv)
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, _ := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message))

	tr := newTestTransport(signer)
	tr.Stream = &clientstream.ClientConfig{Idle: 100 * time.Millisecond}
	s, verified, err := tr.OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	if msg, err := s.Next(); err != nil || msg != testMessage {
		t.Fatalf("Next() = %q, %v; want %q, nil", msg, err, testMessage)
	}
	nexted := make(chan error, 1)
	go func() {
		_, err := s.Next()
		nexted <- err
	}()
	var nextErr error
	select {
	case nextErr = <-nexted:
	case <-time.After(guard):
		t.Fatalf("the idling Next did not return within %s", guard)
	}
	var streamErr *clientstream.Error
	if !errors.As(nextErr, &streamErr) {
		t.Fatalf("Next while comments trickle = %v, want *clientstream.Error", nextErr)
	}
	if streamErr.Code != clientstream.Idle {
		t.Fatalf("trickle code = %q, want %q", streamErr.Code, clientstream.Idle)
	}
	if streamErr.FramesVerified != 1 {
		t.Fatalf("trickle FramesVerified = %d, want 1", streamErr.FramesVerified)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
