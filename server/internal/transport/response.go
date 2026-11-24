package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/stream"
	"github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

// ResponseSigner holds the server signing capability without private-key export.
// PublicKey returns the fixed identity of this handle, not a key-selection policy.
// The provider must bound method duration: the SDK waits synchronously
// and cannot forcibly interrupt a stuck callback.
type ResponseSigner interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

// ResponseKeyRequest is an owned copy; the payload is not the source of key authority.
type ResponseKeyRequest struct {
	Status           int
	Tool             string
	RequestSignature string
	Body             []byte
}

// ResponseKeyAuthorization pins identity/time and the lease until the write completes.
// The provider must bound its callbacks and must not lose the lease on panic/error.
type ResponseKeyAuthorization struct {
	Signer    ResponseSigner
	Timestamp int64
	// Cutoff is the successor activation A known for the selected key (spec 05
	// section 5.1); nil means the provider knows no successor.
	Cutoff  *int64
	Final   func() error
	Release func()
}

// ResponseKeyProvider is selected explicitly; persistence/clock/ring invariants belong to the provider.
type ResponseKeyProvider interface {
	AuthorizeResponse(ResponseKeyRequest) (ResponseKeyAuthorization, error)
}

var errResponseSigner = errors.New("server: response signer unavailable")

var errResponseAuthorization = errors.New("server: response authorization unavailable")

func responsePublicKey(signer ResponseSigner) (public []byte, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			public, result = nil, errResponseSigner
		}
	}()
	provided := signer.PublicKey()
	if len(provided) != ed25519.PublicKeySize {
		complete = true
		return nil, errResponseSigner
	}
	public = append([]byte(nil), provided...)
	if jack.ValidatePublicKey(public) != nil {
		complete = true
		return nil, errResponseSigner
	}
	complete = true
	return public, nil
}

func responseSignature(signer ResponseSigner, public []byte, message string) (signature []byte, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			signature, result = nil, errResponseSigner
		}
	}()
	provided, err := signer.Sign([]byte(message))
	if err != nil || len(provided) != ed25519.SignatureSize {
		complete = true
		return nil, errResponseSigner
	}
	signature = append([]byte(nil), provided...)
	// The provider cannot alter the expected message or attest a different identity.
	if !jack.Verify(public, []byte(message), signature) {
		complete = true
		return nil, errResponseSigner
	}
	complete = true
	return signature, nil
}

func authorizeResponse(provider ResponseKeyProvider, input ResponseKeyRequest) (authorization ResponseKeyAuthorization, err error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			err = errResponseAuthorization
		}
	}()
	authorization, err = provider.AuthorizeResponse(input)
	complete = true
	if err != nil {
		return authorization, errResponseAuthorization
	}
	if authorization.Signer == nil || authorization.Final == nil || authorization.Release == nil || authorization.Timestamp < 0 || authorization.Timestamp > verify.MaxDurableTimestamp {
		return authorization, errResponseAuthorization
	}
	return authorization, nil
}

func finalResponseAuthorization(check func() error) (err error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			err = errResponseAuthorization
		}
	}()
	err = check()
	complete = true
	if err != nil {
		return errResponseAuthorization
	}
	return nil
}

func releaseResponseAuthorization(release func()) {
	if release == nil {
		return
	}
	defer func() { _ = recover() }()
	release()
}

func (h *handler) writeAuthorized(w http.ResponseWriter, status int, header http.Header, body []byte, requestSignature, tool string) {
	payload := append([]byte(nil), body...)
	input := ResponseKeyRequest{Status: status, Tool: tool, RequestSignature: requestSignature, Body: append([]byte(nil), payload...)}
	authorization, err := authorizeResponse(h.keys, input)
	defer releaseResponseAuthorization(authorization.Release)
	refuse := func() {
		writeError(w, http.StatusServiceUnavailable, "rotation_state_unavailable", "response authorization unavailable")
	}
	if err != nil {
		refuse()
		return
	}
	public, err := responsePublicKey(authorization.Signer)
	if err != nil {
		refuse()
		return
	}
	kid := jack.KeyID(public)
	message := jack.ResponseSigningString(status, requestSignature, kid, authorization.Timestamp, payload)
	signature, err := responseSignature(authorization.Signer, public, message)
	if err != nil {
		refuse()
		return
	}
	if err := finalResponseAuthorization(authorization.Final); err != nil {
		refuse()
		return
	}
	header.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: authorization.Timestamp, Sig: jack.EncodeBase64URL(signature)}))
	writeRaw(w, status, header, payload)
}

// StreamOptions configures signed response streams (spec 05 section 3).
type StreamOptions = stream.Options

// StreamCutoffReader is implemented by a response-key provider that can report
// the successor activation of a running stream's key (spec 05 section 5.1), so
// a successor announced after the stream opened is honoured.
type StreamCutoffReader interface {
	StreamCutoff(kid string) (int64, bool, error)
}

// StreamGrant reports the signed-stream limits the server granted to a request
// handed to the wrapped handler (spec 05 section 3.5). The SDK emits no
// heartbeats itself: the wrapped handler emits them as ordinary signed frames.
type StreamGrant struct {
	// Heartbeat is heartbeatMs as granted: at most floor(W*500) milliseconds.
	Heartbeat time.Duration
}

type streamGrantKey struct{}

func withStreamGrant(ctx context.Context, heartbeat time.Duration) context.Context {
	return context.WithValue(ctx, streamGrantKey{}, StreamGrant{Heartbeat: heartbeat})
}

// StreamFromContext returns the signed-stream grant of a request handed to the
// wrapped handler and reports whether the request opted in to a stream.
func StreamFromContext(ctx context.Context) (StreamGrant, bool) {
	grant, ok := ctx.Value(streamGrantKey{}).(StreamGrant)
	return grant, ok
}

type StreamTimer interface {
	Stop() bool
}

type streamAfterFunc func(time.Duration, func()) StreamTimer

// streamHook starts and writes a text/event-stream answer to a request that opted in
// with Jack-Accept: s1.
type streamHook struct {
	handler *handler
	result  verify.Result
	// body is the request body, needed for the final response of 6.3.
	body    []byte
	enabled bool
	// w is the real response writer; the signed stream is written to it
	// directly, never through the buffer.
	w      http.ResponseWriter
	cancel context.CancelFunc
	// identity is the per-identity concurrency key of 3.3.
	identity string
	// release frees the limiter slot held by the stream.
	release func()
	// signing is the key and the authorization of the stream (3.1, 3.3, 5.1).
	signing streamSigning
	// notRequest marks an opt-in request whose body was not a request: it gets
	// the signed 202 of 3.8 instead of a stream.
	notRequest bool
	// finishOnce makes finish idempotent and safe to defer.
	finishOnce     sync.Once
	releaseOnce    sync.Once
	session        *stream.Session
	timer          StreamTimer
	timerMu        sync.Mutex
	timerStopped   bool
	durationAt     time.Time
	timerNow       func() time.Time
	timerAfterFunc streamAfterFunc
	// refusal, when set, is the answer of a stream the hook had to refuse
	// instead of streaming it; it runs once the wrapped handler returned.
	refusal func()
}

// start turns the committed text/event-stream answer into a signed stream. It
// is called once from bufferedWriter.commit and reports whether the bytes of
// the handler are now signed frames; on false the answer is refused, either by
// refusal (a stream the hook refused) or by the bufferedWriter's own 501.
func (s *streamHook) start() bool {
	if s == nil {
		return false
	}
	if s.notRequest {
		// 3.8: a body that was not a request never gets a stream; it gets the
		// signed 202 instead.
		s.refusal = func() { s.handler.writeStreamAccepted(s.w, s.result) }
		return false
	}
	if !s.enabled {
		return false
	}
	// 3.3: the slot is taken before any stream byte; a refusal answers 429.
	release, ok := s.handler.limiter.Acquire(s.identity)
	if !ok {
		s.refusal = func() { s.handler.writeStreamLimit(s.w, s.result) }
		return false
	}
	s.release = release
	signing, err := s.handler.streamKey(s.result)
	if err != nil {
		s.refusal = func() { s.handler.writeStreamUnavailable(s.w, s.result) }
		return false
	}
	s.signing = signing
	sid, err := stream.NewSID()
	if err != nil {
		s.refusal = func() { s.handler.writeStreamUnavailable(s.w, s.result) }
		return false
	}
	flush := func() {}
	if flusher, ok := s.w.(http.Flusher); ok {
		flush = flusher.Flush
	}
	session, err := stream.OpenSession(s.w, stream.SessionConfig{
		Options:    s.handler.streams,
		Key:        signing.key,
		RequestSig: s.result.RequestSig,
		SID:        sid,
		Now:        signing.now,
		Cutoff:     signing.cutoff,
		Final:      signing.gate,
		Flush:      flush,
		Stop:       s.cancel,
		Interrupt:  s.interruptWriter,
	})
	if err != nil {
		// No unsigned stream byte is ever written: the open header failed.
		s.refusal = func() { s.handler.writeStreamRefused(s.w, s.result) }
		return false
	}
	// 2.1 headers: the session owns the body, so the buffered answer is gone.
	header := s.w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("X-Accel-Buffering", "no")
	header.Set("Jack-Auth", session.HeaderValue())
	header.Del("Content-Length")
	s.w.WriteHeader(http.StatusOK)
	flush()
	s.session = session
	if s.timerNow == nil {
		s.timerNow = time.Now
	}
	if s.timerAfterFunc == nil {
		s.timerAfterFunc = func(d time.Duration, f func()) StreamTimer { return time.AfterFunc(d, f) }
	}
	s.durationAt = s.timerNow().Add(s.handler.streams.MaxStreamDuration)
	d := s.handler.streams.MaxStreamDuration
	if cutoff, ok := s.signing.cutoffNow(); ok {
		remaining := time.Duration(cutoff-session.OpenTimestamp()-1) * time.Second
		if remaining < d {
			d = remaining
		}
	}
	if d <= 0 {
		d = time.Millisecond
	}
	final := s.finalResponse
	s.armTimer(session, final)
	return true
}

func (s *streamHook) armTimer(session *stream.Session, final func(string) string) {
	d := s.durationAt.Sub(s.timerNow())
	if d <= 0 {
		err := session.Timeout(final)
		if err != nil {
			s.interruptWriter()
		}
		<-session.Done()
		s.releaseResources()
		return
	}
	if cutoff, ok := s.signing.cutoffNow(); ok {
		remaining := time.Duration(cutoff-s.signing.now()-1) * time.Second
		if remaining < d {
			d = remaining
		}
	}
	// Re-read a provider's live cutoff frequently even when no successor was
	// known at open; a later rotation must shorten the current timer.
	if d > 100*time.Millisecond {
		d = 100 * time.Millisecond
	}
	if d <= 0 {
		d = time.Millisecond
	}
	timer := s.timerAfterFunc(d, func() {
		cutoffReached := false
		if cutoff, ok := s.signing.cutoffNow(); ok {
			cutoffReached = s.signing.now() >= cutoff-1
		}
		timedOut := false
		if !s.timerNow().Before(s.durationAt) || cutoffReached {
			err := session.Timeout(final)
			timedOut = session.Closed()
			if err != nil {
				s.interruptWriter()
				timedOut = true
			}
		}
		if timedOut {
			<-session.Done()
			s.releaseResources()
			return
		}
		if !session.Terminating() {
			s.armTimer(session, final)
		}
	})
	s.timerMu.Lock()
	if s.timerStopped || session.Closed() {
		s.timerMu.Unlock()
		timer.Stop()
		return
	}
	previous := s.timer
	s.timer = timer
	s.timerMu.Unlock()
	if previous != nil {
		previous.Stop()
	}
}
func (s *streamHook) streaming() bool { return s != nil && s.session != nil }

func (s *streamHook) write(p []byte) (int, error) {
	if !s.streaming() {
		return 0, errStreamRefused
	}
	return s.session.Write(p)
}

// flush is a no-op while streaming: the session flushes after every frame, so
// the method only keeps the writer symmetry.
func (s *streamHook) flush() {}

// finish ends the stream and frees its slot once the wrapped handler returned.
// It is idempotent, so it is safe to call it from a defer and from a branch.
func (s *streamHook) finish() {
	if s == nil {
		return
	}
	s.finishOnce.Do(func() {
		defer s.releaseResources()
		s.timerMu.Lock()
		s.timerStopped = true
		timer := s.timer
		s.timerMu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if s.session != nil {
			if err := s.session.Close(); err != nil {
				s.interruptWriter()
			}
			<-s.session.Done()
		}
	})
}

func (s *streamHook) releaseResources() {
	s.releaseOnce.Do(func() {
		defer func() {
			if s.release != nil {
				s.release()
			}
		}()
		if s.signing.release != nil {
			defer s.signing.release()
		}
	})
}

func (s *streamHook) interruptWriter() {
	if s.w != nil {
		controller := http.NewResponseController(s.w)
		_ = controller.SetWriteDeadline(time.Now())
		if closer, ok := s.w.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

// refused reports that the hook has an answer to write instead of the stream.
func (s *streamHook) refused() bool { return s != nil && s.refusal != nil && !s.streaming() }

// fail runs the refusal once.
func (s *streamHook) fail() {
	if s == nil || s.refusal == nil {
		return
	}
	refusal := s.refusal
	s.refusal = nil
	refusal()
}

// finalResponse returns the 6.3 final response for an events/stream close, or
// "" when no final response must be written: no id, another method, or a last
// message that already completes the request.
func (s *streamHook) finalResponse(last string) string {
	if s == nil {
		return ""
	}
	id := s.result.RPCID
	if len(id) == 0 || requestMethod(s.body) != "events/stream" || isFinalResponse(last, id) {
		return ""
	}
	return `{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":` + string(id) + `}}}`
}

// requestMethod returns the method of a JSON-RPC request body, or "" when the
// body is not one.
func requestMethod(body []byte) string {
	var msg struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return ""
	}
	return msg.Method
}

// isFinalResponse reports whether data is the final JSON-RPC response of the
// request with id: JSON-RPC 2.0, no method member, exactly one of result and
// error, and the same id lexeme.
func isFinalResponse(data string, id json.RawMessage) bool {
	var msg struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Method  *json.RawMessage `json:"method"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return false
	}
	if msg.JSONRPC != "2.0" || msg.Method != nil {
		return false
	}
	if (msg.Result != nil) == (msg.Error != nil) {
		return false
	}
	var want, got bytes.Buffer
	if err := json.Compact(&want, id); err != nil {
		return false
	}
	if err := json.Compact(&got, msg.ID); err != nil {
		return false
	}
	return bytes.Equal(want.Bytes(), got.Bytes())
}

// writeStreamLimit writes the signed 3.3 refusal of a stream that would exceed
// the per-identity concurrency limit.
func (h *handler) writeStreamLimit(w http.ResponseWriter, res verify.Result) {
	id := res.RPCID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body := []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32603,"message":"stream_limit_exceeded"}}`)
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusTooManyRequests, header, body, res.RequestSig, res.Tool)
}

// writeStreamRefused writes the signed 501 streaming_unsupported refusal of a
// stream the server cannot sign.
func (h *handler) writeStreamRefused(w http.ResponseWriter, res verify.Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusNotImplemented, header, errorBody("streaming_unsupported", "streaming responses cannot be signed in v0.1"), res.RequestSig, res.Tool)
}

// writeStreamAccepted writes the signed 202 of 3.8: an opt-in request whose
// body was not a request never gets a stream.
func (h *handler) writeStreamAccepted(w http.ResponseWriter, res verify.Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusAccepted, header, nil, res.RequestSig, res.Tool)
}

// writeStreamUnavailable writes the answer of a stream whose signing key
// cannot be selected: the signed 501 when the request carries a signature,
// the unsigned 503 otherwise.
func (h *handler) writeStreamUnavailable(w http.ResponseWriter, res verify.Result) {
	if len(res.RequestSig) > 0 {
		h.writeStreamRefused(w, res)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "rotation_state_unavailable", "response authorization unavailable")
}

// streamIdentity is the concurrency key of 3.3: the stable registry name of the
// caller, else its kid, else the authenticated kid.
func streamIdentity(res verify.Result) string {
	if res.Identity != nil {
		if name := res.Identity.Name(); name != "" {
			return name
		}
		if kid := res.Identity.Kid(); kid != "" {
			return kid
		}
	}
	return res.Kid
}

// streamSigning is the signing key of one stream and the authorization behind
// it. The provider lease stays held for the whole stream, the final gate runs
// before the end frame, and the lease is released only after it (3.1, 3.3, 5.1).
type streamSigning struct {
	key     stream.Key
	now     func() int64
	cutoff  func() (int64, bool)
	gate    func() error
	release func()
}

// cutoffNow returns the best-known successor activation for the stream's key.
func (s streamSigning) cutoffNow() (int64, bool) {
	cutoff, known := int64(0), false
	if s.key.Cutoff != nil {
		cutoff, known = *s.key.Cutoff, true
	}
	if s.cutoff != nil {
		// A successor announced after the stream opened still counts (5.1).
		if a, ok := s.cutoff(); ok && (!known || a < cutoff) {
			cutoff, known = a, true
		}
	}
	return cutoff, known
}

// streamKey selects the signing key of one stream (spec 05 section 3.1) and the
// clock its frames carry, together with the authorization it runs under.
func (h *handler) streamKey(res verify.Result) (streamSigning, error) {
	if h.keys != nil {
		authorization, err := authorizeResponse(h.keys, ResponseKeyRequest{Status: http.StatusOK, Tool: res.Tool, RequestSignature: res.RequestSig})
		if err != nil {
			return streamSigning{}, err
		}
		public, err := responsePublicKey(authorization.Signer)
		if err != nil {
			releaseResponseAuthorization(authorization.Release)
			return streamSigning{}, err
		}
		// The lease stays held for the whole stream: the final gate and the
		// release run in finish, after the end frame (3.1, 3.3, 5.1).
		kid := jack.KeyID(public)
		signing := streamSigning{
			key: stream.Key{
				Kid:       kid,
				PublicKey: public,
				Sign: func(message []byte) ([]byte, error) {
					return responseSignature(authorization.Signer, public, string(message))
				},
				Cutoff: authorization.Cutoff,
			},
			now: func() int64 {
				t := verify.RawNow(h.v)
				if t < authorization.Timestamp {
					t = authorization.Timestamp
				}
				return t
			},
			gate:    authorization.Final,
			release: authorization.Release,
		}
		if reader, ok := h.keys.(StreamCutoffReader); ok {
			signing.cutoff = func() (int64, bool) {
				cutoff, known, err := reader.StreamCutoff(kid)
				if err != nil || !known {
					if authorization.Cutoff != nil {
						return *authorization.Cutoff, true
					}
					return 0, false
				}
				return cutoff, true
			}
		}
		return signing, nil
	}
	if len(h.public) == 0 || h.kid == "" {
		return streamSigning{}, errResponseSigner
	}
	key := stream.Key{Kid: h.kid, PublicKey: h.public}
	if h.signer != nil {
		key.Sign = func(message []byte) ([]byte, error) {
			return responseSignature(h.signer, h.public, string(message))
		}
	} else {
		key.Sign = func(message []byte) ([]byte, error) { return ed25519.Sign(h.key, message), nil }
	}
	now := func() int64 { return verify.RawNow(h.v) }
	return streamSigning{key: key, now: now}, nil
}
