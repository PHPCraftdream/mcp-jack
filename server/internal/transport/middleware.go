// Package transport holds the HTTP hand-off seam: the middleware that
// authenticates requests through a Verifier, forwards accepted requests to
// the wrapped MCP handler with the verified caller identity in the request
// context, and signs every answer.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	"github.com/PHPCraftdream/mcp-jack/server/internal/rpcbody"
	"github.com/PHPCraftdream/mcp-jack/server/internal/stream"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

const (
	defaultMaxBodyBytes = 1 << 20
	// defaultMaxResponseBytes matches the client's response buffer default.
	defaultMaxResponseBytes = 1 << 20
)

// HandlerConfig configures NewHandler.
type HandlerConfig struct {
	// Verifier authenticates and authorizes every request.
	Verifier *verify.Verifier
	// ServerKey signs responses (spec 01 section 5); clients pin its public key.
	ServerKey ed25519.PrivateKey
	// ResponseSigner is selected explicitly instead of ServerKey, with a fixed public identity.
	ResponseSigner ResponseSigner
	// ResponseKeys is a separate opt-in authorization/final-gate profile, with no fallback.
	ResponseKeys ResponseKeyProvider
	// MaxBodyBytes bounds the request body; zero means 1 MiB. The body must
	// be read in full to be hashed, so the limit is a denial-of-service guard.
	MaxBodyBytes int64
	// MaxResponseBytes bounds the response body buffered from the wrapped
	// handler before it is signed; zero means 1 MiB and a negative value makes
	// NewHandler fail. It is distinct from MaxBodyBytes, which bounds only the
	// request. A body of exactly MaxResponseBytes passes; one more byte
	// overflows. On overflow the wrapped handler's context is cancelled, its
	// further writes fail and the client gets a signed 502 with the error code
	// response_too_large; the upstream status, headers and partial body are
	// discarded. Go cannot forcibly stop a handler goroutine: a handler that
	// ignores both context cancellation and write errors, or an idle producer
	// that never writes, is not stopped by this cap and can still delay the
	// answer. The adapter never detaches the wrapped handler.
	MaxResponseBytes int64
	// Profile is the deployment profile of spec 04 section 3: legacy, modern
	// or both. The zero value is legacy and keeps 0.1.x behaviour
	// byte-identical.
	Profile modern.Profile
	// Streams configures signed response streams (spec 05 section 3): the frame
	// cap, the per-identity concurrency limit, the maximum duration and the
	// heartbeat grant. Nil keeps the defaults of that section. A modern-profile
	// request that opted in with `Jack-Accept: s1` and whose handler answers
	// text/event-stream is signed as a stream; every other answer is unchanged.
	Streams *StreamOptions
	// TimerNow and TimerAfterFunc are injectable stream-timer dependencies.
	TimerNow       func() time.Time
	TimerAfterFunc func(time.Duration, func()) StreamTimer
}

type handler struct {
	v      *verify.Verifier
	key    ed25519.PrivateKey
	signer ResponseSigner
	keys   ResponseKeyProvider
	public []byte
	kid    string
	limit  int64
	// respLimit bounds the buffered upstream response body.
	respLimit int64
	// profile selects the era handling of every request (spec 04 section 3).
	profile modern.Profile
	// streams holds the normalized signed-stream options (spec 05 section 3).
	streams stream.Options
	// limiter bounds concurrent streams per authenticated identity (3.3).
	limiter        *stream.Limiter
	next           http.Handler
	timerNow       func() time.Time
	timerAfterFunc streamAfterFunc
}

// NewHandler wraps next, an unmodified MCP server, so that only authenticated
// and authorized requests reach it and every verified answer is signed.
// Protocol-native tools are answered here and never reach next.
//
// The response of next is buffered before it is signed, up to
// HandlerConfig.MaxResponseBytes (default 1 MiB, distinct from the request
// cap MaxBodyBytes). A larger body is answered with a signed 502
// response_too_large; the request context given to next is cancelled and its
// later writes fail, but Go cannot forcibly stop next: a handler that ignores
// both context cancellation and write errors, or an idle producer that never
// writes, is not stopped by the cap and can still delay the answer. A negative
// MaxResponseBytes is an error.
//
// An event-stream (text/event-stream) answer is not passed through unsigned: it
// is answered with the signed 501 streaming_unsupported, except for the signed
// stream of the next paragraph. The 501 takes precedence over the size
// overflow.
//
// In the modern deployment profile a POST request that carried the unsigned
// Jack-Accept: s1 header and has a JSON-RPC id is answered as a signed stream
// instead (spec 05): the open header is written at the first commit and the
// frames are signed as the handler produces them, so the buffered-body rules
// (MaxResponseBytes, response_too_large) do not apply to a stream. A stream is
// refused before any of its bytes with the signed 429 stream_limit_exceeded
// when the per-identity limit is reached (spec 05 section 3.3).
//
// A stream is detected early when the Content-Type is text/event-stream at the
// moment next commits its response headers (first WriteHeader, Write or
// Flush). From then on the request context given to next is cancelled, every
// Write to it fails with an error and its bytes are discarded, so no stream
// bytes are retained. A text/event-stream Content-Type set after the headers
// were committed is still refused when next returns, but without early
// cancellation: earlier writes already succeeded and were buffered, and the
// handler's own return is the only bound.
// Go cannot forcibly stop a handler goroutine, so the signed 501 is written
// only when next returns: a handler that ignores both context cancellation and
// write errors can still delay the answer. The adapter never detaches or
// abandons next; panics from next propagate unchanged.
func NewHandler(cfg HandlerConfig, next http.Handler) (http.Handler, error) {
	var streamsErr error
	if cfg.Streams != nil {
		streamsErr = cfg.Streams.Validate()
	}
	switch {
	case cfg.Verifier == nil:
		return nil, errors.New("server: HandlerConfig.Verifier must be set")
	case cfg.ResponseKeys != nil && (cfg.ResponseSigner != nil || len(cfg.ServerKey) != 0):
		return nil, errors.New("server: select exactly one response signing profile")
	case verify.HasServerKeys(cfg.Verifier) && cfg.ResponseKeys == nil:
		return nil, errors.New("server: candidate server-key delivery requires ResponseKeys")
	case cfg.ResponseSigner != nil && len(cfg.ServerKey) != 0:
		return nil, errors.New("server: select exactly one response signing profile")
	case cfg.ResponseKeys == nil && cfg.ResponseSigner == nil && len(cfg.ServerKey) != ed25519.PrivateKeySize:
		return nil, errors.New("server: HandlerConfig.ServerKey must be an Ed25519 private key")
	case next == nil:
		return nil, errors.New("server: next handler must be set")
	case cfg.MaxResponseBytes < 0:
		// A limit must never silently disable itself.
		return nil, errors.New("server: HandlerConfig.MaxResponseBytes must not be negative")
	case cfg.Profile != "" && !modern.ValidProfile(cfg.Profile):
		return nil, errors.New("server: HandlerConfig.Profile must be legacy, modern or both")
	case streamsErr != nil:
		return nil, streamsErr
	}
	profile := cfg.Profile
	if profile == "" {
		profile = modern.ProfileLegacy
	}
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	respLimit := cfg.MaxResponseBytes
	if respLimit == 0 {
		respLimit = defaultMaxResponseBytes
	}
	var public []byte
	if cfg.ResponseSigner != nil {
		var err error
		public, err = responsePublicKey(cfg.ResponseSigner)
		if err != nil {
			return nil, err
		}
	} else if cfg.ResponseKeys == nil {
		public = cfg.ServerKey.Public().(ed25519.PublicKey)
	}
	var kid string
	if public != nil {
		kid = jack.KeyID(public)
	}
	opts := StreamOptions{}
	if cfg.Streams != nil {
		opts = *cfg.Streams
	}
	opts = opts.Normalize(time.Duration(verify.Window(cfg.Verifier)) * time.Second)
	return &handler{v: cfg.Verifier, key: cfg.ServerKey, signer: cfg.ResponseSigner, keys: cfg.ResponseKeys, public: public, kid: kid, limit: limit, respLimit: respLimit, profile: profile, streams: opts, limiter: stream.NewLimiter(opts.MaxConcurrentStreams), next: next, timerNow: cfg.TimerNow, timerAfterFunc: func(d time.Duration, f func()) StreamTimer {
		if cfg.TimerAfterFunc != nil {
			return cfg.TimerAfterFunc(d, f)
		}
		return time.AfterFunc(d, f)
	}}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.profile == modern.ProfileLegacy {
		h.serve(w, r, false)
		return
	}
	h.serve(w, r, true)
}

// serve is the request pipeline shared by every deployment profile. eraAware
// is false for the legacy profile, where 0.1.x behaviour stays byte-identical;
// it is true otherwise, so the spec 04 era decision runs after authentication
// and before any era-neutral method refusal.
func (h *handler) serve(w http.ResponseWriter, r *http.Request, eraAware bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		// Spec 04 section 3: a non-POST request carries no body, so the era of
		// a method other than GET and POST is decided from the version header
		// instances alone, before the body is read and before authentication.
		// A legacy-era request gets the 0.1.x refusal byte-identically to the
		// legacy profile: no body read, no nonce, no authentication.
		if !eraAware || modern.EraFromHeaders(h.profile, headerList(r.Header)) == "legacy" {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET and POST are defined")
			return
		}
	}
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	if !originFormTarget(target) {
		writeError(w, http.StatusBadRequest, jack.CodeInvalidRequest, "request target must be origin-form")
		return
	}
	target = signedTarget(target)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, jack.CodeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, jack.CodeInvalidRequest, "request body could not be read")
		return
	}

	authenticateOnly := eraAware && r.Method != http.MethodPost
	classifyOnly := eraAware && r.Method == http.MethodPost
	res := h.v.Verify(verify.Request{Method: r.Method, Target: target, AuthValues: r.Header.Values("Jack-Auth"), Body: body, AuthenticateOnly: authenticateOnly, ClassifyOnly: classifyOnly})
	defer res.Done()
	switch {
	case !res.Accepted && !res.Pending:
		if eraAware && res.NonceRecorded && res.Code == jack.CodeInvalidRequest && res.BodyRefusal == rpcbody.ReasonToolName {
			header := http.Header{}
			header.Set("Content-Type", "application/json")
			h.writeSignedMethod(w, r.Method, http.StatusBadRequest, header, errorBody(modern.ClassificationCode, modern.ClassificationMessage), res.RequestSig, res.Tool)
			return
		}
		h.reject(w, r.Method, res)
	case !eraAware:
		if res.Native {
			h.native(w, res, false)
			return
		}
		h.forward(w, r, body, res, false)
	default:
		h.serveModern(w, r, target, body, res)
	}
}

// serveModern applies the era rules of spec 04 section 5 to an authenticated,
// classified request and dispatches its outcome. The rules run before the
// deferred dispatch, so a request they refuse has no native effect and no
// audit event.
func (h *handler) serveModern(w http.ResponseWriter, r *http.Request, target string, body []byte, res verify.Result) {
	out := modern.Classify(h.profile, modern.Request{Method: r.Method, Target: target, Headers: headerList(r.Header), Body: body})
	switch out.Kind {
	case modern.KindRefuse:
		h.writeModernRefusal(w, r.Method, out, res.RequestSig, res.Tool)
	case modern.KindRefuseInvalidRequest:
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		h.writeSignedMethod(w, r.Method, http.StatusBadRequest, header, errorBody(out.ErrorCode, out.Error.Message), res.RequestSig, res.Tool)
	case modern.KindForward:
		if out.Era == "legacy" {
			// 02 section 2 item 1: GET is accepted and POST is dispatched and
			// forwarded exactly as the legacy profile does. A method other than
			// GET and POST never reaches this branch: serve answers it before
			// the body is read (spec 04 section 3).
			res = verify.Dispatch(h.v, res)
			if !res.Accepted {
				h.reject(w, r.Method, res)
				return
			}
			if res.Native {
				h.native(w, res, false)
				return
			}
			h.forward(w, r, body, res, false) // the original r.Header is untouched
			return
		}
		res = verify.Dispatch(h.v, res)
		if !res.Accepted {
			h.reject(w, r.Method, res)
			return
		}
		if res.Native {
			h.native(w, res, true)
			return
		}
		r.Header = headerMap(out.Forward.Headers)
		h.forward(w, r, body, res, true)
	default:
		h.rejectInternal(w, res)
	}
}

// headerList renders the received header list as spec 04 section 2 Header
// values, with names sorted for determinism and values in received order.
// Go's net/http stores headers in a map, so the received wire order is already
// gone by the time the middleware sees the request; the slice order here is a
// deterministic reconstruction, not the wire order, and the names were
// canonicalised by net/http (see Forward.Headers in server/internal/modern).
func headerList(h http.Header) []modern.Header {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]modern.Header, 0, len(names))
	for _, name := range names {
		for _, value := range h[name] {
			list = append(list, modern.Header{Name: name, Value: value})
		}
	}
	return list
}

// headerMap rebuilds a header map from a forwarded header list. Go's net/http
// canonicalises received header names and stores headers in a map, so this
// rebuild preserves the values and the names of the list but not the wire
// order; the spec 04 S9 order and casing are the classification-level
// modern.Header slice (see Forward.Headers in server/internal/modern).
func headerMap(list []modern.Header) http.Header {
	dst := make(http.Header, len(list))
	for _, h := range list {
		dst[h.Name] = append(dst[h.Name], h.Value)
	}
	return dst
}

// writeModernRefusal writes a signed JSON-RPC refusal of spec 04 section 5.1.
// method lets the answer honour S10: a HEAD refusal is signed over the empty
// body it sends.
func (h *handler) writeModernRefusal(w http.ResponseWriter, method string, out modern.Outcome, requestSig, tool string) {
	header := http.Header{}
	header.Set("Content-Type", out.ContentType)
	if out.HTTPStatus == http.StatusMethodNotAllowed {
		header.Set("Allow", "POST")
	}
	id := out.ID
	if len(id) == 0 {
		id = []byte("null")
	}
	payload := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: json.RawMessage(id)}
	payload.Error.Code = out.Error.Code
	payload.Error.Message = out.Error.Message
	body, err := json.Marshal(payload)
	if err != nil {
		// Marshal of this shape cannot fail; never answer unsigned regardless.
		h.writeSignedMethod(w, method, http.StatusInternalServerError, header, errorBody("internal_error", "internal error"), requestSig, tool)
		return
	}
	h.writeSignedMethod(w, method, out.HTTPStatus, header, body, requestSig, tool)
}

// originFormTarget reports whether the raw request target is origin-form: it
// starts with '/' and consists only of the bytes 0x21 to 0x7E. Absolute-,
// authority- and asterisk-form targets, spaces, controls and non-ASCII bytes
// would make the signed bytes ambiguous (spec 01 section 3.1).
func originFormTarget(raw string) bool {
	if !strings.HasPrefix(raw, "/") {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// signedTarget drops the fragment: the first '#' and everything after it is
// not part of the target (a conforming client never sends one, and an HTTP
// stack such as the Rust one drops it before the handler sees the request).
func signedTarget(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		return raw[:i]
	}
	return raw
}

// reject answers a failed request. Once authentication has succeeded the
// client holds a request signature to bind to, so the answer is signed; an
// authentication failure may be unsigned (spec 01 section 5). After
// authentication a HEAD refusal is signed over the empty body (spec 04 section
// 5 S10), which is what writeSignedMethod does.
func (h *handler) reject(w http.ResponseWriter, method string, res verify.Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	if res.HTTPStatus == http.StatusUnauthorized {
		header.Set("WWW-Authenticate", "Jack-Auth")
	}
	body := errorBody(res.Code, res.Message)
	if res.NonceRecorded {
		h.writeSignedMethod(w, method, res.HTTPStatus, header, body, res.RequestSig, res.Tool)
		return
	}
	writeRaw(w, res.HTTPStatus, header, body)
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callToolResult struct {
	Content           []textContent  `json:"content"`
	StructuredContent any            `json:"structuredContent"`
	IsError           bool           `json:"isError"`
	ResultType        string         `json:"resultType,omitempty"`
	Meta              map[string]any `json:"_meta,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

// native answers a protocol-native tool call as a JSON-RPC response whose
// result is an MCP CallToolResult carrying the structured payload. In the
// modern era the result also carries resultType and Jack's serverInfo meta
// (spec 04 C7); modernEra false keeps the 0.1.x bytes exactly.
func (h *handler) native(w http.ResponseWriter, res verify.Result, modernEra bool) {
	text, err := json.Marshal(res.Structured)
	if err != nil {
		h.rejectInternal(w, res)
		return
	}
	result := callToolResult{
		Content:           []textContent{{Type: "text", Text: string(text)}},
		StructuredContent: res.Structured,
	}
	if modernEra {
		result.ResultType = "complete"
		result.Meta = map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{
			"name":    modern.ImplementationName,
			"version": modern.ImplementationVersion,
		}}
	}
	body, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      res.RPCID,
		Result:  result,
	})
	if err != nil {
		h.rejectInternal(w, res)
		return
	}
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusOK, header, body, res.RequestSig, res.Tool)
}

func (h *handler) rejectInternal(w http.ResponseWriter, res verify.Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusInternalServerError, header, errorBody("internal_error", "internal error"), res.RequestSig, res.Tool)
}

// forward hands an authorized request to the wrapped server and signs what it
// answers. modernEra is true when the request was handled as modern-era, which
// is the only era that may open a signed stream (spec 05 section 1.2).
func (h *handler) forward(w http.ResponseWriter, r *http.Request, body []byte, res verify.Result, modernEra bool) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Verified caller identity hand-off (spec 02 section 3): only the SDK-
	// sealed token is stored, under an unexported context key; consumers get
	// an immutable read view from verify.IdentityFromContext. Forwarded
	// requests always have a registered caller.
	ctx = verify.WithIdentity(ctx, res.Identity)
	// 1.1, 3.8: only a modern-era POST that opted in may stream, and only when
	// its body was a request with a JSON-RPC id.
	optIn := modernEra && r.Method == http.MethodPost && stream.AcceptsS1(r.Header.Values("Jack-Accept"))
	admissible := false
	if optIn {
		if msg, ok := rpcbody.Classify(body); ok && msg.Kind == rpcbody.KindRequest &&
			len(msg.ID) > 0 && !bytes.Equal(bytes.TrimSpace(msg.ID), []byte("null")) {
			admissible = true
		}
	}
	hook := &streamHook{handler: h, result: res, body: body, w: w, cancel: cancel,
		identity: streamIdentity(res), enabled: admissible, notRequest: optIn && !admissible,
		timerNow: h.timerNow, timerAfterFunc: h.timerAfterFunc}
	defer hook.finish()
	defer func() {
		if recovered := recover(); recovered != nil {
			hook.finish()
			panic(recovered)
		}
	}()
	if optIn {
		// 3.5: the wrapped handler emits heartbeats as plain signed frames, so
		// it needs the granted interval.
		ctx = withStreamGrant(ctx, h.streams.Heartbeat)
	}
	inner := r.Clone(ctx)
	inner.Body = io.NopCloser(bytes.NewReader(body))
	inner.ContentLength = int64(len(body))

	bw := &bufferedWriter{header: http.Header{}, cancel: cancel, limit: h.respLimit, stream: hook}
	h.next.ServeHTTP(bw, inner)
	if hook.refused() {
		// finish frees the limiter slot on every path (spec 05 section 3.3).
		hook.fail()
		return
	}
	if hook.streaming() {
		// The stream owns the wire; the deferred finish ends it (3.7).
		return
	}

	// The final header is checked too: header changes after the commit are
	// not observable by the writer, and the wire result must stay a signed 501.
	if bw.refused || isEventStream(bw.header.Get("Content-Type")) {
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		h.writeSigned(w, http.StatusNotImplemented, header, errorBody("streaming_unsupported", "streaming responses cannot be signed in v0.1"), res.RequestSig, res.Tool)
		return
	}
	if bw.overflowed {
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		h.writeSigned(w, http.StatusBadGateway, header, errorBody("response_too_large", "upstream response exceeds the configured limit"), res.RequestSig, res.Tool)
		return
	}
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	header := bw.header.Clone()
	header.Del("Content-Length")
	h.writeSigned(w, status, header, bw.body.Bytes(), res.RequestSig, res.Tool)
}

// writeSignedMethod signs and writes an answer to a request with HTTP method
// m. A response to HEAD carries no content on the wire, so spec 04 section 5
// S10 signs every refusal of such a request over the EMPTY body and sends no
// body: the client then verifies exactly the bytes it received. Every other
// method is answered unchanged.
func (h *handler) writeSignedMethod(w http.ResponseWriter, m string, status int, header http.Header, body []byte, requestSig, tool string) {
	if m == http.MethodHead {
		body = nil
	}
	h.writeSigned(w, status, header, body, requestSig, tool)
}

// writeSigned signs the response over its status, the request signature and
// the exact body bytes (spec 01 section 5) and writes it.
func (h *handler) writeSigned(w http.ResponseWriter, status int, header http.Header, body []byte, requestSig, tool string) {
	if h.keys != nil {
		h.writeAuthorized(w, status, header, body, requestSig, tool)
		return
	}
	now := verify.RawNow(h.v)
	signing := jack.ResponseSigningString(status, requestSig, h.kid, now, body)
	var sig []byte
	if h.signer != nil {
		var err error
		sig, err = responseSignature(h.signer, h.public, signing)
		if err != nil {
			// No unsigned success, provider detail, fallback, or retry. Nonce is already consumed.
			writeError(w, http.StatusServiceUnavailable, "internal_error", "response signing unavailable")
			return
		}
	} else {
		sig = ed25519.Sign(h.key, []byte(signing))
	}
	header.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: h.kid, TS: now, Sig: jack.EncodeBase64URL(sig)}))
	writeRaw(w, status, header, body)
}

// writeRaw writes a response with exactly the given headers and body.
func writeRaw(w http.ResponseWriter, status int, header http.Header, body []byte) {
	dst := w.Header()
	for k, vs := range header {
		dst[k] = append([]string(nil), vs...)
	}
	dst.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

// errorBody renders the rejection body of spec 01 section 4.
func errorBody(code, message string) []byte {
	b, _ := json.Marshal(errorEnvelope{Error: errorDetail{Code: code, Message: message}})
	return b
}

// writeError writes an unsigned JSON error for requests that never reached
// authentication.
func writeError(w http.ResponseWriter, status int, code, message string) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	writeRaw(w, status, header, errorBody(code, message))
}

// errStreamRefused is returned by writes to a response that was refused as a
// text/event-stream; a handler writing in a loop should stop on it.
var errStreamRefused = errors.New("server: streaming responses are not supported; response refused")

// errResponseTooLarge is returned by writes once the response of the wrapped
// handler exceeded the buffer limit; a handler writing in a loop should stop.
var errResponseTooLarge = errors.New("server: response exceeds the configured limit")

// bufferedWriter captures the answer of the wrapped handler so it can be
// signed before anything is sent. Headers are committed at the first
// WriteHeader, Write or Flush; the Content-Type seen at that moment decides
// whether the response is a refused event stream. A refused stream cancels the
// request context of the wrapped handler, fails its writes and retains none of
// its bytes. It is used by one goroutine, the one running the wrapped handler.
type bufferedWriter struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	cancel    func()
	committed bool
	refused   bool
	// limit is the maximum number of buffered body bytes.
	limit      int64
	overflowed bool
	// stream, when set, may turn a committed text/event-stream answer into a
	// signed stream instead of refusing it.
	stream *streamHook
}

func (b *bufferedWriter) Header() http.Header { return b.header }

// commit freezes the decision on the Content-Type at the first commit.
func (b *bufferedWriter) commit() {
	if b.committed {
		return
	}
	b.committed = true
	if isEventStream(b.header.Get("Content-Type")) {
		if b.stream != nil && b.stream.start() {
			return
		}
		b.refused = true
		if b.cancel != nil {
			b.cancel()
		}
	}
}

func (b *bufferedWriter) WriteHeader(status int) {
	if b.committed {
		return
	}
	b.status = status
	b.commit()
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if !b.committed {
		b.status = http.StatusOK
		b.commit()
	}
	if b.stream != nil && b.stream.streaming() {
		return b.stream.write(p)
	}
	if b.refused {
		return 0, errStreamRefused
	}
	if b.overflowed {
		return 0, errResponseTooLarge
	}
	// Compare against the remaining room so the sum cannot overflow int64 and
	// nothing is allocated before the check.
	if int64(len(p)) > b.limit-int64(b.body.Len()) {
		b.overflowed = true
		b.body = bytes.Buffer{}
		if b.cancel != nil {
			b.cancel()
		}
		return 0, errResponseTooLarge
	}
	return b.body.Write(p)
}

// Flush commits the headers like net/http does; buffered bytes are still held
// back until the response is signed.
func (b *bufferedWriter) Flush() {
	if !b.committed {
		b.status = http.StatusOK
		b.commit()
	}
	if b.stream != nil && b.stream.streaming() {
		b.stream.flush()
		return
	}
}

// isEventStream reports whether a Content-Type value declares the media type
// text/event-stream: the part before the first ';', trimmed, ASCII-lowercased.
// mime.ParseMediaType is deliberately not used: a malformed parameter list
// must not stop the refusal of an unsignable stream (spec README Q1; same
// rule as the client-side check in client/transport.go).
func isEventStream(contentType string) bool {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return asciiLower(strings.TrimSpace(contentType)) == "text/event-stream"
}

// asciiLower maps ASCII uppercase letters to lowercase, leaving all other
// bytes unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
