package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const (
	defaultMaxBodyBytes = 1 << 20
	// defaultMaxResponseBytes matches the client's response buffer default.
	defaultMaxResponseBytes = 1 << 20
)

// HandlerConfig configures NewHandler.
type HandlerConfig struct {
	// Verifier authenticates and authorizes every request.
	Verifier *Verifier
	// ServerKey signs responses (spec 01 section 5); clients pin its public key.
	ServerKey ed25519.PrivateKey
	// ResponseSigner выбирается явно вместо ServerKey, с фиксированной public identity.
	ResponseSigner ResponseSigner
	// ResponseKeys — отдельный opt-in authorization/final-gate profile, без fallback.
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
}

type handler struct {
	v      *Verifier
	key    ed25519.PrivateKey
	signer ResponseSigner
	keys   ResponseKeyProvider
	public []byte
	kid    string
	limit  int64
	// respLimit bounds the buffered upstream response body.
	respLimit int64
	next      http.Handler
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
// Streaming (text/event-stream) responses are not supported in v0.1 (spec
// README Q1): they are answered with 501 instead of being passed through
// unsigned. The 501 takes precedence over the size overflow.
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
	switch {
	case cfg.Verifier == nil:
		return nil, errors.New("server: HandlerConfig.Verifier must be set")
	case cfg.ResponseKeys != nil && (cfg.ResponseSigner != nil || len(cfg.ServerKey) != 0):
		return nil, errors.New("server: select exactly one response signing profile")
	case cfg.Verifier.cfg.ServerKeys != nil && cfg.ResponseKeys == nil:
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
	return &handler{v: cfg.Verifier, key: cfg.ServerKey, signer: cfg.ResponseSigner, keys: cfg.ResponseKeys, public: public, kid: kid, limit: limit, respLimit: respLimit, next: next}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET and POST are defined")
		return
	}
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

	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	res := h.v.Verify(Request{Method: r.Method, Target: target, AuthValues: r.Header.Values("Jack-Auth"), Body: body})
	defer res.Done()
	switch {
	case !res.Accepted:
		h.reject(w, res)
	case res.Native:
		h.native(w, res)
	default:
		h.forward(w, r, body, res)
	}
}

// reject answers a failed request. Once authentication has succeeded the
// client holds a request signature to bind to, so the answer is signed; an
// authentication failure may be unsigned (spec 01 section 5).
func (h *handler) reject(w http.ResponseWriter, res Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	if res.HTTPStatus == http.StatusUnauthorized {
		header.Set("WWW-Authenticate", "Jack-Auth")
	}
	body := errorBody(res.Code, res.Message)
	if res.NonceRecorded {
		h.writeSigned(w, res.HTTPStatus, header, body, res.RequestSig, res.Tool)
		return
	}
	writeRaw(w, res.HTTPStatus, header, body)
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callToolResult struct {
	Content           []textContent `json:"content"`
	StructuredContent any           `json:"structuredContent"`
	IsError           bool          `json:"isError"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

// native answers a protocol-native tool call as a JSON-RPC response whose
// result is an MCP CallToolResult carrying the structured payload.
func (h *handler) native(w http.ResponseWriter, res Result) {
	text, err := json.Marshal(res.Structured)
	if err != nil {
		h.rejectInternal(w, res)
		return
	}
	body, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      res.RPCID,
		Result: callToolResult{
			Content:           []textContent{{Type: "text", Text: string(text)}},
			StructuredContent: res.Structured,
		},
	})
	if err != nil {
		h.rejectInternal(w, res)
		return
	}
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusOK, header, body, res.RequestSig, res.Tool)
}

func (h *handler) rejectInternal(w http.ResponseWriter, res Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusInternalServerError, header, errorBody("internal_error", "internal error"), res.RequestSig, res.Tool)
}

// forward hands an authorized request to the wrapped server and signs what it
// answers.
func (h *handler) forward(w http.ResponseWriter, r *http.Request, body []byte, res Result) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Verified caller identity hand-off (spec 02 section 3): only the SDK-
	// sealed token is stored, under an unexported context key; consumers get
	// an immutable read view from IdentityFromContext. Forwarded requests
	// always have a registered caller.
	if tok, ok := sealIdentity(res.Identity); ok {
		ctx = context.WithValue(ctx, identityContextKey{}, tok)
	}
	inner := r.Clone(ctx)
	inner.Body = io.NopCloser(bytes.NewReader(body))
	inner.ContentLength = int64(len(body))

	bw := &bufferedWriter{header: http.Header{}, cancel: cancel, limit: h.respLimit}
	h.next.ServeHTTP(bw, inner)

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

// writeSigned signs the response over its status, the request signature and
// the exact body bytes (spec 01 section 5) and writes it.
func (h *handler) writeSigned(w http.ResponseWriter, status int, header http.Header, body []byte, requestSig, tool string) {
	if h.keys != nil {
		h.writeAuthorized(w, status, header, body, requestSig, tool)
		return
	}
	now := h.v.cfg.Now()
	signing := jack.ResponseSigningString(status, requestSig, h.kid, now, body)
	var sig []byte
	if h.signer != nil {
		var err error
		sig, err = responseSignature(h.signer, h.public, signing)
		if err != nil {
			// Нет unsigned success, provider detail, fallback или retry. Nonce уже consumed.
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
}

func (b *bufferedWriter) Header() http.Header { return b.header }

// commit freezes the decision on the Content-Type at the first commit.
func (b *bufferedWriter) commit() {
	if b.committed {
		return
	}
	b.committed = true
	if isEventStream(b.header.Get("Content-Type")) {
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
