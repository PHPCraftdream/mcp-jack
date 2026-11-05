package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const defaultMaxBodyBytes = 1 << 20

// HandlerConfig configures NewHandler.
type HandlerConfig struct {
	// Verifier authenticates and authorizes every request.
	Verifier *Verifier
	// ServerKey signs responses (spec 01 section 5); clients pin its public key.
	ServerKey ed25519.PrivateKey
	// MaxBodyBytes bounds the request body; zero means 1 MiB. The body must
	// be read in full to be hashed, so the limit is a denial-of-service guard.
	MaxBodyBytes int64
}

type handler struct {
	v     *Verifier
	key   ed25519.PrivateKey
	kid   string
	limit int64
	next  http.Handler
}

// NewHandler wraps next, an unmodified MCP server, so that only authenticated
// and authorized requests reach it and every verified answer is signed.
// Protocol-native tools are answered here and never reach next.
//
// The response of next is buffered in full before it is signed, so streaming
// (text/event-stream) responses are not supported in v0.1 (spec README Q1):
// they are answered with 501 instead of being passed through unsigned.
func NewHandler(cfg HandlerConfig, next http.Handler) (http.Handler, error) {
	switch {
	case cfg.Verifier == nil:
		return nil, errors.New("server: HandlerConfig.Verifier must be set")
	case len(cfg.ServerKey) != ed25519.PrivateKeySize:
		return nil, errors.New("server: HandlerConfig.ServerKey must be an Ed25519 private key")
	case next == nil:
		return nil, errors.New("server: next handler must be set")
	}
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	pub := cfg.ServerKey.Public().(ed25519.PublicKey)
	return &handler{v: cfg.Verifier, key: cfg.ServerKey, kid: jack.KeyID(pub), limit: limit, next: next}, nil
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
		h.writeSigned(w, res.HTTPStatus, header, body, res.RequestSig)
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
	h.writeSigned(w, http.StatusOK, header, body, res.RequestSig)
}

func (h *handler) rejectInternal(w http.ResponseWriter, res Result) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	h.writeSigned(w, http.StatusInternalServerError, header, errorBody("internal_error", "internal error"), res.RequestSig)
}

// forward hands an authorized request to the wrapped server and signs what it
// answers.
func (h *handler) forward(w http.ResponseWriter, r *http.Request, body []byte, res Result) {
	inner := r.Clone(r.Context())
	inner.Body = io.NopCloser(bytes.NewReader(body))
	inner.ContentLength = int64(len(body))

	bw := &bufferedWriter{header: http.Header{}}
	h.next.ServeHTTP(bw, inner)

	if mediaType, _, err := mime.ParseMediaType(bw.header.Get("Content-Type")); err == nil && mediaType == "text/event-stream" {
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		h.writeSigned(w, http.StatusNotImplemented, header, errorBody("streaming_unsupported", "streaming responses cannot be signed in v0.1"), res.RequestSig)
		return
	}
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	header := bw.header.Clone()
	header.Del("Content-Length")
	h.writeSigned(w, status, header, bw.body.Bytes(), res.RequestSig)
}

// writeSigned signs the response over its status, the request signature and
// the exact body bytes (spec 01 section 5) and writes it.
func (h *handler) writeSigned(w http.ResponseWriter, status int, header http.Header, body []byte, requestSig string) {
	now := h.v.cfg.Now()
	signing := jack.ResponseSigningString(status, requestSig, h.kid, now, body)
	sig := ed25519.Sign(h.key, []byte(signing))
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

// bufferedWriter captures the answer of the wrapped handler so it can be
// signed before anything is sent.
type bufferedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedWriter) Header() http.Header { return b.header }

func (b *bufferedWriter) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}
