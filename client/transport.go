package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// ErrStreamingUnsupported is returned when the server answers with a
// text/event-stream body: a stream cannot be read in full and therefore
// cannot be signature-verified, so it is refused (spec 01 section 5,
// open question Q1).
var ErrStreamingUnsupported = errors.New("jack client: streaming responses cannot be verified and are refused (spec 01 section 5, open question Q1)")

// UnauthenticatedResponseError reports a 401 answered WITHOUT a verified
// Jack-Auth header. Per spec 01 section 5 a client MUST NOT act on an
// unsigned response beyond reporting its status, so only the status is
// surfaced and the body is never parsed (the Rust client does the same).
type UnauthenticatedResponseError struct {
	Status int
}

func (e *UnauthenticatedResponseError) Error() string {
	return fmt.Sprintf("jack client: unauthenticated response: status %d", e.Status)
}

type signerKeyType struct{}
type fixedNowKeyType struct{}

// WithRequestSigner returns a context carrying a per-request signer override,
// used by enrollment and rotation flows where a different key signs the call.
func WithRequestSigner(ctx context.Context, s Signer) context.Context {
	return context.WithValue(ctx, signerKeyType{}, s)
}

// signerFrom returns the per-request signer override, if any.
func signerFrom(ctx context.Context) Signer {
	s, _ := ctx.Value(signerKeyType{}).(Signer)
	return s
}

// withFixedNow pins the signing clock for one request: the rotate proof ts
// must equal the header ts (spec 03 section 3.1).
func withFixedNow(ctx context.Context, now time.Time) context.Context {
	return context.WithValue(ctx, fixedNowKeyType{}, now)
}

// fixedNowFrom returns the pinned clock, if any.
func fixedNowFrom(ctx context.Context) (time.Time, bool) {
	now, ok := ctx.Value(fixedNowKeyType{}).(time.Time)
	return now, ok
}

// Transport is an http.RoundTripper that signs every request and verifies
// every response before the caller sees its body (spec 01 sections 4 and 5).
type Transport struct {
	// Base is the underlying round tripper; nil means http.DefaultTransport.
	Base http.RoundTripper
	// Aud is the audience string bound into the signing string.
	Aud string
	// Signer is the default signer for outgoing requests.
	Signer Signer
	// ServerKey is the pinned 32-byte raw server public key.
	ServerKey []byte
	// Now is the signing clock; nil means time.Now.
	Now func() time.Time
	// Nonce is the per-request nonce source; nil means RandomNonce.
	Nonce NonceSource
	// Window is the response timestamp tolerance; <= 0 means DefaultWindow.
	Window time.Duration
}

// NewTransport builds a Transport with explicit defaults for the audit fields.
func NewTransport(base http.RoundTripper, aud string, signer Signer, serverKey []byte) *Transport {
	return &Transport{Base: base, Aud: aud, Signer: signer, ServerKey: serverKey}
}

// base returns the underlying round tripper, defaulting per net/http.
func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// NewHTTPClient wraps t in an http.Client.
func NewHTTPClient(t *Transport) *http.Client {
	return &http.Client{Transport: t}
}

// maxBodyBytes caps response buffering so a hostile body cannot exhaust memory.
const maxBodyBytes = 1 << 20

// RoundTrip signs req, sends it, and returns a response whose body has been
// fully read and signature-verified against the pinned server key.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	signer := signerFrom(req.Context())
	if signer == nil {
		signer = t.Signer
	}
	if signer == nil {
		return nil, fmt.Errorf("jack client: no signer configured for request")
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	if fixed, ok := fixedNowFrom(req.Context()); ok {
		now = func() time.Time { return fixed }
	}
	nonceFn := t.Nonce
	if nonceFn == nil {
		nonceFn = RandomNonce
	}

	// Buffer the request body first: the same exact bytes are signed and sent.
	var body []byte
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("jack client: buffering request body: %w", err)
		}
		body = raw
		_ = req.Body.Close()
	}

	// The origin-form target exactly as Go sends it on the wire.
	target := req.URL.RequestURI()

	nonce, err := nonceFn()
	if err != nil {
		return nil, fmt.Errorf("jack client: nonce: %w", err)
	}
	headerVal, err := SignRequest(signer, t.Aud, req.Method, target, body, nonce, now())
	if err != nil {
		return nil, err
	}
	// The request signature binds the response signing string (spec 01 section 5).
	auth, _ := jack.ParseRequestAuth([]string{headerVal})

	clone := req.Clone(req.Context())
	clone.Header.Set("Jack-Auth", headerVal)
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	resp, err := t.base().RoundTrip(clone)
	if err != nil {
		return nil, err
	}

	// Streaming guard BEFORE buffering: a stream cannot be verified (spec 01
	// section 5, open question Q1).
	if isEventStream(resp.Header.Get("Content-Type")) {
		_ = resp.Body.Close()
		return nil, ErrStreamingUnsupported
	}

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("jack client: reading response body: %w", readErr)
	}
	if len(respBody) > maxBodyBytes {
		return nil, fmt.Errorf("jack client: response body exceeds %d bytes", maxBodyBytes)
	}

	window := t.Window
	if vErr := VerifyResponse(t.ServerKey, resp.StatusCode, resp.Header.Values("Jack-Auth"), auth.Sig, respBody, now(), window); vErr != nil {
		var jErr *jack.Error
		if errors.As(vErr, &jErr) && jErr.Code == jack.CodeMissingAuth && resp.StatusCode == http.StatusUnauthorized {
			// Spec 01 section 5: an unsigned answer is acted on only up to
			// its status — the body is never parsed or trusted.
			return nil, &UnauthenticatedResponseError{Status: resp.StatusCode}
		}
		return nil, vErr
	}

	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	return resp, nil
}

// isEventStream reports whether a Content-Type value declares the media type
// text/event-stream: the part before the first ';', trimmed, ASCII-lowercased.
// mime.ParseMediaType is deliberately not used: a malformed parameter list
// must not stop the refusal of an unverifiable stream (spec 01 section 5,
// open question Q1; same rule as the server-side check in server/middleware.go).
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
