package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client/internal/modern"
	streamimpl "github.com/PHPCraftdream/mcp-jack/client/internal/stream"
	"github.com/PHPCraftdream/mcp-jack/client/internal/urlpolicy"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// ErrRedirectRefused is matched (errors.Is) by the error returned when a
// signed request is answered with a redirect status (301, 302, 303, 307 or
// 308). Redirects are never followed, are refused before response
// verification, and the Location header is never surfaced. This is a
// no-follow/no-downgrade guard (a signed request is not replayed to, or
// verified against, a different target); it is NOT TLS enforcement.
var ErrRedirectRefused = errors.New("jack client: redirect response refused")

// RedirectRefusedError reports a redirect-status answer (301, 302, 303, 307,
// 308) to a signed request.
type RedirectRefusedError struct {
	Status int
}

func (e *RedirectRefusedError) Error() string {
	return fmt.Sprintf("jack client: redirect response refused: status %d", e.Status)
}

// Is makes errors.Is(err, ErrRedirectRefused) true.
func (e *RedirectRefusedError) Is(target error) bool { return target == ErrRedirectRefused }

// noFollowRedirects is an http.Client.CheckRedirect that never follows.
func noFollowRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// isRedirectStatus reports whether status is exactly 301, 302, 303, 307 or
// 308. Other 3xx statuses (300, 304, 305, ...) take the normal path
// (streaming guard, signature verification): in particular a correctly signed
// 304 Not Modified is returned as before.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

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

// withFixedNow pins ONLY the signing clock for one request: the rotate proof
// ts must equal the header ts (spec 03 section 3.1). Response verification
// never uses it and always samples the transport clock afresh.
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
	// Stream configures the signed-stream (s1) opt-in used by OpenStream: the
	// idle timeout, the frame cap and the rotation-known server keys. A nil
	// value uses the defaults of spec 05.
	Stream *clientstream.ClientConfig
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

// NewHTTPClient wraps t in an http.Client that never follows redirects: a
// redirect status (301, 302, 303, 307, 308) is refused by the Transport itself
// (ErrRedirectRefused). This is a no-follow guard, not TLS enforcement.
func NewHTTPClient(t *Transport) *http.Client {
	return &http.Client{Transport: t, CheckRedirect: noFollowRedirects}
}

// maxBodyBytes caps response buffering so a hostile body cannot exhaust memory.
const maxBodyBytes = 1 << 20

// RoundTrip signs req, sends it, and returns a response whose body has been
// fully read and signature-verified against the pinned server key.
//
// The destination is checked against the client URL policy
// (client/internal/urlpolicy) before anything else: a refused destination produces no signature, no body
// read and no call to the base RoundTripper. An answer with status 301, 302,
// 303, 307 or 308 is refused locally, before verification, with a
// *RedirectRefusedError; it is never followed and its Location is never
// surfaced. Other 3xx statuses (e.g. a signed 304) are verified normally.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, urlpolicy.ErrMalformedDestination
	}
	if err := urlpolicy.CheckRequestDestination(req); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
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
	signNow := now
	if fixed, ok := fixedNowFrom(req.Context()); ok {
		signNow = func() time.Time { return fixed }
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
	headerVal, err := SignRequest(signer, t.Aud, req.Method, target, body, nonce, signNow())
	if err != nil {
		return nil, err
	}
	// The request signature binds the response signing string (spec 01 section 5).
	auth, err := jack.ParseRequestAuth([]string{headerVal})
	if err != nil {
		return nil, fmt.Errorf("jack client: parsing signed request auth header: %w", err)
	}

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

	// Redirect statuses (301/302/303/307/308) are refused before anything
	// else: never followed, Location never surfaced, signature not meaningful.
	// A no-follow guard so a signed request is not replayed or verified
	// against a different target; not TLS enforcement.
	if isRedirectStatus(resp.StatusCode) {
		_ = resp.Body.Close()
		return nil, &RedirectRefusedError{Status: resp.StatusCode}
	}

	// Streaming guard BEFORE buffering: a stream cannot be verified (spec 01
	// section 5, open question Q1).
	if isEventStreamHeader(resp.Header.Values("Content-Type")) {
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

// OpenStream signs req, sends it with the unsigned `Jack-Accept: s1` request
// header and verifies the answer. A text/event-stream answer becomes a Stream
// whose Next method yields the verified message data values in order and whose
// Close closes the connection, which cancels the request on the server (3.7).
//
// Every other answer is verified as a v1 response by the same rules RoundTrip
// applies (spec 05 sections 1.4 and 4.1) and returned as a *VerifiedResponse;
// an unsigned or badly signed answer is the matching verification error, so a
// refusal is never reported as a bare status. A per-request signer override
// (WithRequestSigner) applies as it does in RoundTrip.
func (t *Transport) OpenStream(req *http.Request) (*clientstream.Stream, *clientstream.VerifiedResponse, error) {
	if req == nil {
		return nil, nil, urlpolicy.ErrMalformedDestination
	}
	signer := signerFrom(req.Context())
	if signer == nil {
		signer = t.Signer
	}
	if signer == nil {
		return nil, nil, fmt.Errorf("jack client: no signer configured for request")
	}
	nonce := t.Nonce
	if nonce == nil {
		nonce = RandomNonce
	}
	s, resp, requestSig, err := streamimpl.Open(req, streamimpl.OpenConfig{
		Base:      t.Base,
		Aud:       t.Aud,
		Signer:    signer,
		ServerKey: t.ServerKey,
		Now:       t.Now,
		Nonce:     nonce,
		Window:    t.Window,
		Config:    t.Stream,
	})
	// 1.4: a non-stream answer is verified through the v1 response path, on
	// the very answer this request got; no second request is sent.
	if errors.Is(err, streamimpl.ErrNotStream) {
		verified, vErr := t.verifyReply(resp, requestSig)
		return nil, verified, vErr
	}
	return s, nil, err
}

// verifyReply verifies a non-stream answer of an opted-in request exactly as
// RoundTrip verifies a normal response (spec 05 sections 1.4 and 4.1).
func (t *Transport) verifyReply(resp *http.Response, requestSig string) (*clientstream.VerifiedResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("jack client: no response to verify")
	}
	// Redirect statuses are refused before anything else, as in RoundTrip.
	if isRedirectStatus(resp.StatusCode) {
		_ = resp.Body.Close()
		return nil, &RedirectRefusedError{Status: resp.StatusCode}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("jack client: reading response body: %w", readErr)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("jack client: response body exceeds %d bytes", maxBodyBytes)
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	window := t.Window
	if vErr := VerifyResponse(t.ServerKey, resp.StatusCode, resp.Header.Values("Jack-Auth"), requestSig, body, now(), window); vErr != nil {
		var jErr *jack.Error
		if errors.As(vErr, &jErr) && jErr.Code == jack.CodeMissingAuth && resp.StatusCode == http.StatusUnauthorized {
			// Spec 01 section 5: an unsigned answer is acted on only up to
			// its status — the body is never parsed or trusted.
			return nil, &UnauthenticatedResponseError{Status: resp.StatusCode}
		}
		return nil, vErr
	}
	return &clientstream.VerifiedResponse{
		Status: resp.StatusCode,
		Header: resp.Header.Clone(),
		Body:   body,
	}, nil
}

// isEventStreamHeader reports whether the Content-Type field lines declare a
// stream: the lines are joined with commas (the combined form a fetch client
// also sees) and any comma-separated member whose media type is
// text/event-stream refuses the response. The media type is the text before
// the first ';' with SP and HTAB trimmed, compared ASCII case-insensitively.
// mime.ParseMediaType is deliberately not used: a malformed parameter list or
// a malformed combined value must not stop the refusal of an unverifiable
// stream (spec 01 section 5, open question Q1).
func isEventStreamHeader(values []string) bool {
	for _, member := range strings.Split(strings.Join(values, ","), ",") {
		if i := strings.IndexByte(member, ';'); i >= 0 {
			member = member[:i]
		}
		if asciiLower(strings.Trim(member, " \t")) == "text/event-stream" {
			return true
		}
	}
	return false
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

// Signer produces Ed25519 signatures over the exact message bytes.
// InMemorySigner is the built-in implementation; OS key stores or ssh-agent
// signers plug in by implementing this interface. KID must equal
// jack.KeyID(PublicKey()) over the 32-byte raw Ed25519 public key
// (spec 01 section 2).
//
// Private keys must never live in config files; profiles carry only public
// data (spec 01 section 6, README principle 5).
type Signer interface {
	// Sign returns the 64-byte Ed25519 signature of message.
	Sign(message []byte) ([]byte, error)
	// PublicKey returns the 32-byte raw Ed25519 public key.
	PublicKey() []byte
	// KID returns jack.KeyID(PublicKey()).
	KID() string
}

// InMemorySigner signs with an in-process Ed25519 private key.
type InMemorySigner struct {
	priv ed25519.PrivateKey
	pub  []byte
	kid  string
}

// NewInMemorySigner builds a signer from a 32-byte Ed25519 seed.
func NewInMemorySigner(seed []byte) (*InMemorySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("jack client: signer seed must be exactly %d bytes", ed25519.SeedSize)
	}
	return newInMemorySigner(ed25519.NewKeyFromSeed(seed)), nil
}

// GenerateSigner creates a signer from a crypto/rand seed.
func GenerateSigner() (*InMemorySigner, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return newInMemorySigner(ed25519.NewKeyFromSeed(seed)), nil
}

func newInMemorySigner(priv ed25519.PrivateKey) *InMemorySigner {
	pub := make([]byte, ed25519.PublicKeySize)
	copy(pub, priv.Public().(ed25519.PublicKey))
	return &InMemorySigner{priv: priv, pub: pub, kid: jack.KeyID(pub)}
}

// Sign returns the Ed25519 signature of message.
func (s *InMemorySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// PublicKey returns a copy of the 32-byte public key.
func (s *InMemorySigner) PublicKey() []byte {
	pub := make([]byte, len(s.pub))
	copy(pub, s.pub)
	return pub
}

// KID returns the key identifier of the public key.
func (s *InMemorySigner) KID() string { return s.kid }

// DefaultWindow is the timestamp acceptance window the server applies by
// default (spec 01 section 4 step 6); the client uses it unless overridden.
const DefaultWindow = 30 * time.Second

// nonceSize is the required nonce length of spec 01 section 2.
const nonceSize = 16

// NonceSource returns the 16 random nonce bytes for one request.
type NonceSource func() ([]byte, error)

// RandomNonce returns 16 bytes from crypto/rand.
func RandomNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// hasControl reports whether s contains an ASCII control character; the
// signing target must not embed line breaks (spec 01 section 3.1).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// SignRequest builds the signed Jack-Auth header value for one request
// (spec 01 sections 3 and 3.1).
func SignRequest(s Signer, aud, method, target string, body []byte, nonce []byte, now time.Time) (string, error) {
	if s == nil {
		return "", fmt.Errorf("jack client: nil signer")
	}
	if len(nonce) != nonceSize {
		return "", fmt.Errorf("jack client: nonce must be exactly %d bytes, got %d", nonceSize, len(nonce))
	}
	if method == "" || hasControl(method) {
		return "", fmt.Errorf("jack client: empty or control-character HTTP method")
	}
	if target == "" || hasControl(target) {
		return "", fmt.Errorf("jack client: empty or control-character target")
	}
	kid := s.KID()
	ts := now.Unix()
	nonceB64 := jack.EncodeBase64URL(nonce)
	sig, err := s.Sign([]byte(jack.RequestSigningString(method, target, aud, kid, ts, nonceB64, body)))
	if err != nil {
		return "", err
	}
	return jack.FormatRequestAuth(jack.RequestAuth{
		Kid:   kid,
		TS:    ts,
		Nonce: nonceB64,
		Sig:   jack.EncodeBase64URL(sig),
	}), nil
}

// VerifyResponse is the client-side mirror of spec 01 section 5: it checks
// that the response was signed by the pinned server key, over the request
// signature, within the window. Each failure is a *jack.Error.
func VerifyResponse(serverKey []byte, status int, headerValues []string, requestSig string, body []byte, now time.Time, window time.Duration) error {
	if len(serverKey) != 32 {
		// Configuration misuse, not a protocol rejection.
		return fmt.Errorf("jack client: pinned server key must be exactly 32 bytes, got %d", len(serverKey))
	}
	if window <= 0 {
		window = DefaultWindow
	}
	windowSeconds := int64(window / time.Second)

	auth, err := jack.ParseResponseAuth(headerValues)
	if err != nil {
		// Spec 01 section 5: client-side verification failures never become
		// HTTP responses, so they carry no status. The shared parser assigns
		// its wire 401 for the server-side path, so remap it to 0 here
		// (mirror of the Rust verify_response remap).
		var jErr *jack.Error
		if errors.As(err, &jErr) {
			return &jack.Error{HTTPStatus: 0, Code: jErr.Code, Message: jErr.Message}
		}
		return err
	}
	if auth.Kid != jack.KeyID(serverKey) {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeUnknownServerKey, Message: "response signed by an unpinned key"}
	}
	// Signed subtraction may overflow; ordered unsigned distance is exact
	// for any int64 endpoints, including the full range up to 2^64-1.
	var distance uint64
	if ts := now.Unix(); ts < auth.TS {
		distance = uint64(auth.TS) - uint64(ts)
	} else {
		distance = uint64(ts) - uint64(auth.TS)
	}
	if distance > uint64(windowSeconds) {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeTimestampOutOfWindow, Message: "response timestamp outside the acceptance window"}
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		// The parser already enforces a canonical 64-byte sig, so any error
		// here can only be a signature mismatch, not a malformed header.
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeBadSignature, Message: "malformed response signature"}
	}
	msg := []byte(jack.ResponseSigningString(status, requestSig, auth.Kid, auth.TS, body))
	if !jack.Verify(serverKey, msg, sig) {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeBadSignature, Message: "response signature does not verify"}
	}
	return nil
}

// RotationResponseKey comes only from an independently trusted/ACKed snapshot.
// NotBefore — signing-time lower bound; KnownCutoff nil means an unknown successor.
type RotationResponseKey struct {
	PublicKey   [32]byte
	NotBefore   int64
	KnownCutoff *int64
}

// RotationCarrier is crypto/interval metadata, not ClockGuard readiness or a trust ACK.
type RotationCarrier struct {
	KID       string
	Timestamp int64
}

// VerifyRotationCarrier preserves the unknown-key → freshness → signature order.
// Transport bounds the body; the function checks its exact bytes, not JSON/payload.
// Caller must then run the durable ClockGuard before DecodeResult, the final
// interval/bridge/revision checks, and whole-state CAS. No fetch, retry, or mutation.
func VerifyRotationCarrier(known map[string]RotationResponseKey, status int, headerValues []string, requestSig string, body []byte, now time.Time, window time.Duration) (RotationCarrier, error) {
	refuse := func(code string) (RotationCarrier, error) {
		return RotationCarrier{}, &jack.Error{HTTPStatus: 0, Code: code, Message: "rotation response verification refused"}
	}
	if window < time.Second || window > 120*time.Second || window%time.Second != 0 {
		return refuse("rotation_state_unknown")
	}
	auth, err := jack.ParseResponseAuth(headerValues)
	if err != nil {
		var parsed *jack.Error
		if errors.As(err, &parsed) {
			return RotationCarrier{}, &jack.Error{HTTPStatus: 0, Code: parsed.Code, Message: parsed.Message}
		}
		return RotationCarrier{}, err
	}
	key, exists := known[auth.Kid]
	if !exists {
		return refuse(jack.CodeUnknownServerKey)
	}
	if jack.ValidatePublicKey(key.PublicKey[:]) != nil || jack.KeyID(key.PublicKey[:]) != auth.Kid || key.NotBefore < 0 || key.NotBefore > rotation.MaxTimestamp {
		return refuse("rotation_state_unknown")
	}
	var cutoff int64
	limited := key.KnownCutoff != nil
	if limited {
		cutoff = *key.KnownCutoff
		if cutoff < key.NotBefore || cutoff > rotation.MaxTimestamp {
			return refuse("rotation_state_unknown")
		}
	}
	if err := VerifyResponse(key.PublicKey[:], status, headerValues, requestSig, body, now, window); err != nil {
		return RotationCarrier{}, err
	}
	if auth.TS < key.NotBefore || (limited && (auth.TS >= cutoff || now.Unix() >= cutoff)) {
		return refuse("rotation_key_interval")
	}
	return RotationCarrier{KID: auth.Kid, Timestamp: auth.TS}, nil
}

// The legacy-era lifecycle below moved here from rpc.go to keep both files
// under the layout limit; the code is unchanged.

// legacyFallback performs the legacy handshake and then the operation.
func (c *Client) legacyFallback(ctx context.Context, signer Signer, version, tool string, args []byte, out any) error {
	if err := c.legacyHandshake(ctx, signer, version); err != nil {
		return err
	}
	return c.callWithArgs(ctx, signer, tool, args, out)
}

// jsonrpcInitializeRequest is the legacy-era initialize request: params holds
// protocolVersion, an empty capabilities object and clientInfo.
type jsonrpcInitializeRequest struct {
	JSONRPC string                  `json:"jsonrpc"`
	ID      int64                   `json:"id"`
	Method  string                  `json:"method"`
	Params  jsonrpcInitializeParams `json:"params"`
}

// jsonrpcInitializeParams is protocolVersion, capabilities and clientInfo in
// the legacy era.
type jsonrpcInitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    struct{}       `json:"capabilities"`
	ClientInfo      map[string]any `json:"clientInfo"`
}

// jsonrpcNotification is a legacy-era JSON-RPC notification: no id and no
// params.
type jsonrpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
}

// legacyRecovery is one in-flight legacy session recovery, shared by every
// caller whose request was rejected for the same session id. err is written
// before done is closed and read only after that.
type legacyRecovery struct {
	done chan struct{}
	err  error
}

// recoverLegacySession re-runs the legacy handshake after a 404 that answered
// sentSessionID. At most one handshake runs per rejected session id: callers
// that arrive while one is in flight wait for it and share its result. The
// current-session check and the flight registration happen under one lock, so
// two 404s cannot both decide that recovery is needed. A 404 for a session
// that is no longer current is ignored.
func (c *Client) recoverLegacySession(ctx context.Context, signer Signer, sentSessionID, version string) error {
	c.mu.Lock()
	if !legacyRecoveryNeeded(sentSessionID, c.sessionID) {
		// The 404 answered a session that was cleared or replaced; it must
		// not start a handshake. The check and the registration are atomic,
		// so both callers cannot observe the same stale state.
		c.mu.Unlock()
		return nil
	}
	if flight, ok := c.recoveries[sentSessionID]; ok {
		c.mu.Unlock()
		select {
		case <-flight.done:
			return flight.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	flight := &legacyRecovery{done: make(chan struct{})}
	if c.recoveries == nil {
		c.recoveries = make(map[string]*legacyRecovery)
	}
	c.recoveries[sentSessionID] = flight
	c.mu.Unlock()

	err := c.legacyHandshake(ctx, signer, version)

	c.mu.Lock()
	flight.err = err
	if c.recoveries[sentSessionID] == flight {
		delete(c.recoveries, sentSessionID)
	}
	c.mu.Unlock()
	close(flight.done)
	return err
}

// cachedSessionID returns the session id the cache currently holds.
func (c *Client) cachedSessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// legacyHandshake runs the legacy-era lifecycle of 2025-11-25/2025-06-18:
// initialize, then notifications/initialized. The initialize reply must be
// accepted by parseLegacyInitialize; the negotiated version and the
// Mcp-Session-Id response header, when the server assigns one, are then sent as
// unsigned headers on notifications/initialized and on every later legacy
// request.
//
// The cached session id, the negotiated version and the settled legacy era are
// committed together, and only after notifications/initialized was accepted,
// and only while the cache still holds the session id this handshake started
// from. Any failure returns its error and clears the cached legacy state under
// the same ownership rule, so a handshake that loses to a newer session neither
// overwrites nor invalidates it.
func (c *Client) legacyHandshake(ctx context.Context, signer Signer, version string) (err error) {
	startSessionID := c.cachedSessionID()
	ok := false
	defer func() {
		if !ok {
			c.invalidateLegacyIf(startSessionID)
		}
	}()
	id := c.nextRequestID()
	initBody, err := json.Marshal(jsonrpcInitializeRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "initialize",
		Params: jsonrpcInitializeParams{
			ProtocolVersion: version,
			ClientInfo:      modernClientInfo(),
		},
	})
	if err != nil {
		return err
	}
	status, header, raw, err := c.roundTrip(ctx, signer, initBody, nil)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return decodeVerifiedCall(status, raw, nil)
	}
	negotiated, err := c.parseLegacyInitialize(raw, id)
	if err != nil {
		return err
	}
	initializedBody, err := json.Marshal(jsonrpcNotification{JSONRPC: "2.0", Method: "notifications/initialized"})
	if err != nil {
		return err
	}
	sessionID := header.Get("Mcp-Session-Id")
	status, _, raw, err = c.roundTrip(ctx, signer, initializedBody, legacySessionHeaders(negotiated, sessionID))
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return decodeVerifiedCall(status, raw, nil)
	}
	c.acceptLegacyHandshake(negotiated, sessionID, startSessionID)
	// Both outcomes are success: the handshake itself succeeded. If a newer
	// session was installed while it ran, acceptLegacyHandshake declined to
	// overwrite it, and the deferred invalidation must not run either.
	ok = true
	return nil
}

// parseLegacyInitialize validates the verified initialize answer (2025-11-25
// lifecycle): a JSON object carrying "jsonrpc":"2.0", the id of the initialize
// request that was sent, exactly one of result and error with no error, and a
// result object whose protocolVersion is a string that this client implements.
// It returns the negotiated version. An unsupported but well-formed version is
// a fallback failure like any other invalid reply.
func (c *Client) parseLegacyInitialize(raw []byte, id int64) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("jack client: legacy initialize failed: "+format, args...)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return fail("the reply is not a JSON object")
	}
	var jsonrpc string
	if member, ok := members["jsonrpc"]; !ok || json.Unmarshal(member, &jsonrpc) != nil || jsonrpc != "2.0" {
		return fail(`the reply does not carry "jsonrpc":"2.0"`)
	}
	wantID := strconv.FormatInt(id, 10)
	if member, ok := members["id"]; !ok || string(bytes.TrimSpace(member)) != wantID {
		return fail("the reply id does not match the initialize request id %s", wantID)
	}
	result, hasResult := members["result"]
	errorMember, hasError := members["error"]
	if hasResult == hasError {
		return fail("the reply must carry exactly one of result and error")
	}
	if hasError {
		var rpcErr struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(errorMember, &rpcErr)
		return fail("the reply is a JSON-RPC error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	if isJSONNullToken(result) {
		return fail("the reply carries no result object")
	}
	var resultMembers map[string]json.RawMessage
	if err := json.Unmarshal(result, &resultMembers); err != nil || resultMembers == nil {
		return fail("the reply result is not an object")
	}
	var negotiated string
	if member, ok := resultMembers["protocolVersion"]; !ok || json.Unmarshal(member, &negotiated) != nil {
		return fail("the reply result carries no protocolVersion string")
	}
	for _, implemented := range c.implementedVersions() {
		if negotiated == implemented {
			return negotiated, nil
		}
	}
	return fail("unsupported protocol version %q", negotiated)
}

// isJSONNullToken reports whether raw is the JSON null token.
func isJSONNullToken(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// acceptLegacyHandshake commits a fully accepted handshake: the settled era,
// the negotiated version and the session id change together under mu, so no
// caller observes a partly accepted session. It commits only while the cache
// still holds expected, the session id the handshake started from; a newer
// session installed while the handshake ran is never overwritten, and the
// handshake reports that by returning false.
func (c *Client) acceptLegacyHandshake(negotiated, sessionID, expected string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessionID != expected {
		return false
	}
	c.settled = EraLegacy
	c.negotiated, c.sessionID = negotiated, sessionID
	return true
}

// invalidateLegacyIf forgets the negotiated version and the session id and
// unsettles the era, but only while the cache still holds expected, the session
// id the operation started from. A handshake that fails after a newer session
// was installed must not clear that newer session.
func (c *Client) invalidateLegacyIf(expected string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessionID != expected {
		return
	}
	c.settled = ""
	c.negotiated, c.sessionID = "", ""
}

// legacySessionHeaders renders the unsigned transport headers of a legacy-era
// request after initialize (2025-11-25 transport, Session): MCP-Protocol-Version
// with the negotiated version and, when the server assigned one, Mcp-Session-Id.
// They are never part of the signing string. An empty negotiated version yields
// no header, so a client without a session sends the 0.1.x bytes.
func legacySessionHeaders(negotiated, sessionID string) []modern.Header {
	if negotiated == "" {
		return nil
	}
	headers := []modern.Header{{Name: "MCP-Protocol-Version", Value: negotiated}}
	if sessionID != "" {
		headers = append(headers, modern.Header{Name: "Mcp-Session-Id", Value: sessionID})
	}
	return headers
}

// legacyRecoveryNeeded reports whether a 404 answer needs a fresh handshake:
// only a request sent with the session id that is still current may end that
// session, so a delayed 404 for an older session cannot invalidate a newer one.
func legacyRecoveryNeeded(sentSessionID, currentSessionID string) bool {
	return sentSessionID != "" && sentSessionID == currentSessionID
}
