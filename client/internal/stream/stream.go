package stream

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client/internal/urlpolicy"
)

// ClientConfig is the caller's signed-stream configuration.
type ClientConfig struct {
	// Idle is streamIdleMs (4.5); zero means DefaultIdle.
	Idle time.Duration
	// FrameMaxBytes is the largest accepted data value (2.17); zero means
	// DefaultFrameMaxBytes.
	FrameMaxBytes int64
	// Keys holds rotation-known server keys by kid (5.2). The pinned transport
	// key is added automatically.
	Keys map[string]Key
	// PinnedSuccessorActivation is the known successor activation of the
	// pinned transport key; nil means unknown.
	PinnedSuccessorActivation *int64
	// Consumer selects the verified frame delivery grammar. The zero value
	// uses ConsumerMCP; ConsumerStdio rejects data containing raw CR or LF.
	Consumer Consumer
}

// Signer is the signing capability Open needs; client.Signer satisfies it.
type Signer interface {
	Sign(message []byte) ([]byte, error)
	PublicKey() []byte
	KID() string
}

// OpenConfig is the transport state Open needs.
type OpenConfig struct {
	// Base is the underlying round tripper; nil means http.DefaultTransport.
	Base http.RoundTripper
	// Aud is the audience string bound into the request signing string.
	Aud string
	// Signer signs the request that opens the stream.
	Signer Signer
	// ServerKey is the pinned 32-byte raw server public key.
	ServerKey []byte
	// Now is the request signing clock; nil means time.Now.
	Now func() time.Time
	// Nonce is the nonce source; nil means 16 random bytes.
	Nonce func() ([]byte, error)
	// Window is W; zero means DefaultWindow.
	Window time.Duration
	// Config carries the stream limits and rotation-known keys; nil is empty.
	Config *ClientConfig
	// Accept is the Jack-Accept value; empty means "s1".
	Accept string
}

// NotStreamError reports an answer that is not an s1 stream (1.4); the caller
// reads such an answer through the v1 response path instead.
type NotStreamError struct{ Status int }

func (e *NotStreamError) Error() string {
	return fmt.Sprintf("jack stream: response is not an s1 stream: status %d", e.Status)
}

// ErrClosed is returned by Next after Close.
var ErrClosed = errors.New("jack stream: stream closed by the caller")

// VerifiedResponse is an answer of Open that is not an s1 stream, verified as an
// ordinary v1 response (spec 05 section 1.4): the status, headers and exact body
// bytes the caller may act on.
type VerifiedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Stream is one open, verified s1 stream.
type Stream struct {
	v    *Verifier
	body io.ReadCloser
	idle time.Duration

	messages chan string
	frames   atomic.Int64

	progress chan struct{} // one slot; signalled when the verified frame count grows
	stopped  chan struct{} // closed when the reader exits

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	timedOut atomic.Bool

	// err is written by the reader goroutine only and read by Next only after
	// messages is closed, so it needs no lock.
	err error
}

// Open signs req, sends it and verifies the open header. When the answer is not
// an s1 stream (1.4) it returns the raw response with its body unread, the
// signature of the request it sent and ErrNotStream, so the caller can verify
// that same answer as a v1 response. It never sends a second request.
func Open(req *http.Request, cfg OpenConfig) (*Stream, *http.Response, string, error) {
	if req == nil {
		return nil, nil, "", errors.New("jack stream: nil request")
	}
	if cfg.Signer == nil {
		return nil, nil, "", errors.New("jack stream: nil signer")
	}
	if len(cfg.ServerKey) != 32 {
		return nil, nil, "", fmt.Errorf("jack stream: pinned server key must be exactly 32 bytes, got %d", len(cfg.ServerKey))
	}
	if cfg.Base == nil {
		cfg.Base = http.DefaultTransport
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Nonce == nil {
		cfg.Nonce = randomNonce
	}
	// Destination policy first: a refused destination is never signed.
	if err := urlpolicy.CheckRequestDestination(req); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, nil, "", err
	}
	var body []byte
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			_ = req.Body.Close()
			return nil, nil, "", fmt.Errorf("jack stream: buffering request body: %w", err)
		}
		body = raw
		_ = req.Body.Close()
	}
	nonce, err := cfg.Nonce()
	if err != nil {
		return nil, nil, "", fmt.Errorf("jack stream: nonce: %w", err)
	}
	if len(nonce) != 16 {
		return nil, nil, "", fmt.Errorf("jack stream: nonce must be exactly 16 bytes, got %d", len(nonce))
	}
	ts := cfg.Now().Unix()
	message := jack.RequestSigningString(req.Method, req.URL.RequestURI(), cfg.Aud,
		cfg.Signer.KID(), ts, jack.EncodeBase64URL(nonce), body)
	sig, err := cfg.Signer.Sign([]byte(message))
	if err != nil {
		return nil, nil, "", fmt.Errorf("jack stream: signing request: %w", err)
	}
	value := jack.FormatRequestAuth(jack.RequestAuth{
		Kid:   cfg.Signer.KID(),
		TS:    ts,
		Nonce: jack.EncodeBase64URL(nonce),
		Sig:   jack.EncodeBase64URL(sig),
	})
	auth, err := jack.ParseRequestAuth([]string{value})
	if err != nil {
		return nil, nil, "", fmt.Errorf("jack stream: parsing signed request auth header: %w", err)
	}
	accept := cfg.Accept
	if accept == "" {
		accept = "s1"
	}
	out := req.Clone(req.Context())
	out.Header.Set("Jack-Auth", value)
	if out.Header.Get("Jack-Accept") == "" {
		out.Header.Set("Jack-Accept", accept)
	}
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	out.ContentLength = int64(len(body))

	client := &http.Client{
		Transport: cfg.Base,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(out)
	if err != nil {
		return nil, nil, "", err
	}
	headers := responseHeaders(resp.Header)
	// 1.4: only status 200 with an event-stream media type is a stream; the
	// answer of every other request stays the caller's to verify as v1. The
	// body is left unread and open for that verification.
	if isRedirectStatus(resp.StatusCode) || resp.StatusCode != http.StatusOK ||
		!isEventStream(resp.StatusCode, headers) {
		return nil, resp, auth.Sig, ErrNotStream
	}

	cc := ClientConfig{}
	if cfg.Config != nil {
		cc = *cfg.Config
	}
	keys := make(map[string]Key, len(cc.Keys)+1)
	for kid, key := range cc.Keys {
		keys[kid] = key
	}
	keys[jack.KeyID(cfg.ServerKey)] = Key{
		PublicKey:           append([]byte(nil), cfg.ServerKey...),
		SuccessorActivation: cc.PinnedSuccessorActivation,
	}
	idle := cc.Idle
	if idle <= 0 {
		idle = DefaultIdle
	}
	v, err := NewVerifier(Expectation{
		Now:           cfg.Now,
		Window:        cfg.Window,
		Keys:          keys,
		RequestSig:    auth.Sig,
		FrameMaxBytes: cc.FrameMaxBytes,
		StreamIdle:    cc.Idle,
		Consumer:      cc.Consumer,
	})
	if err != nil {
		_ = resp.Body.Close()
		return nil, nil, "", err
	}
	if err := v.Open(http.StatusOK, headers); err != nil {
		_ = resp.Body.Close()
		return nil, nil, "", err
	}
	s := &Stream{
		v:        v,
		body:     resp.Body,
		idle:     idle,
		messages: make(chan string),
		progress: make(chan struct{}, 1),
		stopped:  make(chan struct{}),
		closed:   make(chan struct{}),
	}
	go s.watch()
	go s.read()
	return s, nil, auth.Sig, nil
}

// Next returns the next delivered message. Once the stream ends it returns the
// terminal error, or io.EOF when the stream ended without one.
func (s *Stream) Next() (string, error) {
	msg, ok := <-s.messages
	if ok {
		return msg, nil
	}
	if s.err != nil {
		return "", s.err
	}
	return "", io.EOF
}

// Close stops the stream; it is idempotent.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.closeErr = s.body.Close()
	})
	return s.closeErr
}

// FramesVerified returns the number of verified frames so far.
func (s *Stream) FramesVerified() int { return int(s.frames.Load()) }

// read owns the verifier for the life of the stream: it feeds body chunks,
// delivers verified messages, and reports the outcome once the body ends or
// the caller closes the stream.
func (s *Stream) read() {
	defer close(s.stopped)
	defer close(s.messages)
	defer func() { _ = s.body.Close() }()
	buf := make([]byte, 32<<10)
	// The open header is the reference point of the idle deadline (4.5), so
	// the watcher is armed from the very start.
	s.signalProgress()
	for {
		if s.closedFlag() {
			s.err = ErrClosed
			return
		}
		n, err := s.body.Read(buf)
		if n > 0 {
			ferr := s.v.Feed(buf[:n])
			// The counter and the progress signal follow the Feed, before
			// any delivery can block: a verified frame restarts the idle
			// deadline even if its message is never taken (4.5).
			s.noteVerified()
			// 4.4: every message verified by this same feed is delivered
			// first, so the delivered set never depends on read boundaries.
			for {
				msg, ok := s.v.Next()
				if !ok {
					break
				}
				select {
				case s.messages <- msg:
				case <-s.closed:
					s.err = ErrClosed
					return
				}
			}
			s.noteVerified()
			if ferr != nil {
				s.err = ferr
				return
			}
		}
		if err != nil {
			switch {
			case s.timedOut.Load():
				s.err = s.v.ObserveLive(s.idle + time.Millisecond)
			case s.closedFlag():
				s.err = ErrClosed
			default:
				s.err = s.v.Finish()
				for {
					msg, ok := s.v.Next()
					if !ok {
						break
					}
					select {
					case s.messages <- msg:
					case <-s.closed:
						s.err = ErrClosed
						return
					}
				}
			}
			return
		}
	}
}

// noteVerified records the verified frame count and restarts the idle deadline
// when it grew (4.5).
func (s *Stream) noteVerified() {
	n := int64(s.v.FramesVerified())
	if s.frames.Swap(n) != n {
		s.signalProgress()
	}
}

// signalProgress signals the watcher without ever blocking: one pending
// signal is enough, the watcher only needs to re-arm its timer.
func (s *Stream) signalProgress() {
	select {
	case s.progress <- struct{}{}:
	default:
	}
}

// watch enforces the 4.5 idle rule from the last VERIFIED frame, independent of
// how the body happens to complete reads: comments, partial lines and any
// other bytes never signal progress. It exits when the reader does.
func (s *Stream) watch() {
	for {
		timer := time.NewTimer(s.idle + time.Millisecond)
		select {
		case <-s.progress:
			stopTimer(timer)
		case <-timer.C:
			s.timedOut.Store(true)
			_ = s.body.Close()
			return
		case <-s.closed:
			stopTimer(timer)
			return
		case <-s.stopped:
			stopTimer(timer)
			return
		}
	}
}

// stopTimer stops timer and drains its channel when it already fired, so a
// consumed progress/close signal cannot leave an expired timer behind.
func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// closedFlag reports whether Close has been called.
func (s *Stream) closedFlag() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// isRedirectStatus reports whether status is 301, 302, 303, 307 or 308.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// responseHeaders flattens resp.Header into received order: names sorted, and
// every value of a repeated header kept as its own entry.
func responseHeaders(h http.Header) []Header {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Header
	for _, name := range names {
		for _, value := range h[name] {
			out = append(out, Header{Name: name, Value: value})
		}
	}
	return out
}

// randomNonce returns 16 random bytes.
func randomNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
