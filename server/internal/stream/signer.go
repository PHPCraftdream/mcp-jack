package stream

import (
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

var (
	// ErrClosed is returned by Write once the stream ended.
	ErrClosed = errors.New("stream: the signed stream is already closed")
	// ErrKeyRetired reports a key at or past its successor activation (5.1).
	ErrKeyRetired = errors.New("stream: the signing key is at or past its successor activation")
	// ErrHandlerData reports a handler data value a signed frame cannot carry.
	ErrHandlerData = errors.New("stream: handler data value is not valid UTF-8")
)

// cutoffGuardSeconds is the lead the stream keeps before the successor
// activation, so the end frame still carries a legal timestamp (5.1).
const cutoffGuardSeconds int64 = 1

// SessionConfig gathers everything one signed stream needs.
type SessionConfig struct {
	Options    Options
	Key        Key
	RequestSig string
	SID        string
	// Now samples the wall clock in Unix seconds; nil means time.Now.
	Now func() int64
	// Cutoff returns the successor activation known for the key right now
	// (5.1). It is consulted before every frame, so a successor announced
	// while the stream is open is honoured. Nil means only Key.Cutoff applies.
	Cutoff func() (int64, bool)
	// Flush, when set, is called after every frame.
	Flush func()
	// Stop cancels the handler request context when the server ends the stream.
	Stop func()
}

// Session is one signed response stream: the open header of 2.1-2.5 and the
// frame chain of 2.6-2.16, written as the handler produces events. All methods
// are safe for concurrent use: the duration timer may end a stream while the
// handler goroutine writes it.
type Session struct {
	// mu guards the chain state; parserMu serializes parser access and end-of-stream
	// against handler writes; writeMu serializes writes to w.
	mu       sync.Mutex
	parserMu sync.Mutex
	writeMu  sync.Mutex

	w        io.Writer
	flush    func()
	stop     func()
	stopOnce sync.Once
	key      Key
	opts     Options

	requestSig string
	sid        string
	openSig    string
	openTS     int64
	now        func() int64
	cutoffFn   func() (int64, bool)

	parser splitter
	seq    uint64
	prev   string
	lastTS int64
	haveTS bool

	lastMessage string
	frames      int
	closed      bool
}

// OpenSession signs the open header and returns the session. The caller writes
// the 200 status, Content-Type, X-Accel-Buffering and exactly one Jack-Auth
// header carrying HeaderValue before handing body bytes to Write.
func OpenSession(w io.Writer, cfg SessionConfig) (*Session, error) {
	key := cfg.Key
	if w == nil {
		return nil, errors.New("stream: writer is nil")
	}
	if len(key.PublicKey) != 32 {
		return nil, errors.New("stream: key public key must be 32 bytes")
	}
	if key.Sign == nil {
		return nil, errors.New("stream: key signer is nil")
	}
	if key.Kid == "" {
		return nil, errors.New("stream: key id is empty")
	}
	if cfg.RequestSig == "" {
		return nil, errors.New("stream: request signature is empty")
	}
	if _, err := jack.DecodeBase64URLFixed(cfg.SID, 16); err != nil { // 2.4
		return nil, errors.New("stream: sid is not a canonical 16-byte base64url value")
	}
	now := cfg.Now
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	// The transport passes normalized options; this only fills gaps.
	opts := cfg.Options.Normalize(0)

	openTS := now()
	if cutoff, known := lowestCutoff(key.Cutoff, cfg.Cutoff); known && openTS >= cutoff {
		return nil, ErrKeyRetired // 5.1
	}
	signing := OpenSigningString(200, cfg.RequestSig, key.Kid, openTS, cfg.SID) // 2.5
	raw, err := key.Sign([]byte(signing))
	if err != nil {
		return nil, err
	}
	if len(raw) != 64 {
		return nil, errors.New("stream: key did not return a 64-byte signature")
	}
	// 3.1: never sign with a key whose public identity disagrees.
	if !jack.Verify(key.PublicKey, []byte(signing), raw) {
		return nil, errors.New("stream: open signature does not verify under the key")
	}
	s := &Session{
		w:          w,
		flush:      cfg.Flush,
		stop:       cfg.Stop,
		key:        key,
		opts:       opts,
		requestSig: cfg.RequestSig,
		sid:        cfg.SID,
		openSig:    jack.EncodeBase64URL(raw),
		openTS:     openTS,
		now:        now,
		cutoffFn:   cfg.Cutoff,
	}
	s.prev = s.openSig
	s.seq = 0
	return s, nil
}

// lowestCutoff returns the lowest successor activation known from the key and
// from the live source (5.1).
func lowestCutoff(keyCutoff *int64, live func() (int64, bool)) (int64, bool) {
	cutoff, known := int64(0), false
	if keyCutoff != nil {
		cutoff, known = *keyCutoff, true
	}
	if live != nil {
		if a, ok := live(); ok && (!known || a < cutoff) {
			cutoff, known = a, true
		}
	}
	return cutoff, known
}

// HeaderValue is the 2.1 Jack-Auth value of the open header.
func (s *Session) HeaderValue() string {
	return FormatOpenValue(s.key.Kid, s.openTS, s.sid, s.openSig)
}

// OpenTimestamp is the ts of the open header, in Unix seconds.
func (s *Session) OpenTimestamp() int64 { return s.openTS }

// Write forwards handler bytes: every completed event becomes one signed
// message frame. The returned error tells the handler to stop; the stream has
// then been closed with its end frame.
func (s *Session) Write(p []byte) (int, error) {
	s.parserMu.Lock()
	defer s.parserMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	if cutoff, known := s.cutoffLocked(); known && s.now() >= cutoff-cutoffGuardSeconds {
		s.mu.Unlock()
		s.writeMu.Lock()
		s.endHeld()
		s.writeMu.Unlock()
		return 0, ErrClosed
	}
	s.mu.Unlock()
	err := s.parser.feed(p, s.opts.FrameMaxBytes+1024, s.emit)
	if errors.Is(err, errEventTooLarge) {
		// 2.17, 2.18, 3.2: the signal frame is the last message of the stream.
		s.writeMu.Lock()
		_ = s.writeFrameHeld(MessageEvent, SignalValue(SignalFrameTooLarge, s.opts.FrameMaxBytes))
		s.endHeld()
		s.writeMu.Unlock()
		return 0, ErrClosed
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// emit signs one completed handler event as one message frame.
func (s *Session) emit(data string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if data == "" {
		s.mu.Unlock()
		return nil // 2.9: a message frame always carries data
	}
	if !utf8.ValidString(data) {
		s.mu.Unlock()
		s.writeMu.Lock()
		s.endHeld()
		s.writeMu.Unlock()
		return ErrHandlerData
	}
	s.mu.Unlock()
	if int64(len(data)) > s.opts.FrameMaxBytes { // 2.17, 3.2
		// The signal frame is the last message: nothing follows it but the end.
		_ = s.writeFrame(MessageEvent, SignalValue(SignalFrameTooLarge, s.opts.FrameMaxBytes))
		s.writeMu.Lock()
		s.endHeld()
		s.writeMu.Unlock()
		return ErrClosed
	}
	if err := s.writeFrame(MessageEvent, data); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastMessage = data
	s.mu.Unlock()
	return nil
}

// writeFrame signs and writes one frame with the write lock taken here.
func (s *Session) writeFrame(kind, data string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.writeFrameHeld(kind, data)
}

// writeFrameHeld signs and writes one frame of the chain (2.15); the caller
// holds writeMu. The chain state is committed only once the frame reached the
// writer, so a blocking write never holds mu.
func (s *Session) writeFrameHeld(kind, data string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	ts, ok := s.frameTSLocked(kind == EndEvent)
	if !ok {
		s.mu.Unlock()
		return ErrKeyRetired
	}
	seq, prev := s.seq, s.prev
	s.mu.Unlock()

	signing := FrameSigningString(s.sid, seq, ts, prev, DataHash([]byte(data)))
	raw, err := s.key.Sign([]byte(signing))
	if err != nil {
		return err
	}
	if len(raw) != 64 {
		return errors.New("stream: key did not return a 64-byte signature")
	}
	if !jack.Verify(s.key.PublicKey, []byte(signing), raw) {
		return errors.New("stream: frame signature does not verify under the key")
	}
	sig := jack.EncodeBase64URL(raw)
	if _, err := s.w.Write(EncodeFrame(kind, data, seq, ts, sig)); err != nil {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.stopLocked()
		return err
	}
	if s.flush != nil {
		s.flush()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.prev = sig
	s.lastTS = ts
	s.haveTS = true
	s.seq++
	s.frames++
	return nil
}

// frameTSLocked returns the timestamp of the next frame: fresh, never below
// the previous frame (2.16), never at or past the cutoff (5.1) and never close
// enough to it that the end frame could miss its own legal timestamp.
func (s *Session) frameTSLocked(end bool) (int64, bool) {
	now := s.now()
	cutoff, known := s.cutoffLocked()
	if known && !end && now >= cutoff-cutoffGuardSeconds {
		return 0, false
	}
	ts := now
	if s.haveTS && ts < s.lastTS {
		ts = s.lastTS
	}
	if known && ts >= cutoff {
		ts = cutoff - 1
	}
	if s.haveTS && ts < s.lastTS {
		return 0, false
	}
	return ts, true
}

// cutoffLocked returns the lowest successor activation known right now (5.1).
func (s *Session) cutoffLocked() (int64, bool) {
	return lowestCutoff(s.key.Cutoff, s.cutoffFn)
}

// endHeld writes the end frame once and closes the stream (2.16); the caller
// holds writeMu. The end frame is always attempted, even before any message
// frame, so the stream carries the close 5.1 requires.
func (s *Session) endHeld() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if err := s.writeFrameHeld(EndEvent, ""); errors.Is(err, ErrKeyRetired) {
		// There is no legal timestamp left for an end frame.
		s.stopLocked()
		return
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.stopLocked()
}

// stopLocked cancels the handler request context at most once.
func (s *Session) stopLocked() {
	s.stopOnce.Do(func() {
		if s.stop != nil {
			s.stop()
		}
	})
}

// Close ends the stream the handler finished: it writes the end frame unless
// the stream already ended.
func (s *Session) Close() error {
	s.parserMu.Lock()
	defer s.parserMu.Unlock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.endHeld()
	return nil
}

// Timeout ends a stream that reached its maximum duration or its key cutoff:
// it writes the final response of the opening request when final returns a
// non-empty data value, then the end frame. final may be nil.
func (s *Session) Timeout(final func(lastMessage string) string) error {
	if !s.parserMu.TryLock() {
		s.stopLocked()
		return nil
	}
	defer s.parserMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	last := s.lastMessage
	guardBlocked := false
	if cutoff, known := s.cutoffLocked(); known && s.now() >= cutoff-cutoffGuardSeconds {
		guardBlocked = true
	}
	s.mu.Unlock()

	if !s.writeMu.TryLock() {
		// The wire is busy: cancel the handler, but leave the state open so the
		// in-flight write can commit and the caller's deferred Close can end it.
		s.stopLocked()
		return nil
	}
	defer s.writeMu.Unlock()
	if final != nil && !guardBlocked { // 6.3
		if data := final(last); data != "" && data != last {
			_ = s.writeFrameHeld(MessageEvent, data)
		}
	}
	s.endHeld()
	return nil
}

// Closed reports whether the stream already ended.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Frames returns the number of frames written, the end frame included.
func (s *Session) Frames() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames
}
