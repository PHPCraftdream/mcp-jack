// Package stream verifies s1 signed streams (spec 05).
//
// A stream is verified incrementally: the open header of 4.2 first, then the
// raw body chunks of 4.3. The first failure is the terminal code; nothing
// after it is delivered, and every message that verified before it stays
// delivered (4.4). A terminal code is a *Error from Codes(); errors about
// misuse of the API or the Expectation are plain errors and do not end a
// stream.
package stream

import (
	"errors"
	"fmt"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Key is one server stream key the client trusts (4.2 step 4, 5.2).
type Key struct {
	// PublicKey is the 32-byte raw Ed25519 public key.
	PublicKey []byte
	// SuccessorActivation is the known successor activation A for this key;
	// nil means no successor is known.
	SuccessorActivation *int64
}

// Consumer selects the delivery form of a verified message frame (6.1, 6.2).
type Consumer string

const (
	// ConsumerMCP delivers the data value of every verified message frame.
	ConsumerMCP Consumer = "mcp"
	// ConsumerStdio writes one line per message frame, so a data value with a
	// raw CR or LF aborts the stream (6.2).
	ConsumerStdio Consumer = "stdio"
)

// Expectation is the client state one stream is verified against.
type Expectation struct {
	// Now is the clock sample; nil means time.Now. It is called when the open
	// header is verified and once per Feed; Finish and ObserveLive use the
	// arrival times Feed recorded and add the silence they are given.
	Now func() time.Time
	// Window is W of spec 01 section 4; zero or less means DefaultWindow.
	Window time.Duration
	// Keys holds every trusted server key by kid (the pinned key and any
	// rotation-known key); a kid outside the map is UnknownServerKey.
	Keys map[string]Key
	// RequestSig is the sig parameter of the request that opened the stream
	// (2.5).
	RequestSig string
	// FrameMaxBytes is the largest accepted data value (2.17); zero or less
	// means DefaultFrameMaxBytes.
	FrameMaxBytes int64
	// StreamIdle is streamIdleMs (4.5); zero or less means DefaultIdle.
	StreamIdle time.Duration
	// Consumer is 6.1 or 6.2; empty means ConsumerMCP.
	Consumer Consumer
	// FrameNow is, when set, the clock sample used to verify frame index (0
	// for the first frame). The live transport leaves it nil and samples Now
	// per frame; the generated vectors pin one sample per frame (spec 05
	// section 9).
	FrameNow func(index int) time.Time
	// Arrival is, when set, the arrival of the body byte at offset (0-based,
	// after the BOM was stripped); the live transport leaves it nil and uses
	// Now per feed. It makes the verified result independent of how the body
	// is split into feeds (4.5).
	Arrival func(offset int) time.Time
}

// Result is the outcome of a stream that ended without a terminal code.
type Result struct {
	// Messages holds the messages not yet taken by Next, in stream order.
	Messages []string
	// FramesVerified counts the verified frames, end frame and signals
	// included.
	FramesVerified int
	// Complete reports whether the end frame was verified.
	Complete bool
}

// ErrNotStream reports a response that is not an s1 stream (1.4).
var ErrNotStream = errors.New("jack stream: response is not an s1 stream")

// maxEventOverhead reserves the framing bytes of 2.6 on top of the data-value
// cap: `event: `, the `data: ` prefixes, the `jack:` line and the terminators.
const maxEventOverhead int64 = 1024

// Verifier is the incremental verifier of one s1 stream: the open header of
// 4.2 first, then raw body chunks of any split (4.3).
type Verifier struct {
	exp           Expectation
	windowSeconds int64
	parser        *sseParser
	consumed      int // body bytes fed, the stripped BOM included

	open   openHeader
	base   time.Time // clock sample of the verified open header
	opened bool

	lastByte  time.Time // arrival of the last body byte, for 4.5
	lastFrame time.Time // arrival of the last verified frame, for 4.5
	prev      string    // open sig, then the previous frame's sig
	prevTS    int64
	haveTS    bool
	seq       uint64
	frames    int
	ended     bool

	messages []string
	err      *Error
}

// NewVerifier validates exp and returns a verifier ready for Open.
func NewVerifier(exp Expectation) (*Verifier, error) {
	if exp.Window <= 0 {
		exp.Window = DefaultWindow
	}
	if exp.FrameMaxBytes <= 0 {
		exp.FrameMaxBytes = DefaultFrameMaxBytes
	}
	if exp.StreamIdle <= 0 {
		exp.StreamIdle = DefaultIdle
	}
	if exp.Consumer == "" {
		exp.Consumer = ConsumerMCP
	}
	if exp.Consumer != ConsumerMCP && exp.Consumer != ConsumerStdio {
		return nil, fmt.Errorf("jack stream: unknown consumer %q", string(exp.Consumer))
	}
	if exp.RequestSig == "" {
		return nil, errors.New("jack stream: request signature is required")
	}
	if len(exp.Keys) == 0 {
		return nil, errors.New("jack stream: no trusted server keys")
	}
	keys := make(map[string]Key, len(exp.Keys))
	for kid, key := range exp.Keys {
		if len(key.PublicKey) != 32 {
			return nil, fmt.Errorf("jack stream: key %q must be exactly 32 bytes, got %d", kid, len(key.PublicKey))
		}
		if err := jack.ValidatePublicKey(key.PublicKey); err != nil {
			return nil, fmt.Errorf("jack stream: key %q: %w", kid, err)
		}
		keys[kid] = key
	}
	exp.Keys = keys
	if exp.Now == nil {
		exp.Now = time.Now
	}
	return &Verifier{
		exp:           exp,
		windowSeconds: int64(exp.Window / time.Second),
		parser:        newSSEParser(exp.FrameMaxBytes + maxEventOverhead),
	}, nil
}

// Open verifies the open header of 4.2 and starts the chain.
func (v *Verifier) Open(status int, headers []Header) error {
	if v.opened {
		return errors.New("jack stream: open header already verified")
	}
	if v.err != nil {
		return v.err
	}
	base := v.exp.Now()
	v.base = base
	// An empty body must still idle out from the open header.
	v.lastByte = base
	if !isEventStream(status, headers) {
		return ErrNotStream
	}
	var values []string
	for _, h := range headers {
		if asciiLower(h.Name) == "jack-auth" {
			values = append(values, h.Value)
		}
	}
	h, err := openValue(values)
	if err != nil {
		return v.terminate(err)
	}
	key, ok := v.exp.Keys[h.kid]
	if !ok {
		return v.terminate(fail(UnknownServerKey, 0, "stream signed by an unknown server key"))
	}
	if !withinWindow(base.Unix(), h.ts, v.windowSeconds) {
		return v.terminate(fail(OutOfWindow, 0, "open header timestamp outside the acceptance window"))
	}
	if key.SuccessorActivation != nil && h.ts >= *key.SuccessorActivation {
		return v.terminate(fail(AfterCutoff, 0, "open header timestamp at or after the successor activation"))
	}
	sig, decodeErr := jack.DecodeBase64URLFixed(h.sig, 64)
	if decodeErr != nil || !jack.Verify(key.PublicKey,
		[]byte(OpenSigningString(status, v.exp.RequestSig, h.kid, h.ts, h.sid)), sig) {
		return v.terminate(fail(BadSignature, 0, "open header signature does not verify"))
	}
	v.open = h
	v.seq = 0
	v.prev = h.sig
	v.opened = true
	return nil
}

// Feed verifies one raw body chunk in any split (4.3).
func (v *Verifier) Feed(chunk []byte) error {
	if v.err != nil {
		return v.err
	}
	if !v.opened {
		return errors.New("jack stream: feed before the open header was verified")
	}
	at := v.exp.Now()
	v.consumed += len(chunk)
	err := v.parser.feed(chunk, v.onEvent)
	// Feed first: stripped must already include this chunk's bytes so the
	// last received byte maps to the right arrival offset (4.5).
	if len(chunk) > 0 {
		if v.exp.Arrival != nil {
			if n := v.parser.stripped(); n > 0 {
				v.lastByte = v.exp.Arrival(n - 1)
			}
		} else {
			v.lastByte = at
		}
	}
	// 2.17: the budget bounds one event's retained bytes; abort at once.
	if v.parser.exceeded {
		return v.terminate(fail(FrameTooLarge, v.frames, "frame data value exceeds frameMaxBytes"))
	}
	if err != nil {
		if jerr, ok := err.(*Error); ok {
			return v.terminate(jerr)
		}
		return v.terminate(fail(BadFrame, v.frames, err.Error()))
	}
	return nil
}

// onEvent applies the checks of 4.3 in reference order.
func (v *Verifier) onEvent(ev event) error {
	// ev.end is the stripped index of the byte that completed the event, so it
	// maps straight to an arrival offset (4.5).
	at := v.exp.Now()
	if v.exp.Arrival != nil {
		at = v.exp.Arrival(ev.end)
	}
	// 4.5: the deadline runs from the open header and restarts at every
	// verified frame; silence exactly equal to StreamIdle is alive.
	ref := v.base
	if !v.lastFrame.IsZero() {
		ref = v.lastFrame
	}
	if at.Sub(ref) > v.exp.StreamIdle {
		return v.terminate(fail(Idle, v.frames, "stream idle timeout"))
	}
	// 2.16: nothing may follow the end frame.
	if v.ended {
		v.ended = false // the stream aborted, so it is no completion
		return v.terminate(fail(OutOfOrder, v.frames, "event after the end frame"))
	}
	f, ok := parseFrame(ev.fields)
	if !ok {
		return v.terminate(fail(BadFrame, v.frames, "malformed frame"))
	}
	if int64(len(f.data)) > v.exp.FrameMaxBytes {
		return v.terminate(fail(FrameTooLarge, v.frames, "frame data value exceeds frameMaxBytes"))
	}
	if f.seq != v.seq {
		return v.terminate(fail(OutOfOrder, v.frames, "frame sequence number is not the expected next value"))
	}
	now := at
	if v.exp.FrameNow != nil {
		now = v.exp.FrameNow(v.frames)
	}
	if !withinWindow(now.Unix(), f.ts, v.windowSeconds) || (v.haveTS && f.ts < v.prevTS) {
		return v.terminate(fail(StaleFrame, v.frames, "frame timestamp outside the window or below the previous frame"))
	}
	key := v.exp.Keys[v.open.kid] // present: checked by Open
	if key.SuccessorActivation != nil && f.ts >= *key.SuccessorActivation {
		return v.terminate(fail(AfterCutoff, v.frames, "frame timestamp at or after the successor activation"))
	}
	sig, err := jack.DecodeBase64URLFixed(f.sig, 64)
	if err != nil || !jack.Verify(key.PublicKey,
		[]byte(FrameSigningString(v.open.sid, f.seq, f.ts, v.prev, DataHash([]byte(f.data)))), sig) {
		return v.terminate(fail(BadSignature, v.frames, "frame signature does not verify"))
	}
	// The frame is verified from here on and counts.
	v.frames++
	v.lastFrame = at
	v.seq++
	v.prevTS = f.ts
	v.haveTS = true
	v.prev = f.sig

	if f.kind == "message" {
		// 2.18: a transport signal ends the stream and is never delivered;
		// no end frame is read or required.
		if code, ok := SignalCode(f.data); ok {
			return v.terminate(fail(code, v.frames, "transport signal"))
		}
	}
	if f.kind == "jack-end" {
		v.ended = true
		return nil
	}
	if v.exp.Consumer == ConsumerStdio && strings.ContainsAny(f.data, "\n\r") {
		return v.terminate(fail(BadFrame, v.frames, "data value contains a raw CR or LF"))
	}
	v.messages = append(v.messages, f.data)
	return nil
}

// Next pops the message not yet taken by Next.
func (v *Verifier) Next() (string, bool) {
	if len(v.messages) == 0 {
		return "", false
	}
	msg := v.messages[0]
	v.messages[0] = "" // do not retain a delivered message
	v.messages = v.messages[1:]
	return msg, true
}

// Messages returns a copy of the messages not yet taken by Next.
func (v *Verifier) Messages() []string {
	return append([]string(nil), v.messages...)
}

// FramesVerified returns the number of verified frames.
func (v *Verifier) FramesVerified() int { return v.frames }

// Complete reports whether the end frame was verified.
func (v *Verifier) Complete() bool { return v.ended }

// Terminal returns the recorded terminal error, if any.
func (v *Verifier) Terminal() *Error { return v.err }

// Result returns the delivered messages, the verified frame count and whether
// the end frame was verified.
func (v *Verifier) Result() Result {
	return Result{Messages: v.Messages(), FramesVerified: v.frames, Complete: v.ended}
}

// Finish reports the outcome of a body that ended (4.4/4.5).
func (v *Verifier) Finish() error {
	if v.err != nil {
		return v.err
	}
	if !v.opened {
		return errors.New("jack stream: finish before the open header was verified")
	}
	// 2.14: an unterminated trailing line is discarded, but a pending lone CR
	// already ended its line and possibly its event.
	v.parser.reset()
	if v.parser.exceeded {
		return v.terminate(fail(FrameTooLarge, v.frames, "frame data value exceeds frameMaxBytes"))
	}
	if v.err != nil {
		return v.err // an event ended by reset may have terminated the stream
	}
	if v.ended {
		return nil
	}
	ref := v.base
	if !v.lastFrame.IsZero() {
		ref = v.lastFrame
	}
	if !v.lastByte.IsZero() && v.lastByte.Sub(ref) > v.exp.StreamIdle {
		return v.terminate(fail(Idle, v.frames, "stream idle timeout"))
	}
	return v.terminate(fail(Truncated, v.frames, "stream ended before the end frame"))
}

// ObserveLive reports the outcome of an open connection the caller stopped
// reading after silent of trailing silence (4.5). A live observation records
// no error, but it is no completion either.
func (v *Verifier) ObserveLive(silent time.Duration) error {
	if v.err != nil {
		return v.err
	}
	if !v.opened {
		return errors.New("jack stream: observe before the open header was verified")
	}
	ref := v.base
	if !v.lastFrame.IsZero() {
		ref = v.lastFrame
	}
	if v.lastByte.Sub(ref)+silent > v.exp.StreamIdle {
		return v.terminate(fail(Idle, v.frames, "stream idle timeout"))
	}
	return nil
}

// Verify is the one-shot form of Open, Feed and Finish.
func Verify(exp Expectation, status int, headers []Header, chunks [][]byte) (Result, error) {
	v, err := NewVerifier(exp)
	if err != nil {
		return Result{}, err
	}
	if err := v.Open(status, headers); err != nil {
		return v.Result(), err
	}
	for _, chunk := range chunks {
		if err := v.Feed(chunk); err != nil {
			return v.Result(), err
		}
	}
	if err := v.Finish(); err != nil {
		return v.Result(), err
	}
	return v.Result(), nil
}

// terminate records err as the terminal error of the stream (the first
// failure wins) and returns it.
func (v *Verifier) terminate(err *Error) error {
	if v.err == nil {
		v.err = err
	}
	return v.err
}

// withinWindow reports whether the ordered unsigned distance between now and
// ts is at most windowSeconds; the unsigned form is exact for any int64.
func withinWindow(now, ts, windowSeconds int64) bool {
	var distance uint64
	if now < ts {
		distance = uint64(ts) - uint64(now)
	} else {
		distance = uint64(now) - uint64(ts)
	}
	return distance <= uint64(windowSeconds)
}
