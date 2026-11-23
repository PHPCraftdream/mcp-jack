package stream

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// streamBuilder assembles a signed s1 stream with a test key, mirroring the
// wire shape of 2.6 and 2.16 independently of the package under test.
type streamBuilder struct {
	priv       ed25519.PrivateKey
	pub        []byte
	kid        string
	sid        string
	requestSig string
	ts         int64
	seq        uint64
	prev       string
	body       bytes.Buffer
}

// newStream returns a builder with a deterministic key, sid and request sig.
func newStream(t *testing.T, openTS int64) *streamBuilder {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
	return &streamBuilder{
		priv:       priv,
		pub:        pub,
		kid:        jack.KeyID(pub),
		sid:        jack.EncodeBase64URL(bytes.Repeat([]byte{5}, 16)),
		requestSig: jack.EncodeBase64URL(bytes.Repeat([]byte{3}, 64)),
		ts:         openTS,
	}
}

// open signs the 2.5 open signing string for ts, roots the chain in the
// resulting sig and returns the Jack-Auth value of 2.1 in the 2.2 order.
func (b *streamBuilder) open(ts int64) string {
	sig := ed25519.Sign(b.priv, []byte(OpenSigningString(200, b.requestSig, b.kid, ts, b.sid)))
	sigText := jack.EncodeBase64URL(sig)
	b.ts = ts
	b.prev = sigText
	return "s1 kid=" + b.kid + ",ts=" + strconv.FormatInt(ts, 10) + ",sid=" + b.sid + ",sig=" + sigText
}

// frame signs one 2.6 event over the chained prev, appends its exact SSE
// bytes and advances the chain.
func (b *streamBuilder) frame(ts int64, data string) {
	sig := ed25519.Sign(b.priv,
		[]byte(FrameSigningString(b.sid, b.seq, ts, b.prev, DataHash([]byte(data)))))
	sigText := jack.EncodeBase64URL(sig)
	kind := "message"
	if data == "" {
		kind = "jack-end"
	}
	b.body.WriteString("event: " + kind + "\n")
	for _, piece := range strings.Split(data, "\n") {
		if piece == "" {
			b.body.WriteString("data:\n")
			continue
		}
		b.body.WriteString("data: " + piece + "\n")
	}
	b.body.WriteString("jack: seq=" + strconv.FormatUint(b.seq, 10) +
		",ts=" + strconv.FormatInt(ts, 10) + ",sig=" + sigText + "\n\n")
	b.prev = sigText
	b.seq++
}

// raw appends hand-written body bytes.
func (b *streamBuilder) raw(text string) { b.body.WriteString(text) }

// bytes returns the body assembled so far.
func (b *streamBuilder) bytes() []byte { return b.body.Bytes() }

// expectation returns the client state one stream is verified against, with a
// fixed clock sample of now.
func (b *streamBuilder) expectation(t *testing.T, now int64) Expectation {
	t.Helper()
	return Expectation{
		Now:        func() time.Time { return time.Unix(now, 0) },
		Window:     30 * time.Second,
		Keys:       map[string]Key{b.kid: {PublicKey: b.pub}},
		RequestSig: b.requestSig,
	}
}

// scriptedClock is a manually advanced clock.
type scriptedClock struct{ now time.Time }

// Now returns the clock's current sample.
func (c *scriptedClock) Now() time.Time { return c.now }

// Set moves the clock to t.
func (c *scriptedClock) Set(t time.Time) { c.now = t }

// openHeaders returns the 2.1 success response headers carrying value.
func openHeaders(value string) []Header {
	return []Header{
		{Name: "Content-Type", Value: "text/event-stream"},
		{Name: "X-Accel-Buffering", Value: "no"},
		{Name: "Jack-Auth", Value: value},
	}
}

// runStream opens, feeds body in the given chunk sizes and finishes.
func runStream(t *testing.T, exp Expectation, status int, headers []Header, body []byte, chunks ...int) (Result, error) {
	t.Helper()
	v, err := NewVerifier(exp)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Open(status, headers); err != nil {
		return v.Result(), err
	}
	off := 0
	if len(chunks) == 0 {
		if len(body) > 0 {
			if err := v.Feed(body); err != nil {
				return v.Result(), err
			}
		}
	} else {
		for _, n := range chunks {
			if off >= len(body) {
				break
			}
			end := off + n
			if end > len(body) {
				end = len(body)
			}
			if err := v.Feed(body[off:end]); err != nil {
				return v.Result(), err
			}
			off = end
		}
		if off < len(body) {
			if err := v.Feed(body[off:]); err != nil {
				return v.Result(), err
			}
		}
	}
	if err := v.Finish(); err != nil {
		return v.Result(), err
	}
	return v.Result(), nil
}

// wantCode asserts that err is a *Error of code with frames verified.
func wantCode(t *testing.T, err error, code Code, frames int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected terminal code %q, got no error", code)
	}
	var jerr *Error
	if !errors.As(err, &jerr) {
		t.Fatalf("error %v is not a *Error", err)
	}
	if jerr.Code != code {
		t.Fatalf("code = %q, want %q", jerr.Code, code)
	}
	if jerr.FramesVerified != frames {
		t.Fatalf("FramesVerified = %d, want %d", jerr.FramesVerified, frames)
	}
}

// openVerifier returns a verifier whose open header verified.
func openVerifier(t *testing.T, exp Expectation, headers []Header) *Verifier {
	t.Helper()
	v, err := NewVerifier(exp)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Open(200, headers); err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

// equalStrings reports whether a and b hold the same strings in order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// flipMidSignature flips one character in the middle of the sig of value and
// returns both the changed header value and the changed sig.
func flipMidSignature(t *testing.T, value string) (string, string) {
	t.Helper()
	const marker = "sig="
	i := strings.LastIndex(value, marker)
	if i < 0 {
		t.Fatalf("Jack-Auth value %q carries no sig parameter", value)
	}
	sig := []byte(value[i+len(marker):])
	if len(sig) != 86 {
		t.Fatalf("sig is %d chars, want 86", len(sig))
	}
	mid := len(sig) / 2
	if sig[mid] != 'A' {
		sig[mid] = 'A'
	} else {
		sig[mid] = 'B'
	}
	flipped := string(sig)
	return value[:i+len(marker)] + flipped, flipped
}

func TestVerifierOpenSteps(t *testing.T) {
	const now = int64(1_700_000_000)
	tests := []struct {
		name    string
		prepare func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte)
		code    Code
	}{
		{
			name: "missing Jack-Auth",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				b.open(now)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				headers := []Header{
					{Name: "Content-Type", Value: "text/event-stream"},
					{Name: "X-Accel-Buffering", Value: "no"},
				}
				return b.expectation(t, now), headers, b.bytes()
			},
			code: MissingAuth,
		},
		{
			name: "two Jack-Auth headers",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				headers := append(openHeaders(value), Header{Name: "Jack-Auth", Value: value})
				return b.expectation(t, now), headers, b.bytes()
			},
			code: MalformedAuth,
		},
		{
			name: "extra parameter",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now) + ",extra=1"
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: MalformedAuth,
		},
		{
			name: "sid of 15 bytes",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				b.sid = jack.EncodeBase64URL(bytes.Repeat([]byte{5}, 15))
				value := b.open(now)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: MalformedAuth,
		},
		{
			name: "scheme s2",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now)
				value = "s2" + value[len("s1"):]
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: UnsupportedVersion,
		},
		{
			name: "scheme v1",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now)
				value = "v1" + value[len("s1"):]
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: UnsupportedVersion,
		},
		{
			name: "kid outside the trusted keys",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				exp := b.expectation(t, now)
				b.priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
				b.pub = append([]byte(nil), b.priv.Public().(ed25519.PublicKey)...)
				b.kid = jack.KeyID(b.pub)
				value := b.open(now)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return exp, openHeaders(value), b.bytes()
			},
			code: UnknownServerKey,
		},
		{
			name: "open ts one second past the window",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now - 31)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: OutOfWindow,
		},
		{
			name: "open ts one second ahead",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now + 31)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(value), b.bytes()
			},
			code: OutOfWindow,
		},
		{
			name: "open ts at the successor activation",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now)
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				exp := b.expectation(t, now)
				activation := now
				exp.Keys[b.kid] = Key{PublicKey: b.pub, SuccessorActivation: &activation}
				return exp, openHeaders(value), b.bytes()
			},
			code: AfterCutoff,
		},
		{
			name: "flipped mid-signature character",
			prepare: func(t *testing.T, b *streamBuilder) (Expectation, []Header, []byte) {
				value := b.open(now)
				flippedValue, flippedSig := flipMidSignature(t, value)
				b.prev = flippedSig
				b.frame(now, "delivered only if a failed opener is wrongly accepted")
				b.frame(now, "")
				return b.expectation(t, now), openHeaders(flippedValue), b.bytes()
			},
			code: BadSignature,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newStream(t, now)
			exp, headers, body := tc.prepare(t, b)
			res, err := runStream(t, exp, 200, headers, body)
			wantCode(t, err, tc.code, 0)
			if len(res.Messages) != 0 {
				t.Fatalf("delivered %q after a failed opener", res.Messages)
			}
			if res.Complete {
				t.Fatal("Complete() = true after a failed opener")
			}
		})
	}
}

const transportSignal = `{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1024}}`

const transportSignalExtra = `{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1024},"id":7}`

func TestVerifierFrameSteps(t *testing.T) {
	const now = int64(1_700_000_000)

	t.Run("baseline two-frame stream", func(t *testing.T) {
		b := newStream(t, now)
		value := b.open(now)
		b.frame(now, "hello")
		b.frame(now, "")
		res, err := runStream(t, b.expectation(t, now), 200, openHeaders(value), b.bytes())
		if err != nil {
			t.Fatalf("stream failed: %v", err)
		}
		if !res.Complete {
			t.Fatal("Complete() = false, want true")
		}
		if res.FramesVerified != 2 {
			t.Fatalf("FramesVerified = %d, want 2", res.FramesVerified)
		}
		if !equalStrings(res.Messages, []string{"hello"}) {
			t.Fatalf("messages = %q, want [hello]", res.Messages)
		}
	})

	tests := []struct {
		name     string
		build    func(t *testing.T, b *streamBuilder, now int64) (Expectation, string)
		code     Code
		frames   int
		messages []string
	}{
		{
			name: "id field",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.raw("id: 7\n")
				b.frame(now, "hello")
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			code: BadFrame,
		},
		{
			name: "data value over FrameMaxBytes",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, strings.Repeat("a", 1025))
				b.frame(now, "")
				exp := b.expectation(t, now)
				exp.FrameMaxBytes = 1024
				return exp, value
			},
			code: FrameTooLarge,
		},
		{
			name: "seq 2 where 1 is expected",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.seq = 2
				b.frame(now, "two")
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			code:     OutOfOrder,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "frame ts below the previous frame",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.frame(now-1, "older")
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			code:     StaleFrame,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "frame ts 31 s behind the clock sample",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.frame(now-31, "old")
				b.frame(now, "")
				exp := b.expectation(t, now)
				exp.FrameNow = func(int) time.Time { return time.Unix(now, 0) }
				return exp, value
			},
			code:     StaleFrame,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "frame at the successor activation",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.frame(now+5, "late")
				b.frame(now+5, "")
				exp := b.expectation(t, now)
				activation := now + 5
				exp.Keys[b.kid] = Key{PublicKey: b.pub, SuccessorActivation: &activation}
				return exp, value
			},
			code:     AfterCutoff,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "frame signed over the wrong prev",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.prev = jack.EncodeBase64URL(bytes.Repeat([]byte{7}, 64))
				b.frame(now, "second")
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			code:     BadSignature,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "frame after the end frame",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				b.frame(now, "")
				b.frame(now, "late")
				return b.expectation(t, now), value
			},
			code:     OutOfOrder,
			frames:   2,
			messages: []string{"hello"},
		},
		{
			name: "body without an end frame",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, "hello")
				return b.expectation(t, now), value
			},
			code:     Truncated,
			frames:   1,
			messages: []string{"hello"},
		},
		{
			name: "transport signal",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, transportSignal)
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			code:   FrameTooLarge,
			frames: 1,
		},
		{
			name: "signal lookalike with an extra member",
			build: func(t *testing.T, b *streamBuilder, now int64) (Expectation, string) {
				value := b.open(now)
				b.frame(now, transportSignalExtra)
				b.frame(now, "")
				return b.expectation(t, now), value
			},
			frames:   2,
			messages: []string{transportSignalExtra},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newStream(t, now)
			exp, value := tc.build(t, b, now)
			res, err := runStream(t, exp, 200, openHeaders(value), b.bytes())
			if tc.code == "" {
				if err != nil {
					t.Fatalf("stream failed: %v", err)
				}
				if !res.Complete {
					t.Fatal("Complete() = false, want true")
				}
			} else {
				wantCode(t, err, tc.code, tc.frames)
				if res.Complete {
					t.Fatal("Complete() = true after a terminal code")
				}
			}
			if res.FramesVerified != tc.frames {
				t.Fatalf("FramesVerified = %d, want %d", res.FramesVerified, tc.frames)
			}
			if !equalStrings(res.Messages, tc.messages) {
				t.Fatalf("messages = %q, want %q", res.Messages, tc.messages)
			}
		})
	}
}

func TestVerifierArrivalOffsets(t *testing.T) {
	const base = int64(1_700_000_000)
	b := newStream(t, base)
	value := b.open(base)
	b.frame(base, "hello")
	boundary := len(b.bytes())
	b.frame(base, "")
	body := append([]byte(nil), b.bytes()...)
	end := len(body) - 1

	for _, tc := range []struct {
		name string
		at   time.Time
		code Code
	}{
		{name: "event completion at threshold", at: time.Unix(base, 0).Add(90 * time.Second)},
		{name: "event completion past threshold", at: time.Unix(base, 0).Add(90*time.Second + time.Millisecond), code: Idle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arrival := make([]time.Time, len(body))
			for i := range arrival {
				arrival[i] = time.Unix(base, 0)
			}
			arrival[end] = tc.at
			exp := b.expectation(t, base)
			exp.StreamIdle = 90 * time.Second
			exp.FrameNow = func(int) time.Time { return time.Unix(base, 0) }
			exp.Arrival = func(offset int) time.Time {
				if offset < 0 {
					offset = 0
				}
				if offset >= len(arrival) {
					offset = len(arrival) - 1
				}
				return arrival[offset]
			}
			byteCuts := make([]int, len(body))
			for i := range byteCuts {
				byteCuts[i] = i + 1
			}
			for _, strategy := range []struct {
				name string
				cuts []int
			}{
				{name: "whole body"},
				{name: "byte by byte", cuts: byteCuts},
				{name: "frame boundaries", cuts: []int{boundary, len(body)}},
			} {
				t.Run(strategy.name, func(t *testing.T) {
					v := openVerifier(t, exp, openHeaders(value))
					start := 0
					var err error
					cuts := strategy.cuts
					if cuts == nil {
						cuts = []int{len(body)}
					}
					for _, stop := range cuts {
						err = v.Feed(body[start:stop])
						start = stop
						if err != nil {
							break
						}
					}
					if err == nil {
						err = v.Finish()
					}
					res := v.Result()
					if tc.code != "" {
						wantCode(t, err, tc.code, 1)
						if res.Complete {
							t.Fatal("Complete() = true after idle timeout")
						}
						if !equalStrings(res.Messages, []string{"hello"}) {
							t.Fatalf("messages = %q, want [hello]", res.Messages)
						}
					} else {
						if err != nil {
							t.Fatalf("stream failed: %v", err)
						}
						if !res.Complete || res.FramesVerified != 2 || !equalStrings(res.Messages, []string{"hello"}) {
							t.Fatalf("result = %+v, want complete 2-frame [hello]", res)
						}
					}
					wantFrames := 2
					if tc.code != "" {
						wantFrames = 1
					}
					if res.FramesVerified != wantFrames {
						t.Fatalf("FramesVerified = %d, want %d", res.FramesVerified, wantFrames)
					}
				})
			}
		})
	}
}

func TestVerifierIdleWithInjectedClock(t *testing.T) {
	const base = int64(1_700_000_000)
	origin := time.Unix(base, 0)

	// build returns a stream whose message frame completes at +0 ms and whose
	// end frame carries endTS and completes at the sample set by the caller.
	build := func(t *testing.T, endTS int64) (*streamBuilder, *scriptedClock, string, []byte, []byte, Expectation) {
		t.Helper()
		b := newStream(t, base)
		clock := &scriptedClock{now: origin}
		value := b.open(base)
		b.frame(base, "hello")
		split := len(b.bytes())
		b.frame(endTS, "")
		body := b.bytes()
		exp := b.expectation(t, base)
		exp.Now = clock.Now
		return b, clock, value, body[:split], body[split:], exp
	}

	t.Run("gap equal to StreamIdle is alive", func(t *testing.T) {
		_, clock, value, first, last, exp := build(t, base+90)
		v := openVerifier(t, exp, openHeaders(value))
		if err := v.Feed(first); err != nil {
			t.Fatalf("Feed: %v", err)
		}
		clock.Set(origin.Add(90 * time.Second))
		if err := v.Feed(last); err != nil {
			t.Fatalf("Feed of the end frame at exactly StreamIdle: %v", err)
		}
		if err := v.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		res := v.Result()
		if !res.Complete {
			t.Fatal("Complete() = false, want true")
		}
		if res.FramesVerified != 2 {
			t.Fatalf("FramesVerified = %d, want 2", res.FramesVerified)
		}
		if !equalStrings(res.Messages, []string{"hello"}) {
			t.Fatalf("messages = %q, want [hello]", res.Messages)
		}
	})

	t.Run("one millisecond more is idle", func(t *testing.T) {
		_, clock, value, first, last, exp := build(t, base+90)
		v := openVerifier(t, exp, openHeaders(value))
		if err := v.Feed(first); err != nil {
			t.Fatalf("Feed: %v", err)
		}
		clock.Set(origin.Add(90_001 * time.Millisecond))
		err := v.Feed(last)
		wantCode(t, err, Idle, 1)
		if !equalStrings(v.Messages(), []string{"hello"}) {
			t.Fatalf("messages = %q, want [hello]", v.Messages())
		}
	})

	t.Run("open followed by silence", func(t *testing.T) {
		b := newStream(t, base)
		clock := &scriptedClock{now: origin}
		value := b.open(base)
		exp := b.expectation(t, base)
		exp.Now = clock.Now
		v := openVerifier(t, exp, openHeaders(value))
		err := v.ObserveLive(90_001 * time.Millisecond)
		wantCode(t, err, Idle, 0)
		if len(v.Messages()) != 0 {
			t.Fatalf("messages = %q, want none", v.Messages())
		}
	})

	t.Run("comment resets nothing", func(t *testing.T) {
		b := newStream(t, base)
		clock := &scriptedClock{now: origin}
		value := b.open(base)
		b.frame(base, "hello")
		body := b.bytes()
		exp := b.expectation(t, base)
		exp.Now = clock.Now
		v := openVerifier(t, exp, openHeaders(value))
		if err := v.Feed(body); err != nil {
			t.Fatalf("Feed: %v", err)
		}
		clock.Set(origin.Add(80 * time.Second))
		if err := v.Feed([]byte(": keep-alive\n")); err != nil {
			t.Fatalf("Feed of a comment: %v", err)
		}
		err := v.ObserveLive(20 * time.Second)
		wantCode(t, err, Idle, 1)
	})

	t.Run("live observation under the threshold", func(t *testing.T) {
		b := newStream(t, base)
		clock := &scriptedClock{now: origin}
		value := b.open(base)
		b.frame(base, "hello")
		body := b.bytes()
		exp := b.expectation(t, base)
		exp.Now = clock.Now
		v := openVerifier(t, exp, openHeaders(value))
		if err := v.Feed(body); err != nil {
			t.Fatalf("Feed: %v", err)
		}
		if err := v.ObserveLive(1 * time.Second); err != nil {
			t.Fatalf("ObserveLive: %v", err)
		}
		if v.Complete() {
			t.Fatal("Complete() = true after a live observation")
		}
		if v.FramesVerified() != 1 {
			t.Fatalf("FramesVerified = %d, want 1", v.FramesVerified())
		}
	})
}

func TestVerifierStdioConsumer(t *testing.T) {
	const now = int64(1_700_000_000)
	b := newStream(t, now)
	value := b.open(now)
	b.frame(now, "a\nb")
	b.frame(now, "")
	body := b.bytes()
	exp := b.expectation(t, now)

	exp.Consumer = ConsumerStdio
	res, err := runStream(t, exp, 200, openHeaders(value), body)
	wantCode(t, err, BadFrame, 1)
	if len(res.Messages) != 0 {
		t.Fatalf("stdio consumer delivered %q", res.Messages)
	}

	exp.Consumer = ConsumerMCP
	res, err = runStream(t, exp, 200, openHeaders(value), body)
	if err != nil {
		t.Fatalf("MCP consumer stream failed: %v", err)
	}
	if !res.Complete {
		t.Fatal("Complete() = false, want true")
	}
	if res.FramesVerified != 2 {
		t.Fatalf("FramesVerified = %d, want 2", res.FramesVerified)
	}
	if !equalStrings(res.Messages, []string{"a\nb"}) {
		t.Fatalf("messages = %q, want [a\\nb]", res.Messages)
	}
}

func TestVerifierNoDeliveryAfterFailure(t *testing.T) {
	const now = int64(1_700_000_000)
	b := newStream(t, now)
	value := b.open(now)
	b.frame(now, "one")
	b.prev = jack.EncodeBase64URL(bytes.Repeat([]byte{7}, 64))
	b.frame(now, "two")
	b.frame(now, "")
	body := b.bytes()
	exp := b.expectation(t, now)

	v := openVerifier(t, exp, openHeaders(value))
	err := v.Feed(body)
	wantCode(t, err, BadSignature, 1)
	if !equalStrings(v.Messages(), []string{"one"}) {
		t.Fatalf("messages = %q, want [one]", v.Messages())
	}
	if term := v.Terminal(); term == nil || term.Code != BadSignature {
		t.Fatalf("Terminal() = %v, want %q", term, BadSignature)
	}
	err2 := v.Feed([]byte("event: jack-end\ndata:\n\n"))
	if err2 != err {
		t.Fatalf("Feed after failure returned %v, want the same error", err2)
	}
	if !equalStrings(v.Messages(), []string{"one"}) {
		t.Fatalf("messages after the failed Feed = %q, want [one]", v.Messages())
	}
}

func TestVerifierChunkingProperty(t *testing.T) {
	const now = int64(1_700_000_000)
	b := newStream(t, now)
	value := b.open(now)
	want := []string{"one", "two\nthree", "four", "five", "six"}
	var boundaries []int
	for _, msg := range want {
		b.frame(now, msg)
		boundaries = append(boundaries, len(b.bytes()))
	}
	b.frame(now, "")
	boundaries = append(boundaries, len(b.bytes()))
	body := b.bytes()
	exp := b.expectation(t, now)
	headers := openHeaders(value)

	check := func(t *testing.T, label string, res Result, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: stream failed: %v", label, err)
		}
		if !res.Complete {
			t.Fatalf("%s: Complete() = false, want true", label)
		}
		if res.FramesVerified != len(want)+1 {
			t.Fatalf("%s: FramesVerified = %d, want %d", label, res.FramesVerified, len(want)+1)
		}
		if !equalStrings(res.Messages, want) {
			t.Fatalf("%s: messages = %q, want %q", label, res.Messages, want)
		}
	}

	res, err := runStream(t, exp, 200, headers, body)
	check(t, "whole", res, err)

	ones := make([]int, len(body))
	for i := range ones {
		ones[i] = 1
	}
	res, err = runStream(t, exp, 200, headers, body, ones...)
	check(t, "byte by byte", res, err)

	var sizes []int
	prev := 0
	for _, off := range boundaries {
		sizes = append(sizes, off-prev)
		prev = off
	}
	res, err = runStream(t, exp, 200, headers, body, sizes...)
	check(t, "frame boundaries", res, err)

	for i := 1; i < len(body); i++ {
		res, err = runStream(t, exp, 200, headers, body, i)
		check(t, "split at "+strconv.Itoa(i), res, err)
	}
}

func TestVerifierEmptyBodyIsTruncated(t *testing.T) {
	const now = int64(1_700_000_000)
	b := newStream(t, now)
	value := b.open(now)
	res, err := runStream(t, b.expectation(t, now), 200, openHeaders(value), nil)
	wantCode(t, err, Truncated, 0)
	if len(res.Messages) != 0 {
		t.Fatalf("messages = %q, want none", res.Messages)
	}
}

func TestVerifierNotAStream(t *testing.T) {
	const now = int64(1_700_000_000)
	b := newStream(t, now)
	value := b.open(now)
	headers := []Header{
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Jack-Auth", Value: value},
	}
	res, err := runStream(t, b.expectation(t, now), 200, headers, []byte(`{"error":{"code":-32000}}`))
	if !errors.Is(err, ErrNotStream) {
		t.Fatalf("error = %v, want ErrNotStream", err)
	}
	var jerr *Error
	if errors.As(err, &jerr) {
		t.Fatalf("error %v is a terminal *Error, want a plain error", err)
	}
	if len(res.Messages) != 0 {
		t.Fatalf("messages = %q, want none", res.Messages)
	}
}
