package stream

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// authSigText returns the sig parameter of a Jack-Auth value built for kid, ts
// and sid with the parameter order of 2.2.
func authSigText(t *testing.T, value, kid string, ts int64, sid string) string {
	t.Helper()
	prefix := "s1 kid=" + kid + ",ts=" + strconv.FormatInt(ts, 10) + ",sid=" + sid + ",sig="
	rest, ok := strings.CutPrefix(value, prefix)
	if !ok || rest == "" {
		t.Fatalf("Jack-Auth value %q does not carry %q", value, prefix)
	}
	return rest
}

// TestOpenSessionWritesOpenHeaderAndEndFrame covers 2.1, 2.5 and 2.16: the
// open header signs the 200 status of the opening request, the frame chain
// starts at the open signature and Close writes the one end frame.
func TestOpenSessionWritesOpenHeaderAndEndFrame(t *testing.T) {
	const openTS = int64(1000)
	priv, key := testKey(t, 1)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{3}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: fixedClock(openTS)})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// 2.5: the open value carries the signature of the 200 open signing string.
	openSigning := OpenSigningString(200, requestSig, key.Kid, openTS, sid)
	wantSig := jack.EncodeBase64URL(ed25519.Sign(priv, []byte(openSigning)))
	if got, want := s.HeaderValue(), FormatOpenValue(key.Kid, openTS, sid, wantSig); got != want {
		t.Fatalf("HeaderValue = %q, want %q", got, want)
	}
	openSig := authSigText(t, s.HeaderValue(), key.Kid, openTS, sid)
	raw, err := jack.DecodeBase64URLFixed(openSig, 64)
	if err != nil {
		t.Fatalf("2.5: open sig %q is not canonical 64-byte base64url: %v", openSig, err)
	}
	if !jack.Verify(key.PublicKey, []byte(openSigning), raw) {
		t.Fatalf("2.5: open signature does not verify over %q", openSigning)
	}

	// 2.16: Close writes exactly one frame, the end frame, chained from the open.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	frames := parseBody(t, buf.Bytes())
	if len(frames) != 1 {
		t.Fatalf("2.16: body has %d frames, want 1", len(frames))
	}
	end := frames[0]
	if end.event != EndEvent {
		t.Fatalf("2.16: frame event = %q, want %q", end.event, EndEvent)
	}
	if end.data != "" {
		t.Fatalf("2.16: end frame data = %q, want the empty value", end.data)
	}
	if end.jackSeq != "0" {
		t.Fatalf("2.16: end frame seq = %q, want %q", end.jackSeq, "0")
	}
	if end.jackTS != "1000" {
		t.Fatalf("2.16: end frame ts = %q, want %q", end.jackTS, "1000")
	}
	verifyFrame(t, key, end, sid, openSig)
	if got := s.Frames(); got != 1 {
		t.Fatalf("Frames = %d, want 1", got)
	}

	// 2.16: a second Close writes nothing more.
	written := buf.Len()
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if buf.Len() != written {
		t.Fatalf("second Close wrote %d more bytes", buf.Len()-written)
	}
	if got := s.Frames(); got != 1 {
		t.Fatalf("Frames after the second Close = %d, want 1", got)
	}
}

// TestSessionSignsOneFramePerEventInChain covers 2.6 and 2.15: every completed
// handler event becomes one message frame, each signature chained from the
// previous value.
func TestSessionSignsOneFramePerEventInChain(t *testing.T) {
	clock := &mutableClock{ts: 1000}
	_, key := testKey(t, 2)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{6}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: clock.Now})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	openSig := authSigText(t, s.HeaderValue(), key.Kid, 1000, sid)

	// 2.6: two data events of one chunk are two message frames.
	if _, err := s.Write([]byte("data: a\n\ndata: b\n\n")); err != nil {
		t.Fatalf("Write two events: %v", err)
	}
	frames := parseBody(t, buf.Bytes())
	if len(frames) != 2 {
		t.Fatalf("2.6: body has %d frames, want 2", len(frames))
	}
	if frames[0].event != MessageEvent || frames[1].event != MessageEvent {
		t.Fatalf("2.6: events = %q, %q, want two %q", frames[0].event, frames[1].event, MessageEvent)
	}
	if frames[0].jackSeq != "0" || frames[1].jackSeq != "1" {
		t.Fatalf("2.6: seqs = %q, %q, want 0, 1", frames[0].jackSeq, frames[1].jackSeq)
	}
	if frames[0].jackTS != "1000" || frames[1].jackTS != "1000" {
		t.Fatalf("2.6: ts = %q, %q, want 1000, 1000", frames[0].jackTS, frames[1].jackTS)
	}
	if frames[0].data != "a" || frames[1].data != "b" {
		t.Fatalf("2.6: data = %q, %q, want a, b", frames[0].data, frames[1].data)
	}
	sig0 := verifyFrame(t, key, frames[0], sid, openSig)

	// 2.15: the second frame is chained from the first.
	raw, err := jack.DecodeBase64URLFixed(frames[1].jackSig, 64)
	if err != nil {
		t.Fatalf("2.15: second frame sig %q: %v", frames[1].jackSig, err)
	}
	second := FrameSigningString(sid, 1, 1000, sig0, DataHash([]byte("b")))
	if !jack.Verify(key.PublicKey, []byte(second), raw) {
		t.Fatalf("2.15: second frame is not chained from the first over %q", second)
	}
	sig1 := verifyFrame(t, key, frames[1], sid, sig0)

	// 2.6: a later event takes the clock sample of the write.
	clock.Set(1005)
	if _, err := s.Write([]byte("data: c\n\n")); err != nil {
		t.Fatalf("Write at ts 1005: %v", err)
	}
	frames = parseBody(t, buf.Bytes())
	if len(frames) != 3 {
		t.Fatalf("2.6: body has %d frames, want 3", len(frames))
	}
	if frames[2].jackSeq != "2" || frames[2].jackTS != "1005" {
		t.Fatalf("2.6: third frame seq/ts = %q/%q, want 2/1005", frames[2].jackSeq, frames[2].jackTS)
	}
	sig2 := verifyFrame(t, key, frames[2], sid, sig1)

	// 2.16, 2.15: the end frame continues the chain after the last message.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	frames = parseBody(t, buf.Bytes())
	if len(frames) != 4 {
		t.Fatalf("2.16: body has %d frames, want 4", len(frames))
	}
	end := frames[3]
	if end.event != EndEvent {
		t.Fatalf("2.16: last event = %q, want %q", end.event, EndEvent)
	}
	if end.jackSeq != "3" {
		t.Fatalf("2.16: end frame seq = %q, want %q", end.jackSeq, "3")
	}
	if end.jackTS != "1005" {
		t.Fatalf("2.16: end frame ts = %q, want %q", end.jackTS, "1005")
	}
	verifyFrame(t, key, end, sid, sig2)
}

// TestSessionOversizeEndsWithSignalThenEndFrame covers 2.17 and 3.2: an over
// limit data value becomes the signal frame and the stream ends after it.
func TestSessionOversizeEndsWithSignalThenEndFrame(t *testing.T) {
	const limit = int64(1024)
	_, key := testKey(t, 3)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{7}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{FrameMaxBytes: limit}, Key: key, RequestSig: requestSig, SID: sid, Now: fixedClock(1000)})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// 3.2: one byte over the limit is over the limit.
	if _, err := s.Write([]byte("data: " + strings.Repeat("x", 1025) + "\n\n")); err == nil {
		t.Fatal("2.17: Write of an oversize data value = nil error, want an error")
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) != 2 {
		t.Fatalf("2.17: body has %d frames, want 2", len(frames))
	}
	signal := frames[0]
	if signal.event != MessageEvent {
		t.Fatalf("2.17: signal frame event = %q, want %q", signal.event, MessageEvent)
	}
	if want := SignalValue(SignalFrameTooLarge, limit); signal.data != want {
		t.Fatalf("2.17: signal data = %q, want %q", signal.data, want)
	}
	if signal.jackSeq != "0" {
		t.Fatalf("2.17: signal frame seq = %q, want %q", signal.jackSeq, "0")
	}
	sig := verifyFrame(t, key, signal, sid, authSigText(t, s.HeaderValue(), key.Kid, 1000, sid))

	end := frames[1]
	if end.event != EndEvent {
		t.Fatalf("2.17: second frame event = %q, want %q", end.event, EndEvent)
	}
	if end.jackSeq != "1" {
		t.Fatalf("2.17: end frame seq = %q, want %q", end.jackSeq, "1")
	}
	verifyFrame(t, key, end, sid, sig)

	// 2.17: the stream already ended, so a later Write is refused.
	if _, err := s.Write([]byte("data: later\n\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("2.17: Write after the end frame = %v, want ErrClosed", err)
	}
}

// TestSessionStopsBeforeKeyCutoff covers 5.1: no frame carries a ts at or past
// the successor activation of the key.
func TestSessionStopsBeforeKeyCutoff(t *testing.T) {
	cutoff := int64(1003)
	clock := &mutableClock{ts: 1000}
	_, key := testKey(t, 4)
	key.Cutoff = &cutoff
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{8}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: clock.Now})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// 5.1: one event per second from 1000 to 1006; from the cutoff on the write
	// must fail instead of signing.
	for ts := int64(1000); ts <= 1006; ts++ {
		clock.Set(ts)
		_, err := s.Write([]byte("data: step\n\n"))
		if ts < cutoff {
			if err != nil {
				t.Fatalf("5.1: Write at ts %d = %v, want nil", ts, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("5.1: Write at ts %d = nil error, want an error", ts)
		}
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) < 2 {
		t.Fatalf("5.1: body has %d frames, want messages then an end frame", len(frames))
	}
	end := frames[len(frames)-1]
	if end.event != EndEvent {
		t.Fatalf("5.1: last event = %q, want %q", end.event, EndEvent)
	}
	messages := 0
	for i, frame := range frames {
		ts, err := strconv.ParseInt(frame.jackTS, 10, 64)
		if err != nil {
			t.Fatalf("5.1: frame %d ts %q: %v", i, frame.jackTS, err)
		}
		if ts >= cutoff {
			t.Fatalf("5.1: frame %d carries ts %d, at or past the cutoff %d", i, ts, cutoff)
		}
		if i < len(frames)-1 {
			messages++
		}
	}
	if messages == 0 {
		t.Fatal("5.1: no message frame precedes the end frame")
	}
}

// TestSessionRejectsHandlerDataThatIsNotUTF8 covers 2.10: a data value a
// signed frame cannot carry ends the stream with the end frame.
func TestSessionRejectsHandlerDataThatIsNotUTF8(t *testing.T) {
	_, key := testKey(t, 5)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{9}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: fixedClock(1000)})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if _, err := s.Write([]byte("data: \xff\xfe\n\n")); !errors.Is(err, ErrHandlerData) {
		t.Fatalf("2.10: Write of an invalid UTF-8 data value = %v, want ErrHandlerData", err)
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) != 1 {
		t.Fatalf("2.10: body has %d frames, want the end frame only", len(frames))
	}
	if frames[0].event != EndEvent {
		t.Fatalf("2.10: last event = %q, want %q", frames[0].event, EndEvent)
	}
}

// TestSessionDropsHandlerFieldsAndComments covers 2.11-2.13: id, retry, event
// names, unknown fields and comments never reach the signed body.
func TestSessionDropsHandlerFieldsAndComments(t *testing.T) {
	_, key := testKey(t, 6)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{10}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: fixedClock(1000)})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	handler := "id: 7\nretry: 1000\nevent: message\nx-unknown: field\n: a comment\ndata: kept\n\n"
	if _, err := s.Write([]byte(handler)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "retry") {
		t.Fatalf("2.11: body keeps the retry field: %q", out)
	}
	if strings.Contains(out, "id:") {
		t.Fatalf("2.11: body keeps the id field: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, ":") {
			t.Fatalf("2.12: body keeps the comment line %q", line)
		}
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) != 2 {
		t.Fatalf("2.13: body has %d frames, want one message and the end frame", len(frames))
	}
	if frames[0].event != MessageEvent {
		t.Fatalf("2.13: first event = %q, want %q", frames[0].event, MessageEvent)
	}
	if frames[0].data != "kept" {
		t.Fatalf("2.13: first data = %q, want %q", frames[0].data, "kept")
	}
	if frames[1].event != EndEvent {
		t.Fatalf("2.16: last event = %q, want %q", frames[1].event, EndEvent)
	}
}

// TestOpenSessionRefusesRetiredKeyAndBadInput covers 3.1 and 5.1: the session
// refuses a retired key and every input it cannot sign with.
func TestOpenSessionRefusesRetiredKeyAndBadInput(t *testing.T) {
	_, key := testKey(t, 8)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{12}, 64))

	// 5.1: a key at its successor activation signs nothing.
	cutoff := int64(1000)
	retired := key
	retired.Cutoff = &cutoff
	if _, err := OpenSession(new(bytes.Buffer), SessionConfig{Options: Options{}, Key: retired, RequestSig: requestSig, SID: sid, Now: fixedClock(1000)}); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("5.1: OpenSession with a retired key = %v, want ErrKeyRetired", err)
	}

	cases := []struct {
		name       string
		w          io.Writer
		key        Key
		requestSig string
		sid        string
	}{
		{"nil writer", nil, key, requestSig, sid},
		{"sid that is not a 16-byte base64url value", new(bytes.Buffer), key, requestSig, "not-a-sid"},
		{"empty request signature", new(bytes.Buffer), key, "", sid},
	}
	for _, c := range cases {
		if _, err := OpenSession(c.w, SessionConfig{Options: Options{}, Key: c.key, RequestSig: c.requestSig, SID: c.sid, Now: fixedClock(1000)}); err == nil {
			t.Fatalf("%s: OpenSession = nil error, want an error", c.name)
		}
	}
}

// TestSessionEndFrameWithoutMessages covers 2.16 and 5.1: a stream the handler
// closes without writing an event still carries exactly one frame, the end
// frame, signed from the open value with its own fresh timestamp.
func TestSessionEndFrameWithoutMessages(t *testing.T) {
	clock := &mutableClock{ts: 1000}
	_, key := testKey(t, 10)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{15}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{}, Key: key, RequestSig: requestSig, SID: sid, Now: clock.Now})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	openSig := authSigText(t, s.HeaderValue(), key.Kid, 1000, sid)

	// 2.16: the end frame takes the clock sample of the close.
	clock.Set(1003)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) != 1 {
		t.Fatalf("2.16: body has %d frames, want 1", len(frames))
	}
	end := frames[0]
	if end.event != EndEvent {
		t.Fatalf("2.16: frame event = %q, want %q", end.event, EndEvent)
	}
	if end.data != "" {
		t.Fatalf("2.16: end frame data = %q, want the empty value", end.data)
	}
	if end.jackSeq != "0" {
		t.Fatalf("2.16: end frame seq = %q, want %q", end.jackSeq, "0")
	}
	if end.jackTS != "1003" {
		t.Fatalf("2.16: end frame ts = %q, want %q", end.jackTS, "1003")
	}
	verifyFrame(t, key, end, sid, openSig)
	if got := s.Frames(); got != 1 {
		t.Fatalf("Frames = %d, want 1", got)
	}
}

// TestSessionClosesBeforeLiveCutoff covers 5.1: a successor activation the live
// source reports while the stream is open ends the stream before any frame
// could carry a ts at or past it.
func TestSessionClosesBeforeLiveCutoff(t *testing.T) {
	const cutoff = int64(1003)
	clock := &mutableClock{ts: 1000}
	_, key := testKey(t, 9)
	if key.Cutoff != nil {
		t.Fatal("5.1: the key must carry no successor activation of its own")
	}
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{16}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{
		Options:    Options{},
		Key:        key,
		RequestSig: requestSig,
		SID:        sid,
		Now:        clock.Now,
		Cutoff:     func() (int64, bool) { return cutoff, true },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// 5.1: an event below the guard still signs normally.
	if _, err := s.Write([]byte("data: first\n\n")); err != nil {
		t.Fatalf("5.1: Write at ts 1000 = %v, want nil", err)
	}

	// 5.1: from the guard on the stream ends instead of signing.
	clock.Set(1002)
	if _, err := s.Write([]byte("data: second\n\n")); err == nil {
		t.Fatalf("5.1: Write at ts 1002 = nil error, want an error before the cutoff %d", cutoff)
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) < 2 {
		t.Fatalf("5.1: body has %d frames, want messages then an end frame", len(frames))
	}
	last := frames[len(frames)-1]
	if last.event != EndEvent {
		t.Fatalf("5.1: last event = %q, want %q", last.event, EndEvent)
	}
	messages := 0
	for i, frame := range frames {
		ts, parseErr := strconv.ParseInt(frame.jackTS, 10, 64)
		if parseErr != nil {
			t.Fatalf("5.1: frame %d ts %q: %v", i, frame.jackTS, parseErr)
		}
		if ts >= cutoff {
			t.Fatalf("5.1: frame %d carries ts %d, at or past the cutoff %d", i, ts, cutoff)
		}
		if i < len(frames)-1 {
			messages++
		}
	}
	if messages == 0 {
		t.Fatal("5.1: no message frame precedes the end frame")
	}
	endTS, err := strconv.ParseInt(last.jackTS, 10, 64)
	if err != nil {
		t.Fatalf("5.1: end frame ts %q: %v", last.jackTS, err)
	}
	if endTS < 1000 {
		t.Fatalf("5.1: end frame ts = %d, want at least the open ts 1000", endTS)
	}

	if _, err := s.Write([]byte("data: third\n\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("5.1: Write after the end frame = %v, want ErrClosed", err)
	}
}

// TestSessionOversizeFromSplitterBudget covers 2.17, 2.18 and 3.2: one data
// value split across two writes still trips the incremental event budget of
// the splitter, so the stream ends with the signal frame and the end frame.
func TestSessionOversizeFromSplitterBudget(t *testing.T) {
	const limit = int64(1024)
	_, key := testKey(t, 11)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{17}, 64))

	var buf bytes.Buffer
	s, err := OpenSession(&buf, SessionConfig{Options: Options{FrameMaxBytes: limit}, Key: key, RequestSig: requestSig, SID: sid, Now: fixedClock(1000)})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// 2.17: the data value stays unterminated across the two writes, so only
	// the events under construction can observe the size of the whole value.
	_, errFirst := s.Write([]byte("data: " + strings.Repeat("x", 1500)))
	_, errSecond := s.Write([]byte(strings.Repeat("x", 1500) + "\n\n"))
	if errFirst != nil {
		t.Fatalf("2.17: first chunk Write = %v, want nil", errFirst)
	}
	if errSecond == nil {
		t.Fatal("2.17: second chunk Write = nil error, want an error")
	}

	frames := parseBody(t, buf.Bytes())
	if len(frames) != 2 {
		t.Fatalf("2.17: body has %d frames, want 2", len(frames))
	}
	signal := frames[0]
	if signal.event != MessageEvent {
		t.Fatalf("2.17: signal frame event = %q, want %q", signal.event, MessageEvent)
	}
	if want := SignalValue(SignalFrameTooLarge, limit); signal.data != want {
		t.Fatalf("2.17: signal data = %q, want %q", signal.data, want)
	}
	sig := verifyFrame(t, key, signal, sid, authSigText(t, s.HeaderValue(), key.Kid, 1000, sid))

	end := frames[1]
	if end.event != EndEvent {
		t.Fatalf("2.17: second frame event = %q, want %q", end.event, EndEvent)
	}
	verifyFrame(t, key, end, sid, sig)

	if _, err := s.Write([]byte("data: later\n\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("2.18: Write after the signal frame = %v, want ErrClosed", err)
	}
}

// blockingWriter is a writer that reports the first Write attempt and then
// blocks every Write until release is closed, so a test can hold the wire busy.
type blockingWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	started chan struct{}
	release chan struct{}
}

// Write signals started once and waits for release before taking the bytes.
func (b *blockingWriter) Write(p []byte) (int, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// Bytes returns a copy of the bytes written so far.
func (b *blockingWriter) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// TestSessionTimeoutWhileWriteBlocked covers 3.4 and 3.7: a stream that times
// out while the wire is busy cancels the handler instead of waiting for the
// blocked write.
func TestSessionTimeoutWhileWriteBlocked(t *testing.T) {
	_, key := testKey(t, 12)
	sid := testSID()
	requestSig := jack.EncodeBase64URL(bytes.Repeat([]byte{18}, 64))

	w := &blockingWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	stopped := make(chan struct{})
	var stopOnce sync.Once
	s, err := OpenSession(w, SessionConfig{
		Options:    Options{},
		Key:        key,
		RequestSig: requestSig,
		SID:        sid,
		Now:        fixedClock(1000),
		Stop:       func() { stopOnce.Do(func() { close(stopped) }) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("data: blocked\n\n"))
		writeErr <- err
	}()

	select {
	case <-w.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the blocked Write never reached the writer")
	}

	// 3.4: Timeout must not wait for the blocked write.
	done := make(chan struct{})
	go func() {
		_ = s.Timeout(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("3.4: Timeout waited for the blocked write instead of returning")
	}

	// 3.7: the handler request context is cancelled.
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("3.7: Timeout did not stop the handler request context")
	}

	close(w.release)
	select {
	case <-writeErr:
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked Write did not return after the release")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	body := w.Bytes()
	if !bytes.HasSuffix(body, []byte("\n\n")) {
		t.Fatalf("3.7: body does not end with a blank line: %q", body)
	}
	if !bytes.Contains(body, []byte("event: "+EndEvent)) {
		t.Fatalf("3.7: body carries no %q frame: %q", EndEvent, body)
	}
}
