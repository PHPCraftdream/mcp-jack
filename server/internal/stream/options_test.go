package stream

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// wireFrame is one SSE event of a signed stream body parsed back into its
// fields: the wire shape of 2.6 and 2.16.
type wireFrame struct {
	event     string
	data      string
	jackSeq   string
	jackTS    string
	jackSig   string
	hasJack   bool
	dataLines int
}

// testKey returns a deterministic Ed25519 private key and the Key capability
// that signs with it.
func testKey(t *testing.T, label byte) (ed25519.PrivateKey, Key) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{label}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	return priv, Key{
		Kid:       jack.KeyID(pub),
		PublicKey: pub,
		Sign:      func(m []byte) ([]byte, error) { return ed25519.Sign(priv, m), nil },
	}
}

// testSID returns the fixed sid of 2.4: 16 bytes of 0x42, base64url.
func testSID() string { return jack.EncodeBase64URL(bytes.Repeat([]byte{0x42}, 16)) }

// fixedClock returns a clock that always reports ts.
func fixedClock(ts int64) func() int64 { return func() int64 { return ts } }

// mutableClock is a clock a test can move forward.
type mutableClock struct{ ts int64 }

// Now reports the current sample.
func (c *mutableClock) Now() int64 { return c.ts }

// Set moves the clock to ts.
func (c *mutableClock) Set(ts int64) { c.ts = ts }

// parseBody parses a signed stream body into its frames and fails the test on
// any line that is not part of the wire shape of 2.6 and 2.16.
func parseBody(t *testing.T, body []byte) []wireFrame {
	t.Helper()
	if len(body) == 0 {
		return nil
	}
	pieces := strings.Split(string(body), "\n\n")
	if n := len(pieces); pieces[n-1] == "" {
		pieces = pieces[:n-1]
	}
	frames := make([]wireFrame, 0, len(pieces))
	for i, piece := range pieces {
		if piece == "" {
			t.Fatalf("wire: event %d of %q is empty", i, body)
		}
		var frame wireFrame
		haveEvent := false
		comments := 0
		for _, line := range strings.Split(piece, "\n") {
			switch {
			case strings.HasPrefix(line, ":"):
				comments++
			case strings.HasPrefix(line, "event: "):
				if haveEvent {
					t.Fatalf("wire: event %d has two event lines (%q)", i, line)
				}
				haveEvent = true
				frame.event = strings.TrimPrefix(line, "event: ")
			case line == "data:":
				appendDataLine(&frame, "")
			case strings.HasPrefix(line, "data: "):
				appendDataLine(&frame, strings.TrimPrefix(line, "data: "))
			case strings.HasPrefix(line, "jack: "):
				if frame.hasJack {
					t.Fatalf("wire: event %d has two jack lines (%q)", i, line)
				}
				frame.hasJack = true
				frame.jackSeq, frame.jackTS, frame.jackSig = parseJackLine(t, line, i)
			case strings.Contains(line, ":"):
				// 2.11 and 2.13: an unknown field is dropped by the splitter.
			default:
				t.Fatalf("wire: event %d has malformed line %q", i, line)
			}
		}
		if comments != 0 {
			t.Fatalf("wire: event %d of a signed stream carries %d comment lines", i, comments)
		}
		frames = append(frames, frame)
	}
	return frames
}

// appendDataLine adds one data line to frame, joining the pieces with a single
// LF as the splitter does.
func appendDataLine(frame *wireFrame, value string) {
	if frame.dataLines > 0 {
		frame.data += "\n"
	}
	frame.data += value
	frame.dataLines++
}

// parseJackLine parses the parameters of one jack line of 2.6 and 2.16.
func parseJackLine(t *testing.T, line string, event int) (string, string, string) {
	t.Helper()
	params := strings.TrimPrefix(line, "jack: ")
	seqPart, rest, ok := strings.Cut(params, ",")
	if !ok {
		t.Fatalf("wire: event %d jack line %q has no ts", event, line)
	}
	tsPart, sigPart, ok := strings.Cut(rest, ",")
	if !ok || strings.Contains(sigPart, ",") {
		t.Fatalf("wire: event %d jack line %q does not carry exactly the three parameters", event, line)
	}
	seq, ok := strings.CutPrefix(seqPart, "seq=")
	if !ok {
		t.Fatalf("wire: event %d jack line %q has no seq", event, line)
	}
	ts, ok := strings.CutPrefix(tsPart, "ts=")
	if !ok {
		t.Fatalf("wire: event %d jack line %q has no ts", event, line)
	}
	sig, ok := strings.CutPrefix(sigPart, "sig=")
	if !ok || sig == "" {
		t.Fatalf("wire: event %d jack line %q has no sig", event, line)
	}
	return seq, ts, sig
}

// verifyFrame recomputes the 2.15 signing string of frame from its parsed
// jack parameters and checks the signature, returning the sig text so a test
// can chain it as the next prev.
func verifyFrame(t *testing.T, key Key, frame wireFrame, sid, prev string) string {
	t.Helper()
	if !frame.hasJack {
		t.Fatalf("frame %q has no jack line", frame.event)
	}
	if len(key.PublicKey) != 32 {
		t.Fatalf("key public key must be 32 bytes, got %d", len(key.PublicKey))
	}
	seq, err := strconv.ParseUint(frame.jackSeq, 10, 64)
	if err != nil {
		t.Fatalf("frame seq %q: %v", frame.jackSeq, err)
	}
	ts, err := strconv.ParseInt(frame.jackTS, 10, 64)
	if err != nil {
		t.Fatalf("frame ts %q: %v", frame.jackTS, err)
	}
	raw, err := jack.DecodeBase64URLFixed(frame.jackSig, 64)
	if err != nil {
		t.Fatalf("frame sig %q: %v", frame.jackSig, err)
	}
	signing := FrameSigningString(sid, seq, ts, prev, DataHash([]byte(frame.data)))
	if !jack.Verify(key.PublicKey, []byte(signing), raw) {
		t.Fatalf("frame seq %d does not verify; signing string %q", seq, signing)
	}
	return frame.jackSig
}

// TestOptionsDefaultsAndHeartbeatGrant covers 3.2, 3.3, 3.4 and 3.5: the zero
// value defaults of Options, the clamp of GrantHeartbeat and the settings
// Validate admits.
func TestOptionsDefaultsAndHeartbeatGrant(t *testing.T) {
	window := time.Duration(DefaultWindow/time.Second) * time.Second
	got := Options{}.Normalize(window)
	if got.FrameMaxBytes != DefaultFrameMaxBytes {
		t.Errorf("Normalize FrameMaxBytes = %d, want %d", got.FrameMaxBytes, DefaultFrameMaxBytes)
	}
	if got.MaxConcurrentStreams != DefaultMaxConcurrentStreams {
		t.Errorf("Normalize MaxConcurrentStreams = %d, want %d", got.MaxConcurrentStreams, DefaultMaxConcurrentStreams)
	}
	if got.MaxStreamDuration != DefaultMaxStreamDuration {
		t.Errorf("Normalize MaxStreamDuration = %v, want %v", got.MaxStreamDuration, DefaultMaxStreamDuration)
	}
	if got.Heartbeat != 15*time.Second {
		t.Errorf("Normalize Heartbeat = %v, want %v", got.Heartbeat, 15*time.Second)
	}

	grants := []struct {
		name      string
		requested time.Duration
		window    time.Duration
		want      time.Duration
	}{
		{"larger than the grant is clamped", 60 * time.Second, 30 * time.Second, 15 * time.Second},
		{"within the grant is honoured", 5 * time.Second, 30 * time.Second, 5 * time.Second},
		{"bounded by the window", 2 * time.Second, time.Second, 500 * time.Millisecond},
		{"zero request means the maximum", 0, 0, 15 * time.Second},
	}
	for _, c := range grants {
		if got := GrantHeartbeat(c.requested, c.window); got != c.want {
			t.Errorf("%s: GrantHeartbeat(%v, %v) = %v, want %v", c.name, c.requested, c.window, got, c.want)
		}
	}

	validations := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{"zero value", Options{}, false},
		{"frame floor", Options{FrameMaxBytes: 1024}, false},
		{"below the frame floor", Options{FrameMaxBytes: 1023}, true},
		{"negative concurrency", Options{MaxConcurrentStreams: -1}, true},
		{"negative duration", Options{MaxStreamDuration: -time.Second}, true},
		{"negative heartbeat", Options{Heartbeat: -time.Second}, true},
	}
	for _, c := range validations {
		err := c.opts.Validate()
		if c.wantErr && err == nil {
			t.Errorf("%s: Validate() = nil, want an error", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: Validate() = %v, want nil", c.name, err)
		}
	}
}

// TestAcceptsS1Grammar covers the Jack-Accept grammar of 1.1.
func TestAcceptsS1Grammar(t *testing.T) {
	single := []struct {
		in   string
		want bool
	}{
		{"s1", true},
		{"s1,s2", true},
		{" s1 , s2 ", true},
		{"s2, s1", true},
		{"S1", false},
		{"s1\t", false},
		{"s1,,s2", false},
		{"s1,", false},
		{"", false},
		{" ", false},
		{",s1", false},
		{"s1 s2", false},
		{"s1\n", false},
		{"future-token", false},
	}
	for _, c := range single {
		if got := AcceptsS1([]string{c.in}); got != c.want {
			t.Errorf("AcceptsS1(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	multi := []struct {
		name   string
		values []string
		want   bool
	}{
		{"a second line opts in", []string{"s2", "s1"}, true},
		{"tokens are case sensitive", []string{"s2", "S1"}, false},
		{"a bad line contributes no token", []string{"bad\tline", "s1"}, true},
	}
	for _, c := range multi {
		if got := AcceptsS1(c.values); got != c.want {
			t.Errorf("%s: AcceptsS1(%q) = %v, want %v", c.name, c.values, got, c.want)
		}
	}
}

// TestLimiterBoundsPerIdentity covers the per-identity bound of 3.3.
func TestLimiterBoundsPerIdentity(t *testing.T) {
	limiter := NewLimiter(2)
	release1, ok := limiter.Acquire("alice")
	if !ok {
		t.Fatal("alice: first acquire must succeed")
	}
	release2, ok := limiter.Acquire("alice")
	if !ok {
		t.Fatal("alice: second acquire must succeed")
	}
	if _, ok := limiter.Acquire("alice"); ok {
		t.Fatal("alice: third acquire must fail at a limit of two")
	}
	if got := limiter.Active("alice"); got != 2 {
		t.Fatalf("alice: Active = %d, want 2", got)
	}

	releaseBob, ok := limiter.Acquire("bob")
	if !ok {
		t.Fatal("bob: the limit is per identity")
	}
	if got := limiter.Active("bob"); got != 1 {
		t.Fatalf("bob: Active = %d, want 1", got)
	}
	if got := limiter.Active("alice"); got != 2 {
		t.Fatalf("alice: Active = %d, want 2", got)
	}

	release1()
	release1()
	if got := limiter.Active("alice"); got != 1 {
		t.Fatalf("alice: a double release must free one slot only, Active = %d", got)
	}

	release2()
	if got := limiter.Active("alice"); got != 0 {
		t.Fatalf("alice: Active = %d after releasing all, want 0", got)
	}
	release, ok := limiter.Acquire("alice")
	if !ok {
		t.Fatal("alice: an acquire after releasing all must succeed")
	}
	release()
	releaseBob()

	fallback := NewLimiter(0)
	releases := make([]func(), 0, DefaultMaxConcurrentStreams)
	for i := 0; i < DefaultMaxConcurrentStreams; i++ {
		release, ok := fallback.Acquire("carol")
		if !ok {
			t.Fatalf("NewLimiter(0): acquire %d must succeed", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := fallback.Acquire("carol"); ok {
		t.Fatalf("NewLimiter(0) must allow %d streams, not more", DefaultMaxConcurrentStreams)
	}
	if got := fallback.Active("carol"); got != DefaultMaxConcurrentStreams {
		t.Fatalf("carol: Active = %d, want %d", got, DefaultMaxConcurrentStreams)
	}
	for _, release := range releases {
		release()
	}
	if got := fallback.Active("carol"); got != 0 {
		t.Fatalf("carol: Active = %d after releasing all, want 0", got)
	}
}
