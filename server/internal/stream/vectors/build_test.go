package streamvectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
	stream "github.com/PHPCraftdream/mcp-jack/server/internal/stream"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
)

// maxSafeInteger is the largest limit of 2.18 the reference accepts.
const maxSafeInteger = 9007199254740991

// clock48 is the mutable Unix-second clock the session samples: the runner
// moves it to the ts of the frame the session is about to sign.
type clock48 struct{ ts int64 }

// Now returns the clock sample in Unix seconds.
func (c *clock48) Now() int64 { return c.ts }

// Set moves the clock to ts.
func (c *clock48) Set(ts int64) { c.ts = ts }

// buildCorpus is spec/fixtures/modern/stream-build-vectors.json.
type buildCorpus struct {
	Note  string      `json:"note"`
	Cases []buildCase `json:"cases"`
}

// buildCase is one server-signing known-answer vector.
type buildCase struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Input       buildInput `json:"input"`
	Expect      struct {
		JackAuth          string `json:"jack_auth"`
		OpenSigningString string `json:"open_signing_string"`
		Frames            []struct {
			Seq           uint64 `json:"seq"`
			TS            int64  `json:"ts"`
			Prev          string `json:"prev"`
			DataHash      string `json:"data_hash"`
			SigningString string `json:"signing_string"`
			Sig           string `json:"sig"`
		} `json:"frames"`
		StreamB64U string `json:"stream_b64u"`
	} `json:"expect"`
}

// buildInput is the explicit input of one build.
type buildInput struct {
	RequestSig string `json:"request_sig"`
	Kid        string `json:"kid"`
	Status     int    `json:"status"`
	Sid        string `json:"sid"`
	OpenTS     int64  `json:"open_ts"`
	Frames     []struct {
		Seq  uint64 `json:"seq"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	} `json:"frames"`
}

// TestStreamBuildVectors drives every build vector through the production
// session, compares the whole known answer byte for byte, and verifies the
// produced stream through the public client verifier as the positive control
// of section 9.
func TestStreamBuildVectors(t *testing.T) {
	var corpus buildCorpus
	if err := json.Unmarshal(fixtureFile(t, "stream-build-vectors.json"), &corpus); err != nil {
		t.Fatalf("decode stream-build-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 8 {
		t.Fatalf("stream-build-vectors.json: want 8 cases, got %d", len(corpus.Cases))
	}
	priv := testfixture.PrivateKey(t, "svc")
	pub := priv.Public().(ed25519.PublicKey)
	pass := 0
	for _, c := range corpus.Cases {
		if kid := jack.KeyID(pub); kid != c.Input.Kid {
			t.Fatalf("case %s: fixture key id %s, want %s", c.ID, kid, c.Input.Kid)
		}
		// The reference signs one frame per input frame, so the two lists line
		// up index for index and the input carries every data value.
		if len(c.Input.Frames) != len(c.Expect.Frames) {
			t.Fatalf("case %s: %d input frames, %d expected frames", c.ID, len(c.Input.Frames), len(c.Expect.Frames))
		}
		// 2.5: the session must sign the vector's open signing string.
		openSigning := stream.OpenSigningString(c.Input.Status, c.Input.RequestSig, c.Input.Kid, c.Input.OpenTS, c.Input.Sid)
		if openSigning != c.Expect.OpenSigningString {
			t.Fatalf("case %s: open_signing_string\ngot:  %q\nwant: %q", c.ID, openSigning, c.Expect.OpenSigningString)
		}
		// The oversize case is signed against the 1024-byte cap it reports.
		options := stream.Options{}
		if c.ID == "build-oversize-error-frame" {
			options.FrameMaxBytes = 1024
		}
		var buf bytes.Buffer
		clock := &clock48{ts: c.Input.OpenTS}
		session, err := stream.OpenSession(&buf, stream.SessionConfig{
			Options:    options,
			Key:        stream.Key{Kid: c.Input.Kid, PublicKey: pub, Sign: func(m []byte) ([]byte, error) { return ed25519.Sign(priv, m), nil }},
			RequestSig: c.Input.RequestSig,
			SID:        c.Input.Sid,
			Now:        clock.Now,
		})
		if err != nil {
			t.Fatalf("case %s: OpenSession: %v", c.ID, err)
		}
		// Drive the production session: one handler event per non-empty input
		// frame, written at that frame's ts (2.6, 2.9), and the end frame when
		// the last input frame carries the empty data value (2.16). A vector
		// without frames expects an empty body, so the session is left open.
		for i, f := range c.Input.Frames {
			// Pin the session clock to every vector input, including end frames.
			// In particular, long-ts vectors cross the verifier window, and Close
			// must sign the end at the input's timestamp rather than wall time.
			clock.Set(f.TS)
			if f.Data == "" {
				if i == len(c.Input.Frames)-1 {
					if err := session.Close(); err != nil {
						t.Fatalf("case %s: Close: %v", c.ID, err)
					}
				}
				continue
			}
			if _, err := session.Write(sseEvent(f.Data)); err != nil {
				t.Fatalf("case %s: input frame %d: Write: %v", c.ID, i, err)
			}
		}
		if got := session.HeaderValue(); got != c.Expect.JackAuth {
			t.Fatalf("case %s: jack_auth\ngot:  %s\nwant: %s", c.ID, got, c.Expect.JackAuth)
		}
		body := buf.Bytes()
		if got := base64.RawURLEncoding.EncodeToString(body); got != c.Expect.StreamB64U {
			t.Fatalf("case %s: stream_b64u\ngot:  %s\nwant: %s", c.ID, got, c.Expect.StreamB64U)
		}
		checkBuildFrames(t, c, pub, body)

		// Positive control, mirroring buildCaseChecks of
		// spec/tools/modern/streams/vectors/vectors-build.mjs.
		now := c.Input.OpenTS
		frameNows := make([]int64, 0, len(c.Input.Frames))
		for _, f := range c.Input.Frames {
			frameNows = append(frameNows, f.TS)
		}
		// The open header is checked against the same clock, so a stream
		// longer than one window keeps its open ts as the clock.
		if len(frameNows) > 0 {
			if last := frameNows[len(frameNows)-1]; abs64(last-c.Input.OpenTS) <= 30 {
				now = last
			}
		}
		exp := clientstream.Expectation{
			Now:           func() time.Time { return time.Unix(now, 0) },
			Window:        30 * time.Second,
			Keys:          map[string]clientstream.Key{c.Input.Kid: {PublicKey: pub}},
			RequestSig:    c.Input.RequestSig,
			FrameMaxBytes: options.FrameMaxBytes,
		}
		if len(frameNows) > 0 {
			samples := frameNows
			exp.FrameNow = func(index int) time.Time {
				return time.Unix(samples[min(index, len(samples)-1)], 0)
			}
		}
		headers := []clientstream.Header{
			{Name: "Content-Type", Value: "text/event-stream"},
			{Name: "Jack-Auth", Value: session.HeaderValue()},
		}
		wantMessages, wantCode, wantFrames := buildTerminal(c)
		res, verifyErr := clientstream.Verify(exp, 200, headers, [][]byte{body})
		if !slices.Equal(res.Messages, wantMessages) {
			t.Fatalf("case %s: messages differ\ngot:  %q\nwant: %q", c.ID, res.Messages, wantMessages)
		}
		if wantCode == "" {
			if verifyErr != nil {
				t.Fatalf("case %s: want ok terminal, got %v", c.ID, verifyErr)
			}
			if !res.Complete {
				t.Fatalf("case %s: ok terminal without a verified end frame", c.ID)
			}
		} else {
			var terminal *clientstream.Error
			if !errors.As(verifyErr, &terminal) {
				t.Fatalf("case %s: want terminal %s after %d frames, got %v", c.ID, wantCode, wantFrames, verifyErr)
			}
			if string(terminal.Code) != wantCode {
				t.Fatalf("case %s: terminal code %s, want %s", c.ID, terminal.Code, wantCode)
			}
			if terminal.FramesVerified != wantFrames {
				t.Fatalf("case %s: terminal frames_verified %d, want %d", c.ID, terminal.FramesVerified, wantFrames)
			}
			if res.FramesVerified != wantFrames {
				t.Fatalf("case %s: verifier frames_verified %d, want %d", c.ID, res.FramesVerified, wantFrames)
			}
		}
		pass++
	}
	summary(t, "stream-build", pass)
}

// sseEvent renders the handler bytes of one data value: the message event name
// (2.6), one data line per LF-separated piece with a bare `data:` for an empty
// piece (2.10), and the terminating blank line.
func sseEvent(data string) []byte {
	var b strings.Builder
	b.WriteString("event: " + stream.MessageEvent + "\n")
	for _, piece := range strings.Split(data, "\n") {
		if piece == "" {
			b.WriteString("data:\n")
			continue
		}
		b.WriteString("data: ")
		b.WriteString(piece)
		b.WriteByte('\n')
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// checkBuildFrames proves the body is exactly the vector's frame chain: every
// expected frame checks itself out with the exported helpers, and the frames
// encoded from the vector concatenate to the body bytes in order.
func checkBuildFrames(t *testing.T, c buildCase, pub ed25519.PublicKey, body []byte) {
	t.Helper()
	prev := openSigOf(t, c.Expect.JackAuth)
	var encoded []byte
	for i, want := range c.Expect.Frames {
		input := c.Input.Frames[i]
		if want.Seq != input.Seq || want.TS != input.TS {
			t.Fatalf("case %s: frame %d: vector seq/ts %d/%d, input %d/%d",
				c.ID, i, want.Seq, want.TS, input.Seq, input.TS)
		}
		if want.Prev != prev {
			t.Fatalf("case %s: frame %d: prev\ngot:  %s\nwant: %s", c.ID, i, want.Prev, prev)
		}
		hash := stream.DataHash([]byte(input.Data))
		if want.DataHash != hash {
			t.Fatalf("case %s: frame %d: data_hash\ngot:  %s\nwant: %s", c.ID, i, want.DataHash, hash)
		}
		signing := stream.FrameSigningString(c.Input.Sid, want.Seq, want.TS, prev, hash)
		if want.SigningString != signing {
			t.Fatalf("case %s: frame %d: signing_string\ngot:  %q\nwant: %q", c.ID, i, want.SigningString, signing)
		}
		if !jack.Verify(pub, []byte(signing), b64u(t, want.Sig)) {
			t.Fatalf("case %s: frame %d: sig does not verify under the fixture key", c.ID, i)
		}
		kind := stream.MessageEvent
		if input.Data == "" {
			kind = stream.EndEvent
		}
		encoded = append(encoded, stream.EncodeFrame(kind, input.Data, want.Seq, want.TS, want.Sig)...)
		prev = want.Sig
	}
	if !bytes.Equal(encoded, body) {
		t.Fatalf("case %s: frame chain differs from the body\ngot:  %s\nwant: %s", c.ID,
			base64.RawURLEncoding.EncodeToString(body), base64.RawURLEncoding.EncodeToString(encoded))
	}
}

// openSigOf returns the sig parameter of the vector's 2.1 Jack-Auth value.
func openSigOf(t *testing.T, jackAuth string) string {
	t.Helper()
	const marker = ",sig="
	i := strings.LastIndex(jackAuth, marker)
	if i < 0 {
		t.Fatalf("jack_auth %q carries no sig parameter", jackAuth)
	}
	return jackAuth[i+len(marker):]
}

// buildTerminal derives the expected client outcome from the input frames: a
// 2.18 transport signal ends the stream undelivered (4.3 step 6) and counts as
// verified, an empty-data frame is the end frame of 2.9, and a body without one
// ends unterminated (4.4).
func buildTerminal(c buildCase) (messages []string, code string, frames int) {
	messages = make([]string, 0, len(c.Input.Frames))
	ended := false
	for i, f := range c.Input.Frames {
		if signal := signalCode(f.Data); signal != "" {
			return messages, signal, i + 1
		}
		if f.Data == "" {
			ended = true
			continue
		}
		messages = append(messages, f.Data)
	}
	if ended {
		return messages, "", 0
	}
	return messages, "stream_truncated", 0
}

// signalCode returns the 2.18 code of data when data is exactly the transport
// signal object, and "" for an ordinary message. The object is byte-exact: any
// extra member, other member order, or non-canonical limit keeps it
// deliverable, so the canonical rendering must reproduce data.
func signalCode(data string) string {
	var obj struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Code  string          `json:"code"`
			Limit json.RawMessage `json:"limit"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return ""
	}
	if obj.JSONRPC != "2.0" || obj.Method != stream.SignalMethod || obj.Params.Code != stream.SignalFrameTooLarge {
		return ""
	}
	limit, err := strconv.ParseUint(string(obj.Params.Limit), 10, 64)
	if err != nil || limit > maxSafeInteger || strconv.FormatUint(limit, 10) != string(obj.Params.Limit) {
		return ""
	}
	if stream.SignalValue(obj.Params.Code, int64(limit)) != data {
		return ""
	}
	return obj.Params.Code
}

// abs64 is the absolute value of v.
func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
