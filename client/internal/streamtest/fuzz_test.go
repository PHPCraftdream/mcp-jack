package streamtest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	streamimpl "github.com/PHPCraftdream/mcp-jack/client/internal/stream"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
)

const (
	fuzzKid        = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88"
	fuzzSID        = "q9nUNYuH-Xf_cgJBVu4_Dg"
	fuzzRequestSig = "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw"
	fuzzOpenSig    = "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ"
	fuzzPublicKey  = "wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw"
	fuzzNow        = int64(1767225600)
)

func fuzzExpectation(consumer clientstream.Consumer) clientstream.Expectation {
	pub, err := jack.DecodeBase64URLFixed(fuzzPublicKey, 32)
	if err != nil {
		panic(err)
	}
	return clientstream.Expectation{
		Now:           func() time.Time { return time.Unix(fuzzNow, 0) },
		Window:        30 * time.Second,
		FrameMaxBytes: 1024,
		Keys:          map[string]clientstream.Key{fuzzKid: {PublicKey: pub}},
		RequestSig:    fuzzRequestSig,
		Consumer:      consumer,
	}
}

type streamFixture struct {
	Cases []struct {
		ID       string `json:"id"`
		Response struct {
			Stream []string `json:"stream_b64u"`
		} `json:"response"`
	} `json:"cases"`
}

func fuzzFixtureOpenAuth() (string, error) {
	data, err := os.ReadFile("../../../spec/fixtures/modern/stream-vectors.json")
	if err != nil {
		return "", err
	}
	var fixture struct {
		Cases []struct {
			ID       string `json:"id"`
			Response struct {
				Headers [][2]string `json:"headers"`
			} `json:"response"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		return "", err
	}
	for _, tc := range fixture.Cases {
		if tc.ID != "stream-open-duplicate-auth" {
			continue
		}
		for _, header := range tc.Response.Headers {
			if strings.EqualFold(header[0], "Jack-Auth") {
				return header[1], nil
			}
		}
	}
	return "", errors.New("valid Jack-Auth fixture header not found")
}

func fuzzFixtureBody() ([]byte, error) {
	data, err := os.ReadFile("../../../spec/fixtures/modern/stream-vectors.json")
	if err != nil {
		return nil, err
	}
	var fixture streamFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return nil, err
	}
	for _, tc := range fixture.Cases {
		if tc.ID != "stream-ok-single" || len(tc.Response.Stream) != 1 {
			continue
		}
		body, err := base64.RawURLEncoding.DecodeString(tc.Response.Stream[0])
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, errors.New("stream-ok-single fixture not found")
}

// splitSSE independently recognizes events terminated by LF, CR, or CRLF.
// It intentionally keeps only complete events, like the stream protocol.
func splitSSE(body []byte) [][]string {
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	var events [][]string
	var lines []string
	var line strings.Builder
	flushLine := func() {
		lines = append(lines, line.String())
		line.Reset()
	}
	flushEvent := func() {
		if len(lines) > 0 {
			events = append(events, lines)
			lines = nil
		}
	}
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\r':
			flushLine()
			if len(lines) > 0 && lines[len(lines)-1] == "" {
				flushEvent()
			}
			if i+1 < len(body) && body[i+1] == '\n' {
				i++
			}
		case '\n':
			flushLine()
			if len(lines) > 0 && lines[len(lines)-1] == "" {
				flushEvent()
			}
		default:
			line.WriteByte(body[i])
		}
	}
	return events
}

type parsedFrame struct {
	kind string
	data string
	seq  uint64
	ts   int64
	sig  string
}

var (
	seqRE   = regexp.MustCompile(`^(0|[1-9][0-9]{0,14})$`)
	tsRE    = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})$`)
	sigRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
	paramRE = regexp.MustCompile(`^([a-z]+)=([A-Za-z0-9_-]+)$`)
)

func independentFrame(lines []string) (parsedFrame, bool) {
	var f parsedFrame
	var haveEvent, haveData, haveJack bool
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			value = ""
		} else {
			value = strings.TrimPrefix(value, " ")
		}
		if !utf8.ValidString(value) {
			return f, false
		}
		switch name {
		case "event":
			if haveEvent || (value != "message" && value != "jack-end") {
				return f, false
			}
			haveEvent, f.kind = true, value
		case "data":
			if haveData {
				f.data += "\n" + value
			} else {
				haveData, f.data = true, value
			}
		case "jack":
			if haveJack {
				return f, false
			}
			haveJack = true
			params := make(map[string]string, 3)
			for _, part := range strings.Split(value, ",") {
				match := paramRE.FindStringSubmatch(part)
				if match == nil {
					return f, false
				}
				key, paramValue := match[1], match[2]
				switch key {
				case "seq", "ts", "sig":
					if _, exists := params[key]; exists {
						return f, false
					}
					params[key] = paramValue
				default:
					return f, false
				}
			}
			if len(params) != 3 {
				return f, false
			}
			seqText, tsText := params["seq"], params["ts"]
			f.sig = params["sig"]
			if !seqRE.MatchString(seqText) || !tsRE.MatchString(tsText) ||
				!sigRE.MatchString(f.sig) {
				return f, false
			}
			var err error
			f.seq, err = strconv.ParseUint(seqText, 10, 64)
			if err != nil || f.seq > 9007199254740991 {
				return f, false
			}
			parsedTS, err := strconv.ParseUint(tsText, 10, 64)
			if err != nil {
				return f, false
			}
			f.ts = int64(parsedTS)
		case "id", "retry":
			return f, false
		default:
			// Unknown SSE fields have no effect.
		}
	}
	if !haveEvent {
		f.kind = "message"
	}
	return f, haveJack &&
		((f.kind == "jack-end" && (!haveData || f.data == "")) ||
			(f.kind == "message" && haveData && f.data != ""))
}

func checkedFrames(body []byte) ([]parsedFrame, map[uint64]parsedFrame) {
	pub, err := jack.DecodeBase64URLFixed(fuzzPublicKey, ed25519.PublicKeySize)
	if err != nil {
		panic(err)
	}
	prev, expected := fuzzOpenSig, uint64(0)
	var previousTS int64
	haveTS, ended := false, false
	var valid []parsedFrame
	messages := make(map[uint64]parsedFrame)
	for _, lines := range splitSSE(body) {
		if ended {
			break
		}
		f, ok := independentFrame(lines)
		if !ok || len(f.data) > 1024 || f.seq != expected ||
			f.ts < fuzzNow-30 || f.ts > fuzzNow+30 ||
			(haveTS && f.ts < previousTS) {
			break
		}
		sig, err := jack.DecodeBase64URLFixed(f.sig, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(
			pub,
			[]byte(streamimpl.FrameSigningString(
				fuzzSID,
				f.seq,
				f.ts,
				prev,
				streamimpl.DataHash([]byte(f.data)),
			)),
			sig,
		) {
			break
		}
		valid = append(valid, f)
		if f.kind == "message" {
			messages[f.seq] = f
			if code, ok := streamimpl.SignalCode(f.data); ok {
				_ = code
				ended = true
			}
		}
		if f.kind == "jack-end" {
			ended = true
		}
		prev, expected = f.sig, expected+1
		previousTS, haveTS = f.ts, true
	}
	return valid, messages
}

// FuzzSignedStreamFrames compares delivered messages with an independent SSE
// parser and independently verifies the complete-frame signature chain.
func FuzzSignedStreamFrames(f *testing.F) {
	openAuth, err := fuzzFixtureOpenAuth()
	if err != nil {
		f.Fatalf("load stream open auth fixture: %v", err)
	}
	fixture, err := fuzzFixtureBody()
	if err != nil {
		f.Fatalf("load stream fixture: %v", err)
	}
	oversized := append([]byte("data: "), bytes.Repeat([]byte{'x'}, 1025)...)
	oversized = append(oversized, []byte("\njack: seq=0,ts=1767225600,sig="+fuzzOpenSig+"\n\n")...)
	for _, seed := range [][]byte{
		fixture,
		bytes.ReplaceAll(fixture, []byte("\n"), []byte("\r\n")),
		[]byte(""),
		[]byte("data: x\n\n"),
		[]byte("event: message\rdata: x\r\r"),
		[]byte("\xef\xbb\xbfdata: x\n\n"),
		[]byte("data: \x00\n\n"),
		[]byte("data: \xff\n\n"),
		[]byte("event: message\nevent: message\n\n"),
		[]byte("jack: seq=0,ts=1767225600,sig=" + fuzzOpenSig + "\njack: seq=0,ts=1767225600,sig=" + fuzzOpenSig + "\n\n"),
		[]byte("jack: seq=00,ts=1767225600,sig=" + fuzzOpenSig + "\n\n"),
		append(bytes.Repeat([]byte{'x'}, 1100), []byte("\n\n")...),
		oversized,
		[]byte("data: x\r\n\r\n"),
	} {
		if len(seed) <= 1<<20 {
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		valid, signedMessages := checkedFrames(body)
		run := func(c clientstream.Consumer) (clientstream.Result, error) {
			v, err := clientstream.NewVerifier(fuzzExpectation(c))
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Open(200, []clientstream.Header{
				{Name: "Content-Type", Value: "text/event-stream"},
				{Name: "Jack-Auth", Value: openAuth},
			}); err != nil {
				t.Fatalf("fixture open invalid: %v", err)
			}
			if len(body) > 0 {
				_ = v.Feed(body)
			}
			_ = v.Finish()
			return v.Result(), v.Terminal()
		}
		mcp, err := run(clientstream.ConsumerMCP)
		if err != nil {
			var se *clientstream.Error
			if !errors.As(err, &se) || !se.Code.Valid() {
				t.Fatalf("non-typed terminal error: %T %v", err, err)
			}
		}
		if !mcp.Complete && err == nil {
			t.Fatal("incomplete stream without terminal error")
		}
		stdio, serr := run(clientstream.ConsumerStdio)
		if serr != nil {
			var se *clientstream.Error
			if !errors.As(serr, &se) || !se.Code.Valid() {
				t.Fatalf("non-typed stdio terminal error: %T %v", serr, serr)
			}
		}
		stdioFrameCount := len(valid)
		for i, frame := range valid {
			if frame.kind == "message" && strings.ContainsAny(frame.data, "\r\n") {
				stdioFrameCount = i + 1
				break
			}
		}
		if mcp.FramesVerified != len(valid) || stdio.FramesVerified != stdioFrameCount {
			t.Fatalf(
				"verifier accepted %d/%d frames; independent parser verified %d (stdio %d)",
				mcp.FramesVerified,
				stdio.FramesVerified,
				len(valid),
				stdioFrameCount,
			)
		}
		if bytes.Equal(body, fixture) {
			const want = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}`
			if len(mcp.Messages) != 1 || mcp.Messages[0] != want || len(stdio.Messages) != 1 || stdio.Messages[0] != want {
				t.Fatalf("fixture messages mismatch: MCP=%q stdio=%q", mcp.Messages, stdio.Messages)
			}
		}
		messageFrames := make([]parsedFrame, 0, len(signedMessages))
		for _, frame := range signedMessages {
			messageFrames = append(messageFrames, frame)
		}
		sort.Slice(messageFrames, func(i, j int) bool { return messageFrames[i].seq < messageFrames[j].seq })
		lastSeq := uint64(0)
		frameIndex := 0
		for i, msg := range mcp.Messages {
			if msg == "" {
				t.Fatalf("empty delivered message at %d", i)
			}
			if bytes.ContainsAny([]byte(msg), "\r\n") {
				for _, delivered := range stdio.Messages {
					if delivered == msg {
						t.Fatalf("stdio delivered raw-CR/LF message %q", msg)
					}
				}
			}
			for frameIndex < len(messageFrames) && messageFrames[frameIndex].data != msg {
				frameIndex++
			}
			if frameIndex >= len(messageFrames) {
				t.Fatalf("delivered message %d has no verified input frame: %q", i, msg)
			}
			match := messageFrames[frameIndex]
			if i > 0 && match.seq <= lastSeq {
				t.Fatalf("delivered message order is not increasing by accepted seq: %d after %d", match.seq, lastSeq)
			}
			seed := fixtureSeed(t)
			frameSigningString := streamimpl.FrameSigningString(
				fuzzSID,
				match.seq,
				match.ts,
				previousSig(valid, match.seq),
				streamimpl.DataHash([]byte(msg)),
			)
			reSigned := jack.EncodeBase64URL(ed25519.Sign(
				ed25519.NewKeyFromSeed(seed),
				[]byte(frameSigningString),
			))
			if reSigned != match.sig {
				t.Fatalf("delivered message %d does not reproduce its input signature", i)
			}
			lastSeq = match.seq
			frameIndex++
		}
		for i, msg := range stdio.Messages {
			if msg == "" || bytes.ContainsAny([]byte(msg), "\r\n") {
				t.Fatalf("invalid stdio delivered message %d: %q", i, msg)
			}
		}
		if len(stdio.Messages) > len(mcp.Messages) {
			t.Fatalf("stdio delivered %d messages after MCP delivered %d", len(stdio.Messages), len(mcp.Messages))
		}
		for i := 0; i < len(stdio.Messages); i++ {
			if stdio.Messages[i] != mcp.Messages[i] {
				t.Fatalf("consumer message order differs at %d", i)
			}
		}
	})
}

func previousSig(frames []parsedFrame, seq uint64) string {
	if seq == 0 {
		return fuzzOpenSig
	}
	for _, frame := range frames {
		if frame.seq+1 == seq {
			return frame.sig
		}
	}
	return ""
}

func fixtureSeed(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../spec/fixtures/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Keys []struct {
			Name string `json:"name"`
			Seed string `json:"seed_hex"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, key := range fixture.Keys {
		if key.Name == "svc" {
			seed, err := hex.DecodeString(key.Seed)
			if err != nil || len(seed) != ed25519.SeedSize {
				t.Fatalf("invalid svc fixture seed: %v", err)
			}
			return seed
		}
	}
	t.Fatal("svc key fixture not found")
	return nil
}

// FuzzParseOpenStreamAuth checks exact parameters, canonical values, time, and
// reparsability; both canonical and reordered valid signatures are seeds.
func FuzzParseOpenStreamAuth(f *testing.F) {
	fixtureOpen, err := fuzzFixtureOpenAuth()
	if err != nil {
		f.Fatalf("load stream open auth fixture: %v", err)
	}
	reordered, err := reorderedOpenForSeed()
	if err != nil {
		f.Fatalf("build reordered open seed: %v", err)
	}
	for _, auth := range []string{
		"",
		"\r",
		"\n",
		"\x00",
		"\xff",
		"s1 kid=" + fuzzKid + ",ts=9999999999999,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		"s1 kid=" + fuzzKid + ",ts=-1,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		"s1 kid=" + fuzzKid + ",ts=01766725600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		fixtureOpen, reordered,
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + ",nonce=Sw_OOM9qko9FvVsEsziGxg",
		"s2 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		"s1 kid=" + fuzzKid + ",ts=00,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + ",kid=" + fuzzKid,
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + ",kid=" + fuzzKid + ",kid=" + fuzzKid,
		"s1 kid=" + fuzzKid + ",ts=01766725600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig,
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + ",nonce=x",
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + " ",
		"s1 kid=" + fuzzKid + ",ts=1767225600,sid=" + fuzzSID + ",sig=" + fuzzOpenSig + ",kid=" + fuzzKid + "\x00",
	} {
		f.Add(auth)
	}
	f.Fuzz(func(t *testing.T, auth string) {
		if len(auth) > 4096 {
			t.Skip()
		}
		v, err := clientstream.NewVerifier(fuzzExpectation(clientstream.ConsumerMCP))
		if err != nil {
			t.Fatal(err)
		}
		err = v.Open(200, []clientstream.Header{
			{Name: "Content-Type", Value: "text/event-stream"},
			{Name: "Jack-Auth", Value: auth},
		})
		if err != nil {
			var se *clientstream.Error
			if !errors.As(err, &se) || !se.Code.Valid() {
				t.Fatalf("parser returned non-typed error: %T %v", err, err)
			}
			return
		}
		fields := strings.Split(strings.TrimPrefix(auth, "s1 "), ",")
		keys := make(map[string]string, 4)
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if !ok || keys[key] != "" {
				t.Fatalf("accepted malformed or duplicate parameter %q", field)
			}
			keys[key] = value
		}
		if len(keys) != 4 || keys["kid"] != fuzzKid || keys["sid"] != fuzzSID ||
			keys["ts"] != "1767225600" {
			t.Fatalf("accepted auth with wrong parameter set: %q", auth)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(keys["kid"]) ||
			!regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(keys["sid"]) ||
			!sigRE.MatchString(keys["sig"]) || !tsRE.MatchString(keys["ts"]) {
			t.Fatalf("accepted noncanonical value: %q", auth)
		}
		v2, err := clientstream.NewVerifier(fuzzExpectation(clientstream.ConsumerMCP))
		if err != nil {
			t.Fatal(err)
		}
		if err := v2.Open(200, []clientstream.Header{
			{Name: "Content-Type", Value: "text/event-stream"},
			{Name: "Jack-Auth", Value: auth},
		}); err != nil {
			t.Fatalf("accepted auth did not reparse: %v", err)
		}
	})
}

func reorderedOpenForSeed() (string, error) {
	data, err := os.ReadFile("../../../spec/fixtures/keys.json")
	if err != nil {
		return "", err
	}
	var fixture struct {
		Keys []struct {
			Name string `json:"name"`
			Seed string `json:"seed_hex"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		return "", err
	}
	for _, key := range fixture.Keys {
		if key.Name != "svc" {
			continue
		}
		seed, err := hex.DecodeString(key.Seed)
		if err != nil {
			return "", fmt.Errorf("decode svc fixture seed: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return "", fmt.Errorf("svc fixture seed length = %d", len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		sig := jack.EncodeBase64URL(ed25519.Sign(priv, []byte(streamimpl.OpenSigningString(200, fuzzRequestSig, fuzzKid, fuzzNow, fuzzSID))))
		return "s1 ts=1767225600,sig=" + sig + ",sid=" + fuzzSID + ",kid=" + fuzzKid, nil
	}
	return "", errors.New("svc key fixture not found")
}
