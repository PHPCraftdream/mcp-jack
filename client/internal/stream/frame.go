package stream

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Header is one received response header field line.
type Header struct {
	Name  string
	Value string
}

const (
	// OpenDomain is the first line of the 2.5 open signing string.
	OpenDomain = "mcp-jack/stream1/open"
	// FrameDomain is the first line of the 2.15 frame signing string.
	FrameDomain = "mcp-jack/stream1/frame"
	// SignalMethod is the JSON-RPC method of the 2.18 transport signal frame.
	SignalMethod = "notifications/jack/stream_error"
	// DefaultWindow is W of spec 01 section 4 when Expectation.Window is unset.
	DefaultWindow = 30 * time.Second
	// DefaultIdle is streamIdleMs of 4.5 when the caller sets no idle timeout.
	DefaultIdle = 90 * time.Second
	// DefaultFrameMaxBytes is frameMaxBytes of 3.2 when the caller sets none.
	DefaultFrameMaxBytes int64 = 1 << 20
	// MinFrameMaxBytes is the smallest legal frameMaxBytes (3.2).
	MinFrameMaxBytes int64 = 1024
)

var (
	// seqPattern is canonical unsigned decimal of at most 15 digits (2.7).
	seqPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,14})$`)
	// tsPattern is canonical unsigned decimal of at most 12 digits (2.2).
	tsPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,11})$`)
	// paramPattern is one `name=value` pair of a parameter list (2.2, 2.7).
	paramPattern = regexp.MustCompile(`^([a-z]+)=([A-Za-z0-9_-]+)$`)
	// schemePattern matches a scheme that is s or v followed by digits (2.3).
	schemePattern = regexp.MustCompile(`^[sv][0-9]+$`)
	// limitPattern is the canonical decimal limit of a 2.18 signal.
	limitPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
	// signalPrefix precedes the limit of the one signalled code (2.18).
	signalPrefix = []byte(`{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":`)
	// signalSuffix closes the 2.18 signal object.
	signalSuffix = []byte(`}}`)
)

// maxSafeInteger is 2^53-1, the largest integer the JSON number model holds
// exactly (2.7, 2.18).
const maxSafeInteger uint64 = 9007199254740991

// OpenSigningString is the 2.5 open signing string: six lines joined with a
// single LF and no trailing LF.
func OpenSigningString(status int, requestSig, kid string, ts int64, sid string) string {
	return strings.Join([]string{
		OpenDomain,
		strconv.Itoa(status),
		requestSig,
		kid,
		strconv.FormatInt(ts, 10),
		sid,
	}, "\n")
}

// FrameSigningString is the 2.15 frame signing string: six lines joined with a
// single LF and no trailing LF.
func FrameSigningString(sid string, seq uint64, ts int64, prev, hash string) string {
	return strings.Join([]string{
		FrameDomain,
		sid,
		strconv.FormatUint(seq, 10),
		strconv.FormatInt(ts, 10),
		prev,
		hash,
	}, "\n")
}

// DataHash returns base64url(SHA-256(data value)) of 2.15, over the UTF-8 bytes
// of the data value.
func DataHash(data []byte) string { return jack.BodyHash(data) }

// openHeader is a verified-form open header: the values still need the key,
// window, cutoff and signature checks of 4.2 steps 4-7.
type openHeader struct {
	kid string
	ts  int64
	sid string
	sig string
}

// openValue applies the open header checks of 4.2 steps 1-3, in order.
func openValue(values []string) (openHeader, *Error) {
	if len(values) == 0 {
		return openHeader{}, fail(MissingAuth, 0, "response carries no Jack-Auth header")
	}
	if len(values) > 1 {
		return openHeader{}, fail(MalformedAuth, 0, "response carries more than one Jack-Auth header")
	}
	raw := values[0]
	// 2.3: the scheme is read on the raw bytes, before any parameter rule.
	sp := strings.IndexByte(raw, ' ')
	scheme := raw
	if sp >= 0 {
		scheme = raw[:sp]
	}
	if scheme != "s1" {
		if schemePattern.MatchString(scheme) {
			return openHeader{}, fail(UnsupportedVersion, 0, "Jack-Auth scheme is not s1")
		}
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth scheme is not s1")
	}
	if sp < 0 {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth header carries no parameters")
	}
	params, ok := parseParams(raw[sp+1:], []string{"kid", "ts", "sid", "sig"})
	if !ok {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth parameters are malformed")
	}
	tsText := params["ts"]
	if !tsPattern.MatchString(tsText) {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth ts is not canonical decimal")
	}
	if _, err := jack.DecodeBase64URLFixed(params["kid"], 32); err != nil {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth kid is not 32 base64url bytes")
	}
	if _, err := jack.DecodeBase64URLFixed(params["sid"], 16); err != nil {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth sid is not 16 base64url bytes")
	}
	if _, err := jack.DecodeBase64URLFixed(params["sig"], 64); err != nil {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth sig is not 64 base64url bytes")
	}
	ts, err := strconv.ParseUint(tsText, 10, 64)
	if err != nil {
		return openHeader{}, fail(MalformedAuth, 0, "Jack-Auth ts is not a decimal integer")
	}
	return openHeader{kid: params["kid"], ts: int64(ts), sid: params["sid"], sig: params["sig"]}, nil
}

// frame is a frame whose grammar of 2.6-2.13 is verified but whose signature is
// not yet checked.
type frame struct {
	kind string
	data string
	seq  uint64
	ts   int64
	sig  string
}

// parseFrame applies the frame grammar of 2.6-2.13 to one event.
func parseFrame(fields []field) (frame, bool) {
	kind := ""
	haveKind := false
	jackValue := ""
	haveJack := false
	var data []string
	for _, f := range fields {
		// 2.10: every field value, ignored ones included, must be UTF-8.
		value, ok := utf8String(f.value)
		if !ok {
			return frame{}, false
		}
		switch f.name {
		case "event":
			if haveKind || (value != "message" && value != "jack-end") {
				return frame{}, false // 2.8
			}
			kind = value
			haveKind = true
		case "data":
			data = append(data, value)
		case "jack":
			if haveJack {
				return frame{}, false // 2.7: exactly one jack line
			}
			jackValue = value
			haveJack = true
		case "id", "retry":
			return frame{}, false // 2.11
		}
		// 2.13: any other field carries nothing and is ignored.
	}
	if !haveJack {
		return frame{}, false
	}
	params, ok := parseParams(jackValue, []string{"seq", "ts", "sig"})
	if !ok {
		return frame{}, false
	}
	seqText, tsText, sigText := params["seq"], params["ts"], params["sig"]
	if !seqPattern.MatchString(seqText) || !tsPattern.MatchString(tsText) {
		return frame{}, false
	}
	if _, err := jack.DecodeBase64URLFixed(sigText, 64); err != nil {
		return frame{}, false
	}
	value := strings.Join(data, "\n") // 2.10
	if !haveKind {
		kind = "message" // 2.6: the SSE default event type
	}
	// 2.9: the kind is a function of the signed data, so it cannot be forged.
	if kind == "message" {
		if value == "" {
			return frame{}, false
		}
	} else if value != "" {
		return frame{}, false
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || seq > maxSafeInteger {
		return frame{}, false
	}
	ts, err := strconv.ParseUint(tsText, 10, 64)
	if err != nil {
		return frame{}, false
	}
	return frame{kind: kind, data: value, seq: seq, ts: int64(ts), sig: sigText}, true
}

// parseParams parses a `name=value` list joined by single commas, with the name
// set of names exactly once each (2.2, 2.7).
func parseParams(value string, names []string) (map[string]string, bool) {
	out := make(map[string]string, len(names))
	for _, part := range strings.Split(value, ",") {
		m := paramPattern.FindStringSubmatch(part)
		if m == nil {
			return nil, false
		}
		name := m[1]
		known := false
		for _, n := range names {
			if n == name {
				known = true
				break
			}
		}
		if !known {
			return nil, false
		}
		if _, dup := out[name]; dup {
			return nil, false
		}
		out[name] = m[2]
	}
	if len(out) != len(names) {
		return nil, false
	}
	return out, true
}

// utf8String decodes a field value as UTF-8 (2.10), rejecting invalid bytes.
func utf8String(value []byte) (string, bool) {
	if !utf8.Valid(value) {
		return "", false
	}
	return string(value), true
}

// SignalCode reports the signalled code when data is byte-for-byte the 2.18
// transport signal of a signalled code.
func SignalCode(data string) (Code, bool) {
	raw := []byte(data)
	if !bytes.HasPrefix(raw, signalPrefix) || !bytes.HasSuffix(raw, signalSuffix) {
		return "", false
	}
	if len(raw) < len(signalPrefix)+len(signalSuffix) {
		return "", false
	}
	limit := raw[len(signalPrefix) : len(raw)-len(signalSuffix)]
	if !limitPattern.Match(limit) {
		return "", false
	}
	n, err := strconv.ParseUint(string(limit), 10, 64)
	if err != nil || n > maxSafeInteger {
		return "", false
	}
	return FrameTooLarge, true
}

// isEventStream reports whether the answer is an s1 stream: status 200 with an
// exact text/event-stream content type (1.4).
func isEventStream(status int, headers []Header) bool {
	if status != 200 {
		return false
	}
	for _, h := range headers {
		if asciiLower(h.Name) != "content-type" {
			continue
		}
		value := h.Value
		if i := strings.IndexByte(value, ';'); i >= 0 {
			value = value[:i]
		}
		if asciiLower(strings.Trim(value, " \t")) == "text/event-stream" {
			return true
		}
	}
	return false
}

// asciiLower lowercases the ASCII letters of s and leaves every other byte
// unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
