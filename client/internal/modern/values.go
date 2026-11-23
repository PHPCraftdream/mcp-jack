// Package modern implements the pure client-side helpers of the MCP
// 2026-07-28 modern profile (spec 04 section 6: C1-C6, C9 and C11), plus the
// private-only result cache of C8.
//
// Nothing in this package changes the mcp-jack/v1 wire format: it builds the
// request `_meta` and its mirror headers, validates and projects the
// `x-mcp-header` annotations of a tool or event inputSchema, encodes and
// decodes header values (sections 4), detects the era from a verified
// response and keeps a private cache keyed by the exact request. It is pure
// client-side code with no I/O.
package modern

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// ModernMin is MODERN-MIN, the first modern-era protocol version.
	ModernMin = "2026-07-28"

	// MetaVersionKey is the `_meta` member carrying the protocol version.
	MetaVersionKey = "io.modelcontextprotocol/protocolVersion"

	// MetaClientCapabilitiesKey is the `_meta` member carrying the client
	// capabilities object.
	MetaClientCapabilitiesKey = "io.modelcontextprotocol/clientCapabilities"

	// MetaClientInfoKey is the `_meta` member carrying the optional client
	// implementation info.
	MetaClientInfoKey = "io.modelcontextprotocol/clientInfo"

	// AnnotationKey is the schema keyword that marks a property as mirrored
	// into an Mcp-Param header.
	AnnotationKey = "x-mcp-header"

	// SafeIntMax is 2^53-1, the largest integer a JSON number represents
	// exactly and the bound of the section 4 integer text conversion.
	SafeIntMax = 9007199254740991

	// ProjectionReason is the reason token of C6 when a present argument
	// does not match its annotated type.
	ProjectionReason = "header_projection_invalid_value"
)

// ErrHeaderProjectionInvalidValue is returned by ProjectArguments when a
// present argument does not match the type of its annotation (C6). The
// sentinel is returned unwrapped, so errors.Is always works.
var ErrHeaderProjectionInvalidValue = errors.New("jack client: " + ProjectionReason)

// Sentinel markers of the base64 header-value encoding of section 4. They are
// case-sensitive lowercase and never overlap: the shortest sentinel is
// "=?base64??=" (11 characters).
const (
	sentinelOpen  = "=?base64?"
	sentinelClose = "?="
)

// Header is one HTTP header of a modern-profile request. Names are the
// canonical spellings of section 2; values are already encoded.
type Header struct {
	Name  string
	Value string
}

// NameSource returns the S6 source field of method inside params, and whether
// the method has one at all. Every other method, including events/list,
// server/discover, tools/list and subscriptions/listen, has no Mcp-Name.
func NameSource(method string) (field string, ok bool) {
	switch method {
	case "tools/call", "prompts/get", "events/poll", "events/stream",
		"events/subscribe", "events/unsubscribe":
		return "name", true
	case "resources/read":
		return "uri", true
	}
	return "", false
}

// IsVersion reports whether s is exactly 4DIGIT "-" 2DIGIT "-" 2DIGIT: ten
// ASCII characters and nothing else.
func IsVersion(s string) bool {
	if len(s) != 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 4, 7:
			if s[i] != '-' {
				return false
			}
		default:
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
	}
	return true
}

// CompareVersion compares two versions byte-wise (chronological for
// well-formed values) and returns -1, 0 or 1.
func CompareVersion(a, b string) int { return strings.Compare(a, b) }

// IsFieldValue reports whether s satisfies the RFC 9110 field-value syntax
// after OWS removal: HTAB, SP and VCHAR only (0x09 and 0x20-0x7E).
func IsFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0x09 || (b >= 0x20 && b <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

// IsToken reports whether s is 1*tchar (RFC 9110 section 5.6.2): one or more
// of the special characters, DIGIT and ALPHA.
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b >= '0' && b <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)):
		default:
			return false
		}
	}
	return true
}

// IsSentinel reports whether s has the shape "=?base64?" base64 "?=". The
// markers are case-sensitive lowercase and the value is at least 11
// characters, so the two markers cannot overlap.
func IsSentinel(s string) bool {
	return len(s) >= len(sentinelOpen)+len(sentinelClose) &&
		strings.HasPrefix(s, sentinelOpen) &&
		strings.HasSuffix(s, sentinelClose)
}

// EncodeHeaderValue applies C3: a non-empty text that is already sentinel
// shaped, starts or ends with SP, or contains a byte outside 0x20-0x7E is
// sent as "=?base64?" + standard base64 of its UTF-8 bytes + "?=". Every
// other text - the empty string included - is sent as itself.
func EncodeHeaderValue(text string) string {
	if !needsSentinel(text) {
		return text
	}
	return sentinelOpen + base64.StdEncoding.EncodeToString([]byte(text)) + sentinelClose
}

// needsSentinel implements the C3 test of section 4.
func needsSentinel(text string) bool {
	if text == "" {
		return false
	}
	if IsSentinel(text) {
		return true
	}
	if text[0] == ' ' || text[len(text)-1] == ' ' {
		return true
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			return true
		}
	}
	return false
}

// DecodeHeaderValue applies C4. A value that is not sentinel shaped is plain
// text and decodes to itself. A sentinel's inner text must be canonical
// standard base64 of valid UTF-8; the empty inner text decodes to "". The
// second result is false when the value is not decodable at all.
func DecodeHeaderValue(value string) (string, bool) {
	if !IsSentinel(value) {
		return value, true
	}
	inner := value[len(sentinelOpen) : len(value)-len(sentinelClose)]
	if inner == "" {
		return "", true
	}
	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return "", false
	}
	// Canonicality: decode-then-reencode must reproduce the inner text, so
	// padding, alphabet and the unused trailing bits are all enforced.
	if base64.StdEncoding.EncodeToString(decoded) != inner {
		return "", false
	}
	// utf8.Valid rejects overlong forms, encoded surrogates and truncated
	// sequences (RFC 3629). A leading BOM is kept, never stripped.
	if !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

// TextOfValue converts a decoded JSON value to the header text of section 4
// for typ "string", "integer" or "boolean". The second result is false when
// the value is not representable as that type.
//
// An integer must be a JSON number (float64, json.Number, int or int64) that
// is integral and at most 2^53-1 in absolute value; its text is decimal
// without a plus sign, leading zeros or fraction, -0 becomes "0" and 1e3
// becomes "1000".
func TextOfValue(value any, typ string) (string, bool) {
	switch typ {
	case "string":
		s, ok := value.(string)
		return s, ok
	case "boolean":
		b, ok := value.(bool)
		if !ok {
			return "", false
		}
		return strconv.FormatBool(b), true
	case "integer":
		switch n := value.(type) {
		case json.Number:
			return textOfNumber(n)
		case float64:
			return textOfFloat(n)
		case int:
			return textOfInt(int64(n))
		case int64:
			return textOfInt(n)
		}
	}
	return "", false
}

// textOfNumber parses a JSON number lexeme the way JSON.parse does and
// applies the integer text conversion.
func textOfNumber(n json.Number) (string, bool) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		// The decoder already validated the lexeme, so the only possible
		// error is a range overflow; JSON.parse maps that to ±Infinity,
		// which is not an integer.
		return "", false
	}
	return textOfFloat(f)
}

// textOfFloat applies the integer text conversion to a float64.
func textOfFloat(f float64) (string, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > SafeIntMax {
		return "", false
	}
	if f == 0 {
		// Covers negative zero: the text is a single digit.
		return "0", true
	}
	return strconv.FormatFloat(f, 'f', -1, 64), true
}

// textOfInt applies the integer text conversion to an int64.
func textOfInt(v int64) (string, bool) {
	if v < -SafeIntMax || v > SafeIntMax {
		return "", false
	}
	return strconv.FormatInt(v, 10), true
}
