package modern

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// Base64 sentinel markers of spec 04 section 2. The markers are case-sensitive
// lowercase.
const (
	sentinelOpen   = "=?base64?"
	sentinelClose  = "?="
	sentinelMinLen = len(sentinelOpen) + len(sentinelClose)
)

// isVersion reports whether s is 4DIGIT "-" 2DIGIT "-" 2DIGIT: exactly ten
// ASCII characters.
func isVersion(s string) bool {
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

// isModernVersion reports whether s is a well-formed version at or above
// ModernMin. Well-formed versions compare byte-wise, which is chronological.
func isModernVersion(s string) bool {
	return isVersion(s) && s >= ModernMin
}

// isFieldValue reports whether s satisfies the HTTP field-value syntax: HTAB,
// SP or VCHAR only.
func isFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x09 {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// tcharSpecial is the special part of the tchar set of RFC 9110 section 5.6.2.
const tcharSpecial = "!#$%&'*+-.^_`|~"

// isToken reports whether s is 1*tchar.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && !strings.ContainsRune(tcharSpecial, rune(c)) {
			return false
		}
	}
	return true
}

// isSentinel reports whether s begins with the open marker and ends with the
// close marker. An 11-character value has an empty inner text and still
// decodes to the empty string.
func isSentinel(s string) bool {
	return len(s) >= sentinelMinLen && strings.HasPrefix(s, sentinelOpen) && strings.HasSuffix(s, sentinelClose)
}

// encodeHeaderValue implements C3: the sentinel is needed iff text is not empty
// and holds a character outside 0x20-0x7E, starts or ends with SP, or already
// looks like a sentinel.
func encodeHeaderValue(text string) string {
	if text == "" {
		return text
	}
	needs := isSentinel(text) || text[0] == ' ' || text[len(text)-1] == ' ' || hasOutsidePrint(text)
	if !needs {
		return text
	}
	return sentinelOpen + base64.StdEncoding.EncodeToString([]byte(text)) + sentinelClose
}

// hasOutsidePrint reports whether s holds a byte outside 0x20-0x7E.
func hasOutsidePrint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return true
		}
	}
	return false
}

// decodeHeaderValue implements C4. A non-sentinel is plain text and decodes to
// itself. A sentinel's inner text must be canonical standard base64 of valid
// UTF-8, otherwise it is not decodable at all. An empty inner text decodes to
// the empty string.
func decodeHeaderValue(text string) (string, bool) {
	if !isSentinel(text) {
		return text, true
	}
	inner := text[len(sentinelOpen) : len(text)-len(sentinelClose)]
	var decoded []byte
	if inner != "" {
		if len(inner)%4 != 0 {
			return "", false
		}
		data, err := base64.StdEncoding.DecodeString(inner)
		if err != nil {
			return "", false
		}
		// Canonicality: decode-then-encode must reproduce the inner text, which
		// enforces the alphabet and the padding.
		if base64.StdEncoding.EncodeToString(data) != inner {
			return "", false
		}
		decoded = data
	}
	// utf8.Valid rejects an overlong form, an encoded surrogate and a truncated
	// sequence.
	if !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}
