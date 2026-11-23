package dsig

import (
	"crypto/sha256"
	"encoding/base64"
	"unicode/utf8"
)

// This file holds the strict codecs of spec/06-webhooks.md R2.1, R2.4 and R4.1
// (mirroring spec/tools/modern/webhooks/ref/primitives.mjs) plus the exact
// whitespace class the reference uses.

// b64StdEncode returns padded standard base64 (RFC 4648 section 4) of b.
func b64StdEncode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// b64StdDecodeStrict decodes canonical padded standard base64 or reports false.
// It refuses, in this order: a length that is not a multiple of 4, any byte
// outside "A-Za-z0-9+/" and '=', padding anywhere but at the end and more than
// two of it, and a string that does not re-encode to itself (non-zero unused
// trailing bits).
func b64StdDecodeStrict(s string) ([]byte, bool) {
	if len(s)%4 != 0 {
		return nil, false
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pad > 0 {
				return nil, false
			}
		case c == '=':
			pad++
			if pad > 2 {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	// R2.1: canonical means re-encoding the decoded bytes reproduces the input.
	if b64StdEncode(decoded) != s {
		return nil, false
	}
	return decoded, true
}

// b64URLEncode returns canonical unpadded base64url (RFC 4648 section 5) of b.
func b64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64URLDecodeStrict decodes canonical unpadded base64url or reports false.
// It refuses, in this order: a length of 4n+1, any byte outside
// "A-Za-z0-9-_", and a string that does not re-encode to itself.
func b64URLDecodeStrict(s string) ([]byte, bool) {
	if len(s)%4 == 1 {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		if !isB64URLChar(s[i]) {
			return nil, false
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if b64URLEncode(decoded) != s {
		return nil, false
	}
	return decoded, true
}

// isB64URLChar reports whether c is in the unpadded base64url alphabet.
func isB64URLChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}

// isASCIIAlnum reports whether s is non-empty and every byte is [A-Za-z0-9].
func isASCIIAlnum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// isURLAlnum reports whether s is non-empty and every byte is [A-Za-z0-9_-].
func isURLAlnum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isB64URLChar(s[i]) {
			return false
		}
	}
	return true
}

// isJSSpace reports whether r belongs to the whitespace class the reference
// matches with the JavaScript regular expression /\s/.
func isJSSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r',
		0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// hasJSSpace reports whether any rune of s is JavaScript whitespace.
func hasJSSpace(s string) bool {
	for _, r := range s {
		if isJSSpace(r) {
			return true
		}
	}
	return false
}

// hasLeadingJSSpace reports whether the first rune of the non-empty s is
// JavaScript whitespace.
func hasLeadingJSSpace(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return isJSSpace(r)
}

// hasTrailingJSSpace reports whether the last rune of the non-empty s is
// JavaScript whitespace.
func hasTrailingJSSpace(s string) bool {
	r, _ := utf8.DecodeLastRuneInString(s)
	return isJSSpace(r)
}

// sha256Sum returns the SHA-256 digest of b.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
