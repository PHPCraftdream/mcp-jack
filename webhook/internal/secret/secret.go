// Package secret implements the Standard Webhooks secret value of
// spec/06-webhooks.md R2.1 and the two strict base64 codecs of R2.1, R2.4 and
// R7.3, mirroring spec/tools/modern/webhooks/ref/primitives.mjs
// (parseWhsec, b64StdDecodeStrict, b64uDecodeStrict) entry for entry: the same
// check order and the same reason strings.
//
// A secret is the literal prefix "whsec_" followed by canonical padded
// standard base64 (RFC 4648 section 4) that decodes to 24..64 bytes inclusive.
// Parse reports the first failing check as one of the reasons "prefix",
// "alphabet", "padding", "canonical" and "length"; an accepted value reports
// "".
//
// DecodeStd and DecodeURL are the strict codecs: they accept only the
// canonical form, so padding placement, the length congruence, foreign
// characters and non-zero unused trailing bits are all refused. Standard
// library only; every function is pure and deterministic.
package secret

import (
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// prefix is the literal secret prefix of R2.1.
const prefix = "whsec_"

// keyMin and keyMax bound the decoded key length of R2.1, inclusive.
const (
	keyMin = 24
	keyMax = 64
)

// The reason strings of R2.1, in reference order.
const (
	reasonPrefix    = "prefix"
	reasonAlphabet  = "alphabet"
	reasonPadding   = "padding"
	reasonCanonical = "canonical"
	reasonLength    = "length"
)

// isStd reports whether c belongs to the standard base64 alphabet or is pad.
func isStd(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=':
		return true
	}
	return false
}

// isURL reports whether c belongs to the unpadded base64url alphabet.
func isURL(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '_':
		return true
	}
	return false
}

// Parse splits a whsec_ value into its key bytes, or reports the first failing
// check of R2.1 as a reason: "prefix", "alphabet", "padding", "canonical" or
// "length".
func Parse(value string) (key []byte, reason string) {
	body, found := strings.CutPrefix(value, prefix)
	if !found {
		return nil, reasonPrefix
	}
	for i := 0; i < len(body); i++ {
		if !isStd(body[i]) {
			return nil, reasonAlphabet
		}
	}
	if len(body)%4 != 0 {
		return nil, reasonPadding
	}
	if eq := strings.IndexByte(body, '='); eq != -1 {
		rest := body[eq:]
		if len(rest) > 2 {
			return nil, reasonPadding
		}
		for i := 0; i < len(rest); i++ {
			if rest[i] != '=' {
				return nil, reasonPadding
			}
		}
	}
	decoded, ok := DecodeStd(body)
	if !ok {
		return nil, reasonCanonical
	}
	if len(decoded) < keyMin || len(decoded) > keyMax {
		return nil, reasonLength
	}
	return decoded, ""
}

// Encode renders key bytes as a secret value: the prefix followed by canonical
// padded standard base64.
func Encode(key []byte) string {
	return prefix + EncodeStd(key)
}

// Equal compares two keys in constant time, checking the length first.
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// DecodeStd decodes canonical padded standard base64: bytes outside
// [A-Za-z0-9+/] and '=', padding anywhere but at the end or more than two of
// it, a length that is not a multiple of 4, and a value that does not
// re-encode to itself are all refused.
func DecodeStd(s string) ([]byte, bool) {
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
	if len(s)%4 != 0 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if base64.StdEncoding.EncodeToString(decoded) != s {
		return nil, false
	}
	return decoded, true
}

// EncodeStd renders b as padded standard base64.
func EncodeStd(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeURL decodes canonical unpadded base64url: bytes outside
// [A-Za-z0-9_-], a length congruent to 1 mod 4 and a value that does not
// re-encode to itself are all refused.
func DecodeURL(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		if !isURL(s[i]) {
			return nil, false
		}
	}
	if len(s)%4 == 1 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != s {
		return nil, false
	}
	return decoded, true
}

// EncodeURL renders b as unpadded base64url.
func EncodeURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
