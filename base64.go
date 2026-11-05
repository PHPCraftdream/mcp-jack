package jack

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ErrBadBase64URL reports a string that is not canonical unpadded base64url
// (spec 01 section 2: reject padding, foreign characters, non-zero unused bits).
var ErrBadBase64URL = errors.New("jack: invalid base64url")

// b64URLAlphabet is the exact RFC 4648 section 5 url-safe alphabet.
const b64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// b64URLAlphabetOK reports whether every byte of s is in the alphabet.
// Needed because base64.RawURLEncoding silently skips \r and \n instead of failing.
func b64URLAlphabetOK(s string) bool {
	for i := 0; i < len(s); i++ {
		if !b64URLAlphabetChar(s[i]) {
			return false
		}
	}
	return true
}

func b64URLAlphabetChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}

// EncodeBase64URL returns the canonical unpadded base64url encoding of b (RFC 4648 section 5, no padding).
func EncodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeBase64URL strictly decodes an unpadded, canonical base64url string (spec 01 section 2).
func DecodeBase64URL(s string) ([]byte, error) {
	if !b64URLAlphabetOK(s) {
		return nil, ErrBadBase64URL
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrBadBase64URL
	}
	// Go's decoder ignores non-zero unused trailing bits (e.g. a final '?');
	// re-encoding must reproduce the input for the encoding to be canonical.
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrBadBase64URL
	}
	return b, nil
}

// DecodeBase64URLFixed is DecodeBase64URL plus a required exact decoded length of size bytes.
func DecodeBase64URLFixed(s string, size int) ([]byte, error) {
	b, err := DecodeBase64URL(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, ErrBadBase64URL
	}
	return b, nil
}

// KeyID returns base64url(SHA-256(publicKey)) (spec 01 section 2).
func KeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return EncodeBase64URL(sum[:])
}

// BodyHash returns base64url(SHA-256(body)) over the exact bytes; an empty body
// is hashed as an empty byte string, so the result is never empty (spec 01
// section 3.1).
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return EncodeBase64URL(sum[:])
}
