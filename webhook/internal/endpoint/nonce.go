// Package endpoint implements webhook endpoint verification (spec/06-webhooks.md §5).
package endpoint

import (
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const MaxChallengeBytes = 4096

// Error is a verification refusal with a code and an optional reason.
type Error struct{ Code, Reason string }

func (e *Error) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

// NonceOK checks the spelling of a challenge nonce (R5.3).
func NonceOK(value string) bool { return wire.ValidNonce(value) }

// ChallengeEcho checks the status and JSON echo of a challenge (R5.4).
func ChallengeEcho(status int, bodyText, nonce string) *Error {
	if status < 200 || status > 299 {
		return challengeFailure("status")
	}
	if len(bodyText) > MaxChallengeBytes {
		return challengeFailure("too_large")
	}
	obj, valid := jsonObject(bodyText)
	if !valid {
		return challengeFailure("json")
	}
	if obj == nil {
		return challengeFailure("body")
	}
	echo, ok := jsonString(obj["challenge"])
	if !ok {
		return challengeFailure("missing")
	}
	if !secret.Equal([]byte(echo), []byte(nonce)) {
		return challengeFailure("mismatch")
	}
	return nil
}

// PairKey returns the JSON array key of a pair (R5.3).
func PairKey(pair any) (string, bool) {
	var first, second any
	switch p := pair.(type) {
	case []any:
		if len(p) != 2 {
			return "", false
		}
		first, second = p[0], p[1]
	case map[string]any:
		first, second = p["principal"], p["url"]
	case map[string]string:
		first, second = p["principal"], p["url"]
	default:
		return "", false
	}
	principal, principalOK := first.(string)
	url, urlOK := second.(string)
	if !principalOK || !urlOK || principal == "" || url == "" {
		return "", false
	}
	// Reject Go strings that cannot be represented losslessly in JSON.
	if !utf8.ValidString(principal) || !utf8.ValidString(url) {
		return "", false
	}
	var out strings.Builder
	out.WriteByte('[')
	appendJSONString(&out, principal)
	out.WriteByte(',')
	appendJSONString(&out, url)
	out.WriteByte(']')
	return out.String(), true
}

// appendJSONString uses JSON.stringify's spelling, without Go's extra
// escaping of HTML characters and Unicode line/paragraph separators.
func appendJSONString(out *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < ' ' {
				out.WriteString(`\u00`)
				out.WriteByte(hex[r>>4])
				out.WriteByte(hex[r&15])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// EchoInput describes an attempt and its expected echo. Times are in seconds.
type EchoInput struct {
	Nonce, Expected    string
	IssuedAt, Now, TTL int64
	Consumed           bool
	Pair, ExpectedPair any
}

// AcceptEcho checks the nonce, freshness, single use and pair, in that order.
func AcceptEcho(in EchoInput) *Error {
	if !secret.Equal([]byte(in.Nonce), []byte(in.Expected)) {
		return challengeFailure("mismatch")
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 600
	}
	age := in.Now - in.IssuedAt
	// An age outside the int64 range is either older or younger than any TTL.
	if in.Now >= in.IssuedAt && (age < 0 || age > ttl) ||
		in.Now < in.IssuedAt && age < 0 && age > ttl {
		return challengeFailure("expired")
	}
	if in.Consumed {
		return challengeFailure("reused")
	}
	key, ok := PairKey(in.Pair)
	expected, expectedOK := PairKey(in.ExpectedPair)
	if !ok || !expectedOK || key != expected {
		return challengeFailure("pair")
	}
	return nil
}

func challengeFailure(reason string) *Error {
	return &Error{Code: "challenge_failed", Reason: reason}
}
