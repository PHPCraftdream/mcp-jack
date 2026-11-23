// Package wire holds the pure delivery primitives of spec/06-webhooks.md
// sections 1, 2, 3 and 5: the header grammars of R1.4 and R1.5, the
// subscription id grammar of R8.4, the verification nonce of R5.3, the cursor
// bound of R8.9, the closed retry and dedup constants of R1.2, R1.8, R1.10,
// R3.16 and R5.3, and the body parser of R1.3 (message.go).
//
// Everything here mirrors the reference implementation
// (spec/tools/modern/webhooks/ref/receiver.mjs, verification.mjs and
// primitives.mjs) entry for entry, including the check order of the parsed
// body and the exact reason strings "malformed_body" and
// "unknown_envelope_type". No function reads a clock, holds state or performs
// I/O; the caller passes the raw bytes it received (R2.3).
package wire

import (
	"regexp"
	"strconv"
)

// The closed numbers of the profile.
const (
	// MaxBodyBytes is the R1.2 body cap, 256 KiB.
	MaxBodyBytes = 262144
	// DefaultWindowSeconds is the Standard Webhooks freshness window of R3.9.
	DefaultWindowSeconds = 300
	// DefaultJackWindowSeconds is the default w1 window of R4.4.
	DefaultJackWindowSeconds = 30
	// DedupRetentionSeconds is the webhook-id dedup retention of R3.16.
	DedupRetentionSeconds = 1200
	// MaxAttempts is the number of delivery attempts of R1.8.
	MaxAttempts = 4
	// RetryCapSeconds is the retry cap of R1.8 measured from t0.
	RetryCapSeconds = 900
	// NonceTTLSeconds is the challenge nonce lifetime of R5.3.
	NonceTTLSeconds = 600
)

// The grammars of R1.4, R1.5, R5.3 and R8.4.
var (
	webhookIDRE      = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	timestampRE      = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})$`)
	subscriptionIDRE = regexp.MustCompile(`^sub_[0-9a-f]{16}$`)
	nonceRE          = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// ValidWebhookID reports whether v matches the webhook-id grammar of R1.4.
func ValidWebhookID(v string) bool {
	return webhookIDRE.MatchString(v)
}

// ValidTimestamp reports whether v matches the webhook-timestamp grammar of
// R1.5: whole decimal seconds, no sign, no leading zeros, at most 12 digits.
func ValidTimestamp(v string) bool {
	return timestampRE.MatchString(v)
}

// ParseTimestamp parses a value that passed ValidTimestamp into Unix seconds.
// A value outside the grammar reports false, so the result is always in
// 0..999999999999 and never overflows.
func ParseTimestamp(v string) (int64, bool) {
	if !ValidTimestamp(v) {
		return 0, false
	}
	seconds, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return seconds, true
}

// ValidSubscriptionID reports whether v matches the derived subscription id
// grammar of R8.4.
func ValidSubscriptionID(v string) bool {
	return subscriptionIDRE.MatchString(v)
}

// ValidNonce reports whether v is exactly 22 characters of [A-Za-z0-9_-], the
// unpadded base64url form of the 16 CSPRNG bytes of R5.3.
func ValidNonce(v string) bool {
	return nonceRE.MatchString(v)
}

// ValidCursor reports whether v is an acceptable R8.9 cursor: nil is valid, a
// present cursor is 1..512 bytes of printable ASCII 0x21..0x7E.
func ValidCursor(v *string) bool {
	if v == nil {
		return true
	}
	s := *v
	if len(s) < 1 || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
