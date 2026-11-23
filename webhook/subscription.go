package webhook

import (
	"encoding/json"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/subscription"
)

// Subscription is the canonical subscription key and derived ID.
type Subscription = subscription.Key

// SubscriptionError describes an invalid subscription argument or callback URL.
type SubscriptionError = subscription.KeyError

// TTLValue represents a requested subscription lifetime.
type TTLValue = subscription.TTLValue

// Grant holds the authoritative subscription lifetime and refresh deadline.
type Grant = subscription.Grant

// ActiveSecret is a current or still-active previous subscription secret.
type ActiveSecret = subscription.ActiveSecret

// EnvelopeError describes a refusal to construct a control envelope.
type EnvelopeError = subscription.EnvelopeError

// SubscriptionKey derives the canonical key and ID for a subscription.
func SubscriptionKey(principal, url, name string, arguments any) (Subscription, *SubscriptionError) {
	return subscription.SubscriptionKey(principal, url, name, arguments)
}

// TTLGrant computes the TTL grant at the given Unix second.
func TTLGrant(ttl TTLValue, now int64) (Grant, *SubscriptionError) {
	return subscription.TTLGrant(ttl, now)
}

// ActiveSecrets returns the signing secrets in current-first order.
func ActiveSecrets(current, previous []byte, hasPrevious bool, graceEndsAt, now int64) []ActiveSecret {
	return subscription.ActiveSecrets(current, previous, hasPrevious, graceEndsAt, now)
}

// GapEnvelope renders a gap control envelope.
func GapEnvelope(cursor string) []byte { return subscription.GapEnvelope(cursor) }

// TerminatedEnvelope renders a termination envelope with optional JSON object data.
func TerminatedEnvelope(code int64, message string, data json.RawMessage) ([]byte, *EnvelopeError) {
	return subscription.TerminatedEnvelope(code, message, data)
}

// CursorOK reports whether v is a valid opaque cursor or nil.
func CursorOK(v *string) bool { return subscription.CursorOK(v) }
