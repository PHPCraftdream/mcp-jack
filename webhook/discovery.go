package webhook

import (
	"encoding/json"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
)

// SigningKey is an accepted webhook signing key.
type SigningKey = card.Key

// JWK is the public JSON representation of a signing key.
type JWK = card.JWK

// RejectedKey describes a discarded signing key.
type RejectedKey = card.Rejected

// CardOptions identifies the MCP server key to exclude from the signing set.
type CardOptions = card.Options

// CardInfo contains the webhook metadata of a selected Server Card remote.
type CardInfo = card.Info

// CardRemote is a selected Server Card remote.
type CardRemote = card.Remote

// CardFetchInput describes a completed Server Card fetch.
type CardFetchInput = card.FetchInput

// CardFetchResult describes the keys, ranges, refusals, and TTL from a card fetch.
type CardFetchResult = card.FetchResult

// EgressRange is a validated advisory egress CIDR.
type EgressRange = card.EgressRange

// CardError describes a Server Card fetch refusal.
type CardError = card.FetchError

// ValidateJWK validates a webhook JWK or returns its refusal reason.
func ValidateJWK(raw json.RawMessage) (SigningKey, string) { return card.ValidateJWK(raw) }

// AcceptJWKSet validates the keys, excluding server keys and duplicate IDs.
func AcceptJWKSet(entries []json.RawMessage, opts CardOptions) (accepted []SigningKey, rejected []RejectedKey) {
	return card.AcceptJWKSet(entries, opts)
}

// JWKOf returns the JWK representation of a signing key.
func JWKOf(key SigningKey) JWK { return card.JWKOf(key) }

// SelectRemote selects the Server Card remote for the MCP endpoint.
func SelectRemote(raw json.RawMessage, mcpURL string) (CardRemote, bool) {
	return card.SelectRemote(raw, mcpURL)
}

// WebhookInfo extracts webhook metadata from the selected remote.
func WebhookInfo(raw json.RawMessage, mcpURL string) (CardInfo, string) {
	return card.WebhookInfo(raw, mcpURL)
}

// DefaultCardURL returns the reserved default Server Card URL.
func DefaultCardURL(mcpURL string) (string, bool) { return card.DefaultCardURL(mcpURL) }

// SameOrigin reports whether two valid callback URLs have the same origin.
func SameOrigin(a, b string) bool { return card.SameOrigin(a, b) }

// FetchDecision validates a completed Server Card fetch and extracts its keys.
func FetchDecision(in CardFetchInput) (CardFetchResult, *CardError) { return card.FetchDecision(in) }

// ParseCIDRList partitions advisory egress ranges into accepted and rejected entries.
func ParseCIDRList(values []string) (accepted []EgressRange, rejected []string) {
	return card.ParseCIDRList(values)
}

// CardCacheTTL returns the Server Card cache lifetime in seconds.
func CardCacheTTL(headers map[string]string) int64 { return card.CardCacheTTL(headers) }

// KeyForKID finds an accepted signing key by ID.
func KeyForKID(keys []SigningKey, kid string) (SigningKey, bool) { return card.KeyForKID(keys, kid) }

// CrossCheck checks agreement with the optional jack.server.webhook_key tool.
func CrossCheck(cardKeys []SigningKey, toolResult json.RawMessage, require bool) string {
	return card.CrossCheck(cardKeys, toolResult, require)
}
