package webhook

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
)

// SigningKey is an accepted webhook signing key.
type SigningKey = card.Key

// JWK is the public JSON representation of a signing key.
type JWK = card.JWK

// RejectedKey describes a discarded signing key.
type RejectedKey = card.Rejected

// KeySet is a snapshot of the original JWK set and its accepted and rejected keys.
type KeySet = card.KeySet

// KeySource supplies the current signing key snapshot without network I/O.
type KeySource = card.Source

// Static is a fixed KeySource.
type Static = card.Static

// StaticKeySource builds a fixed source from already accepted keys.
func StaticKeySource(keys []SigningKey) KeySource { return card.StaticKeys(keys) }

// CardOptions identifies the MCP server key to exclude from the signing set.
type CardOptions = card.Options

// CardInfo contains the webhook metadata of a selected Server Card remote.
type CardInfo = card.Info

// CardRemote is a selected Server Card remote.
type CardRemote = card.Remote

// CardFetchInput describes a completed Server Card fetch.
type CardFetchInput = card.FetchInput

// CardFetchResult contains the key snapshot, accepted egress ranges, and TTL in seconds.
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

// AcceptKeySet retains the raw signingKeys object and validates its JWK entries.
func AcceptKeySet(signingKeys json.RawMessage, opts CardOptions) KeySet {
	return card.AcceptKeySet(signingKeys, opts)
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

// CrossCheckWebhookKey compares the card's original signingKeys object with
// the jack.server.webhook_key tool result when require is true.
func CrossCheckWebhookKey(cardRaw, toolResult json.RawMessage, require bool) string {
	return card.CrossCheckWebhookKey(cardRaw, toolResult, require)
}

// CardSourceConfig configures live Server Card discovery. An empty CardURL
// defaults to the reserved location returned by DefaultCardURL for MCPURL.
type CardSourceConfig = card.FetcherConfig

// CardSource implements KeySource and can be used as ReceiverConfig.Keys.
// It serves the most recent successful Server Card snapshot.
type CardSource struct{ inner *card.Fetcher }

var _ KeySource = (*CardSource)(nil)

// NewCardSource validates the configuration without fetching the card.
func NewCardSource(cfg CardSourceConfig) (*CardSource, error) {
	inner, err := card.NewFetcher(cfg)
	if err != nil {
		return nil, err
	}
	return &CardSource{inner: inner}, nil
}

// KeySet returns a copy of the current snapshot, even if stale, without network I/O.
func (s *CardSource) KeySet() KeySet { return s.inner.KeySet() }

// TTL returns the remaining cache lifetime, or zero if stale or absent.
func (s *CardSource) TTL() time.Duration { return s.inner.TTL() }

// Refresh fetches the card and atomically replaces the accepted key set on
// success. During rotation both keys are trusted while published together;
// a removed key is dropped on the next successful Refresh. A failed refresh
// leaves the previous snapshot and expiry unchanged.
func (s *CardSource) Refresh(ctx context.Context) *CardError { return s.inner.Refresh(ctx) }
