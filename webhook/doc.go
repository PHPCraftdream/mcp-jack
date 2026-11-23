// Package webhook implements spec/06-webhooks.md for the mcp-jack 0.2.0
// release line. It provides webhook delivery, reception, endpoint verification,
// Server Card key discovery, and subscription helpers.
//
// The wrapped MCP server owns subscriptions, events, and cursors.
// This package supplies building blocks: the canonical subscription key and
// deterministic ID, TTL grant, active-secret selection with grace, gap and
// terminated envelopes, sender, receiver, endpoint verification, an
// SSRF-hardened delivery path, and Server Card discovery, but deliberately
// provides no subscription store or authenticated subscribe/unsubscribe endpoint.
package webhook

import (
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const (
	// MaxBodyBytes is the delivery request body limit.
	MaxBodyBytes = wire.MaxBodyBytes
	// DefaultWindow is the default Standard Webhooks freshness window in seconds.
	DefaultWindow = wire.DefaultWindowSeconds
	// DefaultJackWindow is the default Jack signature freshness window in seconds.
	DefaultJackWindow = wire.DefaultJackWindowSeconds
	// DedupRetention is the default webhook ID retention in seconds.
	DedupRetention = wire.DedupRetentionSeconds
	// NonceTTL is the challenge nonce lifetime in seconds.
	NonceTTL = wire.NonceTTLSeconds
	// MaxCardBytes is the Server Card body limit.
	MaxCardBytes = card.MaxCardBytes
	// MaxDocBytes is the receiver document body limit.
	MaxDocBytes = endpoint.MaxDocBytes
	// MaxChallengeBytes is the challenge response body limit.
	MaxChallengeBytes = endpoint.MaxChallengeBytes
)
