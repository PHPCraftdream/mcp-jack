// Package webhookkey serves the read-only jack.server.webhook_key tool.
// Under R7.6 the tool narrows the Server Card's accepted set and never widens
// it, so callers must configure a subset of the published card keys.
package webhookkey

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"strings"
	"unicode"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

// Key is one accepted webhook signing key. KID is the base64url SHA-256
// digest of the raw key, and PublicKey is the base64url encoding of its 32 bytes.
type Key struct{ KID, PublicKey string }

// Config contains the accepted signing keys and advisory egress ranges.
type Config struct {
	Keys           []Key
	EgressIPRanges []string
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
}

// Provider serves a fixed, validated snapshot of the configured keys and ranges.
type Provider struct {
	keys           []jwk
	egressIPRanges []string
}

// New validates cfg and creates a provider. The keys must already be published
// on the Server Card.
func New(cfg Config) (*Provider, error) {
	if len(cfg.Keys) == 0 || len(cfg.Keys) > 64 {
		return nil, fmt.Errorf("webhookkey: expected 1 to 64 signing keys, got %d", len(cfg.Keys))
	}
	if len(cfg.EgressIPRanges) > 64 {
		return nil, fmt.Errorf("webhookkey: expected at most 64 egress IP ranges, got %d", len(cfg.EgressIPRanges))
	}

	keys := make([]jwk, 0, len(cfg.Keys))
	seen := make(map[string]bool, len(cfg.Keys))
	for i, key := range cfg.Keys {
		raw, err := jack.DecodeBase64URLFixed(key.PublicKey, ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("webhookkey: invalid public key at index %d: %w", i, err)
		}
		if key.KID != jack.KeyID(raw) {
			return nil, fmt.Errorf("webhookkey: KID does not match public key at index %d", i)
		}
		if seen[key.KID] {
			return nil, fmt.Errorf("webhookkey: duplicate KID at index %d", i)
		}
		seen[key.KID] = true
		keys = append(keys, jwk{Kty: "OKP", Crv: "Ed25519", X: key.PublicKey, Kid: key.KID})
	}
	for i, r := range cfg.EgressIPRanges {
		literal, prefix, ok := strings.Cut(r, "/")
		if !ok || literal == "" || prefix == "" || strings.ContainsAny(r, "?#") || strings.Contains(prefix, "/") || strings.IndexFunc(r, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("webhookkey: malformed egress IP range at index %d", i)
		}
	}
	return &Provider{keys: keys, egressIPRanges: append([]string{}, cfg.EgressIPRanges...)}, nil
}

// Call serves the configured keys and ranges to an authenticated caller.
func (p *Provider) Call(c *verify.NativeCall) (verify.NativeResult, *jack.Error) {
	if p == nil || len(p.keys) == 0 || c == nil || c.Tool != verify.ToolWebhookKey || c.Caller == nil {
		return verify.NativeResult{}, &jack.Error{HTTPStatus: 403, Code: jack.CodeOperationDenied, Message: "webhook key request unavailable"}
	}
	return verify.NativeResult{Structured: map[string]any{
		"webhook_key": map[string]any{
			"signing_keys":     map[string]any{"keys": slices.Clone(p.keys)},
			"egress_ip_ranges": slices.Clone(p.egressIPRanges),
		},
	}}, nil
}

var _ verify.NativeTools = (*Provider)(nil)
