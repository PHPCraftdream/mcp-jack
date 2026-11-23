package card

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Key is an accepted signing key. X and PublicKey encode the same bytes as Raw.
type Key struct {
	KID, KTY, CRV, X, PublicKey string
	Raw                         []byte
}

// JWK is the public representation of a webhook signing key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
}

// JWKOf returns the JWK to publish for an Ed25519 signing key.
func JWKOf(key Key) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: key.PublicKey, Kid: key.KID}
}

// Rejected describes a discarded entry. KID is nil if it was not a JSON string.
type Rejected struct {
	KID    *string
	Reason string
}

// Options identifies the MCP server key, which is not a webhook signing key.
type Options struct {
	MCPServerKID       string
	MCPServerPublicKey string
}

// ValidateJWK returns the validated key or the first R7.3 rejection reason.
func ValidateJWK(raw json.RawMessage) (Key, string) {
	return validateJWK(jsonObject(raw))
}

func validateJWK(jwk map[string]json.RawMessage) (Key, string) {
	if kty, _ := jsonString(jwk["kty"]); kty != "OKP" {
		return Key{}, "kty"
	}
	if crv, _ := jsonString(jwk["crv"]); crv != "Ed25519" {
		return Key{}, "crv"
	}
	x, ok := jsonString(jwk["x"])
	if !ok {
		return Key{}, "x_encoding"
	}
	pub, err := jack.DecodeBase64URL(x)
	if err != nil {
		return Key{}, "x_encoding"
	}
	if len(pub) != ed25519.PublicKeySize {
		return Key{}, "x_length"
	}
	if jack.ValidatePublicKey(pub) != nil {
		return Key{}, "x_key"
	}
	kid, _ := jsonString(jwk["kid"])
	if kid == "" {
		return Key{}, "kid_missing"
	}
	if kid != jack.KeyID(pub) {
		return Key{}, "kid_mismatch"
	}
	if raw, present := jwk["alg"]; present {
		if alg, _ := jsonString(raw); alg != "EdDSA" {
			return Key{}, "alg"
		}
	}
	if raw, present := jwk["use"]; present {
		if use, _ := jsonString(raw); use != "sig" {
			return Key{}, "use"
		}
	}
	return Key{KID: kid, KTY: "OKP", CRV: "Ed25519", X: x, PublicKey: x, Raw: pub}, ""
}

// KeySet is one snapshot of a published webhook key set: the raw JWKs as
// published, the accepted keys and the rejected entries.
type KeySet struct {
	Raw      json.RawMessage
	Accepted []Key
	Rejected []Rejected
}

// Source yields the current key set without performing network I/O.
type Source interface {
	KeySet() KeySet
}

// Static serves a fixed key set.
type Static struct{ Set KeySet }

// KeySet returns an independent copy of the fixed snapshot.
func (s Static) KeySet() KeySet { return s.Set.clone() }

// StaticKeys builds a snapshot from already accepted keys.
func StaticKeys(keys []Key) Static {
	jwks := make([]JWK, len(keys))
	for i, key := range keys {
		jwks[i] = JWKOf(key)
	}
	raw, _ := json.Marshal(map[string][]JWK{"keys": jwks})
	return Static{Set: (KeySet{Raw: raw, Accepted: keys}).clone()}
}

func (s KeySet) clone() KeySet {
	s.Raw = slices.Clone(s.Raw)
	s.Accepted = slices.Clone(s.Accepted)
	for i := range s.Accepted {
		s.Accepted[i].Raw = slices.Clone(s.Accepted[i].Raw)
	}
	s.Rejected = slices.Clone(s.Rejected)
	for i := range s.Rejected {
		if kid := s.Rejected[i].KID; kid != nil {
			value := *kid
			s.Rejected[i].KID = &value
		}
	}
	return s
}

// AcceptKeySet retains the original signingKeys object and applies R7.3 to
// its entries for key lookup.
func AcceptKeySet(signingKeys json.RawMessage, opts Options) KeySet {
	accepted, rejected := AcceptJWKSet(keySetEntries(signingKeys), opts)
	return KeySet{Raw: slices.Clone(signingKeys), Accepted: accepted, Rejected: rejected}
}

func keySetEntries(raw json.RawMessage) []json.RawMessage {
	return jsonArray(jsonObject(raw)["keys"])
}

// AcceptJWKSet reports invalid entries first, then server keys, then all
// surviving duplicates. Each group and the accepted keys retain input order.
func AcceptJWKSet(entries []json.RawMessage, opts Options) (accepted []Key, rejected []Rejected) {
	var valid []Key
	for _, raw := range entries {
		jwk := jsonObject(raw)
		key, reason := validateJWK(jwk)
		if reason == "" {
			valid = append(valid, key)
			continue
		}
		var kid *string
		if text, ok := jsonString(jwk["kid"]); ok {
			kid = &text
		}
		rejected = append(rejected, Rejected{KID: kid, Reason: reason})
	}

	surviving := valid[:0]
	counts := make(map[string]int)
	for _, key := range valid {
		if (opts.MCPServerKID != "" && key.KID == opts.MCPServerKID) ||
			(opts.MCPServerPublicKey != "" && key.PublicKey == opts.MCPServerPublicKey) {
			kid := key.KID
			rejected = append(rejected, Rejected{KID: &kid, Reason: "mcp_server_key"})
			continue
		}
		surviving = append(surviving, key)
		counts[key.KID]++
	}
	for _, key := range surviving {
		if counts[key.KID] > 1 {
			kid := key.KID
			rejected = append(rejected, Rejected{KID: &kid, Reason: "duplicate_kid"})
		} else {
			accepted = append(accepted, key)
		}
	}
	return accepted, rejected
}

// KeyForKID finds the first key with the given non-empty kid.
func KeyForKID(keys []Key, kid string) (Key, bool) {
	if kid != "" {
		for _, key := range keys {
			if key.KID == kid {
				return key, true
			}
		}
	}
	return Key{}, false
}

// CrossCheckWebhookKey implements R7.6 against the card's original JWKs, not
// its accepted subset. Any invalid record on either side causes a mismatch.
func CrossCheckWebhookKey(cardRaw, toolResult json.RawMessage, require bool) string {
	if !require {
		return ""
	}
	webhookKey := jsonObject(jsonObject(toolResult)["webhook_key"])
	toolEntries := keySetEntries(webhookKey["signing_keys"])
	if toolEntries == nil {
		return "webhook_key_missing"
	}
	left, leftOK := canonicalJWKs(keySetEntries(cardRaw))
	right, rightOK := canonicalJWKs(toolEntries)
	// Equal sorted records have equal canonical JSON, including multiplicity.
	if !leftOK || !rightOK || !slices.Equal(left, right) {
		return "webhook_key_mismatch"
	}
	return ""
}

func canonicalJWKs(entries []json.RawMessage) ([]JWK, bool) {
	keys := make([]JWK, 0, len(entries))
	for _, raw := range entries {
		key, reason := ValidateJWK(raw)
		if reason != "" {
			return nil, false
		}
		keys = append(keys, JWKOf(key))
	}
	slices.SortStableFunc(keys, func(a, b JWK) int { return strings.Compare(a.Kid, b.Kid) })
	return keys, true
}
