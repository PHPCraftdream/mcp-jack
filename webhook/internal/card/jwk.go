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

// CrossCheck compares the revalidated card keys to the tool's keys when required.
// Card keys from discovery have already had optional alg and use checked before
// projection into Key, which represents only accepted key material.
func CrossCheck(cardKeys []Key, toolResult json.RawMessage, require bool) string {
	if !require {
		return ""
	}
	webhookKey := jsonObject(jsonObject(toolResult)["webhook_key"])
	entries := jsonArray(jsonObject(webhookKey["signing_keys"])["keys"])
	if entries == nil {
		return "webhook_key_missing"
	}
	const mismatch = "webhook_key_mismatch"
	left := make([]JWK, 0, len(cardKeys))
	for _, key := range cardKeys {
		// Validate the supplied fields, not the defaults supplied by JWKOf.
		raw, _ := json.Marshal(JWK{Kty: key.KTY, Crv: key.CRV, X: key.X, Kid: key.KID})
		validated, reason := ValidateJWK(raw)
		if reason != "" {
			return mismatch
		}
		left = append(left, JWKOf(validated))
	}
	right := make([]JWK, 0, len(entries))
	for _, raw := range entries {
		validated, reason := ValidateJWK(raw)
		if reason != "" {
			return mismatch
		}
		right = append(right, JWKOf(validated))
	}
	byKID := func(a, b JWK) int { return strings.Compare(a.Kid, b.Kid) }
	slices.SortStableFunc(left, byKID)
	slices.SortStableFunc(right, byKID)
	// Equal sorted records have equal canonical JSON, including multiplicity.
	if !slices.Equal(left, right) {
		return mismatch
	}
	return ""
}
