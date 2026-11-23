package card_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
)

func cardTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cardTestJWK(seed byte) (card.JWK, []byte) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(pub)
	return card.JWK{
		Kty: "OKP", Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Kid: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, pub
}

func cardTestJWKMembers(jwk card.JWK) map[string]any {
	return map[string]any{"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "kid": jwk.Kid}
}

func TestServerCardValidateJWKReasons(t *testing.T) {
	jwk, pub := cardTestJWK(1)
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	// A 32-byte canonical encoding has two zero padding bits in its last
	// character, so the next alphabet character encodes the same bytes loosely.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := bytes.IndexByte([]byte(alphabet), jwk.X[len(jwk.X)-1])
	nonCanonical := jwk.X[:len(jwk.X)-1] + string(alphabet[last+1])
	tests := []struct {
		name   string
		change map[string]any
		want   string
	}{
		{"valid", nil, ""},
		{"valid optional members", map[string]any{"alg": "EdDSA", "use": "sig", "unknown": true}, ""},
		{"kty before crv", map[string]any{"kty": 1, "crv": nil}, "kty"},
		{"crv before x", map[string]any{"crv": "X25519", "x": nil}, "crv"},
		{"x not a string", map[string]any{"x": nil}, "x_encoding"},
		{"x padded", map[string]any{"x": jwk.X + "="}, "x_encoding"},
		{"x newline", map[string]any{"x": jwk.X + "\n"}, "x_encoding"},
		{"x foreign alphabet", map[string]any{"x": "A+"}, "x_encoding"},
		{"x impossible length", map[string]any{"x": "A"}, "x_encoding"},
		{"x unused bits", map[string]any{"x": nonCanonical}, "x_encoding"},
		{"x empty", map[string]any{"x": ""}, "x_length"},
		{"x short", map[string]any{"x": "AA"}, "x_length"},
		{"x identity before kid", map[string]any{"x": base64.RawURLEncoding.EncodeToString(identity), "kid": nil}, "x_key"},
		{"kid null", map[string]any{"kid": nil}, "kid_missing"},
		{"kid empty", map[string]any{"kid": ""}, "kid_missing"},
		{"kid mismatch before alg", map[string]any{"kid": "other", "alg": "RS256"}, "kid_mismatch"},
		{"alg before use", map[string]any{"alg": "RS256", "use": "enc"}, "alg"},
		{"alg present null", map[string]any{"alg": nil}, "alg"},
		{"use", map[string]any{"use": "enc"}, "use"},
		{"use present null", map[string]any{"use": nil}, "use"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := cardTestJWKMembers(jwk)
			for name, value := range tt.change {
				members[name] = value
			}
			key, reason := card.ValidateJWK(cardTestJSON(t, members))
			if reason != tt.want {
				t.Fatalf("reason = %q, want %q", reason, tt.want)
			}
			if reason == "" && (card.JWKOf(key) != jwk || key.KTY != jwk.Kty || key.CRV != jwk.Crv || key.X != jwk.X ||
				key.PublicKey != jwk.X || !bytes.Equal(key.Raw, pub)) {
				t.Fatalf("unexpected accepted key: %+v", key)
			}
		})
	}
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{"Kty":"OKP"}`)} {
		if _, reason := card.ValidateJWK(raw); reason != "kty" {
			t.Errorf("ValidateJWK(%s) reason = %q, want kty", raw, reason)
		}
	}
	missingKid := cardTestJWKMembers(jwk)
	delete(missingKid, "kid")
	if _, reason := card.ValidateJWK(cardTestJSON(t, missingKid)); reason != "kid_missing" {
		t.Errorf("absent kid reason = %q", reason)
	}
}

func TestServerCardAcceptKeySetPhases(t *testing.T) {
	first, _ := cardTestJWK(2)
	second, _ := cardTestJWK(3)
	dupeA, _ := cardTestJWK(4)
	dupeB, _ := cardTestJWK(5)
	serverKID, _ := cardTestJWK(6)
	serverRaw, _ := cardTestJWK(7)
	invalid := cardTestJWKMembers(first)
	invalid["alg"] = "RS256"
	entries := []json.RawMessage{
		cardTestJSON(t, serverRaw), cardTestJSON(t, dupeA), cardTestJSON(t, second),
		json.RawMessage(`{"kid":42}`), cardTestJSON(t, serverKID), cardTestJSON(t, dupeB),
		cardTestJSON(t, invalid), cardTestJSON(t, dupeA), cardTestJSON(t, serverRaw),
		cardTestJSON(t, first), json.RawMessage(`{"kid":""}`), cardTestJSON(t, dupeB),
	}
	raw := cardTestSigningKeys(t, cardTestJSON(t, entries))
	set := card.AcceptKeySet(raw, card.Options{
		MCPServerKID: serverKID.Kid, MCPServerPublicKey: serverRaw.X,
	})
	if !bytes.Equal(set.Raw, raw) {
		t.Fatalf("raw signing keys = %s, want %s", set.Raw, raw)
	}
	accepted, rejected := set.Accepted, set.Rejected
	if len(accepted) != 2 || card.JWKOf(accepted[0]) != second || card.JWKOf(accepted[1]) != first {
		t.Fatalf("unexpected accepted keys: %+v", accepted)
	}
	empty := ""
	want := []card.Rejected{
		{Reason: "kty"}, {KID: &first.Kid, Reason: "alg"}, {KID: &empty, Reason: "kty"},
		{KID: &serverRaw.Kid, Reason: "mcp_server_key"}, {KID: &serverKID.Kid, Reason: "mcp_server_key"},
		{KID: &serverRaw.Kid, Reason: "mcp_server_key"},
		{KID: &dupeA.Kid, Reason: "duplicate_kid"}, {KID: &dupeB.Kid, Reason: "duplicate_kid"},
		{KID: &dupeA.Kid, Reason: "duplicate_kid"}, {KID: &dupeB.Kid, Reason: "duplicate_kid"},
	}
	if !reflect.DeepEqual(rejected, want) {
		t.Errorf("unexpected rejected keys: %+v", rejected)
	}
}

func TestServerCardKeyLookup(t *testing.T) {
	jwk, _ := cardTestJWK(8)
	keys, _ := card.AcceptJWKSet([]json.RawMessage{cardTestJSON(t, jwk)}, card.Options{})
	if key, ok := card.KeyForKID(keys, jwk.Kid); !ok || card.JWKOf(key) != jwk {
		t.Errorf("known key lookup = %+v, %v", key, ok)
	}
	for _, kid := range []string{"", "missing", jwk.Kid + " "} {
		if _, ok := card.KeyForKID(keys, kid); ok {
			t.Errorf("unexpected match for %q", kid)
		}
	}
}

func cardTestTool(t *testing.T, keys ...any) json.RawMessage {
	t.Helper()
	if keys == nil {
		keys = []any{}
	}
	return cardTestJSON(t, map[string]any{"webhook_key": map[string]any{
		"signing_keys": map[string]any{"keys": keys},
	}})
}

func cardTestSigningKeys(t *testing.T, keys any) json.RawMessage {
	t.Helper()
	return cardTestJSON(t, map[string]any{"keys": keys})
}

func TestStaticKeys(t *testing.T) {
	jwk, _ := cardTestJWK(13)
	key, reason := card.ValidateJWK(cardTestJSON(t, jwk))
	if reason != "" {
		t.Fatal(reason)
	}
	keys := []card.Key{key}
	var source card.Source = card.StaticKeys(keys)
	want := cardTestSigningKeys(t, []card.JWK{jwk})
	keys[0].Raw[0] ^= 1
	snapshot := source.KeySet()
	if !bytes.Equal(snapshot.Raw, want) || len(snapshot.Accepted) != 1 || snapshot.Accepted[0].Raw[0] == keys[0].Raw[0] || len(snapshot.Rejected) != 0 {
		t.Fatalf("unexpected static snapshot: %+v", snapshot)
	}
	snapshot.Raw[0] = '!'
	if got := source.KeySet().Raw; !bytes.Equal(got, want) {
		t.Errorf("static raw after snapshot mutation = %s, want %s", got, want)
	}
	if got := card.StaticKeys(nil).KeySet().Raw; string(got) != `{"keys":[]}` {
		t.Errorf("empty static raw = %s, want an empty keys array", got)
	}
}

func TestServerCardCrossCheck(t *testing.T) {
	first, _ := cardTestJWK(9)
	second, _ := cardTestJWK(10)
	keys := cardTestSigningKeys(t, []card.JWK{first, second})
	good := cardTestJWKMembers(first)
	good["alg"], good["use"] = "EdDSA", "sig"
	badAlg := cardTestJWKMembers(first)
	badAlg["alg"] = "RS256"
	badUse := cardTestJWKMembers(first)
	badUse["use"] = "enc"
	invalidCard := cardTestSigningKeys(t, []any{badAlg, second})

	tests := []struct {
		name    string
		keys    json.RawMessage
		tool    json.RawMessage
		require bool
		want    string
	}{
		{"agree despite order and optional members", keys, cardTestTool(t, second, good), true, ""},
		{"different set", keys, cardTestTool(t, second), true, "webhook_key_mismatch"},
		{"extra duplicate", keys, cardTestTool(t, second, first, first), true, "webhook_key_mismatch"},
		{"empty sets agree", nil, cardTestTool(t), true, ""},
		{"missing", keys, nil, true, "webhook_key_missing"},
		{"keys not an array", keys, json.RawMessage(`{"webhook_key":{"signing_keys":{"keys":null}}}`), true, "webhook_key_missing"},
		{"not required", invalidCard, nil, false, ""},
		{"invalid tool alg", keys, cardTestTool(t, second, badAlg), true, "webhook_key_mismatch"},
		{"invalid card alg even with matching accepted subset", invalidCard, cardTestTool(t, second), true, "webhook_key_mismatch"},
		{"invalid card use", cardTestSigningKeys(t, []any{badUse, second}), cardTestTool(t, second, first), true, "webhook_key_mismatch"},
		{"same invalid record on both sides", invalidCard, cardTestTool(t, second, badAlg), true, "webhook_key_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := card.CrossCheckWebhookKey(tt.keys, tt.tool, tt.require); got != tt.want {
				t.Errorf("CrossCheckWebhookKey = %q, want %q", got, tt.want)
			}
		})
	}
}
