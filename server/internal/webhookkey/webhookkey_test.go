package webhookkey_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/server/internal/webhookkey"
)

func webhookKeyFixture(seedByte byte) webhookkey.Key {
	var seed [ed25519.SeedSize]byte
	seed[0] = seedByte
	raw := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return webhookkey.Key{KID: jack.KeyID(raw), PublicKey: jack.EncodeBase64URL(raw)}
}

func TestWebhookKeyProviderConfigValidation(t *testing.T) {
	key := webhookKeyFixture(0)
	keys := []webhookkey.Key{key}
	for _, tt := range []struct {
		name string
		cfg  webhookkey.Config
	}{
		{"empty key set", webhookkey.Config{}},
		{"too many keys", webhookkey.Config{Keys: make([]webhookkey.Key, 65)}},
		{"non-base64url key", webhookkey.Config{Keys: []webhookkey.Key{{KID: key.KID, PublicKey: "+/invalid"}}}},
		{"padded key", webhookkey.Config{Keys: []webhookkey.Key{{KID: key.KID, PublicKey: key.PublicKey + "="}}}},
		{"31-byte key", webhookkey.Config{Keys: []webhookkey.Key{{KID: key.KID, PublicKey: jack.EncodeBase64URL(make([]byte, 31))}}}},
		{"wrong KID", webhookkey.Config{Keys: []webhookkey.Key{{KID: webhookKeyFixture(1).KID, PublicKey: key.PublicKey}}}},
		{"duplicate KIDs", webhookkey.Config{Keys: []webhookkey.Key{key, key}}},
		{"too many ranges", webhookkey.Config{Keys: keys, EgressIPRanges: make([]string, 65)}},
		{"missing slash", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0"}}},
		{"empty prefix", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0/"}}},
		{"extra slash", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0/24/1"}}},
		{"whitespace", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0/24 "}}},
		{"query", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0/24?"}}},
		{"fragment", webhookkey.Config{Keys: keys, EgressIPRanges: []string{"192.0.2.0/24#"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := webhookkey.New(tt.cfg); err == nil {
				t.Fatal("New accepted invalid config")
			}
		})
	}
	if _, err := webhookkey.New(webhookkey.Config{Keys: keys}); err != nil {
		t.Fatalf("New rejected valid config: %v", err)
	}
}

func TestWebhookKeyProviderCallDenials(t *testing.T) {
	p, err := webhookkey.New(webhookkey.Config{Keys: []webhookkey.Key{webhookKeyFixture(0)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		call *verify.NativeCall
	}{
		{"nil call", nil},
		{"wrong tool", &verify.NativeCall{Tool: verify.ToolServerKey, Caller: &verify.RegistryEntry{}}},
		{"no caller", &verify.NativeCall{Tool: verify.ToolWebhookKey}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := p.Call(tt.call)
			if err == nil || err.HTTPStatus != 403 || err.Code != jack.CodeOperationDenied || out.Structured != nil {
				t.Fatalf("Call = (%+v, %+v), want empty result and 403 %s", out, err, jack.CodeOperationDenied)
			}
		})
	}
}

func TestWebhookKeyProviderStructuredSnapshot(t *testing.T) {
	first, second := webhookKeyFixture(0), webhookKeyFixture(1)
	keys := []webhookkey.Key{first, second}
	ranges := []string{"192.0.2.0/24", "2001:0DB8::/32"}
	p, err := webhookkey.New(webhookkey.Config{Keys: keys, EgressIPRanges: ranges})
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = webhookkey.Key{}
	ranges[0] = "changed"
	call := &verify.NativeCall{Tool: verify.ToolWebhookKey, Caller: &verify.RegistryEntry{}, Arguments: json.RawMessage(`{"ignored":true}`)}
	// encoding/json sorts map keys; the JWK struct preserves the requested field order.
	want := fmt.Sprintf(`{"webhook_key":{"egress_ip_ranges":["192.0.2.0/24","2001:0DB8::/32"],"signing_keys":{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q},{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q}]}}}`,
		first.PublicKey, first.KID, second.PublicKey, second.KID)
	check := func() map[string]any {
		t.Helper()
		out, err := p.Call(call)
		if err != nil {
			t.Fatal(err)
		}
		got, marshalErr := json.Marshal(out.Structured)
		if marshalErr != nil || string(got) != want {
			t.Fatalf("structured result = %s (%v), want %s", got, marshalErr, want)
		}
		return out.Structured.(map[string]any)
	}
	out := check()
	webhook := out["webhook_key"].(map[string]any)
	egress := webhook["egress_ip_ranges"].([]string)
	signing := webhook["signing_keys"].(map[string]any)
	reflect.ValueOf(signing["keys"]).Index(0).FieldByName("X").SetString("changed")
	egress[0] = "changed"
	delete(signing, "keys")
	delete(webhook, "egress_ip_ranges")
	delete(out, "webhook_key")
	check()
}
