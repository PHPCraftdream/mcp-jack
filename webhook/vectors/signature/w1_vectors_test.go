package vectors_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookW1Vectors(t *testing.T) {
	const name = "webhook-w1-vectors.json"
	const want = 25
	corpus := loadCorpus(t, name, want)
	keys := loadFixtureKeys(t)
	checkCorpus(t, corpus, "webhook-w1", want, func(t *testing.T, c vector.Case) map[string]any {
		return runW1Case(t, c, keys)
	})
}

type w1Wire struct {
	deliveryWire
	Aud            string `json:"aud"`
	SubscriptionID string `json:"subscription_id"`
	CallbackURL    string `json:"callback_url"`
}

func (wire w1Wire) parts(t *testing.T) dsig.W1Parts {
	t.Helper()
	return dsig.W1Parts{
		Aud:            wire.Aud,
		SubscriptionID: wire.SubscriptionID,
		WebhookID:      wire.WebhookID,
		Timestamp:      strconv.FormatInt(wire.timestamp(t), 10),
		CallbackURL:    wire.CallbackURL,
		Body:           decodeBody(t, wire.BodyB64U),
	}
}

func runW1Case(t *testing.T, c vector.Case, keys fixtureKeys) map[string]any {
	t.Helper()
	switch c.Kind {
	case "kat-w1":
		input := decodeJSON[struct {
			w1Wire
			Key string `json:"key"`
		}](t, c.Input, "input")
		parts := input.parts(t)
		key := keys.named(t, input.Key)
		header, err := dsig.W1Sign(key.private, key.public.KID, parts)
		if err != nil {
			t.Fatalf("sign w1: %v", err)
		}
		return map[string]any{
			"result":              "accept",
			"header":              header,
			"signing_string_b64u": secret.EncodeURL([]byte(dsig.W1SigningString(parts))),
		}
	case "verify-w1":
		input := decodeJSON[struct {
			Header       json.RawMessage `json:"header"`
			Parts        w1Wire          `json:"parts"`
			Keys         []string        `json:"keys"`
			Now          int64           `json:"now"`
			Window       int64           `json:"window"`
			MCPServerKID string          `json:"mcp_server_kid"`
		}](t, c.Input, "input")
		if vector.Null(input.Header) {
			return decision("missing_jack_auth")
		}
		// A non-string header cannot satisfy the SDK's header grammar.
		header, _ := vector.String(input.Header)
		_, code := dsig.W1Verify(header, input.Parts.parts(t), dsig.W1Keys{
			Keys:         keys.accepted(t, input.Keys),
			Now:          input.Now,
			Window:       input.Window,
			MCPServerKID: input.MCPServerKID,
		})
		return decision(code)
	default:
		t.Fatalf("unknown case kind %q", c.Kind)
		return nil
	}
}
