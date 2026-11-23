package receiver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/receiver"
)

const (
	clock       = int64(1767225600)
	subA        = "sub_0000000000000001"
	subB        = "sub_0000000000000002"
	subC        = "sub_0000000000000003"
	idA         = "msg_test_A"
	idB         = "msg_test_B"
	idC         = "msg_test_C"
	hmacKey     = "0123456789abcdef0123456789abcdef"
	otherSecret = "fedcba9876543210fedcba9876543210"
	audience    = "https://service.example.test"
	callbackA   = "https://hooks.example.test:443/hook"
	callbackB   = "https://hooks.example.test/hook/"
	eventBody   = ` { "eventId":"evt_1", "name":"changed", "timestamp":"2024-02-29T01:02:03.123-01:00", "data":{"value":"é"}, "cursor":"next" } `
	gapBody     = `{"type":"gap","cursor":null}`
	endBody     = `{"type":"terminated","error":{"code":-32024,"message":"revoked"}}`
	challenge   = "AAECAwQFBgcICQoLDA0ODw"
	verifyBody  = `{"type":"verification","challenge":"` + challenge + `"}`
	accepted    = `{"status":"accepted"}`
	duplicate   = `{"status":"duplicate"}`
)

func receiverConfig() receiver.Config {
	return receiver.Config{
		Secrets: []receiver.Secret{{Key: []byte(hmacKey), SubscriptionID: subA}},
		Routed:  []string{subA},
		Enqueue: func(receiver.Message) error { return nil },
	}
}

func TestReceiverCoreRequiresEnqueue(t *testing.T) {
	cfg := receiverConfig() // A nil key source must not mask the error.
	cfg.Enqueue = nil
	r, err := receiver.New(cfg)
	if r != nil || err == nil || err.Error() != "receiver: Config.Enqueue is required" {
		t.Fatalf("New returned receiver=%v, error=%v; want no receiver and the missing-enqueue error", r != nil, err)
	}
}

func newReceiver(t *testing.T, cfg receiver.Config) *receiver.Receiver {
	t.Helper()
	r, err := receiver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signedDelivery(id, sub, body, key string, at int64) receiver.Delivery {
	ts := strconv.FormatInt(at, 10)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(id + "." + ts + "." + body))
	return receiver.Delivery{
		Now: at,
		Headers: [][2]string{
			{"Webhook-ID", id}, {"webhook-timestamp", ts},
			{"webhook-signature", "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))},
			{"X-MCP-Subscription-Id", sub},
		},
		Body: []byte(body),
	}
}

func exampleKey(seed byte) (ed25519.PrivateKey, card.Key) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	x := base64.RawURLEncoding.EncodeToString(public)
	return private, card.Key{
		KID: base64.RawURLEncoding.EncodeToString(digest[:]), KTY: "OKP", CRV: "Ed25519",
		X: x, PublicKey: x, Raw: public,
	}
}

func signV2a(d *receiver.Delivery, private ed25519.PrivateKey, endpoint string) {
	content := endpoint + "." + d.Headers[0][1] + "." + d.Headers[1][1] + "." + string(d.Body)
	digest := sha256.Sum256([]byte(content))
	d.Headers[2][1] += " v2a," + base64.StdEncoding.EncodeToString(ed25519.Sign(private, digest[:]))
}

func jackHeader(d receiver.Delivery, private ed25519.PrivateKey, kid, callback string) [2]string {
	digest := sha256.Sum256(d.Body)
	content := strings.Join([]string{
		"mcp-jack/webhook1/delivery", audience, d.Headers[3][1], d.Headers[0][1],
		d.Headers[1][1], callback, base64.RawURLEncoding.EncodeToString(digest[:]),
	}, "\n")
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(content)))
	return [2]string{"Jack-Webhook-Auth", "w1 kid=" + kid + ",sig=" + sig}
}

func jackConfig() *receiver.JackConfig {
	return &receiver.JackConfig{Aud: audience, CallbackURLs: map[string]string{subA: callbackA}}
}

func checkError(t *testing.T, got receiver.Result, status int, code, message string) {
	t.Helper()
	want := `{"error":{"code":"` + code + `","message":"` + message + `"}}`
	if got.Status != status || got.Code != code || string(got.Body) != want || got.Recorded || len(got.Delivered) != 0 {
		t.Fatalf("got status=%d code=%q body=%s recorded=%t delivered=%q; want %d %s with no recording or forwarding",
			got.Status, got.Code, got.Body, got.Recorded, got.Delivered, status, want)
	}
	if text := receiver.MessageText(code); text != message {
		t.Fatalf("MessageText(%q) = %q, want %q", code, text, message)
	}
}

func checkOK(t *testing.T, got receiver.Result, body string, recorded bool, forwarded ...string) {
	t.Helper()
	if got.Status != 200 || got.Code != "" || string(got.Body) != body || got.Recorded != recorded || len(got.Delivered) != len(forwarded) {
		t.Fatalf("got status=%d code=%q body=%s recorded=%t delivered=%q; want 200 %s recorded=%t delivered=%q",
			got.Status, got.Code, got.Body, got.Recorded, got.Delivered, body, recorded, forwarded)
	}
	for i, want := range forwarded {
		if string(got.Delivered[i]) != want {
			t.Fatalf("delivered[%d] = %q, want %q", i, got.Delivered[i], want)
		}
	}
}

func TestReceiverCoreOrderedRejections(t *testing.T) {
	cases := []struct {
		name, code, message string
		status              int
		change              func(*receiver.Config, *receiver.Delivery)
	}{
		{"absence precedes duplicate", "missing_webhook_header", "a required header is absent", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[3] = d.Headers[0] }},
		{"duplicate precedes grammar", "duplicate_webhook_header", "a required header is repeated", 400,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers[0][1] = "private.id"
				d.Headers = append(d.Headers, [2]string{"webhook-ID", idA})
			}},
		{"id grammar", "malformed_webhook_id", "webhook-id grammar", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[0][1], d.Headers[1][1] = "bad.id", "01" }},
		{"timestamp grammar", "malformed_webhook_timestamp", "webhook-timestamp grammar", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[1][1], d.Headers[3][1] = "01", "sub_BAD" }},
		{"subscription grammar", "malformed_subscription_id", "subscription id grammar", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[3][1] = "sub_BAD" }},
		{"raw body size", "body_too_large", "body or declared length above the limit", 413,
			func(cfg *receiver.Config, d *receiver.Delivery) { cfg.MaxBody, d.Headers[3][1] = 1, subB }},
		{"declared size", "body_too_large", "body or declared length above the limit", 413,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers = append(d.Headers, [2]string{"Content-Length", "262145"}, [2]string{"content-length", "0"})
			}},
		{"declared grammar", "body_too_large", "body or declared length above the limit", 413,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers = append(d.Headers, [2]string{"Content-Length", "+1"})
			}},
		{"declared overflow", "body_too_large", "body or declared length above the limit", 413,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers = append(d.Headers, [2]string{"Content-Length", "18446744073709551616"})
			}},
		{"secret before routing", "unknown_subscription", "no secret applies to the subscription", 401,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[3][1] = subB }},
		{"routing before signature", "subscription_not_routed", "the subscription is not routed", 503,
			func(cfg *receiver.Config, d *receiver.Delivery) { cfg.Routed, d.Headers[2][1] = nil, "" }},
		{"signature grammar", "malformed_signature_header", "signature header grammar", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[2][1] = " v3,AA==" }},
		{"scheme before decode", "unsupported_signature_scheme", "unsupported signature scheme", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[2][1] = "v3,AA==" }},
		{"decode before HMAC", "malformed_signature", "signature value length", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Headers[2][1] = "v1,AA==" }},
		{"HMAC before clock", "bad_signature", "signature does not verify", 401,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Now += 301; d.Body = []byte("tampered") }},
		{"pending wrong HMAC", "bad_signature", "signature does not verify", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				cfg.Secrets[0].SubscriptionID, d.Body = "", []byte(verifyBody)
			}},
		{"stale before server", "stale_timestamp", "timestamp too old", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) { d.Now += 301; cfg.EnforceServerIdentity = true }},
		{"future", "future_timestamp", "timestamp too far ahead", 401,
			func(_ *receiver.Config, d *receiver.Delivery) { d.Now -= 301 }},
		{"no server keys before Jack", "no_server_keys", "no accepted server key", 503,
			func(cfg *receiver.Config, _ *receiver.Delivery) {
				cfg.EnforceServerIdentity, cfg.Jack = true, jackConfig()
			}},
		{"wrong asym endpoint", "bad_server_signature", "server signature does not verify", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				private, key := exampleKey(1)
				cfg.EnforceServerIdentity, cfg.Keys = true, card.StaticKeys([]card.Key{key})
				signV2a(d, private, subB)
			}},
		{"key source absent", "webhook_key_missing", "the webhook key source is missing", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				cfg.WebhookKey.Required = true
				*d = signedDelivery(idA, subA, `[]`, hmacKey, clock)
			}},
		{"key source differs", "webhook_key_mismatch", "the webhook key sources disagree", 401,
			func(cfg *receiver.Config, _ *receiver.Delivery) {
				_, key := exampleKey(1)
				cfg.Keys = card.StaticKeys([]card.Key{key})
				cfg.WebhookKey = receiver.WebhookKeyCheck{Required: true, ToolResult: json.RawMessage(`{"webhook_key":{"signing_keys":{"keys":[]}}}`)}
			}},
		{"not an object", "malformed_body", "body is not a json object", 400,
			func(_ *receiver.Config, d *receiver.Delivery) { *d = signedDelivery(idA, subA, `[]`, hmacKey, clock) }},
		{"invalid date", "malformed_body", "body is not a json object", 400,
			func(_ *receiver.Config, d *receiver.Delivery) {
				bad := strings.Replace(eventBody, "2024-02-29", "2026-02-29", 1)
				*d = signedDelivery(idA, subA, bad, hmacKey, clock)
			}},
		{"invalid envelope fields", "malformed_body", "body is not a json object", 400,
			func(_ *receiver.Config, d *receiver.Delivery) {
				*d = signedDelivery(idA, subA, `{"type":"gap"}`, hmacKey, clock)
			}},
		{"unknown envelope", "unknown_envelope_type", "unknown envelope type", 400,
			func(_ *receiver.Config, d *receiver.Delivery) {
				*d = signedDelivery(idA, subA, `{"type":"private"}`, hmacKey, clock)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, d := receiverConfig(), signedDelivery(idA, subA, eventBody, hmacKey, clock)
			tc.change(&cfg, &d)
			r := newReceiver(t, cfg)
			checkError(t, r.Handle(d), tc.status, tc.code, tc.message)
			if got := r.State().Accepted; len(got) != 0 {
				t.Fatalf("failure recorded %v", got)
			}
		})
	}
	if got := receiver.MessageText("not_a_receiver_code"); got != "" {
		t.Fatalf("unknown code returned %q", got)
	}
}

func TestReceiverCoreFullDeliveryAndDedup(t *testing.T) {
	private, key := exampleKey(1)
	tool, err := json.Marshal(map[string]any{"webhook_key": map[string]any{"signing_keys": map[string]any{"keys": []card.JWK{card.JWKOf(key)}}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := receiverConfig()
	cfg.Jack, cfg.Keys, cfg.EnforceServerIdentity = jackConfig(), card.StaticKeys([]card.Key{key}), true
	cfg.WebhookKey = receiver.WebhookKeyCheck{Required: true, ToolResult: tool}
	cfg.MaxBody = int64(len(eventBody))
	calls := 0
	cfg.Enqueue = func(m receiver.Message) error {
		calls++
		if m.SubscriptionID != subA || m.WebhookID != idA || m.Kind != "event" || m.Type != "" || m.Challenge != "" ||
			m.Cursor == nil || *m.Cursor != "next" || string(m.Raw) != eventBody {
			t.Fatalf("enqueue got %+v raw=%q", m, m.Raw)
		}
		m.Raw[0] = '!'
		return nil
	}
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, eventBody, hmacKey, clock)
	signV2a(&d, private, subA)
	d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackA), [2]string{"Content-Length", "000" + strconv.Itoa(len(d.Body))}, [2]string{"content-length", "ignored"})
	d.Now += 30 // Jack's default window includes the edge.
	got := r.Handle(d)
	if calls != 1 {
		t.Fatalf("Handle returned before exactly one enqueue: calls=%d", calls)
	}
	d.Body[0] = '!'
	checkOK(t, got, accepted, true, eventBody)

	// A duplicate still needs authentication but bypasses body parsing.
	d = signedDelivery(idA, subA, `x`, hmacKey, clock+30+1200)
	signV2a(&d, private, subA)
	checkError(t, r.Handle(d), 401, "missing_jack_auth", "jack header absent")
	d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackA))
	checkOK(t, r.Handle(d), duplicate, false)
	d.Now++ // Outside the inclusive retention window, so it must parse again.
	checkError(t, r.Handle(d), 400, "malformed_body", "body is not a json object")
	if calls != 1 || !slices.Equal(r.State().Accepted, []string{idA}) {
		t.Fatalf("calls=%d snapshot=%+v", calls, r.State())
	}
}

func TestReceiverCoreJackRejections(t *testing.T) {
	private, key := exampleKey(1)
	otherPrivate, otherKey := exampleKey(2)
	for _, tc := range []struct {
		name, code, message string
		status              int
		change              func(*receiver.Config, *receiver.Delivery)
	}{
		{"missing before cross-check", "missing_jack_auth", "jack header absent", 401,
			func(cfg *receiver.Config, _ *receiver.Delivery) { cfg.WebhookKey.Required = true }},
		{"malformed", "malformed_jack_auth", "jack header grammar", 400,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers = append(d.Headers, [2]string{"Jack-Webhook-Auth", "w2"})
			}},
		{"configured server kid", "webhook_key_is_server_key", "the webhook key is the mcp server key", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				cfg.MCPServerKID = otherKey.KID
				d.Headers = append(d.Headers, jackHeader(*d, otherPrivate, otherKey.KID, callbackA))
			}},
		{"derived server kid", "webhook_key_is_server_key", "the webhook key is the mcp server key", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				cfg.MCPServerPublicKey = otherKey.PublicKey
				d.Headers = append(d.Headers, jackHeader(*d, otherPrivate, otherKey.KID, callbackA))
			}},
		{"unknown kid before clock", "unknown_webhook_key", "unknown webhook key", 401,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Now += 31
				d.Headers = append(d.Headers, jackHeader(*d, otherPrivate, otherKey.KID, callbackA))
			}},
		{"window before signature", "jack_timestamp_out_of_window", "jack timestamp outside the window", 401,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Now += 31
				d.Headers = append(d.Headers, jackHeader(*d, otherPrivate, key.KID, callbackA))
			}},
		{"bad Jack signature", "bad_jack_signature", "jack signature does not verify", 401,
			func(_ *receiver.Config, d *receiver.Delivery) {
				d.Headers = append(d.Headers, jackHeader(*d, otherPrivate, key.KID, callbackA))
			}},
		{"missing pending callback", "bad_jack_signature", "jack signature does not verify", 401,
			func(cfg *receiver.Config, d *receiver.Delivery) {
				cfg.Secrets[0].SubscriptionID = ""
				*d = signedDelivery(idA, subA, verifyBody, hmacKey, clock)
				d.Headers = append(d.Headers, jackHeader(*d, private, key.KID, ""))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, d := receiverConfig(), signedDelivery(idA, subA, eventBody, hmacKey, clock)
			cfg.Keys, cfg.Jack = card.StaticKeys([]card.Key{key}), jackConfig()
			tc.change(&cfg, &d)
			r := newReceiver(t, cfg)
			checkError(t, r.Handle(d), tc.status, tc.code, tc.message)
			if got := r.State().Accepted; len(got) != 0 {
				t.Fatalf("failure recorded %v", got)
			}
		})
	}
}

func TestReceiverCoreFiltersServerKeyForAsymmetricVerification(t *testing.T) {
	private, key := exampleKey(1)
	for _, byKID := range []bool{true, false} {
		cfg := receiverConfig()
		cfg.Keys, cfg.EnforceServerIdentity = card.StaticKeys([]card.Key{key}), true
		if byKID {
			cfg.MCPServerKID = key.KID
		} else {
			cfg.MCPServerPublicKey = key.PublicKey
		}
		d := signedDelivery(idA, subA, eventBody, hmacKey, clock)
		signV2a(&d, private, subA)
		checkError(t, newReceiver(t, cfg).Handle(d), 503, "no_server_keys", "no accepted server key")
	}
}

type rotatingSource struct {
	keys  card.Static
	calls int
}

func (s *rotatingSource) KeySet() card.KeySet {
	s.calls++
	return s.keys.KeySet()
}

func TestReceiverCoreReadsRotatedKeysOnNextDelivery(t *testing.T) {
	oldPrivate, oldKey := exampleKey(1)
	newPrivate, newKey := exampleKey(2)
	source := &rotatingSource{keys: card.StaticKeys([]card.Key{oldKey})}
	cfg := receiverConfig()
	cfg.Keys, cfg.EnforceServerIdentity = source, true
	r := newReceiver(t, cfg)
	if source.calls != 0 {
		t.Fatalf("New read the key source %d times", source.calls)
	}

	oldDelivery := signedDelivery(idA, subA, gapBody, hmacKey, clock)
	signV2a(&oldDelivery, oldPrivate, subA)
	checkOK(t, r.Handle(oldDelivery), accepted, true, gapBody)
	newDelivery := signedDelivery(idB, subA, gapBody, hmacKey, clock)
	signV2a(&newDelivery, newPrivate, subA)
	checkError(t, r.Handle(newDelivery), 401, "bad_server_signature", "server signature does not verify")

	source.keys = card.StaticKeys([]card.Key{newKey})
	checkOK(t, r.Handle(newDelivery), accepted, true, gapBody)
	checkError(t, r.Handle(oldDelivery), 401, "bad_server_signature", "server signature does not verify")
	if source.calls != 4 {
		t.Fatalf("key snapshots = %d; want one per Handle (4)", source.calls)
	}
}

// expiringSource stands in for a card fetcher whose key set has outlived its
// cache lifetime: it serves the stored set only while live is true.
type expiringSource struct {
	keys card.Static
	live bool
}

func (s *expiringSource) KeySet() card.KeySet {
	if !s.live {
		return card.KeySet{}
	}
	return s.keys.KeySet()
}

// An expired card key set must stop authenticating deliveries until a
// successful refresh makes the same deliveries verify again.
func TestReceiverRefusesExpiredCardKeys(t *testing.T) {
	private, key := exampleKey(1)
	t.Run("server identity enforced", func(t *testing.T) {
		source := &expiringSource{keys: card.StaticKeys([]card.Key{key}), live: true}
		cfg := receiverConfig()
		cfg.Keys, cfg.EnforceServerIdentity = source, true
		r := newReceiver(t, cfg)
		signed := func(id string) receiver.Delivery {
			d := signedDelivery(id, subA, gapBody, hmacKey, clock)
			signV2a(&d, private, subA)
			return d
		}
		checkOK(t, r.Handle(signed(idA)), accepted, true, gapBody)
		source.live = false // The cache lifetime passed without a refresh.
		checkError(t, r.Handle(signed(idB)), 503, "no_server_keys", "no accepted server key")
		source.live = true // A successful refresh republished the keys.
		checkOK(t, r.Handle(signed(idB)), accepted, true, gapBody)
	})
	t.Run("jack key lookup", func(t *testing.T) {
		source := &expiringSource{keys: card.StaticKeys([]card.Key{key})}
		cfg := receiverConfig()
		cfg.Keys, cfg.Jack = source, jackConfig()
		r := newReceiver(t, cfg)
		delivery := func(id string) receiver.Delivery {
			d := signedDelivery(id, subA, gapBody, hmacKey, clock)
			d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackA))
			return d
		}
		checkError(t, r.Handle(delivery(idA)), 401, "unknown_webhook_key", "unknown webhook key")
		source.live = true
		checkOK(t, r.Handle(delivery(idA)), accepted, true, gapBody)
	})
}

func TestReceiverCoreCrossCheckRejectsInvalidPublishedKey(t *testing.T) {
	private, key := exampleKey(1)
	_, otherKey := exampleKey(2)
	bad := struct {
		card.JWK
		Alg string `json:"alg"`
	}{JWK: card.JWKOf(otherKey), Alg: "RS256"}
	raw, err := json.Marshal(map[string]any{"keys": []any{card.JWKOf(key), bad}})
	if err != nil {
		t.Fatal(err)
	}
	published := card.AcceptKeySet(raw, card.Options{})
	if !reflect.DeepEqual(published.Accepted, []card.Key{key}) || len(published.Rejected) != 1 || published.Rejected[0].Reason != "alg" {
		t.Fatalf("bad fixture: %+v", published)
	}
	tool, err := json.Marshal(map[string]any{"webhook_key": map[string]any{
		"signing_keys": card.StaticKeys([]card.Key{key}).KeySet().Raw,
	}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := receiverConfig()
	cfg.Keys, cfg.EnforceServerIdentity = card.Static{Set: published}, true
	cfg.WebhookKey = receiver.WebhookKeyCheck{Required: true, ToolResult: tool}
	cfg.Enqueue = func(receiver.Message) error {
		t.Fatal("enqueued a delivery after a key mismatch")
		return nil
	}
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, gapBody, hmacKey, clock)
	signV2a(&d, private, subA)
	checkError(t, r.Handle(d), 401, "webhook_key_mismatch", "the webhook key sources disagree")
}

func TestReceiverCorePendingBinding(t *testing.T) {
	private, key := exampleKey(1)
	cfg := receiverConfig()
	cfg.Keys, cfg.Jack, cfg.Routed = card.StaticKeys([]card.Key{key}), jackConfig(), nil
	cfg.Secrets = []receiver.Secret{{Key: []byte(otherSecret), CallbackURL: callbackA}, {Key: []byte(hmacKey), CallbackURL: callbackB}}
	var kinds []string
	cfg.Enqueue = func(m receiver.Message) error {
		kinds = append(kinds, m.Kind)
		if m.Kind == "verification" && (m.Challenge != challenge || m.Type != "verification" || string(m.Raw) != verifyBody) {
			t.Fatalf("verification enqueue got %+v raw=%q", m, m.Raw)
		}
		return nil
	}
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, eventBody, hmacKey, clock)
	d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackB))
	checkError(t, r.Handle(d), 503, "subscription_not_routed", "the subscription is not routed")
	// The refusal must happen before the durable enqueue.
	if len(kinds) != 0 {
		t.Fatalf("unrouted delivery reached enqueue: %v", kinds)
	}
	if state := r.State(); len(state.Accepted) != 0 || len(state.Routed) != 0 || state.Secrets[1].SubscriptionID != "" {
		t.Fatalf("non-verification changed state: %+v", state)
	}
	d = signedDelivery(idA, subA, verifyBody, hmacKey, clock)
	d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackA))
	checkError(t, r.Handle(d), 401, "bad_jack_signature", "jack signature does not verify")
	d.Headers[4] = jackHeader(d, private, key.KID, callbackB)
	got := r.Handle(d)
	if !slices.Equal(kinds, []string{"verification"}) {
		t.Fatalf("challenge returned before exactly one verification enqueue: %v", kinds)
	}
	checkOK(t, got, `{"challenge":"`+challenge+`"}`, true)
	state := r.State()
	if !slices.Equal(state.Routed, []string{subA}) || !slices.Equal(state.Accepted, []string{idA}) ||
		!slices.Equal(state.Secrets, []receiver.SecretState{{CallbackURL: callbackA}, {SubscriptionID: subA, CallbackURL: callbackB}}) {
		t.Fatalf("bad binding snapshot: %+v", state)
	}

	// After binding, use the registered callback map, not the pending callback.
	d.Headers[4] = jackHeader(d, private, key.KID, callbackA)
	checkOK(t, r.Handle(d), duplicate, false)
	d = signedDelivery(idB, subA, gapBody, hmacKey, clock)
	d.Headers = append(d.Headers, jackHeader(d, private, key.KID, callbackA))
	checkOK(t, r.Handle(d), accepted, true, gapBody)
	if !slices.Equal(kinds, []string{"verification", "gap"}) {
		t.Fatalf("enqueue order was %v", kinds)
	}
}

// A successful w1 challenge binds the pending secret to the subscription id.
// The first real event must then verify with that secret entry's callback URL,
// which is the only callback URL the receiver knows when no override exists.
func TestReceiverChallengeThenFirstEventUsesSecretCallbackURL(t *testing.T) {
	private, key := exampleKey(1)
	cfg := receiverConfig()
	cfg.Keys, cfg.Routed = card.StaticKeys([]card.Key{key}), nil
	cfg.Secrets = []receiver.Secret{{Key: []byte(hmacKey), CallbackURL: callbackB}}
	cfg.Jack = &receiver.JackConfig{Aud: audience} // Nil CallbackURLs: no override.
	r := newReceiver(t, cfg)

	challengeDelivery := signedDelivery(idB, subA, verifyBody, hmacKey, clock)
	challengeDelivery.Headers = append(challengeDelivery.Headers, jackHeader(challengeDelivery, private, key.KID, callbackB))
	checkOK(t, r.Handle(challengeDelivery), `{"challenge":"`+challenge+`"}`, true)
	if routed := r.State().Routed; !slices.Equal(routed, []string{subA}) {
		t.Fatalf("challenge did not route the subscription: %v", routed)
	}

	eventDelivery := signedDelivery(idA, subA, eventBody, hmacKey, clock)
	eventDelivery.Headers = append(eventDelivery.Headers, jackHeader(eventDelivery, private, key.KID, callbackB))
	checkOK(t, r.Handle(eventDelivery), accepted, true, eventBody)
	if accepted := r.State().Accepted; !slices.Equal(accepted, []string{idA, idB}) {
		t.Fatalf("accepted ids = %v", accepted)
	}
}

func TestReceiverCoreEnqueueRetry(t *testing.T) {
	cfg := receiverConfig()
	calls, stored := 0, 0
	cfg.Enqueue = func(_ receiver.Message) error {
		calls++
		if calls == 1 {
			return errors.New("private storage detail")
		}
		stored++
		return nil
	}
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, eventBody, hmacKey, clock)
	checkError(t, r.Handle(d), 503, "enqueue_failed", "durable enqueue failed")
	if state := r.State(); len(state.Accepted) != 0 {
		t.Fatalf("enqueue failure recorded %v", state.Accepted)
	}
	checkOK(t, r.Handle(d), accepted, true, eventBody)
	checkOK(t, r.Handle(d), duplicate, false)
	if calls != 2 || stored != 1 {
		t.Fatalf("enqueue calls=%d successful=%d", calls, stored)
	}
}

func TestReceiverCoreTerminationRoutingAndSnapshot(t *testing.T) {
	cfg := receiver.Config{
		Secrets: []receiver.Secret{
			{Key: []byte(hmacKey), SubscriptionID: subC, CallbackURL: callbackB},
			{Key: []byte(otherSecret), CallbackURL: callbackA},
			{Key: []byte(hmacKey), SubscriptionID: subA},
		},
		Routed: []string{subC, subA, subC},
	}
	enqueues := 0
	cfg.Enqueue = func(receiver.Message) error { enqueues++; return nil }
	r := newReceiver(t, cfg)
	checkOK(t, r.Handle(signedDelivery(idC, subC, endBody, hmacKey, clock)), accepted, true, endBody)
	checkOK(t, r.Handle(signedDelivery(idB, subA, endBody, hmacKey, clock)), accepted, true, endBody)
	if routed := r.State().Routed; len(routed) != 0 {
		t.Fatalf("terminated ids still routed: %v", routed)
	}
	checkOK(t, r.Handle(signedDelivery(idC, subC, endBody, hmacKey, clock)), duplicate, false)
	checkError(t, r.Handle(signedDelivery(idA, subC, `{}`, hmacKey, clock)), 400, "malformed_body", "body is not a json object")
	checkError(t, r.Handle(signedDelivery(idA, subC, gapBody, hmacKey, clock)), 410, "subscription_terminated", "the subscription is terminated")
	r.Route([]string{subC, subB, subC}) // Routing never clears termination.
	checkError(t, r.Handle(signedDelivery(idA, subC, gapBody, hmacKey, clock)), 410, "subscription_terminated", "the subscription is terminated")
	want := receiver.State{
		Routed: []string{subB, subC}, Terminated: []string{subA, subC}, Accepted: []string{idB, idC},
		Secrets: []receiver.SecretState{
			{SubscriptionID: subC, CallbackURL: callbackB}, {CallbackURL: callbackA}, {SubscriptionID: subA},
		},
	}
	if got := r.State(); !reflect.DeepEqual(got, want) || enqueues != 2 {
		t.Fatalf("snapshot=%+v, want %+v; enqueues=%d", got, want, enqueues)
	}
	snapshot := r.State()
	snapshot.Routed[0] = "changed"
	snapshot.Terminated[0] = "changed"
	snapshot.Accepted[0] = "changed"
	snapshot.Secrets[0] = receiver.SecretState{}
	if got := r.State(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot shares state: %+v", got)
	}
}

func TestReceiverCoreRouteMakesRegisteredDeliveryEligible(t *testing.T) {
	cfg := receiverConfig()
	cfg.Routed = nil
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, gapBody, hmacKey, clock)
	checkError(t, r.Handle(d), 503, "subscription_not_routed", "the subscription is not routed")
	r.Route([]string{subA})
	checkOK(t, r.Handle(d), accepted, true, gapBody)
}

// The unrouted pending-secret refusal now precedes the durable enqueue, so a
// failing enqueue can no longer surface instead of the routing refusal.
func TestReceiverCorePendingRoutingRefusalPrecedesEnqueue(t *testing.T) {
	cfg := receiverConfig()
	cfg.Secrets[0].SubscriptionID = ""
	cfg.Routed = nil
	calls := 0
	cfg.Enqueue = func(receiver.Message) error { calls++; return errors.New("private storage detail") }
	r := newReceiver(t, cfg)
	d := signedDelivery(idA, subA, eventBody, hmacKey, clock)
	checkError(t, r.Handle(d), 503, "subscription_not_routed", "the subscription is not routed")
	if calls != 0 {
		t.Fatalf("unrouted delivery reached enqueue %d times", calls)
	}
	if state := r.State(); len(state.Accepted) != 0 || len(state.Routed) != 0 || state.Secrets[0].SubscriptionID != "" {
		t.Fatalf("routing refusal changed state: %+v", state)
	}
}

func TestReceiverCoreRegisteredSecretTakesPriority(t *testing.T) {
	cfg := receiverConfig()
	cfg.Secrets = append([]receiver.Secret{{Key: []byte(otherSecret)}}, cfg.Secrets...)
	cfg.Secrets = append(cfg.Secrets, receiver.Secret{Key: []byte(otherSecret), SubscriptionID: subA})
	r := newReceiver(t, cfg)
	checkError(t, r.Handle(signedDelivery(idA, subA, eventBody, otherSecret, clock)), 401, "bad_signature", "signature does not verify")
	checkOK(t, r.Handle(signedDelivery(idA, subA, eventBody, hmacKey, clock)), accepted, true, eventBody)
}
