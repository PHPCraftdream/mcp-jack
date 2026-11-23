package vectors_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/receiver"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/sender"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookReceiverVectors(t *testing.T) {
	const file = "webhook-receiver-vectors.json"
	const wantCases = 107
	corpus, err := vector.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, wantCases, file)
	keys := loadFixtureKeys(t)

	pass := 0
	for _, c := range corpus.Cases {
		if t.Run(c.ID, func(t *testing.T) {
			gotJSON, err := json.Marshal(runReceiverVector(t, c, keys))
			if err != nil {
				t.Fatalf("%s: marshal result: %v", c.ID, err)
			}
			got := decodeJSON[any](t, gotJSON, "result")
			want := decodeJSON[any](t, c.Expect, "expectation")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s:\n got %s\nwant %s", c.ID, gotJSON, c.Expect)
			}
		}) {
			pass++
		}
	}
	if pass != wantCases {
		t.Fatalf("%s: got %d passes, want %d", file, pass, wantCases)
	}
	vector.Summary(t, "webhook-receiver", pass, 0, 0)
}

func runReceiverVector(t *testing.T, c vector.Case, keys map[string]card.Key) map[string]any {
	t.Helper()
	switch c.Kind {
	case "sequence":
		return runSequence(t, c.Input, keys)
	case "sender":
		input := decodeJSON[struct {
			Status       int    `json:"status"`
			Transport    string `json:"transport"`
			Attempt      int    `json:"attempt"`
			T0           int64  `json:"t0"`
			ResponseTime int64  `json:"responseTime"`
			RetryAfter   *int64 `json:"retryAfter"`
		}](t, c.Input, "sender input")
		in := sender.AttemptInput{
			Status: input.Status, Transport: input.Transport, Attempt: input.Attempt,
			T0: input.T0, ResponseTime: input.ResponseTime,
		}
		if input.RetryAfter != nil {
			in.RetryAfter, in.HasRetryAfter = *input.RetryAfter, true
		}
		out := sender.Decide(in)
		got := map[string]any{"action": out.Action}
		if out.Action != "accept" || out.LastError != "" {
			got["lastError"] = out.LastError
		}
		if out.NextAt != 0 {
			got["nextAt"] = out.NextAt
		}
		return got
	case "schedule":
		input := decodeJSON[struct {
			T0 int64 `json:"t0"`
		}](t, c.Input, "schedule input")
		return map[string]any{"times": sender.RetrySchedule(input.T0)}
	case "last-error":
		input := decodeJSON[struct {
			Status int `json:"status"`
		}](t, c.Input, "last-error input")
		return map[string]any{"lastError": nullIfEmpty(sender.LastError(input.Status))}
	default:
		t.Fatalf("%s: unknown kind %q", c.ID, c.Kind)
		return nil
	}
}

type sequenceConfig struct {
	Window                int64    `json:"window"`
	MaxBody               int64    `json:"max_body"`
	DedupRetention        int64    `json:"dedup_retention"`
	EnforceServerIdentity bool     `json:"enforce_server_identity"`
	MCPServerKID          string   `json:"mcp_server_kid"`
	MCPServerPublicKey    string   `json:"mcp_server_public_key"`
	Keys                  []string `json:"keys"`
	Routed                []string `json:"routed"`
	Secrets               []struct {
		Secret         string `json:"secret"`
		SubscriptionID string `json:"subscription_id"`
		CallbackURL    string `json:"callback_url"`
	} `json:"secrets"`
	Jack *struct {
		Aud          string            `json:"aud"`
		Window       int64             `json:"window"`
		CallbackURLs map[string]string `json:"callback_urls"`
	} `json:"jack"`
	WebhookKeyCheck string          `json:"webhook_key_check"`
	WebhookKeyTool  json.RawMessage `json:"webhook_key_tool"`
}

type sequenceStep struct {
	Now        int64           `json:"now"`
	Headers    [][2]string     `json:"headers"`
	Route      []string        `json:"route"`
	Enqueue    string          `json:"enqueue"`
	BodyText   json.RawMessage `json:"body_text"`
	BodyB64U   json.RawMessage `json:"body_b64u"`
	BodyRepeat struct {
		Char  json.RawMessage `json:"char"`
		Count json.RawMessage `json:"count"`
	} `json:"body_repeat"`
}

func runSequence(t *testing.T, raw json.RawMessage, keys map[string]card.Key) map[string]any {
	t.Helper()
	input := decodeJSON[struct {
		Config sequenceConfig `json:"config"`
		Steps  []sequenceStep `json:"steps"`
	}](t, raw, "sequence input")
	cfg := receiverConfig(t, input.Config, keys)
	var failNext bool
	cfg.Enqueue = func(receiver.Message) error {
		if failNext {
			return errors.New("fixture enqueue failure")
		}
		return nil
	}
	r, err := receiver.New(cfg)
	if err != nil {
		t.Fatalf("create receiver: %v", err)
	}

	steps := make([]map[string]any, 0, len(input.Steps))
	for _, step := range input.Steps {
		if step.Route != nil {
			r.Route(step.Route)
		}
		failNext = step.Enqueue == "fail"
		out := r.Handle(receiver.Delivery{Now: step.Now, Headers: step.Headers, Body: step.body(t)})
		var body any
		if err := json.Unmarshal(out.Body, &body); err != nil {
			body = nil
		}
		delivered := make([]any, 0, len(out.Delivered))
		for _, msg := range out.Delivered {
			delivered = append(delivered, decodeJSON[any](t, msg, "delivered message"))
		}
		steps = append(steps, map[string]any{
			"status": out.Status, "body": body, "delivered": delivered,
			"code": nullIfEmpty(out.Code), "recorded": out.Recorded,
		})
	}

	state := r.State()
	secrets := make([]map[string]any, 0, len(state.Secrets))
	for _, entry := range state.Secrets {
		secrets = append(secrets, map[string]any{
			"subscription_id": nullIfEmpty(entry.SubscriptionID),
			"callback_url":    nullIfEmpty(entry.CallbackURL),
		})
	}
	return map[string]any{
		"steps": steps,
		"final_state": map[string]any{
			"routed": state.Routed, "terminated": state.Terminated,
			"secrets": secrets, "accepted": state.Accepted,
		},
	}
}

func receiverConfig(t *testing.T, in sequenceConfig, keys map[string]card.Key) receiver.Config {
	t.Helper()
	cfg := receiver.Config{
		Window:                in.Window,
		MaxBody:               in.MaxBody,
		DedupRetention:        in.DedupRetention,
		EnforceServerIdentity: in.EnforceServerIdentity,
		MCPServerKID:          in.MCPServerKID,
		MCPServerPublicKey:    in.MCPServerPublicKey,
		Routed:                in.Routed,
		WebhookKey: receiver.WebhookKeyCheck{
			Required:   in.WebhookKeyCheck == "require",
			ToolResult: in.WebhookKeyTool,
		},
	}
	keysList := make([]card.Key, 0, len(in.Keys))
	for _, name := range in.Keys {
		key, ok := keys[name]
		if !ok {
			t.Fatalf("unknown fixture key %q", name)
		}
		keysList = append(keysList, key)
	}
	cfg.Keys = card.StaticKeys(keysList)
	for i, entry := range in.Secrets {
		key, reason := secret.Parse(entry.Secret)
		if reason != "" {
			t.Fatalf("decode secret %d: %s", i, reason)
		}
		cfg.Secrets = append(cfg.Secrets, receiver.Secret{
			Key: key, SubscriptionID: entry.SubscriptionID, CallbackURL: entry.CallbackURL,
		})
	}
	if in.Jack != nil {
		cfg.Jack = &receiver.JackConfig{Aud: in.Jack.Aud, Window: in.Jack.Window, CallbackURLs: in.Jack.CallbackURLs}
	}
	return cfg
}

func (s sequenceStep) body(t *testing.T) []byte {
	t.Helper()
	if text, ok := vector.String(s.BodyText); ok {
		return []byte(text)
	}
	if encoded, ok := vector.String(s.BodyB64U); ok {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
		if err != nil {
			t.Fatalf("decode body_b64u: %v", err)
		}
		return raw
	}
	char, hasChar := vector.String(s.BodyRepeat.Char)
	count, hasCount := vector.Int(s.BodyRepeat.Count)
	if hasChar && hasCount {
		return []byte(strings.Repeat(char, int(count)))
	}
	return nil
}

func loadFixtureKeys(t *testing.T) map[string]card.Key {
	t.Helper()
	path := vector.RepoPath("spec", "fixtures", "keys.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture keys: %v", err)
	}
	fixture := decodeJSON[struct {
		Keys []struct {
			Name      string `json:"name"`
			KID       string `json:"kid"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}](t, data, "fixture keys")
	keys := make(map[string]card.Key, len(fixture.Keys))
	for _, entry := range fixture.Keys {
		pub, err := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if err != nil {
			t.Fatalf("decode fixture public key %q: %v", entry.Name, err)
		}
		keys[entry.Name] = card.Key{KID: entry.KID, Raw: pub, PublicKey: entry.PublicKey}
	}
	return keys
}

func decodeJSON[T any](t *testing.T, raw []byte, label string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return value
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
