package vectors_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/subscription"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookSubscriptionVectors(t *testing.T) {
	const label, wantCases = "webhook-subscription", 49
	corpus, err := vector.Load(label + "-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, wantCases, label)

	pass := 0
	for _, c := range corpus.Cases {
		if t.Run(c.ID, func(t *testing.T) {
			got, err := json.Marshal(runSubscriptionCase(t, c))
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}
			var actual, expected any
			if err := json.Unmarshal(got, &actual); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if err := json.Unmarshal(c.Expect, &expected); err != nil {
				t.Fatalf("decode expectation: %v", err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("%s: got %s; want %s", c.ID, got, c.Expect)
			}
		}) {
			pass++
		}
	}
	if pass != wantCases {
		t.Errorf("%s: passed %d cases, want %d", label, pass, wantCases)
	}
	vector.Summary(t, label, pass, 0, 0)
}

func runSubscriptionCase(t *testing.T, c vector.Case) map[string]any {
	t.Helper()
	var input map[string]json.RawMessage
	if err := json.Unmarshal(c.Input, &input); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	text := func(field string) string {
		t.Helper()
		s, ok := vector.String(input[field])
		if !ok {
			t.Fatalf("input.%s must be a string", field)
		}
		return s
	}
	integer := func(field string) int64 {
		t.Helper()
		n, ok := vector.Int(input[field])
		if !ok {
			t.Fatalf("input.%s must be an integer", field)
		}
		return n
	}
	parseSecret := func(field string) []byte {
		t.Helper()
		key, reason := secret.Parse(text(field))
		if reason != "" {
			t.Fatalf("parse input.%s: %s", field, reason)
		}
		return key
	}

	switch c.Kind {
	case "sub-id":
		var args any
		if !vector.Null(input["arguments_text"]) {
			if err := json.Unmarshal([]byte(text("arguments_text")), &args); err != nil {
				t.Fatalf("decode arguments_text: %v", err)
			}
		}
		key, err := subscription.SubscriptionKey(text("principal"), text("url"), text("name"), args)
		if err != nil {
			return reject(err.Code, err.Reason)
		}
		return map[string]any{
			"result": "accept", "id": key.ID, "canonical_url": key.CanonicalURL,
			"canonical_arguments": key.CanonicalArguments, "jcs_input": key.JCSInput,
		}

	case "ttl":
		raw, present := input["ttlMs"]
		ttl := subscription.TTLValue{Present: present, Null: present && vector.Null(raw)}
		if ttl.Present && !ttl.Null {
			ms, ok := vector.Int(raw)
			if !ok {
				return reject("invalid_arguments", "ttl")
			}
			ttl.MS = ms
		}
		grant, err := subscription.TTLGrant(ttl, integer("now"))
		if err != nil {
			return reject(err.Code, err.Reason)
		}
		return map[string]any{"result": "accept", "grantMs": grant.GrantMS, "refreshBefore": grant.RefreshBefore}

	case "secrets":
		current := parseSecret("current")
		var previous []byte
		hasPrevious := !vector.Null(input["previous"])
		if hasPrevious {
			previous = parseSecret("previous")
		}
		active := subscription.ActiveSecrets(current, previous, hasPrevious, integer("graceEndsAt"), integer("now"))
		order := make([]string, 0, len(active))
		for _, entry := range active {
			if entry.Current {
				order = append(order, "current")
			} else {
				order = append(order, "previous")
			}
		}
		return map[string]any{"result": "accept", "order": order}

	case "envelope":
		if text("kind") == "gap" {
			return map[string]any{"result": "accept", "body_text": string(subscription.GapEnvelope(text("cursor")))}
		}
		code, codeOK := vector.Int(input["code"])
		message, messageOK := vector.String(input["message"])
		if !codeOK || !messageOK {
			return reject("invalid_envelope", "")
		}
		body, err := subscription.TerminatedEnvelope(code, message, input["data"])
		if err != nil {
			return reject("invalid_envelope", "")
		}
		return map[string]any{"result": "accept", "body_text": string(body)}

	case "cursor":
		raw, present := input["value"]
		var cursor *string
		if !present {
			return map[string]any{"result": "reject"}
		}
		if !vector.Null(raw) {
			s, ok := vector.String(raw)
			if !ok {
				return map[string]any{"result": "reject"}
			}
			cursor = &s
		}
		if subscription.CursorOK(cursor) {
			return map[string]any{"result": "accept"}
		}
		return map[string]any{"result": "reject"}

	default:
		t.Fatalf("unknown kind %q", c.Kind)
		return nil
	}
}

func reject(code, reason string) map[string]any {
	out := map[string]any{"result": "reject", "code": code}
	if reason != "" {
		out["reason"] = reason
	}
	return out
}
