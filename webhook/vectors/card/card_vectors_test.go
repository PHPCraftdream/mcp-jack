package vectors_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookServerCardKeysVectors(t *testing.T) {
	const label, wantCases = "server-card-keys", 43
	corpus, err := vector.Load(label + "-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, wantCases, label)
	fixtures := loadFixtureKeys(t)

	pass := 0
	for _, c := range corpus.Cases {
		if t.Run(c.ID, func(t *testing.T) {
			got, err := json.Marshal(runCardCase(t, c, fixtures))
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

func loadFixtureKeys(t *testing.T) map[string]card.Key {
	t.Helper()
	path := vector.RepoPath("spec", "fixtures", "keys.json")
	if path == "" {
		t.Fatal("cannot locate fixture keys: module root not found")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Keys []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			KID       string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
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

func namedKeys(t *testing.T, fixtures map[string]card.Key, names []string) []card.Key {
	t.Helper()
	keys := make([]card.Key, 0, len(names))
	for _, name := range names {
		key, ok := fixtures[name]
		if !ok {
			t.Fatalf("unknown fixture key %q", name)
		}
		keys = append(keys, key)
	}
	return keys
}

type cardInput struct {
	Card               json.RawMessage   `json:"card"`
	MCPURL             string            `json:"mcpUrl"`
	CardURL            string            `json:"cardUrl"`
	SigningKeys        []json.RawMessage `json:"signing_keys"`
	MCPServerKID       string            `json:"mcp_server_kid"`
	MCPServerPublicKey string            `json:"mcp_server_public_key"`
	Values             []string          `json:"values"`
	ElapsedMS          *int64            `json:"elapsed_ms"`
	Response           struct {
		Card    json.RawMessage   `json:"card"`
		Raw     *string           `json:"raw"`
		Pad     *int              `json:"pad"`
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
	} `json:"response"`
	Keys       []string        `json:"keys"`
	KID        string          `json:"kid"`
	CardKeys   json.RawMessage `json:"card_keys"`
	ToolResult json.RawMessage `json:"toolResult"`
	Require    bool            `json:"require"`
}

func runCardCase(t *testing.T, c vector.Case, fixtures map[string]card.Key) map[string]any {
	t.Helper()
	var input cardInput
	if err := json.Unmarshal(c.Input, &input); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	opts := card.Options{MCPServerKID: input.MCPServerKID, MCPServerPublicKey: input.MCPServerPublicKey}

	switch c.Kind {
	case "info":
		info, code := card.WebhookInfo(input.Card, input.MCPURL)
		if code != "" {
			return outcome(code)
		}
		return map[string]any{
			"result": "accept", "signing_keys": info.SigningKeys,
			"egress": append([]string{}, info.Egress...), "remote_url": info.RemoteURL,
		}

	case "remote":
		remote, ok := card.SelectRemote(input.Card, input.MCPURL)
		if !ok {
			return outcome("no_remote")
		}
		return map[string]any{"result": "accept", "url": remote.URL}

	case "jwk-set":
		accepted, rejected := card.AcceptJWKSet(input.SigningKeys, opts)
		return map[string]any{"accepted": kids(accepted), "rejected": rejectedKeys(rejected)}

	case "cidr-list":
		accepted, rejected := card.ParseCIDRList(input.Values)
		ranges := make([]map[string]any, 0, len(accepted))
		for _, entry := range accepted {
			ranges = append(ranges, map[string]any{"cidr": entry.CIDR, "family": entry.Family, "prefix": entry.Prefix})
		}
		// The SDK returns rejected texts; the corpus pairs each with a reason.
		bad := make([]map[string]string, 0, len(rejected))
		for _, value := range rejected {
			bad = append(bad, map[string]string{"value": value, "reason": "malformed_cidr"})
		}
		return map[string]any{"accepted": ranges, "rejected": bad}

	case "fetch", "webhook-key-discovery":
		request := fetchInput(t, input)
		if c.Kind == "fetch" {
			request.ElapsedMS = input.ElapsedMS
			request.Options = opts
		}
		result, err := card.FetchDecision(request)
		if err != nil {
			return outcome(err.Code)
		}
		if c.Kind == "webhook-key-discovery" {
			return outcome(card.CrossCheck(result.Keys, input.ToolResult, true))
		}
		egress := make([]string, 0, len(result.Egress))
		for _, entry := range result.Egress {
			egress = append(egress, entry.CIDR)
		}
		return map[string]any{
			"result": "accept", "keys": kids(result.Keys), "egress": egress,
			"rejected": rejectedKeys(result.Rejected), "cache_ttl": result.CacheTTL,
		}

	case "kid":
		if _, ok := card.KeyForKID(namedKeys(t, fixtures, input.Keys), input.KID); !ok {
			return outcome("unknown_webhook_key")
		}
		return outcome("")

	case "webhook-key-check":
		var own []json.RawMessage
		if input.CardKeys != nil {
			if err := json.Unmarshal(input.CardKeys, &own); err != nil {
				t.Fatalf("decode card_keys: %v", err)
			}
		} else {
			for _, key := range namedKeys(t, fixtures, input.Keys) {
				raw, err := json.Marshal(card.JWKOf(key))
				if err != nil {
					t.Fatalf("marshal fixture JWK: %v", err)
				}
				own = append(own, raw)
			}
		}
		keys := make([]card.Key, 0, len(own))
		for _, raw := range own {
			key, reason := card.ValidateJWK(raw)
			if reason != "" {
				return outcome("webhook_key_mismatch")
			}
			keys = append(keys, key)
		}
		return outcome(card.CrossCheck(keys, input.ToolResult, input.Require))

	default:
		t.Fatalf("unknown kind %q", c.Kind)
		return nil
	}
}

func fetchInput(t *testing.T, input cardInput) card.FetchInput {
	t.Helper()
	response := input.Response
	var body []byte
	switch {
	case response.Card != nil:
		var compact bytes.Buffer
		if err := json.Compact(&compact, response.Card); err != nil {
			t.Fatalf("encode response card: %v", err)
		}
		body = compact.Bytes()
	case response.Raw != nil:
		body = []byte(*response.Raw)
	case response.Pad != nil:
		body = bytes.Repeat([]byte(" "), *response.Pad)
	}
	headers := make(map[string]string, len(response.Headers))
	for name, value := range response.Headers {
		headers[strings.ToLower(name)] = value
	}
	return card.FetchInput{
		MCPURL: input.MCPURL, CardURL: input.CardURL, Status: response.Status, Headers: headers, Body: body,
	}
}

func kids(keys []card.Key) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.KID)
	}
	return out
}

func rejectedKeys(keys []card.Rejected) []map[string]any {
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{"kid": key.KID, "reason": key.Reason})
	}
	return out
}

func outcome(code string) map[string]any {
	if code != "" {
		return map[string]any{"result": "reject", "code": code}
	}
	return map[string]any{"result": "accept"}
}
