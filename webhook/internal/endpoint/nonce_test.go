package endpoint_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

const endpointNonce = "KfROIaIYzOA4LouilLN_Jw"

func assertEndpointError(t *testing.T, got *endpoint.Error, code, reason string) {
	t.Helper()
	if code == "" {
		if got != nil {
			t.Fatalf("got %v, want success", got)
		}
		return
	}
	if got == nil || got.Code != code || got.Reason != reason {
		t.Fatalf("got %#v, want code %q and reason %q", got, code, reason)
	}
}

func TestEndpointNonceLengthsAndAlphabet(t *testing.T) {
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{endpointNonce[:21], false}, {endpointNonce, true}, {endpointNonce + "A", false},
		{strings.Repeat("-", 22), true}, {strings.Repeat("+", 22), false},
		{strings.Repeat("/", 22), false}, {endpointNonce[:21] + "=", false},
		{endpointNonce + "\n", false}, {"", false},
	} {
		if got := endpoint.NonceOK(tt.value); got != tt.ok {
			t.Errorf("NonceOK(%q) = %t, want %t", tt.value, got, tt.ok)
		}
	}
}

func TestEndpointChallengeEchoMatrix(t *testing.T) {
	good := `{"challenge":"` + endpointNonce + `"}`
	base := `{"pad":"","challenge":"` + endpointNonce + `"}`
	padBytes := endpoint.MaxChallengeBytes - len(base)
	pad := strings.Repeat("é", padBytes/2) + strings.Repeat("x", padBytes%2)
	atCap := strings.Replace(base, `"pad":""`, `"pad":"`+pad+`"`, 1)
	for _, tt := range []struct {
		name         string
		status       int
		body, reason string
	}{
		{"200", 200, good, ""}, {"204", 204, good, ""}, {"299", 299, good, ""},
		{"199", 199, good, "status"}, {"300", 300, good, "status"}, {"500-before-size", 500, atCap + " ", "status"},
		{"empty", 200, "", "json"}, {"bad-json", 200, "not json", "json"}, {"trailing", 200, good + "{}", "json"},
		{"array", 200, `[1]`, "body"}, {"null", 200, `null`, "body"}, {"scalar", 200, `"challenge"`, "body"},
		{"missing", 200, `{}`, "missing"}, {"non-string", 200, `{"challenge":true}`, "missing"},
		{"null-member", 200, `{"challenge":null}`, "missing"}, {"wrong", 200, `{"challenge":"other"}`, "mismatch"},
		{"case-sensitive", 200, `{"Challenge":"` + endpointNonce + `"}`, "missing"},
		{"duplicate-last", 200, `{"challenge":0,"challenge":"` + endpointNonce + `","ignored":1e999}`, ""},
		{"at-cap", 200, atCap, ""}, {"above-cap", 200, atCap + " ", "too_large"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := ""
			if tt.reason != "" {
				code = "challenge_failed"
			}
			assertEndpointError(t, endpoint.ChallengeEcho(tt.status, tt.body, endpointNonce), code, tt.reason)
		})
	}
}

func TestEndpointPairKeyAndEchoPrecedence(t *testing.T) {
	const url = "https://hooks.example.test/hooks"
	valid := []any{"alice", url}
	object := map[string]any{"url": url, "principal": "alice", "extra": true}
	for _, value := range []any{valid, object, map[string]string{"url": url, "principal": "alice"}} {
		if key, ok := endpoint.PairKey(value); !ok || key != `["alice","`+url+`"]` {
			t.Errorf("PairKey(%#v) = (%q, %t)", value, key, ok)
		}
	}
	const escaped = "[\"<&>\u2028\u2029\",\"\\u0001\\n\\\"\\\\\"]"
	if key, ok := endpoint.PairKey([]any{"<&>\u2028\u2029", "\x01\n\"\\"}); !ok || key != escaped {
		t.Errorf("escaped PairKey = (%q, %t), want %q", key, ok, escaped)
	}
	base := endpoint.EchoInput{Nonce: endpointNonce, Expected: endpointNonce, IssuedAt: 1000, Now: 1600, Pair: valid, ExpectedPair: object}
	assertEndpointError(t, endpoint.AcceptEcho(base), "", "")
	for _, tt := range []struct {
		name, reason string
		mutate       func(*endpoint.EchoInput)
	}{
		{"mismatch-before-expired", "mismatch", func(in *endpoint.EchoInput) { in.Nonce, in.Now, in.Consumed, in.Pair = "wrong", 1601, true, nil }},
		{"expired-before-reused", "expired", func(in *endpoint.EchoInput) { in.Now, in.Consumed, in.Pair = 1601, true, nil }},
		{"reused-before-pair", "reused", func(in *endpoint.EchoInput) { in.Consumed, in.Pair = true, nil }},
		{"principal", "pair", func(in *endpoint.EchoInput) { in.Pair = []any{"bob", url} }},
		{"url", "pair", func(in *endpoint.EchoInput) { in.Pair = []any{"alice", url + "/a"} }},
		{"expected-invalid", "pair", func(in *endpoint.EchoInput) { in.ExpectedPair = nil }},
		{"ttl-shorter", "expired", func(in *endpoint.EchoInput) { in.TTL = 599 }},
		{"ttl-boundary", "", func(in *endpoint.EchoInput) { in.Now, in.TTL = 1001, 1 }},
		{"before-issue", "", func(in *endpoint.EchoInput) { in.Now = 999 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			tt.mutate(&in)
			code := ""
			if tt.reason != "" {
				code = "challenge_failed"
			}
			assertEndpointError(t, endpoint.AcceptEcho(in), code, tt.reason)
		})
	}
	invalid := []any{nil, "alice", 1, []any{}, []any{"alice"}, []any{"alice", url, true}, []any{1, url}, []any{"alice", nil},
		[]any{"", url}, []any{"alice", ""}, []any{"", ""}, map[string]any{}, map[string]any{"principal": "alice"},
		map[string]any{"Principal": "alice", "url": url}, map[string]any{"principal": "alice", "url": true}, []any{"\xff", url},
	}
	for _, value := range invalid {
		if key, ok := endpoint.PairKey(value); key != "" || ok {
			t.Errorf("accepted invalid pair %#v as %q", value, key)
		}
		in := base
		in.Pair, in.ExpectedPair = value, value
		assertEndpointError(t, endpoint.AcceptEcho(in), "challenge_failed", "pair")
	}
}
