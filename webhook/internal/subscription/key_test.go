package subscription_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/subscription"
)

func TestSubscriptionKeyWorkedExamples(t *testing.T) {
	for _, tc := range []struct {
		url, name string
		args      any
		id, canon string
		input     string
	}{
		{
			url:   "https://hooks.example.test/hooks/alice",
			name:  "incident.created",
			args:  map[string]any{"severity": "P1"},
			id:    "sub_10dd9b3f501b751f",
			canon: `{"severity":"P1"}`,
			input: `["mcp-jack/webhook1/subscription","alice","https://hooks.example.test/hooks/alice","incident.created",{"severity":"P1"}]`,
		},
		{
			url:   "https://hooks.example.test:8443/hooks/alice?tenant=1",
			name:  "email.received",
			id:    "sub_ce48aa2e898723ea",
			canon: "null",
			input: `["mcp-jack/webhook1/subscription","alice","https://hooks.example.test:8443/hooks/alice?tenant=1","email.received",null]`,
		},
	} {
		got, err := subscription.SubscriptionKey("alice", tc.url, tc.name, tc.args)
		want := subscription.Key{ID: tc.id, CanonicalURL: tc.url, CanonicalArguments: tc.canon, JCSInput: tc.input}
		if err != nil || got != want {
			t.Errorf("SubscriptionKey(%q) = %+v, %v; want %+v", tc.name, got, err, want)
		}
	}
}

func TestSubscriptionKeyCanonicalURL(t *testing.T) {
	const canonical = "https://hooks.example.test/hooks/alice"
	for _, tc := range []struct{ url, want, id string }{
		{"https://HOOKS.Example.Test/hooks/alice", canonical, "sub_10dd9b3f501b751f"},
		{"https://hooks.example.test:443/hooks/alice", canonical, "sub_10dd9b3f501b751f"},
		{"https://hooks.example.test./hooks/alice", canonical, "sub_10dd9b3f501b751f"},
		{"HTTPS://HOOKS.Example.Test.:443", "https://hooks.example.test/", "sub_4f9e3201ec2038a1"},
	} {
		got, err := subscription.SubscriptionKey("alice", tc.url, "incident.created", map[string]any{"severity": "P1"})
		if err != nil || got.CanonicalURL != tc.want || got.ID != tc.id {
			t.Errorf("SubscriptionKey(%q) = %+v, %v; want canonical URL %q and ID %q", tc.url, got, err, tc.want, tc.id)
		}
	}
}

func TestSubscriptionKeyRefusals(t *testing.T) {
	const valid = "https://hooks.example.test/hooks/alice"
	for _, tc := range []struct {
		url  string
		args any
		want subscription.KeyError
	}{
		{"http://hooks.example.test/hooks/alice", nil, subscription.KeyError{Code: "scheme_not_https"}},
		{"https://alice@hooks.example.test/hooks/alice", nil, subscription.KeyError{Code: "invalid_callback_url", Reason: "userinfo"}},
		{"https://hooks.example.test/hooks/../alice", nil, subscription.KeyError{Code: "invalid_callback_url", Reason: "dot_segment"}},
		{valid, 1, subscription.KeyError{Code: "invalid_arguments", Reason: "arguments"}},
		{valid, map[string]any{"x": math.Inf(1)}, subscription.KeyError{Code: "invalid_arguments", Reason: "arguments"}},
	} {
		got, err := subscription.SubscriptionKey("alice", tc.url, "incident.created", tc.args)
		if got != (subscription.Key{}) || err == nil || *err != tc.want {
			t.Errorf("SubscriptionKey(%q, %#v) = %+v, %v; want a zero key and %+v", tc.url, tc.args, got, err, tc.want)
		}
	}
}

func TestSubscriptionKeyAbsentEqualsNull(t *testing.T) {
	const url = "https://hooks.example.test/hooks/alice"
	var explicit any
	if err := json.Unmarshal([]byte("null"), &explicit); err != nil {
		t.Fatal(err)
	}
	absent, absentErr := subscription.SubscriptionKey("alice", url, "incident.created", nil)
	present, presentErr := subscription.SubscriptionKey("alice", url, "incident.created", explicit)
	if absentErr != nil || presentErr != nil || absent != present || absent.ID != "sub_0712b9ec0b6c804d" || absent.CanonicalArguments != "null" {
		t.Fatalf("absent = %+v, %v; explicit null = %+v, %v; want equal null keys", absent, absentErr, present, presentErr)
	}
}
