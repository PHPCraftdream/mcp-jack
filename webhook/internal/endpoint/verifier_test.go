package endpoint_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

const endpointURL = "https://hooks.example.test/hooks/a"

func TestEndpointAllowlistParsingAndMatching(t *testing.T) {
	for _, tt := range []struct {
		text, host string
		port       int
		path       string
	}{
		{"https://HOOKS.example.test.:443/hooks", "hooks.example.test", 443, "/hooks"},
		{"https://hooks.example.test?", "hooks.example.test", 443, "/"},
		{"https://[2001:0DB8::1]:8443", "[2001:db8::1]", 8443, "/"},
		{"https://*.Example.test.:65535/hooks/", "*.example.test", 65535, "/hooks/"},
		{"https://*.example.test", "*.example.test", 443, "/"},
		{"https://*.example.test:1", "*.example.test", 1, "/"},
		{"https://*.example.test/a/../b", "*.example.test", 443, "/a/../b"},
	} {
		want := endpoint.AllowlistEntry{HostPattern: tt.host, Port: tt.port, Path: tt.path}
		if got, ok := endpoint.ParseAllowlistEntry(tt.text); !ok || got != want {
			t.Errorf("ParseAllowlistEntry(%q) = (%+v, %t), want %+v", tt.text, got, ok, want)
		}
	}
	for _, text := range []string{
		"http://hooks.example.test", "HTTPS://hooks.example.test", "https://", "https://hooks.example.test/x?y=1",
		"https://hooks.example.test/#f", "https://user@hooks.example.test", "https://hooks.example.test/%2E",
		"https://*.example.test?", "https://*.example.test/#f", "https://*.example.test/with space",
		"https://*.example.test/é", "https://*.example.test/\x7f", "https://*.example.test/\n", "https://*.a@b.test",
		"https://*.127.0.0.1", "https://*.[2001:db8::1]", "https://*.test", "https://*..example.test",
		"https://*.example.test:0", "https://*.example.test:0443", "https://*.example.test:65536",
		"https://*.example.test:+443", "https://*.example.test:44x", "https://*.example.test:",
	} {
		if got, ok := endpoint.ParseAllowlistEntry(text); ok || got != (endpoint.AllowlistEntry{}) {
			t.Errorf("accepted %q: %+v", text, got)
		}
	}

	const literal = "https://hooks.example.test/hooks"
	const wildcard = "https://*.example.test/hooks"
	for _, tt := range []struct {
		entry, url string
		ok         bool
	}{
		{literal, endpointURL, true}, {literal, literal, true}, {literal, literal + "x", false},
		{literal, literal + "%2Fa", false}, {literal, "https://HOOKS.EXAMPLE.TEST.:443/hooks/a?x=1", true},
		{literal, "https://hooks.example.test:8443/hooks", false}, {literal, "https://hooks.example.test/Hooks/a", false},
		{literal, "http://hooks.example.test/hooks", false}, {literal, literal + "/.%2e/a", false},
		{literal + "/", literal, false}, {literal + "/", endpointURL, true},
		{"https://hooks.example.test/", "https://hooks.example.test/other", true},
		{wildcard, "https://a.b.example.test/hooks", true}, {wildcard, "https://a.example.test/hooks", true},
		{wildcard, "https://example.test/hooks", false}, {wildcard, "https://notexample.test/hooks", false},
		{wildcard, "https://a.example.test.evil.test/hooks", false}, {wildcard, "https://a.example.test:8443/hooks", false},
		{"https://*.example.test:8443/hooks", "https://a.example.test:8443/hooks/a", true},
	} {
		got, ok := endpoint.AllowlistMatches([]string{"bad", tt.entry}, tt.url)
		if ok != tt.ok || (!ok && got != (endpoint.AllowlistEntry{})) {
			t.Errorf("AllowlistMatches(%q, %q) = (%+v, %t), want match %t", tt.entry, tt.url, got, ok, tt.ok)
		}
	}
	if got, ok := endpoint.AllowlistMatches([]string{wildcard, literal}, endpointURL); !ok || got.HostPattern != "*.example.test" {
		t.Errorf("first match = (%+v, %t)", got, ok)
	}
}

func TestEndpointPureRouteAndGateOrder(t *testing.T) {
	in := endpoint.RouteInput{
		Cache: true, Allowlist: []string{"https://hooks.example.test/hooks"}, URL: endpointURL,
		Hook: true, Doc: []string{"/hooks/"}, DocPath: "/hooks/a", Challenge: &endpoint.Error{},
	}
	for _, tt := range []struct {
		want string
		next func(*endpoint.RouteInput)
	}{
		{"cache", func(in *endpoint.RouteInput) { in.Cache = false }},
		{"allowlist", func(in *endpoint.RouteInput) { in.URL = "https://other.example.test/hooks/a" }},
		{"out_of_band", func(in *endpoint.RouteInput) { in.Hook = false }},
		{"well_known", func(in *endpoint.RouteInput) { in.DocPath = "/hooks" }},
		{"challenge", func(in *endpoint.RouteInput) {
			in.Challenge = &endpoint.Error{Code: "challenge_failed", Reason: "mismatch"}
		}},
	} {
		if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Verified: true, Route: tt.want}) {
			t.Errorf("route = %+v, want %q", got, tt.want)
		}
		tt.next(&in)
	}
	if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Reason: "mismatch"}) {
		t.Errorf("failed challenge route = %+v", got)
	}
	in.Challenge = nil
	if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Reason: "no_route"}) {
		t.Errorf("absent challenge route = %+v", got)
	}
	for _, verified := range []bool{false, true} {
		for _, msg := range []string{"verification", "event", "gap", "terminated"} {
			want := "refuse"
			if msg == "verification" {
				want = "send-challenge"
			} else if verified {
				want = "deliver"
			}
			if got := endpoint.Gate(endpoint.GateInput{Verified: verified, Message: msg}); got != want {
				t.Errorf("Gate(%t, %q) = %q, want %q", verified, msg, got, want)
			}
		}
	}
}

func newEndpointVerifier(t *testing.T, cfg endpoint.Config) *endpoint.Verifier {
	t.Helper()
	v, err := endpoint.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEndpointVerifierCacheAllowlistAndHook(t *testing.T) {
	ctx := context.Background()
	cache := endpoint.NewCache()
	cache.Put("alice", endpointURL, time.Hour)
	if !cache.Get("alice", endpointURL) || cache.Get("bob", endpointURL) || cache.Get("alice", endpointURL+"/other") {
		t.Fatal("verification must be keyed by both principal and canonical URL")
	}
	var calls []string
	cfg := endpoint.Config{
		Cache:     cache,
		Allowlist: []string{"https://hooks.example.test/hooks"},
		Hook: func(_ context.Context, principal, url string) (bool, error) {
			calls = append(calls, "hook:"+principal+":"+url)
			return true, nil
		},
		Challenge: func(context.Context, string, string) error {
			t.Fatal("challenge should have been bypassed")
			return nil
		},
	}
	v := newEndpointVerifier(t, cfg)
	for _, p := range []string{"alice", "bob"} {
		assertEndpointError(t, v.Verify(ctx, p, endpointURL), "", "")
		if !cache.Get(p, endpointURL) {
			t.Errorf("missing cached verification for %s", p)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("unexpected hook calls: %v", calls)
	}
	cfg.Allowlist = nil
	cfg.Cache = nil
	now := int64(1000)
	cfg.Now = func() int64 { return now }
	v = newEndpointVerifier(t, cfg)
	assertEndpointError(t, v.Verify(ctx, "alice", endpointURL), "", "")
	now += 3599
	assertEndpointError(t, v.Verify(ctx, "alice", endpointURL), "", "")
	if len(calls) != 1 {
		t.Fatalf("cache did not short-circuit hook: %v", calls)
	}
	now++
	assertEndpointError(t, v.Verify(ctx, "alice", endpointURL), "", "")
	if len(calls) != 2 || calls[0] != "hook:alice:"+endpointURL || calls[0] != calls[1] {
		t.Fatalf("unexpected hook calls: %v", calls)
	}
	cache.Put("alice", endpointURL, 0)
	if cache.Get("alice", endpointURL) {
		t.Fatal("zero TTL should remove verification")
	}
}

func TestEndpointVerifierChallengeFallbackAndSanitization(t *testing.T) {
	// A loopback IP literal is rejected by delivery before any dial or DNS lookup.
	const blocked = "https://127.0.0.1/hooks"
	const raw = "private endpoint response"
	for _, tt := range []struct {
		name         string
		challengeErr error
		code, reason string
	}{
		{"success", nil, "", ""},
		{"typed-nil-echo", (*endpoint.Error)(nil), "", ""},
		{"wrapped-nil-echo", fmt.Errorf("%s: %w", raw, (*endpoint.Error)(nil)), "challenge_failed", ""},
		{"typed-nil-delivery-error", (*delivery.Error)(nil), "challenge_failed", ""},
		{"mismatch", fmt.Errorf("%s: %w", raw, &endpoint.Error{Code: "challenge_failed", Reason: "mismatch"}), "challenge_failed", "mismatch"},
		{"redact-echo", &endpoint.Error{Code: "challenge_failed", Reason: raw}, "challenge_failed", ""},
		{"generic", errors.New(raw), "challenge_failed", ""},
		{"body-cap", &delivery.Error{Code: "too_large"}, "challenge_failed", "too_large"},
		{"timeout", fmt.Errorf("%s: %w", raw, context.DeadlineExceeded), "timeout", ""},
		{"timeout-code", errors.New("timeout"), "timeout", ""},
		{"connection", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "connection_refused", ""},
		{"blocked", &delivery.Error{Code: "blocked_address", Reason: raw}, "connection_refused", ""},
		{"rebinding", &delivery.Error{Code: "dns_rebinding", Reason: raw}, "connection_refused", ""},
		{"dns", &delivery.Error{Code: "no_answer", Reason: "no_records"}, "connection_refused", ""},
		{"tls", tls.RecordHeaderError{Msg: raw}, "tls_error", ""},
		{"tls-code", &delivery.Error{Code: "tls_error", Err: errors.New(raw)}, "tls_error", ""},
		{"http-4xx", &endpoint.Error{Code: "http_4xx", Reason: raw}, "http_4xx", ""},
		{"redirect", &delivery.Error{Code: "redirect_refused", Reason: "status_302"}, "http_4xx", ""},
		{"non-echo-5xx", &delivery.Error{Code: "http_5xx", Reason: raw}, "challenge_failed", "status"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, hookErr := range []error{nil, errors.New(raw)} {
				var calls []string
				v := newEndpointVerifier(t, endpoint.Config{
					Hook: func(context.Context, string, string) (bool, error) {
						calls = append(calls, "hook")
						return hookErr != nil, hookErr // true with an error is not confirmation.
					},
					Challenge: func(_ context.Context, p, url string) error {
						calls = append(calls, "challenge")
						if p != "alice" || url != blocked {
							t.Errorf("unexpected challenge pair: (%q, %q)", p, url)
						}
						return tt.challengeErr
					},
				})
				err := v.Verify(context.Background(), "alice", blocked)
				assertEndpointError(t, err, tt.code, tt.reason)
				if err != nil && strings.Contains(err.Error(), raw) {
					t.Fatal("raw error leaked")
				}
				if len(calls) != 2 || calls[0] != "hook" || calls[1] != "challenge" {
					t.Fatalf("unexpected call order: %v", calls)
				}
				if err == nil {
					assertEndpointError(t, v.Verify(context.Background(), "alice", blocked), "", "")
					if len(calls) != 2 {
						t.Fatalf("successful challenge was not cached: %v", calls)
					}
				}
			}
		})
	}
	v := newEndpointVerifier(t, endpoint.Config{})
	assertEndpointError(t, v.Verify(context.Background(), "alice", blocked), "challenge_failed", "no_route")
	_, err := v.FetchDoc(context.Background(), blocked)
	assertEndpointError(t, err, "blocked_address", "loopback")
	assertEndpointError(t, v.Verify(context.Background(), "alice", endpointURL+"/%2E%2e"), "invalid_callback_url", "dot_segment")
}
