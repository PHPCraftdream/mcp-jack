package urlcheck_test

import (
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

func TestURLCheckCanonicalForms(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      urlcheck.URL
	}{
		{"empty_path", "https://hooks.example.test", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 443, Path: "/",
			Canonical: "https://hooks.example.test/", HostKind: "name", HostValue: "hooks.example.test",
		}},
		{"uppercase_scheme_and_host_default_port", "HTTPS://HOOKS.Example.Test:443/Hook", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 443, Path: "/Hook",
			Canonical: "https://hooks.example.test/Hook", HostKind: "name", HostValue: "hooks.example.test",
		}},
		{"trailing_dot_non_default_port_query", "https://hooks.example.test.:8443/Hook%2Fa?x=a+b%2F?y=@", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 8443, Path: "/Hook%2Fa", Query: "x=a+b%2F?y=@",
			Canonical: "https://hooks.example.test:8443/Hook%2Fa?x=a+b%2F?y=@", HostKind: "name", HostValue: "hooks.example.test",
		}},
		{"query_only", "https://hooks.example.test?x=%2e%2E", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 443, Path: "/", Query: "x=%2e%2E",
			Canonical: "https://hooks.example.test/?x=%2e%2E", HostKind: "name", HostValue: "hooks.example.test",
		}},
		{"empty_query", "https://hooks.example.test/?", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 443, Path: "/",
			Canonical: "https://hooks.example.test/", HostKind: "name", HostValue: "hooks.example.test",
		}},
		{"bracketed_ipv6_minimum_port", "https://[2001:0DB8:0:0:0:0:0:1]:1/v6", urlcheck.URL{
			Scheme: "https", Host: "[2001:db8::1]", Port: 1, Path: "/v6",
			Canonical: "https://[2001:db8::1]:1/v6", HostKind: "ipv6", HostValue: "2001:db8::1",
		}},
		{"ipv4_maximum_port", "https://192.0.2.7:65535", urlcheck.URL{
			Scheme: "https", Host: "192.0.2.7", Port: 65535, Path: "/",
			Canonical: "https://192.0.2.7:65535/", HostKind: "ipv4", HostValue: "192.0.2.7",
		}},
		{"dots_within_segment", "https://hooks.example.test/a.b/file%2Ejson/%252e", urlcheck.URL{
			Scheme: "https", Host: "hooks.example.test", Port: 443, Path: "/a.b/file%2Ejson/%252e",
			Canonical: "https://hooks.example.test/a.b/file%2Ejson/%252e", HostKind: "name", HostValue: "hooks.example.test",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := urlcheck.Check(tc.raw)
			if err != nil || got != tc.want {
				t.Fatalf("Check(%q) = (%+v, %v), want (%+v, nil)", tc.raw, got, err, tc.want)
			}
			if canonical, ok := urlcheck.Canonical(tc.raw); !ok || canonical != got.Canonical {
				t.Errorf("Canonical(%q) = (%q, %t), want (%q, true)", tc.raw, canonical, ok, got.Canonical)
			}
		})
	}
}

func TestURLCheckReferenceRefusals(t *testing.T) {
	const (
		scheme   = urlcheck.CodeSchemeNotHTTPS
		invalid  = urlcheck.CodeInvalidCallbackURL
		notAHost = urlcheck.CodeNotAHostname
	)
	for _, tc := range []struct {
		name, raw, code, reason string
	}{
		{"http", "http://hooks.example.test", scheme, ""},
		{"ftp", "ftp://hooks.example.test", scheme, ""},
		{"no_scheme", "hooks.example.test/path", scheme, ""},
		{"empty_scheme", "://hooks.example.test", scheme, ""},
		{"first_marker", "http://https://hooks.example.test", scheme, ""},
		{"userinfo", "https://user:pass@hooks.example.test/", invalid, "userinfo"},
		{"fragment", "https://hooks.example.test/?x=1#frag", invalid, "fragment"},
		{"empty_host", "https:///path", invalid, "empty_host"},
		{"zero_port", "https://hooks.example.test:0/", invalid, "port"},
		{"high_port", "https://hooks.example.test:65536/", invalid, "port"},
		{"leading_zero_port", "https://hooks.example.test:0443/", invalid, "port"},
		{"non_numeric_port", "https://hooks.example.test:4x3/", invalid, "port"},
		{"signed_port", "https://hooks.example.test:+443/", invalid, "port"},
		{"empty_port", "https://hooks.example.test:/", invalid, "port"},
		{"space", "https://hooks.example.test/?x=a b", invalid, "character"},
		{"control", "https://hooks.example.test/\x00", invalid, "character"},
		{"del", "https://hooks.example.test/\x7f", invalid, "character"},
		{"non_ascii", "https://hooks.example.test/\xff", invalid, "character"},
		{"stray_bracket", "https://hooks.example.test]/", invalid, "host"},
		{"missing_close_bracket", "https://[2001:db8::1:bad/", invalid, "host"},
		{"after_close_bracket", "https://[2001:db8::1]extra/", invalid, "host"},
		{"too_many_colons", "https://hooks.example.test:443:8443/", invalid, "host"},
		{"short_numeric_host", "https://192.0.2/", notAHost, "not_a_hostname"},
		{"empty_host_text_with_port", "https://:443/", notAHost, "not_a_hostname"},
		// A tail not starting with '/' or '?' cannot reach the path check:
		// a backslash instead of a leading slash is part of the authority.
		{"malformed_path", `https://hooks.example.test\webhook`, notAHost, "not_a_hostname"},
		{"dot", "https://hooks.example.test/a/./b", invalid, "dot_segment"},
		{"dot_dot", "https://hooks.example.test/a/..", invalid, "dot_segment"},
		{"encoded_dot", "https://hooks.example.test/%2e?x=1", invalid, "dot_segment"},
		{"encoded_dot_dot", "https://hooks.example.test/a/%2E%2e/", invalid, "dot_segment"},
		{"mixed_dot_dot", "https://hooks.example.test/a/.%2E/", invalid, "dot_segment"},
		{"character_before_scheme", "http://hooks.example.test/\t", invalid, "character"},
		{"scheme_before_userinfo", "http://user@hooks.example.test/#frag", scheme, ""},
		{"userinfo_before_fragment", "https://user@hooks.example.test/#frag", invalid, "userinfo"},
		{"fragment_before_empty_host", "https://#frag", invalid, "fragment"},
		{"split_before_port", "https://hooks.example.test:bad:443/", invalid, "host"},
		{"port_before_host", "https://[invalid]:bad/", invalid, "port"},
		{"host_before_dot_segment", "https://invalid/..", notAHost, "not_a_hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := urlcheck.Check(tc.raw)
			want := urlcheck.Error{Code: tc.code, Reason: tc.reason}
			if got != (urlcheck.URL{}) || err == nil || *err != want {
				t.Fatalf("Check(%q) = (%+v, %+v), want (zero URL, %+v)", tc.raw, got, err, want)
			}
			wantText := tc.code
			if tc.reason != "" {
				wantText += ": " + tc.reason
			}
			if got := err.Error(); got != wantText {
				t.Errorf("Error() = %q, want %q", got, wantText)
			}
			if canonical, ok := urlcheck.Canonical(tc.raw); ok || canonical != "" {
				t.Errorf("Canonical(%q) = (%q, %t), want (empty string, false)", tc.raw, canonical, ok)
			}
		})
	}
}
