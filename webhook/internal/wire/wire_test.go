package wire_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

// ptr returns a pointer to s, for the cursor cases of ValidCursor.
func ptr(s string) *string {
	return &s
}

func TestValidWebhookID(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"seven characters", "abcdefg", false},
		{"eight characters", "abcdefgh", true},
		{"one hundred twenty eight characters", strings.Repeat("a", 128), true},
		{"one hundred twenty nine characters", strings.Repeat("a", 129), false},
		{"dot", ".", false},
		{"embedded dot", "abcd.efgh", false},
		{"space", " ", false},
		{"embedded space", "abcd efgh", false},
		{"slash", "/", false},
		{"embedded slash", "abcd/efgh", false},
		{"hyphen", "abcd-efg", true},
		{"underscore", "abcd_efg", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidWebhookID(tc.value); got != tc.want {
				t.Fatalf("ValidWebhookID(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidTimestamp(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"zero", "0", true},
		{"double zero", "00", false},
		{"negative", "-1", false},
		{"thirteen digits", "1234567890123", false},
		{"sample second", "1767225600", true},
		{"twelve digit boundary", "999999999999", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidTimestamp(tc.value); got != tc.want {
				t.Fatalf("ValidTimestamp(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  int64
		ok    bool
	}{
		{"zero", "0", 0, true},
		{"sample second", "1767225600", 1767225600, true},
		{"twelve digit boundary", "999999999999", 999999999999, true},
		{"double zero", "00", 0, false},
		{"negative", "-1", 0, false},
		{"thirteen digits", "1234567890123", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := wire.ParseTimestamp(tc.value)
			if ok != tc.ok {
				t.Fatalf("ParseTimestamp(%q) ok = %v, want %v", tc.value, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("ParseTimestamp(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidSubscriptionID(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"valid", "sub_a3f1c8e2b0d49f7e", true},
		{"uppercase hex", "sub_A3F1C8E2B0D49F7E", false},
		{"fifteen hex digits", "sub_a3f1c8e2b0d49f7", false},
		{"seventeen hex digits", "sub_a3f1c8e2b0d49f7e0", false},
		{"missing prefix", "a3f1c8e2b0d49f7e", false},
		{"trailing newline", "sub_a3f1c8e2b0d49f7e\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidSubscriptionID(tc.value); got != tc.want {
				t.Fatalf("ValidSubscriptionID(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidNonce(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"twenty one characters", strings.Repeat("a", 21), false},
		{"base64url", "QUJDREVGR0hJSktMTU5PUA", true},
		{"twenty three characters", strings.Repeat("a", 23), false},
		{"plus character", strings.Repeat("a", 21) + "+", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidNonce(tc.value); got != tc.want {
				t.Fatalf("ValidNonce(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidCursor(t *testing.T) {
	cases := []struct {
		name  string
		value *string
		want  bool
	}{
		{"nil", nil, true},
		{"empty", ptr(""), false},
		{"512 printable bytes", ptr(strings.Repeat("a", 510) + "!~"), true},
		{"513 printable bytes", ptr(strings.Repeat("a", 513)), false},
		{"space byte", ptr("abc def"), false},
		{"delete byte", ptr("abc\x7fdef"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wire.ValidCursor(tc.value); got != tc.want {
				t.Fatalf("ValidCursor = %v, want %v", got, tc.want)
			}
		})
	}
}
