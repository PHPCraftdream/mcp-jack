package ipaddr_test

import (
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
)

// TestIPAddrParseForms checks the literal spellings of R6.3, R6.4 and R6.7: only
// the canonical dotted quad and the hex-group IPv6 forms are literals, and every
// other spelling is refused rather than reinterpreted.
func TestIPAddrParseForms(t *testing.T) {
	v4Good := []string{"0.0.0.0", "255.255.255.255", "192.0.2.1", "8.8.8.8", "0.0.0.9", "100.64.0.1"}
	for _, text := range v4Good {
		bytes, ok := ipaddr.ParseIPv4(text)
		if !ok {
			t.Fatalf("ParseIPv4(%q) failed", text)
		}
		if got := ipaddr.FormatIPv4(bytes); got != text {
			t.Fatalf("ParseIPv4(%q) formats back as %q", text, got)
		}
	}
	if bytes, ok := ipaddr.ParseIPv4("255.0.1.7"); !ok || bytes != [4]byte{255, 0, 1, 7} {
		t.Fatalf("ParseIPv4(%q) = %v, %t", "255.0.1.7", bytes, ok)
	}

	v4Bad := []string{
		"", "127.0.0.01", "0177.0.0.1", "127.1", "2130706433", "0x7f.0.0.1", "1.2.3.4.5",
		"1.2.3", "1.2.3.4.", ".1.2.3", "1.2.3.", "1..2.3", "256.0.0.1", "1.2.3.256",
		"+1.2.3.4", "-1.2.3.4", " 1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", "1,2,3,4",
		"1.2.3.4/32", "١.2.3.4",
	}
	for _, text := range v4Bad {
		if bytes, ok := ipaddr.ParseIPv4(text); ok {
			t.Fatalf("ParseIPv4(%q) = %v, want a refusal", text, bytes)
		}
	}

	// R6.3: the non-literal spellings are never reinterpreted as an address, so
	// the literal-only entry point refuses them too.
	addressBad := []string{
		"127.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "1.2.3.4.5", "a..b",
		"", "[]", "[::1", "::1]", "hooks.example.test", "[127.0.0.1]x",
	}
	for _, text := range addressBad {
		if parsed, ok := ipaddr.ParseAddress(text); ok {
			t.Fatalf("ParseAddress(%q) = %+v, want a refusal", text, parsed)
		}
	}
	if parsed, ok := ipaddr.ParseAddress("[::ffff:1.2.3.4]"); !ok ||
		parsed.Family != "ipv6" || parsed.Address != "::ffff:1.2.3.4" {
		t.Fatalf("ParseAddress(%q) = %+v, %t", "[::ffff:1.2.3.4]", parsed, ok)
	}
	if parsed, ok := ipaddr.ParseAddress("[10.1.2.3]"); !ok ||
		parsed.Family != "ipv4" || parsed.Address != "10.1.2.3" {
		t.Fatalf("ParseAddress(%q) = %+v, %t", "[10.1.2.3]", parsed, ok)
	}

	v6Good := []struct {
		text string
		want string
	}{
		{"::", "::"},
		{"::1", "::1"},
		{"1::", "1::"},
		{"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
		{"1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"},
		{"::1:2:3:4:5:6:7", "0:1:2:3:4:5:6:7"},
		{"2001:db8::1", "2001:db8::1"},
		{"ABCD::1", "abcd::1"},
		{"2606:4700:4700::1111", "2606:4700:4700::1111"},
		{"fe80::1", "fe80::1"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},
		{"0:0:0:0:0:ffff:1.2.3.4", "::ffff:1.2.3.4"},
		{"::1.2.3.4", "::102:304"},
		{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
	}
	for _, tc := range v6Good {
		bytes, ok := ipaddr.ParseIPv6(tc.text)
		if !ok {
			t.Fatalf("ParseIPv6(%q) failed", tc.text)
		}
		if got := ipaddr.FormatIPv6(bytes); got != tc.want {
			t.Fatalf("ParseIPv6(%q) formats as %q, want %q", tc.text, got, tc.want)
		}
		again, ok := ipaddr.ParseIPv6(tc.want)
		if !ok || again != bytes {
			t.Fatalf("the canonical form %q of %q does not parse back to the same bytes", tc.want, tc.text)
		}
	}
	if bytes, ok := ipaddr.ParseIPv6("1:2:3:4:5:6:7:8"); !ok ||
		bytes != [16]byte{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8} {
		t.Fatalf("ParseIPv6(%q) = %v, %t", "1:2:3:4:5:6:7:8", bytes, ok)
	}
	if bytes, ok := ipaddr.ParseIPv6("::ffff:1.2.3.4"); !ok ||
		bytes != [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4} {
		t.Fatalf("ParseIPv6(%q) = %v, %t", "::ffff:1.2.3.4", bytes, ok)
	}

	v6Bad := []string{
		"", ":", ":::", "::1::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
		"1:2:3:4:5:6:7::8", "::1.2.3.4.5", "1:2:3:4:5:6:7:1.2.3.4", "1.2.3.4::",
		"1:2:3:4:5:1.2.3.4:7:8", "1::2.3.4", "[::1]", "::1%eth0", "fe80::1%25eth0",
		"12345::", "::g", "1:2:3:4:5:6:7:", ":1:2:3:4:5:6:7", " ::1", "::1 ",
		"::ffff:1.2.3.04", "::ffff:1.2.3.4:", "0x1::",
	}
	for _, text := range v6Bad {
		if bytes, ok := ipaddr.ParseIPv6(text); ok {
			t.Fatalf("ParseIPv6(%q) = %v, want a refusal", text, bytes)
		}
	}
}

// TestIPAddrFormatIPv6 checks the RFC 5952 form of R6.6: lowercase, no leading
// zeros, the longest zero run of at least two groups compressed (first run on a
// tie), and the mapped shape kept as a dotted quad.
func TestIPAddrFormatIPv6(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"::", "::"},
		{"0:0:0:0:0:0:0:0", "::"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"1:0:0:1:0:0:1:1", "1::1:0:0:1:1"},
		{"0:0:1:0:0:1:0:0", "::1:0:0:1:0:0"},
		{"1:0:1:1:1:1:1:1", "1:0:1:1:1:1:1:1"},
		{"0:1:2:3:4:5:6:7", "0:1:2:3:4:5:6:7"},
		{"1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:0"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},
		{"::ffff:0:0", "::ffff:0.0.0.0"},
		{"ABCD:EF01::", "abcd:ef01::"},
		{"fe80::1:2:3", "fe80::1:2:3"},
		{"2606:4700:4700::1111", "2606:4700:4700::1111"},
	}
	for _, tc := range cases {
		bytes, ok := ipaddr.ParseIPv6(tc.text)
		if !ok {
			t.Fatalf("ParseIPv6(%q) failed", tc.text)
		}
		got := ipaddr.FormatIPv6(bytes)
		if got != tc.want {
			t.Fatalf("FormatIPv6(ParseIPv6(%q)) = %q, want %q", tc.text, got, tc.want)
		}
	}
}
