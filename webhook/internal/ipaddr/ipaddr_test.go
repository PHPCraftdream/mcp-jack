package ipaddr_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
)

// TestIPAddrParseHostForms checks every spelling class of R6.3: the canonical
// dotted quad, the bracketed IPv6 literal and the ASCII LDH name, and the
// refusal of every numeric, octal, hex, short, over-long, empty-label and
// non-ASCII form without reinterpretation.
func TestIPAddrParseHostForms(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	tooLongLabel := strings.Repeat("a", 64)
	name253 := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61),
	}, ".")
	name254 := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 62),
	}, ".")
	if len(name253) != 253 || len(name254) != 254 {
		t.Fatalf("test names are %d and %d bytes, want 253 and 254", len(name253), len(name254))
	}

	cases := []struct {
		host       string
		ok         bool
		kind       string
		address    string
		normalized string
		reason     string
	}{
		{host: "hooks.example.test", ok: true, kind: "name", address: "hooks.example.test", normalized: "hooks.example.test"},
		{host: "hooks.example.test.", ok: true, kind: "name", address: "hooks.example.test", normalized: "hooks.example.test"},
		{host: "HOOKS.Example.Test", ok: true, kind: "name", address: "hooks.example.test", normalized: "hooks.example.test"},
		{host: "HOOKS.Example.Test.", ok: true, kind: "name", address: "hooks.example.test", normalized: "hooks.example.test"},
		{host: "foo.bar", ok: true, kind: "name", address: "foo.bar", normalized: "foo.bar"},
		{host: "2022.example.test", ok: true, kind: "name", address: "2022.example.test", normalized: "2022.example.test"},
		{host: "example.123a", ok: true, kind: "name", address: "example.123a", normalized: "example.123a"},
		{host: longLabel + ".test", ok: true, kind: "name", address: longLabel + ".test", normalized: longLabel + ".test"},
		{host: name253, ok: true, kind: "name", address: name253, normalized: name253},
		{host: "[2606:4700:4700::1111]", ok: true, kind: "ipv6", address: "2606:4700:4700::1111", normalized: "[2606:4700:4700::1111]"},
		{host: "[ABCD::1]", ok: true, kind: "ipv6", address: "abcd::1", normalized: "[abcd::1]"},
		{host: "[::1]", ok: true, kind: "ipv6", address: "::1", normalized: "[::1]"},
		{host: "[::ffff:1.2.3.4]", ok: true, kind: "ipv6", address: "::ffff:1.2.3.4", normalized: "[::ffff:1.2.3.4]"},
		{host: "198.51.100.7", ok: true, kind: "ipv4", address: "198.51.100.7", normalized: "198.51.100.7"},
		{host: "127.0.0.1", ok: true, kind: "ipv4", address: "127.0.0.1", normalized: "127.0.0.1"},
		{host: "0.0.0.0", ok: true, kind: "ipv4", address: "0.0.0.0", normalized: "0.0.0.0"},

		{host: "", ok: false, reason: "not_a_hostname"},
		{host: ".", ok: false, reason: "not_a_hostname"},
		{host: "...", ok: false, reason: "not_a_hostname"},
		{host: "hooks.example.test..", ok: false, reason: "not_a_hostname"},
		{host: "hooks..example.test", ok: false, reason: "not_a_hostname"},
		{host: ".example.test", ok: false, reason: "not_a_hostname"},
		{host: "127.1", ok: false, reason: "not_a_hostname"},
		{host: "2130706433", ok: false, reason: "not_a_hostname"},
		{host: "0x7f.0.0.1", ok: false, reason: "not_a_hostname"},
		{host: "0177.0.0.1", ok: false, reason: "not_a_hostname"},
		{host: "1.2.3.4.5", ok: false, reason: "not_a_hostname"},
		{host: "a..b", ok: false, reason: "not_a_hostname"},
		{host: "-bad.example.test", ok: false, reason: "not_a_hostname"},
		{host: "bad-.example.test", ok: false, reason: "not_a_hostname"},
		{host: "example.-test", ok: false, reason: "not_a_hostname"},
		{host: "example.test-", ok: false, reason: "not_a_hostname"},
		{host: "localhost", ok: false, reason: "not_a_hostname"},
		{host: "foo", ok: false, reason: "not_a_hostname"},
		{host: "example.123", ok: false, reason: "not_a_hostname"},
		{host: "exämple.test", ok: false, reason: "not_a_hostname"},
		{host: tooLongLabel + ".test", ok: false, reason: "not_a_hostname"},
		{host: name254, ok: false, reason: "not_a_hostname"},
		{host: "::1", ok: false, reason: "not_a_hostname"},
		{host: "fe80::1%eth0", ok: false, reason: "not_a_hostname"},
		{host: "bad[host", ok: false, reason: "host"},
		{host: "bad]host", ok: false, reason: "host"},
		{host: "::1]", ok: false, reason: "host"},
		{host: "[::1", ok: false, reason: "host"},
		{host: "[::1]x", ok: false, reason: "host"},
		{host: "[]", ok: false, reason: "host"},
		{host: "[fe80::1%eth0]", ok: false, reason: "host"},
		{host: "[bad::addr]", ok: false, reason: "host"},
		{host: "[2001:db8::1/32]", ok: false, reason: "host"},
	}
	for _, tc := range cases {
		host, reason := ipaddr.ParseHost(tc.host)
		if tc.ok {
			if reason != "" {
				t.Fatalf("ParseHost(%q) failed with reason %q", tc.host, reason)
			}
			if host.Kind != tc.kind || host.Address != tc.address || host.Normalized != tc.normalized {
				t.Fatalf("ParseHost(%q) = {%q %q %q}, want {%q %q %q}",
					tc.host, host.Kind, host.Address, host.Normalized, tc.kind, tc.address, tc.normalized)
			}
			continue
		}
		if reason != tc.reason {
			t.Fatalf("ParseHost(%q) reason = %q, want %q", tc.host, reason, tc.reason)
		}
		if host != (ipaddr.Host{}) {
			t.Fatalf("ParseHost(%q) returned a host alongside reason %q: %+v", tc.host, reason, host)
		}
	}
}

// TestIPAddrCIDR checks the allowedRanges form of R6.11: the prefix bounds, the
// zero-host-bits rule, malformed spellings, containment and the override order.
func TestIPAddrCIDR(t *testing.T) {
	good := []struct {
		text   string
		family string
		prefix int
	}{
		{"10.0.0.0/8", "ipv4", 8},
		{"0.0.0.0/0", "ipv4", 0},
		{"255.255.255.255/32", "ipv4", 32},
		{"192.168.0.0/16", "ipv4", 16},
		{"1.2.3.4/32", "ipv4", 32},
		{"198.18.0.0/15", "ipv4", 15},
		{"::/0", "ipv6", 0},
		{"::1/128", "ipv6", 128},
		{"64:ff9b::/96", "ipv6", 96},
		{"2001:db8::/32", "ipv6", 32},
		{"fc00::/7", "ipv6", 7},
		{"fe80::/10", "ipv6", 10},
		{"2001::/23", "ipv6", 23},
		{"::ffff:0:0/96", "ipv6", 96},
	}
	for _, tc := range good {
		cidr, ok := ipaddr.ParseCIDR(tc.text)
		if !ok {
			t.Fatalf("ParseCIDR(%q) failed", tc.text)
		}
		if cidr.Text != tc.text || cidr.Family != tc.family || cidr.Prefix != tc.prefix {
			t.Fatalf("ParseCIDR(%q) = {%q %q %d}, want {%q %q %d}",
				tc.text, cidr.Text, cidr.Family, cidr.Prefix, tc.text, tc.family, tc.prefix)
		}
		width := 4
		if tc.family == "ipv6" {
			width = 16
		}
		if len(cidr.Bytes) != width {
			t.Fatalf("ParseCIDR(%q) has %d bytes, want %d", tc.text, len(cidr.Bytes), width)
		}
	}

	bad := []string{
		"", "10.0.0.0", "10.0.0.0/", "/8", "10.0.0.0/8/8", "10.0.0.1/8", "10.0.0.0/33",
		"10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/ 8", "10.0.0.0/8 ", "10.0.0.0/08",
		"10.0.0.0/00", "256.0.0.0/8", "::1/129", "2001:db8::1/32",
		"::1/32", "1.2.3.4/0", "abc/8", "-1/8", "1.2.3.4/-1", "10.0.0.0 /8",
		"[10.0.0.0]/8", "::/0128", ":::/0", "::1/128/", "1.2.3.4/32x", "::ffff:0:0/097",
	}
	for _, text := range bad {
		if cidr, ok := ipaddr.ParseCIDR(text); ok {
			t.Fatalf("ParseCIDR(%q) = %+v, want a refusal", text, cidr)
		}
	}

	contains := []struct {
		block   string
		address string
		want    bool
	}{
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "10.0.0.0", true},
		{"10.0.0.0/8", "10.255.255.255", true},
		{"10.0.0.0/8", "11.0.0.0", false},
		{"10.0.0.0/8", "9.255.255.255", false},
		{"192.168.0.0/16", "192.169.0.1", false},
		{"192.168.0.0/16", "192.168.255.255", true},
		{"0.0.0.0/0", "255.255.255.255", true},
		{"1.2.3.4/32", "1.2.3.4", true},
		{"1.2.3.4/32", "1.2.3.5", false},
		{"64:ff9b::/96", "64:ff9b::1", true},
		{"64:ff9b::/96", "64:ff9b:1::1", false},
		{"::/0", "::", true},
		{"::/0", "ffff::1", true},
		{"fe80::/10", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"fe80::/10", "fec0::1", false},
		{"10.0.0.0/8", "::1", false},
		{"10.0.0.0/8", "[10.1.2.3]", true},
		{"10.0.0.0/8", "10.1.2.3:443", false},
		{"10.0.0.0/8", "nope", false},
		{"10.0.0.0/8", "", false},
	}
	for _, tc := range contains {
		cidr, ok := ipaddr.ParseCIDR(tc.block)
		if !ok {
			t.Fatalf("ParseCIDR(%q) failed", tc.block)
		}
		if got := cidr.Contains(tc.address); got != tc.want {
			t.Fatalf("ParseCIDR(%q).Contains(%q) = %t, want %t", tc.block, tc.address, got, tc.want)
		}
	}
	var zero ipaddr.CIDR
	if zero.Contains("10.0.0.1") {
		t.Fatal("a zero CIDR contains an address")
	}

	addresses := []struct {
		text    string
		allow   bool
		reason  string
		family  string
		address string
	}{
		{"8.8.8.8", true, "global", "ipv4", "8.8.8.8"},
		{"93.184.216.34", true, "global", "ipv4", "93.184.216.34"},
		{"127.0.0.1", false, "loopback", "ipv4", "127.0.0.1"},
		{"192.0.0.9", true, "pcp_anycast", "ipv4", "192.0.0.9"},
		{"[10.1.2.3]", false, "private_use", "ipv4", "10.1.2.3"},
		{"[::1]", false, "loopback", "ipv6", "::1"},
		{"::ffff:127.0.0.1", false, "ipv4_mapped/loopback", "ipv6", "::ffff:127.0.0.1"},
		{"64:ff9b::808:808", true, "nat64_well_known", "ipv6", "64:ff9b::808:808"},
		{"nope", false, "not_a_hostname", "", ""},
		{"127.0.0.01", false, "not_a_hostname", "", ""},
		{"2130706433", false, "not_a_hostname", "", ""},
	}
	for _, tc := range addresses {
		got := ipaddr.ClassifyAddress(tc.text)
		if got.Allow != tc.allow || got.Reason != tc.reason || got.Family != tc.family || got.Address != tc.address {
			t.Fatalf("ClassifyAddress(%q) = {%t %q %q %q}, want {%t %q %q %q}",
				tc.text, got.Allow, got.Reason, got.Family, got.Address,
				tc.allow, tc.reason, tc.family, tc.address)
		}
	}

	ranges := []struct {
		text    string
		allowed []string
		allow   bool
		reason  string
		family  string
		address string
	}{
		{"10.1.2.3", []string{"10.0.0.0/8"}, true, "allowed_range", "ipv4", "10.1.2.3"},
		{"10.1.2.3", []string{"192.168.0.0/16", "10.0.0.0/8"}, true, "allowed_range", "ipv4", "10.1.2.3"},
		{"10.1.2.3", []string{"192.168.0.0/16"}, false, "private_use", "ipv4", "10.1.2.3"},
		{"10.1.2.3", []string{"::/0"}, false, "private_use", "ipv4", "10.1.2.3"},
		{"10.1.2.3", nil, false, "private_use", "ipv4", "10.1.2.3"},
		{"10.1.2.3", []string{"10.0.0.0/33", "10.0.0.1/8", "garbage", "", "10.0.0.0/8"}, true, "allowed_range", "ipv4", "10.1.2.3"},
		{"10.1.2.3", []string{"10.1.2.3/32"}, true, "allowed_range", "ipv4", "10.1.2.3"},
		{"8.8.8.8", []string{"8.8.8.0/24"}, true, "global", "ipv4", "8.8.8.8"},
		{"192.0.0.9", []string{"192.0.0.0/24"}, true, "pcp_anycast", "ipv4", "192.0.0.9"},
		{"garbage", []string{"0.0.0.0/0"}, false, "not_a_hostname", "", ""},
		{"127.0.0.01", []string{"127.0.0.0/8"}, false, "not_a_hostname", "", ""},
		{"fc00::1", []string{"fc00::/7"}, true, "allowed_range", "ipv6", "fc00::1"},
		{"::ffff:10.0.0.1", []string{"::ffff:0:0/96"}, true, "allowed_range", "ipv6", "::ffff:10.0.0.1"},
		{"[10.1.2.3]", []string{"10.0.0.0/8"}, true, "allowed_range", "ipv4", "10.1.2.3"},
		{"2001:db8::1", nil, false, "documentation", "ipv6", "2001:db8::1"},
		{"2001:db8::1", []string{"2001:db8::/32"}, true, "allowed_range", "ipv6", "2001:db8::1"},
	}
	for _, tc := range ranges {
		got := ipaddr.ClassifyWithRanges(tc.text, tc.allowed)
		if got.Allow != tc.allow || got.Reason != tc.reason || got.Family != tc.family || got.Address != tc.address {
			t.Fatalf("ClassifyWithRanges(%q, %v) = {%t %q %q %q}, want {%t %q %q %q}",
				tc.text, tc.allowed, got.Allow, got.Reason, got.Family, got.Address,
				tc.allow, tc.reason, tc.family, tc.address)
		}
	}
}
