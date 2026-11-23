package ipaddr_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
)

// wantRow is the independent copy of one registry row: the block text, the
// snake_case registry name and the Globally Reachable column, transcribed here
// from spec/06-webhooks.md R6.5 and R6.6 so the test never trusts the table it
// is checking.
type wantRow struct {
	block     string
	name      string
	reachable bool
}

// registryRowCount is the number of rows R6.5 and R6.6 each require.
const registryRowCount = 27

var wantV4Rows = []wantRow{
	{"0.0.0.0/8", "this_network", false},
	{"0.0.0.0/32", "this_host_on_this_network", false},
	{"10.0.0.0/8", "private_use", false},
	{"100.64.0.0/10", "shared_address_space", false},
	{"127.0.0.0/8", "loopback", false},
	{"169.254.0.0/16", "link_local", false},
	{"172.16.0.0/12", "private_use", false},
	{"192.0.0.0/24", "ietf_protocol_assignments", false},
	{"192.0.0.0/29", "ipv4_service_continuity_prefix", false},
	{"192.0.0.8/32", "ipv4_dummy_address", false},
	{"192.0.0.9/32", "pcp_anycast", true},
	{"192.0.0.10/32", "turn_anycast", true},
	{"192.0.0.170/32", "nat64_dns64_discovery", false},
	{"192.0.0.171/32", "nat64_dns64_discovery", false},
	{"192.0.2.0/24", "documentation", false},
	{"192.31.196.0/24", "as112_v4", true},
	{"192.52.193.0/24", "amt", true},
	{"192.88.99.0/24", "deprecated_6to4_relay_anycast", false},
	{"192.88.99.2/32", "6a44_relay_anycast", false},
	{"192.168.0.0/16", "private_use", false},
	{"192.175.48.0/24", "as112_direct_delegation", true},
	{"198.18.0.0/15", "benchmarking", false},
	{"198.51.100.0/24", "documentation", false},
	{"203.0.113.0/24", "documentation", false},
	{"224.0.0.0/4", "multicast", false},
	{"240.0.0.0/4", "reserved", false},
	{"255.255.255.255/32", "limited_broadcast", false},
}

var wantV6Rows = []wantRow{
	{"::/128", "unspecified", false},
	{"::1/128", "loopback", false},
	{"::/96", "ipv4_compatible_deprecated", false},
	{"::ffff:0:0/96", "ipv4_mapped", false},
	{"64:ff9b::/96", "nat64_well_known", true},
	{"64:ff9b:1::/48", "nat64_local_use", false},
	{"100::/64", "discard_only", false},
	{"100:0:0:1::/64", "dummy_ipv6_prefix", false},
	{"2001::/23", "ietf_protocol_assignments", false},
	{"2001::/32", "teredo", false},
	{"2001:1::1/128", "pcp_anycast", true},
	{"2001:1::2/128", "turn_anycast", true},
	{"2001:1::3/128", "dns_sd_srp_anycast", true},
	{"2001:2::/48", "benchmarking", false},
	{"2001:3::/32", "amt", true},
	{"2001:4:112::/48", "as112_v6", true},
	{"2001:10::/28", "orchid", false},
	{"2001:20::/28", "orchidv2", true},
	{"2001:30::/28", "drone_remote_id", true},
	{"2001:db8::/32", "documentation", false},
	{"2002::/16", "six_to_four", false},
	{"2620:4f:8000::/48", "as112_direct_delegation", true},
	{"3fff::/20", "documentation", false},
	{"5f00::/16", "srv6_sid", false},
	{"fc00::/7", "unique_local", false},
	{"fe80::/10", "link_local", false},
	{"ff00::/8", "multicast", false},
}

// wantHexGroups parses the literal of one expected row with plain arithmetic:
// 1-8 hex groups with at most one "::" compression.
func wantHexGroups(t *testing.T, literal string) []uint16 {
	t.Helper()
	readGroups := func(text string) []uint16 {
		if text == "" {
			return nil
		}
		parts := strings.Split(text, ":")
		out := make([]uint16, 0, len(parts))
		for _, part := range parts {
			value, err := strconv.ParseUint(part, 16, 16)
			if err != nil {
				t.Fatalf("literal %q has an unreadable hex group %q", literal, part)
			}
			out = append(out, uint16(value))
		}
		return out
	}
	if at := strings.Index(literal, "::"); at >= 0 {
		head := readGroups(literal[:at])
		tail := readGroups(literal[at+2:])
		total := len(head) + len(tail)
		if total > 7 {
			t.Fatalf("literal %q has %d groups around ::", literal, total)
		}
		out := make([]uint16, 0, 8)
		out = append(out, head...)
		for i := 0; i < 8-total; i++ {
			out = append(out, 0)
		}
		return append(out, tail...)
	}
	groups := readGroups(literal)
	if len(groups) != 8 {
		t.Fatalf("literal %q has %d groups, want 8", literal, len(groups))
	}
	return groups
}

// wantNetwork parses one expected block text independently of the package.
func wantNetwork(t *testing.T, block string) ([]byte, int) {
	t.Helper()
	parts := strings.Split(block, "/")
	if len(parts) != 2 {
		t.Fatalf("block %q is not <literal>/<prefix>", block)
	}
	prefix, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("block %q has a non-numeric prefix", block)
	}
	literal := parts[0]
	if strings.Contains(literal, ":") {
		groups := wantHexGroups(t, literal)
		out := make([]byte, 16)
		for i, group := range groups {
			out[i*2] = byte(group >> 8)
			out[i*2+1] = byte(group)
		}
		return out, prefix
	}
	octets := strings.Split(literal, ".")
	if len(octets) != 4 {
		t.Fatalf("block %q is not a dotted quad", block)
	}
	out := make([]byte, 4)
	for i, octet := range octets {
		value, err := strconv.Atoi(octet)
		if err != nil || value < 0 || value > 255 {
			t.Fatalf("block %q has a bad octet %q", block, octet)
		}
		out[i] = byte(value)
	}
	return out, prefix
}

// wantMaskedEqual is the containment test of the test: the first prefix bits of
// addr and network agree.
func wantMaskedEqual(addr, network []byte, prefix int) bool {
	if len(addr) != len(network) || prefix < 0 || prefix > len(network)*8 {
		return false
	}
	for i := 0; i < len(network); i++ {
		bits := prefix - i*8
		var mask byte
		switch {
		case bits >= 8:
			mask = 0xff
		case bits <= 0:
			mask = 0x00
		default:
			mask = byte(0xff) << uint(8-bits)
		}
		if addr[i]&mask != network[i]&mask {
			return false
		}
	}
	return true
}

// wantFirstLast builds the first and last address of a network by setting or
// clearing every host bit, independently of the package arithmetic.
func wantFirstLast(network []byte, prefix int) ([]byte, []byte) {
	first := append([]byte(nil), network...)
	last := append([]byte(nil), network...)
	for i := range network {
		bits := prefix - i*8
		var host byte
		switch {
		case bits <= 0:
			host = 0xff
		case bits >= 8:
			host = 0x00
		default:
			host = byte(0xff >> uint(bits))
		}
		first[i] &^= host
		last[i] |= host
	}
	return first, last
}

// wantDeepest returns the deepest expected row containing addr, first row
// winning an equal prefix, and whether any row matched.
func wantDeepest(t *testing.T, rows []wantRow, addr []byte) (wantRow, bool) {
	t.Helper()
	var best wantRow
	bestPrefix := -1
	found := false
	for _, row := range rows {
		network, prefix := wantNetwork(t, row.block)
		if prefix <= bestPrefix {
			continue
		}
		if wantMaskedEqual(addr, network, prefix) {
			best = row
			bestPrefix = prefix
			found = true
		}
	}
	return best, found
}

func wantIPv4Text(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func wantIPv6Array(t *testing.T, b []byte) [16]byte {
	t.Helper()
	var out [16]byte
	if len(b) != 16 {
		t.Fatalf("ipv6 width is %d, want 16", len(b))
	}
	copy(out[:], b)
	return out
}

// TestIPAddrBlockTables checks both registry tables row for row, then classifies
// the first and last address of every row against the deepest expected row, the
// two inheriting chains of R6.7 and the worked examples of R6.7.
func TestIPAddrBlockTables(t *testing.T) {
	if len(wantV4Rows) != registryRowCount || len(wantV6Rows) != registryRowCount {
		t.Fatalf("test tables hold %d and %d rows, want %d each",
			len(wantV4Rows), len(wantV6Rows), registryRowCount)
	}
	if len(ipaddr.V4Blocks) != registryRowCount {
		t.Fatalf("V4Blocks has %d rows, want %d", len(ipaddr.V4Blocks), registryRowCount)
	}
	if len(ipaddr.V6Blocks) != registryRowCount {
		t.Fatalf("V6Blocks has %d rows, want %d", len(ipaddr.V6Blocks), registryRowCount)
	}

	for i, want := range wantV4Rows {
		row := ipaddr.V4Blocks[i]
		if row.Block != want.block || row.Name != want.name || row.Reachable != want.reachable {
			t.Fatalf("V4Blocks[%d] = {%q %q %t}, want {%q %q %t}",
				i, row.Block, row.Name, row.Reachable, want.block, want.name, want.reachable)
		}
		parsed, ok := ipaddr.ParseCIDR(row.Block)
		if !ok {
			t.Fatalf("V4Blocks[%d] block %q does not parse as a CIDR", i, row.Block)
		}
		if parsed.Family != "ipv4" {
			t.Fatalf("V4Blocks[%d] block %q has family %q", i, row.Block, parsed.Family)
		}
		network, prefix := wantNetwork(t, want.block)
		if parsed.Prefix != prefix || len(parsed.Bytes) != 4 || parsed.Bytes[0] != network[0] ||
			parsed.Bytes[1] != network[1] || parsed.Bytes[2] != network[2] || parsed.Bytes[3] != network[3] {
			t.Fatalf("V4Blocks[%d] block %q parsed to %v/%d, want %v/%d",
				i, row.Block, parsed.Bytes, parsed.Prefix, network, prefix)
		}
		if row.Prefix != prefix || row.Bytes != [4]byte{network[0], network[1], network[2], network[3]} {
			t.Fatalf("V4Blocks[%d] fields are %v/%d, want the network %v/%d",
				i, row.Bytes, row.Prefix, network, prefix)
		}
		first, last := wantFirstLast(network, prefix)
		if wantIPv4Text(first) != wantIPv4Text(network) {
			t.Fatalf("V4Blocks[%d] block %q is not a network: first host is %s",
				i, row.Block, wantIPv4Text(first))
		}
		for _, addr := range [][]byte{first, last} {
			text := wantIPv4Text(addr)
			got := ipaddr.ClassifyAddress(text)
			deep, ok := wantDeepest(t, wantV4Rows, addr)
			if !ok {
				t.Fatalf("no expected IPv4 row contains %s", text)
			}
			wantAllow := deep.reachable
			if got.Allow != wantAllow || got.Reason != deep.name {
				t.Fatalf("ClassifyAddress(%q) = allow %t reason %q, want allow %t reason %q",
					text, got.Allow, got.Reason, wantAllow, deep.name)
			}
			if got.Family != "ipv4" || got.Address != text {
				t.Fatalf("ClassifyAddress(%q) = family %q address %q, want ipv4 %q",
					text, got.Family, got.Address, text)
			}
		}
	}

	for i, want := range wantV6Rows {
		row := ipaddr.V6Blocks[i]
		if row.Block != want.block || row.Name != want.name || row.Reachable != want.reachable {
			t.Fatalf("V6Blocks[%d] = {%q %q %t}, want {%q %q %t}",
				i, row.Block, row.Name, row.Reachable, want.block, want.name, want.reachable)
		}
		parsed, ok := ipaddr.ParseCIDR(row.Block)
		if !ok {
			t.Fatalf("V6Blocks[%d] block %q does not parse as a CIDR", i, row.Block)
		}
		if parsed.Family != "ipv6" || len(parsed.Bytes) != 16 {
			t.Fatalf("V6Blocks[%d] block %q parsed to family %q width %d",
				i, row.Block, parsed.Family, len(parsed.Bytes))
		}
		network, prefix := wantNetwork(t, want.block)
		if parsed.Prefix != prefix {
			t.Fatalf("V6Blocks[%d] block %q parsed to prefix %d, want %d",
				i, row.Block, parsed.Prefix, prefix)
		}
		var wantBytes [16]byte
		copy(wantBytes[:], network)
		if row.Prefix != prefix || row.Bytes != wantBytes {
			t.Fatalf("V6Blocks[%d] fields are %v/%d, want the network %v/%d",
				i, row.Bytes, row.Prefix, network, prefix)
		}
		first, last := wantFirstLast(network, prefix)
		var firstBytes [16]byte
		copy(firstBytes[:], first)
		if firstBytes != wantBytes {
			t.Fatalf("V6Blocks[%d] block %q is not a network: first host is %s",
				i, row.Block, ipaddr.FormatIPv6(firstBytes))
		}
		for _, addr := range [][]byte{first, last} {
			text := ipaddr.FormatIPv6(wantIPv6Array(t, addr))
			got := ipaddr.ClassifyAddress(text)
			if got.Family != "ipv6" || got.Address != text {
				t.Fatalf("ClassifyAddress(%q) = family %q address %q, want ipv6 %q",
					text, got.Family, got.Address, text)
			}
			if want.name == "ipv4_mapped" || want.name == "nat64_well_known" {
				embedded := fmt.Sprintf("%d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
				inner := ipaddr.ClassifyAddress(embedded)
				if got.Allow != inner.Allow {
					t.Fatalf("ClassifyAddress(%q) allow = %t, want the embedded decision %t of %s",
						text, got.Allow, inner.Allow, embedded)
				}
				wantReason := want.name
				if !inner.Allow {
					wantReason = want.name + "/" + inner.Reason
				}
				if got.Reason != wantReason {
					t.Fatalf("ClassifyAddress(%q) reason = %q, want %q (embedded %s)",
						text, got.Reason, wantReason, embedded)
				}
				continue
			}
			deep, ok := wantDeepest(t, wantV6Rows, addr)
			if !ok {
				t.Fatalf("no expected IPv6 row contains %s", text)
			}
			wantAllow := deep.reachable
			if got.Allow != wantAllow || got.Reason != deep.name {
				t.Fatalf("ClassifyAddress(%q) = allow %t reason %q, want allow %t reason %q",
					text, got.Allow, got.Reason, wantAllow, deep.name)
			}
		}
	}

	examples := []struct {
		text  string
		allow bool
		why   string
	}{
		{"::ffff:127.0.0.1", false, "ipv4_mapped/loopback"},
		{"64:ff9b::10.0.0.1", false, "nat64_well_known/private_use"},
		{"2002:7f00:1::", false, "six_to_four"},
		{"2001:0:4136:e378::", false, "teredo"},
		{"64:ff9b:1::1", false, "nat64_local_use"},
		{"192.0.0.9", true, "pcp_anycast"},
		{"2620:4f:8000::1", true, "as112_direct_delegation"},
		{"8.8.8.8", true, "global"},
		{"::ffff:8.8.8.8", true, "ipv4_mapped"},
		{"64:ff9b::808:808", true, "nat64_well_known"},
		{"2002:808:808::", false, "six_to_four"},
		{"2001:0:a00:1::", false, "teredo"},
	}
	for _, example := range examples {
		got := ipaddr.ClassifyAddress(example.text)
		if got.Allow != example.allow || got.Reason != example.why {
			t.Fatalf("ClassifyAddress(%q) = allow %t reason %q, want allow %t reason %q",
				example.text, got.Allow, got.Reason, example.allow, example.why)
		}
	}
}
