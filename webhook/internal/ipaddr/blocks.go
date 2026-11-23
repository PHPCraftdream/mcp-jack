package ipaddr

// Block4 is one row of the IPv4 special-purpose registry table of
// spec/06-webhooks.md R6.5. Block is the row text, Name the registry name in
// snake_case (the reason string either way), Reachable the registry's
// "Globally Reachable" column, and Bytes/Prefix the same block as a parsed
// network with every host bit zero.
type Block4 struct {
	Block     string
	Name      string
	Reachable bool
	Bytes     [4]byte
	Prefix    int
}

// Block6 is one row of the IPv6 special-purpose registry table of
// spec/06-webhooks.md R6.6, with the same field meanings as Block4.
type Block6 struct {
	Block     string
	Name      string
	Reachable bool
	Bytes     [16]byte
	Prefix    int
}

// rowSpec is one hand-written table row before the block text is parsed.
type rowSpec struct {
	block     string
	name      string
	reachable bool
}

// v4Rows is R6.5 / IPV4_BLOCKS of ssrf.mjs, row for row and in the same order.
// Rows overlap on purpose: 0.0.0.0/8 contains the registry's own 0.0.0.0/32
// row, and 192.0.0.0/24 contains the /29 and the /32 rows of that /24.
var v4Rows = []rowSpec{
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

// v6Rows is R6.6 / IPV6_BLOCKS of ssrf.mjs, row for row and in the same order.
// Rows overlap on purpose: 2001::/23 contains the more specific 2001::/32 and
// 2001:/28 rows. ::/96 is the Jack addition for the deprecated IPv4-compatible
// form, and it is a different block from ::ffff:0:0/96. 100:0:0:1::/64 is the
// registry's Dummy IPv6 Prefix and sits next to, not inside, 100::/64.
var v6Rows = []rowSpec{
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

// V4Blocks is the IPv4 table of R6.5: exactly the registry rows, in registry
// order, each also parsed into Bytes and Prefix.
var V4Blocks = buildV4Blocks()

// V6Blocks is the IPv6 table of R6.6: exactly the registry rows plus the two
// address-architecture rows and the Jack ::/96 row, in registry order.
var V6Blocks = buildV6Blocks()

// buildV4Blocks parses every R6.5 row and refuses to build a table whose rows
// are not exact networks; the invariant is the one ssrf.mjs asserts at module
// load, so containment arithmetic never depends on a sloppy row.
func buildV4Blocks() []Block4 {
	out := make([]Block4, 0, len(v4Rows))
	for _, spec := range v4Rows {
		parsed, ok := ParseCIDR(spec.block)
		if !ok || parsed.Family != familyIPv4 {
			panic("ipaddr: R6.5 row is not an IPv4 CIDR: " + spec.block)
		}
		row := Block4{
			Block:     spec.block,
			Name:      spec.name,
			Reachable: spec.reachable,
			Prefix:    parsed.Prefix,
		}
		copy(row.Bytes[:], parsed.Bytes)
		out = append(out, row)
	}
	return out
}

// buildV6Blocks parses every R6.6 row under the same invariant as buildV4Blocks.
func buildV6Blocks() []Block6 {
	out := make([]Block6, 0, len(v6Rows))
	for _, spec := range v6Rows {
		parsed, ok := ParseCIDR(spec.block)
		if !ok || parsed.Family != familyIPv6 {
			panic("ipaddr: R6.6 row is not an IPv6 CIDR: " + spec.block)
		}
		row := Block6{
			Block:     spec.block,
			Name:      spec.name,
			Reachable: spec.reachable,
			Prefix:    parsed.Prefix,
		}
		copy(row.Bytes[:], parsed.Bytes)
		out = append(out, row)
	}
	return out
}
