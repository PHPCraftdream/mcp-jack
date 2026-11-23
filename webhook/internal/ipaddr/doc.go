// Package ipaddr implements the address literals and the block tables of the
// webhook delivery-time network rules: spec/06-webhooks.md section 6, R6.3-R6.7
// and R6.11.
//
// The executable definition is spec/tools/modern/webhooks/ref/ssrf.mjs, which
// this package mirrors entry for entry: parseIPv4, parseIPv6, formatIPv4,
// formatIPv6, parseCidr, cidrContains, isLdhName, parseHost, classifyIPv4,
// classifyIPv6, classifyAddress and classifyWithRanges, together with the
// private helpers matchPrefix, hostBitsZero, isMapped, parsedAddress and
// parseHexGroups.
//
// Every function is pure and deterministic: nothing here resolves, dials or
// caches, and the two tables are fixed by R6.5 and R6.6. The single decision
// rule is the registry one: the longest matching row decides, and the address
// is allowed exactly when that row is globally reachable; an address inside no
// row is allowed with reason "global". Equal prefix lengths are settled by
// table order, first row winning.
//
// Four IPv6 forms are handled before the table, in this order (R6.7):
// IPv4-mapped ::ffff:0:0/96 and NAT64 64:ff9b::/96 inherit the embedded IPv4
// decision (reason "ipv4_mapped" or "ipv4_mapped/<ipv4 reason>", likewise for
// "nat64_well_known"), while 6to4 2002::/16 and Teredo 2001:0000::/32 are
// always rejected with their own single reason, "six_to_four" and "teredo".
//
// Host spellings follow R6.3 literally: a canonical dotted quad, a bracketed
// IPv6 literal, or an ASCII LDH name after exactly one trailing dot and
// case folding. Every other spelling, in particular the decimal, octal, hex,
// short, single-integer, over-long-dotted and empty-label forms, is reported as
// "not_a_hostname" and is never reinterpreted as an address.
package ipaddr
