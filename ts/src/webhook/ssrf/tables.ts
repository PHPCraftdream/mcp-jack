/** SSRF range tables and CIDR math of spec 06 section 6 (R6.5, R6.6, R6.11); pure data, no I/O. */
import { parseIPv4, parseIPv6 } from "./address.js";

// address.ts imports these tables back, so one of the two modules is evaluated while the other is still
// in progress. parseIPv4 and parseIPv6 keep their patterns inside their function bodies, and function
// declarations are hoisted, so the module-load range build below works in either evaluation order.

/** The decimal prefix text of a range: 0 or 1-3 digits with no leading zero (R6.11). */
const PREFIX_TEXT = /^(0|[1-9][0-9]{0,2})$/;

/** One special-purpose registry row: its block, its snake_case registry name and Globally Reachable value. */
export interface IpBlock {
  readonly block: string;
  readonly name: string;
  readonly reachable: boolean;
}

/**
 * IPv4 special registry rows (R6.5) in registry order. Rows overlap on purpose (192.0.0.0/24
 * contains the /29 and /32 rows, and 0.0.0.0/8 contains the registry's own 0.0.0.0/32 row), so the
 * longest matching row decides. 224.0.0.0/4 is the multicast block of the address architecture and
 * not a registry row; every registry row inside it is also not globally reachable, so the decision
 * is the same.
 */
export const IPV4_BLOCKS: readonly IpBlock[] = [
  { block: "0.0.0.0/8", name: "this_network", reachable: false },
  { block: "0.0.0.0/32", name: "this_host_on_this_network", reachable: false },
  { block: "10.0.0.0/8", name: "private_use", reachable: false },
  { block: "100.64.0.0/10", name: "shared_address_space", reachable: false },
  { block: "127.0.0.0/8", name: "loopback", reachable: false },
  { block: "169.254.0.0/16", name: "link_local", reachable: false },
  { block: "172.16.0.0/12", name: "private_use", reachable: false },
  { block: "192.0.0.0/24", name: "ietf_protocol_assignments", reachable: false },
  { block: "192.0.0.0/29", name: "ipv4_service_continuity_prefix", reachable: false },
  { block: "192.0.0.8/32", name: "ipv4_dummy_address", reachable: false },
  { block: "192.0.0.9/32", name: "pcp_anycast", reachable: true },
  { block: "192.0.0.10/32", name: "turn_anycast", reachable: true },
  { block: "192.0.0.170/32", name: "nat64_dns64_discovery", reachable: false },
  { block: "192.0.0.171/32", name: "nat64_dns64_discovery", reachable: false },
  { block: "192.0.2.0/24", name: "documentation", reachable: false },
  { block: "192.31.196.0/24", name: "as112_v4", reachable: true },
  { block: "192.52.193.0/24", name: "amt", reachable: true },
  { block: "192.88.99.0/24", name: "deprecated_6to4_relay_anycast", reachable: false },
  { block: "192.88.99.2/32", name: "6a44_relay_anycast", reachable: false },
  { block: "192.168.0.0/16", name: "private_use", reachable: false },
  { block: "192.175.48.0/24", name: "as112_direct_delegation", reachable: true },
  { block: "198.18.0.0/15", name: "benchmarking", reachable: false },
  { block: "198.51.100.0/24", name: "documentation", reachable: false },
  { block: "203.0.113.0/24", name: "documentation", reachable: false },
  { block: "224.0.0.0/4", name: "multicast", reachable: false },
  { block: "240.0.0.0/4", name: "reserved", reachable: false },
  { block: "255.255.255.255/32", name: "limited_broadcast", reachable: false },
];

/**
 * IPv6 special registry rows (R6.6) in registry order. Rows overlap on purpose (2001::/23
 * contains the more specific 2001::/32 rows), so the longest matching row decides. Three rows are
 * Jack additions rather than registry entries: ::/96 ipv4_compatible_deprecated, and 224.0.0.0/4
 * with ff00::/8 multicast from the address architecture. 100:0:0:1::/64 sits next to 100::/64, not
 * inside it, so neither row shadows the other.
 */
export const IPV6_BLOCKS: readonly IpBlock[] = [
  { block: "::/128", name: "unspecified", reachable: false },
  { block: "::1/128", name: "loopback", reachable: false },
  { block: "::/96", name: "ipv4_compatible_deprecated", reachable: false },
  { block: "::ffff:0:0/96", name: "ipv4_mapped", reachable: false },
  { block: "64:ff9b::/96", name: "nat64_well_known", reachable: true },
  { block: "64:ff9b:1::/48", name: "nat64_local_use", reachable: false },
  { block: "100::/64", name: "discard_only", reachable: false },
  { block: "100:0:0:1::/64", name: "dummy_ipv6_prefix", reachable: false },
  { block: "2001::/23", name: "ietf_protocol_assignments", reachable: false },
  { block: "2001::/32", name: "teredo", reachable: false },
  { block: "2001:1::1/128", name: "pcp_anycast", reachable: true },
  { block: "2001:1::2/128", name: "turn_anycast", reachable: true },
  { block: "2001:1::3/128", name: "dns_sd_srp_anycast", reachable: true },
  { block: "2001:2::/48", name: "benchmarking", reachable: false },
  { block: "2001:3::/32", name: "amt", reachable: true },
  { block: "2001:4:112::/48", name: "as112_v6", reachable: true },
  { block: "2001:10::/28", name: "orchid", reachable: false },
  { block: "2001:20::/28", name: "orchidv2", reachable: true },
  { block: "2001:30::/28", name: "drone_remote_id", reachable: true },
  { block: "2001:db8::/32", name: "documentation", reachable: false },
  { block: "2002::/16", name: "six_to_four", reachable: false },
  { block: "2620:4f:8000::/48", name: "as112_direct_delegation", reachable: true },
  { block: "3fff::/20", name: "documentation", reachable: false },
  { block: "5f00::/16", name: "srv6_sid", reachable: false },
  { block: "fc00::/7", name: "unique_local", reachable: false },
  { block: "fe80::/10", name: "link_local", reachable: false },
  { block: "ff00::/8", name: "multicast", reachable: false },
];

/** A parsed `<literal>/<prefix>` range with zero host bits beyond the prefix (R6.11). */
export interface ParsedCidr {
  readonly ok: true;
  readonly family: "ipv4" | "ipv6";
  readonly bytes: Uint8Array;
  readonly prefix: number;
}

/** A parsed registry row: its network bytes plus the row's name and reachability. */
export interface ParsedRange {
  readonly name: string;
  readonly reachable: boolean;
  readonly bytes: Uint8Array;
  readonly prefix: number;
}

/**
 * Parses `<literal>/<prefix>`: exactly one "/", a decimal prefix with no leading zero and at most
 * 32 (IPv4) or 128 (IPv6) bits, a literal the family's parser accepts, and zero host bits beyond
 * the prefix (R6.11).
 */
export function parseCidr(text: unknown): ParsedCidr | { readonly ok: false } {
  if (typeof text !== "string") return { ok: false };
  const slash = text.indexOf("/");
  if (slash === -1 || text.indexOf("/", slash + 1) !== -1) return { ok: false };
  const prefixText = text.slice(slash + 1);
  if (!PREFIX_TEXT.test(prefixText)) return { ok: false };
  const prefix = Number(prefixText);
  const literal = text.slice(0, slash);
  const family: "ipv4" | "ipv6" = literal.includes(":") ? "ipv6" : "ipv4";
  if (prefix > (family === "ipv6" ? 128 : 32)) return { ok: false };
  const parsed = family === "ipv4" ? parseIPv4(literal) : parseIPv6(literal);
  if (!parsed.ok || !hostBitsZero(parsed.bytes, prefix)) return { ok: false };
  return { ok: true, family, bytes: parsed.bytes, prefix };
}

/**
 * Whether an address literal (a bracketed IPv6 literal, a canonical dotted quad or a bare IPv6
 * literal) is inside a parsed range; the families must match (R6.11).
 */
export function cidrContains(cidr: ParsedCidr | { readonly ok: false }, address: string): boolean {
  if (cidr.ok !== true) return false;
  let input = address;
  if (input.startsWith("[") && input.endsWith("]")) input = input.slice(1, -1);
  const quad = parseIPv4(input);
  if (quad.ok) {
    return cidr.family === "ipv4" && matchPrefix(quad.bytes, cidr.bytes, cidr.prefix);
  }
  const v6 = parseIPv6(input);
  if (!v6.ok) return false;
  return cidr.family === "ipv6" && matchPrefix(v6.bytes, cidr.bytes, cidr.prefix);
}

/** The longest matching row of the family's table, or null when no row matches (R6.5, R6.6). */
export function longestMatch(family: "ipv4" | "ipv6", bytes: Uint8Array): ParsedRange | null {
  const ranges = family === "ipv4" ? IPV4_RANGES : IPV6_RANGES;
  let best: ParsedRange | null = null;
  for (const range of ranges) {
    if (best !== null && range.prefix <= best.prefix) continue;
    if (matchPrefix(bytes, range.bytes, range.prefix)) best = range;
  }
  return best;
}

function hostBitsZero(bytes: Uint8Array, prefix: number): boolean {
  const whole = prefix >> 3;
  const restBits = prefix & 7;
  const from = restBits === 0 ? whole : whole + 1;
  for (let i = from; i < bytes.length; i++) {
    if ((bytes[i] ?? 0) !== 0) return false;
  }
  if (restBits === 0) return true;
  const boundary = bytes[whole];
  if (boundary === undefined) return false;
  const mask = (0xff << (8 - restBits)) & 0xff;
  return (boundary & (~mask & 0xff)) === 0;
}

function matchPrefix(bytes: Uint8Array, network: Uint8Array, prefix: number): boolean {
  if (bytes.length !== network.length) return false;
  const whole = prefix >> 3;
  for (let i = 0; i < whole; i++) {
    if ((bytes[i] ?? 0) !== (network[i] ?? 0)) return false;
  }
  const restBits = prefix & 7;
  if (restBits === 0) return true;
  const a = bytes[whole];
  const b = network[whole];
  if (a === undefined || b === undefined) return false;
  const mask = (0xff << (8 - restBits)) & 0xff;
  return (a & mask) === (b & mask);
}

function rangeTable(blocks: readonly IpBlock[], family: "ipv4" | "ipv6"): readonly ParsedRange[] {
  return blocks.map((entry) => {
    const parsed = parseCidr(entry.block);
    if (!parsed.ok || parsed.family !== family) {
      throw new Error(`ssrf: ${family} block ${entry.block} does not parse`);
    }
    return { name: entry.name, reachable: entry.reachable, bytes: parsed.bytes, prefix: parsed.prefix };
  });
}

// Module-load invariant: every row must parse as a CIDR with zero host bits, so containment math is exact.
const IPV4_RANGES: readonly ParsedRange[] = rangeTable(IPV4_BLOCKS, "ipv4");
const IPV6_RANGES: readonly ParsedRange[] = rangeTable(IPV6_BLOCKS, "ipv6");
