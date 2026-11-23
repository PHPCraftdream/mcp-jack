/** SSRF address parsing and classification of spec 06 section 6 (R6.3-R6.7, R6.11); pure, no resolver. */
import { cidrContains, longestMatch, parseCidr } from "./tables.js";

const LDH_LABEL = /^[A-Za-z0-9-]{1,63}$/;
const NUMERIC_LABEL = /^[0-9]+$/;

/** The decision a parsed address receives and the reason that names it. */
export interface AddressVerdict {
  readonly decision: "allow" | "reject";
  readonly reason: string;
}

/**
 * Parses a canonical dotted quad: four decimal octets 0..255, no leading zero, no sign, no
 * whitespace, no short form (R6.3, R6.4).
 */
export function parseIPv4(text: unknown): { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false } {
  // Function-local pattern: tables.ts parses its rows during module load, possibly before this
  // module finishes evaluating, and only hoisted function declarations are safe to call then.
  const octet = /^(0|[1-9][0-9]{0,2})$/;
  if (typeof text !== "string") return { ok: false };
  const parts = text.split(".");
  if (parts.length !== 4) return { ok: false };
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i] ?? "";
    if (!octet.test(part)) return { ok: false };
    const value = Number(part);
    if (value > 255) return { ok: false };
    bytes[i] = value;
  }
  return { ok: true, bytes };
}

/**
 * Parses an IPv6 literal: 1-8 hex groups, at most one "::" compression, at most one embedded
 * dotted quad in the final group, no zone id, no brackets (R6.7).
 */
export function parseIPv6(text: unknown): { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false } {
  if (typeof text !== "string") return { ok: false };
  if (text.includes("%") || text.includes("[") || text.includes("]")) return { ok: false };
  const gap = text.indexOf("::");
  if (gap !== -1 && text.indexOf("::", gap + 2) !== -1) return { ok: false };
  const compressed = gap !== -1;
  const head = compressed ? (gap === 0 ? [] : text.slice(0, gap).split(":")) : text.split(":");
  const tailText = compressed ? text.slice(gap + 2) : "";
  const tail = compressed ? (tailText === "" ? [] : tailText.split(":")) : [];
  const headValues = parseHexGroups(head, !compressed);
  if (headValues === null) return { ok: false };
  const tailValues = parseHexGroups(tail, compressed);
  if (tailValues === null) return { ok: false };
  const total = headValues.length + tailValues.length;
  if (compressed ? total > 7 : total !== 8) return { ok: false };
  const values = compressed ? [...headValues, ...new Array<number>(8 - total).fill(0), ...tailValues] : headValues;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const value = values[i] ?? 0;
    bytes[i * 2] = value >> 8;
    bytes[i * 2 + 1] = value & 0xff;
  }
  return { ok: true, bytes };
}

/** Formats four bytes as a dotted quad (R6.4). */
export function formatIPv4(bytes: Uint8Array): string {
  return `${byteAt(bytes, 0)}.${byteAt(bytes, 1)}.${byteAt(bytes, 2)}.${byteAt(bytes, 3)}`;
}

/**
 * Formats sixteen bytes as RFC 5952 lowercase compressed groups; an IPv4-mapped address keeps the
 * `::ffff:a.b.c.d` shape (R6.6).
 */
export function formatIPv6(bytes: Uint8Array): string {
  if (isMapped(bytes)) return `::ffff:${formatIPv4(bytes.subarray(12, 16))}`;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((byteAt(bytes, i) << 8) | byteAt(bytes, i + 1));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== 0) continue;
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLen < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
}

/** Whether a name is an ASCII LDH name: two or more labels, 1-63 chars, no edge hyphen, at most 253 (R6.3). */
export function isLdhName(name: unknown): boolean {
  if (typeof name !== "string" || name.length > 253) return false;
  const labels = name.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!LDH_LABEL.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return !NUMERIC_LABEL.test(labels[labels.length - 1] ?? "");
}

/** A host parsed into its form, canonical address or normalized name, or its refusal reason (R6.3). */
export type ParsedHost =
  | { readonly ok: true; readonly kind: "ipv4"; readonly address: string; readonly normalized: string }
  | { readonly ok: true; readonly kind: "ipv6"; readonly address: string; readonly normalized: string }
  | { readonly ok: true; readonly kind: "name"; readonly name: string; readonly normalized: string }
  | { readonly ok: false; readonly reason: "not_a_hostname" | "host" };

/**
 * Parses a host into a canonical dotted quad, a bracketed IPv6 literal or an LDH name; every other
 * spelling is never reinterpreted (R6.3). A malformed bracket literal is reason `host`, a numeric
 * or otherwise non-LDH spelling is reason `not_a_hostname`.
 */
export function parseHost(host: unknown): ParsedHost {
  if (typeof host !== "string" || host === "") return { ok: false, reason: "not_a_hostname" };
  if (host.startsWith("[")) {
    if (!host.endsWith("]")) return { ok: false, reason: "host" };
    const inner = host.slice(1, -1);
    if (inner.includes("[") || inner.includes("]") || inner.includes("%")) return { ok: false, reason: "host" };
    const parsed = parseIPv6(inner);
    if (!parsed.ok) return { ok: false, reason: "host" };
    const address = formatIPv6(parsed.bytes);
    return { ok: true, kind: "ipv6", address, normalized: `[${address}]` };
  }
  if (host.includes("[") || host.includes("]")) return { ok: false, reason: "host" };
  const quad = parseIPv4(host);
  if (quad.ok) {
    const address = formatIPv4(quad.bytes);
    return { ok: true, kind: "ipv4", address, normalized: address };
  }
  const name = (host.endsWith(".") ? host.slice(0, -1) : host).toLowerCase();
  if (!isLdhName(name)) return { ok: false, reason: "not_a_hostname" };
  return { ok: true, kind: "name", name, normalized: name };
}

/**
 * Classifies a parsed IPv4 address: the longest matching registry row decides and its name is the
 * reason either way; an address in no row is allowed as `global` (R6.5).
 */
export function classifyIPv4(bytes: Uint8Array): AddressVerdict {
  const best = longestMatch("ipv4", bytes);
  if (best === null) return { decision: "allow", reason: "global" };
  return { decision: best.reachable ? "allow" : "reject", reason: best.name };
}

/**
 * Classifies a parsed IPv6 address: the mapped and NAT64 chains inherit the embedded IPv4 decision,
 * 6to4 and Teredo never do, and otherwise the longest matching registry row decides (R6.6, R6.7).
 */
export function classifyIPv6(bytes: Uint8Array): AddressVerdict {
  if (isMapped(bytes)) {
    const v4 = classifyIPv4(bytes.subarray(12, 16));
    if (v4.decision === "allow") return { decision: "allow", reason: "ipv4_mapped" };
    return { decision: "reject", reason: `ipv4_mapped/${v4.reason}` };
  }
  if (isNat64WellKnown(bytes)) {
    const v4 = classifyIPv4(bytes.subarray(12, 16));
    if (v4.decision === "allow") return { decision: "allow", reason: "nat64_well_known" };
    return { decision: "reject", reason: `nat64_well_known/${v4.reason}` };
  }
  if (byteAt(bytes, 0) === 0x20 && byteAt(bytes, 1) === 0x02) {
    return { decision: "reject", reason: "six_to_four" };
  }
  if (byteAt(bytes, 0) === 0x20 && byteAt(bytes, 1) === 0x01 && byteAt(bytes, 2) === 0 && byteAt(bytes, 3) === 0) {
    return { decision: "reject", reason: "teredo" };
  }
  const best = longestMatch("ipv6", bytes);
  if (best === null) return { decision: "allow", reason: "global" };
  return { decision: best.reachable ? "allow" : "reject", reason: best.name };
}

/** A classified address literal: its family and normalized spelling, or a reason with no address. */
export type ClassifiedAddress =
  | {
      readonly decision: "allow";
      readonly reason: string;
      readonly family: "ipv4" | "ipv6";
      readonly address: string;
    }
  | {
      readonly decision: "reject";
      readonly reason: string;
      readonly family: "ipv4" | "ipv6" | null;
      readonly address: string | null;
    };

/** Classifies one address literal (a bracketed IPv6 literal, a dotted quad or a bare IPv6) (R6.4, R6.7). */
export function classifyAddress(text: string): ClassifiedAddress {
  const parsed = parsedAddress(text);
  if (parsed === null) return { decision: "reject", reason: "not_a_hostname", family: null, address: null };
  const verdict = classifyParsed(parsed);
  if (verdict.decision === "allow") {
    return { decision: "allow", reason: verdict.reason, family: parsed.family, address: parsed.address };
  }
  return { decision: "reject", reason: verdict.reason, family: parsed.family, address: parsed.address };
}

/**
 * Classifies one address literal with the operator override applied after the registry tables: only
 * a rejection can be overridden, by a well-formed range of the same family, and the reason is then
 * `allowed_range`. A malformed entry is ignored and an unparsable spelling stays `not_a_hostname`
 * (R6.11).
 */
export function classifyWithRanges(
  text: string,
  allowedRanges?: readonly string[],
): { readonly decision: "allow" | "reject"; readonly reason: string; readonly address: string | null } {
  const parsed = parsedAddress(text);
  if (parsed === null) return { decision: "reject", reason: "not_a_hostname", address: null };
  const verdict = classifyParsed(parsed);
  if (verdict.decision === "allow") {
    return { decision: "allow", reason: verdict.reason, address: parsed.address };
  }
  const ranges: readonly string[] = allowedRanges ?? [];
  const hit = ranges.some((entry) => {
    const range = parseCidr(entry);
    return range.ok === true && range.family === parsed.family && cidrContains(range, parsed.address);
  });
  if (hit) return { decision: "allow", reason: "allowed_range", address: parsed.address };
  return { decision: "reject", reason: verdict.reason, address: parsed.address };
}

function parseHexGroups(parts: readonly string[], allowDottedLast: boolean): number[] | null {
  const group = /^[0-9a-fA-F]{1,4}$/;
  const out: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? "";
    if (allowDottedLast && i === parts.length - 1 && part.includes(".")) {
      const quad = parseIPv4(part);
      if (!quad.ok) return null;
      out.push((byteAt(quad.bytes, 0) << 8) | byteAt(quad.bytes, 1), (byteAt(quad.bytes, 2) << 8) | byteAt(quad.bytes, 3));
      continue;
    }
    if (!group.test(part)) return null;
    out.push(parseInt(part, 16));
  }
  return out;
}

function byteAt(bytes: Uint8Array, index: number): number {
  return bytes[index] ?? 0;
}

function isMapped(bytes: Uint8Array): boolean {
  for (let i = 0; i < 10; i++) {
    if (byteAt(bytes, i) !== 0) return false;
  }
  return byteAt(bytes, 10) === 0xff && byteAt(bytes, 11) === 0xff;
}

function isNat64WellKnown(bytes: Uint8Array): boolean {
  if (byteAt(bytes, 0) !== 0x00 || byteAt(bytes, 1) !== 0x64 || byteAt(bytes, 2) !== 0xff || byteAt(bytes, 3) !== 0x9b) {
    return false;
  }
  for (let i = 4; i < 12; i++) {
    if (byteAt(bytes, i) !== 0) return false;
  }
  return true;
}

type ParsedLiteral =
  | { readonly family: "ipv4"; readonly bytes: Uint8Array; readonly address: string }
  | { readonly family: "ipv6"; readonly bytes: Uint8Array; readonly address: string };

function parsedAddress(text: unknown): ParsedLiteral | null {
  let input = typeof text === "string" ? text : "";
  if (input.startsWith("[") && input.endsWith("]")) input = input.slice(1, -1);
  const quad = parseIPv4(input);
  if (quad.ok) return { family: "ipv4", bytes: quad.bytes, address: formatIPv4(quad.bytes) };
  const v6 = parseIPv6(input);
  if (v6.ok) return { family: "ipv6", bytes: v6.bytes, address: formatIPv6(v6.bytes) };
  return null;
}

function classifyParsed(parsed: ParsedLiteral): AddressVerdict {
  return parsed.family === "ipv4" ? classifyIPv4(parsed.bytes) : classifyIPv6(parsed.bytes);
}
