/**
 * Value rules of the modern profile of spec 04 (MCP 2026-07-28): the `Mcp-Name`
 * source table, the character classes of section 2, the C3 header-value encoder
 * and C4 decoder of section 4, and the type-to-text projection of section 4.
 * Port of `spec/tools/modern/headers/reference/values.mjs`, without Buffer.
 */

/** Oldest version of the modern profile; a well-formed version at or after it takes the modern path (spec 04 section 1). */
export const MODERN_MIN = "2026-07-28";

/** 2^53-1, the largest magnitude an "integer" header value may have and still round-trip (spec 04 section 4). */
export const SAFE_INT_MAX = 9007199254740991;

/** One shared strict UTF-8 decoder: a decode failure is exactly "not valid UTF-8" (RFC 3629) and ignoreBOM keeps a leading U+FEFF. */
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** One header field: name and value, both as received or as they are to be sent. */
export type HeaderPair = readonly [string, string];

/** The body field a `Mcp-Name` mirror is taken from: `params.name` or `params.uri`. */
export type NameSource = "name" | "uri";

/** Methods that carry a `Mcp-Name` mirror and the body field it mirrors (spec 04 section 5); any other method has no source. */
export const NAME_SOURCE: Readonly<Record<string, NameSource>> = {
  "tools/call": "name",
  "prompts/get": "name",
  "events/poll": "name",
  "events/stream": "name",
  "events/subscribe": "name",
  "events/unsubscribe": "name",
  "resources/read": "uri",
};

/** The `Mcp-Name` source of a method, or null where the mirror does not apply; it is an own-key lookup, so a method named after an `Object` member never matches. */
export function nameSourceOf(method: string): NameSource | null {
  if (!Object.hasOwn(NAME_SOURCE, method)) return null;
  // noUncheckedIndexedAccess: the value is present but typed optional.
  return NAME_SOURCE[method] ?? null;
}

/** version = 4DIGIT "-" 2DIGIT "-" 2DIGIT, exactly ten characters; well-formed versions compare byte-wise, which is chronological. */
export function isVersion(value: unknown): value is string {
  return typeof value === "string" && VERSION_RE.test(value);
}

/** True for a well-formed version at or after MODERN_MIN; a string comparison over the fixed-width form is the newer-or-equal test (spec 04 section 1). */
export function isModernVersion(value: unknown): boolean {
  return isVersion(value) && value >= MODERN_MIN;
}

/** field-value after OWS removal: HTAB, SP or VCHAR only. Iterating code points rejects DEL, every high byte and every non-ASCII character in one test. */
export function isFieldValue(value: string): boolean {
  for (const ch of value) {
    const cp = codePointOf(ch);
    if (cp === 0x09) continue;
    if (cp < 0x20 || cp > 0x7e) return false;
  }
  return true;
}

/** 1*tchar: the special set plus DIGIT and ALPHA, at least one character. */
export function isToken(value: string): boolean {
  if (value.length === 0) return false;
  for (const ch of value) {
    const alnum = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9");
    if (!alnum && !TCHAR_SPECIAL.includes(ch)) return false;
  }
  return true;
}

/** True for the `=?base64?...?=` envelope: the markers are case-sensitive lowercase, and an 11-character value has an empty inner text that still decodes to the empty string. */
export function isSentinel(value: string): boolean {
  return value.startsWith(SENTINEL_OPEN) && value.endsWith(SENTINEL_CLOSE) && value.length >= SENTINEL_MIN_LENGTH;
}

/** C3: the sentinel is needed iff the text is non-empty and holds a code point outside 0x20-0x7E, starts or ends with SP, or already looks like a sentinel. */
export function encodeHeaderValue(text: string): string {
  if (!needsSentinel(text)) return text;
  return SENTINEL_OPEN + encodeBase64(utf8Bytes(text)) + SENTINEL_CLOSE;
}

/** The result of C4: the recovered text, or the single reason a sentinel is not decodable at all. */
export type DecodedHeaderValue =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: "bad_encoding" };

/** C4: a non-sentinel is plain text. A sentinel's inner text must be canonical standard base64 of valid UTF-8, otherwise it is not decodable at all. */
export function decodeHeaderValue(value: string): DecodedHeaderValue {
  const bad: DecodedHeaderValue = { ok: false, reason: "bad_encoding" };
  if (!isSentinel(value)) return { ok: true, text: value };
  const inner = value.slice(SENTINEL_OPEN.length, value.length - SENTINEL_CLOSE.length);
  if (inner !== "" && (inner.length % 4 !== 0 || !BASE64_RE.test(inner))) return bad;
  const bytes = decodeBase64(inner);
  // Canonicality: decode-then-reencode must reproduce the inner text, which
  // also rejects non-zero unused trailing bits.
  if (encodeBase64(bytes) !== inner) return bad;
  try {
    // ignoreBOM keeps a leading U+FEFF instead of dropping it: the header value
    // mirrors the body text byte for byte.
    return { ok: true, text: UTF8_DECODER.decode(bytes) };
  } catch {
    return bad;
  }
}

/** The text of bytes that are valid UTF-8, undefined otherwise; the client reads verified response bodies with it. */
export function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch {
    return undefined;
  }
}

/** Type-to-text of section 4; null means the value is not representable in a header. */
export function valueText(value: unknown, type: string): string | null {
  if (type === "string") return typeof value === "string" ? value : null;
  if (type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value) || Math.abs(value) > SAFE_INT_MAX) return null;
    return String(value);
  }
  if (type === "boolean") return value === true ? "true" : value === false ? "false" : null;
  return null;
}

/** The opening marker of a sentinel, matched case-sensitively. */
const SENTINEL_OPEN = "=?base64?";

/** The closing marker of a sentinel, matched case-sensitively. */
const SENTINEL_CLOSE = "?=";

/** Shortest sentinel: the two markers plus an empty inner text, which still decodes to the empty string. */
const SENTINEL_MIN_LENGTH = SENTINEL_OPEN.length + SENTINEL_CLOSE.length;

/** The version form of spec 04 section 1. */
const VERSION_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

/** Canonical padded standard base64: an empty string, full groups, and at most one padded tail. */
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** tchar minus ALPHA and DIGIT. */
const TCHAR_SPECIAL = "!#$%&'*+-.^_`|~";

/** The exact RFC 4648 section 4 alphabet, padding written separately. */
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Lookup table: alphabet index 0..63, or -1 for any other char code below 128. */
const BASE64_LOOKUP = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i++) {
    table[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** The code point of the one-character string that string iteration yields. */
function codePointOf(ch: string): number {
  const cp = ch.codePointAt(0);
  return cp === undefined ? 0 : cp;
}

/** True when C3 must wrap the text in a sentinel (see encodeHeaderValue). */
function needsSentinel(text: string): boolean {
  if (text === "") return false;
  if (isSentinel(text) || text.startsWith(" ") || text.endsWith(" ")) return true;
  for (const ch of text) {
    const cp = codePointOf(ch);
    if (cp < 0x20 || cp > 0x7e) return true;
  }
  return false;
}

/** UTF-8 bytes of a string; an unpaired surrogate becomes U+FFFD, as in TextEncoder and Node's UTF-8 writer. */
function utf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (const ch of text) {
    let cp = codePointOf(ch);
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
  }
  return Uint8Array.from(out);
}

/** Canonical padded standard base64 of bytes. */
function encodeBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += BASE64_ALPHABET.charAt(b0 >> 2);
    out += BASE64_ALPHABET.charAt(((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    if (b1 === undefined) {
      out += "==";
      break;
    }
    out += BASE64_ALPHABET.charAt(((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    if (b2 === undefined) {
      out += "=";
      break;
    }
    out += BASE64_ALPHABET.charAt(b2 & 0x3f);
  }
  return out;
}

/** The 6-bit value of the character at index i, or -1 for padding or anything outside the alphabet. */
function sextet(s: string, i: number): number {
  const code = s.charCodeAt(i);
  const v = code < 128 ? BASE64_LOOKUP[code] : undefined;
  return v === undefined ? -1 : v;
}

/** Decodes inner text already matched by BASE64_RE; the caller checks canonicality by re-encoding. */
function decodeBase64(inner: string): Uint8Array {
  const out = new Uint8Array((inner.length / 4) * 3);
  let n = 0;
  for (let i = 0; i < inner.length; i += 4) {
    const c0 = sextet(inner, i);
    const c1 = sextet(inner, i + 1);
    const c2 = sextet(inner, i + 2);
    const c3 = sextet(inner, i + 3);
    out[n++] = ((c0 << 2) | (c1 >> 4)) & 0xff;
    if (c2 >= 0) out[n++] = ((c1 << 4) | (c2 >> 2)) & 0xff;
    if (c3 >= 0) out[n++] = ((c2 << 6) | c3) & 0xff;
  }
  return out.subarray(0, n);
}
