// Byte and string primitives of spec 04 sections 2 and 4 (C3 encoder, C4 decoder).
import { SAFE_INT_MAX } from '../spec-data.mjs';

const SENTINEL_OPEN = '=?base64?';
const SENTINEL_CLOSE = '?=';
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TCHAR_SPECIAL = "!#$%&'*+-.^_`|~";

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function deepEqual(a, b) {
  return stableStringify(a) === stableStringify(b);
}

// version = 4DIGIT "-" 2DIGIT "-" 2DIGIT, exactly ten characters.
export function isVersion(s) {
  return typeof s === 'string' && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(s);
}

// Well-formed versions compare byte-wise, which is chronological.
export function compareVersion(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// field-value after OWS removal: HTAB, SP or VCHAR only. Iterating code points
// rejects DEL, every high byte and every non-ASCII character in one test.
export function isFieldValue(s) {
  if (typeof s !== 'string') return false;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp === 0x09) continue;
    if (cp < 0x20 || cp > 0x7e) return false;
  }
  return true;
}

// 1*tchar: the special set plus DIGIT and ALPHA, at least one character.
export function isToken(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (const ch of s) {
    const alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
    if (!alnum && !TCHAR_SPECIAL.includes(ch)) return false;
  }
  return true;
}

// Markers are case-sensitive lowercase. An 11-character value has an empty inner
// text and still decodes to the empty string, so the floor only keeps the two
// markers from overlapping.
export function isSentinel(s) {
  return typeof s === 'string' && s.startsWith(SENTINEL_OPEN) && s.endsWith(SENTINEL_CLOSE) && s.length >= 11;
}

// C3: the sentinel is needed iff the text is non-empty and holds a character
// outside 0x20-0x7E, starts or ends with SP, or already looks like a sentinel.
export function encodeHeaderValue(text) {
  const needsSentinel = text !== ''
    && (isSentinel(text)
      || text.startsWith(' ')
      || text.endsWith(' ')
      || [...text].some((ch) => { const cp = ch.codePointAt(0); return cp < 0x20 || cp > 0x7e; }));
  return needsSentinel ? SENTINEL_OPEN + Buffer.from(text, 'utf8').toString('base64') + SENTINEL_CLOSE : text;
}

// C4: a non-sentinel is plain text. A sentinel's inner text must be canonical
// standard base64 of valid UTF-8, otherwise it is not decodable at all.
export function decodeHeaderValue(text) {
  const bad = { ok: false, reason: 'bad_encoding' };
  if (!isSentinel(text)) return { ok: true, text };
  const inner = text.slice(SENTINEL_OPEN.length, text.length - SENTINEL_CLOSE.length);
  if (inner !== '' && (inner.length % 4 !== 0 || !BASE64_RE.test(inner))) return bad;
  const bytes = Buffer.from(inner, 'base64');
  // Canonicality: decode-then-reencode must reproduce the inner text.
  if (bytes.toString('base64') !== inner) return bad;
  let decoded;
  try {
    // ignoreBOM keeps a leading U+FEFF instead of dropping it: the header value
    // mirrors the body text byte for byte.
    decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return bad;
  }
  return { ok: true, text: decoded };
}

// Type-to-text of section 4; null means the value is not representable.
export function textOfValue(value, type) {
  if (type === 'string') return typeof value === 'string' ? value : null;
  if (type === 'integer') {
    const ok = typeof value === 'number' && Number.isInteger(value) && Math.abs(value) <= SAFE_INT_MAX;
    return ok ? String(value) : null;
  }
  if (type === 'boolean') return value === true ? 'true' : value === false ? 'false' : null;
  return null;
}
