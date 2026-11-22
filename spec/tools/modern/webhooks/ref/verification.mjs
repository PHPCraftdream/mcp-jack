// Reference endpoint verification of spec/06-webhooks.md section 5 (R5.2-R5.10); pure, deterministic, no I/O.
import { constTimeEqual } from './primitives.mjs';
import { checkDelivery, checkUrl, parseHost } from './ssrf.mjs';

const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const MAX_RECEIVERS = 64;
const MAX_RECEIVER_PATH = 1024;
const DEFAULT_DOC_TTL = 300;
const HTTPS_PREFIX = 'https://';
const WILDCARD = '*.';
const PRINTABLE_RE = /^[\x21-\x7e]+$/;
const CONTROL_OR_MARK_RE = /[?#\u0000-\u001f\u007f]/;
const FIRST_PATH_MARK_RE = /[\/?#]/;
const PORT_RE = /^(0|[1-9][0-9]{0,4})$/;
const DEFAULT_PORT = 443;

// R5.3: exactly 22 base64url characters, the unpadded form of 16 CSPRNG bytes.
export const nonceOk = (value) => typeof value === 'string' && NONCE_RE.test(value);

// R5.4: accept a 2xx JSON object whose challenge member equals the nonce; member order is irrelevant.
export function challengeEcho({ status, bodyText, nonce, maxBody = 4096 } = {}) {
  const bad = (reason) => ({ ok: false, code: 'challenge_failed', reason });
  if (!Number.isInteger(status) || status < 200 || status > 299) return bad('status');
  if (typeof bodyText !== 'string') return bad('body');
  if (Buffer.byteLength(bodyText, 'utf8') > maxBody) return bad('too_large');
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return bad('json');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return bad('body');
  const echo = parsed.challenge;
  if (typeof echo !== 'string') return bad('missing');
  if (typeof nonce !== 'string') return bad('mismatch');
  if (!constTimeEqual(Buffer.from(echo, 'utf8'), Buffer.from(nonce, 'utf8'))) return bad('mismatch');
  return { ok: true };
}

// R5.3: the two members of an attempt pair as one comparable value, whatever object carries them.
export function pairKey(pair) {
  let principal;
  let url;
  if (Array.isArray(pair)) {
    if (pair.length !== 2) return null;
    [principal, url] = pair;
  } else if (pair !== null && typeof pair === 'object') {
    principal = pair.principal;
    url = pair.url;
  } else {
    return null;
  }
  if (typeof principal !== 'string' || typeof url !== 'string') return null;
  return JSON.stringify([String(principal), String(url)]);
}

// R5.3: value, freshness, single use and attempt pairing, checked in that order.
export function acceptEcho({ nonce, expected, issuedAt, now, ttl = 600, consumed = false, pair, expectedPair } = {}) {
  const bad = (reason) => ({ ok: false, code: 'challenge_failed', reason });
  if (typeof nonce !== 'string' || typeof expected !== 'string') return bad('mismatch');
  if (!constTimeEqual(Buffer.from(nonce, 'utf8'), Buffer.from(expected, 'utf8'))) return bad('mismatch');
  if (!(now - issuedAt <= ttl)) return bad('expired');
  if (consumed === true) return bad('reused');
  // R5.3: a pair that is not two non-empty strings is never a match, so two invalid pairs never compare equal.
  const attempt = pairKey(pair);
  if (attempt === null || attempt !== pairKey(expectedPair)) return bad('pair');
  return { ok: true };
}

// R5.9: the well-known receiver document, one failure reason naming the first offending check.
export function parseReceiverDoc(text) {
  const bad = (reason) => ({ ok: false, code: 'invalid_document', reason });
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return bad('json');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return bad('receivers');
  const receivers = parsed.receivers;
  if (!Array.isArray(receivers)) return bad('receivers');
  if (receivers.length < 1 || receivers.length > MAX_RECEIVERS) return bad('count');
  for (const entry of receivers) {
    if (typeof entry !== 'string' || entry.length > MAX_RECEIVER_PATH || !entry.startsWith('/')) return bad('entry');
    if (CONTROL_OR_MARK_RE.test(entry)) return bad('entry');
    if (entry.split('/').some((segment) => segment === '.' || segment === '..')) return bad('segment');
  }
  return { ok: true, receivers };
}

// R5.9: one fetch of the well-known document, judged on status, body and size before parsing.
export function checkReceiverDocFetch({ status, bodyText, maxBody = 8192 } = {}) {
  const bad = (reason) => ({ ok: false, code: 'document_fetch_failed', reason });
  if (!Number.isInteger(status) || status !== 200) return bad(Number.isInteger(status) ? `status_${status}` : 'status');
  if (typeof bodyText !== 'string') return bad('body');
  if (Buffer.byteLength(bodyText, 'utf8') > maxBody) return bad('too_large');
  return parseReceiverDoc(bodyText);
}

// R5.9: the same hardened path as a delivery, then the document fetch; no HTTP code lives here.
export function receiverDocRequest({ url, answers, allowedRanges, recheck, redirect, status, bodyText } = {}) {
  const delivery = checkDelivery({ url, answers, allowedRanges, recheck, redirect });
  if (delivery.decision === 'reject') return { ok: false, code: delivery.code, reason: delivery.reason };
  return checkReceiverDocFetch({ status, bodyText });
}

// R5.10: a byte prefix at a segment boundary, case-sensitive, no decoding, document order.
export function receiverDocCovers(doc, urlPath) {
  for (const entry of receiversOf(doc)) {
    if (coversPath(entry, urlPath)) return { covered: true, entry };
  }
  return { covered: false, entry: null };
}

// R5.7: one allowlist entry, `https` only, literal host or `*.parent`, port and path defaults applied.
export function parseAllowlistEntry(text) {
  const bad = { ok: false };
  if (typeof text !== 'string' || !text.startsWith(HTTPS_PREFIX) || !PRINTABLE_RE.test(text)) return bad;
  if (!text.startsWith(`${HTTPS_PREFIX}${WILDCARD}`)) {
    const checked = checkUrl(text);
    if (!checked.ok || checked.query !== '') return bad;
    return { ok: true, hostPattern: checked.host, port: checked.port, path: checked.path };
  }
  const rest = text.slice(HTTPS_PREFIX.length);
  const stop = rest.search(FIRST_PATH_MARK_RE);
  const authority = stop === -1 ? rest : rest.slice(0, stop);
  const path = stop === -1 ? '/' : rest.slice(stop);
  if (CONTROL_OR_MARK_RE.test(path)) return bad;
  if (authority.includes('@')) return bad;
  const colon = authority.indexOf(':');
  const hostText = colon === -1 ? authority : authority.slice(0, colon);
  const portText = colon === -1 ? null : authority.slice(colon + 1);
  if (portText !== null && (!PORT_RE.test(portText) || Number(portText) < 1 || Number(portText) > 65535)) {
    return bad;
  }
  if (!hostText.startsWith(WILDCARD)) return bad;
  const parent = parseHost(hostText.slice(WILDCARD.length));
  if (!parent.ok || parent.kind !== 'name') return bad;
  const port = portText === null ? DEFAULT_PORT : Number(portText);
  return { ok: true, hostPattern: `${WILDCARD}${parent.name}`, port, path };
}

// R5.7: first entry that matches host, port and path prefix wins; a bad url matches nothing.
export function allowlistMatches(entries, canonicalUrl) {
  const checked = checkUrl(canonicalUrl);
  if (!checked.ok) return { matched: false, entry: null };
  const list = Array.isArray(entries) ? entries : [];
  for (const value of list) {
    const entry = typeof value === 'string' ? parseAllowlistEntry(value) : value;
    if (!entry || entry.ok !== true || entry.port !== checked.port) continue;
    if (!hostMatches(entry.hostPattern, checked.host)) continue;
    if (!coversPath(entry.path, checked.path)) continue;
    return { matched: true, entry };
  }
  return { matched: false, entry: null };
}

// R5.2: fixed route order, first success wins; a null hook is not installed.
export function verificationRoute({ cache, allowlist, hook, doc, challenge } = {}) {
  const hit = (route) => ({ verified: true, route, reason: null });
  if (cache === true) return hit('cache');
  if (allowlist && allowlist.matched === true) return hit('allowlist');
  if (hook === true) return hit('out_of_band');
  if (doc && receiverDocCovers(doc.doc, doc.path).covered) return hit('well_known');
  if (challenge && challenge.ok === true) return hit('challenge');
  return { verified: false, route: null, reason: challenge ? challenge.reason : 'no_route' };
}

// R5.9: the well-known document url of the delivery origin, or null.
export function wellKnownUrl(canonicalUrl) {
  const checked = checkUrl(canonicalUrl);
  if (!checked.ok) return null;
  const suffix = checked.port === DEFAULT_PORT ? '' : `:${checked.port}`;
  return `https://${checked.host}${suffix}/.well-known/mcp-webhook-receiver.json`;
}

// R5.9: per-origin document cache TTL, capped at 300 s.
export const docCacheTtl = (maxAgeSeconds) =>
  typeof maxAgeSeconds === 'number' && Number.isFinite(maxAgeSeconds) && maxAgeSeconds >= 0
    ? Math.min(maxAgeSeconds, DEFAULT_DOC_TTL)
    : DEFAULT_DOC_TTL;

const receiversOf = (doc) => {
  if (Array.isArray(doc)) return doc;
  if (doc && typeof doc === 'object' && Array.isArray(doc.receivers)) return doc.receivers;
  return [];
};

const coversPath = (entry, urlPath) => {
  if (typeof entry !== 'string' || typeof urlPath !== 'string' || !urlPath.startsWith(entry)) return false;
  return entry.endsWith('/') || urlPath.length === entry.length || urlPath[entry.length] === '/';
};

const hostMatches = (pattern, host) => {
  if (typeof pattern !== 'string' || typeof host !== 'string') return false;
  if (pattern.startsWith(WILDCARD)) {
    const parent = pattern.slice(WILDCARD.length);
    return host.endsWith(`.${parent}`) && host.length > parent.length + 1;
  }
  return pattern === host;
};
