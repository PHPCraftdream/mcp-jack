// Reference Server Card key discovery of spec/06-webhooks.md section 7 (R7.1-R7.5); pure, deterministic, no fetch.
import { validateJwk } from './primitives.mjs';
import { checkUrl, parseCidr } from './ssrf.mjs';

export const EVENTS_EXTENSION = 'io.modelcontextprotocol/events';

const DEFAULT_PORT = 443;
const CARD_SUFFIX = '/server-card';
const MAX_CARD_BYTES = 65536;
const MAX_CARD_TTL = 300;
const DEFAULT_CARD_TTL = 300;

// R7.2: same scheme, host and port; a url that does not parse is never the same origin.
export function sameOrigin(a, b) {
  const left = checkUrl(a);
  const right = checkUrl(b);
  if (!left.ok || !right.ok) return false;
  return left.scheme === right.scheme && left.host === right.host && left.port === right.port;
}

// R7.2: the reserved default `GET <streamable-http-url>/server-card`, or null off https.
export function defaultCardUrl(mcpUrl) {
  const checked = checkUrl(mcpUrl);
  if (!checked.ok) return null;
  const suffix = checked.port === DEFAULT_PORT ? '' : `:${checked.port}`;
  const path = checked.path.length > 1 && checked.path.endsWith('/') ? checked.path.slice(0, -1) : checked.path;
  return `https://${checked.host}${suffix}${path === '/' ? '' : path}${CARD_SUFFIX}`;
}

// R7.1: exact path, then the longest prefix, then origin only; ties keep document order.
export function selectRemote(card, { mcpUrl } = {}) {
  const target = checkUrl(mcpUrl);
  if (!target.ok) return { ok: false, code: 'no_remote' };
  const remotes = card && Array.isArray(card.remotes) ? card.remotes : [];
  let best = null;
  let bestTier = 0;
  let bestLength = -1;
  for (const remote of remotes) {
    if (!remote || typeof remote !== 'object' || typeof remote.url !== 'string') continue;
    if (remote.url.includes('{')) continue;
    const checked = checkUrl(remote.url);
    if (!checked.ok || !sameOrigin(remote.url, mcpUrl)) continue;
    let tier = 1;
    let length = 0;
    if (checked.path === target.path) {
      tier = 3;
    } else if (target.path.startsWith(checked.path)) {
      tier = 2;
      length = checked.path.length;
    }
    if (tier > bestTier || (tier === bestTier && length > bestLength)) {
      best = remote;
      bestTier = tier;
      bestLength = length;
    }
  }
  return best ? { ok: true, remote: best } : { ok: false, code: 'no_remote' };
}

// R7.1: the events webhooks object of the selected remote; absence states nothing about support.
export function webhookInfo(card, { mcpUrl } = {}) {
  const selected = selectRemote(card, { mcpUrl });
  if (!selected.ok) return selected;
  const info = selected.remote.extensionsInfo?.[EVENTS_EXTENSION]?.webhooks;
  const present = info !== null && typeof info === 'object';
  const keys = present ? info.signingKeys : undefined;
  const signingKeys = keys !== null && typeof keys === 'object' ? keys : null;
  const egressIpRanges = present && Array.isArray(info.egressIpRanges) ? info.egressIpRanges : [];
  return { ok: true, signingKeys, egressIpRanges, remote_url: selected.remote.url };
}

// R7.3: each JWK validated on its own, then the server's own key moved out, then every key of a duplicated kid.
export function acceptJwkSet(signingKeys, { mcpServerKid = null, mcpServerPublicKey = null } = {}) {
  const entries = signingKeys && Array.isArray(signingKeys.keys) ? signingKeys.keys : [];
  const accepted = [];
  const rejected = [];
  for (const jwk of entries) {
    const verdict = validateJwk(jwk);
    if (verdict.ok) accepted.push({ kid: verdict.key.kid, public_key: verdict.key.public_key, pub: verdict.key.pub });
    else rejected.push({ kid: jwk?.kid ?? null, reason: verdict.reason });
  }
  const surviving = [];
  for (const key of accepted) {
    const isServerKey =
      (mcpServerKid !== null && key.kid === mcpServerKid) ||
      (mcpServerPublicKey !== null && key.public_key === mcpServerPublicKey);
    if (isServerKey) rejected.push({ kid: key.kid, reason: 'mcp_server_key' });
    else surviving.push(key);
  }
  const counts = new Map();
  for (const key of surviving) counts.set(key.kid, (counts.get(key.kid) ?? 0) + 1);
  const kept = [];
  for (const key of surviving) {
    if (counts.get(key.kid) > 1) rejected.push({ kid: key.kid, reason: 'duplicate_kid' });
    else kept.push(key);
  }
  return { accepted: kept, rejected };
}

// R7.5: advisory egress CIDRs; malformed entries are dropped and recorded.
export function parseCidrList(values) {
  const accepted = [];
  const rejected = [];
  const list = Array.isArray(values) ? values : [];
  for (const value of list) {
    const parsed = parseCidr(value);
    if (parsed.ok) accepted.push({ cidr: value, family: parsed.family, prefix: parsed.prefix });
    else rejected.push({ value, reason: 'malformed_cidr' });
  }
  return { accepted, rejected };
}

// R7.2: one card fetch decision, in the order https, same origin, redirect, status, time, size, json, keys.
export function fetchDecision({ mcpUrl, cardUrl, response, elapsed_ms } = {}) {
  const card = checkUrl(cardUrl);
  if (!card.ok) return { ok: false, code: 'not_https', reason: card.reason ?? card.code };
  if (!sameOrigin(cardUrl, mcpUrl)) return { ok: false, code: 'cross_origin', reason: 'origin_mismatch' };
  const answer = response && typeof response === 'object' ? response : {};
  const status = answer.status;
  const redirected = answer.redirect_to !== undefined && answer.redirect_to !== null;
  if (redirected || (typeof status === 'number' && status >= 300 && status <= 399)) {
    return { ok: false, code: 'redirect_refused', reason: 'redirect' };
  }
  if (!(typeof status === 'number' && status >= 200 && status <= 299)) {
    return { ok: false, code: 'http_status', reason: 'status' };
  }
  if (typeof elapsed_ms === 'number' && elapsed_ms > 10000) return { ok: false, code: 'timeout', reason: 'elapsed' };
  const body = Buffer.from(typeof answer.body_b64u === 'string' ? answer.body_b64u : '', 'base64');
  if (body.length > MAX_CARD_BYTES) return { ok: false, code: 'too_large', reason: 'body' };
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return { ok: false, code: 'bad_json', reason: 'json' };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, code: 'bad_json', reason: 'shape' };
  }
  const info = webhookInfo(parsed, { mcpUrl });
  if (!info.ok) return { ok: false, code: info.code, reason: 'no_remote' };
  const keys = acceptJwkSet(info.signingKeys);
  return {
    ok: true,
    keys: keys.accepted,
    egressIpRanges: parseCidrList(info.egressIpRanges).accepted,
    rejected_keys: keys.rejected,
    cache_ttl: cardCacheTtl(answer.headers),
  };
}

// R7.2, R7.3: exact kid lookup in the accepted set only.
export function cardKeyForKid(keys, kid) {
  if (typeof kid !== 'string' || kid.length === 0) return { ok: false, code: 'unknown_webhook_key' };
  const list = Array.isArray(keys) ? keys : [];
  const key = list.find((entry) => entry !== null && typeof entry === 'object' && entry.kid === kid);
  return key ? { ok: true, key } : { ok: false, code: 'unknown_webhook_key' };
}

// R7.6: the card key set and the signed `jack.server.webhook_key` tool result must agree, member by member.
export function crossCheckWebhookKey({ keys = [], toolResult = null, require = false } = {}) {
  if (require !== true) return { ok: true };
  const published = toolResult?.webhook_key?.signing_keys?.keys;
  if (!Array.isArray(published)) return { ok: false, code: 'webhook_key_missing' };
  if (canonicalKeySet(keys) !== canonicalKeySet(published)) return { ok: false, code: 'webhook_key_mismatch' };
  return { ok: true };
}

const cardCacheTtl = (headers) => {
  const value = headers !== null && typeof headers === 'object' ? headers['cache-control'] : undefined;
  if (typeof value !== 'string') return DEFAULT_CARD_TTL;
  for (const part of value.split(',')) {
    const token = part.trim();
    if (!/^max-age=[0-9]+$/.test(token)) continue;
    return Math.min(Number(token.slice('max-age='.length)), MAX_CARD_TTL);
  }
  return DEFAULT_CARD_TTL;
};

const canonicalKeySet = (values) => {
  const list = Array.isArray(values) ? values : [];
  const mapped = [];
  for (const entry of list) {
    if (entry === null || typeof entry !== 'object') continue;
    mapped.push({ kty: entry.kty, crv: entry.crv, x: entry.x, kid: entry.kid });
  }
  mapped.sort((left, right) => {
    const a = String(left.kid);
    const b = String(right.kid);
    if (a < b) return -1;
    return a > b ? 1 : 0;
  });
  return JSON.stringify(mapped);
};
