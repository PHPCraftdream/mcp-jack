// Reference subscription lifecycle of spec/06-webhooks.md section 8 (R8.1-R8.9); pure, deterministic, no I/O.
import { parseWhsec, sha256 } from './primitives.mjs';
import { checkUrl } from './ssrf.mjs';

const SUBSCRIPTION_DOMAIN = 'mcp-jack/webhook1/subscription';
const ID_PREFIX = 'sub_';
const ID_HEX_LEN = 16;
const DEFAULT_TTL_MS = 3600000;
const MIN_TTL_MS = 60000;
const MAX_TTL_MS = 86400000;
const CURSOR_MAX = 512;

const invalidArguments = (reason) => ({ ok: false, code: 'invalid_arguments', reason });

// R8.3: RFC 8785 canonical JSON; members sorted by UTF-16 code unit, no whitespace, ECMAScript numbers.
export function jcs(value) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'string') return JSON.stringify(value);
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new Error('jcs cannot serialize a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (type === 'object') {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new Error(`jcs cannot serialize a ${type}`);
}

// R8.2: the canonical callback url, delegated to the section 6 parser; only ok and canonical survive.
export function canonicalUrl(urlText) {
  const checked = checkUrl(urlText);
  return checked.ok ? { ok: true, canonical: checked.canonical } : checked;
}

// R8.1-R8.4: the four-component key, its JCS input and the derived sub_ id.
export function subscriptionKey({ principal, url, name, arguments: args } = {}) {
  if (typeof principal !== 'string') return invalidArguments('principal');
  if (typeof name !== 'string') return invalidArguments('name');
  const target = canonicalUrl(url);
  if (!target.ok) return target;
  const value = args ?? null;
  let canonicalArguments;
  let jcsInput;
  try {
    canonicalArguments = jcs(value);
    jcsInput = jcs([SUBSCRIPTION_DOMAIN, principal, target.canonical, name, value]);
  } catch {
    return invalidArguments('arguments');
  }
  const hex = sha256(Buffer.from(jcsInput, 'utf8')).toString('hex');
  return {
    ok: true,
    id: `${ID_PREFIX}${hex.slice(0, ID_HEX_LEN)}`,
    canonical_url: target.canonical,
    canonical_arguments: canonicalArguments,
    jcs_input: jcsInput,
  };
}

// R8.5: grant in milliseconds plus its ISO 8601 UTC second-precision refresh deadline.
export function ttlGrant({ ttlMs, now } = {}) {
  if (ttlMs === null) return { ok: true, grantMs: null, refreshBefore: null };
  let grantMs = DEFAULT_TTL_MS;
  if (ttlMs !== undefined) {
    if (!Number.isInteger(ttlMs) || ttlMs < 0) return invalidArguments('ttl');
    grantMs = Math.min(Math.max(ttlMs, MIN_TTL_MS), MAX_TTL_MS);
  }
  return { ok: true, grantMs, refreshBefore: isoSeconds(now + Math.floor(grantMs / 1000)) };
}

// R8.6: current first; the previous secret only while the exclusive 300 s grace window is open.
export function activeSecrets({ current, previous, graceEndsAt, now } = {}) {
  const out = [{ secret: secretBytes(current), current: true }];
  if (previous !== undefined && previous !== null && now < graceEndsAt) {
    out.push({ secret: secretBytes(previous), current: false });
  }
  return out;
}

// R8.7: the exact gap body, member order as written.
export const gapEnvelope = (cursor) => JSON.stringify({ type: 'gap', cursor });

// R8.8: the exact terminated body; code is the integer JSON-RPC code, data is present only when supplied.
export const terminatedEnvelope = ({ code, message, data }) => {
  if (!Number.isInteger(code)) throw new Error('terminatedEnvelope requires an integer code');
  if (typeof message !== 'string') throw new Error('terminatedEnvelope requires a string message');
  if (data !== undefined && (data === null || Array.isArray(data) || typeof data !== 'object')) {
    throw new Error('terminatedEnvelope data must be a non-null, non-array object');
  }
  return JSON.stringify({ type: 'terminated', error: { code, message, ...(data === undefined ? {} : { data }) } });
};

// R8.9: null, or 1-512 characters of printable ASCII 0x21-0x7E.
export function cursorOk(value) {
  if (value === null) return true;
  if (typeof value !== 'string' || value.length < 1 || value.length > CURSOR_MAX) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

const isoSeconds = (seconds) => `${new Date(seconds * 1000).toISOString().slice(0, 19)}Z`;

const secretBytes = (value) => {
  if (Buffer.isBuffer(value)) return value;
  const parsed = parseWhsec(value);
  if (!parsed.ok) throw new Error(`activeSecrets requires secret bytes or a whsec_ value (${parsed.reason})`);
  return parsed.key;
};
