// Pinned values and derivations of the webhook matrix (interop/webhook/contract.md
// sections 2 and 3). Dependency-free Node >= 20 tooling: node: builtins only.
import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

// Section 3 of the contract: the whole configuration space of the matrix.
export const CLOCK_BASE = 1800000000;
export const AUD = 'https://svc.example.test';
export const PRINCIPAL = 'alice';
export const EVENT_NAME = 'incident.created';
export const ARGUMENTS_JSON = '{"severity":"P1"}';
export const SECRET_SEED = 'mcp-jack-interop-webhook/secret/1';
export const CALLBACK_HOST = 'hooks.example.test';
export const CALLBACK_PATH = '/hooks/alice';
export const CARD_MCP_URL = 'https://mcp.example.test/mcp';
export const MAX_BODY_BYTES = 262144;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// Exact body bytes of the contract; no trailing newline anywhere.
export const EVENT_BODY = Buffer.from(
  '{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}',
  'utf8',
);
export const GAP_BODY = Buffer.from('{"type":"gap","cursor":"cursor_7f3a"}', 'utf8');
export const TERMINATED_BODY = Buffer.from(
  '{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}',
  'utf8',
);
export const RAW_BODIES = Object.freeze({
  'unknown-type': Buffer.from('{"type":"bogus"}', 'utf8'),
  malformed: Buffer.from('plain text, not JSON', 'utf8'),
});

// Named comparison of a received body, so the scenario table never carries bytes.
export function bodyName(bytes) {
  const body = Buffer.from(bytes);
  if (body.length === 0) return 'empty';
  if (body.equals(EVENT_BODY)) return 'event';
  if (body.equals(GAP_BODY)) return 'gap';
  if (body.equals(TERMINATED_BODY)) return 'terminated';
  for (const [name, pinned] of Object.entries(RAW_BODIES)) {
    if (body.equals(pinned)) return name;
  }
  return 'other';
}

// Canonical JSON text (members sorted, no insignificant whitespace) of a value.
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const members = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(',')}}`;
  }
  return JSON.stringify(value);
}

// Named comparison of a forwarded payload by its parsed value: the enqueue
// callback is handed canonical JSON text of the parsed payload by some SDKs and
// the raw message by others, so the bytes differ while the value does not.
export function jsonBodyName(bytes) {
  const raw = Buffer.from(bytes);
  const pinned = { event: EVENT_BODY, gap: GAP_BODY, terminated: TERMINATED_BODY };
  let parsed = null;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    parsed = null;
  }
  if (parsed !== null) {
    for (const [name, body] of Object.entries(pinned)) {
      if (canonicalJson(parsed) === canonicalJson(JSON.parse(body.toString('utf8')))) return name;
    }
    return 'other';
  }
  return bodyName(raw);
}

export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

// The 32 delivery secret bytes are a digest of the seed, never a whsec_ literal.
export const secretBytes = (seed = SECRET_SEED) => sha256(Buffer.from(seed, 'utf8'));

export const callbackUrl = (port) => `https://${CALLBACK_HOST}:${port}${CALLBACK_PATH}`;

// spec 06 R8.4: sub_ plus the first 16 hex characters of SHA-256 over the JCS array.
export function subscriptionId(url, principal = PRINCIPAL, name = EVENT_NAME, args = ARGUMENTS_JSON) {
  const jcs = `["mcp-jack/webhook1/subscription",${JSON.stringify(principal)},${JSON.stringify(url)},${JSON.stringify(name)},${args}]`;
  return 'sub_' + sha256(Buffer.from(jcs, 'utf8')).toString('hex').slice(0, 16);
}

// spec 06 R1.4: the prefix that belongs to a message kind.
export function kindPrefix(kind) {
  if (kind === 'gap' || kind === 'terminated' || kind === 'verification') return `msg_${kind}_`;
  return 'msg_';
}

// The derived id of message `index`: 32 alphabet characters from a digest.
export function webhookId(scenario, index, kind) {
  const digest = sha256(Buffer.from(`mcp-jack-interop-webhook/id/${scenario}/${index}`, 'utf8'));
  let suffix = '';
  for (let i = 0; i < 32; i++) suffix += ALPHABET[digest[i] % ALPHABET.length];
  return kindPrefix(kind) + suffix;
}

// The prefix a received id carries: 'msg_', 'msg_gap_', 'msg_terminated_',
// 'msg_verification_' or '' when the value does not start with 'msg_'.
export function idPrefix(value) {
  const match = /^msg_(?:(gap|terminated|verification)_)?/.exec(String(value));
  if (match === null) return '';
  return match[1] === undefined ? 'msg_' : `msg_${match[1]}_`;
}

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function deriveKeys(seedHex) {
  const priv = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(String(seedHex), 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const publicKeyB64u = b64u(spki.subarray(spki.length - 32));
  return { priv, publicKey: createPublicKey(priv), publicKeyB64u, kid: keyId(publicKeyB64u) };
}

export function publicKeyFromB64u(text) {
  const raw = Buffer.from(String(text), 'base64url');
  if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 raw bytes');
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export const keyId = (publicKeyB64u) => b64u(sha256(Buffer.from(String(publicKeyB64u), 'base64url')));

export const signBytes = (priv, bytes) => sign(null, bytes, priv);

// spec 06 R4.2: the seven lines of the Jack w1 signing string.
export function w1SigningString(parts) {
  return [
    'mcp-jack/webhook1/delivery',
    parts.aud,
    parts.subscriptionId,
    parts.webhookId,
    String(parts.timestamp),
    parts.callbackUrl,
    b64u(sha256(parts.body)),
  ].join('\n');
}

export function w1Header(priv, kid, parts) {
  return `w1 kid=${kid},sig=${b64u(signBytes(priv, Buffer.from(w1SigningString(parts), 'utf8')))}`;
}

// spec 06 R4.1: scheme w1, then kid and sig once each in any order.
export function parseW1(value) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text.startsWith('w1 ')) return null;
  const params = new Map();
  for (const part of text.slice(3).split(',')) {
    const eq = part.indexOf('=');
    if (eq < 1) return null;
    const name = part.slice(0, eq);
    if (params.has(name)) return null;
    params.set(name, part.slice(eq + 1));
  }
  if (params.size !== 2) return null;
  const kid = params.get('kid');
  const sig = params.get('sig');
  if (!/^[A-Za-z0-9_-]{43}$/.test(kid ?? '')) return null;
  if (!/^[A-Za-z0-9_-]{86}$/.test(sig ?? '')) return null;
  return { kid, sig };
}

// spec 06 R2.4: one or more <scheme>,<value> entries separated by one space.
export function parseEmission(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  const entries = [];
  for (const part of value.split(' ')) {
    const comma = part.indexOf(',');
    if (comma < 1 || comma === part.length - 1) return null;
    entries.push({ scheme: part.slice(0, comma), value: part.slice(comma + 1) });
  }
  return entries.length === 0 ? null : entries;
}

function schemeView(entries, scheme, check) {
  const mine = (entries ?? []).filter((entry) => entry.scheme === scheme);
  let valid = false;
  for (const entry of mine) {
    if (check(entry.value)) {
      valid = true;
      break;
    }
  }
  return { present: mine.length > 0, count: mine.length, valid };
}

// Independent verification of the v1, v1a and v2a entries with pinned material.
export function verifyEmission({ entries, secret, keys, subscriptionId: subId, webhookId: id, timestamp, body }) {
  const raw = Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), Buffer.from(body)]);
  const v1 = (value) => {
    const expected = createHmac('sha256', secret).update(raw).digest();
    const actual = Buffer.from(String(value), 'base64');
    return actual.length === 32 && actual.equals(expected);
  };
  const asymmetric = (signedBytes) => (value) => {
    const signature = Buffer.from(String(value), 'base64');
    if (signature.length !== 64) return false;
    return keys.some((key) => {
      try {
        return verify(null, signedBytes, key, signature);
      } catch {
        return false;
      }
    });
  };
  const v2aContent = Buffer.concat([Buffer.from(`${subId}.${id}.${timestamp}.`, 'utf8'), Buffer.from(body)]);
  return {
    v1: schemeView(entries, 'v1', v1),
    v1a: schemeView(entries, 'v1a', asymmetric(raw)),
    v2a: schemeView(entries, 'v2a', asymmetric(sha256(v2aContent))),
  };
}

// Independent verification of the Jack w1 header.
export function verifyW1({ value, keys, parts }) {
  if (typeof value !== 'string' || value.trim() === '') return { present: false, count: 0, kid: null, valid: false };
  const parsed = parseW1(value);
  if (parsed === null) return { present: true, count: 1, kid: null, valid: false };
  const signed = Buffer.from(w1SigningString(parts), 'utf8');
  const signature = Buffer.from(parsed.sig, 'base64url');
  const valid = keys.some((key) => {
    try {
      return verify(null, signed, key, signature);
    } catch {
      return false;
    }
  });
  return { present: true, count: 1, kid: parsed.kid, valid };
}

const PLACEHOLDER = /^\$(kid|public_key):([A-Za-z0-9_-]+)$/;

// Resolve `$kid:<name>`, `$public_key:<name>`, `$sub` and `$url` in an
// expectation document; an unknown name throws so the driver can report it.
export function resolvePlaceholders(value, vars) {
  if (typeof value === 'string') {
    if (value === '$sub') return vars.subscriptionId;
    if (value === '$url') return vars.url;
    const match = PLACEHOLDER.exec(value);
    if (match === null) return value;
    const entry = vars.keysByName[match[2]];
    if (entry === undefined) throw new Error(`unknown fixture key '${match[2]}' in placeholder '${value}'`);
    return match[1] === 'kid' ? entry.kid : entry.public_key;
  }
  if (Array.isArray(value)) return value.map((item) => resolvePlaceholders(item, vars));
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = resolvePlaceholders(item, vars);
    return out;
  }
  return value;
}
