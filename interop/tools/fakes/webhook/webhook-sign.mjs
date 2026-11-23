// Self-test only: signing, derivation and address helpers shared by the webhook
// fakes. Independent of every SDK; not a reference implementation.
import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const KIND_PREFIX = Object.freeze({
  event: 'msg_',
  gap: 'msg_gap_',
  terminated: 'msg_terminated_',
  verification: 'msg_verification_',
  raw: 'msg_',
});

export const BODIES = Object.freeze({
  event: Buffer.from(
    '{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}',
    'utf8',
  ),
  gap: Buffer.from('{"type":"gap","cursor":"cursor_7f3a"}', 'utf8'),
  terminated: Buffer.from(
    '{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}',
    'utf8',
  ),
});

const REJECTED_V4 = [
  ['0.0.0.0', 8, 'this_network'],
  ['10.0.0.0', 8, 'private_use'],
  ['100.64.0.0', 10, 'shared_address_space'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link_local'],
  ['172.16.0.0', 12, 'private_use'],
  ['192.168.0.0', 16, 'private_use'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
export const secretBytes = (seedText) => sha256(Buffer.from(String(seedText), 'utf8'));
export const keyId = (publicKeyB64u) => b64u(sha256(Buffer.from(String(publicKeyB64u), 'base64url')));

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

function idSuffix(digest) {
  let out = '';
  for (let i = 0; i < 32; i++) out += ALPHABET[digest[i] % ALPHABET.length];
  return out;
}

export function webhookIdFor(scenario, index, kind) {
  const digest = sha256(Buffer.from(`mcp-jack-interop-webhook/id/${scenario}/${index}`, 'utf8'));
  return (KIND_PREFIX[kind] ?? KIND_PREFIX.event) + idSuffix(digest);
}

export function randomWebhookId(kind) {
  return (KIND_PREFIX[kind] ?? KIND_PREFIX.event) + idSuffix(randomBytes(32));
}

export function subscriptionIdFor(url, principal = 'alice', name = 'incident.created', args = '{"severity":"P1"}') {
  const jcs = `["mcp-jack/webhook1/subscription",${JSON.stringify(principal)},${JSON.stringify(url)},${JSON.stringify(name)},${args}]`;
  return 'sub_' + sha256(Buffer.from(jcs, 'utf8')).toString('hex').slice(0, 16);
}

export function emissionHeader({ secret, keys, webhookId, timestamp, body, endpointId }) {
  const content = Buffer.concat([Buffer.from(`${webhookId}.${timestamp}.`, 'utf8'), Buffer.from(body)]);
  const entries = [`v1,${createHmac('sha256', secret).update(content).digest('base64')}`];
  const endpointContent = Buffer.concat([Buffer.from(`${endpointId}.${webhookId}.${timestamp}.`, 'utf8'), Buffer.from(body)]);
  for (const key of keys ?? []) {
    entries.push(`v1a,${sign(null, content, key.priv).toString('base64')}`);
    entries.push(`v2a,${sign(null, sha256(endpointContent), key.priv).toString('base64')}`);
  }
  return entries.join(' ');
}

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

export function w1Header(parts) {
  const signature = sign(null, Buffer.from(w1SigningString(parts), 'utf8'), parts.priv);
  return `w1 kid=${parts.kid},sig=${b64u(signature)}`;
}

function ipv4ToInt(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

function cidrContains(cidr, value) {
  const text = String(cidr);
  const slash = text.indexOf('/');
  const base = ipv4ToInt(slash === -1 ? text : text.slice(0, slash));
  if (base === null) return false;
  const length = slash === -1 ? 32 : Number(text.slice(slash + 1));
  if (!Number.isInteger(length) || length < 0 || length > 32) return false;
  if (length === 0) return true;
  const mask = length === 32 ? 0xffffffff : (0xffffffff << (32 - length)) >>> 0;
  return ((base & mask) >>> 0) === ((value & mask) >>> 0);
}

export function classifyAddress(address, allowedRanges = []) {
  const value = ipv4ToInt(address);
  if (value === null) return { allow: false, reason: 'not_an_ip' };
  for (const range of allowedRanges ?? []) {
    if (cidrContains(range, value)) return { allow: true, reason: 'allowed_range' };
  }
  for (const [base, length, reason] of REJECTED_V4) {
    const start = ipv4ToInt(base);
    const mask = length === 0 ? 0 : (0xffffffff << (32 - length)) >>> 0;
    if (((start & mask) >>> 0) === ((value & mask) >>> 0)) return { allow: false, reason };
  }
  return { allow: true, reason: 'global' };
}
