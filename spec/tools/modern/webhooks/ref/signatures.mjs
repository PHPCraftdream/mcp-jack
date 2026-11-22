// Reference signatures of spec/06-webhooks.md sections 2 and 4; pure, node:crypto only.
import { createPublicKey, sign, verify } from 'node:crypto';
import { b64StdDecodeStrict, b64StdEncode, b64u, b64uDecodeStrict, constTimeEqual, hmacSha256, sha256 } from './primitives.mjs';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SIG_LEN_ASYM = 64;
const SIG_LEN_HMAC = 32;
const SP = ' ';
const SIGNATURE_SCHEMES = new Set(['v1', 'v1a', 'v2a']);
const KID_LEN = 43;
const W1_SIG_LEN = 86;
const W1_SCHEME = 'w1';

const bytesOf = (buf) => (Buffer.isBuffer(buf) ? buf : Buffer.from(buf));

const utf8 = (text, body) => Buffer.concat([Buffer.from(`${text}.`, 'utf8'), bytesOf(body)]);

const privateOf = (key) => {
  const inner = key && typeof key === 'object' ? (key.priv ?? key.key) : undefined;
  return inner ?? key;
};

const publicKeyOf = (raw) => createPublicKey({ key: Buffer.concat([SPKI_PREFIX, bytesOf(raw)]), format: 'der', type: 'spki' });

function verifies(keyObject, message, sig) {
  try {
    return verify(null, message, keyObject, sig) === true;
  } catch {
    return false;
  }
}

// R2.2: id, timestamp and raw body joined by dots as UTF-8 bytes.
export const v1Content = ({ webhookId, timestamp, body }) => utf8(`${webhookId}.${timestamp}`, body);

// R2.2: v1 header entry over the decoded secret bytes.
export const v1Sign = (secretBytes, parts) => `v1,${b64StdEncode(hmacSha256(secretBytes, v1Content(parts)))}`;

// R2.5: v1a content is the same raw content as v1.
export const v1aContent = (parts) => v1Content(parts);

// R2.5: v1a header entry, an Ed25519 signature over the raw content.
export const v1aSign = (key, parts) => `v1a,${b64StdEncode(sign(null, v1aContent(parts), privateOf(key)))}`;

// R2.6: endpoint id, id, timestamp and body hashed once with SHA-256.
export const v2aContent = ({ endpointId, webhookId, timestamp, body }) =>
  sha256(utf8(`${endpointId}.${webhookId}.${timestamp}`, body));

// R2.6: v2a header entry, an Ed25519 signature over the SHA-256 digest.
export const v2aSign = (key, parts) => `v2a,${b64StdEncode(sign(null, v2aContent(parts), privateOf(key)))}`;

// R2.4: split the header into scheme and value pairs, without decoding.
export function parseSignatureHeader(value) {
  const bad = { ok: false, code: 'malformed_signature_header' };
  if (typeof value !== 'string' || value.length === 0) return bad;
  if (/^\s/.test(value) || /\s$/.test(value)) return bad;
  const entries = [];
  for (const part of value.split(SP)) {
    if (part.length === 0 || /\s/.test(part)) return bad;
    const comma = part.indexOf(',');
    if (comma <= 0 || comma === part.length - 1) return bad;
    const scheme = part.slice(0, comma);
    const entry = part.slice(comma + 1);
    if (!/^[A-Za-z0-9]+$/.test(scheme)) return bad;
    if (entry.includes(',') || /\s/.test(entry)) return bad;
    entries.push({ scheme, value: entry });
  }
  return { ok: true, entries };
}

// R3.11: every scheme must be v1, v1a or v2a.
export function checkSchemes(entries) {
  return entries.every((entry) => SIGNATURE_SCHEMES.has(entry.scheme))
    ? { ok: true }
    : { ok: false, code: 'unsupported_signature_scheme' };
}

// R3.12: canonical standard base64 of exactly 32 bytes for v1 and 64 bytes for v1a and v2a.
export function decodeEntries(entries) {
  const bad = { ok: false, code: 'malformed_signature' };
  const out = [];
  for (const entry of entries) {
    const sig = b64StdDecodeStrict(entry.value);
    if (!sig) return bad;
    if (entry.scheme === 'v1' ? sig.length !== SIG_LEN_HMAC : sig.length !== SIG_LEN_ASYM) return bad;
    out.push({ scheme: entry.scheme, sig });
  }
  return { ok: true, entries: out };
}

// R3.13: accept when any v1 entry equals the HMAC of the v1 content.
export function v1Verify(decoded, secretBytes, parts) {
  const mac = hmacSha256(secretBytes, v1Content(parts));
  const ok = decoded.some((entry) => entry.scheme === 'v1' && constTimeEqual(entry.sig, mac));
  return ok ? { ok: true } : { ok: false, code: 'bad_signature' };
}

// R3.14: accept when any v1a or v2a entry verifies under an accepted key, returning that key's kid.
export function asymVerify(decoded, keys, parts) {
  const entries = decoded.filter((entry) => entry.scheme === 'v1a' || entry.scheme === 'v2a');
  if (entries.length === 0) return { ok: false, code: 'bad_server_signature' };
  const messages = {
    v1a: v1aContent(parts),
    v2a: v2aContent({ endpointId: parts.endpointId, webhookId: parts.webhookId, timestamp: parts.timestamp, body: parts.body }),
  };
  for (const key of keys) {
    let publicKey;
    try {
      publicKey = publicKeyOf(key.pub);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (verifies(publicKey, messages[entry.scheme], entry.sig)) return { ok: true, kid: key.kid };
    }
  }
  return { ok: false, code: 'bad_server_signature' };
}

// R2.8: current v1, previous v1, current v1a and v2a, then previous v1a and v2a, in that order.
export function emissionEntries({ secrets = [], keys = [], webhookId, timestamp, body, endpointId }) {
  const parts = { webhookId, timestamp, body, endpointId };
  const out = [];
  const currentSecret = secrets.find((entry) => entry.current === true);
  const previousSecret = secrets.find((entry) => entry.current === false || entry.current === undefined);
  const currentKey = keys.find((entry) => entry.current === true);
  const previousKey = keys.find((entry) => entry.current === false || entry.current === undefined);
  if (currentSecret) out.push(v1Sign(currentSecret.secret, parts));
  if (previousSecret) out.push(v1Sign(previousSecret.secret, parts));
  if (currentKey) out.push(v1aSign(currentKey.key, parts), v2aSign(currentKey.key, parts));
  if (previousKey) out.push(v1aSign(previousKey.key, parts), v2aSign(previousKey.key, parts));
  return out;
}

// R2.8: the emission set as one space-delimited header value.
export function emissionHeader(options) {
  return emissionEntries(options).join(SP);
}

// R4.2: seven LF-joined signing-string lines with no trailing LF.
export const w1SigningString = ({ aud, subscriptionId, webhookId, timestamp, callbackUrl, body }) =>
  [
    'mcp-jack/webhook1/delivery',
    aud,
    subscriptionId,
    webhookId,
    String(timestamp),
    callbackUrl,
    b64u(sha256(body)),
  ].join('\n');

// R4.1: the Jack header value from its two parameters.
export const w1HeaderValue = ({ kid, sig }) => `${W1_SCHEME} kid=${kid},sig=${sig}`;

// R4.2: sign the signing string and render the Jack header value.
export function w1Sign(key, parts) {
  if (!key || typeof key !== 'object' || typeof key.kid !== 'string') throw new Error('w1Sign requires a key with a kid');
  const sig = b64u(sign(null, Buffer.from(w1SigningString(parts), 'utf8'), privateOf(key)));
  return w1HeaderValue({ kid: key.kid, sig });
}

// R4.1: parse the Jack header grammar: w1, one SP, kid and sig once each, base64url values of fixed length.
export function parseW1Header(value) {
  const bad = { ok: false, code: 'malformed_jack_auth' };
  if (typeof value !== 'string' || !value.startsWith(`${W1_SCHEME} `)) return bad;
  const rest = value.slice(W1_SCHEME.length + 1);
  if (rest.length === 0 || /\s/.test(rest)) return bad;
  const params = new Map();
  for (const part of rest.split(',')) {
    if (part.length === 0) return bad;
    const eq = part.indexOf('=');
    if (eq <= 0 || eq === part.length - 1) return bad;
    const name = part.slice(0, eq);
    const paramValue = part.slice(eq + 1);
    if ((name !== 'kid' && name !== 'sig') || params.has(name)) return bad;
    if (!/^[A-Za-z0-9_-]+$/.test(paramValue)) return bad;
    params.set(name, paramValue);
  }
  const kid = params.get('kid');
  const sig = params.get('sig');
  if (!kid || !sig || kid.length !== KID_LEN || sig.length !== W1_SIG_LEN) return bad;
  return { ok: true, kid, sig };
}

// R3.15, R4.4, R4.5: parse, refuse the MCP server key id, look up the kid, check the window, then verify the signature.
export function w1Verify(headerValue, parts, { keys = [], now, window, mcpServerKid = null } = {}) {
  const parsed = parseW1Header(headerValue);
  if (!parsed.ok) return { ok: false, code: 'malformed_jack_auth' };
  if (mcpServerKid !== null && parsed.kid === mcpServerKid) return { ok: false, code: 'webhook_key_is_server_key' };
  const entry = keys.find((key) => key.kid === parsed.kid);
  if (!entry) return { ok: false, code: 'unknown_webhook_key' };
  if (Math.abs(now - Number(parts.timestamp)) > window) return { ok: false, code: 'jack_timestamp_out_of_window' };
  const sig = b64uDecodeStrict(parsed.sig);
  const message = Buffer.from(w1SigningString(parts), 'utf8');
  let publicKey;
  try {
    publicKey = publicKeyOf(entry.pub);
  } catch {
    return { ok: false, code: 'bad_jack_signature' };
  }
  if (!sig || !verifies(publicKey, message, sig)) return { ok: false, code: 'bad_jack_signature' };
  return { ok: true, kid: parsed.kid };
}
