// Self-test only: Ed25519 and wire helpers shared by the modern fakes (spec 01 sections 3 and 5). Not a reference implementation.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

// DER prefixes for a raw 32-byte Ed25519 seed (PKCS8) and a raw 32-byte
// Ed25519 public key (SPKI), RFC 8410; identical to interop/tools/fakes/fake-server.mjs.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// spec 01 section 3: the request header set is exactly kid, ts, nonce, sig, in
// that order, with the value alphabet A-Za-z0-9_- and a decimal ts of at most
// 12 digits and no leading zero (spec 01 section 3 grammar rules).
const REQUEST_AUTH = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),nonce=([A-Za-z0-9_-]+),sig=([A-Za-z0-9_-]+)$/;
// spec 01 section 5: the response header set is exactly kid, ts, sig.
const RESPONSE_AUTH = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)$/;
// spec 04 section 2: canonical RFC 4648 section 4 standard base64.
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// spec 04 section 2: exactly four digits, '-', two digits, '-', two digits.
const VERSION = /^\d{4}-\d{2}-\d{2}$/;

/** Unpadded base64url of the given bytes (spec 01 section 2). */
export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

/** Unpadded base64url of SHA-256 over the given bytes (spec 01 section 3.1). */
export const sha256b64u = (bytes) => b64u(createHash('sha256').update(bytes).digest());

/**
 * Derive the Ed25519 keypair from a 32-byte seed by prefixing the PKCS8 DER
 * header, and report the public key and its kid exactly like the fixture
 * generator does. kid = base64url(SHA-256(raw public key)).
 */
export function deriveKeys(seedHex) {
  const priv = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKeyB64u = publicKeyB64uFromPriv(priv);
  return { priv, publicKey: createPublicKey(priv), publicKeyB64u, kid: keyId(publicKeyB64u) };
}

/** Ed25519 KeyObject from a base64url encoding of the 32 raw key bytes (spec 01 section 2). */
export function publicKeyFromB64u(text) {
  const raw = Buffer.from(text, 'base64url');
  if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 raw bytes');
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

/** The raw public key of an Ed25519 private KeyObject, as base64url. */
export function publicKeyB64uFromPriv(priv) {
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return b64u(spki.subarray(spki.length - 32));
}

/** kid = base64url(SHA-256(raw public key bytes)) (spec 01 section 2). */
export function keyId(publicKeyB64u) {
  return b64u(createHash('sha256').update(Buffer.from(publicKeyB64u, 'base64url')).digest());
}

/**
 * Parse a request Jack-Auth value (spec 01 section 3). Returns
 * { kid, ts, nonce, sig } or null when the header does not match the strict
 * v1 grammar. The value is trimmed first; the parameter order is fixed.
 */
export function parseRequestAuth(header) {
  if (typeof header !== 'string') return null;
  const match = REQUEST_AUTH.exec(header.trim());
  if (match === null) return null;
  return { kid: match[1], ts: Number(match[2]), nonce: match[3], sig: match[4] };
}

/**
 * Build and sign the eight-line request signing string of spec 01 section 3.1.
 * `nonce` may be the raw 16 bytes or an already-encoded base64url string.
 * `body` is the exact request body byte string (a Buffer or Uint8Array).
 */
export function signRequest(priv, { aud, kid, method, target, ts, nonce, body }) {
  const nonceText = typeof nonce === 'string' ? nonce : b64u(nonce);
  const signing = [
    'mcp-jack/v1/request',
    method,
    target,
    aud,
    kid,
    String(ts),
    nonceText,
    sha256b64u(body),
  ].join('\n');
  const sig = b64u(sign(null, Buffer.from(signing, 'utf8'), priv));
  return {
    signing,
    header: `v1 kid=${kid},ts=${ts},nonce=${nonceText},sig=${sig}`,
    sig,
  };
}

/**
 * Recompute the request signing string from a parsed auth value and verify it
 * against the given public key (spec 01 section 4 step 7). Any failure, a
 * malformed key included, is simply `false`.
 */
export function verifyRequest(publicKeyB64u, { aud, method, target, auth, body }) {
  const signing = [
    'mcp-jack/v1/request',
    method,
    target,
    aud,
    auth.kid,
    String(auth.ts),
    auth.nonce,
    sha256b64u(body),
  ].join('\n');
  return verifySignature(publicKeyB64u, signing, auth.sig);
}

/** Sign a response header over the exact response body bytes (spec 01 section 5). */
export function signResponseHeader(priv, kid, status, requestSig, ts, body) {
  const signing = [
    'mcp-jack/v1/response',
    String(status),
    requestSig,
    kid,
    String(ts),
    sha256b64u(body),
  ].join('\n');
  const sig = b64u(sign(null, Buffer.from(signing, 'utf8'), priv));
  return `v1 kid=${kid},ts=${ts},sig=${sig}`;
}

/**
 * Verify a response Jack-Auth value (spec 01 section 5). Returns null when the
 * signature verifies, 'malformed_auth' when the header does not parse, and
 * 'bad_signature' when it parses but does not verify against the pinned key.
 */
export function verifyResponseHeader(publicKeyB64u, header, status, requestSig, body) {
  const match = typeof header === 'string' ? RESPONSE_AUTH.exec(header.trim()) : null;
  if (match === null) return 'malformed_auth';
  const signing = [
    'mcp-jack/v1/response',
    String(status),
    requestSig,
    match[1],
    match[2],
    sha256b64u(body),
  ].join('\n');
  return verifySignature(publicKeyB64u, signing, match[3]) ? null : 'bad_signature';
}

/**
 * The deterministic nonce of contract section 2: the first 16 bytes of
 * SHA-256 over utf8('mcp-jack-interop-modern/nonce/' + scenario + '/' + index).
 */
export function nonceFor(scenario, index) {
  const digest = createHash('sha256')
    .update(Buffer.from(`mcp-jack-interop-modern/nonce/${scenario}/${index}`, 'utf8'))
    .digest();
  return Buffer.from(digest.subarray(0, 16));
}

/**
 * spec 04 section 4 `C4`: decode a `=?base64? ... ?=` sentinel. Returns the
 * decoded text when the sentinel inner text is canonical standard base64 and
 * valid UTF-8, the value itself when the value is plain, and null when a
 * sentinel is not decodable.
 */
export function sentinelDecode(value) {
  if (typeof value !== 'string') return null;
  if (!value.startsWith('=?base64?') || !value.endsWith('?=')) return value;
  const inner = value.slice('=?base64?'.length, -'?='.length);
  if (!CANONICAL_BASE64.test(inner)) return null;
  const bytes = Buffer.from(inner, 'base64');
  // Canonical means decode-then-encode reproduces the text exactly.
  if (bytes.toString('base64') !== inner) return null;
  try {
    // fatal: overlong forms, encoded surrogates and truncated sequences fail.
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** spec 04 section 2: a well-formed version is exactly YYYY-MM-DD. */
export function wellFormedVersion(value) {
  return typeof value === 'string' && VERSION.test(value);
}

/**
 * spec 04 section 2: RFC 9110 field-value syntax. Only HTAB (0x09), SP (0x20)
 * and VCHAR (0x21-0x7E) bytes are allowed; anything else, including every byte
 * of 0x80-0xFF, violates the syntax.
 */
export function isFieldValue(text) {
  if (typeof text !== 'string') return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 0x09 || code === 0x20 || (code >= 0x21 && code <= 0x7e)) continue;
    return false;
  }
  return true;
}

// Shared Ed25519 verification; a malformed key or signature is a verification
// failure rather than a throw.
function verifySignature(publicKeyB64u, signing, sigText) {
  try {
    return verify(
      null,
      Buffer.from(signing, 'utf8'),
      publicKeyFromB64u(publicKeyB64u),
      Buffer.from(sigText, 'base64url'),
    );
  } catch {
    return false;
  }
}
