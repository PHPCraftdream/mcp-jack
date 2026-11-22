// Reference primitives of spec/06-webhooks.md sections 2 and 7; pure, node:crypto only.
import { createHash, createHmac, createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import { PKCS8_PREFIX } from '../../../gen/core.mjs';
import { validatePublicKey } from '../../../reference-verifier.mjs';

const B64U_RE = /^[A-Za-z0-9_-]*$/;
const B64_STD_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const WHSEC_PREFIX = 'whsec_';
const SEED_LEN = 32;
const KEY_MIN = 24;
const KEY_MAX = 64;

const bytesOf = (buf) => (Buffer.isBuffer(buf) ? buf : Buffer.from(buf));

// R1.4, R4.5: unpadded base64url of a buffer.
export const b64u = (buf) => bytesOf(buf).toString('base64url');

// R4.2, R5.3: SHA-256 digest as a Buffer.
export const sha256 = (buf) => createHash('sha256').update(bytesOf(buf)).digest();

// R2.2: HMAC-SHA256 over the raw content bytes.
export const hmacSha256 = (keyBytes, buf) => createHmac('sha256', bytesOf(keyBytes)).update(bytesOf(buf)).digest();

// R2.2, R5.3: constant time comparison, length check first.
export function constTimeEqual(a, b) {
  const left = bytesOf(a);
  const right = bytesOf(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// R7.3: canonical unpadded base64url or null; padding, foreign characters, length % 4 == 1 and non-canonical trailing bits fail.
export function b64uDecodeStrict(str) {
  if (typeof str !== 'string' || !B64U_RE.test(str) || str.length % 4 === 1) return null;
  const buf = Buffer.from(str, 'base64url');
  return b64u(buf) === str ? buf : null;
}

// R2.1, R2.2: standard base64 with padding.
export const b64StdEncode = (buf) => bytesOf(buf).toString('base64');

// R2.1, R2.4: canonical standard base64 or null; alphabet, padding placement, length % 4 and trailing bits are checked.
export function b64StdDecodeStrict(str) {
  if (typeof str !== 'string' || !B64_STD_RE.test(str) || str.length % 4 !== 0) return null;
  const buf = Buffer.from(str, 'base64');
  return b64StdEncode(buf) === str ? buf : null;
}

// R2.1: parse a whsec_ value into 24-64 key bytes, or an invalid_secret decision with a reason.
export function parseWhsec(value) {
  const bad = (reason) => ({ ok: false, code: 'invalid_secret', reason });
  if (typeof value !== 'string' || !value.startsWith(WHSEC_PREFIX)) return bad('prefix');
  const body = value.slice(WHSEC_PREFIX.length);
  if (/[^A-Za-z0-9+/=]/.test(body)) return bad('alphabet');
  const eq = body.indexOf('=');
  if (body.length % 4 !== 0) return bad('padding');
  if (eq !== -1 && !/^={1,2}$/.test(body.slice(eq))) return bad('padding');
  const key = b64StdDecodeStrict(body);
  if (!key) return bad('canonical');
  if (key.length < KEY_MIN || key.length > KEY_MAX) return bad('length');
  return { ok: true, key };
}

// R4.5, R7.3: derive an Ed25519 key pair from a 32-byte seed.
export function ed25519KeyFromSeed(seed) {
  const raw = bytesOf(seed);
  if (raw.length !== SEED_LEN) throw new Error('ed25519KeyFromSeed requires a 32-byte seed');
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv)
    .export({ format: 'der', type: 'spki' })
    .subarray(-SEED_LEN);
  return { priv, pub, public_key: b64u(pub), kid: b64u(sha256(pub)) };
}

// R7.1, R7.3: the JWK a card publishes for a signing key.
export const jwkOf = (key) => ({ kty: 'OKP', crv: 'Ed25519', x: key.public_key, kid: key.kid });

// R7.3: validate one card JWK, checking kty, crv, x encoding, x length, x key, kid presence, kid value, alg and use in that order.
export function validateJwk(jwk) {
  const bad = (reason) => ({ ok: false, reason });
  if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'OKP') return bad('kty');
  if (jwk.crv !== 'Ed25519') return bad('crv');
  const pub = b64uDecodeStrict(jwk.x);
  if (!pub) return bad('x_encoding');
  if (pub.length !== SEED_LEN) return bad('x_length');
  if (validatePublicKey(pub) !== null) return bad('x_key');
  if (typeof jwk.kid !== 'string' || jwk.kid.length === 0) return bad('kid_missing');
  const kid = b64u(sha256(pub));
  if (jwk.kid !== kid) return bad('kid_mismatch');
  if (jwk.alg !== undefined && jwk.alg !== 'EdDSA') return bad('alg');
  if (jwk.use !== undefined && jwk.use !== 'sig') return bad('use');
  return { ok: true, key: { kid, public_key: b64u(pub), pub } };
}
