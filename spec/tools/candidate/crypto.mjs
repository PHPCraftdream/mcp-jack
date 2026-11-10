import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';

const FIELD = (1n << 255n) - 19n;
const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (n, m = FIELD) => ((n % m) + m) % m;
const pow = (base, exponent, modulus = FIELD) => {
  let out = 1n;
  let value = mod(base, modulus);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) out = (out * value) % modulus;
    value = (value * value) % modulus;
  }
  return out;
};
const inv = (n) => pow(n, FIELD - 2n);
const curveD = mod(-121665n * inv(121666n));
const curveD2 = mod(2n * curveD);
const sqrtM1 = pow(2n, (FIELD - 1n) / 4n);
const identity = Object.freeze({ X: 0n, Y: 1n, Z: 1n, T: 0n });
const baseX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const baseY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
const base = Object.freeze({ X: baseX, Y: baseY, Z: 1n, T: mod(baseX * baseY) });
const littleInt = (bytes) => [...bytes].reduceRight((n, b) => (n << 8n) | BigInt(b), 0n);
const littleBytes = (n, length) => {
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1, n >>= 8n) out[i] = Number(n & 255n);
  return out;
};
const concat = (...parts) => Buffer.concat(parts.map((v) => Buffer.from(v)));
export const sha256 = (value) => createHash('sha256').update(value).digest();
export const sha512 = (value) => createHash('sha512').update(value).digest();
export const base64url = (value) => Buffer.from(value).toString('base64url');
export const strictBase64url = (value, bytes) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === bytes && base64url(decoded) === value ? decoded : null;
};
export const keyId = (publicKey) => base64url(sha256(publicKey));

const add = (p, q) => {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(p.T * curveD2 * q.T);
  const d = mod(2n * p.Z * q.Z);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return { X: mod(e * f), Y: mod(g * h), T: mod(e * h), Z: mod(f * g) };
};
const multiply = (point, scalar) => {
  let result = identity;
  let addend = point;
  for (let n = scalar; n > 0n; n >>= 1n) {
    if (n & 1n) result = add(result, addend);
    addend = add(addend, addend);
  }
  return result;
};
const encodePoint = (point) => {
  const zInv = inv(point.Z);
  const x = mod(point.X * zInv);
  const out = littleBytes(mod(point.Y * zInv), 32);
  if (x & 1n) out[31] |= 128;
  return out;
};
export const decodePoint = (bytes) => {
  const raw = Buffer.from(bytes);
  if (raw.length !== 32) return null;
  const sign = raw[31] >> 7;
  const y = littleInt(raw) & ((1n << 255n) - 1n);
  if (y >= FIELD) return null;
  const y2 = mod(y * y);
  const x2 = mod((y2 - 1n) * inv(mod(curveD * y2 + 1n)));
  let x = pow(x2, (FIELD + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * sqrtM1);
  if (mod(x * x) !== x2 || (x === 0n && sign === 1)) return null;
  if (Number(x & 1n) !== sign) x = mod(FIELD - x);
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
};
const isIdentity = (point) => point.X === 0n && mod(point.Y - point.Z) === 0n;
export const validPublicKey = (value) => {
  const point = decodePoint(value);
  return point !== null && !isIdentity(point) && isIdentity(multiply(point, ORDER));
};

export const publicFromSeed = (seed) => {
  const raw = Buffer.from(seed);
  if (raw.length !== 32) throw new TypeError('Ed25519 seed must be 32 bytes');
  const digest = sha512(raw);
  const scalarBytes = Buffer.from(digest.subarray(0, 32));
  scalarBytes[0] &= 248;
  scalarBytes[31] &= 63;
  scalarBytes[31] |= 64;
  return encodePoint(multiply(base, littleInt(scalarBytes)));
};

export const signSeed = (seed, message) => {
  const raw = Buffer.from(seed);
  if (raw.length !== 32) throw new TypeError('Ed25519 seed must be 32 bytes');
  const m = Buffer.from(message);
  const digest = sha512(raw);
  const scalarBytes = Buffer.from(digest.subarray(0, 32));
  scalarBytes[0] &= 248;
  scalarBytes[31] &= 63;
  scalarBytes[31] |= 64;
  const scalar = littleInt(scalarBytes);
  const publicKey = encodePoint(multiply(base, scalar));
  const r = littleInt(sha512(concat(digest.subarray(32), m))) % ORDER;
  const encodedR = encodePoint(multiply(base, r));
  const challenge = littleInt(sha512(concat(encodedR, publicKey, m))) % ORDER;
  return concat(encodedR, littleBytes((r + challenge * scalar) % ORDER, 32));
};

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
export const verifyNode = (publicKey, message, signature) => {
  const sig = Buffer.from(signature);
  if (sig.length !== 64 || littleInt(sig.subarray(32)) >= ORDER || !validPublicKey(publicKey)) return false;
  const key = createPublicKey({ key: concat(SPKI_PREFIX, publicKey), format: 'der', type: 'spki' });
  return nodeVerify(null, Buffer.from(message), key, sig);
};

export const RFC8032_TEST = Object.freeze({
  seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  signature: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
    + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
});

export const testSeed = (name) => sha256(Buffer.from(`mcp-jack test key: ${name}`, 'utf8'));
