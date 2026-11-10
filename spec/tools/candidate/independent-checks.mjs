import { createHash } from 'node:crypto';
import { signSeed } from './crypto.mjs';

const fromHex = (value) => Buffer.from(value, 'hex');
const EXPECTED_RFC = Object.freeze({
  seed: fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
  publicKey: fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
  signature: fromHex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
});
const assertBytes = (actual, expected) => Buffer.from(actual).equals(Buffer.from(expected));

export const pureVerifier = (publicKey, message, signature) => {
  const P = (1n << 255n) - 19n;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const mod = (n, m = P) => ((n % m) + m) % m;
  const pow = (base, e, m = P) => { let out = 1n; let x = mod(base, m); for (; e > 0n; e >>= 1n) { if (e & 1n) out = out * x % m; x = x * x % m; } return out; };
  const inv = (x) => pow(x, P - 2n);
  const d = mod(-121665n * inv(121666n));
  const sqrtM1 = pow(2n, (P - 1n) / 4n);
  const integer = (bytes) => [...bytes].reduceRight((n, b) => (n << 8n) | BigInt(b), 0n);
  const decode = (bytes) => {
    const raw = Buffer.from(bytes);
    if (raw.length !== 32) return null;
    const sign = raw[31] >> 7;
    const y = integer(raw) & ((1n << 255n) - 1n);
    if (y >= P) return null;
    const y2 = mod(y * y);
    const x2 = mod((y2 - 1n) * inv(mod(d * y2 + 1n)));
    let x = pow(x2, (P + 3n) / 8n);
    if (mod(x * x) !== x2) x = mod(x * sqrtM1);
    if (mod(x * x) !== x2 || (x === 0n && sign !== 0)) return null;
    if (Number(x & 1n) !== sign) x = mod(P - x);
    return { x, y };
  };
  const add = (p, q) => {
    const xx = mod(p.x * q.x);
    const yy = mod(p.y * q.y);
    const dxy = mod(d * xx * yy);
    return { x: mod((p.x * q.y + p.y * q.x) * inv(1n + dxy)), y: mod((yy + xx) * inv(1n - dxy)) };
  };
  const multiply = (point, scalar) => {
    let result = { x: 0n, y: 1n };
    let current = point;
    for (let n = scalar; n > 0n; n >>= 1n) {
      if (n & 1n) result = add(result, current);
      current = add(current, current);
    }
    return result;
  };
  const encode = (point) => {
    let y = point.y;
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i += 1, y >>= 8n) out[i] = Number(y & 255n);
    if (point.x & 1n) out[31] |= 128;
    return out;
  };
  const sig = Buffer.from(signature);
  if (sig.length !== 64) return false;
  const a = decode(publicKey);
  const r = decode(sig.subarray(0, 32));
  const s = integer(sig.subarray(32));
  if (!a || !r || s >= L) return false;
  const identity = encode({ x: 0n, y: 1n });
  if (assertBytes(encode(a), identity) || !assertBytes(encode(multiply(a, L)), identity)) return false;
  const challenge = integer(createHash('sha512').update(Buffer.concat([sig.subarray(0, 32), Buffer.from(publicKey), Buffer.from(message)])).digest()) % L;
  const base = { x: 15112221349535400772501151409588531511454012693041857206046113283949847762202n, y: 46316835694926478169428394003475163141307993866256225615783033603165251855960n };
  return assertBytes(encode(multiply(base, s)), encode(add(r, multiply(a, challenge))));
};

export const runCryptoKats = () => {
  const signature = signSeed(EXPECTED_RFC.seed, Buffer.alloc(0));
  if (!assertBytes(signature, EXPECTED_RFC.signature) || !pureVerifier(EXPECTED_RFC.publicKey, Buffer.alloc(0), signature)) throw new Error('RFC 8032 Ed25519 empty-message KAT mismatch');
  return { publicKey: EXPECTED_RFC.publicKey.toString('hex'), signature: signature.toString('hex'), message: '' };
};
