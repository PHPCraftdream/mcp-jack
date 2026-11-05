/** Strict Ed25519 verification and public-key validity rules (spec 01 strict verification, spec 03 section 2) on node:crypto plus BigInt point arithmetic. */
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { Code, JackError } from "./errors.js";

// Constant time is NOT required here: public data, admission-time only
// (spec 01 section 2, spec 03 section 2).

// Extended-coordinate point (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032).
interface Point {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;
}

// Identical constants to spec/tools/reference-verifier.mjs.
const P = (1n << 255n) - 19n; // 2^255 - 19
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // group order
const D = mod(-121665n * inv(121666n)); // RFC 8032 section 5.1
const D2 = mod(2n * D);
const SQRT_M1 = pow(2n, (P - 1n) / 4n); // 2^((p-1)/4) mod p
const P_PLUS_3_DIV_8 = (P + 3n) / 8n; // exponent for the square-root candidate

/** Reduce a into [0, P). */
function mod(a: bigint): bigint {
  return ((a % P) + P) % P;
}

/** a^(P-2) mod P: the multiplicative inverse, since P is prime. */
function inv(a: bigint): bigint {
  return pow(a, P - 2n);
}

/** Square-and-multiply modular exponentiation. */
function pow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = base;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % P;
    }
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

/** Little-endian BigInt of the bytes. */
function toBig(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    // Loop bounds guarantee i is in range; noUncheckedIndexedAccess needs the cast.
    result = (result << 8n) | BigInt(bytes[i] as number);
  }
  return result;
}

/** Decode the 32-byte Ed25519 encoding, rejecting non-canonical encodings and points not on the curve (RFC 8032 section 5.1.3, spec 03 section 2); null for any rejection. */
function decodePoint(b: Uint8Array): Point | null {
  if (b.length !== 32) {
    return null;
  }
  const sign = (b[31] as number) >> 7;
  const y = toBig(b) & ((1n << 255n) - 1n); // clears the sign bit (little-endian encoding)
  if (y >= P) {
    return null; // non-canonical: y must be below 2^255 - 19
  }
  const y2 = mod(y * y);
  const x2 = mod(mod(y2 - 1n) * inv(mod(D * y2 + 1n)));
  // x = x2^((p+3)/8) mod p; if that is not a square root, multiply by sqrtM1.
  let x = pow(x2, P_PLUS_3_DIV_8);
  if (mod(x * x) !== x2) {
    x = mod(x * SQRT_M1);
  }
  if (mod(x * x) !== x2) {
    return null; // not on the curve
  }
  if (x === 0n && sign === 1) {
    return null; // non-canonical sign for a point with x = 0
  }
  // Make x's parity match the sign bit.
  if (Number(x & 1n) !== sign) {
    x = mod(P - x);
  }
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
}

/** p + q using the standard extended-coordinate addition formulas (RFC 8032 section 5.1.4). */
function addPoints(p: Point, q: Point): Point {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(p.T * D2 * q.T);
  const dd = mod(2n * p.Z * q.Z);
  const e = b - a;
  const f = dd - c;
  const g = dd + c;
  const h = b + a;
  return {
    X: mod(e * f),
    Y: mod(g * h),
    T: mod(e * h),
    Z: mod(f * g),
  };
}

/** k*p by double-and-add over the bits of k (least significant first). */
function mulPoint(p: Point, k: bigint): Point {
  let r: Point = { X: 0n, Y: 1n, Z: 1n, T: 0n };
  let q = p;
  while (k > 0n) {
    if (k & 1n) {
      r = addPoints(r, q);
    }
    q = addPoints(q, q);
    k >>= 1n;
  }
  return r;
}

/** Whether q is the neutral element (x = 0, y = 1). */
function isIdentity(q: Point): boolean {
  return q.X === 0n && mod(q.Y - q.Z) === 0n;
}

/** Verify: sig is a valid Ed25519 signature of message under publicKey, with the strict rule that the scalar S (little-endian sig[32:64]) is below the group order L (spec 01 section 2); a signature with S >= L is invalid even if the verification equation holds. */
export function verify(publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  if (publicKey.length !== 32 || sig.length !== 64) {
    return false; // wrong lengths: false, never throw
  }
  // Strict S check BEFORE node:crypto: crypto historically does not enforce S < L.
  let s = 0n;
  for (let i = 63; i >= 32; i--) {
    s = (s << 8n) | BigInt(sig[i] as number);
  }
  if (s >= L) {
    return false;
  }
  // Wrap the raw 32-byte key in the fixed Ed25519 SPKI DER prefix.
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(publicKey),
  ]);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  return cryptoVerify(null, Buffer.from(message), key, Buffer.from(sig));
}

/** Whether pub satisfies spec 03 section 2: exactly 32 bytes, canonical, on the curve, not the identity, and in the prime-order subgroup; null means acceptable. */
export function validatePublicKey(publicKey: Uint8Array): JackError | null {
  if (publicKey.length !== 32) {
    return new JackError(400, Code.KEY_REJECTED, "public key must be 32 bytes");
  }
  const p = decodePoint(publicKey);
  if (p === null) {
    return new JackError(400, Code.KEY_REJECTED, "non-canonical or off-curve public key");
  }
  if (isIdentity(p)) {
    return new JackError(400, Code.KEY_REJECTED, "identity point");
  }
  if (!isIdentity(mulPoint(p, L))) {
    return new JackError(400, Code.KEY_REJECTED, "not in the prime-order subgroup");
  }
  return null;
}
