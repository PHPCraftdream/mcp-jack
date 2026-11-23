/** Webhook crypto primitives of spec 06 sections 2 and 7: whsec_ parsing, strict base64, SHA-256, HMAC-SHA256 and constant-time comparison; pure, node:crypto only. */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { decodeBase64URL } from "../../core/encoding.js";

/** The literal secret prefix of spec 06 R2.1. */
export const WHSEC_PREFIX = "whsec_";

/** A rejected secret value: the reason names the failing check, never the value (spec 06 R2.1). */
export interface SecretRejection {
  readonly ok: false;
  readonly code: "invalid_secret";
  readonly reason: string;
}

/** The result of parseWhsec: the decoded 24-64 key bytes, or a rejection with its reason. */
export type SecretParse = { readonly ok: true; readonly key: Uint8Array } | SecretRejection;

/** Standard base64 alphabet with at most two trailing pad characters (no pad before a non-pad character). */
const B64_STD_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** The unpadded URL-safe base64 alphabet. */
const B64U_RE = /^[A-Za-z0-9_-]*$/;

/** Inclusive decoded secret length bounds of spec 06 R2.1. */
const KEY_MIN = 24;
const KEY_MAX = 64;

/** Canonical standard base64 with padding (spec 06 R2.2): a 32-byte MAC is always 44 characters ending "=". */
export function encodeBase64Std(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** Strictly decodes canonical padded standard base64 or null (spec 06 R2.1, R2.4): alphabet, length % 4, trailing padding only, and trailing bits checked by re-encoding. */
export function decodeBase64StdStrict(value: string): Uint8Array | null {
  if (!B64_STD_RE.test(value) || value.length % 4 !== 0) {
    return null;
  }
  const bytes = Buffer.from(value, "base64");
  // Non-zero unused trailing bits decode silently, so the encoding is canonical
  // only when re-encoding reproduces the input exactly.
  return encodeBase64Std(bytes) === value ? bytes : null;
}

/** Strictly decodes canonical unpadded base64url or null (spec 06 R7.3): padding, foreign characters, length % 4 == 1 and non-canonical trailing bits fail. */
export function decodeBase64UrlStrict(value: string): Uint8Array | null {
  if (!B64U_RE.test(value) || value.length % 4 === 1) {
    return null;
  }
  try {
    // decodeBase64URL is hand-written and enforces canonical form; it throws
    // BadBase64UrlError instead of returning null.
    return decodeBase64URL(value);
  } catch {
    return null;
  }
}

/** SHA-256 digest bytes (spec 06 R4.2, R5.3). */
export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return createHash("sha256").update(Buffer.from(bytes)).digest();
}

/** HMAC-SHA256 over the exact message bytes (spec 06 R2.2); keyBytes are the decoded secret or signing-key bytes. */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return createHmac("sha256", Buffer.from(key)).update(Buffer.from(message)).digest();
}

/** Constant-time comparison, length check first (spec 06 R2.2, R5.3). */
export function constTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Parses a whsec_ value into 24-64 key bytes, or an invalid_secret decision
 * whose reason names the failing check (spec 06 R2.1): prefix, alphabet,
 * padding, canonical, length, in that order. The value is never echoed.
 */
export function parseWhsec(value: unknown): SecretParse {
  const bad = (reason: string): SecretRejection => ({ ok: false, code: "invalid_secret", reason });
  if (typeof value !== "string" || !value.startsWith(WHSEC_PREFIX)) {
    return bad("prefix");
  }
  const body = value.slice(WHSEC_PREFIX.length);
  if (/[^A-Za-z0-9+/=]/.test(body)) {
    return bad("alphabet");
  }
  const eq = body.indexOf("=");
  if (body.length % 4 !== 0) {
    return bad("padding");
  }
  if (eq !== -1 && !/^={1,2}$/.test(body.slice(eq))) {
    return bad("padding");
  }
  const key = decodeBase64StdStrict(body);
  if (key === null) {
    return bad("canonical");
  }
  if (key.length < KEY_MIN || key.length > KEY_MAX) {
    return bad("length");
  }
  return { ok: true, key };
}
