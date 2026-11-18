/** Strict unpadded base64url encode/decode for bodies, keys and signatures; hand-written because Buffer.from("base64url") accepts malformed input. */
import { createHash } from "node:crypto";

/** A string that is not canonical unpadded base64url (spec 01 section 2: no padding, no foreign characters, no non-zero unused bits). */
export class BadBase64UrlError extends Error {
  constructor() {
    super("jack: invalid base64url");
    this.name = "BadBase64UrlError";
  }
}

/** The exact RFC 4648 section 5 url-safe alphabet. */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Lookup table: alphabet index 0..63, or -1 for any other char code below 128. */
const LOOKUP = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Canonical unpadded base64url encoding of bytes (RFC 4648 section 5, no padding). Node's "base64url" encoding is canonical and never pads. */
export function encodeBase64URL(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Strictly decodes an unpadded, canonical base64url string (spec 01 section 2). */
export function decodeBase64URL(s: string): Uint8Array {
  // Reject length % 4 === 1 early: it cannot carry a whole trailing byte.
  if (s.length % 4 === 1) {
    throw new BadBase64UrlError();
  }
  // Hand-written decode: Buffer.from("base64url") silently skips \r\n and
  // ignores wrong trailing bits, so it cannot enforce the canonical form.
  const codes = new Uint8Array(Math.floor(s.length / 4) * 3 + 3);
  let n = 0; // number of 6-bit groups collected
  let acc = 0; // pending 6-bit groups
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    // noUncheckedIndexedAccess: capture the lookup result so the guard narrows it.
    const v = code < 128 ? LOOKUP[code] : undefined;
    if (v === undefined || v === -1) {
      throw new BadBase64UrlError();
    }
    acc = (acc << 6) | v;
    n++;
    if (n === 4) {
      const o = (i >> 2) * 3; // byte offset of this full group in the output
      codes[o] = (acc >>> 16) & 0xff;
      codes[o + 1] = (acc >>> 8) & 0xff;
      codes[o + 2] = acc & 0xff;
      n = 0;
      acc = 0;
    }
  }
  // Trailing 2 chars -> 1 byte; trailing 3 chars -> 2 bytes; keep whole bytes only.
  const full = Math.floor(s.length / 4) * 3;
  let len: number;
  if (n === 0) {
    len = full;
  } else if (n === 2) {
    codes[full] = (acc >>> 4) & 0xff;
    len = full + 1;
  } else {
    codes[full] = (acc >>> 10) & 0xff;
    codes[full + 1] = (acc >>> 2) & 0xff;
    len = full + 2;
  }
  const bytes = codes.subarray(0, len);
  // Go's decoder ignores non-zero unused trailing bits; re-encoding must
  // reproduce the input for the encoding to be canonical.
  if (encodeBase64URL(bytes) !== s) {
    throw new BadBase64UrlError();
  }
  return bytes;
}

/** DecodeBase64URL plus a required exact decoded length of size bytes. */
export function decodeBase64URLFixed(s: string, size: number): Uint8Array {
  const bytes = decodeBase64URL(s);
  if (bytes.length !== size) {
    throw new BadBase64UrlError();
  }
  return bytes;
}

/** base64url(SHA-256(publicKey)) (spec 01 section 2). */
export function keyId(publicKey: Uint8Array): string {
  return encodeBase64URL(createHash("sha256").update(Buffer.from(publicKey)).digest());
}

/** base64url(SHA-256(body)) over the exact bytes; an empty body is hashed as an empty byte string, so the result is never empty (spec 01 section 3.1). */
export function bodyHash(body: Uint8Array): string {
  return encodeBase64URL(createHash("sha256").update(Buffer.from(body)).digest());
}
