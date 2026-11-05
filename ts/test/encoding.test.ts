/** Tests for the strict unpadded base64url codec, ported from Go's base64_test.go. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  BadBase64UrlError,
  bodyHash,
  decodeBase64URL,
  decodeBase64URLFixed,
  encodeBase64URL,
  keyId,
} from "../src/encoding.js";
import { loadKeys } from "./fixtures.js";

/** Deterministic byte pattern shared with Go's tests: b[i] = (i*7+1) & 0xff. */
function pattern(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = (i * 7 + 1) & 0xff;
  }
  return b;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

test("encode/decode round trip over the Go sizes plus empty and single byte", () => {
  const inputs: Uint8Array[] = [new Uint8Array(0), new TextEncoder().encode("x"), pattern(16), pattern(32), pattern(64)];
  for (const input of inputs) {
    const enc = encodeBase64URL(input);
    const dec = decodeBase64URL(enc);
    assert.ok(bytesEqual(dec, input), `round trip mismatch for ${enc}`);
  }
});

test("decodeBase64URL rejects malformed and non-canonical strings", () => {
  // Each case must throw BadBase64UrlError; names ported from Go.
  const failCases: readonly [name: string, in_: string][] = [
    ["padding1", "ab="],
    ["padding2", "ab=="],
    ["space", "a b"],
    ["newline", "ab\n"],
    ["nonAlphabet", "?"],
    ["lengthMod4One", "a"],
    // "aa_" is alphabet-legal but non-canonical: 'a'=26, '_'=63 gives
    // bits 011010 011010 111111 -> bytes {0x69, 0xAF} plus two non-zero
    // unused bits; the canonical encoding of those bytes is "aa8".
    ["nonCanonicalTrailingBits", "aa_"],
    // "ab": 011010 011011 -> byte 0x69 plus four non-zero unused bits.
    ["nonCanonicalTwoChars", "ab"],
  ];
  for (const [name, input] of failCases) {
    assert.throws(
      () => decodeBase64URL(input),
      BadBase64UrlError,
      `case ${name}: decodeBase64URL(${JSON.stringify(input)}) should reject`,
    );
  }
});

test("decodeBase64URL accepts verified canonical constants", () => {
  // Ok cases verified against node's independent base64url decoder.
  const okCases: readonly [in_: string, want: number[]][] = [
    ["aw", [0x6b]], // 011010 110000: unused bits are zero
    ["aag", [0x69, 0xa8]], // 011010 011010 100000
    ["aa8", [0x69, 0xaf]], // 011010 011010 111100
  ];
  for (const [input, want] of okCases) {
    assert.deepEqual(Array.from(decodeBase64URL(input)), want, `decodeBase64URL(${input})`);
  }
  // Canonical encoding of {0x6b} is exactly "aw".
  assert.equal(encodeBase64URL(new Uint8Array([0x6b])), "aw");
});

test("decodeBase64URLFixed enforces the exact decoded length", () => {
  const fixed = decodeBase64URLFixed("aw", 1);
  assert.equal(fixed.length, 1);
  assert.equal(fixed[0], 0x6b);
  assert.throws(() => decodeBase64URLFixed("aw", 2), BadBase64UrlError, "wrong size must throw");
  assert.throws(() => decodeBase64URLFixed("aw", 0), BadBase64UrlError, "zero size must throw");
  assert.throws(() => decodeBase64URLFixed("a", 1), BadBase64UrlError, "bad length must throw");
});

test("keyId and bodyHash are deterministic 43-char strings with a node:crypto oracle", () => {
  const pub = pattern(32);
  const id1 = keyId(pub);
  const id2 = keyId(pub);
  assert.equal(id1, id2, "keyId must be deterministic");
  assert.equal(id1.length, 43);
  // Independent oracle: node:crypto SHA-256, base64url.
  const oracle = createHash("sha256").update(Buffer.from(pub)).digest().toString("base64url");
  assert.equal(id1, oracle);

  const h1 = bodyHash(new TextEncoder().encode("payload"));
  const h2 = bodyHash(new TextEncoder().encode("payload"));
  assert.equal(h1, h2, "bodyHash must be deterministic");
  assert.equal(h1.length, 43);
  assert.equal(h1, createHash("sha256").update("payload").digest().toString("base64url"));

  const empty1 = keyId(new Uint8Array(0));
  const empty2 = keyId(new Uint8Array(0));
  assert.equal(empty1, empty2, "keyId(empty) must be deterministic");
  assert.equal(empty1.length, 43);
});

test("fixture cross-check: every keys.json key decodes and hashes to its kid", () => {
  for (const key of loadKeys().keys) {
    const pub = decodeBase64URLFixed(key.publicKey, 32);
    const id = keyId(pub);
    assert.equal(id, key.kid, `keyId mismatch for key ${key.name}`);
    assert.equal(keyId(pub), key.kid, `keyId not deterministic for key ${key.name}`);
  }
});
