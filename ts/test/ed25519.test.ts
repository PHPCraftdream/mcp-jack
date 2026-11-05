/** Tests for strict Ed25519 verification and public-key rules, ported from Go's keys_test.go and ed25519_test.go. */
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { keyId, decodeBase64URLFixed } from "../src/encoding.js";
import { validatePublicKey, verify } from "../src/ed25519.js";
import { Code } from "../src/errors.js";
import { loadKeys, loadKeyVectors } from "./fixtures.js";
import type { TestKey } from "./fixtures.js";

// Test-only Ed25519 helpers mirroring Go's ed25519.NewKeyFromSeed and Sign,
// via node:crypto PKCS8/SPKI DER wrappers.

/** PKCS8 DER prefix wrapping a raw Ed25519 seed (RFC 8410). */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
/** Fixed 12-byte SPKI DER prefix before the raw 32-byte Ed25519 public key. */
const SPKI_PREFIX_LEN = 12;

/** Ed25519 private key from a 32-byte seed (Go's ed25519.NewKeyFromSeed). */
function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

/** Raw 32-byte Ed25519 public key of priv. */
function publicKeyOf(priv: KeyObject): Uint8Array {
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(SPKI_PREFIX_LEN));
}

/** Deterministic Ed25519 signature of message under priv (RFC 8032). */
function signEd25519(priv: KeyObject, message: Uint8Array): Uint8Array {
  return new Uint8Array(cryptoSign(null, Buffer.from(message), priv));
}

/** Finds a keys.json entry by name; the fixture is the oracle. */
function findKeyByName(name: string): TestKey {
  for (const key of loadKeys().keys) {
    if (key.name === name) {
      return key;
    }
  }
  throw new Error(`no test key named ${name}`);
}

function seedOf(key: TestKey): Uint8Array {
  const seed = Buffer.from(key.seedHex, "hex");
  assert.equal(seed.length, 32, `seed for ${key.name} must be 32 bytes`);
  return new Uint8Array(seed);
}

test("key-vectors: validatePublicKey accepts valid and rejects bad keys", () => {
  const vectors = loadKeyVectors();
  for (const c of vectors.cases) {
    const pub = new Uint8Array(Buffer.from(c.publicKeyHex, "hex"));
    const err = validatePublicKey(pub);
    if (c.expect === "valid") {
      assert.equal(err, null, `case ${c.id}: expected valid, got ${String(err)}`);
      continue;
    }
    assert.ok(err instanceof Error, `case ${c.id}: expected rejection, got null`);
    assert.equal(err.httpStatus, 400, `case ${c.id}: httpStatus`);
    assert.equal(err.code, Code.KEY_REJECTED, `case ${c.id}: code`);
  }
});

test("keys.json derivation: seed -> public key, kid and validity", () => {
  for (const key of loadKeys().keys) {
    const seed = seedOf(key);
    const priv = privateKeyFromSeed(seed);
    const pub = publicKeyOf(priv);
    const wantPub = decodeBase64URLFixed(key.publicKey, 32);
    assert.ok(Buffer.compare(Buffer.from(pub), Buffer.from(wantPub)) === 0, `public key mismatch for ${key.name}`);
    assert.equal(keyId(wantPub), key.kid, `keyId mismatch for ${key.name}`);
    assert.equal(validatePublicKey(pub), null, `validatePublicKey(${key.name}) should accept`);
  }
});

test("verify accepts a valid signature and rejects a different message", () => {
  const key = findKeyByName("alice");
  const priv = privateKeyFromSeed(seedOf(key));
  const pub = publicKeyOf(priv);
  const encoder = new TextEncoder();
  const msg = encoder.encode("mcp-jack test message");
  const sig = signEd25519(priv, msg);
  assert.equal(verify(pub, msg, sig), true, "Verify returned false for a valid signature");
  assert.equal(verify(pub, encoder.encode("other message"), sig), false, "Verify accepted a different message");
});

test("verify rejects a malleated signature with S >= L", () => {
  // Spec 01 section 2 requires rejecting S >= L even though the
  // verification equation would hold.
  const key = findKeyByName("alice");
  const priv = privateKeyFromSeed(seedOf(key));
  const pub = publicKeyOf(priv);
  const msg = new TextEncoder().encode("mcp-jack test message");
  const sig = signEd25519(priv, msg);

  const l = 2n ** 252n + 27742317777372353535851937790883648493n;
  const s = BigInt(`0x${Buffer.from(sig.subarray(32, 64)).reverse().toString("hex")}`);
  const sPlusL = s + l;
  assert.ok(sPlusL.toString(2).length <= 254, "S+L does not fit in 32 bytes");
  // Little-endian padded to 32 bytes.
  const hex = sPlusL.toString(16).padStart(64, "0");
  const malleated = Uint8Array.from(sig);
  malleated.set(Buffer.from(hex, "hex").reverse(), 32);
  assert.equal(verify(pub, msg, malleated), false, "Verify accepted a malleated signature with S >= L");
});

test("verify rejects bad key and signature lengths", () => {
  const key = findKeyByName("alice");
  const priv = privateKeyFromSeed(seedOf(key));
  const pub = publicKeyOf(priv);
  const msg = new TextEncoder().encode("mcp-jack test message");
  const sig = signEd25519(priv, msg);

  assert.equal(verify(pub.subarray(0, 31), msg, sig), false, "Verify accepted a 31-byte public key");
  assert.equal(verify(pub, msg, sig.subarray(0, 63)), false, "Verify accepted a 63-byte signature");
  const long = new Uint8Array(sig.length + 1);
  long.set(sig, 0);
  assert.equal(verify(pub, msg, long), false, "Verify accepted a 65-byte signature");
  // Returns false rather than throwing on empty inputs.
  assert.equal(verify(new Uint8Array(0), msg, sig), false, "Verify must return false for an empty key");
  assert.equal(verify(pub, msg, new Uint8Array(0)), false, "Verify must return false for an empty signature");
});
