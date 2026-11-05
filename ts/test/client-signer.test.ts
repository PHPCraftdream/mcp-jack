/** InMemorySigner tests, ported from Go client/signer_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { InMemorySigner, generateSigner } from "../src/client/signer.js";
import { validatePublicKey, verify } from "../src/ed25519.js";
import { encodeBase64URL, keyId } from "../src/encoding.js";
import { loadKeys } from "./fixtures.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

test("signer from every fixture key", () => {
  // keys.json pins publicKey and kid per seed, so derivation must reproduce both;
  // kid must equal encodeBase64URL(SHA-256(pub)).
  for (const key of loadKeys().keys) {
    assert.equal(key.seedHex.length, 64, `key ${key.name}: seed_hex must be 64 hex chars`);
    const seed = Buffer.from(key.seedHex, "hex");
    assert.equal(seed.length, 32, `key ${key.name}: decoded seed is ${seed.length} bytes, want 32`);
    const signer = new InMemorySigner(new Uint8Array(seed));
    const pub = signer.publicKey();
    assert.equal(pub.length, 32, `key ${key.name}: public key length`);
    assert.equal(encodeBase64URL(pub), key.publicKey, `key ${key.name}: public key base64url`);
    assert.equal(signer.kid(), key.kid, `key ${key.name}: kid`);
    assert.equal(keyId(pub), key.kid, `key ${key.name}: kid equals base64url(SHA-256(pub))`);
    assert.equal(validatePublicKey(pub), null, `key ${key.name}: validatePublicKey`);
  }
});

test("generateSigner produces distinct valid keys", () => {
  const s1 = generateSigner();
  const pub1 = s1.publicKey();
  assert.equal(pub1.length, 32, "first signer: public key length");
  assert.equal(validatePublicKey(pub1), null, "first signer: validatePublicKey");
  const s2 = generateSigner();
  const pub2 = s2.publicKey();
  assert.equal(pub2.length, 32, "second signer: public key length");
  assert.equal(validatePublicKey(pub2), null, "second signer: validatePublicKey");
  assert.notEqual(s1.kid(), s2.kid(), "two generated signers must not share a kid");
});

test("new InMemorySigner rejects bad seeds", () => {
  // The constructor throws, so no instance exists; Go's non-nil-signer check is subsumed.
  assert.throws(() => new InMemorySigner(new Uint8Array(0)), () => true, "zero-length seed");
  assert.throws(() => new InMemorySigner(new Uint8Array(31)), () => true, "31-byte seed");
});

test("sign round trip with tamper detection and key-copy semantics", () => {
  const keys = loadKeys().keys;
  const key = keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const signer = new InMemorySigner(Buffer.from(key.seedHex, "hex"));

  const msg = utf8("mcp-jack signer round trip test message");
  const sig = signer.sign(msg);
  assert.equal(sig.length, 64, `key ${key.name}: signature length`);
  assert.equal(verify(signer.publicKey(), msg, sig), true, `key ${key.name}: verify own signature`);

  // Flipping one message byte must invalidate the signature.
  const tampered = new Uint8Array(msg);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  assert.equal(verify(signer.publicKey(), tampered, sig), false, `key ${key.name}: tampered message accepted`);

  // publicKey() returns copies: mutating the returned bytes must not corrupt the signer.
  const pub = signer.publicKey();
  pub.fill(0xaa);
  assert.equal(verify(signer.publicKey(), msg, sig), true, `key ${key.name}: mutation corrupted the signer's key`);
  assert.equal(signer.kid(), key.kid, `key ${key.name}: kid after mutating returned key`);
  assert.equal(encodeBase64URL(signer.publicKey()), key.publicKey, `key ${key.name}: key base64url after mutation`);
});