/** ClientUserKey/ServerUserKey tests: role-opposite user-key access pinned against keys.json, key-vectors.json and the pre-existing Ed25519 oracles, not a self-roundtrip-only oracle. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";
import { ClientUserKey, ServerUserKey, UserKeyHandoff, generateClientUserKey, issueUserKey } from "../src/user-key.js";
import { InMemorySigner, type Signer } from "../src/client/signer.js";
import { signRequest } from "../src/client/auth.js";
import { parseRequestAuth } from "../src/auth-header.js";
import { validatePublicKey, verify } from "../src/ed25519.js";
import { JackError, Code } from "../src/errors.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../src/encoding.js";
import { loadKeys, loadKeyVectors } from "./fixtures.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const bytes = (a: Uint8Array): Uint8Array => new Uint8Array(a);
const fromHex = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));

/** Content comparison for secret material: the boolean result keeps seed bytes out of failure diagnostics. */
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) {
      return false;
    }
  }
  return true;
};

test("client key from every fixture key", () => {
  // keys.json pins seed_hex, public_key and kid per key, so derivation must
  // reproduce both; verify() over the PINNED public key is the independent oracle.
  const keys = loadKeys().keys;
  assert.ok(keys.length >= 2, "keys.json returned too few keys");
  for (const key of keys) {
    assert.equal(key.seedHex.length, 64, `key ${key.name}: seed_hex must be 64 hex chars`);
    const seed = Buffer.from(key.seedHex, "hex");
    assert.equal(seed.length, 32, `key ${key.name}: decoded seed is ${seed.length} bytes, want 32`);
    const keyObj = new ClientUserKey(new Uint8Array(seed));
    const pub = keyObj.publicKey();
    assert.equal(pub.length, 32, `key ${key.name}: public key length`);
    assert.equal(encodeBase64URL(pub), key.publicKey, `key ${key.name}: public key base64url`);
    assert.equal(keyObj.kid(), key.kid, `key ${key.name}: kid`);
    assert.equal(keyId(pub), key.kid, `key ${key.name}: kid equals base64url(SHA-256(pub))`);
    assert.equal(validatePublicKey(pub), null, `key ${key.name}: validatePublicKey`);
    const msg = utf8("mcp-jack user-key pinned message");
    const sig = keyObj.sign(msg);
    assert.equal(sig.length, 64, `key ${key.name}: signature length`);
    // Verify under the fixture's public_key string, not the key's own output.
    const pinnedPub = decodeBase64URLFixed(key.publicKey, 32);
    assert.equal(verify(pinnedPub, msg, sig), true, `key ${key.name}: signature verifies under pinned key`);
  }
  // Negative: alice's signature must not verify under bob's pinned public key.
  const alice = keys[0];
  const bob = keys[1];
  assert.ok(alice !== undefined && bob !== undefined, "keys.json returned no keys");
  assert.notEqual(alice.seedHex, bob.seedHex, "fixture keys alice/bob must differ");
  const aliceKey = new ClientUserKey(Buffer.from(alice.seedHex, "hex"));
  const bobPub = decodeBase64URLFixed(bob.publicKey, 32);
  assert.equal(
    verify(bobPub, utf8("mcp-jack user-key pinned message"), aliceKey.sign(utf8("mcp-jack user-key pinned message"))),
    false,
    "alice signature must not verify under bob's pinned public key",
  );
});

test("generation produces distinct valid signing keys", () => {
  const a = generateClientUserKey();
  const b = generateClientUserKey();
  const pubA = a.publicKey();
  const pubB = b.publicKey();
  assert.equal(pubA.length, 32, "generated public key length");
  assert.equal(validatePublicKey(pubA), null, "generated public key a is valid");
  assert.equal(validatePublicKey(pubB), null, "generated public key b is valid");
  assert.notEqual(a.kid(), b.kid(), "two generated keys must have distinct kids");
  const msg = utf8("mcp-jack user-key generation check");
  assert.equal(verify(pubA, msg, a.sign(msg)), true, "key a signs and verifies under its own public key");
  assert.equal(verify(pubB, msg, b.sign(msg)), true, "key b signs and verifies under its own public key");
  assert.equal(verify(pubB, msg, a.sign(msg)), false, "key a signature must not verify under key b");
  assert.equal(verify(pubA, msg, b.sign(msg)), false, "key b signature must not verify under key a");
});

test("matches InMemorySigner for the same seed", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const seed = new Uint8Array(Buffer.from(key.seedHex, "hex"));
  const uk = new ClientUserKey(seed);
  const signer = new InMemorySigner(seed);
  assert.deepEqual(bytes(uk.publicKey()), bytes(signer.publicKey()), "public key bytes");
  assert.equal(uk.kid(), signer.kid(), "kid");
  const msg = utf8("mcp-jack user-key determinism check");
  assert.deepEqual(bytes(uk.sign(msg)), bytes(signer.sign(msg)), "Ed25519 is deterministic: identical signature bytes");
});

test("sign and verify negative controls", () => {
  const key = new ClientUserKey(Buffer.from(loadKeys().keys[0]?.seedHex ?? "", "hex"));
  const other = new ClientUserKey(Buffer.from(loadKeys().keys[1]?.seedHex ?? "", "hex"));
  const msg = utf8("mcp-jack user-key negative controls");
  const sig = key.sign(msg);
  const tampered = new Uint8Array(msg);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  assert.equal(verify(key.publicKey(), tampered, sig), false, "tampered message accepted");
  const flipped = new Uint8Array(sig);
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  assert.equal(verify(key.publicKey(), msg, flipped), false, "flipped signature byte accepted");
  assert.equal(verify(key.publicKey(), msg, sig.subarray(0, 63)), false, "truncated signature must return false, not throw");
  assert.equal(verify(key.publicKey(), msg, other.sign(msg)), false, "signature from another key accepted");
});

test("client import rejects wrong runtime types and lengths", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const typeLie = (err: unknown): boolean => err instanceof Error && err.message === "jack user-key: seed must be a Uint8Array";
  const lengthLie = (n: number) => (err: unknown): boolean =>
    err instanceof Error && err.message === `jack user-key: seed must be exactly 32 bytes, got ${n}`;
  assert.throws(() => new ClientUserKey(new Uint8Array(0)), lengthLie(0), "zero-length seed");
  assert.throws(() => new ClientUserKey(new Uint8Array(31)), lengthLie(31), "31-byte seed");
  assert.throws(() => new ClientUserKey(new Uint8Array(33)), lengthLie(33), "33-byte seed");
  assert.throws(() => new ClientUserKey("nope" as unknown as Uint8Array), typeLie, "string seed");
  assert.throws(() => new ClientUserKey(null as unknown as Uint8Array), typeLie, "null seed");
  assert.throws(() => new ClientUserKey(new ArrayBuffer(32) as unknown as Uint8Array), typeLie, "ArrayBuffer seed");
  assert.throws(() => new ClientUserKey([1, 2, 3] as unknown as Uint8Array), typeLie, "array seed");
  // One thrown case: message matches the house prefix and never echoes seed material.
  let message = "";
  try {
    new ClientUserKey("nope" as unknown as Uint8Array);
  } catch (err) {
    message = (err as Error).message;
  }
  assert.equal(message.startsWith("jack user-key:"), true, "error message prefix");
  assert.equal(message.includes(key.seedHex), false, "error message must not contain the seed hex");
  // Buffer is a Uint8Array subclass and must be accepted.
  const bufKey = new ClientUserKey(Buffer.from(key.seedHex, "hex"));
  assert.equal(encodeBase64URL(bufKey.publicKey()), key.publicKey, "Buffer seed: public key");
  assert.equal(bufKey.kid(), key.kid, "Buffer seed: kid");
});

test("mutating the input seed does not change the stored key", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const input = new Uint8Array(Buffer.from(key.seedHex, "hex"));
  const uk = new ClientUserKey(input);
  const pubBefore = uk.publicKey();
  const kidBefore = uk.kid();
  const reference = new InMemorySigner(new Uint8Array(Buffer.from(key.seedHex, "hex")));
  const msg = utf8("mcp-jack user-key input-copy check");
  input.fill(0);
  assert.deepEqual(bytes(uk.publicKey()), bytes(pubBefore), "public key after input mutation");
  assert.equal(uk.kid(), kidBefore, "kid after input mutation");
  assert.deepEqual(bytes(uk.sign(msg)), bytes(reference.sign(msg)), "signature after input mutation matches an independent signer on the same seed (deterministic)");
});

test("public outputs are independent copies", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const seedBytes = Buffer.from(key.seedHex, "hex");
  const uk = new ClientUserKey(new Uint8Array(seedBytes));
  const msg = utf8("mcp-jack user-key output-copy check");
  const sig = uk.sign(msg);
  const pub = uk.publicKey();
  pub.fill(0xaa);
  assert.equal(encodeBase64URL(uk.publicKey()), key.publicKey, "publicKey after mutating a previous output");
  assert.equal(uk.kid(), key.kid, "kid after mutating a public output");
  assert.equal(verify(uk.publicKey(), msg, sig), true, "signatures still verify under the untouched key");
});

test("the seed never appears in JSON, inspection or own properties", () => {
  const key = loadKeys().keys.find((k) => k.name === "root");
  assert.ok(key !== undefined, "keys.json has no root key");
  const seedBytes = Buffer.from(key.seedHex, "hex");
  const uk = new ClientUserKey(new Uint8Array(seedBytes));
  const json = JSON.stringify(uk);
  assert.equal(json.includes(key.seedHex), false, "JSON contains the seed hex");
  assert.equal(json.includes(encodeBase64URL(new Uint8Array(seedBytes))), false, "JSON contains the base64url seed");
  const text = inspect(uk, { depth: Number.POSITIVE_INFINITY });
  assert.equal(text.includes(key.seedHex), false, "inspect output contains the seed hex");
  assert.equal(text.includes(encodeBase64URL(new Uint8Array(seedBytes))), false, "inspect output contains the base64url seed");
  assert.deepEqual(Object.getOwnPropertyNames(uk), [], "private # fields leave no own properties");
  assert.equal(json === "{}", true, "default JSON serialization reveals nothing");
  let message = "";
  try {
    new ClientUserKey(new Uint8Array(31));
  } catch (err) {
    message = (err as Error).message;
  }
  assert.equal(message.includes(key.seedHex), false, "import-error message must never contain the seed bytes");
});

test("usable as the client Signer with no secret export", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const seed = new Uint8Array(Buffer.from(key.seedHex, "hex"));
  const keyObj = new ClientUserKey(seed);
  // (a) Compile-time structural bridge: ClientUserKey satisfies Signer without an adapter.
  const asSigner: Signer = keyObj;
  // (b) Same header as InMemorySigner over the same seed and fixed request parameters.
  const aud = "https://svc.example.test";
  const body = utf8("{\"method\":\"tools/list\"}");
  const nonce = new Uint8Array(16).fill(0xab);
  const ts = 1700000000;
  const headerA = signRequest(asSigner, aud, "POST", "/target", body, nonce, ts);
  const headerB = signRequest(new InMemorySigner(seed), aud, "POST", "/target", body, nonce, ts);
  assert.equal(headerA, headerB, "identical header to InMemorySigner for the same seed and parameters");
  // (c) A minimal class implementing ONLY Signer (no export method) is accepted.
  class FixedSigner implements Signer {
    sign(): Uint8Array {
      return new Uint8Array(64).fill(7);
    }
    publicKey(): Uint8Array {
      return new Uint8Array(32).fill(7);
    }
    kid(): string {
      return keyId(this.publicKey());
    }
  }
  const fixedSig = new Uint8Array(64).fill(7);
  const fixedHeader = signRequest(new FixedSigner(), aud, "POST", "/target", body, nonce, ts);
  const parsed = parseRequestAuth([fixedHeader]);
  assert.equal(parsed.sig, encodeBase64URL(fixedSig), "Signer requires no export method");
});

test("server import accepts every fixture public key", () => {
  const keys = loadKeys().keys;
  assert.ok(keys.length >= 2, "keys.json returned too few keys");
  for (const key of keys) {
    const pinned = decodeBase64URLFixed(key.publicKey, 32);
    const srv = new ServerUserKey(decodeBase64URLFixed(key.publicKey, 32));
    assert.equal(srv.kid(), key.kid, `key ${key.name}: server kid`);
    assert.equal(keyId(srv.publicKey()), key.kid, `key ${key.name}: kid equals keyId(public key)`);
    assert.deepEqual(bytes(srv.publicKey()), bytes(pinned), `key ${key.name}: public key bytes`);
    assert.equal(validatePublicKey(srv.publicKey()), null, `key ${key.name}: server-stored public key is valid`);
  }
});

test("server import rejects invalid public keys (key vectors)", () => {
  const jackMatcher = (err: unknown): boolean =>
    err instanceof JackError && err.code === Code.KEY_REJECTED && err.httpStatus === 400;
  // Oracle: every key-vectors.json case, valid and rejected.
  const vectors = loadKeyVectors();
  assert.ok(vectors.cases.length > 0, "key-vectors.json returned no cases");
  for (const kvc of vectors.cases) {
    const keyBytes = fromHex(kvc.publicKeyHex);
    if (kvc.expect === "rejected") {
      assert.throws(() => new ServerUserKey(keyBytes), jackMatcher, `key-vectors ${kvc.id}`);
    } else if (kvc.expect === "valid") {
      const srv = new ServerUserKey(keyBytes);
      assert.deepEqual(bytes(srv.publicKey()), bytes(keyBytes), `key-vectors ${kvc.id}`);
    } else {
      assert.fail(`key-vectors ${kvc.id}: unexpected expect value ${kvc.expect}`);
    }
  }
  // Explicit labeled cases: the CORRECT identity encoding is 0x01 followed by 31 zero bytes.
  const identity = new Uint8Array(32);
  identity[0] = 0x01;
  assert.throws(() => new ServerUserKey(identity), jackMatcher, "identity point (0x01 followed by 31 zero bytes)");
  // 32 zero bytes is a distinct small-order point.
  assert.throws(() => new ServerUserKey(new Uint8Array(32)), jackMatcher, "small-order point (y = 0, order 4)");
  // Type lies land in the runtime guard, not validatePublicKey.
  const typeMatcher = (err: unknown): boolean => err instanceof Error && err.message === "jack user-key: public key must be a Uint8Array";
  assert.throws(() => new ServerUserKey("nope" as unknown as Uint8Array), typeMatcher, "string public key");
  assert.throws(() => new ServerUserKey(null as unknown as Uint8Array), typeMatcher, "null public key");
  assert.throws(() => new ServerUserKey(new ArrayBuffer(32) as unknown as Uint8Array), typeMatcher, "ArrayBuffer public key");
  assert.throws(() => new ServerUserKey([1, 2, 3] as unknown as Uint8Array), typeMatcher, "array public key");
  // Bad lengths land in validatePublicKey and arrive as JackError KEY_REJECTED.
  assert.throws(() => new ServerUserKey(new Uint8Array(0)), jackMatcher, "zero-length public key");
  assert.throws(() => new ServerUserKey(new Uint8Array(31)), jackMatcher, "31-byte public key");
  assert.throws(() => new ServerUserKey(new Uint8Array(33)), jackMatcher, "33-byte public key");
});

test("server import copies the input; later mutation does not change the stored identity", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const seed = new Uint8Array(Buffer.from(key.seedHex, "hex"));
  const signer = new ClientUserKey(seed);
  const msg = utf8("mcp-jack user-key server-copy check");
  const sig = signer.sign(msg);
  const input = decodeBase64URLFixed(key.publicKey, 32);
  const srv = new ServerUserKey(input);
  const snapshot = bytes(input);
  input.fill(0);
  assert.equal(srv.kid(), key.kid, "kid after input mutation");
  assert.deepEqual(bytes(srv.publicKey()), snapshot, "stored public key bytes are an independent copy");
  assert.equal(verify(srv.publicKey(), msg, sig), true, "signature-verification identity unchanged after input mutation");
});

test("the server wrapper exposes no private access", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const pinned = decodeBase64URLFixed(key.publicKey, 32);
  const issuedPair = issueUserKey();
  const issuedSeed = issuedPair.handoff.exportSeed();
  const records = [
    { srv: new ServerUserKey(pinned), seedHex: key.seedHex, seedB64u: encodeBase64URL(fromHex(key.seedHex)), label: "fixture-backed" },
    { srv: issuedPair.server, seedHex: Buffer.from(issuedSeed).toString("hex"), seedB64u: encodeBase64URL(issuedSeed), label: "issued" },
  ];
  for (const rec of records) {
    assert.deepEqual(Object.getOwnPropertyNames(rec.srv), [], `${rec.label}: private # fields leave no own properties`);
    const protoNames = Object.getOwnPropertyNames(Object.getPrototypeOf(rec.srv))
      .filter((n) => n !== "constructor")
      .sort();
    assert.deepEqual(protoNames, ["kid", "publicKey"], `${rec.label}: prototype exposes exactly kid and publicKey`);
    const probe = rec.srv as unknown as Record<string, unknown>;
    assert.equal(typeof probe.exportSeed, "undefined", `${rec.label}: server wrapper has no exportSeed`);
    assert.equal(typeof probe.sign, "undefined", `${rec.label}: server wrapper has no sign`);
    const json = JSON.stringify(rec.srv);
    assert.equal(json.includes(rec.seedHex), false, `${rec.label}: JSON contains the seed hex`);
    assert.equal(json.includes(rec.seedB64u), false, `${rec.label}: JSON contains the base64url seed`);
    assert.equal(json === "{}", true, `${rec.label}: default JSON serialization reveals nothing`);
    const text = inspect(rec.srv, { depth: Number.POSITIVE_INFINITY });
    assert.equal(text.includes(rec.seedHex), false, `${rec.label}: inspect output contains the seed hex`);
    assert.equal(text.includes(rec.seedB64u), false, `${rec.label}: inspect output contains the base64url seed`);
    const expectedPub = rec.srv.publicKey();
    const expectedKid = rec.srv.kid();
    const pub = rec.srv.publicKey();
    pub.fill(0xaa);
    assert.equal(rec.srv.kid(), expectedKid, `${rec.label}: kid after mutating a public output`);
    assert.deepEqual(bytes(rec.srv.publicKey()), bytes(expectedPub), `${rec.label}: publicKey after mutating a previous output`);
  }
});

test("issuance couples the roles without private recovery", () => {
  const issued = issueUserKey();
  // The handoff export re-imports to exactly the issued server identity.
  const backup = issued.handoff.exportSeed();
  const client = new ClientUserKey(backup);
  assert.equal(client.kid(), issued.server.kid(), "issued server kid equals client kid from the handoff export");
  assert.deepEqual(bytes(client.publicKey()), bytes(issued.server.publicKey()), "issued server public key equals client public key from the handoff export");
  // A message signed by the re-imported client verifies under the issued server public key.
  const msg = utf8("mcp-jack user-key issuance coupling");
  assert.equal(verify(issued.server.publicKey(), msg, client.sign(msg)), true, "client signature verifies under issued server public key");
  // Re-importing from a SECOND fresh exportSeed() call reproduces the same pub/kid.
  const reimported = new ClientUserKey(issued.handoff.exportSeed());
  assert.deepEqual(bytes(reimported.publicKey()), bytes(issued.server.publicKey()), "second exportSeed reimport: public key bytes");
  assert.equal(reimported.kid(), issued.server.kid(), "second exportSeed reimport: kid");
  // The handoff surface exposes ONLY exportSeed: no signing, no identity.
  const handoffProtoNames = Object.getOwnPropertyNames(Object.getPrototypeOf(issued.handoff))
    .filter((n) => n !== "constructor")
    .sort();
  assert.deepEqual(handoffProtoNames, ["exportSeed"], "handoff prototype exposes exactly exportSeed");
  const handoffProbe = issued.handoff as unknown as Record<string, unknown>;
  assert.equal(typeof handoffProbe.sign, "undefined", "handoff has no sign");
  assert.equal(typeof handoffProbe.kid, "undefined", "handoff has no kid");
  assert.equal(typeof handoffProbe.publicKey, "undefined", "handoff has no publicKey");
  // Issuance is fresh every time.
  assert.notEqual(issueUserKey().server.kid(), issueUserKey().server.kid(), "two issuances must differ");
  // Server side stays private-free.
  assert.deepEqual(Object.getOwnPropertyNames(issued.server), [], "issued server exposes no own properties");
  const protoNames = Object.getOwnPropertyNames(Object.getPrototypeOf(issued.server))
    .filter((n) => n !== "constructor")
    .sort();
  assert.deepEqual(protoNames, ["kid", "publicKey"], "issued server prototype exposes exactly kid and publicKey");
  const probe = issued.server as unknown as Record<string, unknown>;
  assert.equal(typeof probe.exportSeed, "undefined", "issued server has no exportSeed");
  assert.equal(typeof probe.sign, "undefined", "issued server has no sign");
});

test("the handoff export is a fresh private copy", () => {
  const issued = issueUserKey();
  const handoff = issued.handoff;
  const msg = utf8("mcp-jack user-key handoff freshness");
  const seed = handoff.exportSeed();
  assert.equal(seed.length, 32, "exported seed length");
  const seed2 = handoff.exportSeed();
  assert.equal(seed === seed2, false, "exportSeed must return a new array instance each call");
  // Snapshot the pre-mutation bytes and keep the retained public identity.
  const snapshot = bytes(seed);
  const serverKid = issued.server.kid();
  assert.equal(sameBytes(seed, seed2), true, "exportSeed content is stable");
  seed.fill(0xff);
  assert.equal(sameBytes(seed, seed2), false, "mutating one export does not alias the second exported copy");
  assert.equal(sameBytes(seed2, snapshot), true, "second exported copy still matches the pre-mutation snapshot");
  const seed3 = handoff.exportSeed();
  assert.equal(sameBytes(seed3, snapshot), true, "later exports match the pre-mutation snapshot");
  // Behavioral proof: the untouched stored secret still yields the issued identity.
  const reimported = new ClientUserKey(seed3);
  assert.equal(reimported.kid(), serverKid, "reimported kid matches the retained server kid");
  assert.equal(verify(issued.server.publicKey(), msg, reimported.sign(msg)), true, "reimported client signs/verifies under the retained server identity");
  // Default serialization and inspection of the handoff reveal nothing.
  const seedHex = Buffer.from(seed3).toString("hex");
  const seedB64u = encodeBase64URL(seed3);
  const handoffJson = JSON.stringify(handoff);
  assert.equal(handoffJson === "{}", true, "handoff default JSON serialization reveals nothing");
  const text = inspect(handoff, { depth: Number.POSITIVE_INFINITY });
  assert.equal(text.includes(seedHex), false, "handoff inspect output contains the seed hex");
  assert.equal(text.includes(seedB64u), false, "handoff inspect output contains the base64url seed");
  assert.deepEqual(Object.getOwnPropertyNames(handoff), [], "handoff private # field leaves no own properties");
});

test("the handoff enforces its advertised seed invariant", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const typeMatcher = (err: unknown): boolean => err instanceof Error && err.message === "jack user-key: seed must be a Uint8Array";
  const lengthMatcher = (n: number) => (err: unknown): boolean =>
    err instanceof Error && err.message === `jack user-key: seed must be exactly 32 bytes, got ${n}`;
  assert.throws(() => new UserKeyHandoff(new Uint8Array(0)), lengthMatcher(0), "zero-length seed");
  assert.throws(() => new UserKeyHandoff(new Uint8Array(31)), lengthMatcher(31), "31-byte seed");
  assert.throws(() => new UserKeyHandoff(new Uint8Array(33)), lengthMatcher(33), "33-byte seed");
  assert.throws(() => new UserKeyHandoff("nope" as unknown as Uint8Array), typeMatcher, "string seed");
  assert.throws(() => new UserKeyHandoff(null as unknown as Uint8Array), typeMatcher, "null seed");
  assert.throws(() => new UserKeyHandoff(new ArrayBuffer(32) as unknown as Uint8Array), typeMatcher, "ArrayBuffer seed");
  assert.throws(() => new UserKeyHandoff([1, 2, 3] as unknown as Uint8Array), typeMatcher, "array seed");
  // Positive control: a fixture seed round-trips and reproduces the fixture identity.
  const fixtureSeed = fromHex(key.seedHex);
  const h = new UserKeyHandoff(fixtureSeed);
  const exported = h.exportSeed();
  assert.equal(exported.length, 32, "fixture seed export length");
  assert.equal(sameBytes(exported, fromHex(key.seedHex)), true, "fixture seed export content");
  const reimported = new ClientUserKey(exported);
  assert.equal(reimported.kid(), key.kid, "reimport from handoff export reproduces the fixture kid");
  // Input-copy: later mutation of the constructor argument does not affect the handoff.
  const input = fromHex(key.seedHex);
  const h2 = new UserKeyHandoff(input);
  const snapshot = bytes(input);
  input.fill(0);
  assert.equal(sameBytes(h2.exportSeed(), snapshot), true, "handoff stores an independent copy of the seed");
});

test("client method surface exposes no private export", () => {
  const key = loadKeys().keys[0];
  assert.ok(key !== undefined, "keys.json returned no keys");
  const imported = new ClientUserKey(fromHex(key.seedHex));
  const generated = generateClientUserKey();
  const msg = utf8("mcp-jack user-key client surface check");
  const cases: Array<{ label: string; client: ClientUserKey }> = [
    { label: "imported", client: imported },
    { label: "generated", client: generated },
  ];
  for (const rec of cases) {
    assert.deepEqual(Object.getOwnPropertyNames(rec.client), [], `${rec.label}: private # fields leave no own properties`);
    const protoNames = Object.getOwnPropertyNames(Object.getPrototypeOf(rec.client))
      .filter((n) => n !== "constructor")
      .sort();
    assert.deepEqual(protoNames, ["kid", "publicKey", "sign"], `${rec.label}: prototype exposes exactly kid, publicKey and sign`);
    const probe = rec.client as unknown as Record<string, unknown>;
    assert.equal(typeof probe.exportSeed, "undefined", `${rec.label}: client has no exportSeed`);
  }
  // Positive controls: the public surface really works.
  assert.equal(imported.kid(), key.kid, "imported: kid matches the fixture kid");
  assert.equal(encodeBase64URL(imported.publicKey()), key.publicKey, "imported: public key matches the fixture public_key");
  const importedSig = imported.sign(msg);
  assert.equal(verify(imported.publicKey(), msg, importedSig), true, "imported: own-message signature verifies");
  assert.equal(validatePublicKey(generated.publicKey()), null, "generated: public key passes validatePublicKey");
  const generatedSig = generated.sign(msg);
  assert.equal(verify(generated.publicKey(), msg, generatedSig), true, "generated: own-message signature verifies");
});
