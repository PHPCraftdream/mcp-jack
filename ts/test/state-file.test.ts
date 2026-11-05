/** Tests for the file-backed state store, ported from Go's statefile_test.go plus the file rollback subtest of state_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  serializeInviteRecord,
  serializeRegistryEntry,
} from "../src/server/state.js";
import type { RegistryEntry } from "../src/server/state.js";
import type { InviteRecord } from "../src/server/state.js";
import { FileState, StateCorruptError, openFileState } from "../src/server/state-file.js";
import { decodeBase64URL, encodeBase64URL, keyId } from "../src/encoding.js";
import { validatePublicKey } from "../src/ed25519.js";
import { loadKeys } from "./fixtures.js";

/**
 * Builds a registry entry with a real Ed25519 public key derived from id, and
 * kid = base64url(SHA-256(public_key)), so documents seeded with it pass the
 * strict file-load validation. Keep ids unique within a test.
 */
function stateTestKey(id: string, name: string): RegistryEntry {
  const seed = createHash("sha256").update(id).digest();
  // RFC 8410 PKCS#8 Ed25519 private key prefix followed by the 32-byte seed.
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  // The SPKI DER encoding ends with the 32-byte public key.
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  return {
    kid: keyId(pub),
    publicKey: encodeBase64URL(pub),
    name,
    kind: "human",
    scopes: ["read"],
  };
}

/** Fixture keys as registry entries. */
function fixtureKeys(): RegistryEntry[] {
  return loadKeys().keys.map((k) => ({
    kid: k.kid,
    publicKey: k.publicKey,
    name: k.name,
    kind: "human",
    scopes: ["read"],
  }));
}

/** Two distinct fixture keys; asserts the fixture is large enough first. */
function fixturePair(): [RegistryEntry, RegistryEntry] {
  const keys = fixtureKeys();
  assert.ok(keys.length >= 2, "keys.json needs at least two keys");
  return [keys[0] as RegistryEntry, keys[1] as RegistryEntry];
}

/** A valid invite for document-level invite cases. */
function testInvite(inviteId: string): InviteRecord {
  return { inviteId, scopes: ["read"], kind: "human", createdBy: "root", createdAt: 1767225500, expiresAt: 1767228600 };
}

/** New temp directory cleaned up when the test ends. */
function tempDir(t: { after(fn: () => void): unknown }): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-jack-state-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Writes text as dir/state.json. */
function writeDoc(dir: string, text: string): string {
  const path = join(dir, "state.json");
  writeFileSync(path, text);
  return path;
}

/** Wraps marshaled entries and invites as a full state document (Go fileTestDoc). */
function testDoc(entries: readonly RegistryEntry[], invites: readonly InviteRecord[] = []): string {
  const keyParts = entries.map((e) => JSON.stringify(serializeRegistryEntry(e)));
  const inviteParts = invites.map((v) => JSON.stringify(serializeInviteRecord(v)));
  return `{"version":1,"keys":[${keyParts.join(",")}],"invites":[${inviteParts.join(",")}]}`;
}

/** Writes doc as the state file and asserts openFileState rejects it as corrupt (Go fileTestLoad). */
function assertLoadCorrupt(dir: string, doc: string): void {
  const path = writeDoc(dir, doc);
  assert.throws(() => openFileState(path), (err) => err instanceof StateCorruptError);
}

/** Go fileTestCorrupt: also requires the error message to mention the file name. */
function assertCorruptNamed(dir: string, doc: string): void {
  const path = writeDoc(dir, doc);
  assert.throws(
    () => openFileState(path),
    (err: unknown) =>
      err instanceof StateCorruptError && (err as Error).message.includes("state.json"),
  );
}

test("fixture keys are real Ed25519 public keys", () => {
  // Proves the fixture keys are valid so the rejection tests below fail for
  // the mutated field only.
  for (const k of loadKeys().keys) {
    const pub = decodeBase64URL(k.publicKey);
    assert.equal(pub.length, 32, k.kid);
    assert.equal(keyId(pub), k.kid);
    assert.equal(validatePublicKey(pub), null);
  }
});

test("missing state file starts empty", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  const view = store.view();
  assert.deepEqual(view.keys, []);
  assert.deepEqual(view.invites, []);
  assert.ok(store instanceof FileState);

  const entry = stateTestKey("k1", "alice");
  store.update((e) => {
    e.putKey(entry);
    e.putInvite({ inviteId: "i1", createdBy: "root", createdAt: 0, expiresAt: 0 });
  });
  const doc = JSON.parse(readFileSync(path, "utf8")) as {
    version: number;
    keys: unknown[];
    invites: unknown[];
  };
  assert.equal(doc.version, 1);
  assert.equal(doc.keys.length, 1);
  assert.equal(doc.invites.length, 1);
});

test("file state round trip is sorted, indented and newline-terminated", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  // Deliberately insert out of sort order.
  const kzz = stateTestKey("zz", "zoe");
  const kaa = stateTestKey("aa", "ann");
  store.update((e) => {
    e.putKey(kzz);
    e.putKey(kaa);
    e.putInvite({ inviteId: "i9", createdBy: "root", createdAt: 0, expiresAt: 0 });
    e.putInvite({ inviteId: "i2", createdBy: "root", createdAt: 0, expiresAt: 0 });
  });
  const want = store.view();

  const reopened = openFileState(path);
  assert.deepStrictEqual(reopened.view(), want);

  const data = readFileSync(path, "utf8");
  assert.ok(data.endsWith("\n"), "file does not end with newline");
  assert.ok(data.includes('\n  "'), "file is not indented JSON");
  // Kids are hashes, so derive the expected order from the actual values.
  const [first, second] = kaa.kid < kzz.kid ? [kaa, kzz] : [kzz, kaa];
  const firstIdx = data.indexOf(`"kid": "${first.kid}"`);
  const secondIdx = data.indexOf(`"kid": "${second.kid}"`);
  assert.ok(firstIdx !== -1 && secondIdx !== -1 && firstIdx < secondIdx, "keys not sorted by kid");
  const i9Idx = data.indexOf('"invite_id": "i9"');
  const i2Idx = data.indexOf('"invite_id": "i2"');
  assert.ok(i9Idx !== -1 && i2Idx !== -1 && i2Idx < i9Idx, "invites not sorted by invite id");
});

test("valid document from a fixture key loads", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  const view = openFileState(writeDoc(dir, testDoc([entry]))).view();
  assert.equal(view.keys.length, 1);
  const got = view.keys[0];
  assert.ok(got);
  assert.equal(got.kid, entry.kid);
});

test("load rejects a kid mismatch", (t) => {
  const dir = tempDir(t);
  const [entry, other] = fixturePair();
  assertLoadCorrupt(dir, testDoc([entry]).replace(`"kid":"${entry.kid}"`, `"kid":"${other.kid}"`));
});

test("load rejects a wrong-length public key", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(
    dir,
    testDoc([entry]).replace(`"public_key":"${entry.publicKey}"`, `"public_key":"${encodeBase64URL(new Uint8Array(16))}"`),
  );
});

test("load rejects a malformed base64url public key", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, publicKey: "not base64url!" }]));
});

test("load rejects an invalid name with a space", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, name: "bad name!" }]));
});

test("load rejects a name longer than 64 characters", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, name: "a".repeat(65) }]));
});

test("load rejects a duplicate name", (t) => {
  const dir = tempDir(t);
  const [entry, other] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, name: "same" }, { ...other, name: "same" }]));
});

test("load rejects a kind that is neither human nor agent", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, kind: "robot" }]));
});

test("load rejects an uppercase scope", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, scopes: ["Read"] }]));
});

test("load rejects a scope with an empty segment", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, scopes: ["a::b"] }]));
});

test("load rejects duplicate scopes", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, scopes: ["read", "read"] }]));
});

test("load rejects the identity public key even with a matching kid", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  // The neutral point's encoding passes the kid check and must fail validatePublicKey.
  const identity = new Uint8Array(32);
  identity[0] = 1;
  assertLoadCorrupt(dir, testDoc([{ ...entry, publicKey: encodeBase64URL(identity), kid: keyId(identity) }]));
});

test("load rejects a key whose scopes field is missing", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([entry]).replace('"scopes":["read"],', ""));
});

test("load rejects a key whose scopes field is null", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([entry]).replace('"scopes":["read"]', '"scopes":null'));
});

test("load rejects an agent key holding admin", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, kind: "agent", scopes: ["admin"] }]));
});

test("load rejects a negative not_before", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, notBefore: -1 }]));
});

test("load rejects a negative not_after", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, notAfter: -1 }]));
});

test("load rejects not_before not before not_after", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, testDoc([{ ...entry, notBefore: 10, notAfter: 10 }]));
});

test("load rejects an unknown field inside an entry", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  const wire = { ...serializeRegistryEntry(entry), unexpected: 1 };
  assertLoadCorrupt(dir, `{"version":1,"keys":[${JSON.stringify(wire)}],"invites":[]}`);
});

test("load rejects a duplicate kid among valid entries", (t) => {
  const dir = tempDir(t);
  const [entry, other] = fixturePair();
  // The twin carries the first entry's kid and key material with a different
  // name, so each entry alone is valid and only the duplicate-kid rule can
  // reject the document (it also runs before name checking, as in Go).
  const twin: RegistryEntry = { ...entry, name: other.name };
  assertLoadCorrupt(dir, testDoc([entry, twin]));
});

test("load rejects a duplicate invite id", (t) => {
  const dir = tempDir(t);
  assertLoadCorrupt(dir, testDoc([], [testInvite("i1"), testInvite("i1")]));
});

test("load rejects an invite whose scopes field is missing", (t) => {
  const dir = tempDir(t);
  // Keys stay empty so the surgery hits the invite's scopes, not a key's.
  const doc = testDoc([], [testInvite("i1")]);
  assertLoadCorrupt(dir, doc.replace('"scopes":["read"],', ""));
});

test("load rejects an invite whose scopes field is null", (t) => {
  const dir = tempDir(t);
  const doc = testDoc([], [testInvite("i1")]);
  assertLoadCorrupt(dir, doc.replace('"scopes":["read"]', '"scopes":null'));
});

test("load rejects a file that is not JSON", (t) => {
  const dir = tempDir(t);
  assertCorruptNamed(dir, "not json at all");
});

test("load rejects an empty file", (t) => {
  const dir = tempDir(t);
  assertCorruptNamed(dir, "");
});

test("load rejects an unknown top-level field", (t) => {
  const dir = tempDir(t);
  assertCorruptNamed(dir, '{"version":1,"keys":[],"invites":[],"extra":1}');
});

test("load rejects an unsupported version", (t) => {
  const dir = tempDir(t);
  assertCorruptNamed(dir, '{"version":2,"keys":[],"invites":[]}');
});

test("load rejects a non-object document", (t) => {
  const dir = tempDir(t);
  assertCorruptNamed(dir, "[]");
});

test("load rejects trailing data after the document", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertCorruptNamed(dir, `${testDoc([entry])} trailing`);
});

test("file state rolls back memory and disk", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  const entry = stateTestKey("k1", "alice");
  store.update((e) => {
    e.putKey(entry);
    e.putInvite({ inviteId: "i1", createdBy: "root", createdAt: 0, expiresAt: 0 });
  });
  const beforeBytes = readFileSync(path, "utf8");
  const before = store.view();

  const boom = new Error("boom");
  assert.throws(
    () =>
      store.update((e) => {
        e.putKey(stateTestKey("k2", "mallory"));
        e.removeInvite("i1");
        throw boom;
      }),
    (err) => err === boom,
  );
  assert.deepStrictEqual(store.view(), before);
  assert.equal(readFileSync(path, "utf8"), beforeBytes);
});

test("failed update leaves no trace", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  const entry = stateTestKey("k1", "alice");
  store.update((e) => {
    e.putKey(entry);
  });
  const beforeBytes = readFileSync(path, "utf8");
  const before = store.view();

  const boom = new Error("boom");
  assert.throws(
    () =>
      store.update((e) => {
        e.putKey(stateTestKey("k2", "mallory"));
        throw boom;
      }),
    (err) => err === boom,
  );
  assert.equal(readFileSync(path, "utf8"), beforeBytes);
  assert.deepStrictEqual(store.view(), before);
  const names = readdirSync(dir).filter((name) => name !== "state.json");
  assert.deepEqual(names, []);
});

test("successful update leaves the directory clean", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  const entry = stateTestKey("k1", "alice");
  store.update((e) => {
    e.putKey(entry);
  });
  const names = readdirSync(dir);
  assert.equal(names.length, 1);
  const first = names[0];
  assert.ok(first !== undefined); // narrows the indexed read for noUncheckedIndexedAccess
  assert.ok(!first.startsWith(".mcp-jack-state-"), `temp file ${first} left behind`);
});

test("sequential updates all land on disk", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  const writers = 16;
  for (let i = 0; i < writers; i++) {
    const id = `k-${String(i).padStart(2, "0")}`;
    store.update((e) => {
      e.putKey(stateTestKey(id, `user-${i}`));
    });
  }
  const reopened = openFileState(path);
  assert.equal(reopened.view().keys.length, writers);
});
