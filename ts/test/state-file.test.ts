/** Tests for the file-backed state store, ported from Go's statefile_test.go plus the file rollback subtest of state_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
import { loadKeys, loadStateFileVectors } from "./fixtures.js";

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
  };
}

/** Fixture keys as registry entries. */
function fixtureKeys(): RegistryEntry[] {
  return loadKeys().keys.map((k) => ({
    kid: k.kid,
    publicKey: k.publicKey,
    name: k.name,
  }));
}

/** Two distinct fixture keys; asserts the fixture is large enough first. */
function fixturePair(): [RegistryEntry, RegistryEntry] {
  const keys = fixtureKeys();
  assert.ok(keys.length >= 2, "keys.json needs at least two keys");
  const first = keys[0];
  const second = keys[1];
  assert.ok(first !== undefined && second !== undefined, "keys.json needs at least two keys");
  return [first, second];
}

/** A valid invite for document-level invite cases. */
function testInvite(inviteId: string): InviteRecord {
  return { inviteId, createdBy: "root", createdAt: 1767225500, expiresAt: 1767228600 };
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
  assert.deepEqual(readdirSync(dir), [], "opening a missing file must not create it");

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

test("explicit empty collection arrays load as empty state", (t) => {
  const dir = tempDir(t);
  const store = openFileState(writeDoc(dir, JSON.stringify({ version: 1, keys: [], invites: [] })));
  assert.deepEqual(store.view(), { keys: [], invites: [] });
});

test("missing collection arrays and non-arrays are corrupt without a store or file rewrite", (t) => {
  const cases: readonly { label: string; absent?: true; value?: unknown }[] = [
    { label: "absent", absent: true },
    { label: "null", value: null },
    { label: "string", value: "not-an-array" },
    { label: "number", value: 1 },
    { label: "boolean", value: true },
    { label: "object", value: {} },
  ];

  for (const member of ["keys", "invites"] as const) {
    for (const invalid of cases) {
      const dir = tempDir(t);
      const doc: Record<string, unknown> = { version: 1, keys: [], invites: [] };
      if (invalid.absent) {
        delete doc[member];
      } else {
        doc[member] = invalid.value;
      }
      const path = writeDoc(dir, JSON.stringify(doc));
      const before = readFileSync(path);
      const holder: { store: FileState | undefined } = { store: undefined };
      assert.throws(
        () => {
          holder.store = openFileState(path);
        },
        (err: unknown) => err instanceof StateCorruptError && err.message.includes(`${member}: not an array`),
        `${member} ${invalid.label} must be rejected with a member-specific error`,
      );
      assert.equal(holder.store, undefined, `${member} ${invalid.label} must not return a usable store`);
      assert.deepEqual(readFileSync(path), before, `${member} ${invalid.label} must leave raw bytes unchanged`);
    }
  }
});

test("an empty state writes explicit collection arrays and reloads", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const store = openFileState(path);
  assert.equal(existsSync(path), false, "opening a missing file must not create it");

  store.update(() => {});
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  assert.ok(typeof raw === "object" && raw !== null && !Array.isArray(raw), "written state must be an object");
  assert.ok("keys" in raw && Array.isArray(raw.keys), "writer must emit keys as an array");
  assert.ok("invites" in raw && Array.isArray(raw.invites), "writer must emit invites as an array");
  assert.equal(raw.keys.length, 0);
  assert.equal(raw.invites.length, 0);
  assert.deepEqual(openFileState(path).view(), { keys: [], invites: [] });
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

// ---------------------------------------------------------------------------
// The strict-boolean admin field.
// ---------------------------------------------------------------------------

/** Swaps the serialized entry's `"admin":false` member for an arbitrary JSON value. */
function entryAdmin(entry: RegistryEntry, json: string): string {
  return testDoc([entry]).replace(`"admin":false`, `"admin":${json}`);
}

/** Same for the serialized invite. */
function inviteAdmin(invite: InviteRecord, json: string): string {
  return testDoc([], [invite]).replace(`"admin":false`, `"admin":${json}`);
}

test("load rejects an entry admin of the string \"true\"", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, entryAdmin(entry, '"true"'));
});

test("load rejects an entry admin of the number 1", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, entryAdmin(entry, "1"));
});

test("load rejects an entry admin of null", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  assertLoadCorrupt(dir, entryAdmin(entry, "null"));
});

test("an entry without admin loads as non-admin", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  const doc = testDoc([entry]).replace(`"admin":false,`, "");
  const got = openFileState(writeDoc(dir, doc)).lookup(entry.kid);
  assert.ok(got, "entry expected");
  assert.equal(got.admin, undefined);
});

test("an entry with admin true loads as admin", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  const got = openFileState(writeDoc(dir, testDoc([{ ...entry, admin: true }]))).lookup(entry.kid);
  assert.ok(got, "entry expected");
  assert.equal(got.admin, true);
});

test("an invite without admin loads as non-admin", (t) => {
  const dir = tempDir(t);
  const doc = testDoc([], [testInvite("i1")]).replace(`"admin":false,`, "");
  const got = openFileState(writeDoc(dir, doc)).view().invites[0];
  assert.ok(got, "invite expected");
  assert.equal(got.admin, undefined);
});

test("an invite with admin true loads as admin", (t) => {
  const dir = tempDir(t);
  const got = openFileState(writeDoc(dir, testDoc([], [{ ...testInvite("i1"), admin: true }]))).view().invites[0];
  assert.ok(got, "invite expected");
  assert.equal(got.admin, true);
});

test("load rejects an invite admin of the string \"true\"", (t) => {
  const dir = tempDir(t);
  assertLoadCorrupt(dir, inviteAdmin(testInvite("i1"), '"true"'));
});

test("load rejects an invite admin of the number 1", (t) => {
  const dir = tempDir(t);
  assertLoadCorrupt(dir, inviteAdmin(testInvite("i1"), "1"));
});

test("load rejects an invite admin of null", (t) => {
  const dir = tempDir(t);
  assertLoadCorrupt(dir, inviteAdmin(testInvite("i1"), "null"));
});

// ---------------------------------------------------------------------------
// Required invite timestamps and identifiers (spec 03 section 10).
// ---------------------------------------------------------------------------

const rawValidInvite: Record<string, unknown> = {
  invite_id: "i1",
  created_by: "root",
  created_at: 100,
  expires_at: 200,
};

/** Writes an invite document and requires a named rejection without changing its raw bytes. */
function assertInviteRejectedUnchanged(t: { after(fn: () => void): unknown }, rawInvite: Record<string, unknown>, member: string): void {
  const dir = tempDir(t);
  const doc = JSON.stringify({ version: 1, keys: [], invites: [rawInvite] });
  const path = writeDoc(dir, doc);
  const before = readFileSync(path);
  assert.throws(
    () => openFileState(path),
    (err: unknown) => err instanceof StateCorruptError && err.message.includes(`invites[0].${member}`),
    `expected an error naming invites[0].${member}`,
  );
  assert.deepEqual(readFileSync(path), before, "the failed load must not rewrite the file");
}

test("invite timestamps are required nonnegative integers", (t) => {
  const invalidValues: readonly unknown[] = [null, "100", true, 1.5, -1];
  for (const field of ["created_at", "expires_at"] as const) {
    for (const value of invalidValues) {
      assertInviteRejectedUnchanged(t, { ...rawValidInvite, [field]: value }, field);
    }
    const missing: Record<string, unknown> = { ...rawValidInvite };
    delete missing[field];
    assertInviteRejectedUnchanged(t, missing, field);
  }

  assertInviteRejectedUnchanged(t, { ...rawValidInvite, invite_id: "" }, "invite_id");
  const missingId: Record<string, unknown> = { ...rawValidInvite };
  delete missingId["invite_id"];
  assertInviteRejectedUnchanged(t, missingId, "invite_id");
  assertInviteRejectedUnchanged(t, { ...rawValidInvite, invite_id: null }, "invite_id");
  assertInviteRejectedUnchanged(t, { ...rawValidInvite, invite_id: 1 }, "invite_id");

  assertInviteRejectedUnchanged(t, { ...rawValidInvite, created_by: "" }, "created_by");
  const missingCreator: Record<string, unknown> = { ...rawValidInvite };
  delete missingCreator["created_by"];
  assertInviteRejectedUnchanged(t, missingCreator, "created_by");
  assertInviteRejectedUnchanged(t, { ...rawValidInvite, created_by: null }, "created_by");
  assertInviteRejectedUnchanged(t, { ...rawValidInvite, created_by: false }, "created_by");
  assertInviteRejectedUnchanged(t, { ...rawValidInvite, created_at: 201, expires_at: 200 }, "created_at");
});

test("valid raw invites accept zero/equal and 100/200 timestamps", (t) => {
  const dir = tempDir(t);
  for (const [createdAt, expiresAt] of [[0, 0], [100, 200]] as const) {
    const rawInvite: Record<string, unknown> = { ...rawValidInvite, created_at: createdAt, expires_at: expiresAt };
    const path = writeDoc(dir, JSON.stringify({ version: 1, keys: [], invites: [rawInvite] }));
    const invite = openFileState(path).view().invites[0];
    assert.ok(invite, "invite expected");
    assert.equal(invite.inviteId, "i1");
    assert.equal(invite.createdAt, createdAt);
    assert.equal(invite.expiresAt, expiresAt);
  }
});

/** Appends a raw key_ttl_seconds JSON value to the serialized invite (valid JSON — the object brace is preserved). */
function inviteKeyTtl(invite: InviteRecord, json: string): string {
  return testDoc([], [invite]).replace(
    `"expires_at":${invite.expiresAt}}`,
    `"expires_at":${invite.expiresAt},"key_ttl_seconds":${json}}`,
  );
}

/** Checks the JSON value before requiring a named TTL rejection and untouched bytes. */
function assertTtlRejected(t: { after(fn: () => void): unknown }, json: string, expected: unknown): void {
  const dir = tempDir(t);
  const doc = inviteKeyTtl(testInvite("i1"), json);
  const parsed: unknown = JSON.parse(doc);
  assert.ok(typeof parsed === "object" && parsed !== null && !Array.isArray(parsed), "raw state document must be an object");
  assert.ok("invites" in parsed && Array.isArray(parsed.invites), "raw invites must be an array");
  assert.equal(parsed.invites.length, 1, "raw state document must contain one invite");
  const rawInvite: unknown = parsed.invites[0];
  assert.ok(typeof rawInvite === "object" && rawInvite !== null && !Array.isArray(rawInvite), "raw invite must be an object");
  assert.ok("key_ttl_seconds" in rawInvite, "raw invite must contain key_ttl_seconds");
  assert.ok(Object.hasOwn(rawInvite, "key_ttl_seconds"), "raw invite must own key_ttl_seconds");
  assert.deepEqual(rawInvite.key_ttl_seconds, expected, "the raw JSON has the intended TTL value");
  const path = writeDoc(dir, doc);
  const before = readFileSync(path);
  assert.throws(
    () => openFileState(path),
    (err: unknown) => err instanceof StateCorruptError && err.message.includes("invites[0].key_ttl_seconds"),
    "expected an error naming invites[0].key_ttl_seconds",
  );
  assert.deepEqual(readFileSync(path), before, "the failed load must not rewrite the file");
}

test("load rejects an invite key_ttl_seconds of null", (t) => {
  assertTtlRejected(t, "null", null);
});

test("load rejects an invite key_ttl_seconds of 0", (t) => {
  assertTtlRejected(t, "0", 0);
});

test("load rejects an invite key_ttl_seconds above the maximum", (t) => {
  assertTtlRejected(t, "31536001", 31536001);
});

test("the same document shape with an in-range key_ttl_seconds loads: the rejections above are the TTL guard", (t) => {
  const dir = tempDir(t);
  const got = openFileState(writeDoc(dir, inviteKeyTtl(testInvite("i1"), "3600"))).view().invites[0];
  assert.ok(got, "invite expected");
  assert.equal(got.keyTtlSeconds, 3600);
});

test("an invite key_ttl_seconds of 1 loads", (t) => {
  const dir = tempDir(t);
  const got = openFileState(writeDoc(dir, testDoc([], [{ ...testInvite("i1"), keyTtlSeconds: 1 }]))).view().invites[0];
  assert.ok(got, "invite expected");
  assert.equal(got.keyTtlSeconds, 1);
});

test("an invite key_ttl_seconds of 31536000 loads", (t) => {
  const dir = tempDir(t);
  const got = openFileState(writeDoc(dir, testDoc([], [{ ...testInvite("i1"), keyTtlSeconds: 31536000 }]))).view().invites[0];
  assert.ok(got, "invite expected");
  assert.equal(got.keyTtlSeconds, 31536000);
});

test("a default invite keeps key_ttl_seconds absent through a rewrite, never null", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const original = testDoc([], [testInvite("i1")]).replace(`"admin":false,`, "");
  const store = openFileState(writeDoc(dir, original));
  const inv = store.view().invites[0];
  assert.ok(inv, "invite expected");
  // The in-memory record has no TTL member at all — undefined, never null.
  assert.equal(inv.keyTtlSeconds, undefined);
  assert.equal("keyTtlSeconds" in inv, false);

  // A no-op update rewrites the file; the member must stay ABSENT in the text.
  store.update(() => {});
  const rewritten = readFileSync(path, "utf8");
  assert.ok(!rewritten.includes("key_ttl_seconds"), `key_ttl_seconds leaked into the rewrite: ${rewritten}`);
  // And the round trip preserves the absence.
  const reloaded = openFileState(path).view().invites[0];
  assert.ok(reloaded, "reloaded invite expected");
  assert.equal(reloaded.keyTtlSeconds, undefined);
});

// ---------------------------------------------------------------------------
// Legacy kind/scopes members are unknown fields: rejected with the member
// named, and a failed load NEVER touches the file.
// ---------------------------------------------------------------------------

/** Asserts openFileState rejects doc naming `member`, and the raw file bytes are byte-identical after the failed load. */
function assertLegacyRejected(t: { after(fn: () => void): unknown }, doc: string, member: string): void {
  const dir = tempDir(t);
  const path = writeDoc(dir, doc);
  const before = readFileSync(path, "utf8");
  assert.throws(
    () => openFileState(path),
    (err: unknown) =>
      err instanceof StateCorruptError && (err as Error).message.includes(`unknown field "${member}"`),
    `expected a rejection naming ${member}`,
  );
  assert.equal(readFileSync(path, "utf8"), before, "the failed load must not rewrite the file");
}

test("legacy entry kind is an unknown field and the file stays untouched", (t) => {
  const [entry] = fixturePair();
  const doc = testDoc([entry]).replace(`"name":"${entry.name}","admin"`, `"name":"${entry.name}","kind":"human","admin"`);
  assertLegacyRejected(t, doc, "kind");
});

test("legacy entry scopes is an unknown field and the file stays untouched", (t) => {
  const [entry] = fixturePair();
  const doc = testDoc([entry]).replace(`"name":"${entry.name}","admin"`, `"name":"${entry.name}","scopes":["read"],"admin"`);
  assertLegacyRejected(t, doc, "scopes");
});

test("legacy invite kind is an unknown field and the file stays untouched", (t) => {
  const doc = testDoc([], [testInvite("i1")]).replace(`"invite_id":"i1","admin"`, `"invite_id":"i1","kind":"human","admin"`);
  assertLegacyRejected(t, doc, "kind");
});

test("legacy invite scopes is an unknown field and the file stays untouched", (t) => {
  const doc = testDoc([], [testInvite("i1")]).replace(`"invite_id":"i1","admin"`, `"invite_id":"i1","scopes":["read"],"admin"`);
  assertLegacyRejected(t, doc, "scopes");
});

// ---------------------------------------------------------------------------
// Unchanged rejection classes.
// ---------------------------------------------------------------------------

test("load rejects the identity public key even with a matching kid", (t) => {
  const dir = tempDir(t);
  const [entry] = fixturePair();
  // The neutral point's encoding passes the kid check and must fail validatePublicKey.
  const identity = new Uint8Array(32);
  identity[0] = 1;
  assertLoadCorrupt(dir, testDoc([{ ...entry, publicKey: encodeBase64URL(identity), kid: keyId(identity) }]));
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

// ---------------------------------------------------------------------------
// The shared state-file vectors (spec/fixtures/state-file-vectors.json).
// ---------------------------------------------------------------------------

test("state-file vectors: valid documents load, invalid ones are rejected with the file untouched", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  for (const c of loadStateFileVectors().cases) {
    const text = JSON.stringify(c.document, null, 2);
    writeFileSync(path, text);
    const before = readFileSync(path, "utf8");
    if (c.expect === "valid") {
      const store = openFileState(path);
      if (c.id === "statefile-valid-default-invite") {
        // The default invite keeps keyTtlSeconds undefined, never null.
        const inv = store.view().invites[0];
        assert.ok(inv, `${c.id}: invite expected`);
        assert.equal(inv.keyTtlSeconds, undefined);
      }
    } else {
      assert.throws(
        () => openFileState(path),
        (err: unknown) => err instanceof StateCorruptError,
        `${c.id}: expected StateCorruptError`,
      );
      // Legacy cases must name the offending member; every failed load must
      // leave the raw file text byte-identical.
      if (c.id.includes("-kind-")) {
        assert.throws(
          () => openFileState(path),
          (err: unknown) => err instanceof StateCorruptError && (err as Error).message.includes("kind"),
          `${c.id}: message must name kind`,
        );
      }
      if (c.id.includes("-scopes-")) {
        assert.throws(
          () => openFileState(path),
          (err: unknown) => err instanceof StateCorruptError && (err as Error).message.includes("scopes"),
          `${c.id}: message must name scopes`,
        );
      }
      assert.equal(readFileSync(path, "utf8"), before, `${c.id}: the failed load must not touch the file`);
    }
  }
});

// ---------------------------------------------------------------------------
// File rollback behavior.
// ---------------------------------------------------------------------------

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
