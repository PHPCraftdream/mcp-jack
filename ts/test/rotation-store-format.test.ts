import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { bodyHash } from "../src/encoding.js";
import { anchorSnapshot, clockBytes, encodedSnapshot, pack, readClock, unpack } from "../src/rotation-store-format.js";
import type { RotationStoreOptions, StoreBundle } from "../src/rotation-store-format.js";
import type { RotationBinding } from "../src/rotation-record.js";
import { fixture } from "./fixtures.js";

interface Corpus { binding: RotationBinding; keys: Record<string, { kid: string; public_key: string }> }
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const anchor = corpus.keys["anchor"];
assert.ok(anchor);
const options: RotationStoreOptions = { binding: corpus.binding, window: 30,
  checkpoint: { ordinal: 0, hash: "-", kid: anchor.kid, publicKeyB64u: anchor.public_key, publishedAt: 0 } };
const initial = anchorSnapshot(options);
const profile = bodyHash(Buffer.from(encodedSnapshot(initial, options)));
const clock = { ...initial.clock, highWater: 100, revision: 1 };
const bundle: StoreBundle = { storeId: randomBytes(16).toString("base64url"), profile, owner: 1, dirty: false, fenced: false,
  clockBytes: clockBytes(clock), snapshotBytes: encodedSnapshot({ ...initial, clock }, options) };

function payload(bytes: Uint8Array): string {
  return (JSON.parse(Buffer.from(bytes).toString("utf8")) as { payload: string }).payload;
}
function seal(text: string): Uint8Array {
  return Buffer.from(JSON.stringify({ payload: text, checksum: bodyHash(Buffer.from(text, "utf8")) }));
}

test("trust store format: sealed separate records round-trip without clock authority or aliases", () => {
  const bytes = pack(bundle);
  const decoded = unpack(bytes, options, profile);
  assert.deepEqual(decoded.bundle, bundle);
  assert.deepEqual(decoded.clock, clock);
  assert.deepEqual(decoded.snapshot.clock, clock);
  assert.equal(Object.isFrozen(decoded.bundle), true);
  bytes.fill(0);
  assert.equal(decoded.bundle.clockBytes, bundle.clockBytes);
  const advanced = unpack(pack({ ...bundle, clockBytes: clockBytes({ ...clock, highWater: 101, revision: 2 }) }), options, profile);
  assert.equal(advanced.snapshot.clock.highWater, 100);
  assert.equal(advanced.clock.highWater, 101);
  assert.equal(advanced.bundle.snapshotBytes, bundle.snapshotBytes);
});

test("trust store format: checksum, exact domains/schema/numbers and independent OOB refusal", () => {
  const bytes = pack(bundle);
  const original = payload(bytes);
  const value = JSON.parse(original) as Record<string, unknown>;
  const mutations: Record<string, unknown>[] = [
    { ...value, domain: "mcp-jack/server-ring/v1" }, { ...value, format_version: 2 },
    { ...value, store_id: Buffer.alloc(16).toString("base64url") }, { ...value, store_id: bundle.storeId + "=" },
    { ...value, profile: "other" }, { ...value, owner: 0 }, { ...value, owner: null },
    { ...value, owner: Number.MAX_SAFE_INTEGER + 1 }, { ...value, dirty: null }, { ...value, fenced: 0 },
    { ...value, clock: {} }, { ...value, snapshot: null }, { ...value, extra: true },
  ];
  for (const changed of mutations) assert.throws(() => unpack(seal(JSON.stringify(changed)), options, profile));
  for (const name of Object.keys(value)) {
    const missing = { ...value };
    delete missing[name];
    assert.throws(() => unpack(seal(JSON.stringify(missing)), options, profile));
  }
  for (const owner of ["-0", "1.0", "1e0", "-1"]) {
    assert.throws(() => unpack(seal(original.replace('"owner":1', `"owner":${owner}`)), options, profile));
  }
  assert.throws(() => unpack(seal(original.replace('"owner":1', '"owner":1,"owner":1')), options, profile));
  const escaped = '"' + String.fromCharCode(92) + 'u006fwner":1';
  assert.throws(() => unpack(seal(original.replace('"owner":1', '"owner":1,' + escaped)), options, profile));
  assert.throws(() => unpack(Buffer.from(JSON.stringify({ payload: original + " ", checksum: bodyHash(Buffer.from(original)) })), options, profile));
  assert.throws(() => unpack(Buffer.from(JSON.stringify({ payload: original, checksum: bodyHash(Buffer.from(original)), extra: true })), options, profile));
  assert.throws(() => unpack(bytes, options, "other"));
  assert.throws(() => unpack(bytes, { ...options, window: 31 }, profile));
  assert.throws(() => unpack(bytes, { ...options, binding: { ...options.binding, aud: "other" } }, profile));
  assert.throws(() => unpack(bytes, { ...options, checkpoint: { ...options.checkpoint, kid: "other" } }, profile));
});

test("trust store format: copied tuple cannot outrun independent guard; raw clock schema is strict", () => {
  for (const guard of [{ ...clock, highWater: 99 }, { ...clock, revision: 0 }]) {
    assert.throws(() => unpack(pack({ ...bundle, clockBytes: clockBytes(guard) }), options, profile));
  }
  const serialized = bundle.clockBytes;
  for (const name of ["high_water", "clock_revision"]) {
    const parsed = JSON.parse(serialized) as Record<string, unknown>;
    for (const invalid of [-1, null, "1", Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => readClock(JSON.stringify({ ...parsed, [name]: invalid }), options));
    }
    const original = name === "high_water" ? 100 : 1;
    for (const invalid of ["-0", `${original}.0`, `${original}e0`]) {
      assert.throws(() => readClock(serialized.replace(`"${name}":${original}`, `"${name}":${invalid}`), options));
    }
  }
  assert.throws(() => readClock(serialized.replace('"unsafe":false', '"unsafe":null'), options));
  assert.throws(() => readClock(serialized.replace('"window":30', '"window":31'), options));
  assert.throws(() => readClock(serialized.replace('"unsafe":false', '"unsafe":false,"extra":0'), options));
});
