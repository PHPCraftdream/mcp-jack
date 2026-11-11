import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { client, encodeBase64URL, keyId, rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

type Mutable<T> = T extends readonly (infer Value)[] ? Mutable<Value>[] : T extends object ? { -readonly [Key in keyof T]: Mutable<T[Key]> } : T;
interface Corpus {
  binding: rotation.RotationBinding;
  keys: Record<string, { kid: string; public_key: string }>;
  valid_chains: Record<string, string[]>;
}
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const anchor = corpus.keys["anchor"];
assert.ok(anchor);
const checkpoint: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: anchor.kid, publicKeyB64u: anchor.public_key, publishedAt: 0 };

function snapshotFrom(records: readonly rotation.RotationRecord[], binding = corpus.binding, root = checkpoint): Mutable<rotation.RotationTrustSnapshot> {
  const keys: Mutable<rotation.RotationTrustKey>[] = [{ ordinal: root.ordinal, kid: root.kid, publicKeyB64u: root.publicKeyB64u,
    notBefore: root.ordinal === 0 ? 0 : root.publishedAt + rotation.ROTATION_GRACE_SECONDS, knownCutoff: null }];
  let head: rotation.RotationCursor = { ordinal: root.ordinal, hash: root.hash };
  let highWater = root.publishedAt;
  for (const record of records) {
    const previous = keys[keys.length - 1];
    assert.ok(previous);
    previous.knownCutoff = record.activatesAt;
    keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null });
    head = { ordinal: record.ordinal, hash: record.hash };
    highWater = record.publishedAt;
  }
  return { formatVersion: 1, binding: { ...binding }, window: 30, checkpoint: { ...root }, head: { ...head },
    records: records.map((record) => record.wire), keys, revision: 7, fenced: false,
    clock: { binding: { ...binding }, window: 30, highWater, revision: 1, unsafe: false } };
}

function example(): Mutable<rotation.RotationTrustSnapshot> {
  const wires = corpus.valid_chains["overlapping"];
  assert.ok(wires);
  return snapshotFrom(rotation.verifyRotationChain(wires.map((wire) => Buffer.from(wire, "utf8")), corpus.binding, checkpoint));
}

function validate(input: rotation.RotationTrustSnapshot): rotation.RotationTrustSnapshot {
  return rotation.validateRotationTrustSnapshot(input, corpus.binding, 30, checkpoint);
}

function refusal(error: unknown): boolean {
  return error instanceof rotation.RotationError && error.code === "rotation_state_unknown";
}

test("whole trust owns frozen chain/key/checkpoint/clock values without ACK", () => {
  const input = example();
  const output = validate(input);
  const first = output.records[0];
  assert.deepEqual(output, input);
  for (const value of [output, output.binding, output.checkpoint, output.head, output.records, output.keys,
    ...output.keys, output.clock, output.clock.binding]) assert.ok(Object.isFrozen(value));
  input.binding.aud = "changed";
  input.checkpoint.kid = "changed";
  input.head.hash = "changed";
  input.records[0] = "changed";
  const key = input.keys[0];
  assert.ok(key);
  key.knownCutoff = 0;
  input.clock.binding.aud = "changed";
  assert.equal(output.records[0], first);
  assert.equal(output.binding.aud, corpus.binding.aud);
  assert.equal(output.clock.binding.aud, corpus.binding.aud);
  assert.equal(output.checkpoint.kid, checkpoint.kid);
  assert.notEqual(output.keys[0]?.knownCutoff, 0);
});

test("whole trust rejects redundant/identity/time domains and sanitizes throwing input", () => {
  const mutations: ((value: Mutable<rotation.RotationTrustSnapshot>) => void)[] = [
    (v) => { v.formatVersion = 2; }, (v) => { v.binding.aud = "other"; }, (v) => { v.window = 31; },
    (v) => { v.checkpoint.publishedAt = 1; }, (v) => { v.head.ordinal--; }, (v) => { v.head.hash = "wrong"; },
    (v) => { v.records[0] = "invalid wire"; }, (v) => { v.keys.pop(); },
    (v) => { const key = v.keys[0]; assert.ok(key); key.ordinal++; },
    (v) => { const key = v.keys[0]; assert.ok(key); key.kid = "wrong"; },
    (v) => { const key = v.keys[0]; assert.ok(key); key.publicKeyB64u = "wrong"; },
    (v) => { const key = v.keys[0]; assert.ok(key); key.notBefore++; },
    (v) => { const key = v.keys[0]; assert.ok(key); key.knownCutoff = 1; },
    (v) => { v.revision = 0; }, (v) => { v.revision = Number.MAX_SAFE_INTEGER + 1; },
    (v) => { v.fenced = "false" as unknown as boolean; }, (v) => { v.clock.binding.aud = "other"; },
    (v) => { v.clock.window = 31; }, (v) => { v.clock.highWater = -1; }, (v) => { v.clock.highWater = NaN; },
    (v) => { v.clock.highWater = rotation.ROTATION_MAX_TIMESTAMP + 1; }, (v) => { v.clock.revision = -1; },
    (v) => { v.clock.unsafe = undefined as unknown as boolean; },
  ];
  for (const mutate of mutations) {
    const input = example();
    mutate(input);
    assert.throws(() => validate(input), refusal);
  }
  const throwing = example();
  Object.defineProperty(throwing, "clock", { get() { throw new Error("private provider detail"); } });
  assert.throws(() => validate(throwing), (error) => refusal(error) && !String(error).includes("private provider detail"));
  assert.throws(() => rotation.validateRotationTrustSnapshot(example(), corpus.binding, 31, checkpoint), refusal);
  assert.throws(() => rotation.validateRotationTrustSnapshot(example(), corpus.binding, 30, { ...checkpoint, hash: "wrong" }), refusal);
});

test("inspection fences preserved; copied clock compatibility is not readiness", () => {
  const input = example();
  const valid = validate(input);
  assert.ok(rotation.rotationTrustClockCompatible(valid, valid.clock));
  assert.ok(rotation.rotationTrustClockCompatible(valid, { ...valid.clock, highWater: valid.clock.highWater + 1, revision: valid.clock.revision + 1 }));
  for (const clock of [{ ...valid.clock, highWater: valid.clock.highWater - 1 }, { ...valid.clock, revision: 0 },
    { ...valid.clock, unsafe: true }, { ...valid.clock, window: 31 }, { ...valid.clock, binding: { ...valid.binding, aud: "other" } }]) {
    assert.equal(rotation.rotationTrustClockCompatible(valid, clock), false);
  }
  input.fenced = true;
  input.clock.unsafe = true;
  const fenced = validate(input);
  assert.equal(fenced.fenced, true);
  assert.equal(fenced.clock.unsafe, true);
  assert.equal(rotation.rotationTrustClockCompatible(fenced, fenced.clock), false);
});

test("whole trust pending128 boundary uses actual signed equal-time chain", () => {
  const signer = (index: number): client.InMemorySigner => new client.InMemorySigner(createHash("sha256").update(`public trust capacity fixture ${index}`).digest());
  let old = signer(0);
  const root: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: keyId(old.publicKey()), publicKeyB64u: encodeBase64URL(old.publicKey()), publishedAt: 0 };
  let tail = root;
  const records: rotation.RotationRecord[] = [];
  for (let index = 1; index <= 129; index++) {
    const next = signer(index);
    const record = rotation.createRotationRecord(corpus.binding, tail, old, next, 1000);
    records.push(record);
    tail = { ordinal: record.ordinal, hash: record.hash, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, publishedAt: record.publishedAt };
    old = next;
  }
  const accepted = snapshotFrom(records.slice(0, 128), corpus.binding, root);
  assert.equal(rotation.validateRotationTrustSnapshot(accepted, corpus.binding, 30, root).keys.length, 129);
  assert.throws(() => rotation.validateRotationTrustSnapshot(snapshotFrom(records, corpus.binding, root), corpus.binding, 30, root), refusal);
  const oversized = example();
  oversized.records = Array<string>(rotation.ROTATION_MAX_RETAINED_KEYS).fill("not parsed");
  assert.throws(() => validate(oversized), refusal);
});

test("local trust JSON codec roundtrips owned state and does not repair inspection fences", () => {
  const input = example();
  input.fenced = true;
  input.clock.unsafe = true;
  const encoded = rotation.encodeRotationTrustSnapshot(input, corpus.binding, 30, checkpoint);
  const decoded = rotation.decodeRotationTrustSnapshot(encoded, corpus.binding, 30, checkpoint);
  assert.deepEqual(decoded, input);
  assert.equal(decoded.keys[decoded.keys.length - 1]?.knownCutoff, null);
  assert.equal(rotation.rotationTrustClockCompatible(decoded, decoded.clock), false);
  assert.deepEqual(rotation.encodeRotationTrustSnapshot(decoded, corpus.binding, 30, checkpoint), encoded);
  const model = JSON.parse(Buffer.from(encoded).toString("utf8")) as Record<string, unknown>;
  const reordered = Object.fromEntries(Object.entries(model).reverse());
  assert.deepEqual(rotation.decodeRotationTrustSnapshot(Buffer.from(JSON.stringify(reordered)), corpus.binding, 30, checkpoint), decoded);
  const first = decoded.records[0];
  encoded.fill(0);
  input.records[0] = "changed";
  assert.equal(decoded.records[0], first);
});

test("local trust JSON rejects duplicate/extra/missing/null/noncanonical numeric evidence", () => {
  const text = Buffer.from(rotation.encodeRotationTrustSnapshot(example(), corpus.binding, 30, checkpoint)).toString("utf8");
  const escapedVersion = '"' + String.fromCharCode(92) + 'u0066ormat_version"';
  const changes: readonly [string, string][] = [
    ['"format_version":1', '"format_version":1,"format_version":1'],
    ['"format_version":1', `"format_version":1,${escapedVersion}:1`],
    ['"format_version":1', '"format_version":1,"signer_refs":[]'],
    ['"format_version":1', '"format_version":1e0'],
    ['"window":30', '"window":30.0'],
    ['"clock_revision":1', '"clock_revision":1e0'],
    ['"trust_revision":7', '"trust_revision":9007199254740992'],
    ['"published_at":0', '"published_at":-0'],
    ['"fenced":false', '"fenced":null'],
    ['"unsafe":false', '"unsafe":"false"'],
    [',"known_cutoff":null', ''],
    [JSON.stringify(corpus.binding.endpoint), '"' + String.fromCharCode(92) + 'ud800"'],
  ];
  for (const [from, to] of changes) {
    const changed = text.replace(from, to);
    assert.notEqual(changed, text, from);
    assert.throws(() => rotation.decodeRotationTrustSnapshot(Buffer.from(changed), corpus.binding, 30, checkpoint), refusal);
  }
  const model = JSON.parse(text) as Record<string, unknown>;
  for (const name of ["records", "keys", "head", "binding", "checkpoint", "clock"]) {
    assert.throws(() => rotation.decodeRotationTrustSnapshot(Buffer.from(JSON.stringify({ ...model, [name]: null })), corpus.binding, 30, checkpoint), refusal);
  }
  assert.throws(() => rotation.decodeRotationTrustSnapshot(Buffer.from(text + " {}"), corpus.binding, 30, checkpoint), refusal);
  assert.throws(() => rotation.decodeRotationTrustSnapshot(Uint8Array.of(0xff), corpus.binding, 30, checkpoint), refusal);
  assert.throws(() => rotation.decodeRotationTrustSnapshot(Buffer.from(text), { ...corpus.binding, aud: "other" }, 30, checkpoint), refusal);
});

test("local trust snapshot byte bound is inclusive and distinct from HTTP refresh cap", () => {
  const encoded = rotation.encodeRotationTrustSnapshot(example(), corpus.binding, 30, checkpoint);
  const padded = Buffer.alloc(rotation.ROTATION_MAX_TRUST_SNAPSHOT_BYTES, 32);
  padded.set(encoded);
  assert.equal(rotation.decodeRotationTrustSnapshot(padded, corpus.binding, 30, checkpoint).revision, 7);
  assert.throws(() => rotation.decodeRotationTrustSnapshot(Buffer.alloc(rotation.ROTATION_MAX_TRUST_SNAPSHOT_BYTES + 1, 32), corpus.binding, 30, checkpoint), refusal);
  assert.throws(() => rotation.encodeRotationTrustSnapshot({ ...example(), revision: 0 }, corpus.binding, 30, checkpoint), refusal);
});
