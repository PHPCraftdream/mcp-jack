import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { client, encodeBase64URL, keyId, rotation } from "../src/index.js";
import { corpus, denies, overlapping, root, serverFrom, trustFrom, validateServer, WINDOW } from "./rotation-server-fixtures.js";
import type { Mutable } from "./rotation-server-fixtures.js";

// Deterministic PRNG: a fixed seed reproduces every refusal.
const SEED = 0x5eed00a3;

class SplitMix32 {
  private state: number;
  constructor(seed: number) { this.state = seed >>> 0; }
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let value = this.state;
    value = Math.imul(value ^ (value >>> 16), 0x21f0aaad) >>> 0;
    value = Math.imul(value ^ (value >>> 15), 0x735a2d97) >>> 0;
    return (value ^ (value >>> 15)) >>> 0;
  }
  below(limit: number): number { return this.next() % limit; }
}

function signer(index: number): client.InMemorySigner {
  return new client.InMemorySigner(createHash("sha256").update(`rotation-property:${index}`).digest());
}

// Mirrors fixtures.signedChain but with parameterized publication times.
function generatedChain(count: number, publishedAt: (index: number) => number): { readonly base: rotation.RotationCheckpoint; readonly records: rotation.RotationRecord[] } {
  let old = signer(0);
  const base: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: keyId(old.publicKey()), publicKeyB64u: encodeBase64URL(old.publicKey()), publishedAt: 0 };
  let tail = base;
  const records: rotation.RotationRecord[] = [];
  for (let index = 1; index <= count; index++) {
    const next = signer(index);
    const record = rotation.createRotationRecord(corpus.binding, tail, old, next, publishedAt(index));
    records.push(record);
    tail = { ordinal: record.ordinal, hash: record.hash, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, publishedAt: record.publishedAt };
    old = next;
  }
  return { base, records };
}

function prng32(random: SplitMix32): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index++) bytes[index] = random.next() & 0xff;
  return bytes;
}

function flipFirstChar(text: string): string {
  const flipped = (text[0] === "A" ? "B" : "A") + text.slice(1);
  assert.notEqual(flipped, text, "flip must change the character");
  return flipped;
}

const unavailable = denies("rotation_state_unavailable");
const checkpointUnavailable = denies("rotation_checkpoint_unavailable");

function encode(input: rotation.RotationServerSnapshot, base: rotation.RotationCheckpoint): Uint8Array {
  return rotation.encodeRotationServerSnapshot(input, corpus.binding, WINDOW, base);
}

function decode(bytes: Uint8Array, base: rotation.RotationCheckpoint): rotation.RotationServerSnapshot {
  return rotation.decodeRotationServerSnapshot(bytes, corpus.binding, WINDOW, base);
}

function opaqueReference(random: SplitMix32, label: string): string {
  const target = 1 + random.below(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES);
  let text = "";
  while (Buffer.byteLength(text, "utf8") < target) {
    const candidate = random.below(8) === 0 ? "é" : String.fromCharCode(97 + random.below(26));
    if (Buffer.byteLength(text + candidate, "utf8") <= rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES) text += candidate;
  }
  assert.ok(text.length > 0, `seed=${SEED} reference=${label} subject=empty`);
  assert.ok(Buffer.byteLength(text, "utf8") <= rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES, `seed=${SEED} reference=${label} subject=over-limit`);
  return text;
}

/** FREE fields (fenced/revision/clock.highWater/clock.revision/clock.unsafe/references[*].reference) are deliberately skipped. */
function assertSameMustFields(actual: rotation.RotationServerSnapshot, expected: rotation.RotationServerSnapshot, label: string): void {
  const left = actual.trust;
  const right = expected.trust;
  assert.equal(left.binding.endpoint, right.binding.endpoint, `${label} field=trust.binding.endpoint`);
  assert.equal(left.binding.aud, right.binding.aud, `${label} field=trust.binding.aud`);
  assert.equal(left.window, right.window, `${label} field=trust.window`);
  assert.equal(left.checkpoint.ordinal, right.checkpoint.ordinal, `${label} field=trust.checkpoint.ordinal`);
  assert.equal(left.checkpoint.hash, right.checkpoint.hash, `${label} field=trust.checkpoint.hash`);
  assert.equal(left.checkpoint.kid, right.checkpoint.kid, `${label} field=trust.checkpoint.kid`);
  assert.equal(left.checkpoint.publicKeyB64u, right.checkpoint.publicKeyB64u, `${label} field=trust.checkpoint.publicKeyB64u`);
  assert.equal(left.checkpoint.publishedAt, right.checkpoint.publishedAt, `${label} field=trust.checkpoint.publishedAt`);
  assert.equal(left.head.ordinal, right.head.ordinal, `${label} field=trust.head.ordinal`);
  assert.equal(left.head.hash, right.head.hash, `${label} field=trust.head.hash`);
  assert.deepEqual(left.records, right.records, `${label} field=trust.records`);
  assert.equal(left.keys.length, right.keys.length, `${label} field=trust.keys.length`);
  for (const [index, key] of left.keys.entries()) {
    const other = right.keys[index];
    assert.ok(other, `${label} field=trust.keys[${index}] missing`);
    assert.equal(key.ordinal, other.ordinal, `${label} field=trust.keys[${index}].ordinal`);
    assert.equal(key.kid, other.kid, `${label} field=trust.keys[${index}].kid`);
    assert.equal(key.publicKeyB64u, other.publicKeyB64u, `${label} field=trust.keys[${index}].publicKeyB64u`);
    assert.equal(key.notBefore, other.notBefore, `${label} field=trust.keys[${index}].notBefore`);
    assert.equal(key.knownCutoff, other.knownCutoff, `${label} field=trust.keys[${index}].knownCutoff`);
  }
  assert.deepEqual(left.clock.binding, right.clock.binding, `${label} field=trust.clock.binding`);
  assert.equal(left.clock.window, right.clock.window, `${label} field=trust.clock.window`);
  assert.equal(actual.signerReferences.length, expected.signerReferences.length, `${label} field=signerReferences.length`);
  for (const [index, entry] of actual.signerReferences.entries()) {
    const other = expected.signerReferences[index];
    assert.ok(other, `${label} field=signerReferences[${index}] missing`);
    assert.equal(entry.kid, other.kid, `${label} field=signerReferences[${index}].kid`);
  }
}

test("generated server snapshots round-trip and freeze", () => {
  const random = new SplitMix32(SEED);
  for (const length of [0, 1, 2, 4]) {
    const chain = generatedChain(length, (index) => 1000 + index);
    const input = serverFrom(trustFrom(chain.records, chain.base));
    for (const [index, entry] of input.signerReferences.entries()) {
      entry.reference = opaqueReference(random, `chain=${length} reference=${index}`);
    }
    const validated = validateServer(input, chain.base);
    const encoded = encode(input, chain.base);
    const decoded = decode(encoded, chain.base);
    assert.deepEqual(decoded, validated, `seed=${SEED} chain=${length} subject=round-trip`);
    assert.deepEqual(encode(decoded, chain.base), encoded, `seed=${SEED} chain=${length} subject=canonical-reencode`);
    for (const value of [decoded, decoded.trust, decoded.signerReferences]) assert.ok(Object.isFrozen(value), `seed=${SEED} chain=${length} subject=frozen`);
  }
  const boundaryChain = generatedChain(1, (index) => 1000 + index);
  const boundary = serverFrom(trustFrom(boundaryChain.records, boundaryChain.base));
  const reference = boundary.signerReferences[0];
  assert.ok(reference, `seed=${SEED} chain=1 reference=0 subject=boundary-reference`);
  reference.reference = "a".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES);
  validateServer(boundary, boundaryChain.base);
  reference.reference = "a".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES + 1);
  assert.throws(() => validateServer(boundary, boundaryChain.base), unavailable, `seed=${SEED} chain=1 reference=0 subject=validate-over-limit`);
  assert.throws(() => encode(boundary, boundaryChain.base), unavailable, `seed=${SEED} chain=1 reference=0 subject=encode-over-limit`);
  const surrogate = serverFrom(trustFrom(boundaryChain.records, boundaryChain.base));
  const lone = surrogate.signerReferences[0];
  assert.ok(lone, `seed=${SEED} chain=1 reference=0 subject=surrogate-reference`);
  lone.reference = "\ud800";
  assert.throws(() => encode(surrogate, boundaryChain.base), unavailable, `seed=${SEED} chain=1 reference=0 subject=lone-surrogate`);
});

test("every single-byte mutation of a stored server snapshot is refused or confined to free fields", () => {
  const anchorInput = serverFrom(trustFrom([], root));
  const anchorEncoded = encode(anchorInput, root);
  const anchorBaseline = decode(anchorEncoded, root);
  assert.deepEqual(anchorBaseline, validateServer(anchorInput, root), `seed=${SEED} doc=anchor subject=baseline`);
  for (const [index, initial] of Array.from(anchorEncoded).entries()) {
    const mutated = Buffer.from(anchorEncoded);
    mutated[index] = initial ^ 1;
    let decoded: rotation.RotationServerSnapshot | undefined;
    let failure: unknown;
    try { decoded = decode(mutated, root); } catch (error) { failure = error; }
    if (decoded === undefined) {
      assert.ok(failure instanceof rotation.RotationError, `seed=${SEED} doc=anchor byte=${index} subject=rotation-error`);
    } else {
      assertSameMustFields(decoded, anchorBaseline, `seed=${SEED} doc=anchor byte=${index}`);
    }
  }
  const docChain = generatedChain(2, (index) => 1000 + index);
  const docInput = serverFrom(trustFrom(docChain.records, docChain.base));
  const docEncoded = encode(docInput, docChain.base);
  const docBaseline = decode(docEncoded, docChain.base);
  const sampleRandom = new SplitMix32(SEED);
  const samples: number[] = [];
  for (let sample = 0; sample < 128; sample += 1) samples.push(sampleRandom.below(docEncoded.length));
  for (const index of samples) {
    const mutated = Buffer.from(docEncoded);
    const initial = mutated[index];
    assert.ok(initial !== undefined, `seed=${SEED} doc=records byte=${index}`);
    mutated[index] = initial ^ 1;
    let decoded: rotation.RotationServerSnapshot | undefined;
    let failure: unknown;
    try { decoded = decode(mutated, docChain.base); } catch (error) { failure = error; }
    if (decoded === undefined) {
      assert.ok(failure instanceof rotation.RotationError, `seed=${SEED} doc=records byte=${index} subject=rotation-error sampled=${samples.join(",")}`);
    } else {
      assertSameMustFields(decoded, docBaseline, `seed=${SEED} doc=records byte=${index} sampled=${samples.join(",")}`);
    }
  }
  assert.deepEqual(decode(anchorEncoded, root), validateServer(anchorInput, root), `seed=${SEED} subject=positive-control`);
});

test("publication accepts exactly one fixed-P record and refuses every single-field violation", () => {
  const generated = generatedChain(4, (index) => 1000 + index);
  const generatedExtra = generated.records[2];
  const otherRecord = generatedChain(2, (index) => 5000 + index * 7).records[0];
  assert.ok(generatedExtra && otherRecord, `seed=${SEED} subject=extra-records`);
  const shapes: { readonly label: string; readonly records: readonly rotation.RotationRecord[]; readonly base: rotation.RotationCheckpoint; readonly extra: string }[] = [
    { label: "fixture", records: overlapping(), base: root, extra: otherRecord.wire },
    { label: "generated", records: generated.records, base: generated.base, extra: generatedExtra.wire },
  ];
  const state = (shape: { readonly records: readonly rotation.RotationRecord[]; readonly base: rotation.RotationCheckpoint }, count: number): Mutable<rotation.RotationServerSnapshot> =>
    serverFrom(trustFrom(shape.records.slice(0, count), shape.base));
  const publish = (shape: { readonly base: rotation.RotationCheckpoint }, from: rotation.RotationServerSnapshot, to: rotation.RotationServerSnapshot): rotation.RotationServerSnapshot =>
    rotation.validateRotationServerPublication(from, to, corpus.binding, WINDOW, shape.base);
  for (const shape of shapes) {
    const length = shape.records.length;
    for (let n = 0; n + 1 <= length; n += 1) {
      const next = state(shape, n + 1);
      assert.deepEqual(publish(shape, state(shape, n), next), validateServer(next, shape.base), `seed=${SEED} shape=${shape.label} step=${n} subject=accepted`);
    }
    assert.throws(() => publish(shape, state(shape, 0), state(shape, 2)), unavailable, `seed=${SEED} shape=${shape.label} subject=batched`);
    assert.throws(() => publish(shape, state(shape, 1), state(shape, 1)), unavailable, `seed=${SEED} shape=${shape.label} subject=self-publication`);
    const pair = (fromCount: number, toCount: number): [Mutable<rotation.RotationServerSnapshot>, Mutable<rotation.RotationServerSnapshot>] =>
      [state(shape, fromCount), state(shape, toCount)];
    const cases: { label: string; accepted?: boolean; build: () => [Mutable<rotation.RotationServerSnapshot>, Mutable<rotation.RotationServerSnapshot>] }[] = [
      { label: "revision+1", build: () => { const [from, to] = pair(0, 1); to.trust.revision += 1; return [from, to]; } },
      { label: "revision 0", build: () => { const [from, to] = pair(0, 1); to.trust.revision = 0; return [from, to]; } },
      { label: "clock.highWater+1", build: () => { const [from, to] = pair(0, 1); to.trust.clock.highWater += 1; return [from, to]; } },
      { label: "clock.highWater-1", build: () => { const [from, to] = pair(0, 1); to.trust.clock.highWater -= 1; return [from, to]; } },
      { label: "clock.revision+1 (caller-authoritative)", accepted: true, build: () => { const [from, to] = pair(0, 1); to.trust.clock.revision += 1; return [from, to]; } },
      { label: "clock.revision 0", build: () => { const [from, to] = pair(0, 1); to.trust.clock.revision = 0; return [from, to]; } },
      { label: "clock.unsafe", build: () => { const [from, to] = pair(0, 1); to.trust.clock.unsafe = true; return [from, to]; } },
      { label: "fenced desired", build: () => { const [from, to] = pair(0, 1); to.trust.fenced = true; return [from, to]; } },
      { label: "fenced base", build: () => { const [from, to] = pair(0, 1); from.trust.fenced = true; return [from, to]; } },
      { label: "records pop", build: () => { const [from, to] = pair(0, 1); to.trust.records.pop(); return [from, to]; } },
      { label: "records duplicate last", build: () => { const [from, to] = pair(0, 1); const last = to.trust.records.at(-1); assert.ok(last, "records empty"); to.trust.records.push(last); return [from, to]; } },
      {
        label: "records swap last two",
        build: () => {
          const [from, to] = pair(1, 2);
          const last = to.trust.records.at(-1);
          const previous = to.trust.records.at(-2);
          assert.ok(last && previous, "records too short");
          to.trust.records[to.trust.records.length - 1] = previous;
          to.trust.records[to.trust.records.length - 2] = last;
          return [from, to];
        },
      },
      {
        label: "records replace last",
        build: () => {
          const [from, to] = pair(0, 1);
          const last = to.trust.records.at(-1);
          assert.ok(last, "records empty");
          assert.notEqual(last, shape.extra, `seed=${SEED} shape=${shape.label} subject=replacement-collision`);
          to.trust.records[to.trust.records.length - 1] = shape.extra;
          return [from, to];
        },
      },
      { label: "records push extra", build: () => { const [from, to] = pair(0, 1); to.trust.records.push(shape.extra); return [from, to]; } },
      { label: "keys pop", build: () => { const [from, to] = pair(0, 1); to.trust.keys.pop(); return [from, to]; } },
      {
        label: "keys swap last two",
        build: () => {
          const [from, to] = pair(0, 1);
          const last = to.trust.keys.at(-1);
          const previous = to.trust.keys.at(-2);
          assert.ok(last && previous, "keys too short");
          to.trust.keys[to.trust.keys.length - 1] = previous;
          to.trust.keys[to.trust.keys.length - 2] = last;
          return [from, to];
        },
      },
      { label: "keys notBefore+1", build: () => { const [from, to] = pair(0, 1); const last = to.trust.keys.at(-1); assert.ok(last, "keys empty"); last.notBefore += 1; return [from, to]; } },
      { label: "keys notBefore-1", build: () => { const [from, to] = pair(0, 1); const last = to.trust.keys.at(-1); assert.ok(last, "keys empty"); last.notBefore -= 1; return [from, to]; } },
      { label: "head ordinal+1", build: () => { const [from, to] = pair(0, 1); to.trust.head.ordinal += 1; return [from, to]; } },
      { label: "head hash changed", build: () => { const [from, to] = pair(0, 1); to.trust.head.hash = flipFirstChar(to.trust.head.hash); return [from, to]; } },
      { label: "references pop", build: () => { const [from, to] = pair(0, 1); to.signerReferences.pop(); return [from, to]; } },
      {
        label: "references swap",
        build: () => {
          const [from, to] = pair(0, 1);
          const last = to.signerReferences.at(-1);
          const previous = to.signerReferences.at(-2);
          assert.ok(last && previous, "references too short");
          to.signerReferences[to.signerReferences.length - 1] = previous;
          to.signerReferences[to.signerReferences.length - 2] = last;
          return [from, to];
        },
      },
      // Retained reference text is pinned; the reference of the NEW key is free (control, accepted).
      { label: "references replaced text", build: () => { const [from, to] = pair(0, 1); const anchor = to.signerReferences[0]; assert.ok(anchor, "references empty"); anchor.reference = "replacement"; return [from, to]; } },
      { label: "new key reference text is free", accepted: true, build: () => { const [from, to] = pair(0, 1); const last = to.signerReferences.at(-1); assert.ok(last, "references empty"); last.reference = "replacement"; return [from, to]; } },
      {
        label: "references replaced kid",
        build: () => {
          const [from, to] = pair(0, 1);
          const last = to.signerReferences.at(-1);
          const anchor = to.signerReferences[0];
          assert.ok(last && anchor, "references missing");
          last.kid = anchor.kid;
          return [from, to];
        },
      },
      {
        label: "references push extra",
        build: () => {
          const [from, to] = pair(0, 1);
          const anchor = to.signerReferences[0];
          assert.ok(anchor, "references missing");
          to.signerReferences.push({ kid: anchor.kid, reference: anchor.reference });
          return [from, to];
        },
      },
      { label: "revision only bump", build: () => { const [from, to] = pair(0, 0); to.trust.revision += 1; return [from, to]; } },
    ];
    for (const { label, accepted, build } of cases) {
      const [from, to] = build();
      if (accepted === true) {
        assert.deepEqual(publish(shape, from, to), validateServer(to, shape.base), `seed=${SEED} shape=${shape.label} mutation=${label} subject=accepted`);
      } else {
        assert.throws(() => publish(shape, from, to), unavailable, `seed=${SEED} shape=${shape.label} mutation=${label}`);
      }
    }
  }
});

test("server-key pages serve generated rings exactly and refuse wrong cursors or outside signers", () => {
  const ring = generatedChain(20, (index) => 1000 + index);
  const snapshot = validateServer(serverFrom(trustFrom(ring.records, ring.base)), ring.base);
  const signerKey = snapshot.trust.keys[0];
  const lastRecord = ring.records[19];
  assert.ok(signerKey && lastRecord, `seed=${SEED} subject=ring-keys`);
  for (let k = 0; k <= 20; k += 1) {
    const previous = k === 0 ? undefined : ring.records[k - 1];
    const cursor: rotation.RotationCursor = { ordinal: k, hash: previous === undefined ? "-" : previous.hash };
    const page = rotation.rotationServerKeyPage(snapshot, cursor, signerKey.publicKeyB64u);
    const end = Math.min(k + rotation.ROTATION_MAX_PAGE_RECORDS, 20);
    const expected = ring.records.slice(k, end).map((record) => record.wire);
    assert.deepEqual(page.records, expected, `seed=${SEED} k=${k} subject=records`);
    assert.equal(page.complete, k + rotation.ROTATION_MAX_PAGE_RECORDS >= 20, `seed=${SEED} k=${k} subject=complete`);
    assert.deepEqual(page.head, { ordinal: 20, hash: lastRecord.hash }, `seed=${SEED} k=${k} subject=head`);
    assert.deepEqual(page.current, { kid: signerKey.kid, public_key: signerKey.publicKeyB64u }, `seed=${SEED} k=${k} subject=current`);
    for (const value of [page, page.records, page.head]) assert.ok(Object.isFrozen(value), `seed=${SEED} k=${k} subject=frozen`);
  }
  for (let k = 1; k <= 20; k += 1) {
    const poisoned = ring.records[(k + 3) % 20];
    const previous = ring.records[k - 1];
    assert.ok(poisoned && previous, `seed=${SEED} k=${k} subject=cursor-records`);
    assert.notEqual(poisoned.hash, previous.hash, `seed=${SEED} k=${k} subject=hash-collision`);
    assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: k, hash: poisoned.hash }, signerKey.publicKeyB64u), checkpointUnavailable,
      `seed=${SEED} k=${k} subject=wrong-hash`);
  }
  assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: 21, hash: lastRecord.hash }, signerKey.publicKeyB64u), checkpointUnavailable,
    `seed=${SEED} k=21 subject=cursor-beyond-head`);
  const strangerKey = encodeBase64URL(prng32(new SplitMix32(SEED)));
  assert.notEqual(strangerKey, signerKey.publicKeyB64u, `seed=${SEED} subject=stranger-collision`);
  assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: 0, hash: "-" }, strangerKey), unavailable, `seed=${SEED} subject=outside-signer`);
  const short = validateServer(serverFrom(trustFrom(ring.records.slice(0, 17), ring.base)), ring.base);
  const seventeenth = ring.records[16];
  const firstRecord = ring.records[0];
  assert.ok(seventeenth && firstRecord, `seed=${SEED} subject=short-ring`);
  const first = rotation.rotationServerKeyPage(short, { ordinal: 0, hash: "-" }, signerKey.publicKeyB64u);
  assert.equal(first.records.length, 16, `seed=${SEED} subject=short-ring-first-page`);
  assert.equal(first.complete, false, `seed=${SEED} subject=short-ring-first-incomplete`);
  const rest = rotation.rotationServerKeyPage(short, { ordinal: 1, hash: firstRecord.hash }, signerKey.publicKeyB64u);
  assert.equal(rest.records.length, 16, `seed=${SEED} subject=short-ring-rest-page`);
  assert.equal(rest.complete, true, `seed=${SEED} subject=short-ring-rest-complete`);
});

test("private store files refuse every single-byte corruption", { skip: process.platform !== "linux" }, (context) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-rotation-property-")));
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  chmodSync(dir, 0o700);
  const config: rotation.RotationServerStoreOptions = { binding: corpus.binding, checkpoint: root, window: WINDOW, anchorReference: "opaque-provider/anchor", now: () => 1000 };
  const path = join(dir, "ring");
  rotation.RotationServerStore.initializeUnused(path, config);
  const original = readFileSync(path);
  // Clean copies need explicit mode 0600: the owner profile refuses any other file mode.
  const cleanPath = join(dir, "clean");
  writeFileSync(cleanPath, original, { mode: 0o600 });
  const store = rotation.RotationServerStore.open(cleanPath, config);
  assert.equal(store.snapshot().snapshot.trust.revision, 1, `seed=${SEED} subject=positive-control`);
  store.close();
  let exercised = 0;
  for (const [index, initial] of Array.from(original).entries()) {
    const mutated = Buffer.from(original);
    mutated[index] = initial ^ 1;
    const casePath = join(dir, `case-${index}`);
    writeFileSync(casePath, mutated, { mode: 0o600 });
    assert.throws(() => rotation.RotationServerStore.open(casePath, config), unavailable, `seed=${SEED} byte=${index}`);
    exercised += 1;
  }
  const sampleRandom = new SplitMix32(SEED);
  for (let sample = 0; sample < 24; sample += 1) {
    const index = sampleRandom.below(original.length);
    const mutated = Buffer.from(original);
    const initial = mutated[index];
    assert.ok(initial !== undefined, `seed=${SEED} byte=${index}`);
    mutated[index] = initial ^ 0x80;
    const casePath = join(dir, `case-high-${sample}-${index}`);
    writeFileSync(casePath, mutated, { mode: 0o600 });
    assert.throws(() => rotation.RotationServerStore.open(casePath, config), unavailable, `seed=${SEED} byte=${index} xor=0x80`);
  }
  assert.equal(exercised, original.length, `seed=${SEED} subject=sweep-complete`);
});
