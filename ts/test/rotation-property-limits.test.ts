import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { client, encodeBase64URL, keyId, rotation } from "../src/index.js";
import { corpus, denies, serverFrom, trustFrom, validateServer, WINDOW } from "./rotation-server-fixtures.js";

// Детерминированный PRNG: фиксированный seed воспроизводит каждый refusal.
const SEED = 0x5eed00a4;

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

function throwsCode(fn: () => unknown, code: string, label: string): void {
  assert.throws(fn, (error: unknown) => error instanceof rotation.RotationError && error.code === code, `seed=${SEED} ${label}`);
}

const unavailable = denies("rotation_state_unavailable");

function encode(input: rotation.RotationServerSnapshot, base: rotation.RotationCheckpoint): Uint8Array {
  return rotation.encodeRotationServerSnapshot(input, corpus.binding, WINDOW, base);
}

function decode(bytes: Uint8Array, base: rotation.RotationCheckpoint): rotation.RotationServerSnapshot {
  return rotation.decodeRotationServerSnapshot(bytes, corpus.binding, WINDOW, base);
}

// One 1153-record chain shared by every test: generation dominates the cost of this file.
let cachedChain: { readonly base: rotation.RotationCheckpoint; readonly records: rotation.RotationRecord[] } | undefined;
function bigChain(): { readonly base: rotation.RotationCheckpoint; readonly records: rotation.RotationRecord[] } {
  if (cachedChain === undefined) cachedChain = generatedChain(1153, (index) => 1000 + index);
  return cachedChain;
}

test("chain verification accepts every prefix and refuses exactly at the retained-key capacity", () => {
  const chain = bigChain();
  const wires = chain.records.map((record) => Buffer.from(record.wire, "utf8"));
  const prefix = rotation.verifyRotationChain(wires.slice(0, chain.records.length - 1), corpus.binding, chain.base);
  assert.equal(prefix.length, 1152, `seed=${SEED} scenario=chain-1152 subject=length`);
  assert.equal(prefix.length + 1, rotation.ROTATION_MAX_RETAINED_KEYS, `seed=${SEED} scenario=chain-1152 subject=key-total`);
  throwsCode(() => rotation.verifyRotationChain(wires, corpus.binding, chain.base), "capacity", "scenario=chain-1153");
  const random = new SplitMix32(SEED);
  for (let sample = 0; sample < 6; sample += 1) {
    const length = 1 + random.below(chain.records.length - 1);
    const accepted = rotation.verifyRotationChain(wires.slice(0, length), corpus.binding, chain.base);
    assert.equal(accepted.length, length, `seed=${SEED} scenario=prefix length=${length}`);
  }
});

test("pending boundary sits exactly at 128 pending keys", () => {
  const chain = bigChain();
  const pending = trustFrom(chain.records.slice(0, 128), chain.base);
  pending.clock.highWater = 1000;
  const snapshot = validateServer(serverFrom(pending), chain.base);
  const highWater = snapshot.trust.clock.highWater;
  const pendingCount = snapshot.trust.keys.filter((key) => key.notBefore > highWater).length;
  assert.equal(snapshot.trust.keys.length, 129, `seed=${SEED} scenario=pending-128 subject=key-count`);
  assert.equal(pendingCount, 128, `seed=${SEED} scenario=pending-128 subject=pending-count`);
  const overflow = trustFrom(chain.records.slice(0, 129), chain.base);
  overflow.clock.highWater = 1000;
  assert.throws(() => validateServer(serverFrom(overflow), chain.base), unavailable, `seed=${SEED} scenario=pending-129`);
  throwsCode(() => rotation.validateRotationTrustSnapshot(overflow, corpus.binding, WINDOW, chain.base), "rotation_state_unknown",
    "scenario=pending-129 subject=trust-code");
});

test("retired boundary sits exactly at 1024 retired keys with 128 still pending", () => {
  const chain = bigChain();
  const retired = trustFrom(chain.records.slice(0, 1152), chain.base);
  retired.clock.highWater = 174824;
  const snapshot = validateServer(serverFrom(retired), chain.base);
  const highWater = snapshot.trust.clock.highWater;
  let pendingCount = 0;
  let retiredCount = 0;
  for (const key of snapshot.trust.keys) {
    if (key.notBefore > highWater) pendingCount += 1;
    else if (key.knownCutoff !== null && key.knownCutoff <= highWater) retiredCount += 1;
  }
  assert.equal(highWater, 174824, `seed=${SEED} scenario=retired-1024 subject=high-water`);
  assert.equal(pendingCount, 128, `seed=${SEED} scenario=retired-1024 subject=pending-count`);
  assert.equal(retiredCount, 1024, `seed=${SEED} scenario=retired-1024 subject=retired-count`);
  const overflow = trustFrom(chain.records.slice(0, 1152), chain.base);
  overflow.clock.highWater = 174825;
  assert.throws(() => validateServer(serverFrom(overflow), chain.base), unavailable, `seed=${SEED} scenario=retired-1025`);
});

test("full retained snapshot round-trips and the 1153-record shape refuses before signatures", () => {
  const chain = bigChain();
  const retained = trustFrom(chain.records.slice(0, 1152), chain.base);
  retained.clock.highWater = 174824;
  const snapshot = validateServer(serverFrom(retained), chain.base);
  const encoded = encode(snapshot, chain.base);
  const decoded = decode(encoded, chain.base);
  assert.deepEqual(decoded, snapshot, `seed=${SEED} scenario=retained-1152 subject=round-trip`);
  assert.deepEqual(encode(decoded, chain.base), encoded, `seed=${SEED} scenario=retained-1152 subject=canonical-reencode`);
  // The 1153rd record itself is valid: the shape refusal must not depend on signature validity.
  const last = chain.records[1152];
  assert.ok(last, `seed=${SEED} scenario=retained-1153 subject=record-1153`);
  const keys = new Map<string, string>([[chain.base.kid, chain.base.publicKeyB64u]]);
  for (const record of chain.records) keys.set(record.newKid, record.publicKeyB64u);
  assert.equal(rotation.parseRotationRecord(Buffer.from(last.wire, "utf8"), corpus.binding, keys).ordinal, 1153,
    `seed=${SEED} scenario=retained-1153 subject=record-1153-parses`);
  const overflow = trustFrom(chain.records, chain.base);
  assert.throws(() => validateServer(serverFrom(overflow), chain.base), unavailable, `seed=${SEED} scenario=retained-1153 subject=shape-refusal`);
});
