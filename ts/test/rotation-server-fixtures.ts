import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { client, encodeBase64URL, keyId, rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

export type Mutable<T> = T extends readonly (infer Value)[] ? Mutable<Value>[] : T extends object ? { -readonly [Key in keyof T]: Mutable<T[Key]> } : T;

interface Corpus {
  binding: rotation.RotationBinding;
  keys: Record<string, { kid: string; public_key: string }>;
  valid_chains: Record<string, string[]>;
}

export const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const anchor = corpus.keys["anchor"];
assert.ok(anchor);
export const root: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: anchor.kid, publicKeyB64u: anchor.public_key, publishedAt: 0 };
export const WINDOW = 30;

/** Независимо подписанные records overlapping-цепочки из общего fixture corpus. */
export function overlapping(): rotation.RotationRecord[] {
  const wires = corpus.valid_chains["overlapping"];
  assert.ok(wires);
  return rotation.verifyRotationChain(wires.map((wire) => Buffer.from(wire, "utf8")), corpus.binding, root);
}

/** Реально подписанная цепочка с равным P (все ключи pending) и её собственный anchor checkpoint. */
export function signedChain(count: number): { readonly base: rotation.RotationCheckpoint; readonly records: rotation.RotationRecord[] } {
  const signer = (index: number): client.InMemorySigner => new client.InMemorySigner(createHash("sha256").update(`server ring fixture ${index}`).digest());
  let old = signer(0);
  const base: rotation.RotationCheckpoint = { ...root, kid: keyId(old.publicKey()), publicKeyB64u: encodeBase64URL(old.publicKey()) };
  let tail = base;
  const records: rotation.RotationRecord[] = [];
  for (let index = 1; index <= count; index++) {
    const next = signer(index);
    const record = rotation.createRotationRecord(corpus.binding, tail, old, next, 1000);
    records.push(record);
    tail = { ordinal: record.ordinal, hash: record.hash, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, publishedAt: record.publishedAt };
    old = next;
  }
  return { base, records };
}

/** Первый key — checkpoint base; каждый record добавляет следующий (P = publishedAt последнего). */
export function trustFrom(records: readonly rotation.RotationRecord[], base = root, revision = records.length + 1): Mutable<rotation.RotationTrustSnapshot> {
  const keys: Mutable<rotation.RotationTrustKey>[] = [{ ordinal: base.ordinal, kid: base.kid, publicKeyB64u: base.publicKeyB64u,
    notBefore: base.ordinal === 0 ? 0 : base.publishedAt + rotation.ROTATION_GRACE_SECONDS, knownCutoff: null }];
  let head: rotation.RotationCursor = { ordinal: base.ordinal, hash: base.hash };
  let highWater = base.publishedAt;
  for (const record of records) {
    const previous = keys[keys.length - 1];
    assert.ok(previous);
    previous.knownCutoff = record.activatesAt;
    keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null });
    head = { ordinal: record.ordinal, hash: record.hash };
    highWater = record.publishedAt;
  }
  return { formatVersion: 1, binding: { ...corpus.binding }, window: WINDOW, checkpoint: { ...base }, head: { ...head },
    records: records.map((record) => record.wire), keys, revision, fenced: false,
    clock: { binding: { ...corpus.binding }, window: WINDOW, highWater, revision: records.length + 1, unsafe: false } };
}

/** Каждому key соответствует opaque provider handle, не private-key material. */
export function serverFrom(trust: Mutable<rotation.RotationTrustSnapshot>): Mutable<rotation.RotationServerSnapshot> {
  return { formatVersion: 1, trust, signerReferences: trust.keys.map((key) => ({ kid: key.kid, reference: `opaque-provider/${key.kid}` })) };
}

export function validateServer(input: rotation.RotationServerSnapshot, base = root): rotation.RotationServerSnapshot {
  return rotation.validateRotationServerSnapshot(input, corpus.binding, WINDOW, base);
}

export function denies(code: string): (error: unknown) => boolean {
  return (error) => error instanceof rotation.RotationError && error.code === code;
}
