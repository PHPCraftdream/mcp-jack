import assert from "node:assert/strict";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { corpus, denies, overlapping, root, serverFrom, trustFrom, validateServer, WINDOW } from "./rotation-server-fixtures.js";
import type { Mutable } from "./rotation-server-fixtures.js";

const unavailable = denies("rotation_state_unavailable");

function encode(input: rotation.RotationServerSnapshot): Uint8Array {
  return rotation.encodeRotationServerSnapshot(input, corpus.binding, WINDOW, root);
}

function decode(bytes: Uint8Array): rotation.RotationServerSnapshot {
  return rotation.decodeRotationServerSnapshot(bytes, corpus.binding, WINDOW, root);
}

test("server snapshot keeps protected references out of public trust and owns frozen values", () => {
  const input = serverFrom(trustFrom(overlapping()));
  const loaded = decode(encode(input));
  assert.deepEqual(loaded, input);
  for (const value of [loaded, loaded.trust, loaded.signerReferences, ...loaded.signerReferences]) assert.ok(Object.isFrozen(value));
  const reference = loaded.signerReferences[0]?.reference;
  const wire = loaded.trust.records[0];
  const first = input.signerReferences[0];
  assert.ok(first);
  first.reference = "changed";
  input.trust.records[0] = "changed";
  assert.equal(loaded.signerReferences[0]?.reference, reference);
  assert.equal(loaded.trust.records[0], wire);
  const publicText = Buffer.from(rotation.encodeRotationTrustSnapshot(loaded.trust, corpus.binding, WINDOW, root)).toString("utf8");
  assert.ok(!publicText.includes("opaque-provider") && !publicText.includes("signer_refs"));
  // Reference — opaque handle: совпадение значений у разных kid не делает его key authority.
  const shared = serverFrom(trustFrom(overlapping()));
  const target = shared.signerReferences[1];
  assert.ok(target);
  target.reference = shared.signerReferences[0]?.reference ?? "";
  validateServer(shared);
});

test("server publication accepts exactly one fixed-P overlapping transition and preserves references", () => {
  const records = overlapping();
  const [first, second] = records;
  assert.ok(first && second);
  assert.ok(second.publishedAt < first.activatesAt, "fixture must keep pending announcements overlapping");
  const state = (count: number): Mutable<rotation.RotationServerSnapshot> => serverFrom(trustFrom(records.slice(0, count)));
  const publish = (from: rotation.RotationServerSnapshot, to: rotation.RotationServerSnapshot): rotation.RotationServerSnapshot =>
    rotation.validateRotationServerPublication(from, to, corpus.binding, WINDOW, root);
  assert.deepEqual(publish(state(0), state(1)), validateServer(state(1)));
  assert.deepEqual(publish(state(1), state(2)), validateServer(state(2)));
  assert.throws(() => publish(state(0), state(2)), unavailable, "one publication silently batched two authorizations");
  const moved = state(1);
  moved.trust.clock.highWater++;
  assert.throws(() => publish(state(0), moved), unavailable, "fixed P resampled or moved");
  const replaced = state(1);
  const reference = replaced.signerReferences[0];
  assert.ok(reference);
  reference.reference = "replacement";
  assert.throws(() => publish(state(0), replaced), unavailable, "existing signer reference replaced");
  const mutations: ((value: Mutable<rotation.RotationServerSnapshot>) => void)[] = [
    (v) => { v.trust.revision++; },
    (v) => { v.trust.clock.revision = 0; },
    (v) => { v.trust.fenced = true; },
  ];
  for (const mutate of mutations) {
    const value = state(1);
    mutate(value);
    assert.throws(() => publish(state(0), value), unavailable);
  }
  const fencedBase = state(0);
  fencedBase.trust.fenced = true;
  assert.throws(() => publish(fencedBase, state(1)), unavailable);
  assert.throws(() => publish(state(1), state(1)), unavailable);
});

test("server snapshot rejects missing, mismatched, oversized and ambiguous references", () => {
  const mutations: ((value: Mutable<rotation.RotationServerSnapshot>) => void)[] = [
    (v) => { v.formatVersion = 2; },
    (v) => { v.signerReferences = v.signerReferences.slice(0, 2); },
    (v) => { const [a, b] = v.signerReferences; assert.ok(a && b); a.kid = b.kid; },
    (v) => { const a = v.signerReferences[0]; assert.ok(a); a.reference = ""; },
    (v) => { const a = v.signerReferences[0]; assert.ok(a); a.reference = "x".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES + 1); },
    (v) => { const a = v.signerReferences[0]; assert.ok(a); a.reference = "\u00e9".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES / 2 + 1); },
    (v) => { const a = v.signerReferences[0]; assert.ok(a); a.reference = "\ud800"; },
    (v) => { const a = v.signerReferences[0]; assert.ok(a); a.reference = 1 as unknown as string; },
    (v) => { const key = v.trust.keys[0]; assert.ok(key); key.notBefore++; },
    (v) => { v.trust.records.pop(); },
  ];
  for (const mutate of mutations) {
    const value = serverFrom(trustFrom(overlapping()));
    mutate(value);
    assert.throws(() => encode(value), unavailable);
    assert.throws(() => validateServer(value), unavailable);
  }
  const boundary = serverFrom(trustFrom(overlapping()));
  const reference = boundary.signerReferences[0];
  assert.ok(reference);
  reference.reference = "x".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES);
  validateServer(boundary);
  const throwing = { get formatVersion(): number { throw new Error("hostile getter"); } } as unknown as rotation.RotationServerSnapshot;
  assert.throws(() => validateServer(throwing), unavailable);
});

test("server codec is strict, order-independent and never repairs fences or adds private fields", () => {
  const input = serverFrom(trustFrom(overlapping()));
  const encoded = Buffer.from(encode(input)).toString("utf8");
  const negatives: [string, string][] = [
    ['"format_version":1', '"format_version":1,"format_version":1'],
    ['"format_version":1', '"format_version":1e0'],
    ['"reference":', '"private_key":"forbidden","reference":'],
    ['"reference":', '"reference":null,"reference":'],
    ['"signer_refs":[', '"extra":0,"signer_refs":['],
  ];
  for (const [from, to] of negatives) {
    const changed = encoded.replace(from, to);
    assert.notEqual(changed, encoded, "negative token missing");
    assert.throws(() => decode(Buffer.from(changed, "utf8")), unavailable, to);
  }
  for (const bytes of [new Uint8Array(0), Buffer.from("[]"), Buffer.from("null"), Buffer.from(`${encoded}x`, "utf8")]) {
    assert.throws(() => decode(bytes), unavailable);
  }
  const reformatted = JSON.stringify(JSON.parse(encoded), null, 2);
  assert.deepEqual(decode(Buffer.from(reformatted, "utf8")), validateServer(input));
  const fenced = serverFrom(trustFrom(overlapping()));
  fenced.trust.fenced = true;
  fenced.trust.clock.unsafe = true;
  const loaded = decode(encode(fenced));
  assert.equal(loaded.trust.fenced, true);
  assert.equal(loaded.trust.clock.unsafe, true);
  assert.equal(rotation.rotationTrustClockCompatible(loaded.trust, loaded.trust.clock), false);
});
