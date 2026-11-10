import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { decodeBase64URL, rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

interface Corpus {
  binding: rotation.RotationBinding;
  keys: Record<string, { kid: string; public_key: string }>;
  valid_chains: Record<string, string[]>;
  source_controls: { decreasing_prefix: string };
  malformed: { id: string; expected: string; setup: string; binding: rotation.RotationBinding; wire_b64u: string }[];
}

const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const anchorKey = corpus.keys["anchor"];
assert.ok(anchorKey);
const checkpoint: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: anchorKey.kid, publicKeyB64u: anchorKey.public_key, publishedAt: 0 };
const allKeys = new Map(Object.values(corpus.keys).map((key) => [key.kid, key.public_key]));
const overlapping = corpus.valid_chains["overlapping"];
assert.ok(overlapping && overlapping.length === 2);
const first = overlapping[0];
assert.ok(first);
const raw = (wire: string): Uint8Array => Buffer.from(wire, "utf8");

function rejects(code: string): (error: unknown) => boolean {
  return (error) => error instanceof rotation.RotationError && error.code === code;
}

test("candidate rotation: all19 independent negative outcomes", () => {
  assert.equal(corpus.malformed.length, 19);
  for (const row of corpus.malformed) {
    const wire = decodeBase64URL(row.wire_b64u);
    assert.throws(() => {
      switch (row.setup) {
        case "chain": rotation.verifyRotationChain([wire], corpus.binding, checkpoint); break;
        case "after-r1": rotation.verifyRotationChain([raw(first), wire], corpus.binding, checkpoint); break;
        case "decreasing": rotation.verifyRotationChain([raw(corpus.source_controls.decreasing_prefix), wire], corpus.binding, checkpoint); break;
        case "single": rotation.parseRotationRecord(wire, row.binding, allKeys); break;
        default: assert.fail(`unknown fixture setup ${row.setup}`);
      }
    }, rejects(row.expected), row.id);
  }
});

test("candidate rotation: exact bytes, full-record hash, overlapping and equal activation", () => {
  for (const [name, wires] of Object.entries(corpus.valid_chains)) {
    const records = rotation.verifyRotationChain(wires.map(raw), corpus.binding, checkpoint);
    assert.equal(records.length, 2);
    for (const [index, record] of records.entries()) {
      assert.equal(record.wire, wires[index]);
      assert.equal(record.hash, createHash("sha256").update(record.wire, "utf8").digest("base64url"));
      assert.ok(Object.isFrozen(record));
    }
    assert.ok(Object.isFrozen(records));
    assert.equal(rotation.selectedRotationOrdinal(records, 173799), 0);
    if (name === "tie") {
      assert.equal(rotation.selectedRotationOrdinal(records, 173800), 2);
      assert.equal(rotation.rotationAssignmentValid(records, 1, 173800, 173800), false);
    } else {
      assert.equal(rotation.rotationAssignmentValid(records, 1, 173800, 173800), true);
      assert.equal(rotation.rotationAssignmentValid(records, 1, 177399, 177400), false);
      assert.equal(rotation.rotationAssignmentValid(records, 0, 173799, 173800), false);
    }
  }
});

test("candidate rotation: unknown authorizer cannot be admitted by its own payload", () => {
  assert.throws(() => rotation.parseRotationRecord(raw(first), corpus.binding, new Map()), rejects("unknown_authorizer"));
  const bytes = raw(first);
  const parsed = rotation.parseRotationRecord(bytes, corpus.binding, allKeys);
  bytes.fill(0);
  assert.equal(parsed.wire, first);
  assert.throws(() => rotation.parseRotationRecord(raw(first), { ...corpus.binding, endpoint: "\ud800" }, allKeys), rejects("utf8"));
});

test("candidate rotation: strict numeric domains and retained-key reuse", () => {
  const records = rotation.verifyRotationChain(overlapping.map(raw), corpus.binding, checkpoint);
  for (const invalid of [-1, 0.5, NaN, Infinity, rotation.ROTATION_MAX_TIMESTAMP + 1]) {
    assert.equal(rotation.rotationAssignmentValid(records, 1, invalid, 173800), false);
    assert.equal(rotation.rotationAssignmentValid(records, 1, 173800, invalid), false);
    assert.throws(() => rotation.selectedRotationOrdinal(records, invalid), rejects("timestamp"));
  }
  assert.throws(() => rotation.verifyRotationChain([], corpus.binding, { ...checkpoint, ordinal: Number.MAX_SAFE_INTEGER + 1 }), rejects("anchor_key_id"));
  const next = corpus.keys["next1"];
  assert.ok(next);
  assert.throws(() => rotation.verifyRotationChain([raw(first)], corpus.binding, checkpoint, new Map([[next.kid, next.public_key]])), rejects("key_reuse"));
  assert.equal(rotation.rotationAssignmentValid(records, 1, 173799, 173799), false);
});
