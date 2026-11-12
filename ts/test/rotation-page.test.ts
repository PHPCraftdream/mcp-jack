import assert from "node:assert/strict";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

interface Corpus {
  binding: rotation.RotationBinding;
  keys: Record<string, { kid: string; public_key: string }>;
  valid_chains: { overlapping: string[] };
  source_controls: { decreasing_prefix: string };
}
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const keys = new Map(Object.values(corpus.keys).map((key) => [key.kid, key.public_key]));
const records = corpus.valid_chains.overlapping.map((wire) => rotation.parseRotationRecord(Buffer.from(wire), corpus.binding, keys));
const r1 = records[0];
const r2 = records[1];
const anchor = corpus.keys["anchor"];
assert.ok(r1 && r2 && anchor);
const current = { kid: anchor.kid, publicKeyB64u: anchor.public_key };
const zero: rotation.RotationCursor = { ordinal: 0, hash: "-" };
const c1: rotation.RotationCursor = { ordinal: 1, hash: r1.hash };
const c2: rotation.RotationCursor = { ordinal: 2, hash: r2.hash };
const known = new Map([[1, r1.hash], [2, r2.hash]]);

function page(delivered: readonly rotation.RotationRecord[], head: rotation.RotationCursor, complete = true): rotation.DecodedRotationResult {
  return { current, records: delivered.map((record) => record.wire), head, complete };
}
function denied(code: string): (error: unknown) => boolean {
  return (error) => error instanceof rotation.RotationError && error.code === code;
}

test("page framing: exact extension, duplicate-prefix extension and retained suffix no-op", () => {
  const extension = rotation.validateRotationPageFraming(page(records, c2), zero, records, new Map());
  assert.equal(extension.extensionStart, 0);
  assert.deepEqual(extension.terminal, c2);
  assert.equal(extension.complete, true);
  const prefix = rotation.validateRotationPageFraming(page(records, c2), c1, records, known);
  assert.equal(prefix.extensionStart, 1);
  assert.deepEqual(prefix.terminal, c2);
  const duplicate = rotation.validateRotationPageFraming(page([r2], c2), c2, [r2], known);
  assert.equal(duplicate.extensionStart, 1);
  assert.deepEqual(duplicate.terminal, c2);
  const incomplete = rotation.validateRotationPageFraming(page([r1], c2, false), zero, [r1], new Map());
  assert.deepEqual(incomplete.terminal, c1);
  assert.deepEqual(incomplete.head, c2);
  assert.equal(incomplete.complete, false);
  // Duplicate-only — no-op, не продвижение cursor к объявленному head.
  const noop = rotation.validateRotationPageFraming(page([r1], c2, false), c1, [r1], known);
  assert.deepEqual(noop.terminal, c1);
  assert.equal(noop.extensionStart, 1);
});

test("page framing: empty exact page owns its metadata and never mutates caller cursor", () => {
  const cursor = { ordinal: 0, hash: "-" };
  const result = rotation.validateRotationPageFraming(page([], zero), cursor, [], new Map());
  cursor.hash = "caller mutation";
  assert.deepEqual(result.terminal, zero);
  for (const value of [result, result.terminal, result.head]) assert.ok(Object.isFrozen(value));
  assert.equal(result.extensionStart, 0);
});

test("page framing: gaps, incomplete empty pages and head contradictions fail closed", () => {
  for (const [delivered, cursor, head, complete] of [
    [[r2], zero, c2, true],
    [[r2, r1], c2, c1, true],
    [[r1], c2, c1, true],
    [records, zero, c1, true],
    [records, zero, { ordinal: 2, hash: r1.hash }, true],
    [records, zero, c2, false],
    [[], zero, c1, false],
    [[], zero, c1, true],
  ] as const) {
    assert.throws(() => rotation.validateRotationPageFraming(page(delivered, head, complete), cursor, delivered, known), denied("rotation_gap"));
  }
  assert.throws(() => rotation.validateRotationPageFraming(page(records, c2), c2, records, new Map([[2, r2.hash]])), denied("rotation_gap"));
});

test("page framing: authenticated known-position conflict is not accepted as duplicate", () => {
  const conflict = rotation.parseRotationRecord(Buffer.from(corpus.source_controls.decreasing_prefix), corpus.binding, keys);
  assert.notEqual(conflict.hash, r1.hash);
  assert.throws(() => rotation.validateRotationPageFraming(page([conflict], { ordinal: 1, hash: conflict.hash }), c1, [conflict], known), denied("rotation_conflict"));
  assert.throws(() => rotation.validateRotationPageFraming(page([], c1), c1, [], new Map([[1, r2.hash]])), denied("rotation_conflict"));
});

test("page framing: mixed response/record snapshots, forged hash and page overflow rejected", () => {
  assert.throws(() => rotation.validateRotationPageFraming(page([r1], c1), zero, [r2], new Map()), denied("rotation_record_invalid"));
  assert.throws(() => rotation.validateRotationPageFraming(page([r1], c1), zero, [{ ...r1, hash: r2.hash }], new Map()), denied("rotation_record_invalid"));
  assert.throws(() => rotation.validateRotationPageFraming(page([], zero), zero, [r1], new Map()), denied("rotation_result_invalid"));
  const oversized = Array.from({ length: 17 }, () => r1);
  assert.throws(() => rotation.validateRotationPageFraming(page(oversized, c1), c1, oversized, known), denied("rotation_result_invalid"));
});
