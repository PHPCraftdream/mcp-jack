import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { client, encodeBase64URL, keyId, rotation } from "../../../src/index.js";
import { corpus, root } from "../../support/rotation-server-fixtures.js";

// Deterministic PRNG: a fixed seed reproduces every refusal.
const SEED = 0x5eed00a2;

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

const rotationError = (error: unknown): boolean => error instanceof rotation.RotationError;

function flipFirstChar(text: string): string {
  const flipped = (text[0] === "A" ? "B" : "A") + text.slice(1);
  assert.notEqual(flipped, text, "flip must change the character");
  return flipped;
}

function resultLiteral(wires: readonly string[], complete: boolean, head: rotation.RotationCursor): rotation.DecodedRotationResult {
  return { current: { kid: root.kid, publicKeyB64u: root.publicKeyB64u }, records: wires, head: { ordinal: head.ordinal, hash: head.hash }, complete };
}

test("generated pages frame one contiguous extension from the exact cursor", () => {
  const { records } = generatedChain(6, (index) => 1000 + index * 10);
  const wires = records.map((record) => record.wire);
  const tailRecord = records[5];
  assert.ok(tailRecord, `seed=${SEED} subject=tail-record`);
  const head: rotation.RotationCursor = { ordinal: 6, hash: tailRecord.hash };
  for (let k = 0; k <= 6; k += 1) {
    const previous = k === 0 ? undefined : records[k - 1];
    const cursor: rotation.RotationCursor = { ordinal: k, hash: previous === undefined ? "-" : previous.hash };
    const page = records.slice(k);
    const framing = rotation.validateRotationPageFraming(resultLiteral(page.map((record) => record.wire), true, head), cursor, page, new Map());
    assert.equal(framing.extensionStart, 0, `seed=${SEED} k=${k} subject=extensionStart`);
    assert.deepEqual(framing.terminal, head, `seed=${SEED} k=${k} subject=terminal`);
    for (const value of [framing, framing.terminal, framing.head]) assert.ok(Object.isFrozen(value), `seed=${SEED} k=${k} subject=frozen`);
    const partial = records.slice(k, k + 2);
    const partialTail = partial.length === 0 ? undefined : partial[partial.length - 1];
    const partialWires = partial.map((record) => record.wire);
    if (partialTail !== undefined && partialTail.ordinal < 6) {
      const partialFraming = rotation.validateRotationPageFraming(resultLiteral(partialWires, false, head), cursor, partial, new Map());
      assert.equal(partialFraming.extensionStart, 0, `seed=${SEED} k=${k} subject=partial-extensionStart`);
      assert.deepEqual(partialFraming.terminal, { ordinal: partialTail.ordinal, hash: partialTail.hash }, `seed=${SEED} k=${k} subject=partial-terminal`);
    } else {
      // An incomplete page must promise a head STRICTLY beyond the terminal — otherwise rotation_gap.
      throwsCode(() => rotation.validateRotationPageFraming(resultLiteral(partialWires, false, head), cursor, partial, new Map()), "rotation_gap",
        `k=${k} subject=partial-saturated`);
    }
  }
  const firstRecord = records[0];
  const secondRecord = records[1];
  assert.ok(firstRecord && secondRecord, `seed=${SEED} subject=prefix-records`);
  const acknowledged = new Map([[1, firstRecord.hash]]);
  const framing = rotation.validateRotationPageFraming(resultLiteral(wires, true, head), { ordinal: 2, hash: secondRecord.hash }, records, acknowledged);
  assert.equal(framing.extensionStart, 2, `seed=${SEED} subject=acknowledged-extension`);
  assert.deepEqual(framing.terminal, head, `seed=${SEED} subject=acknowledged-terminal`);
});

test("every framing mutation is rejected with its exact code", () => {
  const { records } = generatedChain(4, (index) => 1000 + index);
  const r1 = records[0];
  const r2 = records[1];
  const r3 = records[2];
  const r4 = records[3];
  assert.ok(r1 && r2 && r3 && r4, `seed=${SEED} subject=chain`);
  const wires = [r1.wire, r2.wire, r3.wire, r4.wire];
  const cursor: rotation.RotationCursor = { ordinal: 2, hash: r2.hash };
  const acknowledged = new Map([[1, r1.hash]]);
  const tail: rotation.RotationCursor = { ordinal: 4, hash: r4.hash };
  const baseline = rotation.validateRotationPageFraming(resultLiteral(wires, true, tail), cursor, records, acknowledged);
  assert.equal(baseline.extensionStart, 2, `seed=${SEED} subject=baseline-extension`);
  assert.deepEqual(baseline.terminal, tail, `seed=${SEED} subject=baseline-terminal`);
  // A suffix-only page [r3, r4] is a VALID extension (extensionStart 0): the known prefix is optional.
  const suffix = rotation.validateRotationPageFraming(resultLiteral([r3.wire, r4.wire], true, tail), cursor, [r3, r4], acknowledged);
  assert.equal(suffix.extensionStart, 0, `seed=${SEED} subject=suffix-extension`);
  const scenario = (pageRecords: readonly rotation.RotationRecord[], resultRecords: readonly string[], pageCursor: rotation.RotationCursor,
    pageAcknowledged: ReadonlyMap<number, string>, head: rotation.RotationCursor, complete: boolean): unknown =>
    rotation.validateRotationPageFraming(resultLiteral(resultRecords, complete, head), pageCursor, pageRecords, pageAcknowledged);
  const cases: { label: string; code: string; run: () => unknown }[] = [
    { label: "result records swapped", code: "rotation_record_invalid", run: () => scenario(records, [r2.wire, r1.wire, r3.wire, r4.wire], cursor, acknowledged, tail, true) },
    { label: "records swapped against unchanged result", code: "rotation_record_invalid", run: () => scenario([r2, r1, r3, r4], wires, cursor, acknowledged, tail, true) },
    { label: "records swapped", code: "rotation_gap", run: () => scenario([r2, r1, r3, r4], [r2.wire, r1.wire, r3.wire, r4.wire], cursor, acknowledged, tail, true) },
    { label: "records duplicated", code: "rotation_gap", run: () => scenario([r1, r1, r2, r3, r4], [r1.wire, r1.wire, r2.wire, r3.wire, r4.wire], cursor, acknowledged, tail, true) },
    { label: "records removed", code: "rotation_gap", run: () => scenario([r1, r3, r4], [r1.wire, r3.wire, r4.wire], cursor, acknowledged, tail, true) },
    { label: "result wire replaced", code: "rotation_record_invalid", run: () => scenario(records, [r1.wire, r2.wire, "x", r4.wire], cursor, acknowledged, tail, true) },
    { label: "record hash mutated", code: "rotation_record_invalid", run: () => scenario([r1, r2, { ...r3, hash: flipFirstChar(r3.hash) }, r4], wires, cursor, acknowledged, tail, true) },
    { label: "cursor hash wrong", code: "rotation_conflict", run: () => scenario(records, wires, { ordinal: 2, hash: r1.hash }, acknowledged, tail, true) },
    { label: "acknowledged hash wrong", code: "rotation_conflict", run: () => scenario(records, wires, cursor, new Map([[1, flipFirstChar(r1.hash)]]), tail, true) },
    { label: "acknowledged empty", code: "rotation_gap", run: () => scenario(records, wires, cursor, new Map<number, string>(), tail, true) },
    { label: "no extension", code: "rotation_gap", run: () => scenario([r1], [r1.wire], cursor, new Map([[1, r1.hash]]), tail, true) },
    { label: "extension skips cursor+1", code: "rotation_gap", run: () => scenario([r4], [r4.wire], cursor, acknowledged, tail, true) },
    { label: "head behind terminal", code: "rotation_gap", run: () => scenario(records, wires, cursor, acknowledged, { ordinal: 3, hash: r3.hash }, true) },
    { label: "head hash flipped", code: "rotation_gap", run: () => scenario(records, wires, cursor, acknowledged, { ordinal: 4, hash: flipFirstChar(r4.hash) }, true) },
    { label: "complete with terminal head", code: "rotation_gap", run: () => scenario(records, wires, cursor, acknowledged, tail, false) },
    { label: "incomplete empty page", code: "rotation_gap", run: () => scenario([], [], cursor, acknowledged, tail, false) },
    { label: "complete partial page", code: "rotation_gap", run: () => scenario([r1, r2], [r1.wire, r2.wire], cursor, acknowledged, tail, true) },
    { label: "cursor hash shape", code: "rotation_gap", run: () => scenario(records, wires, { ordinal: 0, hash: "x" }, acknowledged, tail, true) },
    { label: "cursor dash ordinal", code: "rotation_gap", run: () => scenario(records, wires, { ordinal: 1, hash: "-" }, acknowledged, tail, true) },
    { label: "head ordinal over max", code: "rotation_gap", run: () => scenario(records, wires, cursor, acknowledged, { ordinal: 9007199254740992, hash: r4.hash }, true) },
    { label: "cursor ordinal over max", code: "rotation_gap", run: () => scenario(records, wires, { ordinal: 9007199254740992, hash: r2.hash }, acknowledged, tail, true) },
  ];
  for (const { label, code, run } of cases) throwsCode(run, code, `mutation=${label}`);
});

test("page and body limits hold exactly", () => {
  const full = generatedChain(16, (index) => 1000 + index);
  const fullTail = full.records[15];
  assert.ok(fullTail, `seed=${SEED} subject=tail-16`);
  const fullFraming = rotation.validateRotationPageFraming(resultLiteral(full.records.map((record) => record.wire), true, { ordinal: 16, hash: fullTail.hash }),
    { ordinal: 0, hash: "-" }, full.records, new Map());
  assert.equal(fullFraming.extensionStart, 0, `seed=${SEED} subject=page-16-accepted`);
  assert.equal(fullFraming.terminal.ordinal, 16, `seed=${SEED} subject=page-16-terminal`);
  const over = generatedChain(17, (index) => 1000 + index);
  const overTail = over.records[16];
  assert.ok(overTail, `seed=${SEED} subject=tail-17`);
  throwsCode(() => rotation.validateRotationPageFraming(resultLiteral(over.records.map((record) => record.wire), true, { ordinal: 17, hash: overTail.hash }),
    { ordinal: 0, hash: "-" }, over.records, new Map()), "rotation_result_invalid", "scenario=page-17");
  assert.equal(over.records.length - 1, rotation.ROTATION_MAX_PAGE_RECORDS, `seed=${SEED} subject=page-limit`);
  const partial = over.records.slice(0, 15);
  const partialTail = partial[14];
  assert.ok(partialTail, `seed=${SEED} subject=tail-15`);
  const partialFraming = rotation.validateRotationPageFraming(resultLiteral(partial.map((record) => record.wire), false, { ordinal: 17, hash: overTail.hash }),
    { ordinal: 0, hash: "-" }, partial, new Map());
  assert.equal(partialFraming.extensionStart, 0, `seed=${SEED} subject=page-15-accepted`);
  assert.deepEqual(partialFraming.terminal, { ordinal: 15, hash: partialTail.hash }, `seed=${SEED} subject=page-15-terminal`);
  // Both payload slots share one literal: padding whitespace outside the slots (1 or 2 bytes) keeps the filler length integral.
  const payload = (filler: string): string =>
    `{"current":{"kid":"${root.kid}","public_key":"${root.publicKeyB64u}"},"records":["${filler}"],"head":{"ordinal":0,"hash":"-"},"complete":true}`;
  const envelope = (body: string, pad = 1): Uint8Array =>
    Buffer.from(`{"jsonrpc":"2.0",${" ".repeat(pad)}"id":7,"result":{"content":[{"type":"text","text":${JSON.stringify(body)}}],"structuredContent":${body},"isError":false}}`, "utf8");
  const pad = 1 + ((rotation.ROTATION_MAX_BODY_BYTES - Buffer.byteLength(envelope(payload("")))) % 2);
  const base = Buffer.byteLength(envelope(payload(""), pad));
  const fillerLength = (rotation.ROTATION_MAX_BODY_BYTES - base) / 2;
  assert.ok(Number.isInteger(fillerLength) && fillerLength > 0, `seed=${SEED} filler=${String(fillerLength)} base=${String(base)}`);
  const filler = `rotation-property-${"p".repeat(fillerLength - 18)}`;
  const body = envelope(payload(filler), pad);
  assert.equal(Buffer.byteLength(body), rotation.ROTATION_MAX_BODY_BYTES, `seed=${SEED} subject=body-at-limit`);
  assert.deepEqual(rotation.decodeRotationResult(body, 7).records, [filler], `seed=${SEED} subject=body-at-limit-decodes`);
  throwsCode(() => rotation.decodeRotationResult(Buffer.concat([body, Buffer.from(" ")]), 7), "rotation_result_invalid", "scenario=body-limit+1");
});

test("canonical result bodies reject every single-byte mutation", () => {
  const payload = `{"current":{"kid":"${root.kid}","public_key":"${root.publicKeyB64u}"},"records":["rotation-property"],"head":{"ordinal":0,"hash":"-"},"complete":true}`;
  const envelope = (body: string): Uint8Array =>
    Buffer.from(`{"jsonrpc":"2.0", "id":7,"result":{"content":[{"type":"text","text":${JSON.stringify(body)}}],"structuredContent":${body},"isError":false}}`, "utf8");
  const body = envelope(payload);
  const baseline = rotation.decodeRotationResult(body, 7);
  assert.deepEqual(baseline.records, ["rotation-property"], `seed=${SEED} subject=baseline`);
  let exercised = 0;
  for (const [byte, initial] of Array.from(body).entries()) {
    const mutated = Buffer.from(body);
    mutated[byte] = initial ^ 1;
    assert.throws(() => rotation.decodeRotationResult(mutated, 7), rotationError, `seed=${SEED} byte=${byte}`);
    exercised += 1;
  }
  const random = new SplitMix32(SEED);
  for (let sample = 0; sample < 16; sample += 1) {
    const byte = random.below(body.length);
    const mutated = Buffer.from(body);
    const initial = mutated[byte];
    assert.ok(initial !== undefined, `seed=${SEED} byte=${byte}`);
    mutated[byte] = initial ^ 0x80;
    assert.throws(() => rotation.decodeRotationResult(mutated, 7), rotationError, `seed=${SEED} byte=${byte} xor=0x80 subject=non-ascii`);
  }
  assert.equal(exercised, body.length, `seed=${SEED} exercised=${exercised} expected=${body.length}`);
  assert.deepEqual(rotation.decodeRotationResult(body, 7), baseline, `seed=${SEED} subject=positive-control`);
});
