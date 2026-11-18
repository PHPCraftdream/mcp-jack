import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { bodyHash, client, encodeBase64URL, keyId, rotation, validatePublicKey } from "../../../src/index.js";
import { corpus, root } from "../../support/rotation-server-fixtures.js";

// Deterministic PRNG: a fixed seed reproduces every refusal.
const SEED = 0x5eed00a1;

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

// Mirror of rotation-sign.ts: exact body lines and both proof messages, signed by hand.
function handSignedWire(parts: { ordinal: number; previousHash: string; oldKid: string; oldSigner: client.InMemorySigner; newKid: string; newPublicB64u: string; nextSigner: client.InMemorySigner; publishedAt: number }): string {
  const body = [rotation.ROTATION_DOMAIN, encodeBase64URL(Buffer.from(corpus.binding.endpoint, "utf8")), encodeBase64URL(Buffer.from(corpus.binding.aud, "utf8")),
    String(parts.ordinal), parts.previousHash, parts.oldKid, parts.newKid, parts.newPublicB64u, String(parts.publishedAt), String(parts.publishedAt + rotation.ROTATION_GRACE_SECONDS)].join("\n");
  const nextProof = encodeBase64URL(parts.nextSigner.sign(Buffer.from(`${rotation.ROTATION_DOMAIN}/next-proof\n${body}`, "ascii")));
  const oldProof = encodeBase64URL(parts.oldSigner.sign(Buffer.from(`${rotation.ROTATION_DOMAIN}/authorize\n${body}\n${nextProof}`, "ascii")));
  return `${body}\n${nextProof}\n${oldProof}`;
}

test("generated records round-trip: every decoded field matches the created record", () => {
  const random = new SplitMix32(SEED);
  for (const length of [1, 2, 4]) {
    // PRNG publication times must stay strictly monotone for createRotationRecord.
    let previous = 0;
    const publish = (index: number): number => {
      previous = Math.max(previous + 1, 1000 + Math.floor(random.below(50)) + index);
      return previous;
    };
    const { records } = generatedChain(length, publish);
    for (const [index, record] of records.entries()) {
      const authorizers = new Map([[record.oldKid, encodeBase64URL(signer(record.ordinal - 1).publicKey())]]);
      const wire = Buffer.from(record.wire, "utf8");
      const decoded = rotation.parseRotationRecord(wire, corpus.binding, authorizers);
      const label = `seed=${SEED} chain=${length} record=${index}`;
      assert.equal(decoded.ordinal, record.ordinal, `${label} field=ordinal`);
      assert.equal(decoded.previousHash, record.previousHash, `${label} field=previousHash`);
      assert.equal(decoded.oldKid, record.oldKid, `${label} field=oldKid`);
      assert.equal(decoded.newKid, record.newKid, `${label} field=newKid`);
      assert.equal(decoded.publicKeyB64u, record.publicKeyB64u, `${label} field=publicKeyB64u`);
      assert.equal(decoded.publishedAt, record.publishedAt, `${label} field=publishedAt`);
      assert.equal(decoded.activatesAt, record.publishedAt + rotation.ROTATION_GRACE_SECONDS, `${label} field=activatesAt`);
      assert.equal(decoded.wire, record.wire, `${label} field=wire`);
      assert.equal(decoded.hash, bodyHash(wire), `${label} field=hash`);
      assert.deepEqual(rotation.parseRotationRecord(wire, corpus.binding, authorizers), decoded, `${label} field=repeat-parse`);
    }
  }
});

test("every single-byte mutation of a generated record is rejected and never poisons the parser", () => {
  const random = new SplitMix32(SEED);
  const four = generatedChain(4, (index) => 1000 + index);
  const two = generatedChain(2, (index) => 2000 + index);
  const fourIndex = random.below(four.records.length);
  const twoIndex = random.below(two.records.length);
  const picked = four.records[fourIndex];
  const other = two.records[twoIndex];
  assert.ok(picked && other, `seed=${SEED} picked=${fourIndex} other=${twoIndex}`);
  for (const [name, record] of [["chain4", picked], ["chain2", other]] as const) {
    const authorizers = new Map([[record.oldKid, encodeBase64URL(signer(record.ordinal - 1).publicKey())]]);
    const original = Buffer.from(record.wire, "utf8");
    const control = rotation.parseRotationRecord(original, corpus.binding, authorizers);
    let exercised = 0;
    for (const [byte, initial] of Array.from(original).entries()) {
      const mutated = Buffer.from(original);
      mutated[byte] = initial ^ 1;
      assert.throws(() => rotation.parseRotationRecord(mutated, corpus.binding, authorizers), rotationError, `seed=${SEED} record=${name} byte=${byte}`);
      assert.deepEqual(rotation.parseRotationRecord(original, corpus.binding, authorizers), control, `seed=${SEED} record=${name} byte=${byte} subject=parser-state`);
      exercised += 1;
    }
    for (let sample = 0; sample < 16; sample += 1) {
      const byte = random.below(original.length);
      const mutated = Buffer.from(original);
      const initial = mutated[byte];
      assert.ok(initial !== undefined, `seed=${SEED} record=${name} byte=${byte}`);
      mutated[byte] = initial ^ 0x80;
      assert.throws(() => rotation.parseRotationRecord(mutated, corpus.binding, authorizers), rotationError, `seed=${SEED} record=${name} byte=${byte} xor=0x80`);
    }
    assert.equal(exercised, original.length, `seed=${SEED} record=${name} exercised=${exercised} expected=${original.length}`);
  }
});

test("line-targeted mutations fail with the exact candidate error code", () => {
  const random = new SplitMix32(SEED);
  const { records } = generatedChain(2, (index) => 1000 + index);
  const record = records[0];
  assert.ok(record, `seed=${SEED} record=0 missing`);
  const lines = record.wire.split("\n");
  assert.equal(lines.length, 12, `seed=${SEED} subject=line-count`);
  const authorizers = new Map([[record.oldKid, encodeBase64URL(signer(record.ordinal - 1).publicKey())]]);
  const anchorPublic = root.publicKeyB64u;
  assert.equal(anchorPublic.length, 43, `seed=${SEED} subject=anchor-key-length`);
  const strangerKidBytes = prng32(random);
  const strangerKeyBytes = prng32(random);
  const nextKidBytes = prng32(random);
  // Fixed PRNG bytes are deterministic: assert they never form a valid curve point before relying on "new_key".
  assert.ok(validatePublicKey(strangerKidBytes) !== null, `seed=${SEED} subject=stranger-kid-validity`);
  assert.ok(validatePublicKey(strangerKeyBytes) !== null, `seed=${SEED} subject=stranger-key-validity`);
  const strangerKid = encodeBase64URL(strangerKidBytes);
  const strangerKey = encodeBase64URL(strangerKeyBytes);
  const nextKid = encodeBase64URL(nextKidBytes);
  assert.notEqual(strangerKid, record.oldKid, `seed=${SEED} subject=stranger-kid-collision`);
  assert.notEqual(strangerKey, record.publicKeyB64u, `seed=${SEED} subject=stranger-key-collision`);
  assert.notEqual(nextKid, record.newKid, `seed=${SEED} subject=next-kid-collision`);
  const proof = lines[10];
  const oldProof = lines[11];
  assert.ok(proof && oldProof, `seed=${SEED} subject=proof-lines`);
  const ordinalRejections = ["0", "01", "+1", "-1", "1.0", "1e0", "1E0", "9007199254740992", "99999999999999999999"];
  const cases: { line: number; replacement: string; code: string }[] = [
    { line: 0, replacement: "mcp-jack/server-key-rotation/min2", code: "domain" },
    { line: 1, replacement: "!!!", code: "binding_encoding" },
    { line: 1, replacement: encodeBase64URL(Buffer.from("https://other.example.test/mcp", "utf8")), code: "binding" },
    { line: 2, replacement: "!!!", code: "binding_encoding" },
    { line: 2, replacement: encodeBase64URL(Buffer.from("https://other.example.test", "utf8")), code: "binding" },
    ...ordinalRejections.map((replacement) => ({ line: 3, replacement, code: "ordinal" })),
    { line: 4, replacement: "x", code: "new_proof" },
    { line: 5, replacement: "!", code: "key_id" },
    { line: 5, replacement: strangerKid, code: "unknown_authorizer" },
    { line: 6, replacement: "!", code: "key_id" },
    { line: 6, replacement: nextKid, code: "new_key_id" },
    { line: 7, replacement: anchorPublic.slice(0, 42), code: "base64url" },
    { line: 7, replacement: strangerKey, code: "new_key" },
    { line: 8, replacement: "01", code: "timestamp" },
    { line: 8, replacement: "-1", code: "timestamp" },
    { line: 8, replacement: String(record.publishedAt + 1), code: "activation" },
    { line: 9, replacement: "01", code: "timestamp" },
    { line: 9, replacement: String(record.activatesAt + 1), code: "activation" },
    { line: 10, replacement: "!", code: "proof_encoding" },
    { line: 10, replacement: flipFirstChar(proof), code: "new_proof" },
    { line: 11, replacement: "!", code: "proof_encoding" },
    { line: 11, replacement: flipFirstChar(oldProof), code: "old_authorization" },
  ];
  for (const { line, replacement, code } of cases) {
    const mutated = lines.slice();
    mutated[line] = replacement;
    throwsCode(() => rotation.parseRotationRecord(Buffer.from(mutated.join("\n"), "utf8"), corpus.binding, authorizers), code,
      `line=${line} replacement=${replacement.slice(0, 24)}`);
  }
  throwsCode(() => rotation.parseRotationRecord(Buffer.from(`${record.wire}\n`, "ascii"), corpus.binding, authorizers), "trailing_lf", "line=wire replacement=trailing-lf");
  throwsCode(() => rotation.parseRotationRecord(Buffer.from(`\n${record.wire}`, "ascii"), corpus.binding, authorizers), "line_count", "line=wire replacement=leading-lf");
  throwsCode(() => rotation.parseRotationRecord(Buffer.from(lines.slice(0, 11).join("\n"), "utf8"), corpus.binding, authorizers), "line_count", "line=wire replacement=missing-last");
});

test("chain order, duplication, gaps and signer references are rejected with exact codes", () => {
  const { base, records } = generatedChain(5, (index) => 1000 + index);
  const wires: Uint8Array[] = records.map((record) => Buffer.from(record.wire, "utf8"));
  const wire = (index: number): Uint8Array => {
    const value = wires[index];
    assert.ok(value !== undefined, `seed=${SEED} wire=${index}`);
    return value;
  };
  assert.equal(rotation.verifyRotationChain(wires, corpus.binding, base).length, 5, `seed=${SEED} scenario=baseline`);
  const swap = wires.slice();
  const first = wire(0);
  const second = wire(1);
  swap[0] = second;
  swap[1] = first;
  // Mispositioned wires fail at parse time first: their oldKid was never admitted into the key set.
  throwsCode(() => rotation.verifyRotationChain(swap, corpus.binding, base), "unknown_authorizer", "scenario=swap-1-2");
  throwsCode(() => rotation.verifyRotationChain(wires.slice().reverse(), corpus.binding, base), "unknown_authorizer", "scenario=reverse");
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(2), wire(3), wire(4)], corpus.binding, base), "unknown_authorizer", "scenario=remove-second");
  throwsCode(() => rotation.verifyRotationChain([wire(1), wire(1), wire(2), wire(3), wire(4)], corpus.binding, base), "unknown_authorizer", "scenario=replace-first");
  // Wires that still parse against the admitted key set reach the sequence gate.
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(0), wire(2), wire(3), wire(4)], corpus.binding, base), "ordinal_sequence", "scenario=duplicate-first");
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(1), wire(1), wire(2), wire(3), wire(4)], corpus.binding, base), "ordinal_sequence", "scenario=duplicate-second");
  throwsCode(() => rotation.verifyRotationChain([...wires, wire(4)], corpus.binding, base), "ordinal_sequence", "scenario=append-last");
  const keys = new Map<string, string>([[base.kid, base.publicKeyB64u]]);
  for (const record of records) keys.set(record.newKid, record.publicKeyB64u);
  const tail = records[2];
  const secondRecord = records[1];
  assert.ok(tail && secondRecord, `seed=${SEED} subject=chain-records`);
  const publishedAfter = tail.publishedAt + 1;
  const freshKid = keyId(signer(4).publicKey());
  const reuseWire = handSignedWire({
    ordinal: 4, previousHash: tail.hash, oldKid: tail.newKid, oldSigner: signer(3),
    newKid: keyId(signer(1).publicKey()), newPublicB64u: encodeBase64URL(signer(1).publicKey()), nextSigner: signer(1), publishedAt: publishedAfter,
  });
  assert.equal(rotation.parseRotationRecord(Buffer.from(reuseWire, "utf8"), corpus.binding, keys).newKid, keyId(signer(1).publicKey()),
    `seed=${SEED} scenario=key-reuse subject=parse-accepted`);
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(1), wire(2), Buffer.from(reuseWire, "utf8")], corpus.binding, base), "key_reuse", "scenario=key-reuse");
  const adjacentWire = handSignedWire({
    ordinal: 4, previousHash: tail.hash, oldKid: secondRecord.newKid, oldSigner: signer(2),
    newKid: freshKid, newPublicB64u: encodeBase64URL(signer(4).publicKey()), nextSigner: signer(4), publishedAt: publishedAfter,
  });
  assert.equal(rotation.parseRotationRecord(Buffer.from(adjacentWire, "utf8"), corpus.binding, keys).newKid, freshKid,
    `seed=${SEED} scenario=adjacency subject=parse-accepted`);
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(1), wire(2), Buffer.from(adjacentWire, "utf8")], corpus.binding, base), "adjacency", "scenario=adjacency");
  const orderedWire = handSignedWire({
    ordinal: 4, previousHash: tail.hash, oldKid: tail.newKid, oldSigner: signer(3),
    newKid: freshKid, newPublicB64u: encodeBase64URL(signer(4).publicKey()), nextSigner: signer(4), publishedAt: tail.publishedAt - 1,
  });
  assert.equal(rotation.parseRotationRecord(Buffer.from(orderedWire, "utf8"), corpus.binding, keys).publishedAt, tail.publishedAt - 1,
    `seed=${SEED} scenario=publication-order subject=parse-accepted`);
  throwsCode(() => rotation.verifyRotationChain([wire(0), wire(1), wire(2), Buffer.from(orderedWire, "utf8")], corpus.binding, base), "publication_order", "scenario=publication-order");
  const limit = rotation.ROTATION_MAX_RETAINED_KEYS;
  const stranger = (index: number): [string, string] => {
    const key = signer(1000 + index);
    return [keyId(key.publicKey()), encodeBase64URL(key.publicKey())];
  };
  const fullStrangers = new Map<string, string>();
  for (let index = 0; index < limit; index += 1) fullStrangers.set(...stranger(index));
  throwsCode(() => rotation.verifyRotationChain([], corpus.binding, root, fullStrangers), "capacity", "scenario=retained-without-anchor");
  const anchoredRing = new Map<string, string>();
  for (let index = 0; index < limit - 1; index += 1) anchoredRing.set(...stranger(index));
  anchoredRing.set(root.kid, root.publicKeyB64u);
  assert.equal(anchoredRing.size, limit, `seed=${SEED} scenario=retained-with-anchor subject=size`);
  assert.deepEqual(rotation.verifyRotationChain([], corpus.binding, root, anchoredRing), [], `seed=${SEED} scenario=retained-with-anchor`);
  const oversized = new Map<string, string>();
  for (let index = 0; index < limit + 1; index += 1) oversized.set(...stranger(index));
  throwsCode(() => rotation.verifyRotationChain([], corpus.binding, root, oversized), "capacity", "scenario=retained-oversized");
  const filler = "A".repeat(100);
  throwsCode(() => rotation.verifyRotationChain(Array.from({ length: limit + 1 }, () => Buffer.from(filler, "ascii")), corpus.binding, root), "capacity", "scenario=wires-over-limit");
  throwsCode(() => rotation.verifyRotationChain(Array.from({ length: limit }, () => Buffer.from(filler, "ascii")), corpus.binding, root), "line_count", "scenario=wires-at-limit");
});

test("record framing bounds hold exactly at 8192 bytes", () => {
  const limit = rotation.ROTATION_MAX_RECORD_BYTES;
  throwsCode(() => rotation.parseRotationRecord(new Uint8Array(0), corpus.binding, new Map()), "record_size", "scenario=empty");
  throwsCode(() => rotation.parseRotationRecord(Buffer.alloc(limit, "A"), corpus.binding, new Map()), "line_count", "scenario=limit-open");
  throwsCode(() => rotation.parseRotationRecord(Buffer.alloc(limit + 1, "A"), corpus.binding, new Map()), "record_size", "scenario=limit-closed");
  throwsCode(() => rotation.parseRotationRecord(Buffer.alloc(limit, 0x80), corpus.binding, new Map()), "non_ascii", "scenario=non-ascii-at-limit");
});
