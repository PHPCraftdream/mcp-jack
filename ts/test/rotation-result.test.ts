import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJsonRaw, rotation } from "../src/index.js";
import { parseCandidateJsonRaw } from "../src/json-raw.js";
import { fixture } from "./fixtures.js";

interface Corpus {
  binding: rotation.RotationBinding;
  keys: { anchor: { kid: string; public_key: string } };
  valid_chains: { overlapping: string[] };
}
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const initial = {
  current: { kid: corpus.keys.anchor.kid, public_key: corpus.keys.anchor.public_key },
  records: [] as string[],
  head: { ordinal: 0, hash: "-" },
  complete: true,
};
const payload = JSON.stringify(initial);
function envelope(structured = payload, text = structured, id: string | number = 1): string {
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"content":[{"type":"text","text":${JSON.stringify(text)}}],"structuredContent":${structured},"isError":false}}`;
}
const raw = (text: string): Uint8Array => Buffer.from(text, "utf8");
function rejected(wire: string, id: string | number = 1): void {
  assert.throws(() => rotation.decodeRotationResult(raw(wire), id), (error: unknown) => error instanceof rotation.RotationError && error.code === "rotation_result_invalid");
}

test("rotation result: exact shape, reordered text parity, immutable decoded values", () => {
  const reordered = JSON.stringify({ complete: true, head: initial.head, records: [], current: { public_key: initial.current.public_key, kid: initial.current.kid } }, null, 2);
  for (const id of [1, 1.5, "request-✓"]) {
    const result = rotation.decodeRotationResult(raw(envelope(payload, reordered, id)), id);
    assert.equal(result.current.kid, initial.current.kid);
    assert.equal(result.current.publicKeyB64u, initial.current.public_key);
    assert.deepEqual(result.head, { ordinal: 0, hash: "-" });
    assert.deepEqual(result.records, []);
    assert.equal(result.complete, true);
    for (const object of [result, result.current, result.head, result.records]) assert.ok(Object.isFrozen(object));
  }
  rejected(envelope(), 2);
  rejected(envelope().replace('"id":1', '"id":1e0'));
  rejected(envelope().replace('"id":1', '"id":9007199254740993'), 9007199254740992);
});

test("rotation result: duplicates and extra members rejected at every object boundary", () => {
  const ordinary = envelope();
  for (const [from, to] of [
    ['"jsonrpc":"2.0"', '"jsonrpc":"2.0","jsonrpc":"2.0"'],
    ['"isError":false', '"isError":false,"isError":false'],
    ['"type":"text"', '"type":"text","type":"text"'],
  ]) {
    assert.ok(from !== undefined && to !== undefined);
    rejected(ordinary.replace(from, to));
  }
  for (const changed of [
    payload.replace('"complete":true', '"complete":true,"complete":true'),
    payload.replace('"kid":', '"kid":"duplicate","kid":'),
    payload.replace('"ordinal":0', '"ordinal":0,"ordinal":0'),
    payload.replace('"complete":true', '"complete":true,"extra":1'),
    payload.replace('"kid":', '"extra":1,"kid":'),
    payload.replace('"ordinal":0', '"ordinal":0,"extra":1'),
  ]) {
    rejected(envelope(changed));
    rejected(envelope(payload, changed));
  }
  rejected(ordinary.replace('"jsonrpc":', '"extra":1,"jsonrpc":'));
  rejected(ordinary.replace('"isError":false', '"isError":false,"extra":1'));
  rejected(ordinary.replace('"type":"text"', '"type":"text","extra":1'));
  const escapedDuplicate = '{"complete":true,"\\u0063omplete":true,"current":' + JSON.stringify(initial.current) + ',"records":[],"head":{"ordinal":0,"hash":"-"}}';
  rejected(envelope(escapedDuplicate));
});

test("rotation result: lexical numbers, wrong types, malformed current/hash and parity fail closed", () => {
  for (const lexical of ["-0", "0.0", "0e0"]) rejected(envelope(payload.replace('"ordinal":0', `"ordinal":${lexical}`)));
  for (const changed of [
    payload.replace('"complete":true', '"complete":null'),
    payload.replace('"records":[]', '"records":{}'),
    payload.replace('"ordinal":0', '"ordinal":null'),
    payload.replace('"hash":"-"', '"hash":"wrong"'),
    payload.replace(initial.current.kid, "wrong"),
    payload.replace(initial.current.public_key, initial.current.public_key + "="),
    payload.replace('"records":[]', '"records":[null]'),
  ]) rejected(envelope(changed));
  rejected(envelope().replace('"isError":false', '"isError":true'));
  rejected(envelope().replace('"type":"text"', '"type":"image"'));
  const content = `"content":[{"type":"text","text":${JSON.stringify(payload)}}]`;
  rejected(envelope().replace(content, '"content":null'));
  rejected(envelope().replace(content, '"content":[]'));
  rejected(envelope().replace(`"text":${JSON.stringify(payload)}`, '"text":123'));
  // Обе source schemas валидны; только text/structured parity запрещает эту пару.
  const first = corpus.valid_chains.overlapping[0];
  const hash = corpus.valid_chains.overlapping[1]?.split("\n")[4];
  assert.ok(first && hash);
  const other = JSON.stringify({ ...initial, records: [first], head: { ordinal: 1, hash } });
  assert.equal(rotation.decodeRotationResult(raw(envelope(other)), 1).head.ordinal, 1);
  rejected(envelope(other.replace(hash, hash + "=")));
  rejected(envelope(payload, other));
  const surrogate = String.fromCharCode(0xd800);
  rejected(envelope(payload, surrogate));
  assert.throws(() => rotation.decodeRotationResult(new Uint8Array([0xff]), 1), rotation.RotationError);
});

test("rotation result: actual full-body cap is inclusive, page cap counts every record", () => {
  const ordinary = raw(envelope());
  const buffer = Uint8Array.from(ordinary).buffer;
  assert.throws(() => rotation.decodeRotationResult(buffer as unknown as Uint8Array, 1), rotation.RotationError);
  assert.throws(() => rotation.decodeRotationResult(new DataView(buffer) as unknown as Uint8Array, 1), rotation.RotationError);
  const exact = Buffer.concat([ordinary, Buffer.alloc(rotation.ROTATION_MAX_BODY_BYTES - ordinary.length, 0x20)]);
  assert.equal(rotation.decodeRotationResult(exact, 1).head.ordinal, 0);
  assert.throws(() => rotation.decodeRotationResult(Buffer.concat([exact, Buffer.from(" ")]), 1), rotation.RotationError);
  const first = corpus.valid_chains.overlapping[0];
  assert.ok(first);
  const recordBuffer = Uint8Array.from(raw(first)).buffer;
  const keys = new Map([[initial.current.kid, initial.current.public_key]]);
  assert.throws(() => rotation.parseRotationRecord(recordBuffer as unknown as Uint8Array, corpus.binding, keys), (error: unknown) => error instanceof rotation.RotationError && error.code === "record_size");
  // Только schema/page count: intrinsic links/cursor проверяются позднее controller.
  const page = { ...initial, records: Array.from({ length: 16 }, () => first) };
  assert.equal(rotation.decodeRotationResult(raw(envelope(JSON.stringify(page))), 1).records.length, 16);
  page.records.push(first);
  rejected(envelope(JSON.stringify(page)));
});

test("rotation result: exhaustive escaped member spellings preserve values but never hide duplicates", { timeout: 30_000 }, () => {
  const ordinary = envelope();
  const members: readonly (readonly [string, string])[] = [
    ["jsonrpc", '"2.0"'],
    ["isError", "false"],
    ["type", '"text"'],
    ["complete", "true"],
    ["kid", JSON.stringify(initial.current.kid)],
    ["ordinal", "0"],
  ];
  let cases = 0;
  let expectedCases = 0;
  for (const [name, value] of members) {
    const target = `${JSON.stringify(name)}:${value}`;
    assert.equal(ordinary.split(target).length, 2, `unique source member: ${name}`);
    expectedCases += (2 ** name.length) - 1;
    for (let mask = 1; mask < 2 ** name.length; mask += 1) {
      const escaped = Array.from(name, (character, index) => (mask & (1 << index)) === 0
        ? character
        : `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
      const member = `"${escaped}":${value}`;
      const positive = ordinary.replace(target, member);
      // Независимый JSON decoder подтверждает семантику escape spelling.
      assert.deepEqual(JSON.parse(positive), JSON.parse(ordinary), `${name}/${mask}: ${positive}`);
      assert.equal(rotation.decodeRotationResult(raw(positive), 1).current.kid, initial.current.kid, `${name}/${mask}`);
      rejected(ordinary.replace(target, `${target},${member}`));
      cases += 1;
    }
  }
  assert.equal(cases, expectedCases);
  assert.equal(cases, 658);
  assert.equal(rotation.decodeRotationResult(raw(ordinary), 1).complete, true);
});

test("shared JSON parser: native last-wins unchanged; candidate duplicate/scalar/depth guards isolated", () => {
  assert.equal((parseJsonRaw('{"x":1,"x":2}').value as { x: number }).x, 2);
  assert.throws(() => parseCandidateJsonRaw('{"x":1,"x":2}'));
  const depth64 = "[".repeat(64) + "0" + "]".repeat(64);
  const depth65 = "[".repeat(65) + "0" + "]".repeat(65);
  assert.ok(parseCandidateJsonRaw(depth64));
  assert.throws(() => parseCandidateJsonRaw(depth65));
  assert.ok(parseJsonRaw(depth65));
  const native = parseJsonRaw('{"__proto__":{"polluted":true}}').value;
  assert.equal(Object.getPrototypeOf(native), Object.prototype);
  assert.ok(Object.hasOwn(native as object, "__proto__"));
});
