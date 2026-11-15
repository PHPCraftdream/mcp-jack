import assert from "node:assert/strict";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

interface Corpus {
  keys: { anchor: { kid: string; public_key: string } };
}
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const payload = JSON.stringify({
  current: { kid: corpus.keys.anchor.kid, public_key: corpus.keys.anchor.public_key },
  records: [],
  head: { ordinal: 0, hash: "-" },
  complete: true,
});
// id подставляется сырым lexeme: JSON.stringify нормализовал бы форму числа.
function envelope(idLexeme: string): string {
  return `{"jsonrpc":"2.0","id":${idLexeme},"result":{"content":[{"type":"text","text":${JSON.stringify(payload)}}],"structuredContent":${payload},"isError":false}}`;
}
const raw = (text: string): Uint8Array => Buffer.from(text, "utf8");
function rejected(wire: string, id: string | number | bigint = 7): void {
  assert.throws(
    () => rotation.decodeRotationResult(raw(wire), id),
    (error: unknown) => error instanceof rotation.RotationError && error.code === "rotation_result_invalid",
  );
}

test("rotation result id: numeric response id must be the canonical JSON text of the expected value", () => {
  assert.equal(rotation.decodeRotationResult(raw(envelope("7")), 7).complete, true);
  // Пробел вокруг lexeme вне lexeme: значение и текст не меняются.
  assert.equal(rotation.decodeRotationResult(raw(envelope(' 7 ')), 7).complete, true);
  for (const lexeme of ["7.0", "7e0", "7E0", "+7", "07", "-0", "7."]) rejected(envelope(lexeme));
  rejected(envelope('"7"'));
  assert.throws(
    () => rotation.decodeRotationResult(raw(envelope("7")), "7"),
    (error: unknown) => error instanceof rotation.RotationError && error.code === "rotation_result_invalid",
  );
});

test("rotation result id: a bigint expectedId matches only the exact decimal text above 2^53", () => {
  // A bigint carries 9007199254740993 exactly (a double would round it to ...992).
  assert.equal(rotation.decodeRotationResult(raw(envelope("9007199254740993")), 9007199254740993n).complete, true);
  rejected(envelope("9007199254740992"), 9007199254740993n);
  for (const lexeme of ["9007199254740993.0", "9.007199254740993e15", "9007199254740993e0"]) rejected(envelope(lexeme), 9007199254740993n);
  // 1e999: Number -> Infinity, invalid с обеих сторон.
  rejected(envelope("1"), Number("1e999"));
  rejected(envelope("1e999"), Number("1e999"));
});

test("rotation result id: canonical response matches non-canonical expected numeric value", () => {
  // expectedId — само число 7; ответ обязан нести канонический текст "7".
  assert.equal(rotation.decodeRotationResult(raw(envelope("7")), 7).head.ordinal, 0);
  rejected(envelope("7e0"));
  // -0: значение равно 0, канонический текст JSON.stringify(-0) — "0".
  assert.equal(rotation.decodeRotationResult(raw(envelope("0")), -0).complete, true);
  rejected(envelope("-0"), -0);
});
