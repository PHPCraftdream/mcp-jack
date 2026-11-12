import assert from "node:assert/strict";
import { test } from "node:test";
import { bodyHash } from "../src/encoding.js";
import { rotation } from "../src/index.js";
import { denies, overlapping, serverFrom, signedChain, trustFrom, validateServer } from "./rotation-server-fixtures.js";

const invalidParams = denies("invalid_params");
const checkpointUnavailable = denies("rotation_checkpoint_unavailable");

function args(ordinal: string, cursorHash: string): string {
  return `{"after_ordinal":${ordinal},"after_hash":${JSON.stringify(cursorHash)}}`;
}

test("server-key arguments accept exactly one canonical cursor and own the result", () => {
  const [first] = overlapping();
  assert.ok(first);
  const zero = rotation.decodeRotationServerKeyArguments(args("0", "-"));
  assert.deepEqual(zero, { ordinal: 0, hash: "-" });
  assert.ok(Object.isFrozen(zero));
  assert.deepEqual(rotation.decodeRotationServerKeyArguments(args("1", first.hash)), { ordinal: 1, hash: first.hash });
  // Порядок членов и whitespace не значимы; семантика не зависит от last-wins map.
  assert.deepEqual(rotation.decodeRotationServerKeyArguments(' { "after_hash" : "-" ,\n"after_ordinal" : 0 } '), zero);
  assert.equal(rotation.decodeRotationServerKeyArguments(args(String(Number.MAX_SAFE_INTEGER), first.hash)).ordinal, Number.MAX_SAFE_INTEGER);
});

test("server-key arguments reject every non-canonical shape as invalid_params", () => {
  const [first] = overlapping();
  assert.ok(first);
  const good = first.hash;
  // Последний символ canonical hash имеет нулевые trailing bits; "B" их нарушает.
  const trailingBits = `${good.slice(0, 42)}B`;
  const bad: (string | undefined)[] = [
    undefined, "", "null", "[]", "0", '"x"', "{}", "{ }",
    '{"after_ordinal":0}', '{"after_hash":"-"}',
    '{"after_ordinal":0,"after_hash":"-","extra":1}',
    '{"after_ordinal":0,"after_ordinal":0,"after_hash":"-"}',
    '{"after_ordinal":0,"after_hash":"-","after_hash":"-"}',
    '{"after_ordinal":0,"after_hash":null}', '{"after_ordinal":null,"after_hash":"-"}',
    '{"after_ordinal":"0","after_hash":"-"}', '{"after_ordinal":0,"after_hash":0}',
    '{"after_ordinal":true,"after_hash":"-"}', '{"after_ordinal":[0],"after_hash":"-"}',
    args("0.0", "-"), args("0e0", "-"), args("1E0", good), args("-0", "-"), args("-1", good), args("+1", good), args("01", good),
    args("9007199254740992", good), args("99999999999999999999", good),
    args("0", ""), args("0", good), args("0", "-="), args("1", "-"), args("1", ""), args("1", `${good}=`),
    args("1", good.slice(1)), args("1", `${good}A`), args("1", `${good.slice(0, 42)}*`), args("1", trailingBits),
  ];
  assert.notEqual(trailingBits, good);
  for (const text of bad) assert.throws(() => rotation.decodeRotationServerKeyArguments(text), invalidParams, String(text));
});

test("server-key page serves one immutable ring view from the exact acknowledged cursor", () => {
  const records = overlapping();
  const [first, second] = records;
  assert.ok(first && second);
  const snapshot = validateServer(serverFrom(trustFrom(records)));
  const anchorKey = snapshot.trust.keys[0];
  const tailKey = snapshot.trust.keys[2];
  assert.ok(anchorKey && tailKey);
  const full = rotation.rotationServerKeyPage(snapshot, { ordinal: 0, hash: "-" }, anchorKey.publicKeyB64u);
  assert.deepEqual(full, { current: { kid: anchorKey.kid, public_key: anchorKey.publicKeyB64u }, records: [first.wire, second.wire],
    head: { ordinal: 2, hash: second.hash }, complete: true });
  for (const value of [full, full.current, full.records, full.head]) assert.ok(Object.isFrozen(value));
  const advanced = rotation.rotationServerKeyPage(snapshot, { ordinal: 1, hash: first.hash }, tailKey.publicKeyB64u);
  assert.deepEqual(advanced.records, [second.wire]);
  assert.deepEqual(advanced.current, { kid: tailKey.kid, public_key: tailKey.publicKeyB64u });
  const caught = rotation.rotationServerKeyPage(snapshot, { ordinal: 2, hash: second.hash }, anchorKey.publicKeyB64u);
  assert.deepEqual(caught.records, []);
  assert.equal(caught.complete, true);
  assert.deepEqual(caught.head, { ordinal: 2, hash: second.hash });
});

test("server-key page is bounded to 16 records and always advances", () => {
  const { base, records } = signedChain(20);
  const snapshot = validateServer(serverFrom(trustFrom(records, base)), base);
  const signer = snapshot.trust.keys[0]?.publicKeyB64u;
  assert.ok(signer);
  const firstPage = rotation.rotationServerKeyPage(snapshot, { ordinal: 0, hash: "-" }, signer);
  assert.equal(firstPage.records.length, rotation.ROTATION_MAX_PAGE_RECORDS);
  assert.deepEqual(firstPage.records, records.slice(0, 16).map((record) => record.wire));
  assert.equal(firstPage.complete, false);
  assert.deepEqual(firstPage.head, { ordinal: 20, hash: records[19]?.hash });
  const sixteenth = records[15];
  assert.ok(sixteenth);
  const rest = rotation.rotationServerKeyPage(snapshot, { ordinal: 16, hash: sixteenth.hash }, signer);
  assert.deepEqual(rest.records, records.slice(16).map((record) => record.wire));
  assert.equal(rest.complete, true);
  // Ровно 16 записей до head: страница complete без пустого продолжения.
  const exact = validateServer(serverFrom(trustFrom(records.slice(0, 16), base)), base);
  const page = rotation.rotationServerKeyPage(exact, { ordinal: 0, hash: "-" }, signer);
  assert.equal(page.records.length, 16);
  assert.equal(page.complete, true);
});

test("server-key page refuses cursors outside the retained ring or with a wrong hash", () => {
  const records = overlapping();
  const [first, second] = records;
  assert.ok(first && second);
  const snapshot = validateServer(serverFrom(trustFrom(records)));
  const signer = snapshot.trust.keys[0]?.publicKeyB64u;
  assert.ok(signer);
  const refused: [number, string][] = [
    [0, first.hash], [0, ""], [1, "-"], [1, second.hash], [2, first.hash], [3, second.hash], [Number.MAX_SAFE_INTEGER, second.hash], [-1, "-"],
  ];
  for (const [ordinal, cursorHash] of refused) {
    assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal, hash: cursorHash }, signer), checkpointUnavailable, `${ordinal}:${cursorHash}`);
  }
  // Подписант вне ring никогда не получает fallback на другой key.
  const outsider = bodyHash(Buffer.from("unknown signer", "utf8"));
  assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: 0, hash: "-" }, outsider), denies("rotation_state_unavailable"));
});

test("server-key page honors a retained checkpoint: older cursors are unavailable", () => {
  const records = overlapping();
  const [first, second] = records;
  assert.ok(first && second);
  const base: rotation.RotationCheckpoint = { ordinal: first.ordinal, hash: first.hash, kid: first.newKid, publicKeyB64u: first.publicKeyB64u, publishedAt: first.publishedAt };
  const snapshot = validateServer(serverFrom(trustFrom([second], base)), base);
  const signer = base.publicKeyB64u;
  const page = rotation.rotationServerKeyPage(snapshot, { ordinal: 1, hash: first.hash }, signer);
  assert.deepEqual(page.records, [second.wire]);
  assert.equal(page.complete, true);
  assert.deepEqual(rotation.rotationServerKeyPage(snapshot, { ordinal: 2, hash: second.hash }, signer).records, []);
  assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: 0, hash: "-" }, signer), checkpointUnavailable);
  assert.throws(() => rotation.rotationServerKeyPage(snapshot, { ordinal: 1, hash: second.hash }, signer), checkpointUnavailable);
});
