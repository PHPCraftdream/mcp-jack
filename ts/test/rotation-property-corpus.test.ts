import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { denies } from "./rotation-server-fixtures.js";

/** One jack.server.key arguments case of the shared differential corpus. */
interface ArgumentCase {
  readonly id: string;
  readonly text: string;
  readonly accept: boolean;
  readonly ordinal?: number;
  readonly hash?: string;
}

/** One rotation HTTP result case of the shared differential corpus. */
interface ResultCase {
  readonly id: string;
  readonly id_json: string;
  readonly body: string;
  readonly accept: boolean;
  readonly kid?: string;
  readonly public_key?: string;
  readonly records?: readonly string[];
  readonly head_ordinal?: number;
  readonly head_hash?: string;
  readonly complete?: boolean;
  /** SDK ids whose decoder API cannot represent the expected id lexeme (see corpus note). */
}

/** RotationPropertyCorpus is rust/tests/rotation-property-corpus.json. */
interface Corpus {
  readonly format: string;
  readonly anchor_kid: string;
  readonly cursor_hash: string;
  readonly server_key_arguments: readonly ArgumentCase[];
  readonly result_bodies: readonly ResultCase[];
}

// Тот же walk вверх, что в fixtures.ts: тест собирается и в dist-test/test.
function repoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "spec", "fixtures"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`corpus root not found: no spec/fixtures above ${dir}`);
    dir = parent;
  }
}

const corpus = JSON.parse(readFileSync(join(repoRoot(), "rust", "tests", "rotation-property-corpus.json"), "utf8")) as Corpus;
const invalidParams = denies("invalid_params");
const resultInvalid = denies("rotation_result_invalid");

function cursor(entry: ArgumentCase): { readonly ordinal: number; readonly hash: string } {
  const { ordinal, hash } = entry;
  assert.ok(ordinal !== undefined && hash !== undefined, entry.id);
  return { ordinal, hash };
}

/** Строгая форма ожидания принятого result-body (DecodedRotationResult). */
function expectation(entry: ResultCase): {
  readonly current: { readonly kid: string; readonly publicKeyB64u: string };
  readonly records: readonly string[];
  readonly head: { readonly ordinal: number; readonly hash: string };
  readonly complete: boolean;
} {
  const { kid, public_key: publicKeyB64u, records, head_ordinal: ordinal, head_hash: hash, complete } = entry;
  assert.ok(kid !== undefined && publicKeyB64u !== undefined && records !== undefined &&
    ordinal !== undefined && hash !== undefined && complete !== undefined, entry.id);
  return { current: { kid, publicKeyB64u }, records, head: { ordinal, hash }, complete };
}

/**
 * Integer lexemes beyond 2^53 are passed as bigint so the decoder sees the exact
 * value; everything else keeps the number path. Values of 309 digits or more stay
 * numbers (Infinity: rejected, like the exact overflow gate of Go and Rust).
 */
function exactBigInt(lexeme: string): bigint | undefined {
  const m = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(lexeme);
  if (m === null) return undefined;
  const sign = m[1] ?? "";
  const whole = m[2] ?? "0";
  const frac = m[3] ?? "";
  const shift = Number(m[4] ?? "0") - frac.length;
  if (!Number.isSafeInteger(shift) || shift < 0) return undefined;
  const digits = (whole + frac).replace(/^0+(?=[0-9])/, "");
  if (digits.length + shift > 308) return undefined;
  return BigInt(sign + digits + "0".repeat(shift));
}

function expectedId(entry: ResultCase): string | number | bigint {
  if (entry.id_json.startsWith("\"")) return JSON.parse(entry.id_json) as string;
  const exact = exactBigInt(entry.id_json);
  return exact !== undefined && (exact > BigInt(Number.MAX_SAFE_INTEGER) || exact < -BigInt(Number.MAX_SAFE_INTEGER)) ? exact : Number(entry.id_json);
}

test("differential corpus is well-formed and sized", () => {
  assert.equal(corpus.format, "mcp-jack-rotation-property-corpus-v1");
  assert.equal(corpus.server_key_arguments.length, 50);
  assert.equal(corpus.result_bodies.length, 54);
  assert.equal(corpus.server_key_arguments.filter((entry) => entry.accept).length, 9);
  assert.equal(corpus.server_key_arguments.filter((entry) => !entry.accept).length, 41);
  assert.equal(corpus.result_bodies.filter((entry) => entry.accept).length, 14);
  assert.equal(corpus.result_bodies.filter((entry) => !entry.accept).length, 40);
  assert.equal(corpus.anchor_kid.length, 43);
  assert.equal(corpus.cursor_hash.length, 43);
  const record = corpus.server_key_arguments.find((entry) => entry.id === "record-cursor");
  assert.ok(record);
  assert.equal(record.hash, corpus.cursor_hash);
});

test("jack.server.key arguments accept and reject identically to the shared corpus", () => {
  for (const entry of corpus.server_key_arguments) {
    if (entry.accept) {
      const decoded = rotation.decodeRotationServerKeyArguments(entry.text);
      assert.deepEqual(decoded, cursor(entry), entry.id);
      assert.ok(Object.isFrozen(decoded), entry.id);
    } else {
      assert.throws(() => rotation.decodeRotationServerKeyArguments(entry.text), invalidParams, entry.id);
    }
  }
});

test("rotation result decoding accepts and rejects identically to the shared corpus", () => {
  for (const entry of corpus.result_bodies) {
    const body = Buffer.from(entry.body, "utf8");
    if (entry.accept) {
      const decoded = rotation.decodeRotationResult(body, expectedId(entry));
      assert.deepEqual(decoded, expectation(entry), entry.id);
      // Всё дерево результата immutable: mirror-parity не позволяет mutable просачивание.
      for (const value of [decoded, decoded.current, decoded.head, decoded.records]) {
        assert.ok(Object.isFrozen(value), entry.id);
      }
    } else {
      assert.throws(() => rotation.decodeRotationResult(body, expectedId(entry)), resultInvalid, entry.id);
    }
  }
});
