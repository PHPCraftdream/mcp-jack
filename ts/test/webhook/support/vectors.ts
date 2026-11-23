import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { decodeBase64URL, encodeBase64URL } from "../../../src/core/encoding.js";
import { parseWhsec } from "../../../src/webhook/crypto/primitives.js";
import { webhookSigningKeyFromSeed } from "../../../src/webhook/crypto/signatures.js";
import type { AcceptedWebhookKey, WebhookSigningKey } from "../../../src/webhook/crypto/signatures.js";
import { fixture, loadKeys } from "../../support/fixtures/index.js";
import type { TestKey } from "../../support/fixtures/index.js";

export interface VectorCase {
  readonly id: string;
  readonly rule: string;
  readonly description: string;
  readonly kind: string;
  readonly input: Record<string, unknown>;
  readonly expect: Record<string, unknown>;
  readonly [extra: string]: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isVectorCase(value: unknown): value is VectorCase {
  return isRecord(value) && typeof value.id === "string" && typeof value.rule === "string" &&
    typeof value.description === "string" && typeof value.kind === "string" &&
    isRecord(value.input) && isRecord(value.expect);
}

export function loadWebhookVectors(file: string): {
  readonly note: string;
  readonly clock: number;
  readonly cases: readonly VectorCase[];
} {
  const data: unknown = fixture("modern/" + file);
  if (!isRecord(data) || typeof data.note !== "string" || typeof data.clock !== "number" ||
      !Array.isArray(data.cases)) {
    throw new Error(`${file}: invalid webhook vector corpus`);
  }
  const entries: readonly unknown[] = data.cases;
  const cases = entries.map((entry, index) => {
    if (!isVectorCase(entry)) throw new Error(`${file}: invalid vector at index ${index}`);
    return entry;
  });
  return { note: data.note, clock: data.clock, cases };
}

export function deepEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left)) {
    if (!Array.isArray(right) || left.length !== right.length) return false;
    for (let i = 0; i < left.length; i++) {
      if (Object.hasOwn(left, i) !== Object.hasOwn(right, i) || !deepEqual(left[i], right[i])) return false;
    }
    return true;
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length &&
    keys.every((key) => Object.hasOwn(right, key) && deepEqual(left[key], right[key]));
}

function stableText(value: unknown): string {
  if (Array.isArray(value)) return `[${Array.from(value, stableText).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableText(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? String(value);
}

export function diffText(left: unknown, right: unknown): string {
  return `got:  ${stableText(left)}\nwant: ${stableText(right)}`;
}

export async function runCorpus(options: {
  readonly corpus: string;
  readonly file: string;
  readonly expectedCases: number;
  readonly run: (c: VectorCase) => unknown | Promise<unknown>;
}): Promise<void> {
  const { corpus, file, expectedCases, run } = options;
  const { cases } = loadWebhookVectors(file);
  assert.equal(cases.length, expectedCases, `${corpus}: case count`);
  const ids = new Set(cases.map((c) => c.id));
  assert.equal(ids.size, cases.length, `${corpus}: duplicate case id`);

  const ran = new Set<string>();
  const failures: string[] = [];
  let pass = 0;
  for (const c of cases) {
    ran.add(c.id);
    const label = `case ${c.id} (rule ${c.rule})`;
    try {
      const got = await run(c);
      if (deepEqual(got, c.expect)) pass++;
      else failures.push(`${label}:\n${diffText(got, c.expect)}`);
    } catch (error) {
      failures.push(`${label}:\ngot:  threw ${String(error)}\nwant: ${stableText(c.expect)}`);
    }
  }
  try {
    assert.equal(ran.size, expectedCases, `${corpus}: not every case ran`);
    assert.equal(pass, expectedCases, failures.join("\n\n"));
  } finally {
    console.log(`VECTOR-SUMMARY corpus=${corpus} sdk=ts pass=${pass} excluded=0 deviation=0`);
  }
}

let keys: ReadonlyMap<string, TestKey> | undefined;

function fixtureKey(name: string): TestKey {
  keys ??= new Map(loadKeys().keys.map((key) => [key.name, key]));
  const key = keys.get(name);
  if (key === undefined) throw new Error(`unknown fixture key: ${name}`);
  return key;
}

export function acceptedKey(name: string): AcceptedWebhookKey {
  const { kid, publicKey } = fixtureKey(name);
  return { kid, kty: "OKP", crv: "Ed25519", x: publicKey, publicKey, raw: bytes(publicKey) };
}

export function signingKey(name: string): WebhookSigningKey {
  return webhookSigningKeyFromSeed(Buffer.from(fixtureKey(name).seedHex, "hex"));
}

export function bytes(b64u: string): Uint8Array {
  return decodeBase64URL(b64u);
}

export function b64u(value: Uint8Array): string {
  return encodeBase64URL(value);
}

export function utf8(value: string): Uint8Array {
  return Buffer.from(value, "utf8");
}

export function secretBytes(value: unknown): Uint8Array {
  const parsed = parseWhsec(value);
  if (!parsed.ok) throw new Error(`fixture secret rejected (${parsed.reason})`);
  return parsed.key;
}

export function refusal(code: string, reason?: string): Record<string, unknown> {
  return reason === undefined ? { result: "reject", code } : { result: "reject", code, reason };
}
