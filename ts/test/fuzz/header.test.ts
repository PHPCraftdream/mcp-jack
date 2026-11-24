import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeHeaderValue, encodeHeaderValue } from "../../src/modern/values.js";
import { fixture } from "../support/fixtures/index.js";
import { corpus, mutateBytes, random, runProperty, settings } from "./helper.js";

function encodedExpectedValues(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    if (value.length === 2 && typeof value[0] === "string" && typeof value[1] === "string" && /^Mcp-/i.test(value[0])) return [value[1]];
    return value.flatMap(encodedExpectedValues);
  }
  return Object.values(value).flatMap(encodedExpectedValues);
}

function mutateEncoded(value: string, next: () => number): string {
  const bytes = new TextEncoder().encode(value);
  const changed = mutateBytes(bytes, next);
  return new TextDecoder().decode(changed);
}

test("fuzz modern header value encoding", () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const boundaries = corpus("header-boundaries.json") as { valid: string[]; malformed: string[] };
  const encoding = fixture("modern/header-encoding-vectors.json") as { cases?: { kind?: string; header_value?: string; expect?: { ok?: boolean } }[] };
  const malformedVectors = (encoding.cases ?? []).filter((v) => v.kind === "decode" && v.expect?.ok === false).map((v) => v.header_value).filter((v): v is string => typeof v === "string");
  const xHeaders = fixture("modern/x-mcp-header-vectors.json");
  const xEncoded = encodedExpectedValues(xHeaders).filter((value) => value.startsWith("=?base64?") && value.endsWith("?="));
  assert.ok(xEncoded.length > 0);
  const rejects = [...boundaries.malformed, ...malformedVectors];
  const identityValues = [...boundaries.valid.filter((v) => !/[\uD800-\uDFFF]/.test(v)), ...xEncoded, "Hello 世界", "x".repeat(20), "\uFEFFkept", "=?base64?empty?="];
  const surrogateValues = boundaries.valid.filter((v) => /[\uD800-\uDFFF]/.test(v));
  const encodedBoundaries = identityValues.map(encodeHeaderValue);
  const mutated = encodedBoundaries.flatMap((value) => [mutateEncoded(value, next), value.slice(0, Math.floor(next() * (value.length + 1))), value.toUpperCase(), value.slice(0, -1), value.startsWith("=?base64?") ? value.replace("?=", "?==") : "=?base64?" + value + "?="]);
  const cases = [...identityValues, ...encodedBoundaries, ...rejects, ...mutated];
  for (let i = 0; i < iterations; i++) {
    const input = cases[Math.floor(next() * cases.length)]!;
    runProperty(seed, i, input, () => {
      const decoded = decodeHeaderValue(input);
      assert.ok(decoded.ok || decoded.reason === "bad_encoding");
      if (identityValues.includes(input)) assert.deepEqual(decodeHeaderValue(encodeHeaderValue(input)), { ok: true, text: input });
    });
  }
  for (const value of identityValues) runProperty(seed, iterations, value, () => assert.deepEqual(decodeHeaderValue(encodeHeaderValue(value)), { ok: true, text: value }));
  for (const value of surrogateValues) runProperty(seed, iterations, value, () => assert.doesNotThrow(() => decodeHeaderValue(encodeHeaderValue(value))));
  for (let i = 0; i < rejects.length; i++) runProperty(seed, i, rejects[i], () => assert.deepEqual(decodeHeaderValue(rejects[i]!), { ok: false, reason: "bad_encoding" }));
});
