import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSignatureHeader, checkSignatureSchemes, decodeSignatureEntries, parseW1Header } from "../../src/webhook/crypto/signatures.js";
import { isEnvelopeTimestamp, parseWebhookBody } from "../../src/webhook/receiver/envelope.js";
import { fixture } from "../support/fixtures/index.js";
import { corpus, mutateBytes, random, runProperty, settings } from "./helper.js";

function collectBodyTexts(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap(collectBodyTexts);
  const row = value as Record<string, unknown>;
  return [...(typeof row.body_text === "string" ? [row.body_text] : []), ...Object.values(row).flatMap(collectBodyTexts)];
}

test("fuzz webhook signature and envelope parsers", () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const boundaries = corpus("webhook-boundaries.json") as { signatureHeaders: string[]; w1: string[]; timestamps: string[] };
  const sigText = JSON.stringify(fixture("modern/webhook-signature-vectors.json"));
  const w1Text = JSON.stringify(fixture("modern/webhook-w1-vectors.json"));
  const sigCases = [...boundaries.signatureHeaders, ...(sigText.match(/(?:v1a?|v2a),[^\" ]+/g) ?? []), "v1,@@@@", "v3,AAAA"];
  const w1Cases = [...boundaries.w1, ...(w1Text.match(/w1 [^\" ]+/g) ?? [])];
  const timestamps = [...boundaries.timestamps, "2024-02-29T00:00:00Z", "2023-02-29T00:00:00Z", "2024-01-01T24:00:00Z", "NaN"];
  const corpusBodies = collectBodyTexts(fixture("modern/webhook-receiver-vectors.json"));
  const validBody = new TextEncoder().encode('{"data":{},"eventId":"e","name":"n","timestamp":"2024-01-01T00:00:00Z"}');
  const bodies = [validBody, ...corpusBodies.map((body) => new TextEncoder().encode(body)), new TextEncoder().encode("{"), Uint8Array.of(0xc3, 0x28), Uint8Array.of(0xff, 0xfe, 0x7b)];
  const sources = [...sigCases, ...w1Cases].map((value) => new TextEncoder().encode(value));
  const shortSources = [...sources, ...bodies].flatMap((bytes) => Array.from({ length: Math.min(bytes.length, 128) + 1 }, (_, n) => bytes.subarray(0, n)));
  for (let j = 0; j < bodies.length; j++) {
    const body = bodies[j]!;
    runProperty(seed, j, { input_hex: Buffer.from(body).toString("hex"), input_utf8: Buffer.from(body).toString("utf8") }, () => assert.equal(typeof parseWebhookBody(body).ok, "boolean"), body);
  }
  runProperty(seed, bodies.length, "valid envelope body", () => assert.equal(parseWebhookBody(validBody).ok, true), validBody);
  for (let i = 0; i < iterations; i++) {
    const bytes = shortSources[Math.floor(next() * shortSources.length)]!;
    const mutated = mutateBytes(bytes, next);
    const value = Buffer.from(mutated).toString("utf8");
    runProperty(seed, i, { input_hex: Buffer.from(mutated).toString("hex"), input_json: JSON.stringify(value) }, () => {
      const sig = parseSignatureHeader(value); if (sig.ok) { const schemes = checkSignatureSchemes(sig.entries); if (schemes.ok) decodeSignatureEntries(sig.entries); }
      assert.equal(typeof parseW1Header(value).ok, "boolean");
      assert.equal(typeof parseWebhookBody(mutated).ok, "boolean");
    }, mutated);
    const ts = timestamps[Math.floor(next() * timestamps.length)]!;
    runProperty(seed, i, ts, () => assert.equal(typeof isEnvelopeTimestamp(ts), "boolean"));
  }
});
