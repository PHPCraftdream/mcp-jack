import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSignatureHeader, checkSignatureSchemes, decodeSignatureEntries, parseW1Header } from "../../src/webhook/crypto/signatures.js";
import { isEnvelopeTimestamp, parseWebhookBody } from "../../src/webhook/receiver/envelope.js";
import { fixture } from "../support/fixtures/index.js";
import { corpus, mutateBytes, random, runProperty, settings, spliceBytes } from "./helper.js";

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function fixtureRows(value: unknown): Record<string, unknown>[] {
  const cases = asRecord(value)?.cases;
  return Array.isArray(cases) ? cases.map(asRecord).filter((row): row is Record<string, unknown> => row !== undefined) : [];
}

function collectNamedHeaders(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap(collectNamedHeaders);
  const row = value as Record<string, unknown>;
  return [...[row.signature_header, row.header].filter((item): item is string => typeof item === "string"), ...Object.values(row).flatMap(collectNamedHeaders)];
}

function collectBodyTexts(value: unknown): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap(collectBodyTexts);
  const row = value as Record<string, unknown>;
  return [...(typeof row.body_text === "string" ? [row.body_text] : []), ...Object.values(row).flatMap(collectBodyTexts)];
}

test("fuzz webhook signature and envelope parsers", () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const boundaries = corpus("webhook-boundaries.json") as { signatureHeaders: string[]; w1: string[]; timestamps: string[]; bodyCases: { body: string; expected: "ok:gap" | "ok:event" | "malformed_body" | "unknown_envelope_type" }[] };
  const signatureVectors = fixture("modern/webhook-signature-vectors.json");
  const w1Vectors = fixture("modern/webhook-w1-vectors.json");
  const sigText = JSON.stringify(signatureVectors);
  const w1Text = JSON.stringify(w1Vectors);
  const sigCases = [...boundaries.signatureHeaders, ...collectNamedHeaders(signatureVectors), ...(sigText.match(/(?:v1a?|v2a),[^\" ]+/g) ?? []), "v1,@@@@", "v3,AAAA"];
  const w1Cases = [...boundaries.w1, ...collectNamedHeaders(w1Vectors), ...(w1Text.match(/w1 [^\" ]+/g) ?? [])];
  for (let i = 0; i < sigCases.length; i++) runProperty(seed, i, sigCases[i], () => assert.equal(typeof parseSignatureHeader(sigCases[i]!).ok, "boolean"));
  for (let i = 0; i < w1Cases.length; i++) runProperty(seed, i, w1Cases[i], () => assert.equal(typeof parseW1Header(w1Cases[i]!).ok, "boolean"));
  let vectorIndex = 0;
  for (const row of fixtureRows(signatureVectors)) {
    if (row.kind !== "verify") continue;
    const input = asRecord(row.input);
    const envelope = asRecord(input?.envelope);
    const expected = asRecord(row.expect);
    const header = envelope?.signature_header;
    const code = expected?.code;
    if (typeof header !== "string") continue;
    runProperty(seed, vectorIndex++, { id: row.id, header }, () => {
      const parsed = parseSignatureHeader(header);
      assert.equal(parsed.ok, code !== "malformed_signature_header");
      if (parsed.ok && code === "unsupported_signature_scheme") assert.deepEqual(checkSignatureSchemes(parsed.entries), { ok: false, code });
      if (parsed.ok && code === "malformed_signature") {
        assert.equal(checkSignatureSchemes(parsed.entries).ok, true);
        assert.deepEqual(decodeSignatureEntries(parsed.entries), { ok: false, code });
      }
    });
  }
  for (const row of fixtureRows(w1Vectors)) {
    if (row.kind !== "verify-w1") continue;
    const input = asRecord(row.input);
    const header = input?.header;
    const expected = asRecord(row.expect);
    const code = expected?.code;
    if (typeof header !== "string") continue;
    runProperty(seed, vectorIndex++, { id: row.id, header }, () => {
      const parsed = parseW1Header(header);
      if (code === "malformed_jack_auth") assert.deepEqual(parsed, { ok: false, code });
      else if (expected?.result === "accept") assert.equal(parsed.ok, true);
    });
  }
  const timestamps = [...boundaries.timestamps, "2024-02-29T00:00:00Z", "2023-02-29T00:00:00Z", "2024-01-01T24:00:00Z", "NaN"];
  const corpusBodies = collectBodyTexts(fixture("modern/webhook-receiver-vectors.json"));
  const validBody = new TextEncoder().encode('{"data":{},"eventId":"e","name":"n","timestamp":"2024-01-01T00:00:00Z"}');
  const knownBodies = boundaries.bodyCases.map(({ body }) => new TextEncoder().encode(body));
  const invalidUtf8Bodies = [Uint8Array.of(0xc3, 0x28), Uint8Array.of(0xff, 0xfe, 0x7b)];
  const expectedBodyResults = new Map<string, "ok:gap" | "ok:event" | "malformed_body" | "unknown_envelope_type">([
    [Buffer.from(validBody).toString("hex"), "ok:event"],
    ...boundaries.bodyCases.map(({ body, expected }) => [Buffer.from(body, "utf8").toString("hex"), expected] as const),
    ...invalidUtf8Bodies.map((body) => [Buffer.from(body).toString("hex"), "malformed_body"] as const),
  ]);
  const bodies = [validBody, ...corpusBodies.map((body) => new TextEncoder().encode(body)), new TextEncoder().encode("{"), ...invalidUtf8Bodies, ...knownBodies];
  const sources = [...sigCases, ...w1Cases].map((value) => new TextEncoder().encode(value));
  const shortInputs = [...sources, ...bodies].filter((bytes) => bytes.length <= 128);
  const sampledInputs = shortInputs.slice(0, 32);
  for (const input of ["v1,@@@@", "v1,AAAA", "v1,AAAA=", "v1,AAAA v1,AAAA", "v1,AAAA  v1,AAAA", " v1,AAAA", "v1,AAAA "]) {
    runProperty(seed, iterations, input, () => {
      const parsed = parseSignatureHeader(input);
      if (input === "v1,@@@@") { assert.ok(parsed.ok); assert.deepEqual(decodeSignatureEntries(parsed.entries), { ok: false, code: "malformed_signature" }); }
      else if (input === "v1,AAAA v1,AAAA") { assert.ok(parsed.ok); assert.equal(parsed.entries.length, 2); assert.equal(decodeSignatureEntries(parsed.entries).ok, false); }
      else if (input.includes(" ") || input.startsWith(" ") || input.endsWith(" ")) assert.equal(parsed.ok, false);
      else { assert.ok(parsed.ok); assert.deepEqual(decodeSignatureEntries(parsed.entries), { ok: false, code: "malformed_signature" }); }
    });
  }
  const goodW1 = `w1 kid=${"A".repeat(43)},sig=${"A".repeat(86)}`;
  runProperty(seed, iterations, goodW1, () => assert.deepEqual(parseW1Header(goodW1), { ok: true, kid: "A".repeat(43), sig: "A".repeat(86) }));
  for (const bad of [`w1 kid=${"A".repeat(43)},kid=${"A".repeat(43)},sig=${"A".repeat(86)}`, `w1 kid=${"A".repeat(43)},sig=${"A".repeat(86)},extra=A`, `w1 kid=${"A".repeat(43)},sig=${"A".repeat(85)}`]) {
    runProperty(seed, iterations, bad, () => assert.deepEqual(parseW1Header(bad), { ok: false, code: "malformed_jack_auth" }));
  }
  for (const [timestamp, expected] of [["2024-02-29T00:00:00Z", true], ["2023-02-29T00:00:00Z", false], ["2024-01-01T24:00:00Z", false], ["NaN", false]] as const) {
    runProperty(seed, iterations, timestamp, () => assert.equal(isEnvelopeTimestamp(timestamp), expected));
  }
  for (let j = 0; j < bodies.length; j++) {
    const body = bodies[j]!;
    runProperty(seed, j, { input_hex: Buffer.from(body).toString("hex"), input_json: JSON.stringify(Buffer.from(body).toString("utf8")) }, () => {
      const parsed = parseWebhookBody(body);
      const expected = expectedBodyResults.get(Buffer.from(body).toString("hex"));
      if (expected === "ok:gap") assert.deepEqual(parsed, { ok: true, envelope: { type: "gap", message: JSON.parse(Buffer.from(body).toString("utf8")) } });
      else if (expected === "ok:event") assert.deepEqual(parsed, { ok: true, envelope: { type: null, message: JSON.parse(Buffer.from(body).toString("utf8")) } });
      else if (expected === "unknown_envelope_type" || expected === "malformed_body") assert.deepEqual(parsed, { ok: false, code: expected });
      else if (Buffer.from(body).equals(Buffer.from("{"))) assert.deepEqual(parsed, { ok: false, code: "malformed_body" });
      else assert.equal(typeof parsed.ok, "boolean");
    }, body);
  }
  for (let sourceIndex = 0; sourceIndex < shortInputs.length; sourceIndex++) {
    const source = shortInputs[sourceIndex]!;
    for (let prefixIndex = 0; prefixIndex <= source.length; prefixIndex++) {
      const bytes = source.subarray(0, prefixIndex);
      const text = Buffer.from(bytes).toString("utf8");
      runProperty(seed, sourceIndex * 129 + prefixIndex, { input_hex: Buffer.from(bytes).toString("hex"), input_json: JSON.stringify(text) }, () => {
        assert.equal(typeof parseSignatureHeader(text).ok, "boolean");
        assert.equal(typeof parseW1Header(text).ok, "boolean");
        assert.equal(typeof parseWebhookBody(bytes).ok, "boolean");
      }, bytes);
    }
  }
  runProperty(seed, bodies.length, "valid envelope body", () => assert.equal(parseWebhookBody(validBody).ok, true), validBody);
  for (let i = 0; i < iterations; i++) {
    const bytes = sampledInputs[Math.floor(next() * sampledInputs.length)]!;
    const secondSource = sources[Math.floor(next() * sources.length)]!;
    const mutated = mutateBytes(bytes, next);
    const splice = spliceBytes(bytes, secondSource, Math.floor(next() * (bytes.length + 1)));
    const value = Buffer.from(mutated).toString("utf8");
    runProperty(seed, i, { input_hex: Buffer.from(mutated).toString("hex"), splice_hex: Buffer.from(splice).toString("hex"), input_json: JSON.stringify(value) }, () => {
      for (const candidate of [mutated, splice]) {
        const candidateText = Buffer.from(candidate).toString("utf8");
        const parsedCandidate = parseSignatureHeader(candidateText);
        assert.equal(typeof parsedCandidate.ok, "boolean");
        const w1Candidate = parseW1Header(candidateText);
        if (w1Candidate.ok) assert.ok(w1Candidate.kid.length === 43 && w1Candidate.sig.length === 86);
        assert.equal(typeof parseWebhookBody(candidate).ok, "boolean");
      }
      const sig = parseSignatureHeader(value);
      if (value === "v1,@@@@") { assert.ok(sig.ok); assert.equal(checkSignatureSchemes(sig.entries).ok, true); assert.deepEqual(decodeSignatureEntries(sig.entries), { ok: false, code: "malformed_signature" }); }
      if (value === "v3,AAAA") { assert.ok(sig.ok); assert.deepEqual(checkSignatureSchemes(sig.entries), { ok: false, code: "unsupported_signature_scheme" }); }
      if (sig.ok) {
        assert.ok(sig.entries.length > 0);
        const schemes = checkSignatureSchemes(sig.entries);
        if (schemes.ok) {
          const decoded = decodeSignatureEntries(sig.entries);
          assert.equal(typeof decoded.ok, "boolean");
          if (decoded.ok) {
            assert.equal(decoded.entries.length, sig.entries.length);
            for (let index = 0; index < sig.entries.length; index++) {
              const encoded: string = String(sig.entries[index]!.value);
              assert.equal(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded), true);
              assert.equal(Buffer.from(decoded.entries[index]!.sig).toString("base64"), encoded);
            }
          }
        } else {
          assert.equal(schemes.code, "unsupported_signature_scheme");
          assert.equal(decodeSignatureEntries(sig.entries).ok, false);
        }
      }
      const w1 = parseW1Header(value);
      if (w1.ok) {
        assert.ok(w1.kid.length === 43 && /^[A-Za-z0-9_-]+$/.test(w1.kid));
        assert.ok(w1.sig.length === 86 && /^[A-Za-z0-9_-]+$/.test(w1.sig));
        assert.ok(w1.kid === Buffer.from(w1.kid, "base64url").toString("base64url"));
        assert.ok(w1.sig === Buffer.from(w1.sig, "base64url").toString("base64url"));
      } else assert.equal(w1.code, "malformed_jack_auth");
      const envelope = parseWebhookBody(mutated);
      if (!Buffer.from(mutated).equals(Buffer.from(validBody))) assert.equal(typeof envelope.ok, "boolean");
    }, mutated);
    const ts = timestamps[Math.floor(next() * timestamps.length)]!;
    runProperty(seed, i, ts, () => assert.equal(typeof isEnvelopeTimestamp(ts), "boolean"));
  }
});
