import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStreamOpenAuth, formatStreamOpenAuth } from "../../src/stream/wire.js";
import { fixture } from "../support/fixtures/index.js";
import { corpus, mutateBytes, random, runProperty, settings } from "./helper.js";

test("fuzz stream open auth grammar", () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const kid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; const sid = "AAAAAAAAAAAAAAAAAAAAAA"; const sig = "A".repeat(86);
  const valid = `s1 kid=${kid},ts=0,sid=${sid},sig=${sig}`;
  const validMax = `s1 kid=${kid},ts=999999999999,sid=${sid},sig=${sig}`;
  const vectors = fixture("modern/stream-vectors.json") as { cases?: { response?: { headers?: string[][] } }[] };
  const fixtureHeaders = (vectors.cases ?? []).flatMap((entry) => entry.response?.headers ?? []).filter(([name, value]) => name?.toLowerCase() === "jack-auth" && typeof value === "string").map(([, value]) => value!);
  const fixed = [valid, validMax, `s1 sig=${sig},sid=${sid},ts=999999999999,kid=${kid}`, `s1 kid=${kid},ts=1,sid=${sid},sig=${sig},kid=${kid}`, `s1 kid=${kid},ts=1,sid=${sid},sig=${sig},extra=A`, `s1 kid=${kid},ts=01,sid=${sid},sig=${sig}`,
    ...["-1", "9007199254740992", "9223372036854775808", "1.5", "NaN", "Infinity"].map((ts) => `s1 kid=${kid},ts=${ts},sid=${sid},sig=${sig}`)];
  const boundaries = corpus("open-auth-boundaries.json") as { values: string[] };
  const sources = [...fixed, ...fixtureHeaders, ...boundaries.values];
  for (let i = 0; i < iterations; i++) {
    const source = sources[Math.floor(next() * sources.length)] ?? valid;
    const input = i % 2 === 0 ? source : new TextDecoder().decode(mutateBytes(new TextEncoder().encode(source), next));
    runProperty(seed, i, input, () => {
      const result = parseStreamOpenAuth(input);
      assert.equal(typeof result.ok, "boolean");
      if (result.ok) {
        assert.equal(formatStreamOpenAuth(result.value), `s1 kid=${result.value.kid},ts=${result.value.ts},sid=${result.value.sid},sig=${result.value.sig}`);
        assert.deepEqual(parseStreamOpenAuth(formatStreamOpenAuth(result.value)), result);
        assert.ok(result.value.ts >= 0 && result.value.ts <= 999999999999);
      }
    });
  }
  for (const input of fixed.filter((value) => value.includes("ts=-1") || value.includes("ts=9007199254740992") || value.includes("ts=9223372036854775808") || value.includes("ts=1.5") || value.includes("ts=NaN") || value.includes("ts=Infinity"))) {
    runProperty(seed, iterations, input, () => assert.equal(parseStreamOpenAuth(input).ok, false));
  }
  assert.equal(parseStreamOpenAuth(valid).ok, true);
  assert.equal(parseStreamOpenAuth(validMax).ok, true);
});
