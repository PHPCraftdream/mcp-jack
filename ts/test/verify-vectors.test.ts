/**
 * Conformance runner for every single-request vector in
 * spec/fixtures/request-vectors.json, ported from Go's TestRequestVectors +
 * checkOutcome (server/verify_test.go). Each case builds its own independent
 * state (fresh MemoryState seeded from the fixture registry, fresh NonceStore
 * preseeded from the fixture cache, injected fixed clock, and no authorization
 * rules — the admin-only contract has none), runs the exact body bytes through the
 * Verifier with the REAL native tools, and compares result, kid / HTTP status
 * + code, nonce_recorded, audit, structured (with the `<b64u43>` wildcard rule
 * of spec/tests/README.md) and the verified caller identity: present and
 * frozen on forwarded accepts, absent everywhere else.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64URL, encodeBase64URL } from "../src/encoding.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { MemoryState } from "../src/server/state.js";
import type { RegistryEntry as StateRegistryEntry } from "../src/server/state.js";
import { Verifier } from "../src/server/verify.js";
import type { JsonValue } from "./fixtures.js";
import { loadRegistry, loadRequestVectors } from "./fixtures.js";
import type { HeaderPair, RegistryEntry as FixtureRegistryEntry } from "./fixtures.js";

/** Builder form of a readonly src type (exactOptionalPropertyTypes-safe writes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

/** Fixture registry entry -> src registry entry; optional fields are assigned only when defined (exactOptionalPropertyTypes). */
function toStateEntry(e: FixtureRegistryEntry): StateRegistryEntry {
  const out: Mutable<StateRegistryEntry> = {
    kid: e.kid,
    publicKey: e.publicKey,
    name: e.name,
  };
  if (e.admin !== undefined) {
    out.admin = e.admin;
  }
  if (e.notBefore !== undefined) {
    out.notBefore = e.notBefore;
  }
  if (e.notAfter !== undefined) {
    out.notAfter = e.notAfter;
  }
  return out;
}

/**
 * The `<b64u43>` rule of spec/tests/README.md: a string in the expectation
 * equal to "<b64u43>" matches any canonical 43-character base64url string
 * (decode/encode round-trips, rejecting non-canonical trailing bits). Objects
 * and arrays must match recursively; everything else compares strictly.
 */
function deepMatch(expected: JsonValue, actual: unknown): boolean {
  if (expected === "<b64u43>") {
    if (typeof actual !== "string" || actual.length !== 43 || !/^[A-Za-z0-9_-]{43}$/.test(actual)) {
      return false;
    }
    try {
      return encodeBase64URL(decodeBase64URL(actual)) === actual;
    } catch {
      return false;
    }
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) {
      return false;
    }
    return expected.every((item, i) => deepMatch(item, actual[i]));
  }
  if (typeof expected === "object" && expected !== null) {
    if (typeof actual !== "object" || actual === null || Array.isArray(actual)) {
      return false;
    }
    const want = expected as { readonly [key: string]: JsonValue };
    const got = actual as Record<string, unknown>;
    // Same key SETS: an unexpected extra key is a mismatch, not a pass.
    if (Object.keys(got).length !== Object.keys(want).length) {
      return false;
    }
    return Object.keys(want).every((key) => Object.hasOwn(got, key) && deepMatch(want[key] as JsonValue, got[key]));
  }
  return Object.is(expected, actual);
}

test("request vectors: every case", () => {
  const vectors = loadRequestVectors();
  const cases = vectors.cases;
  assert.ok(cases.length > 0, "no request vectors");
  // The vectors must pin the same registry fixture the runner seeds.
  assert.equal(vectors.registry, "registry.json", "vectors.registry");

  for (const c of cases) {
    // Independent state per case (spec tests README): fresh registry, nonce
    // cache preseeded exactly like Go's CheckAndRecord(n.Kid, n.Nonce, 0,
    // n.RetainUntil) — the return value is deliberately ignored.
    const st = new MemoryState();
    st.update((edit) => {
      for (const e of loadRegistry().keys) {
        edit.putKey(toStateEntry(e));
      }
    });
    const nonces = new NonceStore();
    for (const n of c.state.nonceCache) {
      nonces.checkAndRecord(n.kid, n.nonce, 0, n.retainUntil);
    }
    const now = c.state.now;
    const verifier = new Verifier({
      aud: c.state.aud,
      state: st,
      nonces,
      native: new Native(),
      window: c.state.windowSeconds,
      now: () => now,
    });
    const body = decodeBase64URL(c.request.bodyB64u);
    const res = verifier.verify({
      method: c.request.method,
      target: c.request.target,
      authValues: jackAuthValues(c.request.headers),
      body,
    });

    const label = `case ${c.id}`;
    assert.equal(res.accepted, c.expect.result === "accept", label);
    if (res.accepted) {
      assert.equal(res.kid, c.expect.kid, `${label}: kid`);
    } else {
      assert.equal(res.httpStatus, c.expect.httpStatus, `${label}: httpStatus`);
      assert.equal(res.code, c.expect.code, `${label}: code`);
    }
    // The field is absent in early-failure fixtures: absent means false.
    assert.equal(res.nonceRecorded, c.expect.nonceRecorded ?? false, `${label}: nonceRecorded`);

    if (c.expect.audit === undefined) {
      assert.equal(res.audit, undefined, `${label}: unexpected audit event`);
    } else {
      const want = c.expect.audit;
      assert.ok(res.audit !== undefined, `${label}: missing audit event`);
      assert.equal(res.audit.tool, want.tool, `${label}: audit.tool`);
      assert.equal(res.audit.outcome, want.outcome, `${label}: audit.outcome`);
      assert.equal(res.audit.actorKid, want.actorKid, `${label}: audit.actorKid`);
      // Fixture null means "no code field on the event"; a string must match.
      if (want.code === null) {
        assert.equal(res.audit.code, undefined, `${label}: audit.code`);
      } else {
        assert.equal(res.audit.code, want.code, `${label}: audit.code`);
      }
    }

    // Structured: presence parity, then the <b64u43>-aware deep match against
    // the real tools' result.
    if (c.expect.structured === undefined) {
      assert.equal(res.structured, undefined, `${label}: unexpected structured result`);
    } else {
      assert.ok(res.structured !== undefined, `${label}: missing structured result`);
      assert.ok(deepMatch(c.expect.structured, res.structured), `${label}: structured mismatch`);
    }

    // Identity: only forwarded accepts carry the verified caller identity the
    // SDK hands to the wrapped handler — frozen, and equal to the fixture
    // snapshot; native accepts and every reject carry none.
    if (c.expect.identity !== undefined) {
      assert.ok(res.identity !== undefined, `${label}: missing identity`);
      assert.deepStrictEqual({ ...res.identity }, c.expect.identity, `${label}: identity`);
      assert.ok(Object.isFrozen(res.identity), `${label}: identity must be frozen`);
    } else {
      assert.equal(res.identity, undefined, `${label}: unexpected identity`);
    }
    // requestSig / rpcId / tool are deliberately not compared (Go's
    // checkOutcome does not either).
  }
});
