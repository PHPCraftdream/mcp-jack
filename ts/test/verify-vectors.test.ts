/**
 * Conformance runner for every single-request vector in
 * spec/fixtures/request-vectors.json, ported from Go's TestRequestVectors +
 * checkOutcome (server/verify_test.go). Each case builds its own independent
 * state (fresh MemoryState, fresh NonceStore preseeded from the fixture cache,
 * fixture-named policy, injected fixed clock), runs the exact body bytes
 * through the Verifier, and compares result, kid / HTTP status + code,
 * nonce_recorded and audit with the fixture expectation.
 *
 * TestAdminSequences is a LATER task and is deliberately NOT ported here.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Code, JackError } from "../src/errors.js";
import { decodeBase64URL } from "../src/encoding.js";
import type { NativeCall, NativeResult, NativeTools } from "../src/server/verify.js";
import { Verifier } from "../src/server/verify.js";
import { NonceStore } from "../src/server/nonce.js";
import { parsePolicy } from "../src/server/policy.js";
import { MemoryState } from "../src/server/state.js";
import type { RegistryEntry as StateRegistryEntry } from "../src/server/state.js";
import { loadDefaultPolicy, loadRegistry, loadRequestVectors, loadWildcardPolicy } from "./fixtures.js";
import type { HeaderPair, PolicyDocument, RegistryEntry as FixtureRegistryEntry, RequestVectors } from "./fixtures.js";

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
    scopes: e.scopes,
  };
  if (e.kind !== undefined) {
    out.kind = e.kind;
  }
  if (e.notBefore !== undefined) {
    out.notBefore = e.notBefore;
  }
  if (e.notAfter !== undefined) {
    out.notAfter = e.notAfter;
  }
  return out;
}

const policyCache = new Map<string, ReturnType<typeof parsePolicy>>();

/** Resolves a case's policy name through the vectors' OWN name->file mapping; the file must be one with a typed loader. */
function policyFor(vectors: RequestVectors, name: string): ReturnType<typeof parsePolicy> {
  const file = vectors.policies[name];
  if (file === undefined) {
    throw new Error(`unknown policy "${name}"`);
  }
  const cached = policyCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const doc: PolicyDocument | undefined =
    file === "policy.json" ? loadDefaultPolicy() : file === "policy-wildcard.json" ? loadWildcardPolicy() : undefined;
  if (doc === undefined) {
    throw new Error(`no typed loader for policy fixture "${file}"`);
  }
  const parsed = parsePolicy(JSON.stringify(doc));
  policyCache.set(file, parsed);
  return parsed;
}

/**
 * TEST DOUBLE, not the real native tools. It reproduces ONLY spec 03 section 4
 * rule 1 — the admin gate — the one piece of native-tool behavior that
 * verifier-level expectations depend on: an admin tool called without the
 * admin scope is rejected. Enrollment/rotation/user/invite logic is the later
 * ts/src/server/native.ts task. Because the double's structured result is the
 * empty object `{}`, the fixture `structured` comparisons for the two native
 * accept cases are skipped below (see the comment at the structured check).
 */
class AdminGateNativeTools implements NativeTools {
  call(c: NativeCall): NativeResult {
    if (c.tool.startsWith("jack.admin.") && !(c.caller?.scopes ?? []).includes("admin")) {
      throw new JackError(403, Code.INSUFFICIENT_SCOPE, "the caller lacks admin");
    }
    return { structured: {} };
  }
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
      policy: policyFor(vectors, c.state.policy),
      native: new AdminGateNativeTools(),
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

    // The two native accept cases (native-whoami, native-admin-list) expect a
    // real structured result, but AdminGateNativeTools returns `{}`; the
    // comparison is skipped until the later ts/src/server/native.ts task
    // provides the real tools. Nothing else is assertable here.
    if (c.expect.structured !== undefined) {
      continue;
    }
    // requestSig / rpcId / tool are deliberately not compared (Go's
    // checkOutcome does not either).
  }
});
