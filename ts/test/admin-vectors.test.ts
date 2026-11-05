/**
 * Port of Go's TestAdminSequences (server/verify_test.go) with the full
 * expectation set, run against the REAL native tools (ts/src/server/native.ts):
 * every admin sequence step is compared for result / kid / status + code,
 * nonce_recorded, audit, structured (with the `<b64u43>` wildcard rule of
 * spec/tests/README.md) and the `after` state summary. Before any step runs,
 * each case is cross-checked against the generator's documented seeded-code
 * derivation (spec/tests/README.md "Sequences", spec/tools/gen-fixtures.mjs):
 * code = base64url(SHA-256("seeded invite <label>")), and
 * invite_id = base64url(SHA-256(code bytes)).
 *
 * The second test re-runs the seven request vectors that
 * verify-vectors.test.ts could only run against a test double, this time
 * through the real tools, comparing the full expectation including structured.
 *
 * Helpers (jackAuthValues, toStateEntry, toStateInvite, policyFor, deepMatch)
 * are local copies: verify-vectors.test.ts and fixtures.ts export none of them.
 */
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { classifyBody, parseJsonRaw, TOOL_ENROLL, Verifier } from "../src/server/verify.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { parsePolicy } from "../src/server/policy.js";
import { MemoryState } from "../src/server/state.js";
import type { InviteRecord as StateInviteRecord, RegistryEntry as StateRegistryEntry, StateView } from "../src/server/state.js";
import type {
  AfterState,
  AdminVectors,
  Expect,
  HeaderPair,
  InviteRecord as FixtureInviteRecord,
  RegistryEntry as FixtureRegistryEntry,
  RequestVectors,
  Step,
  UserSummary,
} from "./fixtures.js";
import { type JsonValue, loadAdminVectors, loadDefaultPolicy, loadRegistry, loadRequestVectors, loadWildcardPolicy } from "./fixtures.js";

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

/** Fixture invite record -> src invite record; optional fields are assigned only when defined (exactOptionalPropertyTypes). */
function toStateInvite(i: FixtureInviteRecord): StateInviteRecord {
  const out: Mutable<StateInviteRecord> = {
    inviteId: i.inviteId,
    scopes: i.scopes,
    createdBy: i.createdBy,
    createdAt: i.createdAt,
    expiresAt: i.expiresAt,
  };
  if (i.kind !== undefined) {
    out.kind = i.kind;
  }
  if (i.keyTtlSeconds !== undefined) {
    out.keyTtlSeconds = i.keyTtlSeconds;
  }
  return out;
}

const policyCache = new Map<string, ReturnType<typeof parsePolicy>>();

/**
 * Resolves an admin case's policy NAME to a parsed policy: exactly the two
 * fixture policies exist ("default" -> policy.json, "wildcard" ->
 * policy-wildcard.json); anything else is a fixture error.
 */
function policyFor(name: string): ReturnType<typeof parsePolicy> {
  const cached = policyCache.get(name);
  if (cached !== undefined) {
    return cached;
  }
  const doc = name === "default" ? loadDefaultPolicy() : name === "wildcard" ? loadWildcardPolicy() : undefined;
  if (doc === undefined) {
    throw new Error(`unknown policy "${name}"`);
  }
  const parsed = parsePolicy(JSON.stringify(doc));
  policyCache.set(name, parsed);
  return parsed;
}

/** Request-vectors variant: resolves through the vectors' OWN name->file mapping. */
function requestPolicyFor(vectors: RequestVectors, name: string): ReturnType<typeof parsePolicy> {
  const file = vectors.policies[name];
  if (file === undefined) {
    throw new Error(`unknown policy "${name}"`);
  }
  const cached = policyCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const doc = file === "policy.json" ? loadDefaultPolicy() : file === "policy-wildcard.json" ? loadWildcardPolicy() : undefined;
  if (doc === undefined) {
    throw new Error(`no typed loader for policy fixture "${file}"`);
  }
  const parsed = parsePolicy(JSON.stringify(doc));
  policyCache.set(file, parsed);
  return parsed;
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

/** The after.users shape the fixtures expect: summary of the registry keyed by name (Go summarize). */
function summarize(view: StateView, now: number): AfterState {
  const keys = [...view.keys].sort((a, b) => (a.name < b.name ? -1 : 1));
  const users: UserSummary[] = keys.map((k) => {
    const out: Mutable<UserSummary> = {
      name: k.name,
      kid: k.kid,
      kind: k.kind ?? "human",
      scopes: [...(k.scopes ?? [])].sort(),
    };
    // Always present as number|null: deepStrictEqual treats a missing key
    // differently from an explicit null.
    out.notBefore = k.notBefore ?? null;
    out.notAfter = k.notAfter ?? null;
    return out;
  });
  return { users, invites: view.invites.filter((i) => now < i.expiresAt).length };
}

/**
 * The full per-step expectation check shared by both tests: result / kid or
 * status + code, nonce_recorded, audit parity and structured deepMatch.
 */
function checkOutcome(label: string, res: ReturnType<Verifier["verify"]>, want: Expect): void {
  assert.equal(res.accepted, want.result === "accept", `${label}: accepted`);
  if (res.accepted) {
    assert.equal(res.kid, want.kid, `${label}: kid`);
  } else {
    assert.equal(res.httpStatus, want.httpStatus, `${label}: httpStatus`);
    assert.equal(res.code, want.code, `${label}: code`);
  }
  // The field is absent in early-failure fixtures: absent means false.
  assert.equal(res.nonceRecorded, want.nonceRecorded ?? false, `${label}: nonceRecorded`);

  if (want.audit === undefined) {
    assert.equal(res.audit, undefined, `${label}: unexpected audit event`);
  } else {
    const a = res.audit;
    assert.ok(a !== undefined, `${label}: missing audit event`);
    assert.equal(a.tool, want.audit.tool, `${label}: audit.tool`);
    assert.equal(a.outcome, want.audit.outcome, `${label}: audit.outcome`);
    assert.equal(a.actorKid, want.audit.actorKid, `${label}: audit.actorKid`);
    // Fixture null means "no code field on the event"; a string must match.
    if (want.audit.code === null) {
      assert.equal(a.code, undefined, `${label}: audit.code`);
    } else {
      assert.equal(a.code, want.audit.code, `${label}: audit.code`);
    }
  }

  // Structured: presence parity first, then the <b64u43>-aware deep match.
  if (want.structured === undefined) {
    assert.equal(res.structured, undefined, `${label}: unexpected structured result`);
  } else {
    assert.ok(res.structured !== undefined, `${label}: missing structured result`);
    assert.ok(deepMatch(want.structured, res.structured), `${label}: structured mismatch`);
  }
}

/**
 * The generator's seeded-code labels (spec/tools/gen-fixtures.mjs inv() and
 * enrollArgs()): every pre-seeded invite and every 32-byte enroll code in
 * these fixtures derives from one of them.
 */
const SEEDED_LABELS: readonly string[] = ["i1", "live", "old", "nope"];

/** The generator's derivation: b64url(SHA-256("seeded invite <label>")). */
function seededInviteCode(label: string): string {
  return encodeBase64URL(createHash("sha256").update(`seeded invite ${label}`).digest());
}

/** The invite-id rule of spec 03 section 3.3: b64url(SHA-256(code bytes)). */
function inviteIdOfCode(code: string): string {
  return encodeBase64URL(createHash("sha256").update(Buffer.from(decodeBase64URLFixed(code, 32))).digest());
}

/** The string "code" member of a step's jack.enroll arguments when it strictly decodes to 32 bytes; undefined otherwise. */
function enrollCodeOf(step: Step): string | undefined {
  const msg = classifyBody(decodeBase64URL(step.request.bodyB64u));
  if (msg === undefined || !msg.hasTool || msg.tool !== TOOL_ENROLL || msg.arguments === undefined) {
    return undefined;
  }
  let code: JsonValue | undefined;
  try {
    code = parseJsonRaw(msg.arguments).source.members?.get("code")?.value;
  } catch {
    return undefined;
  }
  if (typeof code !== "string") {
    return undefined;
  }
  try {
    decodeBase64URLFixed(code, 32);
  } catch {
    return undefined; // not canonical 32 bytes: nothing to cross-check
  }
  return code;
}

test("admin vectors: every sequence through the real verifier and native tools", () => {
  const vectors: AdminVectors = loadAdminVectors();
  const cases = vectors.cases;
  assert.ok(cases.length > 0, "no admin vectors");

  for (const c of cases) {
    // Cases are independent (spec tests README): fresh state per case.
    const st = new MemoryState();
    st.update((edit) => {
      for (const e of c.state.registry) {
        edit.putKey(toStateEntry(e));
      }
      for (const i of c.state.invites) {
        edit.putInvite(toStateInvite(i));
      }
    });
    // Nonce cache preseeded exactly like Go's CheckAndRecord(n.Kid, n.Nonce, 0,
    // n.RetainUntil) — the return value is deliberately ignored.
    const nonces = new NonceStore();
    for (const n of c.state.nonceCache) {
      nonces.checkAndRecord(n.kid, n.nonce, 0, n.retainUntil);
    }
    // The clock closes over the case's constant now; never re-read c.state.now.
    const now = c.state.now;
    const verifier = new Verifier({
      aud: c.state.aud,
      state: st,
      nonces,
      policy: policyFor(c.state.policy),
      native: new Native(),
      window: c.state.windowSeconds,
      now: () => now,
    });

    // Fixture cross-checks, run from the immutable case document BEFORE any
    // step executes: no state a step might change is consulted.
    // (i) every seeded invite_id is the documented derivation of a seeded code;
    for (const seeded of c.state.invites) {
      assert.ok(
        SEEDED_LABELS.some((l) => inviteIdOfCode(seededInviteCode(l)) === seeded.inviteId),
        `case ${c.id}: seeded invite_id ${seeded.inviteId} is not derived from any documented seeded code`,
      );
    }
    // (ii) every 32-byte code in the case's enroll requests is a documented seeded code.
    for (const step of c.steps) {
      const code = enrollCodeOf(step);
      if (code !== undefined) {
        assert.ok(
          SEEDED_LABELS.some((l) => seededInviteCode(l) === code),
          `case ${c.id}: enroll code ${code} is not the seeded code of any documented label`,
        );
      }
    }

    for (let i = 0; i < c.steps.length; i++) {
      const step = c.steps[i];
      // noUncheckedIndexedAccess: the loop bound guarantees presence.
      assert.ok(step !== undefined, `case ${c.id}: step ${i} missing`);
      const label = `case ${c.id} step ${i}`;
      const body = decodeBase64URL(step.request.bodyB64u);
      const res = verifier.verify({
        method: step.request.method,
        target: step.request.target,
        authValues: jackAuthValues(step.request.headers),
        body,
      });
      // (b)-(e) Full expectation set.
      checkOutcome(label, res, step.expect);
      // (f) after: always present in these fixtures; compare the built summary.
      assert.ok(step.expect.after !== undefined, `${label}: missing after expectation`);
      const view = st.view();
      assert.deepStrictEqual(summarize(view, now), step.expect.after, `${label}: state after the step`);
    }
  }
});

test("request vectors: jack.* cases through the real native tools", () => {
  const vectors = loadRequestVectors();
  assert.ok(vectors.cases.length > 0, "no request vectors");
  assert.equal(vectors.registry, "registry.json", "vectors.registry");

  // Select by content, not by id: only tools/call cases whose tool is a
  // jack.* native tool exercise the real tools' verifier-visible behavior.
  const selected = vectors.cases.filter((c) => {
    const msg = classifyBody(decodeBase64URL(c.request.bodyB64u));
    return msg !== undefined && msg.hasTool && msg.tool.startsWith("jack.");
  });
  assert.ok(selected.length > 0, "no jack.* request vectors selected");

  for (const c of selected) {
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
      policy: requestPolicyFor(vectors, c.state.policy),
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
    // Same full expectation set as the sequences, minus `after` (which does
    // not exist on request vectors).
    checkOutcome(label, res, c.expect);
  }
});
