/**
 * Port of Go's TestAdminSequences (server/verify_test.go) with the full
 * expectation set, run against the REAL native tools (ts/src/server/native.ts)
 * under the admin-only contract (no authorization rules exist): every admin sequence step
 * is compared for result / kid / status + code, nonce_recorded, audit and
 * structured (with the `<b64u43>` wildcard rule of spec/tests/README.md), plus
 * the full durable `after` state — users with admin/bounds always present,
 * invites as full records where implementation-created ids are scrubbed to the
 * "<b64u43>" placeholder — and a raw nonmutation check: a rejected step must
 * leave the serialized durable data byte-identical (member presence included).
 *
 * Before any step runs, each case is cross-checked against the generator's
 * documented seeded-code derivation (spec/tests/README.md "Sequences",
 * spec/tools/gen-fixtures.mjs): code = base64url(SHA-256("seeded invite
 * <label>")), and invite_id = base64url(SHA-256(code bytes)).
 *
 * The second test re-runs the request vectors' jack.* cases through the real
 * tools, comparing the full expectation including structured.
 *
 * Helpers (jackAuthValues, toStateEntry, toStateInvite, deepMatch) are local
 * copies: verify-vectors.test.ts and fixtures.ts export none of them.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { classifyBody, parseJsonRaw, TOOL_ENROLL, Verifier } from "../src/server/verify.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { MemoryState, serializeInviteRecord, serializeRegistryEntry } from "../src/server/state.js";
import { openFileState } from "../src/server/state-file.js";
import type {
  InviteRecord as StateInviteRecord,
  RegistryEntry as StateRegistryEntry,
  StateView,
} from "../src/server/state.js";
import type {
  AfterInvite,
  AfterUser,
  AdminVectors,
  Expect,
  HeaderPair,
  InviteRecord as FixtureInviteRecord,
  RegistryEntry as FixtureRegistryEntry,
  Step,
} from "./fixtures.js";
import { type JsonValue, loadAdminVectors, loadRegistry, loadRequestVectors } from "./fixtures.js";

/** Builder form of a readonly type (exactOptionalPropertyTypes-safe writes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** New temp directory cleaned up when the test ends. */
function tempDir(t: { after(fn: () => void): unknown }): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-jack-admin-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

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

/** Fixture invite record -> src invite record; optional fields are assigned only when defined (exactOptionalPropertyTypes). */
function toStateInvite(i: FixtureInviteRecord): StateInviteRecord {
  const out: Mutable<StateInviteRecord> = {
    inviteId: i.inviteId,
    createdBy: i.createdBy,
    createdAt: i.createdAt,
    expiresAt: i.expiresAt,
  };
  if (i.admin !== undefined) {
    out.admin = i.admin;
  }
  if (i.keyTtlSeconds !== undefined) {
    out.keyTtlSeconds = i.keyTtlSeconds;
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

/** Placeholder that matches any implementation-created invite id (spec tests README "Sequences"). */
const PLACEHOLDER = "<b64u43>";

/** The generator's stable invite sort: scrubbed invite_id text, then created_at. */
function compareAfterInvites(a: AfterInvite, b: AfterInvite): number {
  if (a.inviteId !== b.inviteId) {
    return a.inviteId < b.inviteId ? -1 : 1;
  }
  if (a.createdAt !== b.createdAt) {
    return a.createdAt < b.createdAt ? -1 : 1;
  }
  return 0;
}

/** Validate implementation-created ids at the expectation boundary, before scrubbing. */
function assertGeneratedInviteId(inviteId: string, label: string): void {
  assert.doesNotThrow(
    () => decodeBase64URLFixed(inviteId, 32),
    `${label}: generated invite id must be canonical 32-byte base64url`,
  );
}

/** Compare complete persisted invite records before after-state expectations replace generated ids with placeholders. */
function assertPersistedInvites(
  live: StateView,
  reopened: StateView,
  preExistingIds: ReadonlySet<string>,
  label: string,
): void {
  for (const invite of live.invites) {
    if (!preExistingIds.has(invite.inviteId)) {
      assertGeneratedInviteId(invite.inviteId, `${label}: live state`);
    }
  }
  for (const invite of reopened.invites) {
    if (!preExistingIds.has(invite.inviteId)) {
      assertGeneratedInviteId(invite.inviteId, `${label}: reopened state`);
    }
  }
  const liveInvites = live.invites
    .map((invite) => ({
      inviteId: invite.inviteId,
      admin: invite.admin === true,
      createdBy: invite.createdBy,
      createdAt: invite.createdAt,
      expiresAt: invite.expiresAt,
      ...(invite.keyTtlSeconds !== undefined ? { keyTtlSeconds: invite.keyTtlSeconds } : {}),
    }))
    .sort((a, b) => (a.inviteId < b.inviteId ? -1 : a.inviteId > b.inviteId ? 1 : 0));
  const reopenedInvites = reopened.invites
    .map((invite) => ({
      inviteId: invite.inviteId,
      admin: invite.admin === true,
      createdBy: invite.createdBy,
      createdAt: invite.createdAt,
      expiresAt: invite.expiresAt,
      ...(invite.keyTtlSeconds !== undefined ? { keyTtlSeconds: invite.keyTtlSeconds } : {}),
    }))
    .sort((a, b) => (a.inviteId < b.inviteId ? -1 : a.inviteId > b.inviteId ? 1 : 0));
  assert.deepStrictEqual(reopenedInvites, liveInvites, `${label}: persisted invite records changed`);
}

/**
 * The full durable after-state the fixtures expect, built from the live view:
 * users as complete entries (admin always boolean, bounds always number|null,
 * sorted by name) and invites as full records with implementation-created ids
 * scrubbed to the placeholder (ids present in the case's INITIAL state are
 * pre-seeded and keep their literal id), key_ttl_seconds spread only when
 * actually set — never null.
 */
function afterStateOf(view: StateView, preExistingIds: ReadonlySet<string>): {
  users: readonly AfterUser[];
  invites: readonly AfterInvite[];
} {
  const users: AfterUser[] = [...view.keys]
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .map((k) => ({
      kid: k.kid,
      publicKey: k.publicKey,
      name: k.name,
      admin: k.admin === true,
      notBefore: k.notBefore ?? null,
      notAfter: k.notAfter ?? null,
    }));
  const invites = view.invites
    .map((i): AfterInvite => {
      if (!preExistingIds.has(i.inviteId)) {
        assertGeneratedInviteId(i.inviteId, "after-state generated invite");
      }
      const out: Mutable<AfterInvite> = {
        inviteId: preExistingIds.has(i.inviteId) ? i.inviteId : PLACEHOLDER,
        admin: i.admin === true,
        createdBy: i.createdBy,
        createdAt: i.createdAt,
        expiresAt: i.expiresAt,
      };
      // Never null: an unset TTL is absent, matching the fixture records.
      if (i.keyTtlSeconds !== undefined) {
        out.keyTtlSeconds = i.keyTtlSeconds;
      }
      return out;
    })
    .sort(compareAfterInvites);
  return { users, invites };
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

function inviteSnapshot(inviteIds: readonly string[]): StateView {
  return {
    keys: [],
    invites: inviteIds.map((inviteId) => ({
      inviteId,
      createdBy: "fixture-admin",
      createdAt: 1,
      expiresAt: 2,
    })),
  };
}

function writeInviteSnapshot(path: string, view: StateView): void {
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      keys: [],
      invites: view.invites.map(serializeInviteRecord),
    }),
  );
}

function isCanonicalIdAssertion(err: unknown): boolean {
  return err instanceof Error && err.name === "AssertionError" && err.message.includes("canonical 32-byte base64url");
}

test("admin persisted-invite oracle binds canonical IDs to complete records", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "records.json");
  const generatedA = encodeBase64URL(new Uint8Array(32).fill(7));
  const generatedB = encodeBase64URL(new Uint8Array(32).fill(8));
  assert.notEqual(generatedA, generatedB, "generated control IDs must be distinct");
  const inviteA: StateInviteRecord = {
    inviteId: generatedA,
    admin: true,
    createdBy: "creator-a",
    createdAt: 1,
    expiresAt: 20,
    keyTtlSeconds: 60,
  };
  const inviteB: StateInviteRecord = {
    inviteId: generatedB,
    createdBy: "creator-b",
    createdAt: 2,
    expiresAt: 30,
  };
  const liveView: StateView = { keys: [], invites: [inviteA, inviteB] };

  writeInviteSnapshot(path, liveView);
  const reopenedLiveView = openFileState(path).view();
  assert.doesNotThrow(() => assertPersistedInvites(liveView, reopenedLiveView, new Set(), "unchanged records"));

  const reorderedLiveView: StateView = { keys: [], invites: [inviteB, inviteA] };
  writeInviteSnapshot(path, reorderedLiveView);
  const reopenedReorderedView = openFileState(path).view();
  assert.doesNotThrow(() =>
    assertPersistedInvites(reorderedLiveView, reopenedReorderedView, new Set(), "reordered storage records"),
  );

  // Corrupt the on-disk invite IDs while retaining the independently specified record contents.
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      keys: [],
      invites: [
        {
          invite_id: generatedB,
          admin: true,
          created_by: "creator-a",
          created_at: 1,
          expires_at: 20,
          key_ttl_seconds: 60,
        },
        {
          invite_id: generatedA,
          created_by: "creator-b",
          created_at: 2,
          expires_at: 30,
        },
      ],
    }),
  );
  const swappedView = openFileState(path).view();
  assert.deepStrictEqual(
    swappedView.invites.map((invite) => invite.inviteId).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    liveView.invites.map((invite) => invite.inviteId).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    "swapped records retain the live ID multiset",
  );
  assert.deepStrictEqual(
    afterStateOf(swappedView, new Set()),
    afterStateOf(liveView, new Set()),
    "after-state masks the swapped ID-to-record associations",
  );
  assert.throws(
    () => assertPersistedInvites(liveView, swappedView, new Set(), "swapped persisted records"),
    (err: unknown) =>
      err instanceof Error && err.name === "AssertionError" && err.message.includes("persisted invite records changed"),
  );
});

test("admin persisted-invite oracle accepts canonical IDs and preserves preseeded literals", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const generatedA = encodeBase64URL(new Uint8Array(32).fill(1));
  const generatedB = encodeBase64URL(new Uint8Array(32).fill(2));
  assert.notEqual(generatedA, generatedB, "generated control IDs must be distinct");
  const fixtureLiteral = "fixture-literal-id";
  const preExistingIds = new Set([fixtureLiteral]);

  const liveA = inviteSnapshot([generatedA, fixtureLiteral]);
  writeInviteSnapshot(path, liveA);
  const reopenedA = openFileState(path).view();
  assert.doesNotThrow(() => assertPersistedInvites(liveA, reopenedA, preExistingIds, "unchanged generated invite record"));
  assert.deepStrictEqual(afterStateOf(liveA, preExistingIds).invites, [
    {
      inviteId: PLACEHOLDER,
      admin: false,
      createdBy: "fixture-admin",
      createdAt: 1,
      expiresAt: 2,
    },
    {
      inviteId: fixtureLiteral,
      admin: false,
      createdBy: "fixture-admin",
      createdAt: 1,
      expiresAt: 2,
    },
  ]);

  const liveB = inviteSnapshot([generatedB]);
  writeInviteSnapshot(path, liveB);
  const reopenedB = openFileState(path).view();
  assert.doesNotThrow(() => assertPersistedInvites(liveB, reopenedB, new Set(), "independent generated invite record"));
});

test("admin persisted-invite oracle detects persisted rewrites and rejects invalid generated IDs", (t) => {
  const dir = tempDir(t);
  const generatedA = encodeBase64URL(new Uint8Array(32).fill(3));
  const generatedB = encodeBase64URL(new Uint8Array(32).fill(4));
  const path = join(dir, "corrupt.json");
  const live = inviteSnapshot([generatedA]);
  writeInviteSnapshot(path, live);
  const liveFileView = openFileState(path).view();
  const wire = readFileSync(path, "utf8");
  assert.ok(wire.includes(generatedA), "wire invite_id must contain the live generated ID");
  writeFileSync(path, wire.replace(generatedA, generatedB));
  const rewritten = openFileState(path).view();
  assert.throws(
    () => assertPersistedInvites(liveFileView, rewritten, new Set(), "corrupted writer roundtrip"),
    (err: unknown) =>
      err instanceof Error && err.name === "AssertionError" && err.message.includes("persisted invite records changed"),
  );

  const validPath = join(dir, "valid.json");
  const validView = inviteSnapshot([generatedA]);
  writeInviteSnapshot(validPath, validView);
  const validReopened = openFileState(validPath).view();
  const invalidIds: readonly { readonly label: string; readonly inviteId: string }[] = [
    { label: "invalid alphabet", inviteId: `!${generatedA.slice(1)}` },
    { label: "decoded size 31", inviteId: encodeBase64URL(new Uint8Array(31).fill(5)) },
    { label: "decoded size 33", inviteId: encodeBase64URL(new Uint8Array(33).fill(6)) },
    { label: "padding", inviteId: `${generatedA}=` },
    { label: "noncanonical unused trailing bits", inviteId: `${"A".repeat(42)}B` },
  ];
  for (const [index, invalid] of invalidIds.entries()) {
    const invalidPath = join(dir, `invalid-${index}.json`);
    const invalidView = inviteSnapshot([invalid.inviteId]);
    writeInviteSnapshot(invalidPath, invalidView);
    // Loading is deliberately permissive about nonempty invite_id syntax; the oracle must reject it.
    const reopenedInvalid = openFileState(invalidPath).view();
    assert.throws(
      () => afterStateOf(invalidView, new Set()),
      isCanonicalIdAssertion,
      `${invalid.label}: after-state must reject the generated ID before scrubbing`,
    );
    assert.throws(
      () => assertPersistedInvites(invalidView, validReopened, new Set(), `${invalid.label}: invalid live state`),
      isCanonicalIdAssertion,
      `${invalid.label}: persisted-invite oracle must reject an invalid live ID`,
    );
    assert.throws(
      () => assertPersistedInvites(validView, reopenedInvalid, new Set(), `${invalid.label}: invalid reopened state`),
      isCanonicalIdAssertion,
      `${invalid.label}: persisted-invite oracle must reject an invalid reopened ID`,
    );
    assert.throws(
      () => assertPersistedInvites(invalidView, reopenedInvalid, new Set(), invalid.label),
      isCanonicalIdAssertion,
      `${invalid.label}: matching invalid IDs must not pass by equality`,
    );
  }
});

test("admin vectors: every sequence through the real verifier and native tools", (t) => {
  const vectors: AdminVectors = loadAdminVectors();
  const cases = vectors.cases;
  assert.ok(cases.length > 0, "no admin vectors");
  const dir = tempDir(t);

  for (const c of cases) {
    // Cases are independent (spec tests README): serialize fixture state once,
    // then drive the sequence against the actual file-backed store.
    const path = join(dir, "state.json");
    const initialDoc = {
      version: 1,
      keys: c.state.registry.map((entry) => serializeRegistryEntry(toStateEntry(entry))),
      invites: c.state.invites.map((invite) => serializeInviteRecord(toStateInvite(invite))),
    };
    writeFileSync(path, JSON.stringify(initialDoc));
    let st = openFileState(path);
    // Nonce cache preseeded exactly like Go's CheckAndRecord(n.Kid, n.Nonce, 0,
    // n.RetainUntil) — the return value is deliberately ignored.
    const nonces = new NonceStore();
    for (const n of c.state.nonceCache) {
      nonces.checkAndRecord(n.kid, n.nonce, 0, n.retainUntil);
    }
    // The clock closes over the case's constant now; never re-read c.state.now.
    const now = c.state.now;
    // Invite ids present in the INITIAL state are pre-seeded: they keep their
    // literal id in after.invites; anything created during the sequence is
    // implementation-created and appears as the "<b64u43>" placeholder.
    const preExistingIds = new Set(c.state.invites.map((i) => i.inviteId));

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
      // Raw nonmutation snapshots: compare both the in-memory store and exact
      // disk bytes, including optional-member presence.
      const beforeMemory = JSON.stringify(st.view());
      const beforeBytes = readFileSync(path);
      const verifier = new Verifier({
        aud: c.state.aud,
        state: st,
        nonces,
        native: new Native(),
        window: c.state.windowSeconds,
        now: () => now,
      });
      const body = decodeBase64URL(step.request.bodyB64u);
      const res = verifier.verify({
        method: step.request.method,
        target: step.request.target,
        authValues: jackAuthValues(step.request.headers),
        body,
      });
      // (b)-(e) Full expectation set.
      checkOutcome(label, res, step.expect);
      // (f) EVERY step — accepted or rejected — must consume the literal
      // expect.after: a rejected step's after equals the pre-step state, so a
      // compare here is simultaneously the literal postcondition AND the
      // durable-nonmutation check.
      assert.ok(step.expect.after !== undefined, `${label}: missing after expectation`);
      const liveView = st.view();
      const reopened = openFileState(path);
      const reopenedView = reopened.view();
      assertPersistedInvites(liveView, reopenedView, preExistingIds, `${label}: file reopen`);
      assert.deepStrictEqual(
        afterStateOf(liveView, preExistingIds),
        step.expect.after,
        `${label}: in-memory state after the step`,
      );
      assert.deepStrictEqual(
        afterStateOf(reopenedView, preExistingIds),
        step.expect.after,
        `${label}: reopened file state after the step`,
      );
      if (!res.accepted) {
        assert.deepEqual(readFileSync(path), beforeBytes, `${label}: rejected step changed raw file bytes`);
        assert.equal(JSON.stringify(st.view()), beforeMemory, `${label}: rejected step mutated in-memory state`);
      }
      st = reopened;
    }

    // The last literal after expectation is already checked against the real
    // writer and a fresh strict-reader reopen above; do not rewrite the file
    // from an in-memory snapshot here, which could mask writer bugs.
    const finalStep = c.steps[c.steps.length - 1];
    assert.ok(finalStep !== undefined, `case ${c.id}: no steps`);
    assert.ok(finalStep.expect.after !== undefined, `case ${c.id}: missing final after expectation`);
    const reopened = openFileState(path);
    const finalLiveView = st.view();
    const finalReopenedView = reopened.view();
    assertPersistedInvites(finalLiveView, finalReopenedView, preExistingIds, `case ${c.id}: final reopen`);
    assert.deepStrictEqual(
      afterStateOf(finalReopenedView, preExistingIds),
      finalStep.expect.after,
      `case ${c.id}: final state after reopen`,
    );
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
