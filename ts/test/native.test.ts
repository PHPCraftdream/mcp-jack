/**
 * Tests for the protocol-native tools of spec 03 (admin-only contract),
 * ported from Go's native_test.go (TestBootstrapAdminThenEnroll,
 * TestInviteCodeIsNeverStored, TestLastAdministratorSurvivesConcurrentRevokes,
 * TestAdminToolsRequireAdminBeforeArguments) and extended for the set_admin
 * tool. Calls go to Native.call DIRECTLY (no Verifier, no signatures — the
 * verifier owns authentication; Native trusts its NativeCall), with the
 * default CSPRNG like Go's NativeOptions{}.
 */
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { Code, JackError } from "../src/errors.js";
import { rotateProofString } from "../src/signing.js";
import { Native, activeAdmins, bootstrapAdmin } from "../src/server/native.js";
import {
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_INVITE_LIST,
  TOOL_ADMIN_INVITE_REVOKE,
  TOOL_ADMIN_USER_CREATE,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ADMIN_USER_SET_ADMIN,
  TOOL_ENROLL,
  TOOL_ROTATE_KEY,
  TOOL_WHOAMI,
} from "../src/server/verify.js";
import type { NativeCall } from "../src/server/verify.js";
import {
  MemoryState,
  StateEdit,
  type RegistryEntry,
  type StateStore,
  type StateView,
} from "../src/server/state.js";
import { encodeBase64URL, keyId } from "../src/encoding.js";
import { loadKeys, type TestKey } from "./fixtures.js";

/** The fixtures' clock (Go testNow), in Unix seconds. */
const NOW = 1767225600;

const native = new Native();

/** Fixture key by name; undefined would be a typo in the test, so assert it exists. */
function key(name: string): TestKey {
  const found = loadKeys().keys.find((k) => k.name === name);
  assert.ok(found, `fixture key ${name} expected`);
  return found;
}

/** A registered entry built from a fixture key; admin is present only when true (member-presence rule). */
function entry(k: TestKey, name: string, admin = false): RegistryEntry {
  const e: { -readonly [K in keyof RegistryEntry]: RegistryEntry[K] } = {
    kid: k.kid,
    publicKey: k.publicKey,
    name,
  };
  if (admin) e.admin = true;
  return e;
}

/** NativeCall builder; Native trusts the call, so ts/now/aud/target are boilerplate. */
function call(partial: {
  tool: string;
  arguments?: string | undefined;
  caller?: RegistryEntry | undefined;
  kid?: string;
  state: StateStore;
}): NativeCall {
  return {
    tool: partial.tool,
    arguments: partial.arguments,
    caller: partial.caller,
    kid: partial.kid ?? partial.caller?.kid ?? "",
    ts: NOW,
    now: NOW,
    aud: "aud",
    state: partial.state,
    target: "",
  };
}

/** Runs fn and returns the caught JackError; a non-JackError or success rethrows. */
function jackErrorOf(fn: () => unknown): JackError {
  try {
    fn();
  } catch (err) {
    if (err instanceof JackError) {
      return err;
    }
    throw err;
  }
  throw new Error("expected a JackError throw");
}

/** Runs fn and returns undefined on success or the caught JackError. */
function callError(c: NativeCall): JackError | undefined {
  try {
    native.call(c);
    return undefined;
  } catch (err) {
    if (err instanceof JackError) {
      return err;
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Bootstrap and enrollment.
// ---------------------------------------------------------------------------

test("bootstrapAdmin then enroll consumes the first-admin invite", () => {
  const st = new MemoryState();

  // A ttl outside [1, 604800] is a plain Error and stores nothing.
  assert.throws(() => bootstrapAdmin(st, NOW, 0, {}), /bootstrap ttl/);
  assert.throws(() => bootstrapAdmin(st, NOW, 604801, {}), /bootstrap ttl/);
  assert.equal(st.view().invites.length, 0);

  const code = bootstrapAdmin(st, NOW, 600);
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);
  const invites = st.view().invites;
  assert.equal(invites.length, 1);
  const inv = invites[0];
  assert.ok(inv, "expected exactly one invite");
  // The id is derived here independently of native.ts: base64url(SHA-256(raw code bytes)).
  const expectedId = createHash("sha256").update(Buffer.from(code, "base64url")).digest("base64url");
  assert.equal(inv.inviteId, expectedId);
  assert.equal(inv.admin, true); // the bootstrap invite is an ADMIN invite
  assert.equal(inv.createdBy, "bootstrap");
  assert.equal(inv.createdAt, NOW);
  assert.equal(inv.expiresAt, NOW + 600); // 1767226200

  const newbie = key("newbie");
  const result = native.call(
    call({
      tool: TOOL_ENROLL,
      arguments: JSON.stringify({ code, name: "first", public_key: newbie.publicKey }),
      caller: undefined,
      kid: newbie.kid,
      state: st,
    }),
  );
  assert.deepEqual(result.structured, { kid: newbie.kid, name: "first", admin: true });
  const got = st.lookup(newbie.kid);
  assert.ok(got, "enrolled key missing");
  assert.equal(got.admin, true); // admin inheritance from the invite
  assert.equal(got.notAfter, undefined); // the bootstrap invite sets no key ttl
  assert.equal(st.view().invites.length, 0); // consumed

  // The same code cannot enroll twice: invalid_invite, with the target set even on failure.
  const newbie2 = key("newbie2");
  const again = call({
    tool: TOOL_ENROLL,
    arguments: JSON.stringify({ code, name: "second", public_key: newbie2.publicKey }),
    caller: undefined,
    kid: newbie2.kid,
    state: st,
  });
  const err = jackErrorOf(() => native.call(again));
  assert.equal(err.httpStatus, 403);
  assert.equal(err.code, Code.INVALID_INVITE);
  assert.equal(again.target, "second");
  assert.equal(st.view().invites.length, 0);
});

test("the invite code never appears in the stored state", () => {
  const st = new MemoryState();
  const lowadminKey = key("lowadmin");
  const admin1 = entry(lowadminKey, "admin1", true);
  st.update((e) => e.putKey(admin1));

  // Stale `scopes` argument members are INERT (never invalid_params).
  const result = native.call(
    call({
      tool: TOOL_ADMIN_INVITE_CREATE,
      arguments: '{"scopes":["read"]}',
      caller: admin1,
      state: st,
    }),
  );
  const structured = result.structured as { invite_id: unknown; code: unknown; expires_at: unknown };
  assert.equal(typeof structured.invite_id, "string");
  assert.equal(typeof structured.code, "string");
  const inviteId = structured.invite_id as string;
  const code = structured.code as string;
  assert.equal(inviteId.length, 43);
  assert.equal(code.length, 43);
  // invite.create's default ttl is 3600 seconds.
  assert.equal(structured.expires_at, NOW + 3600); // 1767229200

  const stored = JSON.stringify(st.view());
  assert.ok(!stored.includes(code), "the raw code must not be stored");
  assert.ok(stored.includes(inviteId), "the invite id is stored");
});

test("a deterministic random source pins the exact invite code and id", () => {
  // Expected values are built from the injected bytes with plain node:crypto,
  // so a wrong tool-side derivation (code or id) fails the comparison.
  const injected = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff));
  const expectedCode = injected.toString("base64url");
  const expectedId = createHash("sha256").update(injected).digest("base64url");
  const source = (n: number): Uint8Array => {
    assert.equal(n, 32);
    return new Uint8Array(injected);
  };

  const st = new MemoryState();
  const lowadminKey = key("lowadmin");
  const admin1 = entry(lowadminKey, "admin1", true);
  st.update((e) => e.putKey(admin1));
  const result = new Native({ randomBytes: source }).call(
    call({
      tool: TOOL_ADMIN_INVITE_CREATE,
      arguments: "{}",
      caller: admin1,
      state: st,
    }),
  );
  const structured = result.structured as { invite_id: unknown; code: unknown; expires_at: unknown };
  assert.equal(structured.code, expectedCode);
  assert.equal(structured.invite_id, expectedId);
  assert.equal(structured.expires_at, NOW + 3600);
  const inv = st.view().invites[0];
  assert.ok(inv, "invite expected");
  assert.equal(inv.inviteId, expectedId);
  assert.equal(inv.admin, undefined); // default invite: admin member absent (false)
  assert.equal(inv.createdBy, lowadminKey.kid);

  const boot = new MemoryState();
  const code = bootstrapAdmin(boot, NOW, 600, { randomBytes: source });
  assert.equal(code, expectedCode);
  const binv = boot.view().invites[0];
  assert.ok(binv, "bootstrap invite expected");
  assert.equal(binv.inviteId, expectedId);
  assert.equal(binv.admin, true);
  assert.equal(binv.expiresAt, NOW + 600);
});

test("a failing or short random source is internal_error for invite.create and a plain error for bootstrap", () => {
  const throwing = (): Uint8Array => {
    throw new Error("no entropy");
  };
  const st = new MemoryState();
  const lowadminKey = key("lowadmin");
  const admin1 = entry(lowadminKey, "admin1", true);
  st.update((e) => e.putKey(admin1));
  const err = jackErrorOf(() =>
    new Native({ randomBytes: throwing }).call(
      call({
        tool: TOOL_ADMIN_INVITE_CREATE,
        arguments: "{}",
        caller: admin1,
        state: st,
      }),
    ),
  );
  assert.equal(err.httpStatus, 500);
  assert.equal(err.code, "internal_error");
  assert.equal(st.view().invites.length, 0); // nothing stored on the failure

  const short: (n: number) => Uint8Array = (n) => new Uint8Array(n > 16 ? 16 : n);
  assert.throws(() => bootstrapAdmin(new MemoryState(), NOW, 600, { randomBytes: short }), /no randomness/);
  assert.throws(() => bootstrapAdmin(new MemoryState(), NOW, 600, { randomBytes: throwing }), /no randomness/);
});

// ---------------------------------------------------------------------------
// jack.admin.user.set_admin.
// ---------------------------------------------------------------------------

test("set_admin grants and demotes; the view normalizes admin to a boolean", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const newbieKey = key("newbie");
  const admin = entry(rootKey, "admin-a", true);
  const reader = entry(newbieKey, "reader");
  st.update((e) => {
    e.putKey(admin);
    e.putKey(reader);
  });

  // Grant.
  const granted = native.call(
    call({
      tool: TOOL_ADMIN_USER_SET_ADMIN,
      arguments: JSON.stringify({ kid: reader.kid, admin: true }),
      caller: admin,
      state: st,
    }),
  );
  assert.deepEqual(granted.structured, {
    kid: reader.kid,
    public_key: reader.publicKey,
    name: "reader",
    admin: true,
    not_before: null,
    not_after: null,
  });
  assert.equal(st.lookup(reader.kid)?.admin, true);

  // Demote.
  const demoted = native.call(
    call({
      tool: TOOL_ADMIN_USER_SET_ADMIN,
      arguments: JSON.stringify({ kid: reader.kid, admin: false }),
      caller: admin,
      state: st,
    }),
  );
  assert.deepEqual(demoted.structured, {
    kid: reader.kid,
    public_key: reader.publicKey,
    name: "reader",
    admin: false,
    not_before: null,
    not_after: null,
  });
  const stored = st.lookup(reader.kid);
  assert.ok(stored, "reader expected");
  assert.equal(stored.admin, undefined); // member-presence rule: false is absent in memory
});

test("self-demote succeeds while another active admin remains; the last admin cannot be demoted", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin2Key = key("admin2");
  const adminA = entry(rootKey, "admin-a", true);
  const adminB = entry(admin2Key, "admin-b", true);
  st.update((e) => {
    e.putKey(adminA);
    e.putKey(adminB);
  });

  // Self-demote with another active admin present: allowed.
  const errSelf = callError(
    call({
      tool: TOOL_ADMIN_USER_SET_ADMIN,
      arguments: JSON.stringify({ kid: adminA.kid, admin: false }),
      caller: adminA,
      state: st,
    }),
  );
  assert.equal(errSelf, undefined, "self-demote must succeed with another admin remaining");
  assert.equal(st.lookup(adminA.kid)?.admin, undefined);

  // Demoting the only remaining active admin: 409 last_admin.
  const err = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_SET_ADMIN,
        arguments: JSON.stringify({ kid: adminB.kid, admin: false }),
        caller: adminB,
        state: st,
      }),
    ),
  );
  assert.equal(err.httpStatus, 409);
  assert.equal(err.code, Code.LAST_ADMIN);
  assert.equal(st.lookup(adminB.kid)?.admin, true); // unchanged
});

test("set_admin requires a strict-boolean admin argument (before the target lookup)", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));

  const badArgs = [
    JSON.stringify({ kid: "whatever" }), // absent
    JSON.stringify({ kid: "whatever", admin: null }),
    JSON.stringify({ kid: "whatever", admin: "true" }),
    JSON.stringify({ kid: "whatever", admin: 1 }),
  ];
  for (const args of badArgs) {
    // Even on an UNKNOWN kid the argument error must win: arguments are judged
    // before the target lookup.
    const c = call({ tool: TOOL_ADMIN_USER_SET_ADMIN, arguments: args, caller: admin, state: st });
    const err = jackErrorOf(() => native.call(c));
    assert.equal(err.httpStatus, 400, `args=${args}: status`);
    assert.equal(err.code, Code.INVALID_PARAMS, `args=${args}: code`);
    assert.equal(c.target, "", `args=${args}: target untouched`);
  }

  // Valid arguments on an unknown kid: 404 unknown_target.
  const c = call({
    tool: TOOL_ADMIN_USER_SET_ADMIN,
    arguments: JSON.stringify({ kid: "no-such-kid", admin: true }),
    caller: admin,
    state: st,
  });
  const err = jackErrorOf(() => native.call(c));
  assert.equal(err.httpStatus, 404);
  assert.equal(err.code, Code.UNKNOWN_TARGET);
});

// ---------------------------------------------------------------------------
// jack.admin.user.create.
// ---------------------------------------------------------------------------

test("user.create defaults to non-admin, accepts admin true, and inherits nothing", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const svcKey = key("svc");
  const newbieKey = key("newbie");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));

  // Default: admin false (absent member in memory, false in the view).
  const r1 = native.call(
    call({
      tool: TOOL_ADMIN_USER_CREATE,
      arguments: JSON.stringify({ name: "plain", public_key: svcKey.publicKey }),
      caller: admin,
      state: st,
    }),
  );
  assert.deepEqual(r1.structured, { kid: svcKey.kid });
  const plain = st.lookup(svcKey.kid);
  assert.ok(plain, "created entry expected");
  assert.equal(plain.admin, undefined);

  // admin: true works; stale `scopes`/`kind` members are INERT.
  const r2 = native.call(
    call({
      tool: TOOL_ADMIN_USER_CREATE,
      arguments: JSON.stringify({
        name: "boss",
        public_key: newbieKey.publicKey,
        admin: true,
        scopes: ["read"],
        kind: "human",
      }),
      caller: admin,
      state: st,
    }),
  );
  assert.deepEqual(r2.structured, { kid: newbieKey.kid });
  assert.equal(st.lookup(newbieKey.kid)?.admin, true);
});

test("user.create rejects mistyped admin and keeps the name_taken/key_exists order", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const svcKey = key("svc");
  const newbieKey = key("newbie");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => {
    e.putKey(admin);
    e.putKey(entry(svcKey, "svc"));
  });

  for (const adminArg of [1, '"true"', null]) {
    const err = jackErrorOf(() =>
      native.call(
        call({
          tool: TOOL_ADMIN_USER_CREATE,
          arguments: `{"name":"x${String(adminArg).replace(/[^a-z0-9]/gi, "")}","public_key":"${newbieKey.publicKey}","admin":${String(adminArg)}}`,
          caller: admin,
          state: st,
        }),
      ),
    );
    assert.equal(err.httpStatus, 400, `admin=${String(adminArg)}: status`);
    assert.equal(err.code, Code.INVALID_PARAMS, `admin=${String(adminArg)}: code`);
  }

  // Validity bounds and key checks (unchanged): bad name, bad key, crossed bounds.
  const badName = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_CREATE,
        arguments: JSON.stringify({ name: "bad name!", public_key: newbieKey.publicKey }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(badName.code, Code.INVALID_PARAMS);
  const badKey = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_CREATE,
        arguments: JSON.stringify({ name: "okname", public_key: encodeBase64URL(new Uint8Array(16)) }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(badKey.code, Code.KEY_REJECTED);
  const crossed = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_CREATE,
        arguments: JSON.stringify({
          name: "okname2",
          public_key: newbieKey.publicKey,
          not_before: 100,
          not_after: 100,
        }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(crossed.code, Code.INVALID_PARAMS);

  // Name conflict before key conflict: reusing "svc" with an unused key is name_taken.
  const nameFirst = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_CREATE,
        arguments: JSON.stringify({ name: "svc", public_key: newbieKey.publicKey }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(nameFirst.httpStatus, 409);
  assert.equal(nameFirst.code, Code.NAME_TAKEN);
  // Key conflict with a free name: key_exists.
  const keyFirst = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_CREATE,
        arguments: JSON.stringify({ name: "other", public_key: svcKey.publicKey }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(keyFirst.httpStatus, 409);
  assert.equal(keyFirst.code, Code.KEY_EXISTS);
});

// ---------------------------------------------------------------------------
// Admin gate ordering: 403 admin_required BEFORE argument parsing.
// ---------------------------------------------------------------------------

const ADMIN_TOOLS = [
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_CREATE,
  TOOL_ADMIN_USER_SET_ADMIN,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_INVITE_LIST,
  TOOL_ADMIN_INVITE_REVOKE,
] as const;

test("non-admin callers get admin_required on every admin tool, before argument parsing", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const newbie3Key = key("newbie3");
  const admin = entry(rootKey, "admin-a", true);
  const reader = entry(newbie3Key, "reader");
  st.update((e) => {
    e.putKey(admin);
    e.putKey(reader);
  });

  // Valid arguments ...
  const validArgs: Readonly<Record<string, string>> = {
    [TOOL_ADMIN_USER_GET]: JSON.stringify({ kid: rootKey.kid }),
    [TOOL_ADMIN_USER_CREATE]: JSON.stringify({ name: "x", public_key: rootKey.publicKey }),
    [TOOL_ADMIN_USER_SET_ADMIN]: JSON.stringify({ kid: rootKey.kid, admin: true }),
    [TOOL_ADMIN_USER_REVOKE]: JSON.stringify({ kid: rootKey.kid }),
    [TOOL_ADMIN_INVITE_REVOKE]: JSON.stringify({ invite_id: "i1" }),
    [TOOL_ADMIN_USER_LIST]: "{}",
    [TOOL_ADMIN_INVITE_CREATE]: "{}",
    [TOOL_ADMIN_INVITE_LIST]: "{}",
  };
  for (const tool of ADMIN_TOOLS) {
    const c = call({ tool, arguments: validArgs[tool], caller: reader, state: st });
    const err = jackErrorOf(() => native.call(c));
    assert.equal(err.httpStatus, 403, `${tool} (valid args): status`);
    assert.equal(err.code, Code.ADMIN_REQUIRED, `${tool} (valid args): code`);
    assert.equal(c.target, "", `${tool} (valid args): target untouched`);
  }

  // ... and with garbage / missing arguments alike (raw text "7" is not even an object).
  for (const tool of ADMIN_TOOLS) {
    for (const args of [undefined, "7", '{"kid":7}']) {
      const c = call({ tool, arguments: args, caller: reader, state: st });
      const err = jackErrorOf(() => native.call(c));
      assert.equal(err.httpStatus, 403, `${tool} (args=${args ?? "none"}): status`);
      assert.equal(err.code, Code.ADMIN_REQUIRED, `${tool} (args=${args ?? "none"}): code`);
    }
  }

  // whoami is NOT gated: a non-admin caller succeeds.
  const who = native.call(call({ tool: TOOL_WHOAMI, arguments: "{}", caller: reader, state: st }));
  assert.deepEqual(who.structured, {
    kid: reader.kid,
    name: "reader",
    admin: false,
    not_before: null,
    not_after: null,
  });
});

// ---------------------------------------------------------------------------
// invite.create / invite.list / invite.revoke.
// ---------------------------------------------------------------------------

/** Creates an invite and returns the structured result plus the stored record. */
function createInvite(st: MemoryState, admin: RegistryEntry, args: string): {
  inviteId: string;
  code: string;
  expiresAt: number;
} {
  const result = native.call(call({ tool: TOOL_ADMIN_INVITE_CREATE, arguments: args, caller: admin, state: st }));
  const structured = result.structured as { invite_id: string; code: string; expires_at: number };
  return { inviteId: structured.invite_id, code: structured.code, expiresAt: structured.expires_at };
}

test("invite.create defaults: admin false, ttl 3600", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));
  createInvite(st, admin, "{}");
  const inv = st.view().invites[0];
  assert.ok(inv, "invite expected");
  assert.equal(inv.admin, undefined);
  assert.equal(inv.createdAt, NOW);
  assert.equal(inv.expiresAt, NOW + 3600);
  assert.equal(inv.createdBy, admin.kid);
  assert.equal(inv.keyTtlSeconds, undefined);
});

test("invite.create ttl and key_ttl bounds", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));

  for (const bad of ["0", "604801"]) {
    const err = jackErrorOf(() => createInvite(st, admin, `{"ttl_seconds":${bad}}`));
    assert.equal(err.httpStatus, 400, `ttl=${bad}`);
    assert.equal(err.code, Code.INVALID_PARAMS, `ttl=${bad}`);
  }
  for (const good of ["1", "604800"]) {
    st.update((e) => e.invites().forEach((i) => e.removeInvite(i.inviteId)));
    createInvite(st, admin, `{"ttl_seconds":${good}}`);
    const inv = st.view().invites[0];
    assert.ok(inv, `ttl=${good}: invite expected`);
    assert.equal(inv.expiresAt, NOW + Number(good), `ttl=${good}`);
  }

  for (const bad of ["0", "31536001"]) {
    const err = jackErrorOf(() => createInvite(st, admin, `{"key_ttl_seconds":${bad}}`));
    assert.equal(err.httpStatus, 400, `key_ttl=${bad}`);
    assert.equal(err.code, Code.INVALID_PARAMS, `key_ttl=${bad}`);
  }
  for (const good of ["1", "31536000"]) {
    st.update((e) => e.invites().forEach((i) => e.removeInvite(i.inviteId)));
    createInvite(st, admin, `{"key_ttl_seconds":${good}}`);
    const inv = st.view().invites[0];
    assert.ok(inv, `key_ttl=${good}: invite expected`);
    assert.equal(inv.keyTtlSeconds, Number(good), `key_ttl=${good}`);
  }
});

test("an admin invite enrolls an admin; a plain invite enrolls a non-admin; key_ttl sets not_after", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));

  // Admin invite.
  const adminInvite = createInvite(st, admin, '{"admin":true}');
  const newbieKey = key("newbie");
  const r1 = native.call(
    call({
      tool: TOOL_ENROLL,
      arguments: JSON.stringify({ code: adminInvite.code, name: "boss", public_key: newbieKey.publicKey }),
      caller: undefined,
      kid: newbieKey.kid,
      state: st,
    }),
  );
  assert.deepEqual(r1.structured, { kid: newbieKey.kid, name: "boss", admin: true });
  assert.equal(st.lookup(newbieKey.kid)?.admin, true);

  // Plain invite with a key ttl: enrolled admin false, not_after = now + ttl.
  const plainInvite = createInvite(st, admin, '{"key_ttl_seconds":600}');
  const newbie2Key = key("newbie2");
  const r2 = native.call(
    call({
      tool: TOOL_ENROLL,
      arguments: JSON.stringify({ code: plainInvite.code, name: "plain", public_key: newbie2Key.publicKey }),
      caller: undefined,
      kid: newbie2Key.kid,
      state: st,
    }),
  );
  assert.deepEqual(r2.structured, { kid: newbie2Key.kid, name: "plain", admin: false });
  const enrolled = st.lookup(newbie2Key.kid);
  assert.ok(enrolled, "enrolled entry expected");
  assert.equal(enrolled.admin, undefined);
  assert.equal(enrolled.notAfter, NOW + 600);
});

test("invite.list returns live invites with boolean admin, sorted created_at then invite_id", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => {
    e.putKey(admin);
    // A dead invite (expired before NOW) must not appear.
    e.putInvite({ inviteId: "dead", createdBy: admin.kid, createdAt: NOW - 100, expiresAt: NOW - 50 });
    // Two live invites out of order (same created_at, ids to sort).
    e.putInvite({ inviteId: "zz", createdBy: admin.kid, createdAt: NOW, expiresAt: NOW + 100 });
    e.putInvite({ inviteId: "aa", admin: true, createdBy: admin.kid, createdAt: NOW, expiresAt: NOW + 100 });
    e.putInvite({ inviteId: "older", createdBy: admin.kid, createdAt: NOW - 10, expiresAt: NOW + 100 });
  });
  const result = native.call(call({ tool: TOOL_ADMIN_INVITE_LIST, arguments: "{}", caller: admin, state: st }));
  assert.deepEqual(result.structured, {
    invites: [
      { invite_id: "older", admin: false, created_by: admin.kid, created_at: NOW - 10, expires_at: NOW + 100 },
      { invite_id: "aa", admin: true, created_by: admin.kid, created_at: NOW, expires_at: NOW + 100 },
      { invite_id: "zz", admin: false, created_by: admin.kid, created_at: NOW, expires_at: NOW + 100 },
    ],
  });
});

test("invite.revoke removes a live invite; an expired one is unknown_target", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => {
    e.putKey(admin);
    e.putInvite({ inviteId: "live", createdBy: admin.kid, createdAt: NOW, expiresAt: NOW + 100 });
    e.putInvite({ inviteId: "dead", createdBy: admin.kid, createdAt: NOW - 100, expiresAt: NOW - 50 });
  });
  const revoked = native.call(
    call({ tool: TOOL_ADMIN_INVITE_REVOKE, arguments: '{"invite_id":"live"}', caller: admin, state: st }),
  );
  assert.deepEqual(revoked.structured, { invite_id: "live" });
  assert.equal(st.view().invites.some((i) => i.inviteId === "live"), false);
  // The dead invite was never in the live set, so revoking it is unknown_target.
  const err = jackErrorOf(() =>
    native.call(call({ tool: TOOL_ADMIN_INVITE_REVOKE, arguments: '{"invite_id":"dead"}', caller: admin, state: st })),
  );
  assert.equal(err.httpStatus, 404);
  assert.equal(err.code, Code.UNKNOWN_TARGET);
});

// ---------------------------------------------------------------------------
// whoami and rotation.
// ---------------------------------------------------------------------------

test("whoami reports the full entry view", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));
  const who = native.call(call({ tool: TOOL_WHOAMI, arguments: "{}", caller: admin, state: st }));
  assert.deepEqual(who.structured, {
    kid: admin.kid,
    name: "admin-a",
    admin: true,
    not_before: null,
    not_after: null,
  });
  // An unregistered caller is unknown_key.
  const stranger = key("mallory");
  const err = jackErrorOf(() =>
    native.call(call({ tool: TOOL_WHOAMI, arguments: "{}", caller: undefined, kid: stranger.kid, state: st })),
  );
  assert.equal(err.httpStatus, 401);
  assert.equal(err.code, Code.UNKNOWN_KEY);
});

/** Ed25519 key material derived from id, like state-file.test.ts's stateTestKey. */
function newKeyMaterial(id: string): { priv: KeyObject; publicKey: string; kid: string } {
  const seed = createHash("sha256").update(id).digest();
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  return { priv, publicKey: encodeBase64URL(pub), kid: keyId(pub) };
}

test("rotation preserves admin (true and false), name and bounds; the result names the new kid", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const svcKey = key("svc");
  const admin = entry(rootKey, "admin-a", true);
  const plain = { ...entry(svcKey, "plain"), notBefore: 5, notAfter: 999 };
  st.update((e) => {
    e.putKey(admin);
    e.putKey(plain);
  });

  const rotate = (caller: RegistryEntry, mat: { priv: KeyObject; publicKey: string; kid: string }): unknown => {
    const proof = encodeBase64URL(
      new Uint8Array(nodeSign(null, Buffer.from(rotateProofString("aud", caller.kid, mat.kid, NOW)), mat.priv)),
    );
    const result = native.call(
      call({
        tool: TOOL_ROTATE_KEY,
        arguments: JSON.stringify({ public_key: mat.publicKey, proof }),
        caller,
        state: st,
      }),
    );
    return (result.structured as { kid: string }).kid;
  };

  // The admin rotates: admin true, name and bounds preserved.
  const adminNew = newKeyMaterial("admin-a-next");
  assert.deepEqual(rotate(admin, adminNew), adminNew.kid);
  const movedAdmin = st.lookup(adminNew.kid);
  assert.ok(movedAdmin, "rotated admin expected");
  assert.equal(movedAdmin.admin, true);
  assert.equal(movedAdmin.name, "admin-a");
  assert.equal(st.lookup(admin.kid), undefined); // old kid removed

  // The non-admin rotates: admin false preserved as an absent member.
  const plainNew = newKeyMaterial("plain-next");
  assert.deepEqual(rotate(plain, plainNew), plainNew.kid);
  const movedPlain = st.lookup(plainNew.kid);
  assert.ok(movedPlain, "rotated plain expected");
  assert.equal(movedPlain.admin, undefined);
  assert.equal(movedPlain.name, "plain");
  assert.equal(movedPlain.notBefore, 5);
  assert.equal(movedPlain.notAfter, 999);
  assert.equal(st.lookup(plain.kid), undefined);
});

// ---------------------------------------------------------------------------
// activeAdmins and the last-admin rule against validity bounds.
// ---------------------------------------------------------------------------

test("activeAdmins counts admin===true entries within validity bounds; an expired admin does not block last_admin", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const expadminKey = key("expadmin");
  const newbie3Key = key("newbie3");
  st.update((e) => {
    // The only ACTIVE admin.
    e.putKey(entry(rootKey, "admin-a", true));
    // An admin whose validity has expired: not counted, does not block last_admin.
    e.putKey({ ...entry(expadminKey, "expired-admin", true), notAfter: NOW - 100 });
    // A plain user.
    e.putKey(entry(newbie3Key, "reader"));
  });
  assert.equal(activeAdmins(st.view().keys, NOW), 1);

  // Demoting the sole ACTIVE admin still fails last_admin despite the expired admin.
  const admin = st.lookup(rootKey.kid);
  assert.ok(admin, "active admin expected");
  const err = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_USER_SET_ADMIN,
        arguments: JSON.stringify({ kid: rootKey.kid, admin: false }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(err.httpStatus, 409);
  assert.equal(err.code, Code.LAST_ADMIN);

  // A non-admin entry does not count at all.
  const onlyUsers = [entry(newbie3Key, "reader")];
  assert.equal(activeAdmins(onlyUsers, NOW), 0);
});

/**
 * Serialized-concurrency checks (accurately labeled: JS is single-threaded,
 * so Promise.all over synchronous native.call thunks runs them strictly in
 * submission order against the shared store). What each test discriminates
 * is the LAST-ADMIN guard of spec 03 sections 4 and 9 — removing THAT guard
 * (not the admin gate) changes the asserted outcome:
 * (a) a sole administrator's self-demotions must BOTH fail last_admin; with
 *     the guard removed the first succeeds and the registry loses its only
 *     active admin;
 * (b) two demotions that individually satisfy the rule (each alone leaves
 *     one active admin) but jointly violate it must serialize so the second
 *     fails last_admin and one active admin survives; with the guard removed
 *     both succeed and zero admins remain;
 * (c) concurrent enrolls racing one name: exactly one accepts beside the
 *     SEEDED root entry, the losers fail name_taken WITHOUT consuming their
 *     invites (spec 03 section 3.2 step 7);
 * (d) concurrent enrolls reusing one invite code: the first accepts — as an
 *     admin, the bootstrap invite being an admin invite — the rest fail
 *     invalid_invite, and the invite is consumed exactly once.
 */

/** Collects the outcome of one native.call: "ok" or the JackError code. */
function outcome(c: NativeCall): () => { ok: boolean; code?: string } {
  return () => {
    try {
      native.call(c);
      return { ok: true };
    } catch (err) {
      if (err instanceof JackError) {
        return { ok: false, code: err.code };
      }
      throw err;
    }
  };
}

test("a sole administrator cannot be demoted: concurrent self-demotions both fail last_admin", async () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));
  const mk = (): NativeCall =>
    call({
      tool: TOOL_ADMIN_USER_SET_ADMIN,
      arguments: JSON.stringify({ kid: admin.kid, admin: false }),
      caller: admin,
      state: st,
    });
  const [a, b] = await Promise.all([outcome(mk())(), outcome(mk())()]);
  assert.deepEqual(a, { ok: false, code: Code.LAST_ADMIN });
  assert.deepEqual(b, { ok: false, code: Code.LAST_ADMIN });
  // The guard, not the admin gate, rejected both: the caller was an admin
  // throughout, and the only active admin survives.
  assert.equal(st.lookup(admin.kid)?.admin, true, "the sole admin must survive");
});

test("demotions that would jointly leave no admin serialize: the second fails last_admin", async () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin2Key = key("admin2");
  const adminA = entry(rootKey, "admin-a", true);
  const adminB = entry(admin2Key, "admin-b", true);
  st.update((e) => {
    e.putKey(adminA);
    e.putKey(adminB);
  });
  // Run alone, each demotion leaves one active admin; run together they would
  // leave none. Spec 03 section 9: they must serialize so the second fails.
  // The CALLER (admin-a) is an admin for both calls — only the last-admin
  // guard can reject the second, which is exactly what this pins.
  const first = call({
    tool: TOOL_ADMIN_USER_SET_ADMIN,
    arguments: JSON.stringify({ kid: adminB.kid, admin: false }),
    caller: adminA,
    state: st,
  });
  const second = call({
    tool: TOOL_ADMIN_USER_SET_ADMIN,
    arguments: JSON.stringify({ kid: adminA.kid, admin: false }),
    caller: adminA,
    state: st,
  });
  const [a, b] = await Promise.all([outcome(first)(), outcome(second)()]);
  assert.deepEqual(a, { ok: true });
  assert.deepEqual(b, { ok: false, code: Code.LAST_ADMIN });
  assert.equal(activeAdmins(st.view().keys, NOW), 1, "exactly one active admin must survive");
  assert.equal(st.lookup(adminA.kid)?.admin, true);
  assert.equal(st.lookup(adminB.kid)?.admin, undefined);
});

test("enrolls racing one name: one accept beside the seeded root; losers keep their invites", async () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => e.putKey(admin));
  // One invite PER racer, so the only contended resource is the name.
  const racers = [key("newbie"), key("newbie2"), key("newbie3"), key("mallory")];
  const codes = racers.map(() => createInvite(st, admin, "{}").code);
  const calls = racers.map((k, i) => {
    const c = call({
      tool: TOOL_ENROLL,
      arguments: JSON.stringify({ code: codes[i], name: "same-name", public_key: k.publicKey }),
      caller: undefined,
      kid: k.kid,
      state: st,
    });
    return c;
  });
  const results = await Promise.all(calls.map((c) => outcome(c)()));
  const accepted = results.filter((r) => r.ok);
  assert.equal(accepted.length, 1, "exactly one enroll must accept");
  assert.deepEqual(
    results.slice(1),
    racers.slice(1).map(() => ({ ok: false, code: Code.NAME_TAKEN })),
  );
  // Registry cardinality INCLUDES the seeded root: root + the one winner.
  assert.equal(st.view().keys.length, 2);
  const winner = st.view().keys.find((k) => k.name === "same-name");
  assert.ok(winner, "the winning enroll is registered");
  assert.equal(winner.kid, racers[0]?.kid);
  // A name_taken failure does not consume the loser's invite (03 section 3.2
  // step 7): 4 created, 1 consumed by the winner, 3 intact.
  assert.equal(st.view().invites.length, 3);
});

test("enrolls reusing one invite code: the first accepts as an admin, the rest fail invalid_invite", async () => {
  const st = new MemoryState();
  const code = bootstrapAdmin(st, NOW, 600);
  const racers = [key("newbie"), key("newbie2"), key("newbie3")];
  const calls = racers.map((k) =>
    call({
      tool: TOOL_ENROLL,
      arguments: JSON.stringify({ code, name: `name-${k.name}`, public_key: k.publicKey }),
      caller: undefined,
      kid: k.kid,
      state: st,
    }),
  );
  const results = await Promise.all(calls.map((c) => outcome(c)()));
  assert.deepEqual(results[0], { ok: true });
  assert.deepEqual(
    results.slice(1),
    racers.slice(1).map(() => ({ ok: false, code: Code.INVALID_INVITE })),
  );
  // The single-use invite is consumed exactly once; the enrolled entry is an
  // admin (the bootstrap invite is an admin invite).
  assert.equal(st.view().invites.length, 0);
  assert.equal(st.view().keys.length, 1);
  assert.equal(st.lookup(racers[0]?.kid ?? "")?.admin, true);
});

// ---------------------------------------------------------------------------
// The Go interleaved-revoke test, adapted to the admin-only registry.
// ---------------------------------------------------------------------------

/**
 * The Go concurrency test, adapted to single-threaded JS: an interleaved
 * update is simulated by running the opposing revoke INSIDE the caller's
 * update, before its edit runs. DERIVATION: an implementation checking the
 * last-admin rule outside the transaction would apply admin-a's stale
 * decision after admin-b's revoke and leave 0 administrators — this test
 * fails for that bug; the real implementation re-reads the caller inside
 * update and its discarded edit cannot resurrect it.
 */
class InterleavingStore implements StateStore {
  private readonly inner: MemoryState;
  private hook: (() => void) | undefined;
  private ran = false;

  constructor(inner: MemoryState, hook: (() => void) | undefined) {
    this.inner = inner;
    this.hook = hook;
  }

  get ranHook(): boolean {
    return this.ran;
  }

  view(): StateView {
    return this.inner.view();
  }

  lookup(kid: string): RegistryEntry | undefined {
    return this.inner.lookup(kid);
  }

  update(fn: (edit: StateEdit) => void): void {
    // Only the FIRST update interleaves; afterwards pure delegation.
    if (!this.ran && this.hook !== undefined) {
      this.ran = true;
      this.hook();
    }
    this.inner.update(fn);
  }
}

test("the last administrator survives interleaved, failing and sequential revokes", () => {
  const rootKey = key("root");
  const admin2Key = key("admin2");
  const adminA = entry(rootKey, "admin-a", true);
  const adminB = entry(admin2Key, "admin-b", true);

  // Sub-cases are independent: a fresh MemoryState per case.

  // (a) Interleaved, order 1: admin-b's revoke completes before admin-a's edit runs.
  {
    const st = new MemoryState();
    st.update((e) => {
      e.putKey(adminA);
      e.putKey(adminB);
    });
    const inner = st;
    const wrapper = new InterleavingStore(inner, () => {
      const err = revoke(adminB, adminA.kid, inner);
      assert.equal(err, undefined, "admin-b's interleaved revoke must succeed");
    });
    const err = revoke(adminA, adminB.kid, wrapper);
    assert.ok(wrapper.ranHook, "the interleaving hook must have run");
    assert.ok(err, "admin-a's revoke must fail once it has been removed");
    assert.equal(err.httpStatus, 401);
    assert.equal(err.code, Code.UNKNOWN_KEY);
    assert.equal(activeAdmins(st.view().keys, NOW), 1);
    const remaining = st.view().keys[0];
    assert.ok(remaining, "one entry expected");
    assert.equal(remaining.name, "admin-b");
  }

  // (b) Mirror order: admin-a's revoke completes first, admin-b fails identically.
  {
    const st = new MemoryState();
    st.update((e) => {
      e.putKey(adminA);
      e.putKey(adminB);
    });
    const inner = st;
    const wrapper = new InterleavingStore(inner, () => {
      const err = revoke(adminA, adminB.kid, inner);
      assert.equal(err, undefined, "admin-a's interleaved revoke must succeed");
    });
    const err = revoke(adminB, adminA.kid, wrapper);
    assert.ok(wrapper.ranHook, "the interleaving hook must have run");
    assert.ok(err, "admin-b's revoke must fail once it has been removed");
    assert.equal(err.httpStatus, 401);
    assert.equal(err.code, Code.UNKNOWN_KEY);
    assert.equal(activeAdmins(st.view().keys, NOW), 1);
    const names = st.view().keys.map((k) => k.name);
    assert.deepEqual(names, ["admin-a"]);
  }

  // (c) An update that throws midway: nothing is applied (MemoryState.swap only happens on normal return).
  {
    const st = new MemoryState();
    st.update((e) => {
      e.putKey(adminA);
      e.putKey(adminB);
    });
    const throwing: StateStore = {
      view: () => st.view(),
      lookup: (kid) => st.lookup(kid),
      update: (fn) =>
        st.update((edit) => {
          fn(edit);
          throw new Error("boom");
        }),
    };
    const err = revoke(adminA, adminB.kid, throwing);
    assert.ok(err, "the revocation must surface an error");
    assert.equal(err.httpStatus, 500);
    assert.equal(err.code, "internal_error");
    // Unchanged: both entries still present.
    assert.equal(activeAdmins(st.view().keys, NOW), 2);
    assert.ok(st.lookup(adminB.kid), "admin-b still registered");
  }

  // (d) Sequential: the successful revoke invalidates the other caller's stale entry.
  {
    const st = new MemoryState();
    st.update((e) => {
      e.putKey(adminA);
      e.putKey(adminB);
    });
    assert.equal(revoke(adminA, adminB.kid, st), undefined);
    const err = revoke(adminB, adminA.kid, st);
    assert.ok(err, "the stale admin-b entry must fail");
    assert.equal(err.httpStatus, 401);
    assert.equal(err.code, Code.UNKNOWN_KEY);
    assert.equal(activeAdmins(st.view().keys, NOW), 1);
  }
});

/** A revoke through Native.call; returns the caught JackError, undefined on success. */
function revoke(caller: RegistryEntry, targetKid: string, store: StateStore): JackError | undefined {
  return callError(
    call({
      tool: TOOL_ADMIN_USER_REVOKE,
      arguments: JSON.stringify({ kid: targetKid }),
      caller,
      state: store,
    }),
  );
}
