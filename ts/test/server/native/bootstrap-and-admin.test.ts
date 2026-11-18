import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { Code } from "../../../src/core/errors.js";
import { Native, bootstrapAdmin } from "../../../src/server/native.js";
import { TOOL_ADMIN_INVITE_CREATE, TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ADMIN_USER_CREATE, TOOL_ADMIN_USER_GET, TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_REVOKE, TOOL_ADMIN_USER_SET_ADMIN, TOOL_ENROLL, TOOL_WHOAMI } from "../../../src/server/verify.js";
import { MemoryState } from "../../../src/server/registry/state.js";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { NOW, native, key, entry, call, jackErrorOf, callError, ADMIN_TOOLS } from "./support.js";

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
