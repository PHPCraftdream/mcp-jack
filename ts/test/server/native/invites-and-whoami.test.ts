import assert from "node:assert/strict";
import { sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { Code } from "../../../src/core/errors.js";
import { rotateProofString } from "../../../src/core/signing.js";
import { bootstrapAdmin } from "../../../src/server/native.js";
import { TOOL_ADMIN_INVITE_CREATE, TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ENROLL, TOOL_ROTATE_KEY, TOOL_WHOAMI } from "../../../src/server/verify.js";
import { MemoryState, type RegistryEntry } from "../../../src/server/registry/state.js";
import { encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { NOW, native, key, entry, call, jackErrorOf, createInvite, newKeyMaterial, revoke } from "./support.js";

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

test("invite.create purges expired invites in the same edit and keeps live ones", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  st.update((e) => {
    e.putKey(admin);
    e.putInvite({ inviteId: "expired", createdBy: admin.kid, createdAt: NOW - 100, expiresAt: NOW - 1 });
    e.putInvite({ inviteId: "live", createdBy: admin.kid, createdAt: NOW, expiresAt: NOW + 100 });
  });
  const result = native.call(call({ tool: TOOL_ADMIN_INVITE_CREATE, arguments: "{}", caller: admin, now: NOW + 1, state: st }));
  assert.ok(result.structured, "invite.create must succeed");
  const ids = st.view().invites.map((i) => i.inviteId);
  assert.equal(ids.length, 2, "the live seed and the new invite must stay");
  assert.ok(!ids.includes("expired"), "the expired invite must be gone from the stored document");
  assert.ok(ids.includes("live"), "a live invite is never purged");
});

test("a failed enroll or revoke of an expired invite keeps the old error and leaves it stored", () => {
  const st = new MemoryState();
  const rootKey = key("root");
  const admin = entry(rootKey, "admin-a", true);
  const raw = Buffer.alloc(32, 0x42);
  const code = encodeBase64URL(raw);
  st.update((e) => {
    e.putKey(admin);
    e.putInvite({ inviteId: keyId(raw), createdBy: admin.kid, createdAt: NOW - 200, expiresAt: NOW - 1 });
  });
  const fresh = key("newbie");
  const enrollErr = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ENROLL,
        arguments: JSON.stringify({ code, name: "fresh", public_key: fresh.publicKey }),
        caller: undefined,
        kid: fresh.kid,
        state: st,
      }),
    ),
  );
  assert.equal(enrollErr.httpStatus, 403);
  assert.equal(enrollErr.code, Code.INVALID_INVITE);
  const revokeErr = jackErrorOf(() =>
    native.call(
      call({
        tool: TOOL_ADMIN_INVITE_REVOKE,
        arguments: JSON.stringify({ invite_id: keyId(raw) }),
        caller: admin,
        state: st,
      }),
    ),
  );
  assert.equal(revokeErr.httpStatus, 404);
  assert.equal(revokeErr.code, Code.UNKNOWN_TARGET);
  // Both edits failed, so the whole atomic edit (purge included) rolled back.
  assert.deepEqual(st.view().invites.map((i) => i.inviteId), [keyId(raw)]);
});

test("bootstrapAdmin purges expired invites in the same edit", () => {
  const st = new MemoryState();
  st.update((e) => {
    e.putInvite({ inviteId: "expired", createdBy: "old", createdAt: 0, expiresAt: 1 });
  });
  bootstrapAdmin(st, NOW, 600);
  const invites = st.view().invites;
  assert.equal(invites.length, 1);
  const invite = invites[0];
  assert.ok(invite, "the fresh admin invite expected");
  assert.equal(invite.createdBy, "bootstrap");
});

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
