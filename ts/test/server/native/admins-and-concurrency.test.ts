import assert from "node:assert/strict";
import { test } from "node:test";
import { Code } from "../../../src/core/errors.js";
import { activeAdmins, bootstrapAdmin } from "../../../src/server/native.js";
import { TOOL_ADMIN_USER_SET_ADMIN, TOOL_ENROLL } from "../../../src/server/verify.js";
import type { NativeCall } from "../../../src/server/verify.js";
import { MemoryState, type StateStore } from "../../../src/server/registry/state.js";
import { NOW, native, key, entry, call, jackErrorOf, createInvite, outcome, InterleavingStore, revoke } from "./support.js";

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
      lookupInvite: (id) => st.lookupInvite(id),
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
