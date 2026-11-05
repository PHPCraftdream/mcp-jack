/**
 * Tests for the protocol-native tools of spec 03, ported from Go's
 * native_test.go (TestBootstrapAdminThenEnroll, TestInviteCodeIsNeverStored,
 * TestLastAdministratorSurvivesConcurrentRevokes,
 * TestAdminToolsRequireAdminBeforeArguments). Calls go to Native.call DIRECTLY
 * (no Verifier, no signatures — the verifier owns authentication; Native
 * trusts its NativeCall), with the default CSPRNG like Go's NativeOptions{}.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { Code, JackError } from "../src/errors.js";
import { Native, activeAdmins, bootstrapAdmin } from "../src/server/native.js";
import {
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ENROLL,
} from "../src/server/verify.js";
import type { NativeCall } from "../src/server/verify.js";
import {
  MemoryState,
  StateEdit,
  type RegistryEntry,
  type StateStore,
  type StateView,
} from "../src/server/state.js";
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

/** A registered entry built from a fixture key. */
function entry(k: TestKey, name: string, scopes: readonly string[]): RegistryEntry {
  return { kid: k.kid, publicKey: k.publicKey, name, kind: "human", scopes: [...scopes] };
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
  assert.deepEqual(inv.scopes, ["admin"]);
  assert.equal(inv.kind, "human");
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
  assert.deepEqual(result.structured, { kid: newbie.kid, name: "first", kind: "human", scopes: ["admin"] });
  const got = st.lookup(newbie.kid);
  assert.ok(got, "enrolled key missing");
  assert.deepEqual(got.scopes, ["admin"]);
  assert.equal(got.kind, "human");
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
  const lowadmin = key("lowadmin");
  const admin1 = entry(lowadmin, "admin1", ["admin", "read"]);
  st.update((e) => e.putKey(admin1));

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
  const lowadmin = key("lowadmin");
  const admin1 = entry(lowadmin, "admin1", ["admin", "read"]);
  st.update((e) => e.putKey(admin1));
  const result = new Native({ randomBytes: source }).call(
    call({
      tool: TOOL_ADMIN_INVITE_CREATE,
      arguments: '{"scopes":["read"]}',
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
  assert.equal(inv.createdBy, lowadmin.kid);

  const boot = new MemoryState();
  const code = bootstrapAdmin(boot, NOW, 600, { randomBytes: source });
  assert.equal(code, expectedCode);
  const binv = boot.view().invites[0];
  assert.ok(binv, "bootstrap invite expected");
  assert.equal(binv.inviteId, expectedId);
  assert.deepEqual(binv.scopes, ["admin"]);
  assert.equal(binv.kind, "human");
  assert.equal(binv.expiresAt, NOW + 600);
});

test("a failing or short random source is internal_error for invite.create and a plain error for bootstrap", () => {
  const throwing = (): Uint8Array => {
    throw new Error("no entropy");
  };
  const st = new MemoryState();
  const lowadmin = key("lowadmin");
  const admin1 = entry(lowadmin, "admin1", ["admin", "read"]);
  st.update((e) => e.putKey(admin1));
  const err = jackErrorOf(() =>
    new Native({ randomBytes: throwing }).call(
      call({
        tool: TOOL_ADMIN_INVITE_CREATE,
        arguments: '{"scopes":["read"]}',
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

/** A revoke through Native.call; returns the caught JackError, undefined on success. */
function revoke(caller: RegistryEntry, targetKid: string, store: StateStore): JackError | undefined {
  try {
    native.call(
      call({
        tool: TOOL_ADMIN_USER_REVOKE,
        arguments: JSON.stringify({ kid: targetKid }),
        caller,
        state: store,
      }),
    );
    return undefined;
  } catch (err) {
    if (err instanceof JackError) {
      return err;
    }
    throw err;
  }
}

test("the last administrator survives interleaved, failing and sequential revokes", () => {
  const rootKey = key("root");
  const admin2Key = key("admin2");
  const adminA = entry(rootKey, "admin-a", ["admin"]);
  const adminB = entry(admin2Key, "admin-b", ["admin"]);

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

test("admin tools require the admin scope before the arguments", () => {
  const st = new MemoryState();
  const newbie3 = key("newbie3");
  const reader = entry(newbie3, "reader", ["read"]);
  st.update((e) => e.putKey(reader));

  // Raw arguments text "7" is not an object; the scope check must come first.
  const c = call({
    tool: TOOL_ADMIN_USER_LIST,
    arguments: "7",
    caller: reader,
    state: st,
  });
  const err = jackErrorOf(() => native.call(c));
  assert.equal(err.httpStatus, 403);
  assert.equal(err.code, Code.INSUFFICIENT_SCOPE);
  assert.equal(c.target, "");
});
