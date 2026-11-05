/** Tests for the in-memory state store, ported from Go's state_test.go (memory parts). */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MemoryState,
  StateEdit,
  serializeInviteRecord,
  serializeRegistryEntry,
  type InviteRecord,
  type RegistryEntry,
} from "../src/server/state.js";

type Writable<T> = { -readonly [K in keyof T]: T[K] };
function writable<T>(value: T): Writable<T> {
  return value as Writable<T>;
}

/** Synthetic entry; MemoryState never validates, so no real keys are needed. */
function testKey(kid: string, name: string): RegistryEntry {
  return { kid, publicKey: `pk-${kid}`, name, kind: "human", scopes: ["read"] };
}

test("registry entry with no bounds serializes with null bounds", () => {
  const entry: RegistryEntry = { kid: "k1", publicKey: "pk", name: "alice", kind: "human", scopes: ["read"] };
  assert.equal(
    JSON.stringify(serializeRegistryEntry(entry)),
    `{"kid":"k1","public_key":"pk","name":"alice","kind":"human","scopes":["read"],"not_before":null,"not_after":null}`,
  );
});

test("invite record with no ttl serializes with null key_ttl_seconds", () => {
  const inv: InviteRecord = {
    inviteId: "i1",
    scopes: ["read"],
    kind: "human",
    createdBy: "root",
    createdAt: 1767225500,
    expiresAt: 1767228600,
  };
  assert.equal(
    JSON.stringify(serializeInviteRecord(inv)),
    `{"invite_id":"i1","scopes":["read"],"kind":"human","created_by":"root","created_at":1767225500,"expires_at":1767228600,"key_ttl_seconds":null}`,
  );
});

test("set bounds and ttl serialize as numbers", () => {
  const entry: RegistryEntry = {
    kid: "k1",
    publicKey: "pk",
    name: "alice",
    kind: "human",
    scopes: ["read"],
    notBefore: 1767225500,
    notAfter: 1767229200,
  };
  assert.equal(
    JSON.stringify(serializeRegistryEntry(entry)),
    `{"kid":"k1","public_key":"pk","name":"alice","kind":"human","scopes":["read"],"not_before":1767225500,"not_after":1767229200}`,
  );
  const inv: InviteRecord = {
    inviteId: "i1",
    scopes: ["read"],
    kind: "human",
    createdBy: "root",
    createdAt: 1767225500,
    expiresAt: 1767228600,
    keyTtlSeconds: 3600,
  };
  assert.equal(
    JSON.stringify(serializeInviteRecord(inv)),
    `{"invite_id":"i1","scopes":["read"],"kind":"human","created_by":"root","created_at":1767225500,"expires_at":1767228600,"key_ttl_seconds":3600}`,
  );
});

test("scopes omitted through putKey normalize to []", () => {
  const store = new MemoryState();
  const entry = testKey("k1", "alice");
  const { scopes: _omit, ...withoutScopes } = entry;
  store.update((e) => e.putKey(withoutScopes));
  const view = store.view();
  const got = view.keys[0];
  assert.ok(got, "expected one key");
  assert.deepEqual(got.scopes, []);
  assert.equal(JSON.stringify(serializeRegistryEntry(got).scopes), "[]");
});

test("put and get by kid and by name", () => {
  const store = new MemoryState();
  const k = testKey("k1", "alice");
  store.update((e) => e.putKey(k));
  store.update((e) => {
    const got = e.key(k.kid);
    assert.ok(got, "Key(kid) should find the entry");
    assert.equal(got.name, "alice");
    const byName = e.keyByName("alice");
    assert.ok(byName, "KeyByName(alice) should find the entry");
    assert.equal(byName.kid, k.kid);
    assert.equal(e.key("missing"), undefined);
    assert.equal(e.keyByName("nobody"), undefined);
  });
});

test("putkey replaces on same kid", () => {
  const store = new MemoryState();
  const entry = testKey("k1", "alice");
  const replaced: RegistryEntry = { ...entry, name: "alice2", scopes: ["read", "write"] };
  store.update((e) => {
    e.putKey(entry);
    e.putKey(replaced);
  });
  const view = store.view();
  assert.equal(view.keys.length, 1);
  const got = view.keys[0];
  assert.ok(got);
  assert.equal(got.name, "alice2");
  assert.equal(got.scopes?.length, 2);
});

test("remove returns false when absent", () => {
  const store = new MemoryState();
  store.update((e) => {
    assert.equal(e.removeKey("ghost"), false);
    assert.equal(e.removeInvite("ghost-invite"), false);
  });
});

test("keys sorted by kid, invites sorted by invite id", () => {
  const store = new MemoryState();
  const kz = testKey("kid-zz", "zoe");
  const ka = testKey("kid-aa", "ann");
  const km = testKey("kid-mm", "mel");
  store.update((e) => {
    e.putKey(kz);
    e.putKey(ka);
    e.putKey(km);
    e.putInvite({ inviteId: "i9", createdBy: "root", createdAt: 0, expiresAt: 0 });
    e.putInvite({ inviteId: "i2", createdBy: "root", createdAt: 0, expiresAt: 0 });
    e.putInvite({ inviteId: "i5", createdBy: "root", createdAt: 0, expiresAt: 0 });
  });
  const wantKids = [ka.kid, km.kid, kz.kid].sort();
  store.update((e) => {
    const keys = e.keys();
    assert.equal(keys.length, wantKids.length);
    for (const [i, k] of keys.entries()) {
      const want = wantKids[i];
      assert.ok(want !== undefined, `wantKids[${i}]`);
      assert.equal(k.kid, want);
    }
    const invites = e.invites();
    assert.deepEqual(
      invites.map((inv) => inv.inviteId),
      ["i2", "i5", "i9"].sort(),
    );
  });
});

test("edit getters are deep copies", () => {
  const store = new MemoryState();
  const k = testKey("k1", "alice");
  store.update((e) => e.putKey(k));
  store.update((e) => {
    const got = e.key(k.kid);
    assert.ok(got, "Key(kid) not found");
    writable(got).name = "MUTATED";
    const scopes = got.scopes;
    assert.ok(scopes, "scopes expected");
    writable(scopes)[0] = "MUTATED";
  });
  const view = store.view();
  const got = view.keys[0];
  assert.ok(got);
  assert.equal(got.name, "alice");
  assert.equal(got.scopes?.[0], "read");
});

test("enroll flow consumes an invite and adds a key atomically", () => {
  const store = new MemoryState();
  const admin = testKey("kid-admin", "root");
  store.update((e) => {
    e.putInvite({ inviteId: "i1", scopes: ["read"], createdBy: "root", createdAt: 0, expiresAt: 0 });
    e.putKey(admin);
  });
  const enrolled = testKey("kid-new", "bob");
  const { scopes: _omit, ...enrolledRest } = enrolled;
  store.update((e) => {
    const inv = e.invite("i1");
    assert.ok(inv, "invite missing");
    e.removeInvite("i1");
    const invScopes = inv.scopes;
    e.putKey(invScopes === undefined ? enrolledRest : { ...enrolledRest, scopes: invScopes });
  });
  const view = store.view();
  assert.equal(view.keys.length, 2);
  assert.ok(view.keys.some((k) => k.kid === enrolled.kid), "enrolled key missing from view");
  assert.equal(view.invites.length, 0);
});

test("rollback on error leaves memory state untouched and propagates the same error", () => {
  const store = new MemoryState();
  store.update((e) => {
    e.putKey(testKey("kid-1", "alice"));
    e.putInvite({ inviteId: "i1", createdBy: "root", createdAt: 0, expiresAt: 0 });
  });
  const before = store.view();
  const boom = new Error("boom");
  assert.throws(
    () =>
      store.update((e) => {
        e.putKey(testKey("kid-2", "mallory"));
        e.removeInvite("i1");
        throw boom;
      }),
    (err) => err === boom,
  );
  const after = store.view();
  assert.deepEqual(after, before);
});

test("view is a copy: mutations never reach the store", () => {
  const store = new MemoryState();
  store.update((e) => e.putKey(testKey("kid-1", "alice")));
  const view = store.view();
  const first = view.keys[0];
  assert.ok(first);
  writable(first).name = "MUTATED";
  const scopes = first.scopes;
  assert.ok(scopes);
  writable(scopes)[0] = "MUTATED";
  view.keys.push(testKey("kid-2", "mallory"));
  view.invites.push({ inviteId: "i1", createdBy: "root", createdAt: 0, expiresAt: 0 });

  const after = store.view();
  assert.equal(after.keys.length, 1);
  const got = after.keys[0];
  assert.ok(got);
  assert.equal(got.name, "alice");
  assert.equal(got.scopes?.[0], "read");
  assert.equal(after.invites.length, 0);
});

test("view pointee isolation: notAfter mutations do not leak", () => {
  const store = new MemoryState();
  const entry: RegistryEntry = { ...testKey("kid-1", "alice"), notAfter: 123 };
  store.update((e) => e.putKey(entry));
  const view = store.view();
  const got = view.keys[0];
  assert.ok(got);
  assert.equal(got.notAfter, 123);
  writable(got).notAfter = 999;
  const fresh = store.view();
  const freshGot = fresh.keys[0];
  assert.ok(freshGot);
  assert.equal(freshGot.notAfter, 123);
});

test("putKey input isolation: caller mutations do not leak into the store", () => {
  const store = new MemoryState();
  const entry: RegistryEntry = { ...testKey("kid-1", "alice"), notBefore: 5 };
  store.update((e) => e.putKey(entry));
  const scopes = entry.scopes;
  assert.ok(scopes);
  writable(scopes)[0] = "admin";
  writable(scopes).push("extra");
  writable(entry).notBefore = 0;
  const got = store.view().keys[0];
  assert.ok(got);
  assert.deepEqual(got.scopes, ["read"]);
  assert.equal(got.notBefore, 5);

  const store2 = new MemoryState();
  const inv: InviteRecord = {
    inviteId: "i1",
    scopes: ["read"],
    createdBy: "root",
    createdAt: 0,
    expiresAt: 0,
    keyTtlSeconds: 3600,
  };
  store2.update((e) => e.putInvite(inv));
  const invScopes = inv.scopes;
  assert.ok(invScopes);
  writable(invScopes)[0] = "admin";
  writable(invScopes).push("extra");
  writable(inv).keyTtlSeconds = 0;
  const gotInv = store2.view().invites[0];
  assert.ok(gotInv);
  assert.deepEqual(gotInv.scopes, ["read"]);
  assert.equal(gotInv.keyTtlSeconds, 3600);
});

test("rollback discards the edit; caller mutation after commit does not leak", () => {
  const store = new MemoryState();
  const entry: RegistryEntry = { ...testKey("kid-1", "alice"), notBefore: 7 };
  const boom = new Error("boom");
  assert.throws(
    () =>
      store.update((e) => {
        e.putKey(entry);
        throw boom;
      }),
    (err) => err === boom,
  );
  assert.equal(store.view().keys.length, 0);

  // Mutating the caller's object only after putKey must not change the
  // committed value: the store keeps what was there at put time.
  store.update((e) => {
    e.putKey(entry);
    writable(entry).notBefore = 999;
  });
  const got = store.view().keys[0];
  assert.ok(got);
  assert.equal(got.notBefore, 7);
});

test("retained edit cannot corrupt committed state", () => {
  const store = new MemoryState();
  let kept: StateEdit | undefined;
  store.update((e) => {
    e.putKey(testKey("kid-1", "alice"));
    kept = e;
  });
  assert.ok(kept, "edit not retained");
  const original = store.view().keys[0];
  assert.ok(original);
  kept.putKey({ ...original, name: "hacked" });
  kept.putKey(testKey("kid-2", "mallory"));

  const view = store.view();
  assert.equal(view.keys.length, 1);
  const got = view.keys[0];
  assert.ok(got);
  assert.equal(got.name, "alice");
  assert.equal(got.kid, "kid-1");
});

test("sequential updates: 32 commits plus 32 failures leave 32 keys, 16 toggles end absent", () => {
  // JS is single-threaded, so the Go race test reduces to a sequential parity check.
  const store = new MemoryState();
  const writers = 32;
  let failures = 0;
  const boom = new Error("boom");
  for (let i = 0; i < writers; i++) {
    store.update((e) => e.putKey(testKey(`kid-${i}`, `user-${i}`)));
    try {
      store.update(() => {
        throw boom;
      });
      assert.fail("expected throw");
    } catch (err) {
      assert.equal(err, boom); // a swallowed error (assert.fail path) or unrelated throw fails here
      failures++;
    }
  }
  assert.equal(failures, writers);
  assert.equal(store.view().keys.length, writers);

  const togglers = 16;
  const shared = testKey("kid-shared", "shared");
  for (let i = 0; i < togglers; i++) {
    store.update((e) => {
      if (e.key(shared.kid) !== undefined) {
        e.removeKey(shared.kid);
      } else {
        e.putKey(shared);
      }
    });
  }
  // 16 sequential toggles from absent end absent; a lost update breaks the parity.
  assert.equal(store.view().keys.length, writers);
});
