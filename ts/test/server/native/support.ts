import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { JackError } from "../../../src/core/errors.js";
import { Native, activeAdmins } from "../../../src/server/native.js";
import { TOOL_ADMIN_INVITE_CREATE, TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ADMIN_USER_CREATE, TOOL_ADMIN_USER_GET, TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_REVOKE, TOOL_ADMIN_USER_SET_ADMIN } from "../../../src/server/verify.js";
import type { NativeCall } from "../../../src/server/verify.js";
import { MemoryState, StateEdit, type RegistryEntry, type StateStore, type StateView } from "../../../src/server/registry/state.js";
import { encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { loadKeys, type TestKey } from "../../support/fixtures/index.js";


/** The fixtures' clock (Go testNow), in Unix seconds. */
export const NOW = 1767225600;

export const native = new Native();

/** Fixture key by name; undefined would be a typo in the test, so assert it exists. */
export function key(name: string): TestKey {
  const found = loadKeys().keys.find((k) => k.name === name);
  assert.ok(found, `fixture key ${name} expected`);
  return found;
}

/** A registered entry built from a fixture key; admin is present only when true (member-presence rule). */
export function entry(k: TestKey, name: string, admin = false): RegistryEntry {
  const e: { -readonly [K in keyof RegistryEntry]: RegistryEntry[K] } = {
    kid: k.kid,
    publicKey: k.publicKey,
    name,
  };
  if (admin) e.admin = true;
  return e;
}

/** NativeCall builder; Native trusts the call, so ts/now/aud/target are boilerplate. */
export function call(partial: {
  tool: string;
  arguments?: string | undefined;
  caller?: RegistryEntry | undefined;
  kid?: string;
  now?: number;
  state: StateStore;
}): NativeCall {
  return {
    tool: partial.tool,
    arguments: partial.arguments,
    caller: partial.caller,
    kid: partial.kid ?? partial.caller?.kid ?? "",
    ts: NOW,
    now: partial.now ?? NOW,
    aud: "aud",
    state: partial.state,
    target: "",
  };
}

/** Runs fn and returns the caught JackError; a non-JackError or success rethrows. */
export function jackErrorOf(fn: () => unknown): JackError {
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
export function callError(c: NativeCall): JackError | undefined {
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

// ---------------------------------------------------------------------------
// jack.admin.user.set_admin.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// jack.admin.user.create.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Admin gate ordering: 403 admin_required BEFORE argument parsing.
// ---------------------------------------------------------------------------

export const ADMIN_TOOLS = [
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_CREATE,
  TOOL_ADMIN_USER_SET_ADMIN,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_INVITE_LIST,
  TOOL_ADMIN_INVITE_REVOKE,
] as const;

// ---------------------------------------------------------------------------
// invite.create / invite.list / invite.revoke.
// ---------------------------------------------------------------------------

/** Creates an invite and returns the structured result plus the stored record. */
export function createInvite(st: MemoryState, admin: RegistryEntry, args: string): {
  inviteId: string;
  code: string;
  expiresAt: number;
} {
  const result = native.call(call({ tool: TOOL_ADMIN_INVITE_CREATE, arguments: args, caller: admin, state: st }));
  const structured = result.structured as { invite_id: string; code: string; expires_at: number };
  return { inviteId: structured.invite_id, code: structured.code, expiresAt: structured.expires_at };
}

// ---------------------------------------------------------------------------
// whoami and rotation.
// ---------------------------------------------------------------------------

/** Ed25519 key material derived from id, like state-file.test.ts's stateTestKey. */
export function newKeyMaterial(id: string): { priv: KeyObject; publicKey: string; kid: string } {
  const seed = createHash("sha256").update(id).digest();
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  return { priv, publicKey: encodeBase64URL(pub), kid: keyId(pub) };
}

// ---------------------------------------------------------------------------
// activeAdmins and the last-admin rule against validity bounds.
// ---------------------------------------------------------------------------

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
export function outcome(c: NativeCall): () => { ok: boolean; code?: string } {
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
export class InterleavingStore implements StateStore {
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

  lookupInvite(inviteId: string): ReturnType<StateStore["lookupInvite"]> {
    return this.inner.lookupInvite(inviteId);
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
export function revoke(caller: RegistryEntry, targetKid: string, store: StateStore): JackError | undefined {
  return callError(
    call({
      tool: TOOL_ADMIN_USER_REVOKE,
      arguments: JSON.stringify({ kid: targetKid }),
      caller,
      state: store,
    }),
  );
}
