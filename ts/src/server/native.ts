/**
 * The protocol-native tools of spec 03: enrollment, key rotation, whoami and
 * user/invite administration, ported from Go's native.go. Integer arguments
 * are judged on their RAW JSON TEXT through the tokenizer of verify.ts (spec
 * 03 section 3), and every state change is one StateStore.update, so it is
 * atomic (spec 03 section 9).
 */
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import {
  BadBase64UrlError,
  decodeBase64URLFixed,
  encodeBase64URL,
  keyId,
} from "../encoding.js";
import { validatePublicKey, verify as verifyEd25519 } from "../ed25519.js";
import { Code, JackError } from "../errors.js";
import { rotateProofString } from "../signing.js";
import { validName, validScope } from "../syntax.js";
import {
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_INVITE_LIST,
  TOOL_ADMIN_INVITE_REVOKE,
  TOOL_ADMIN_USER_CREATE,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ADMIN_USER_SET_SCOPES,
  TOOL_ENROLL,
  TOOL_ROTATE_KEY,
  TOOL_WHOAMI,
  parseJsonRaw,
} from "./verify.js";
import type {
  NativeCall,
  NativeResult,
  NativeTools,
  RawJsonNode,
} from "./verify.js";
import type {
  InviteRecord,
  RegistryEntry,
  StateEdit,
  StateStore,
} from "./state.js";

// ---------------------------------------------------------------------------
// Local helpers.
// ---------------------------------------------------------------------------

/** Builder form of an entry/invite: optional fields are assigned only when defined (exactOptionalPropertyTypes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** Configuration of the native tool implementation. */
export interface NativeOptions {
  /**
   * Returns n bytes from a CSPRNG; undefined means node:crypto randomBytes.
   * Invite codes come from it, so tests may inject a deterministic source but
   * production must not.
   */
  randomBytes?: (n: number) => Uint8Array;
}

const INVALID_PARAMS_MESSAGE = "an argument is missing, mistyped or out of range";
const KEY_REJECTED_MESSAGE = "the public key is not acceptable";

function invalidParams(): JackError {
  return new JackError(400, Code.INVALID_PARAMS, INVALID_PARAMS_MESSAGE);
}

function keyRejected(): JackError {
  return new JackError(400, Code.KEY_REJECTED, KEY_REJECTED_MESSAGE);
}

/** asJackError: a JackError thrown out of update propagates unchanged; anything else is an internal failure. */
function updateError(err: unknown): JackError {
  if (err instanceof JackError) {
    return err;
  }
  return new JackError(500, "internal_error", "internal error");
}

/** Runs fn atomically; a non-JackError throw is an internal error (Go asJackError). */
function runUpdate(state: StateStore, fn: (edit: StateEdit) => void): void {
  try {
    state.update(fn);
  } catch (err) {
    throw updateError(err);
  }
}

// ---------------------------------------------------------------------------
// Argument decoding against the raw-JSON source tree (spec 03 section 3).
// ---------------------------------------------------------------------------

/** params.arguments decoded once per call; lookup happens ONLY via the members map (no __proto__ aliasing). */
type Args = ReadonlyMap<string, RawJsonNode>;

/** Parses params.arguments; undefined means no arguments, anything but a plain object is invalid_params. */
function parseArgs(raw: string | undefined): Args {
  if (raw === undefined) {
    return new Map<string, RawJsonNode>();
  }
  let parsed: { value: unknown; source: RawJsonNode };
  try {
    parsed = parseJsonRaw(raw);
  } catch {
    throw invalidParams();
  }
  const value = parsed.value;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidParams();
  }
  const members = parsed.source.members;
  // parseJsonRaw guarantees members is defined exactly when the value is an object.
  return members ?? new Map<string, RawJsonNode>();
}

/** Member present with a JSON string value. */
function strArg(args: Args, key: string): string | undefined {
  const node = args.get(key);
  if (node === undefined || typeof node.value !== "string") {
    return undefined;
  }
  return node.value;
}

/** An integer ONLY on the lexical rule of spec 03 section 3: no fraction, no exponent (`-0` is 0). */
const INTEGER_TEXT = /^-?(0|[1-9][0-9]*)$/;

/** Member present with an integer JSON number within [min, max]; undefined when absent or invalid. */
function intArg(args: Args, key: string, min: number, max: number): number | undefined {
  const node = args.get(key);
  if (node === undefined || typeof node.value !== "number" || !INTEGER_TEXT.test(node.text)) {
    return undefined;
  }
  const v = node.value;
  if (!Number.isInteger(v) || v < min || v > max) {
    return undefined;
  }
  // Go decodes into int64, where -0 is 0 (spec 03 section 3); normalize at the read boundary.
  return v === 0 ? 0 : v;
}

/** Optional validity bound: absent OR explicit null is unbounded; otherwise the integer rule. */
function timeArg(args: Args, key: string): number | null {
  const node = args.get(key);
  if (node === undefined || node.value === null) {
    return null;
  }
  const v = intArg(args, key, 0, 999999999999);
  if (v === undefined) {
    throw invalidParams();
  }
  return v;
}

/** Array of distinct valid scopes, required. */
function scopesArg(args: Args): string[] {
  const node = args.get("scopes");
  if (node === undefined || node.items === undefined) {
    throw invalidParams();
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of node.items) {
    const s = item.value;
    if (typeof s !== "string" || !validScope(s) || seen.has(s)) {
      throw invalidParams();
    }
    seen.add(s);
    out.push(s);
  }
  return out;
}

/** Optional kind: absent is "human"; an explicit null or any other value is invalid (Go kindFrom). */
function kindArg(args: Args): string {
  const node = args.get("kind");
  if (node === undefined) {
    return "human";
  }
  const kind = node.value;
  if (kind !== "human" && kind !== "agent") {
    throw invalidParams();
  }
  return kind;
}

/** Decodes a submitted public key and applies the validity rules of spec 03 section 2. */
function publicKeyArg(args: Args): Uint8Array {
  const s = strArg(args, "public_key");
  if (s === undefined) {
    throw invalidParams();
  }
  let raw: Uint8Array;
  try {
    raw = decodeBase64URLFixed(s, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      throw keyRejected();
    }
    throw err;
  }
  if (validatePublicKey(raw) !== null) {
    throw keyRejected();
  }
  return raw;
}

// ---------------------------------------------------------------------------
// Shared views and helpers.
// ---------------------------------------------------------------------------

/** Snake_case full view of an entry in Go entryView field order; undefined kind normalizes to "human". */
function entryView(e: RegistryEntry): {
  kid: string;
  public_key: string;
  name: string;
  kind: string;
  scopes: string[];
  not_before: number | null;
  not_after: number | null;
} {
  return {
    kid: e.kid,
    public_key: e.publicKey,
    name: e.name,
    kind: e.kind ?? "human",
    scopes: e.scopes === undefined ? [] : [...e.scopes],
    not_before: e.notBefore ?? null,
    not_after: e.notAfter ?? null,
  };
}

/** True when s is held by scopes (Go contains). */
function holds(scopes: readonly string[] | undefined, want: string): boolean {
  return scopes !== undefined && scopes.includes(want);
}

/** Whether now is inside the entry's validity interval (null bounds are unbounded). */
function entryActive(e: RegistryEntry, now: number): boolean {
  return (
    (e.notBefore === undefined || e.notBefore === null || e.notBefore <= now) &&
    (e.notAfter === undefined || e.notAfter === null || now < e.notAfter)
  );
}

/** Active administrators over a registry snapshot (spec 03 section 4 rule 4). */
export function activeAdmins(keys: readonly RegistryEntry[], now: number): number {
  let n = 0;
  for (const e of keys) {
    if (holds(e.scopes, "admin") && entryActive(e, now)) {
      n++;
    }
  }
  return n;
}

/** base64url(SHA-256(raw invite-code bytes)). */
function inviteIdOf(rawCode: Uint8Array): string {
  return encodeBase64URL(createHash("sha256").update(Buffer.from(rawCode)).digest());
}

/** Rules 1 and 2 of spec 03 section 4 for scopes about to be added to a kind. */
function grantable(
  caller: RegistryEntry,
  added: readonly string[],
  kind: string,
  after: readonly string[],
): void {
  for (const s of added) {
    if (!holds(caller.scopes, s)) {
      throw new JackError(403, Code.SCOPE_ESCALATION, "the key may not grant a scope it does not hold");
    }
  }
  if (kind === "agent" && after.includes("admin")) {
    throw new JackError(403, Code.AGENT_ADMIN_FORBIDDEN, "an agent key cannot hold the admin scope");
  }
}

/** Re-reads the calling administrator inside the transaction (spec 03 section 9). */
function currentAdmin(edit: StateEdit, c: NativeCall): RegistryEntry {
  const caller = edit.key(c.caller?.kid ?? "");
  if (caller === undefined) {
    throw new JackError(401, Code.UNKNOWN_KEY, "unknown key");
  }
  if (!holds(caller.scopes, "admin")) {
    throw new JackError(403, Code.INSUFFICIENT_SCOPE, "the key lacks the admin scope");
  }
  return caller;
}

/** Protected target rule: the administrator must hold every scope the target holds. */
function requireProtectedTarget(caller: RegistryEntry, target: RegistryEntry): void {
  const scopes = target.scopes ?? [];
  for (const s of scopes) {
    if (!holds(caller.scopes, s)) {
      throw new JackError(403, Code.FORBIDDEN_ADMIN_TARGET, "the key holds a scope the administrator lacks");
    }
  }
}

// ---------------------------------------------------------------------------
// Native.
// ---------------------------------------------------------------------------

const DEFAULT_INVITE_TTL = 3600;
const MAX_INVITE_TTL = 604800;
const MAX_KEY_TTL = 31536000;

/** Resolves the random source: the injected override, else node crypto (Go randRead). */
function randomSource(opts: NativeOptions): (n: number) => Uint8Array {
  return opts.randomBytes ?? ((n: number) => nodeRandomBytes(n));
}

/** Draws an invite code; a failing or short random source is a plain Error (Go newInviteCode). */
function drawInviteCode(random: (n: number) => Uint8Array): { code: string; raw: Uint8Array } {
  let raw: Uint8Array;
  try {
    raw = random(32);
  } catch {
    throw new Error("server: no randomness for the invite code");
  }
  if (raw.length !== 32) {
    throw new Error("server: no randomness for the invite code");
  }
  return { code: encodeBase64URL(raw), raw };
}

/** The protocol-native tool implementation (Go NativeTools). */
export class Native implements NativeTools {
  private readonly random: (n: number) => Uint8Array;

  constructor(opts: NativeOptions = {}) {
    this.random = randomSource(opts);
  }

  call(c: NativeCall): NativeResult {
    switch (c.tool) {
      case TOOL_ENROLL:
        return this.enroll(c);
      case TOOL_WHOAMI:
        return this.whoami(c);
      case TOOL_ROTATE_KEY:
        return this.rotate(c);
      case TOOL_ADMIN_USER_LIST:
      case TOOL_ADMIN_USER_GET:
      case TOOL_ADMIN_USER_CREATE:
      case TOOL_ADMIN_USER_SET_SCOPES:
      case TOOL_ADMIN_USER_REVOKE:
      case TOOL_ADMIN_INVITE_CREATE:
      case TOOL_ADMIN_INVITE_LIST:
      case TOOL_ADMIN_INVITE_REVOKE:
        return this.admin(c);
    }
    // Defensive: the verifier gates by isNativeTool.
    throw new JackError(403, Code.OPERATION_DENIED, "operation is not permitted");
  }

  /** Enrolls the signing key with an invite (spec 03 section 3.2); the verifier checked steps 1-4. */
  private enroll(c: NativeCall): NativeResult {
    // Before argument parsing, Go parity.
    if (c.caller !== undefined) {
      throw new JackError(409, Code.KEY_EXISTS, "the key is already registered");
    }
    const args = parseArgs(c.arguments);
    const code = strArg(args, "code");
    const name = strArg(args, "name");
    const publicKey = strArg(args, "public_key");
    if (code === undefined || name === undefined || publicKey === undefined || !validName(name)) {
      throw invalidParams();
    }
    c.target = name;

    let rawCode: Uint8Array;
    try {
      rawCode = decodeBase64URLFixed(code, 32);
    } catch (err) {
      // A malformed code is invalid_invite, not invalid_params.
      if (err instanceof BadBase64UrlError) {
        throw new JackError(403, Code.INVALID_INVITE, "the invite is not valid");
      }
      throw err;
    }
    const inviteId = inviteIdOf(rawCode);

    // A holder object, not a let, so the closure assignment is visible after update returns.
    const out: { entry: RegistryEntry | undefined } = { entry: undefined };
    runUpdate(c.state, (edit) => {
      const invite = edit.invite(inviteId);
      if (invite === undefined || c.now >= invite.expiresAt) {
        throw new JackError(403, Code.INVALID_INVITE, "the invite is not valid");
      }
      if (edit.keyByName(name) !== undefined) {
        throw new JackError(409, Code.NAME_TAKEN, "the name is already used");
      }
      if (edit.key(c.kid) !== undefined) {
        throw new JackError(409, Code.KEY_EXISTS, "the key is already registered");
      }
      const enrolled: Mutable<RegistryEntry> = {
        kid: c.kid,
        publicKey,
        name,
        kind: invite.kind ?? "human",
        scopes: invite.scopes === undefined ? [] : [...invite.scopes],
      };
      if (typeof invite.keyTtlSeconds === "number") {
        enrolled.notAfter = c.now + invite.keyTtlSeconds;
      }
      edit.putKey(enrolled);
      edit.removeInvite(inviteId);
      out.entry = enrolled;
    });
    const enrolled = out.entry;
    if (enrolled === undefined) {
      throw new JackError(500, "internal_error", "internal error");
    }
    return {
      structured: {
        kid: enrolled.kid,
        name: enrolled.name,
        kind: enrolled.kind ?? "human",
        scopes: enrolled.scopes === undefined ? [] : [...enrolled.scopes],
      },
    };
  }

  private whoami(c: NativeCall): NativeResult {
    if (c.caller === undefined) {
      throw new JackError(401, Code.UNKNOWN_KEY, "unknown key");
    }
    parseArgs(c.arguments); // must at least parse to a plain object
    const v = entryView(c.caller);
    return {
      structured: {
        kid: v.kid,
        name: v.name,
        kind: v.kind,
        scopes: v.scopes,
        not_before: v.not_before,
        not_after: v.not_after,
      },
    };
  }

  /** Replaces the caller's key (spec 03 section 3.1); the proof is checked before existence. */
  private rotate(c: NativeCall): NativeResult {
    if (c.caller === undefined) {
      throw new JackError(401, Code.UNKNOWN_KEY, "unknown key");
    }
    const args = parseArgs(c.arguments);
    const publicKey = strArg(args, "public_key");
    const proof = strArg(args, "proof");
    if (publicKey === undefined || proof === undefined) {
      throw invalidParams();
    }
    // Key validity BEFORE the proof (spec 03 section 3.1 order).
    const raw = publicKeyArg(args);
    const newKid = keyId(raw);
    c.target = newKid;

    const signing = rotateProofString(c.aud, c.caller.kid, newKid, c.ts);
    let sig: Uint8Array;
    try {
      sig = decodeBase64URLFixed(proof, 64);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        throw new JackError(400, Code.INVALID_PROOF, "the proof does not verify");
      }
      throw err;
    }
    if (!verifyEd25519(raw, new TextEncoder().encode(signing), sig)) {
      throw new JackError(400, Code.INVALID_PROOF, "the proof does not verify");
    }

    runUpdate(c.state, (edit) => {
      if (edit.key(newKid) !== undefined) {
        throw new JackError(409, Code.KEY_EXISTS, "the key is already registered");
      }
      const current = edit.key(c.caller?.kid ?? "");
      if (current === undefined) {
        throw new JackError(401, Code.UNKNOWN_KEY, "unknown key");
      }
      const moved: Mutable<RegistryEntry> = {
        kid: newKid,
        publicKey,
        name: current.name,
        scopes: current.scopes === undefined ? [] : [...current.scopes],
      };
      if (current.kind !== undefined) moved.kind = current.kind;
      if (current.notBefore !== undefined) moved.notBefore = current.notBefore;
      if (current.notAfter !== undefined) moved.notAfter = current.notAfter;
      edit.removeKey(current.kid);
      edit.putKey(moved);
    });
    return { structured: { kid: newKid } };
  }

  /**
   * The user/invite administration tools in the check order of spec 03
   * section 4: admin scope, arguments, key validity, target, rules,
   * conflicts, last administrator, then the atomic change.
   */
  private admin(c: NativeCall): NativeResult {
    if (c.caller === undefined) {
      throw new JackError(401, Code.UNKNOWN_KEY, "unknown key");
    }
    // BEFORE argument parsing (Go TestAdminToolsRequireAdminBeforeArguments).
    if (!holds(c.caller.scopes, "admin")) {
      throw new JackError(403, Code.INSUFFICIENT_SCOPE, "the key lacks the admin scope");
    }
    const args = parseArgs(c.arguments);

    switch (c.tool) {
      case TOOL_ADMIN_USER_LIST: {
        const keys = [...c.state.view().keys];
        keys.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        return { structured: { users: keys.map(entryView) } };
      }

      case TOOL_ADMIN_USER_GET: {
        const kid = strArg(args, "kid");
        if (kid === undefined) {
          throw invalidParams();
        }
        c.target = kid;
        const entry = c.state.lookup(kid);
        if (entry === undefined) {
          throw new JackError(404, Code.UNKNOWN_TARGET, "no such key");
        }
        return { structured: entryView(entry) };
      }

      case TOOL_ADMIN_USER_CREATE:
        return this.userCreate(c, args);
      case TOOL_ADMIN_USER_SET_SCOPES:
        return this.userSetScopes(c, args);
      case TOOL_ADMIN_USER_REVOKE:
        return this.userRevoke(c, args);
      case TOOL_ADMIN_INVITE_CREATE:
        return this.inviteCreate(c, args);
      case TOOL_ADMIN_INVITE_LIST:
        return this.inviteList(c);
      case TOOL_ADMIN_INVITE_REVOKE:
        return this.inviteRevoke(c, args);
    }
    throw new JackError(403, Code.OPERATION_DENIED, "operation is not permitted");
  }

  private userCreate(c: NativeCall, args: Args): NativeResult {
    // Order: name, scopes, kind, bounds, public key (Go userCreate).
    const name = strArg(args, "name");
    if (name === undefined || !validName(name)) {
      throw invalidParams();
    }
    const scopes = scopesArg(args);
    const kind = kindArg(args);
    const notBefore = timeArg(args, "not_before");
    const notAfter = timeArg(args, "not_after");
    if (notBefore !== null && notAfter !== null && notBefore >= notAfter) {
      throw invalidParams();
    }
    const raw = publicKeyArg(args);
    const kid = keyId(raw);
    c.target = name;

    runUpdate(c.state, (edit) => {
      const caller = currentAdmin(edit, c);
      grantable(caller, scopes, kind, scopes);
      if (edit.keyByName(name) !== undefined) {
        throw new JackError(409, Code.NAME_TAKEN, "the name is already used");
      }
      if (edit.key(kid) !== undefined) {
        throw new JackError(409, Code.KEY_EXISTS, "the key is already registered");
      }
      const entry: Mutable<RegistryEntry> = {
        kid,
        publicKey: strArg(args, "public_key") ?? "",
        name,
        kind,
        scopes: [...scopes],
        notBefore,
        notAfter,
      };
      edit.putKey(entry);
    });
    return { structured: { kid } };
  }

  private userSetScopes(c: NativeCall, args: Args): NativeResult {
    const kid = strArg(args, "kid");
    if (kid === undefined) {
      throw invalidParams();
    }
    const scopes = scopesArg(args);
    c.target = kid;

    const out: { view: ReturnType<typeof entryView> | undefined } = { view: undefined };
    runUpdate(c.state, (edit) => {
      const caller = currentAdmin(edit, c);
      const target = edit.key(kid);
      if (target === undefined) {
        throw new JackError(404, Code.UNKNOWN_TARGET, "no such key");
      }
      const targetKind = target.kind ?? "human";
      const added = scopes.filter((s) => !holds(target.scopes, s));
      grantable(caller, added, targetKind, scopes);
      requireProtectedTarget(caller, target);
      // Last admin against the registry AS IT WOULD BE after the change.
      const after = edit.keys().map((e) => (e.kid === kid ? { ...e, scopes: [...scopes] } : e));
      if (activeAdmins(after, c.now) < 1) {
        throw new JackError(409, Code.LAST_ADMIN, "the change would leave no active administrator");
      }
      const updated: Mutable<RegistryEntry> = {
        kid: target.kid,
        publicKey: target.publicKey,
        name: target.name,
        scopes: [...scopes],
      };
      if (target.kind !== undefined) updated.kind = target.kind;
      if (target.notBefore !== undefined) updated.notBefore = target.notBefore;
      if (target.notAfter !== undefined) updated.notAfter = target.notAfter;
      edit.putKey(updated);
      out.view = entryView(updated);
    });
    if (out.view === undefined) {
      throw new JackError(500, "internal_error", "internal error");
    }
    return { structured: out.view };
  }

  private userRevoke(c: NativeCall, args: Args): NativeResult {
    const kid = strArg(args, "kid");
    if (kid === undefined) {
      throw invalidParams();
    }
    c.target = kid;

    runUpdate(c.state, (edit) => {
      const caller = currentAdmin(edit, c);
      const target = edit.key(kid);
      if (target === undefined) {
        throw new JackError(404, Code.UNKNOWN_TARGET, "no such key");
      }
      requireProtectedTarget(caller, target);
      const rest = edit.keys().filter((e) => e.kid !== kid);
      if (activeAdmins(rest, c.now) < 1) {
        throw new JackError(409, Code.LAST_ADMIN, "the change would leave no active administrator");
      }
      edit.removeKey(kid);
    });
    return { structured: { kid } };
  }

  private inviteCreate(c: NativeCall, args: Args): NativeResult {
    const scopes = scopesArg(args);
    const kind = kindArg(args);
    let ttl = DEFAULT_INVITE_TTL;
    if (args.has("ttl_seconds")) {
      const v = intArg(args, "ttl_seconds", 1, MAX_INVITE_TTL);
      if (v === undefined) {
        throw invalidParams();
      }
      ttl = v;
    }
    let keyTtl: number | undefined;
    if (args.has("key_ttl_seconds")) {
      const v = intArg(args, "key_ttl_seconds", 1, MAX_KEY_TTL);
      if (v === undefined) {
        throw invalidParams();
      }
      keyTtl = v;
    }

    // Randomness is drawn BEFORE the update (Go parity); a bad source is an internal error.
    let drawn: { code: string; raw: Uint8Array };
    try {
      drawn = drawInviteCode(this.random);
    } catch {
      throw new JackError(500, "internal_error", "internal error");
    }
    const inviteId = inviteIdOf(drawn.raw);
    c.target = inviteId;
    const expiresAt = c.now + ttl;

    runUpdate(c.state, (edit) => {
      const caller = currentAdmin(edit, c);
      grantable(caller, scopes, kind, scopes);
      const invite: Mutable<InviteRecord> = {
        inviteId,
        scopes: [...scopes],
        kind,
        createdBy: caller.kid,
        createdAt: c.now,
        expiresAt,
      };
      if (keyTtl !== undefined) {
        invite.keyTtlSeconds = keyTtl;
      }
      edit.putInvite(invite);
    });
    return { structured: { invite_id: inviteId, code: drawn.code, expires_at: expiresAt } };
  }

  private inviteList(c: NativeCall): NativeResult {
    const live = c.state.view().invites.filter((i) => c.now < i.expiresAt);
    live.sort((a, b) =>
      a.createdAt !== b.createdAt ? (a.createdAt < b.createdAt ? -1 : 1) : a.inviteId < b.inviteId ? -1 : a.inviteId > b.inviteId ? 1 : 0,
    );
    return {
      structured: {
        invites: live.map((i) => ({
          invite_id: i.inviteId,
          scopes: i.scopes === undefined ? [] : [...i.scopes],
          kind: i.kind ?? "human",
          created_by: i.createdBy,
          created_at: i.createdAt,
          expires_at: i.expiresAt,
        })),
      },
    };
  }

  private inviteRevoke(c: NativeCall, args: Args): NativeResult {
    const inviteId = strArg(args, "invite_id");
    if (inviteId === undefined) {
      throw invalidParams();
    }
    c.target = inviteId;

    runUpdate(c.state, (edit) => {
      currentAdmin(edit, c);
      const invite = edit.invite(inviteId);
      if (invite === undefined || c.now >= invite.expiresAt) {
        throw new JackError(404, Code.UNKNOWN_TARGET, "no such invite");
      }
      edit.removeInvite(inviteId);
    });
    return { structured: { invite_id: inviteId } };
  }
}

/** Creates the first administrator's invite out of band (spec 03 section 5); the code is stored nowhere else. */
export function bootstrapAdmin(
  state: StateStore,
  now: number,
  ttlSeconds: number,
  opts: NativeOptions = {},
): string {
  if (ttlSeconds < 1 || ttlSeconds > MAX_INVITE_TTL) {
    throw new Error("server: bootstrap ttl must be between 1 and 604800 seconds");
  }
  // Go returns the randomness error unwrapped.
  const drawn = drawInviteCode(randomSource(opts));
  const inviteId = inviteIdOf(drawn.raw);
  const invite: Mutable<InviteRecord> = {
    inviteId,
    scopes: ["admin"],
    kind: "human",
    createdBy: "bootstrap",
    createdAt: now,
    expiresAt: now + ttlSeconds,
  };
  state.update((edit) => {
    edit.putInvite(invite);
  });
  return drawn.code;
}
