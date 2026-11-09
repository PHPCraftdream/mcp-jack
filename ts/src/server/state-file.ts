/** Strict load and persist of the server state file; ported from Go's statefile.go.
 *
 * Admin-only contract: an entry/invite may carry an optional strict-boolean
 * `admin` (absent means false); an invite's `key_ttl_seconds` is absent when
 * unset and otherwise an integer in 1..31536000 — never null.
 */
import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { decodeBase64URL, BadBase64UrlError, keyId } from "../encoding.js";
import { validatePublicKey } from "../ed25519.js";
import { validName } from "../syntax.js";
import {
  type InviteRecord,
  type RegistryEntry,
  StateEdit,
  type StateStore,
  type StateView,
  cloneInvites,
  cloneKeys,
  lookupKey,
  serializeInviteRecord,
  serializeRegistryEntry,
  sortedInvites,
  sortedKeys,
} from "./state.js";

/** Builder form of an entry/invite: optional fields are assigned only when defined (exactOptionalPropertyTypes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** Reports an existing state file that failed strict decode or validation (Go ErrStateCorrupt; Go errors.Is becomes instanceof). */
export class StateCorruptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StateCorruptError";
  }
}

/** On-disk version this module reads and writes. */
const VERSION = 1;

/** Throws a StateCorruptError with the bare detail; openFileState adds the file path in one place. */
function corrupt(detail: string): never {
  throw new StateCorruptError(detail);
}

/** Plain JSON object check (arrays and null are not objects for this purpose). */
function asObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    corrupt(`${what}: wrong shape`);
  }
  return value as Record<string, unknown>;
}

/** Rejects any field outside the allowed set (Go DisallowUnknownFields). */
function checkKnownFields(obj: Record<string, unknown>, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      corrupt(`${what}: unknown field "${key}"`);
    }
  }
}

/** String field: missing or null decodes as "" (Go's leniency for null scalars); any other non-string is corrupt. */
function stringField(obj: Record<string, unknown>, key: string, what: string): string {
  if (!Object.hasOwn(obj, key)) {
    return "";
  }
  const value = obj[key];
  if (value === null) {
    return "";
  }
  if (typeof value !== "string") {
    corrupt(`${what}.${key}: not a string`);
  }
  return value;
}

/** Nullable integer field: missing or null stays undefined; non-integers are corrupt. */
function nullableIntField(obj: Record<string, unknown>, key: string, what: string): number | undefined {
  if (!Object.hasOwn(obj, key)) {
    return undefined;
  }
  const value = obj[key];
  if (value === null) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isInteger(value)) {
    corrupt(`${what}.${key}: not an integer`);
  }
  return value;
}

/** Required nonnegative integer field; missing, null, non-integers and negatives are corrupt. */
function requiredNonnegativeIntField(obj: Record<string, unknown>, key: string, what: string): number {
  if (!Object.hasOwn(obj, key)) {
    corrupt(`${what}.${key}: must be a non-negative integer`);
  }
  const value = obj[key];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    corrupt(`${what}.${key}: must be a non-negative integer`);
  }
  return value;
}

/** Boolean field: absent decodes as false; present value must be exactly true or false. */
function boolField(obj: Record<string, unknown>, key: string, what: string): boolean {
  if (!Object.hasOwn(obj, key)) {
    return false;
  }
  const value = obj[key];
  if (value === true) {
    return true;
  }
  if (value === false) {
    return false;
  }
  corrupt(`${what}.${key}: not a boolean`);
}

/** Strict per-entry decode into a RegistryEntry; no optional property ever receives undefined. */
function decodeEntry(value: unknown, what: string): RegistryEntry {
  const obj = asObject(value, what);
  checkKnownFields(obj, ["kid", "public_key", "name", "admin", "not_before", "not_after"], what);
  const decoded: Mutable<RegistryEntry> = {
    kid: stringField(obj, "kid", what),
    publicKey: stringField(obj, "public_key", what),
    name: stringField(obj, "name", what),
  };
  const admin = boolField(obj, "admin", what);
  if (admin) {
    decoded.admin = true;
  }
  const notBefore = nullableIntField(obj, "not_before", what);
  if (notBefore !== undefined) {
    decoded.notBefore = notBefore;
  }
  const notAfter = nullableIntField(obj, "not_after", what);
  if (notAfter !== undefined) {
    decoded.notAfter = notAfter;
  }
  return decoded;
}

/** Maximum invite key TTL in seconds (spec 03 section 3.2). */
const MAX_KEY_TTL_SECONDS = 31536000;

/** Strict per-invite decode into an InviteRecord. */
function decodeInvite(value: unknown, what: string): InviteRecord {
  const obj = asObject(value, what);
  checkKnownFields(obj, ["invite_id", "admin", "created_by", "created_at", "expires_at", "key_ttl_seconds"], what);
  const decoded: Mutable<InviteRecord> = {
    inviteId: stringField(obj, "invite_id", what),
    createdBy: stringField(obj, "created_by", what),
    createdAt: requiredNonnegativeIntField(obj, "created_at", what),
    expiresAt: requiredNonnegativeIntField(obj, "expires_at", what),
  };
  // Invite-record validity (spec 03 section 10): non-empty strings and
  // created_at <= expires_at; required timestamp helpers enforce nonnegative integers.
  if (decoded.inviteId === "") {
    corrupt(`${what}.invite_id: must be a non-empty string`);
  }
  if (decoded.createdBy === "") {
    corrupt(`${what}.created_by: must be a non-empty string`);
  }
  if (decoded.createdAt > decoded.expiresAt) {
    corrupt(`${what}.created_at: must not be after expires_at`);
  }
  const admin = boolField(obj, "admin", what);
  if (admin) {
    decoded.admin = true;
  }
  if (Object.hasOwn(obj, "key_ttl_seconds")) {
    const value = obj["key_ttl_seconds"];
    if (value === null) {
      corrupt(`${what}.key_ttl_seconds: must be absent or an integer`);
    }
    if (typeof value !== "number" || !Number.isInteger(value)) {
      corrupt(`${what}.key_ttl_seconds: must be absent or an integer`);
    }
    if (value < 1 || value > MAX_KEY_TTL_SECONDS) {
      corrupt(`${what}.key_ttl_seconds: must be an integer in 1..${MAX_KEY_TTL_SECONDS}`);
    }
    decoded.keyTtlSeconds = value;
  }
  return decoded;
}

/** validateKeys enforces the load-time rules of 02-authorization.md section 1, in Go's order. */
function validateKeys(keys: readonly RegistryEntry[]): void {
  const seenNames = new Set<string>();
  for (const k of keys) {
    if (!validName(k.name)) {
      corrupt(`invalid name ${JSON.stringify(k.name)} for key ${k.kid}`);
    }
    if (seenNames.has(k.name)) {
      corrupt(`duplicate name ${k.name}`);
    }
    seenNames.add(k.name);
    if (k.notBefore !== undefined && k.notBefore !== null && k.notBefore < 0) {
      corrupt(`negative not_before for key ${k.kid}`);
    }
    if (k.notAfter !== undefined && k.notAfter !== null && k.notAfter < 0) {
      corrupt(`negative not_after for key ${k.kid}`);
    }
    if (
      k.notBefore !== undefined &&
      k.notBefore !== null &&
      k.notAfter !== undefined &&
      k.notAfter !== null &&
      k.notBefore >= k.notAfter
    ) {
      corrupt(`not_before not before not_after for key ${k.kid}`);
    }
    let pub: Uint8Array;
    try {
      pub = decodeBase64URL(k.publicKey);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        corrupt(`invalid public key for key ${k.kid}`);
      }
      throw err;
    }
    if (pub.length !== 32) {
      corrupt(`invalid public key for key ${k.kid}`);
    }
    if (keyId(pub) !== k.kid) {
      corrupt(`kid mismatch for key ${k.kid}`);
    }
    const invalid = validatePublicKey(pub);
    if (invalid !== null) {
      corrupt(`key ${k.kid}: ${invalid.message}`);
    }
  }
}

/**
 * Decodes a state document strictly, in Go decodeState's order so the
 * rejection classes match: parse, shape, unknown fields, version, duplicate
 * ids, then validateKeys. Errors carry the bare detail;
 * openFileState prefixes them with the file path.
 */
function decodeState(text: string): { keys: RegistryEntry[]; invites: InviteRecord[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    corrupt((err as Error).message);
  }
  // JSON.parse already rejects trailing data after the document and accepts
  // trailing whitespace — Go's second-decode/EOF check — and cannot produce
  // undefined holes.
  const doc = asObject(parsed, "state document");
  checkKnownFields(doc, ["version", "keys", "invites"], "state document");

  const versionValue = Object.hasOwn(doc, "version") ? doc["version"] : null;
  const version =
    versionValue === null
      ? 0 // absent or null decodes as 0, which then fails the version check
      : (typeof versionValue === "number" && Number.isInteger(versionValue)
          ? versionValue
          : corrupt("version: not an integer"));

  const keysValue = doc["keys"];
  const keys: RegistryEntry[] = Array.isArray(keysValue)
    ? keysValue.map((item, i) => decodeEntry(item, `keys[${i}]`))
    : corrupt("keys: not an array");
  const invitesValue = doc["invites"];
  const invites: InviteRecord[] = Array.isArray(invitesValue)
    ? invitesValue.map((item, i) => decodeInvite(item, `invites[${i}]`))
    : corrupt("invites: not an array");

  // Go decodes the whole document before the version check, so element
  // decoding errors surface before version errors.
  if (version !== VERSION) {
    corrupt(`unsupported version ${version}`);
  }

  const seenKids = new Set<string>();
  for (const k of keys) {
    if (seenKids.has(k.kid)) {
      corrupt(`duplicate key ${k.kid}`);
    }
    seenKids.add(k.kid);
  }
  const seenInvites = new Set<string>();
  for (const v of invites) {
    if (seenInvites.has(v.inviteId)) {
      corrupt(`duplicate invite ${v.inviteId}`);
    }
    seenInvites.add(v.inviteId);
  }
  validateKeys(keys);
  return { keys, invites };
}

/** File-backed StateStore; on-disk format {"version":1,"keys":[...],"invites":[...]}; atomic writes. */
export class FileState implements StateStore {
  private readonly path: string;
  private keys: RegistryEntry[];
  private invites: InviteRecord[];

  /** Internal; use openFileState(). */
  constructor(path: string, keys: RegistryEntry[], invites: InviteRecord[]) {
    this.path = path;
    this.keys = keys;
    this.invites = invites;
  }

  /** Deep-copy snapshot, keys sorted by kid and invites sorted by inviteId. */
  view(): StateView {
    return { keys: sortedKeys(this.keys), invites: sortedInvites(this.invites) };
  }

  /** Deep copy of the entry with the given kid, without copying the whole registry. */
  lookup(kid: string): RegistryEntry | undefined {
    return lookupKey(this.keys, kid);
  }

  /**
   * Runs fn on a deep copy; on a throw nothing is written or swapped in and
   * the error propagates unchanged. On success the file is written atomically
   * first and only then the memory state is swapped in; a write failure leaves
   * both disk and memory untouched.
   */
  update(fn: (edit: StateEdit) => void): void {
    const edit = new StateEdit(cloneKeys(this.keys), cloneInvites(this.invites));
    fn(edit);
    this.write(edit.snapshot());
    this.keys = cloneKeys(edit.snapshot().keys);
    this.invites = cloneInvites(edit.snapshot().invites);
  }

  /** Marshals deterministically and atomically replaces the file (temp file in the same directory, fsync, rename). */
  private write(snap: { keys: RegistryEntry[]; invites: InviteRecord[] }): void {
    const doc = {
      version: VERSION,
      keys: sortedKeys(snap.keys).map(serializeRegistryEntry),
      invites: sortedInvites(snap.invites).map(serializeInviteRecord),
    };
    const data = JSON.stringify(doc, null, 2) + "\n";
    const tmp = join(dirname(this.path), `.mcp-jack-state-${randomBytes(8).toString("hex")}.tmp`);
    let fd: number | undefined;
    try {
      // Exclusive create: never clobber an existing file (Go CreateTemp).
      fd = openSync(tmp, "wx", 0o600);
      // writeSync can write partially, so loop until the whole buffer is out.
      const buf = Buffer.from(data, "utf8");
      let written = 0;
      while (written < buf.length) {
        written += writeSync(fd, buf, written, buf.length - written);
      }
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
    } catch (err) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // best effort: the unlink below is what matters
        }
      }
      try {
        unlinkSync(tmp);
      } catch {
        // best effort
      }
      throw new Error(`write state file ${this.path}: ${(err as Error).message}`);
    }
    try {
      renameSync(tmp, this.path);
    } catch (err) {
      try {
        unlinkSync(tmp);
      } catch {
        // best effort
      }
      throw new Error(`rename state file ${this.path}: ${(err as Error).message}`);
    }
  }
}

/** Loads the state file at path. A missing file yields an empty store; anything unreadable or any strict-decode/validation failure throws. */
export function openFileState(path: string): FileState {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // Go: a missing file yields an empty store.
      return new FileState(path, [], []);
    }
    throw new Error(`read state file ${path}: ${(err as Error).message}`);
  }
  // Exactly one place attaches the file path, so EVERY load-time rejection
  // mentions it (Go wraps the whole decode with "state file %s: %w").
  let decoded: { keys: RegistryEntry[]; invites: InviteRecord[] };
  try {
    decoded = decodeState(text);
  } catch (err) {
    if (err instanceof StateCorruptError) {
      throw new StateCorruptError(`state file ${path}: ${err.message}`);
    }
    throw err;
  }
  return new FileState(path, decoded.keys, decoded.invites);
}
