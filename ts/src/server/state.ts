/**
 * In-memory registry and invite state with atomic update closures; the
 * last-admin rule depends on the atomicity. Ported from Go's state.go.
 */

/** One registered key in the server state (spec 02 section 1); field shapes match ts/test/fixtures.ts. */
export interface RegistryEntry {
  readonly kid: string;
  readonly publicKey: string;
  readonly name: string;
  readonly kind?: string | null;
  readonly scopes?: readonly string[];
  readonly notBefore?: number | null;
  readonly notAfter?: number | null;
}

/** One pending invite (spec 03 sections 3.2 and 9). */
export interface InviteRecord {
  readonly inviteId: string;
  readonly scopes?: readonly string[];
  readonly kind?: string | null;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly keyTtlSeconds?: number | null;
}

/** Immutable snapshot of the store: deep copies, keys sorted by kid, invites sorted by inviteId. */
export interface StateView {
  readonly keys: RegistryEntry[];
  readonly invites: InviteRecord[];
}

/** Builder form of an entry/invite: optional fields are assigned only when defined (exactOptionalPropertyTypes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** Wire (snake_case) shape of a registry entry, exactly the on-disk/fixture field names and order. */
export interface WireRegistryEntry {
  kid: string;
  public_key: string;
  name: string;
  kind: string | null;
  scopes: string[];
  not_before: number | null;
  not_after: number | null;
}

/** Wire shape of an invite record. */
export interface WireInviteRecord {
  invite_id: string;
  scopes: string[];
  kind: string | null;
  created_by: string;
  created_at: number;
  expires_at: number;
  key_ttl_seconds: number | null;
}

/** Snake_case wire object in Go struct-tag field order; scopes undefined normalizes to []; bounds undefined map to null. */
export function serializeRegistryEntry(entry: RegistryEntry): WireRegistryEntry {
  return {
    kid: entry.kid,
    public_key: entry.publicKey,
    name: entry.name,
    kind: entry.kind ?? null,
    scopes: entry.scopes === undefined ? [] : [...entry.scopes],
    not_before: entry.notBefore ?? null,
    not_after: entry.notAfter ?? null,
  };
}

/** Same for invites. */
export function serializeInviteRecord(invite: InviteRecord): WireInviteRecord {
  return {
    invite_id: invite.inviteId,
    scopes: invite.scopes === undefined ? [] : [...invite.scopes],
    kind: invite.kind ?? null,
    created_by: invite.createdBy,
    created_at: invite.createdAt,
    expires_at: invite.expiresAt,
    key_ttl_seconds: invite.keyTtlSeconds ?? null,
  };
}

/** Shared registry/invite store interface (Go StateStore); update is synchronous and atomic. */
export interface StateStore {
  view(): StateView;
  /** Copy of the entry with the given kid, or undefined. Must not copy the whole registry. */
  lookup(kid: string): RegistryEntry | undefined;
  /** Runs fn on a deep copy of the state and swaps it in only if fn returned normally; if fn throws, nothing is applied and the error propagates unchanged. */
  update(fn: (edit: StateEdit) => void): void;
}

/** Internal clone of one entry: copies the scopes array; numbers are already copied by value. */
function cloneEntry(entry: RegistryEntry): RegistryEntry {
  const out: Mutable<RegistryEntry> = {
    kid: entry.kid,
    publicKey: entry.publicKey,
    name: entry.name,
    scopes: entry.scopes === undefined ? [] : [...entry.scopes],
  };
  if (entry.kind !== undefined) {
    out.kind = entry.kind;
  }
  if (entry.notBefore !== undefined) {
    out.notBefore = entry.notBefore;
  }
  if (entry.notAfter !== undefined) {
    out.notAfter = entry.notAfter;
  }
  return out;
}

/** Internal clone of one invite. */
function cloneInvite(invite: InviteRecord): InviteRecord {
  const out: Mutable<InviteRecord> = {
    inviteId: invite.inviteId,
    scopes: invite.scopes === undefined ? [] : [...invite.scopes],
    createdBy: invite.createdBy,
    createdAt: invite.createdAt,
    expiresAt: invite.expiresAt,
  };
  if (invite.kind !== undefined) {
    out.kind = invite.kind;
  }
  if (invite.keyTtlSeconds !== undefined) {
    out.keyTtlSeconds = invite.keyTtlSeconds;
  }
  return out;
}

/** Deep copies of entries (entry object and scopes array each copied). */
export function cloneKeys(keys: readonly RegistryEntry[]): RegistryEntry[] {
  return keys.map(cloneEntry);
}

/** Deep copies of invites. */
export function cloneInvites(invites: readonly InviteRecord[]): InviteRecord[] {
  return invites.map(cloneInvite);
}

/** Clone + sort by kid. Kids are base64url ASCII, so UTF-16 code-unit order equals Go's byte order. */
export function sortedKeys(keys: readonly RegistryEntry[]): RegistryEntry[] {
  return cloneKeys(keys).sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
}

/** Clone + sort by inviteId (same ASCII-order argument as sortedKeys). */
export function sortedInvites(invites: readonly InviteRecord[]): InviteRecord[] {
  return cloneInvites(invites).sort((a, b) =>
    a.inviteId < b.inviteId ? -1 : a.inviteId > b.inviteId ? 1 : 0,
  );
}

/** Deep copy of the entry with the given kid, or undefined. */
export function lookupKey(keys: readonly RegistryEntry[], kid: string): RegistryEntry | undefined {
  for (const entry of keys) {
    if (entry.kid === kid) {
      return cloneEntry(entry);
    }
  }
  return undefined;
}

/** Mutable deep copy of the current state handed to update() callbacks (Go StateEdit). */
export class StateEdit {
  // Field names avoid the public keys()/invites() methods: a field and a
  // method cannot share a name in one class.
  private keyEntries: RegistryEntry[];
  private inviteEntries: InviteRecord[];

  /** Internal; stores hand edits to update() callbacks. Left callable so tests can retain edits. */
  constructor(keys: RegistryEntry[], invites: InviteRecord[]) {
    this.keyEntries = keys;
    this.inviteEntries = invites;
  }

  /** Deep copy of the entry with the given kid, or undefined. */
  key(kid: string): RegistryEntry | undefined {
    return lookupKey(this.keyEntries, kid);
  }

  /** Deep copy of the entry with the given name, or undefined. */
  keyByName(name: string): RegistryEntry | undefined {
    for (const entry of this.keyEntries) {
      if (entry.name === name) {
        return cloneEntry(entry);
      }
    }
    return undefined;
  }

  /** Deep copies of all entries sorted by kid. */
  keys(): RegistryEntry[] {
    return sortedKeys(this.keyEntries);
  }

  /** Deep copy of the invite with the given id, or undefined. */
  invite(inviteId: string): InviteRecord | undefined {
    for (const inv of this.inviteEntries) {
      if (inv.inviteId === inviteId) {
        return cloneInvite(inv);
      }
    }
    return undefined;
  }

  /** Deep copies of all invites sorted by inviteId. */
  invites(): InviteRecord[] {
    return sortedInvites(this.inviteEntries);
  }

  /** Replaces by kid or appends; clones the input; undefined scopes normalize to [] (Go's nil→empty). */
  putKey(entry: RegistryEntry): void {
    const cloned = cloneEntry(entry);
    for (const [i, cur] of this.keyEntries.entries()) {
      if (cur.kid === cloned.kid) {
        this.keyEntries[i] = cloned;
        return;
      }
    }
    this.keyEntries.push(cloned);
  }

  /** Deletes the entry with the given kid; reports whether anything was removed. */
  removeKey(kid: string): boolean {
    for (const [i, cur] of this.keyEntries.entries()) {
      if (cur.kid === kid) {
        this.keyEntries.splice(i, 1);
        return true;
      }
    }
    return false;
  }

  /** Replaces by inviteId or appends; clones the input; undefined scopes normalize to []. */
  putInvite(invite: InviteRecord): void {
    const cloned = cloneInvite(invite);
    for (const [i, cur] of this.inviteEntries.entries()) {
      if (cur.inviteId === cloned.inviteId) {
        this.inviteEntries[i] = cloned;
        return;
      }
    }
    this.inviteEntries.push(cloned);
  }

  /** Deletes the invite with the given id; reports whether anything was removed. */
  removeInvite(inviteId: string): boolean {
    for (const [i, cur] of this.inviteEntries.entries()) {
      if (cur.inviteId === inviteId) {
        this.inviteEntries.splice(i, 1);
        return true;
      }
    }
    return false;
  }

  /** Module-internal: stores shallow-read this right before cloning on swap-in. */
  snapshot(): { keys: RegistryEntry[]; invites: InviteRecord[] } {
    return { keys: this.keyEntries, invites: this.inviteEntries };
  }
}

/** In-memory StateStore (Go MemoryState). JS is single-threaded and update is synchronous, so no lock is needed. */
export class MemoryState implements StateStore {
  private keys: RegistryEntry[] = [];
  private invites: InviteRecord[] = [];

  /** Deep-copy snapshot, keys sorted by kid and invites sorted by inviteId. */
  view(): StateView {
    return { keys: sortedKeys(this.keys), invites: sortedInvites(this.invites) };
  }

  /** Deep copy of the entry with the given kid, without copying the whole registry. */
  lookup(kid: string): RegistryEntry | undefined {
    return lookupKey(this.keys, kid);
  }

  /**
   * Runs fn on a deep copy; swaps the copy in only if fn returned normally.
   * The swap-in re-clone keeps an edit retained past update from aliasing
   * committed state; a thrown error propagates unchanged with the edit discarded.
   */
  update(fn: (edit: StateEdit) => void): void {
    const edit = new StateEdit(cloneKeys(this.keys), cloneInvites(this.invites));
    fn(edit);
    this.keys = cloneKeys(edit.snapshot().keys);
    this.invites = cloneInvites(edit.snapshot().invites);
  }
}
