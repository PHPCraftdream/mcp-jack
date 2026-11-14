import { bodyHash, decodeBase64URLFixed } from "./encoding.js";
import { parseCandidateJsonRaw } from "./json-raw.js";
import type { RawJsonNode } from "./json-raw.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { RotationError, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP, ROTATION_GRACE_SECONDS } from "./rotation-record.js";
import type { RotationBinding } from "./rotation-record.js";
import { decodeRotationTrustSnapshot, encodeRotationTrustSnapshot, ROTATION_MAX_TRUST_SNAPSHOT_BYTES } from "./rotation-trust-json.js";
import { validateRotationTrustSnapshot } from "./rotation-trust.js";
import type { RotationClockTuple, RotationTrustSnapshot } from "./rotation-trust.js";

export interface RotationStoreOptions {
  readonly binding: RotationBinding;
  readonly window: number;
  readonly checkpoint: RotationCheckpoint;
  readonly now?: () => number;
}

export interface StoreBundle {
  readonly storeId: string;
  readonly profile: string;
  readonly owner: number;
  readonly dirty: boolean;
  readonly fenced: boolean;
  readonly clockBytes: string;
  readonly snapshotBytes: string;
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function invalidStore(): never { throw new RotationError("rotation_state_unavailable"); }

function fields(node: RawJsonNode, names: readonly string[]): ReadonlyMap<string, RawJsonNode> {
  const members = node.members;
  if (members === undefined || members.size !== names.length || names.some((name) => !members.has(name))) invalidStore();
  return members;
}
function get(members: ReadonlyMap<string, RawJsonNode>, name: string): RawJsonNode {
  const value = members.get(name);
  if (value === undefined) invalidStore();
  return value;
}
function text(node: RawJsonNode): string { if (typeof node.value !== "string") invalidStore(); return node.value; }
function boolean(node: RawJsonNode): boolean { if (typeof node.value !== "boolean") invalidStore(); return node.value; }
function integer(node: RawJsonNode): number {
  if (node.text.length > 16 || !/^(0|[1-9][0-9]*)$/.test(node.text) || typeof node.value !== "number" || !Number.isSafeInteger(node.value)) invalidStore();
  return node.value;
}

export function anchorSnapshot(options: RotationStoreOptions): RotationTrustSnapshot {
  const checkpoint = options.checkpoint;
  return validateRotationTrustSnapshot({ formatVersion: 1, binding: options.binding, window: options.window, checkpoint,
    head: { ordinal: checkpoint.ordinal, hash: checkpoint.hash }, records: [],
    keys: [{ ordinal: checkpoint.ordinal, kid: checkpoint.kid, publicKeyB64u: checkpoint.publicKeyB64u,
      notBefore: checkpoint.ordinal === 0 ? 0 : checkpoint.publishedAt + ROTATION_GRACE_SECONDS, knownCutoff: null }],
    revision: 1, fenced: false, clock: { binding: options.binding, window: options.window, highWater: 0, revision: 0, unsafe: false },
  }, options.binding, options.window, checkpoint);
}

export function clockBytes(clock: RotationClockTuple): string {
  return JSON.stringify({ binding: clock.binding, window: clock.window, high_water: clock.highWater, clock_revision: clock.revision, unsafe: clock.unsafe });
}

export function readClock(bytes: string, options: RotationStoreOptions): RotationClockTuple {
  const root = fields(parseCandidateJsonRaw(bytes), ["binding", "window", "high_water", "clock_revision", "unsafe"]);
  const binding = fields(get(root, "binding"), ["endpoint", "aud"]);
  const highWater = integer(get(root, "high_water"));
  const revision = integer(get(root, "clock_revision"));
  if (text(get(binding, "endpoint")) !== options.binding.endpoint || text(get(binding, "aud")) !== options.binding.aud ||
    integer(get(root, "window")) !== options.window || highWater > ROTATION_MAX_TIMESTAMP || revision > ROTATION_MAX_ORDINAL) invalidStore();
  return Object.freeze({ binding: options.binding, window: options.window, highWater, revision, unsafe: boolean(get(root, "unsafe")) });
}

const CLIENT_DOMAIN = "mcp-jack/client-trust/private-file/v1";

/** Seal — accidental corruption check, не MAC/backup rollback oracle; domain разделяет client/server profiles. */
export function packBundle(bundle: StoreBundle, domain: string): Uint8Array {
  const payload = JSON.stringify({ domain, format_version: 1, store_id: bundle.storeId, profile: bundle.profile, owner: bundle.owner,
    dirty: bundle.dirty, fenced: bundle.fenced, clock: bundle.clockBytes, snapshot: bundle.snapshotBytes });
  const bytes = Buffer.from(JSON.stringify({ payload, checksum: bodyHash(Buffer.from(payload, "utf8")) }), "utf8");
  if (bytes.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) invalidStore();
  return bytes;
}

/** Envelope без snapshot decode: caller проверяет snapshot своего типа против clock. */
export function unpackBundle(bytes: Uint8Array, options: RotationStoreOptions, profile: string, domain: string): { readonly bundle: StoreBundle; readonly clock: RotationClockTuple } {
  if (bytes.length === 0 || bytes.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) invalidStore();
  const outer = fields(parseCandidateJsonRaw(utf8.decode(bytes)), ["payload", "checksum"]);
  const payload = text(get(outer, "payload"));
  if (bodyHash(Buffer.from(payload, "utf8")) !== text(get(outer, "checksum"))) invalidStore();
  const root = fields(parseCandidateJsonRaw(payload), ["domain", "format_version", "store_id", "profile", "owner", "dirty", "fenced", "clock", "snapshot"]);
  const storeId = text(get(root, "store_id"));
  const identity = decodeBase64URLFixed(storeId, 16);
  const owner = integer(get(root, "owner"));
  if (text(get(root, "domain")) !== domain || integer(get(root, "format_version")) !== 1 || identity.every((byte) => byte === 0) || text(get(root, "profile")) !== profile || owner < 1 || owner > ROTATION_MAX_ORDINAL) invalidStore();
  const bundle = Object.freeze({ storeId, profile, owner, dirty: boolean(get(root, "dirty")), fenced: boolean(get(root, "fenced")),
    clockBytes: text(get(root, "clock")), snapshotBytes: text(get(root, "snapshot")) });
  return { bundle, clock: readClock(bundle.clockBytes, options) };
}

export function pack(bundle: StoreBundle): Uint8Array {
  return packBundle(bundle, CLIENT_DOMAIN);
}

export function unpack(bytes: Uint8Array, options: RotationStoreOptions, profile: string): { readonly bundle: StoreBundle; readonly clock: RotationClockTuple; readonly snapshot: RotationTrustSnapshot } {
  const { bundle, clock } = unpackBundle(bytes, options, profile, CLIENT_DOMAIN);
  const snapshot = decodeRotationTrustSnapshot(Buffer.from(bundle.snapshotBytes, "utf8"), options.binding, options.window, options.checkpoint);
  if (snapshot.clock.highWater > clock.highWater || snapshot.clock.revision > clock.revision) invalidStore();
  return { bundle, clock, snapshot };
}

export function encodedSnapshot(snapshot: RotationTrustSnapshot, options: RotationStoreOptions): string {
  return Buffer.from(encodeRotationTrustSnapshot(snapshot, options.binding, options.window, options.checkpoint)).toString("utf8");
}
