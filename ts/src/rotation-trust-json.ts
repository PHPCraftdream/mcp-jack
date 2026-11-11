import { parseCandidateJsonRaw } from "./json-raw.js";
import type { RawJsonNode } from "./json-raw.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { RotationError, ROTATION_MAX_ORDINAL } from "./rotation-record.js";
import type { RotationBinding } from "./rotation-record.js";
import { validateRotationTrustSnapshot } from "./rotation-trust.js";
import type { RotationClockTuple, RotationTrustKey, RotationTrustSnapshot } from "./rotation-trust.js";

export const ROTATION_MAX_TRUST_SNAPSHOT_BYTES = 16 * 1024 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function fail(): never {
  throw new RotationError("rotation_state_unknown");
}

function object(node: RawJsonNode, names: readonly string[]): ReadonlyMap<string, RawJsonNode> {
  const members = node.members;
  if (members === undefined || members.size !== names.length || names.some((name) => !members.has(name))) fail();
  return members;
}

function field(members: ReadonlyMap<string, RawJsonNode>, name: string): RawJsonNode {
  const value = members.get(name);
  if (value === undefined) fail();
  return value;
}

function text(node: RawJsonNode): string {
  if (typeof node.value !== "string") fail();
  return node.value;
}

function number(node: RawJsonNode): number {
  if (node.text.length > 16 || !/^(0|[1-9][0-9]*)$/.test(node.text) || typeof node.value !== "number" ||
    !Number.isSafeInteger(node.value) || node.value > ROTATION_MAX_ORDINAL) fail();
  return node.value;
}

function boolean(node: RawJsonNode): boolean {
  if (typeof node.value !== "boolean") fail();
  return node.value;
}

function binding(node: RawJsonNode): RotationBinding {
  const value = object(node, ["endpoint", "aud"]);
  return { endpoint: text(field(value, "endpoint")), aud: text(field(value, "aud")) };
}

function checkpoint(node: RawJsonNode): RotationCheckpoint {
  const value = object(node, ["ordinal", "hash", "kid", "public_key", "published_at"]);
  return { ordinal: number(field(value, "ordinal")), hash: text(field(value, "hash")), kid: text(field(value, "kid")),
    publicKeyB64u: text(field(value, "public_key")), publishedAt: number(field(value, "published_at")) };
}

function key(node: RawJsonNode): RotationTrustKey {
  const value = object(node, ["ordinal", "kid", "public_key", "not_before", "known_cutoff"]);
  const cutoff = field(value, "known_cutoff");
  return { ordinal: number(field(value, "ordinal")), kid: text(field(value, "kid")), publicKeyB64u: text(field(value, "public_key")),
    notBefore: number(field(value, "not_before")), knownCutoff: cutoff.value === null ? null : number(cutoff) };
}

function clock(node: RawJsonNode): RotationClockTuple {
  const value = object(node, ["binding", "window", "high_water", "clock_revision", "unsafe"]);
  return { binding: binding(field(value, "binding")), window: number(field(value, "window")), highWater: number(field(value, "high_water")),
    revision: number(field(value, "clock_revision")), unsafe: boolean(field(value, "unsafe")) };
}

/** Strict local parse сохраняет fences; не выполняет clock operation, persistence или ACK. */
export function decodeRotationTrustSnapshot(
  bytes: Uint8Array,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): RotationTrustSnapshot {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) fail();
    const root = object(parseCandidateJsonRaw(utf8.decode(bytes)), ["format_version", "binding", "window", "checkpoint", "head", "records", "keys", "trust_revision", "fenced", "clock"]);
    const head = object(field(root, "head"), ["ordinal", "hash"]);
    const records = field(root, "records").items;
    const keys = field(root, "keys").items;
    if (records === undefined || records.length >= ROTATION_MAX_RETAINED_KEYS || keys === undefined || keys.length > ROTATION_MAX_RETAINED_KEYS) fail();
    return validateRotationTrustSnapshot({
      formatVersion: number(field(root, "format_version")), binding: binding(field(root, "binding")), window: number(field(root, "window")),
      checkpoint: checkpoint(field(root, "checkpoint")), head: { ordinal: number(field(head, "ordinal")), hash: text(field(head, "hash")) },
      records: records.map(text), keys: keys.map(key), revision: number(field(root, "trust_revision")),
      fenced: boolean(field(root, "fenced")), clock: clock(field(root, "clock")),
    }, expectedBinding, window, expectedCheckpoint);
  } catch {
    return fail();
  }
}

/** Валидирует whole value до serialization; local16MiB — не HTTP/physical DB guarantee. */
export function encodeRotationTrustSnapshot(
  input: RotationTrustSnapshot,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): Uint8Array {
  try {
    const value = validateRotationTrustSnapshot(input, expectedBinding, window, expectedCheckpoint);
    const encoded = Buffer.from(JSON.stringify({
      format_version: value.formatVersion, binding: value.binding, window: value.window,
      checkpoint: { ordinal: value.checkpoint.ordinal, hash: value.checkpoint.hash, kid: value.checkpoint.kid,
        public_key: value.checkpoint.publicKeyB64u, published_at: value.checkpoint.publishedAt },
      head: value.head, records: value.records,
      keys: value.keys.map((entry) => ({ ordinal: entry.ordinal, kid: entry.kid, public_key: entry.publicKeyB64u,
        not_before: entry.notBefore, known_cutoff: entry.knownCutoff })),
      trust_revision: value.revision, fenced: value.fenced,
      clock: { binding: value.clock.binding, window: value.clock.window, high_water: value.clock.highWater,
        clock_revision: value.clock.revision, unsafe: value.clock.unsafe },
    }), "utf8");
    if (encoded.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) fail();
    return encoded;
  } catch {
    return fail();
  }
}
