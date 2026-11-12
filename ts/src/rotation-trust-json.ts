import { parseCandidateJsonRaw } from "./json-raw.js";
import type { RawJsonNode } from "./json-raw.js";
import { nodeBoolean, nodeField, nodeNumber, nodeObject, nodeText } from "./rotation-json-node.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { RotationError } from "./rotation-record.js";
import type { RotationBinding } from "./rotation-record.js";
import { validateRotationTrustSnapshot } from "./rotation-trust.js";
import type { RotationClockTuple, RotationTrustKey, RotationTrustSnapshot } from "./rotation-trust.js";

export const ROTATION_MAX_TRUST_SNAPSHOT_BYTES = 16 * 1024 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function fail(): never {
  throw new RotationError("rotation_state_unknown");
}

function binding(node: RawJsonNode): RotationBinding {
  const value = nodeObject(node, ["endpoint", "aud"]);
  return { endpoint: nodeText(nodeField(value, "endpoint")), aud: nodeText(nodeField(value, "aud")) };
}

function checkpoint(node: RawJsonNode): RotationCheckpoint {
  const value = nodeObject(node, ["ordinal", "hash", "kid", "public_key", "published_at"]);
  return { ordinal: nodeNumber(nodeField(value, "ordinal")), hash: nodeText(nodeField(value, "hash")), kid: nodeText(nodeField(value, "kid")),
    publicKeyB64u: nodeText(nodeField(value, "public_key")), publishedAt: nodeNumber(nodeField(value, "published_at")) };
}

function key(node: RawJsonNode): RotationTrustKey {
  const value = nodeObject(node, ["ordinal", "kid", "public_key", "not_before", "known_cutoff"]);
  const cutoff = nodeField(value, "known_cutoff");
  return { ordinal: nodeNumber(nodeField(value, "ordinal")), kid: nodeText(nodeField(value, "kid")), publicKeyB64u: nodeText(nodeField(value, "public_key")),
    notBefore: nodeNumber(nodeField(value, "not_before")), knownCutoff: cutoff.value === null ? null : nodeNumber(cutoff) };
}

function clock(node: RawJsonNode): RotationClockTuple {
  const value = nodeObject(node, ["binding", "window", "high_water", "clock_revision", "unsafe"]);
  return { binding: binding(nodeField(value, "binding")), window: nodeNumber(nodeField(value, "window")), highWater: nodeNumber(nodeField(value, "high_water")),
    revision: nodeNumber(nodeField(value, "clock_revision")), unsafe: nodeBoolean(nodeField(value, "unsafe")) };
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
    const root = nodeObject(parseCandidateJsonRaw(utf8.decode(bytes)), ["format_version", "binding", "window", "checkpoint", "head", "records", "keys", "trust_revision", "fenced", "clock"]);
    const head = nodeObject(nodeField(root, "head"), ["ordinal", "hash"]);
    const records = nodeField(root, "records").items;
    const keys = nodeField(root, "keys").items;
    if (records === undefined || records.length >= ROTATION_MAX_RETAINED_KEYS || keys === undefined || keys.length > ROTATION_MAX_RETAINED_KEYS) fail();
    return validateRotationTrustSnapshot({
      formatVersion: nodeNumber(nodeField(root, "format_version")), binding: binding(nodeField(root, "binding")), window: nodeNumber(nodeField(root, "window")),
      checkpoint: checkpoint(nodeField(root, "checkpoint")), head: { ordinal: nodeNumber(nodeField(head, "ordinal")), hash: nodeText(nodeField(head, "hash")) },
      records: records.map(nodeText), keys: keys.map(key), revision: nodeNumber(nodeField(root, "trust_revision")),
      fenced: nodeBoolean(nodeField(root, "fenced")), clock: clock(nodeField(root, "clock")),
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
