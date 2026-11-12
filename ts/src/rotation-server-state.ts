import { parseCandidateJsonRaw } from "./json-raw.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { nodeField, nodeNumber, nodeObject, nodeText } from "./rotation-json-node.js";
import { RotationError, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL } from "./rotation-record.js";
import type { RotationBinding } from "./rotation-record.js";
import { rotationTrustClockCompatible, validateRotationTrustSnapshot } from "./rotation-trust.js";
import type { RotationTrustSnapshot } from "./rotation-trust.js";
import { decodeRotationTrustSnapshot, encodeRotationTrustSnapshot, ROTATION_MAX_TRUST_SNAPSHOT_BYTES } from "./rotation-trust-json.js";

export const ROTATION_MAX_SIGNER_REFERENCE_BYTES = 1024;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Opaque server-local handle подписанта; не private-key encoding и не key authority. */
export interface RotationSignerReference {
  readonly kid: string;
  readonly reference: string;
}

/** Хранится только в protected server store; никогда не входит в delivery payload. */
export interface RotationServerSnapshot {
  readonly formatVersion: number;
  readonly trust: RotationTrustSnapshot;
  readonly signerReferences: readonly RotationSignerReference[];
}

function refuse(): never {
  throw new RotationError("rotation_state_unavailable");
}

function ownReference(entry: RotationSignerReference, kid: string): RotationSignerReference {
  const own = { kid: entry.kid, reference: entry.reference };
  // Lone surrogate не переживает UTF-8 round trip: это аналог invalid UTF-8.
  if (own.kid !== kid || typeof own.reference !== "string" || own.reference.length === 0 ||
    Buffer.byteLength(own.reference, "utf8") > ROTATION_MAX_SIGNER_REFERENCE_BYTES ||
    Buffer.from(own.reference, "utf8").toString("utf8") !== own.reference) refuse();
  return Object.freeze(own);
}

/** Проверяет whole trust и ровно одну opaque reference на каждый retained key; возвращает owned frozen value. */
export function validateRotationServerSnapshot(
  input: RotationServerSnapshot,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): RotationServerSnapshot {
  try {
    const version = input.formatVersion;
    const rawReferences = input.signerReferences;
    const trust = validateRotationTrustSnapshot(input.trust, expectedBinding, window, expectedCheckpoint);
    if (version !== 1 || !Array.isArray(rawReferences) || rawReferences.length !== trust.keys.length) refuse();
    const references = trust.keys.map((key, index) => {
      const entry = rawReferences[index];
      if (entry === undefined) refuse();
      return ownReference(entry, key.kid);
    });
    return Object.freeze({ formatVersion: 1, trust, signerReferences: Object.freeze(references) });
  } catch {
    return refuse();
  }
}

/** Проверяет один fixed-P переход; это не durable authorization и не persistence. */
export function validateRotationServerPublication(
  expected: RotationServerSnapshot,
  desired: RotationServerSnapshot,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): RotationServerSnapshot {
  try {
    const previous = validateRotationServerSnapshot(expected, expectedBinding, window, expectedCheckpoint);
    const next = validateRotationServerSnapshot(desired, expectedBinding, window, expectedCheckpoint);
    const before = previous.trust;
    const after = next.trust;
    if (before.revision === ROTATION_MAX_ORDINAL || after.revision !== before.revision + 1 ||
      after.records.length !== before.records.length + 1 || before.fenced || after.fenced ||
      !rotationTrustClockCompatible(before, after.clock)) refuse();
    if (before.records.some((wire, index) => after.records[index] !== wire) ||
      previous.signerReferences.some((entry, index) => {
        const other = next.signerReferences[index];
        return other === undefined || other.kid !== entry.kid || other.reference !== entry.reference;
      })) refuse();
    const last = after.keys[after.keys.length - 1];
    // P уже зафиксирован в clock.highWater; A = P + 48h выводится только из него.
    if (last === undefined || last.notBefore - ROTATION_GRACE_SECONDS !== after.clock.highWater) refuse();
    return next;
  } catch {
    return refuse();
  }
}

/** Private local format: object order не значим, caller не передаёт его клиентам. */
export function encodeRotationServerSnapshot(
  input: RotationServerSnapshot,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): Uint8Array {
  try {
    const value = validateRotationServerSnapshot(input, expectedBinding, window, expectedCheckpoint);
    const trust = Buffer.from(encodeRotationTrustSnapshot(value.trust, expectedBinding, window, expectedCheckpoint)).toString("utf8");
    const references = JSON.stringify(value.signerReferences.map((entry) => ({ kid: entry.kid, reference: entry.reference })));
    const encoded = Buffer.from(`{"format_version":1,"public":${trust},"signer_refs":${references}}`, "utf8");
    if (encoded.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) refuse();
    return encoded;
  } catch {
    return refuse();
  }
}

/** Strict parse сохраняет fences/unsafe; успешный decode не является serving readiness. */
export function decodeRotationServerSnapshot(
  bytes: Uint8Array,
  expectedBinding: RotationBinding,
  window: number,
  expectedCheckpoint: RotationCheckpoint,
): RotationServerSnapshot {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > ROTATION_MAX_TRUST_SNAPSHOT_BYTES) refuse();
    const root = nodeObject(parseCandidateJsonRaw(utf8.decode(bytes)), ["format_version", "public", "signer_refs"]);
    const items = nodeField(root, "signer_refs").items;
    if (items === undefined || items.length > ROTATION_MAX_RETAINED_KEYS) refuse();
    const signerReferences = items.map((item) => {
      const entry = nodeObject(item, ["kid", "reference"]);
      return { kid: nodeText(nodeField(entry, "kid")), reference: nodeText(nodeField(entry, "reference")) };
    });
    // Source slice вложенного объекта разбирается тем же strict trust decoder, без повторной схемы.
    const trust = decodeRotationTrustSnapshot(Buffer.from(nodeField(root, "public").text, "utf8"), expectedBinding, window, expectedCheckpoint);
    return validateRotationServerSnapshot({ formatVersion: nodeNumber(nodeField(root, "format_version")), trust, signerReferences },
      expectedBinding, window, expectedCheckpoint);
  } catch {
    return refuse();
  }
}
