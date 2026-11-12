import { validatePublicKey } from "./ed25519.js";
import { decodeBase64URLFixed, keyId } from "./encoding.js";
import { parseRotationRecord, RotationError, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import type { RotationBinding, RotationRecord } from "./rotation-record.js";

export const ROTATION_MAX_RETAINED_KEYS = 1024 + 128 + 1;

/** Checkpoint только из независимо доверенного или ранее подтверждённого snapshot. */
export interface RotationCheckpoint {
  readonly ordinal: number;
  readonly hash: string;
  readonly kid: string;
  readonly publicKeyB64u: string;
  readonly publishedAt: number;
}

function reject(code: string): never {
  throw new RotationError(code);
}

function admittedKey(kid: string, text: string): void {
  try {
    const bytes = decodeBase64URLFixed(text, 32);
    if (keyId(bytes) !== kid || validatePublicKey(bytes) !== null) reject("anchor_key_id");
  } catch {
    reject("anchor_key_id");
  }
}

function timestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= ROTATION_MAX_TIMESTAMP;
}

/** Contiguous extension; не выполняет ACK, persistence, pagination или hidden refresh. */
export function verifyRotationChain(
  wires: readonly Uint8Array[],
  binding: RotationBinding,
  checkpoint: RotationCheckpoint,
  retained: ReadonlyMap<string, string> = new Map(),
): readonly RotationRecord[] {
  if (wires.length > ROTATION_MAX_RETAINED_KEYS || retained.size > ROTATION_MAX_RETAINED_KEYS) reject("capacity");
  if (!Number.isSafeInteger(checkpoint.ordinal) || checkpoint.ordinal < 0 || checkpoint.ordinal > ROTATION_MAX_ORDINAL || !timestamp(checkpoint.publishedAt)) reject("anchor_key_id");
  admittedKey(checkpoint.kid, checkpoint.publicKeyB64u);
  if (checkpoint.ordinal === 0) {
    if (checkpoint.hash !== "-") reject("previous_hash");
  } else {
    try { decodeBase64URLFixed(checkpoint.hash, 32); } catch { reject("previous_hash"); }
  }
  const keys = new Map(retained);
  for (const [kid, publicKey] of keys) admittedKey(kid, publicKey);
  if (!keys.has(checkpoint.kid) && keys.size === ROTATION_MAX_RETAINED_KEYS) reject("capacity");
  keys.set(checkpoint.kid, checkpoint.publicKeyB64u);
  let previous = checkpoint;
  const records: RotationRecord[] = [];
  for (const wire of wires) {
    const record = parseRotationRecord(wire, binding, keys);
    if (previous.ordinal === ROTATION_MAX_ORDINAL || record.ordinal !== previous.ordinal + 1) reject("ordinal_sequence");
    if (record.previousHash !== previous.hash) reject("previous_hash");
    if (record.oldKid !== previous.kid) reject("adjacency");
    if (record.publishedAt < previous.publishedAt) reject("publication_order");
    if (keys.has(record.newKid)) reject("key_reuse");
    if (keys.size >= ROTATION_MAX_RETAINED_KEYS) reject("capacity");
    keys.set(record.newKid, record.publicKeyB64u);
    records.push(record);
    previous = { ordinal: record.ordinal, hash: record.hash, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, publishedAt: record.publishedAt };
  }
  return Object.freeze(records);
}

/** Входные records уже должны быть проверены; при равных activation побеждает ordinal. */
export function selectedRotationOrdinal(records: readonly RotationRecord[], now: number): number {
  if (!timestamp(now)) reject("timestamp");
  let selected = 0;
  for (const record of records) {
    if (record.activatesAt <= now && record.ordinal > selected) selected = record.ordinal;
  }
  return selected;
}

/** Lower bound по ts и строгий известный cutoff по ts И finalNow. */
export function rotationAssignmentValid(records: readonly RotationRecord[], ordinal: number, ts: number, finalNow: number): boolean {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal > ROTATION_MAX_ORDINAL || !timestamp(ts) || !timestamp(finalNow)) return false;
  let found = ordinal === 0;
  for (const record of records) {
    if (record.ordinal === ordinal) {
      found = true;
      if (ts < record.activatesAt) return false;
    }
    if (ordinal < ROTATION_MAX_ORDINAL && record.ordinal === ordinal + 1 && (ts >= record.activatesAt || finalNow >= record.activatesAt)) return false;
  }
  return found;
}
