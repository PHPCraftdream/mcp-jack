import { rotationBindingError } from "./rotation-binding.js";
import { ROTATION_MAX_RETAINED_KEYS, verifyRotationChain } from "./rotation-chain.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { RotationError, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL, ROTATION_MAX_RECORD_BYTES, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import type { RotationBinding } from "./rotation-record.js";
import type { RotationCursor } from "./rotation-page.js";

/** Copied CAS dependency, не самостоятельная time authority. */
export interface RotationClockTuple {
  readonly binding: RotationBinding;
  readonly window: number;
  readonly highWater: number;
  readonly revision: number;
  readonly unsafe: boolean;
}

export interface RotationTrustKey {
  readonly ordinal: number;
  readonly kid: string;
  readonly publicKeyB64u: string;
  readonly notBefore: number;
  readonly knownCutoff: number | null;
}

/** Whole value; parse/validation не выполняют persistence или ACK. */
export interface RotationTrustSnapshot {
  readonly formatVersion: number;
  readonly binding: RotationBinding;
  readonly window: number;
  readonly checkpoint: RotationCheckpoint;
  readonly head: RotationCursor;
  readonly records: readonly string[];
  readonly keys: readonly RotationTrustKey[];
  readonly revision: number;
  readonly fenced: boolean;
  readonly clock: RotationClockTuple;
}

function fail(): never {
  throw new RotationError("rotation_state_unknown");
}

function timestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= ROTATION_MAX_TIMESTAMP;
}

function ordinal(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= ROTATION_MAX_ORDINAL;
}

function sameBinding(left: RotationBinding, right: RotationBinding): boolean {
  return left.endpoint === right.endpoint && left.aud === right.aud;
}

function ownBinding(value: RotationBinding): RotationBinding {
  const binding = { endpoint: value.endpoint, aud: value.aud };
  if (typeof binding.endpoint !== "string" || typeof binding.aud !== "string" || binding.endpoint.length > 2048 || binding.aud.length > 1024 ||
    rotationBindingError(binding) !== undefined) fail();
  return Object.freeze(binding);
}

function ownCheckpoint(value: RotationCheckpoint): RotationCheckpoint {
  const checkpoint = { ordinal: value.ordinal, hash: value.hash, kid: value.kid,
    publicKeyB64u: value.publicKeyB64u, publishedAt: value.publishedAt };
  if (typeof checkpoint.hash !== "string" || (checkpoint.hash.length !== 1 && checkpoint.hash.length !== 43) ||
    typeof checkpoint.kid !== "string" || checkpoint.kid.length !== 43 || typeof checkpoint.publicKeyB64u !== "string" || checkpoint.publicKeyB64u.length !== 43) fail();
  return Object.freeze(checkpoint);
}

function sameCheckpoint(left: RotationCheckpoint, right: RotationCheckpoint): boolean {
  return left.ordinal === right.ordinal && left.hash === right.hash && left.kid === right.kid &&
    left.publicKeyB64u === right.publicKeyB64u && left.publishedAt === right.publishedAt;
}

function validClock(clock: RotationClockTuple, binding: RotationBinding, window: number): boolean {
  return sameBinding(clock.binding, binding) && clock.window === window && timestamp(clock.highWater) &&
    ordinal(clock.revision) && typeof clock.unsafe === "boolean";
}

/** Проверяет exact OOB expectations, полный bounded chain и redundant metadata; возвращает owned frozen values. */
export function validateRotationTrustSnapshot(
  input: RotationTrustSnapshot,
  expectedBinding: RotationBinding,
  expectedWindow: number,
  expectedCheckpoint: RotationCheckpoint,
): RotationTrustSnapshot {
  try {
    const binding = ownBinding(input.binding);
    const oobBinding = ownBinding(expectedBinding);
    const checkpoint = ownCheckpoint(input.checkpoint);
    const oobCheckpoint = ownCheckpoint(expectedCheckpoint);
    const rawClock = input.clock;
    const clock: RotationClockTuple = Object.freeze({ binding: ownBinding(rawClock.binding), window: rawClock.window,
      highWater: rawClock.highWater, revision: rawClock.revision, unsafe: rawClock.unsafe });
    const version = input.formatVersion;
    const window = input.window;
    const revision = input.revision;
    const fenced = input.fenced;
    const rawHead = input.head;
    const head = Object.freeze({ ordinal: rawHead.ordinal, hash: rawHead.hash });
    const rawRecords = input.records;
    const rawKeys = input.keys;
    if (version !== 1 || !sameBinding(binding, oobBinding) || !Number.isSafeInteger(expectedWindow) ||
      expectedWindow < 1 || expectedWindow > 120 || window !== expectedWindow || !sameCheckpoint(checkpoint, oobCheckpoint) ||
      !ordinal(revision) || revision === 0 || typeof fenced !== "boolean" || !validClock(clock, binding, window) ||
      !timestamp(checkpoint.publishedAt) || checkpoint.publishedAt > ROTATION_MAX_TIMESTAMP - ROTATION_GRACE_SECONDS ||
      (checkpoint.ordinal === 0 && checkpoint.publishedAt !== 0) || !Array.isArray(rawRecords) || !Array.isArray(rawKeys)) fail();
    const count = rawRecords.length;
    if (!ordinal(count) || count >= ROTATION_MAX_RETAINED_KEYS || rawKeys.length !== count + 1) fail();
    const wires: Uint8Array[] = [];
    const texts: string[] = [];
    for (let index = 0; index < count; index++) {
      const wire = rawRecords[index];
      if (typeof wire !== "string" || wire.length === 0 || wire.length > ROTATION_MAX_RECORD_BYTES) fail();
      const bytes = Buffer.from(wire, "utf8");
      if (bytes.length > ROTATION_MAX_RECORD_BYTES || bytes.toString("utf8") !== wire) fail();
      texts.push(wire);
      wires.push(bytes);
    }
    const records = verifyRotationChain(wires, binding, checkpoint);
    const keys: RotationTrustKey[] = [{ ordinal: checkpoint.ordinal, kid: checkpoint.kid,
      publicKeyB64u: checkpoint.publicKeyB64u, notBefore: checkpoint.ordinal === 0 ? 0 : checkpoint.publishedAt + ROTATION_GRACE_SECONDS,
      knownCutoff: null }];
    let computedHead: RotationCursor = { ordinal: checkpoint.ordinal, hash: checkpoint.hash };
    for (const record of records) {
      const previous = keys[keys.length - 1];
      if (previous === undefined) fail();
      keys[keys.length - 1] = { ...previous, knownCutoff: record.activatesAt };
      keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u,
        notBefore: record.activatesAt, knownCutoff: null });
      computedHead = { ordinal: record.ordinal, hash: record.hash };
    }
    if (head.ordinal !== computedHead.ordinal || head.hash !== computedHead.hash) fail();
    let pending = 0;
    let retired = 0;
    for (let index = 0; index < keys.length; index++) {
      const expected = keys[index];
      const actual = rawKeys[index];
      if (expected === undefined || actual === undefined || actual.ordinal !== expected.ordinal || actual.kid !== expected.kid ||
        actual.publicKeyB64u !== expected.publicKeyB64u || actual.notBefore !== expected.notBefore || actual.knownCutoff !== expected.knownCutoff) fail();
      if (expected.notBefore > clock.highWater) pending++;
      else if (expected.knownCutoff !== null && expected.knownCutoff <= clock.highWater) retired++;
    }
    if (pending > 128 || retired > 1024) fail();
    return Object.freeze({ formatVersion: 1, binding, window, checkpoint, head,
      records: Object.freeze(texts), keys: Object.freeze(keys.map((key) => Object.freeze(key))), revision, fenced, clock });
  } catch {
    return fail();
  }
}

/** Требует validated snapshot; tuple check не заменяет fresh authoritative store operation. */
export function rotationTrustClockCompatible(snapshot: RotationTrustSnapshot, clock: RotationClockTuple): boolean {
  try {
    return snapshot.formatVersion === 1 && snapshot.fenced === false && snapshot.clock.unsafe === false && clock.unsafe === false &&
      Number.isSafeInteger(snapshot.window) && snapshot.window >= 1 && snapshot.window <= 120 &&
      rotationBindingError(snapshot.binding) === undefined && validClock(snapshot.clock, snapshot.binding, snapshot.window) &&
      validClock(clock, snapshot.binding, snapshot.window) && snapshot.clock.highWater <= clock.highWater && snapshot.clock.revision <= clock.revision;
  } catch {
    return false;
  }
}
