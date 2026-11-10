import { bodyHash, decodeBase64URLFixed } from "./encoding.js";
import { RotationError, ROTATION_MAX_ORDINAL } from "./rotation-record.js";
import type { RotationRecord } from "./rotation-record.js";
import { ROTATION_MAX_PAGE_RECORDS } from "./rotation-result.js";
import type { DecodedRotationResult } from "./rotation-result.js";

export interface RotationCursor {
  readonly ordinal: number;
  readonly hash: string;
}

/** Только framing metadata; terminal не заменяет ACKed cursor автоматически. */
export interface RotationPageFraming {
  readonly extensionStart: number;
  readonly terminal: RotationCursor;
  readonly head: RotationCursor;
  readonly complete: boolean;
}

function fail(code: string): never {
  throw new RotationError(code);
}

function validCursor(cursor: RotationCursor): boolean {
  if (!Number.isSafeInteger(cursor.ordinal) || cursor.ordinal < 0 || cursor.ordinal > ROTATION_MAX_ORDINAL) return false;
  if (cursor.ordinal === 0) return cursor.hash === "-";
  try {
    decodeBase64URLFixed(cursor.hash, 32);
    return true;
  } catch {
    return false;
  }
}

/**
 * Caller уже проверил outer/ClockGuard/result schema и intrinsic record proofs.
 * Здесь только contiguous page/cursor/known-position/head framing (§3 candidate).
 * Проверки authorizer adjacency, P order, reuse, current binding и first bridge
 * остаются controller/chain gates; нет ACK, persistence, hidden retry или fetch.
 */
export function validateRotationPageFraming(
  result: DecodedRotationResult,
  cursor: RotationCursor,
  records: readonly RotationRecord[],
  acknowledgedHashes: ReadonlyMap<number, string>,
): RotationPageFraming {
  if (!validCursor(cursor) || !validCursor(result.head)) fail("rotation_gap");
  if (records.length !== result.records.length || records.length > ROTATION_MAX_PAGE_RECORDS) fail("rotation_result_invalid");
  const acknowledgedCursor = acknowledgedHashes.get(cursor.ordinal);
  if (acknowledgedCursor !== undefined && acknowledgedCursor !== cursor.hash) fail("rotation_conflict");
  let previous: RotationCursor | undefined;
  let extensionStart = records.length;
  let sawExtension = false;
  for (const [index, record] of records.entries()) {
    if (record.wire !== result.records[index] || bodyHash(Buffer.from(record.wire, "utf8")) !== record.hash) fail("rotation_record_invalid");
    if (!Number.isSafeInteger(record.ordinal) || record.ordinal < 1 || record.ordinal > ROTATION_MAX_ORDINAL) fail("rotation_gap");
    if (previous !== undefined && (previous.ordinal === ROTATION_MAX_ORDINAL || record.ordinal !== previous.ordinal + 1 || record.previousHash !== previous.hash)) fail("rotation_gap");
    if (record.ordinal <= cursor.ordinal) {
      if (sawExtension) fail("rotation_gap");
      const known = record.ordinal === cursor.ordinal ? cursor.hash : acknowledgedHashes.get(record.ordinal);
      if (known === undefined) fail("rotation_gap");
      if (known !== record.hash) fail("rotation_conflict");
    } else if (!sawExtension) {
      if (cursor.ordinal === ROTATION_MAX_ORDINAL || record.ordinal !== cursor.ordinal + 1 || record.previousHash !== cursor.hash || (previous !== undefined && previous.ordinal !== cursor.ordinal)) fail("rotation_gap");
      extensionStart = index;
      sawExtension = true;
    }
    previous = { ordinal: record.ordinal, hash: record.hash };
  }
  if (!sawExtension && previous !== undefined && previous.ordinal !== cursor.ordinal) fail("rotation_gap");
  const terminal = previous ?? cursor;
  if (result.complete) {
    if (result.head.ordinal !== terminal.ordinal || result.head.hash !== terminal.hash) fail("rotation_gap");
  } else if (records.length === 0 || result.head.ordinal <= terminal.ordinal) {
    fail("rotation_gap");
  }
  return Object.freeze({
    extensionStart,
    terminal: Object.freeze({ ordinal: terminal.ordinal, hash: terminal.hash }),
    head: Object.freeze({ ordinal: result.head.ordinal, hash: result.head.hash }),
    complete: result.complete,
  });
}
