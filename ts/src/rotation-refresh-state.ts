import { bodyHash } from "./encoding.js";
import { verifyRotationChain, ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import { parseRotationRecord, RotationError, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL } from "./rotation-record.js";
import type { RotationRecord } from "./rotation-record.js";
import { validateRotationPageFraming } from "./rotation-page.js";
import type { RotationCursor, RotationPageFraming } from "./rotation-page.js";
import type { DecodedRotationResult } from "./rotation-result.js";
import type { RotationClockTuple, RotationTrustSnapshot } from "./rotation-trust.js";

function recordFailure(error: unknown): never {
  const gaps = ["unknown_authorizer", "adjacency", "previous_hash", "ordinal_sequence", "publication_order"];
  throw new RotationError(error instanceof RotationError && gaps.includes(error.code) ? "rotation_gap" : "rotation_record_invalid");
}

/** Reference: Go client/rotation/refresh.go; только pre-authority validation, не ACK. */
export function prepareRefreshExtension(
  snapshot: RotationTrustSnapshot,
  page: DecodedRotationResult,
  cursor: RotationCursor,
  carrierTimestamp: number,
): { readonly framing: RotationPageFraming; readonly extension: readonly RotationRecord[] } {
  if (cursor.ordinal !== snapshot.head.ordinal || cursor.hash !== snapshot.head.hash || page.head.ordinal < cursor.ordinal) throw new RotationError("rotation_gap");
  const authorizers = new Map<string, string>(snapshot.keys.map((key) => [key.kid, key.publicKeyB64u]));
  const hashes = new Map<number, string>([[snapshot.checkpoint.ordinal, snapshot.checkpoint.hash]]);
  for (const [index, wire] of snapshot.records.entries()) hashes.set(snapshot.checkpoint.ordinal + index + 1, bodyHash(Buffer.from(wire, "utf8")));
  const records: RotationRecord[] = [];
  for (const wire of page.records) {
    let record: RotationRecord;
    try { record = parseRotationRecord(Buffer.from(wire, "utf8"), snapshot.binding, authorizers); }
    catch (error) { return recordFailure(error); }
    if (record.publishedAt > carrierTimestamp) throw new RotationError("rotation_record_invalid");
    records.push(record);
    authorizers.set(record.newKid, record.publicKeyB64u);
  }
  const framing = validateRotationPageFraming(page, cursor, records, hashes);
  const extension = records.slice(framing.extensionStart);
  if (extension.length > 0) {
    const tail = snapshot.keys[snapshot.keys.length - 1];
    if (tail === undefined || snapshot.revision === ROTATION_MAX_ORDINAL || snapshot.keys.length + extension.length > ROTATION_MAX_RETAINED_KEYS) throw new RotationError("rotation_state_changed");
    const previous = snapshot.records.length === 0 ? snapshot.checkpoint : {
      ordinal: snapshot.head.ordinal, hash: snapshot.head.hash, kid: tail.kid,
      publicKeyB64u: tail.publicKeyB64u, publishedAt: tail.notBefore - ROTATION_GRACE_SECONDS,
    };
    const retained = new Map<string, string>(snapshot.keys.map((key) => [key.kid, key.publicKeyB64u]));
    try { verifyRotationChain(extension.map((record) => Buffer.from(record.wire, "utf8")), snapshot.binding, previous, retained); }
    catch (error) { return recordFailure(error); }
  }
  return Object.freeze({ framing, extension: Object.freeze(extension) });
}

/** Только bounded value construction после captured guard; validation/CAS выполняет store. */
export function extendedRefreshSnapshot(
  snapshot: RotationTrustSnapshot,
  extension: readonly RotationRecord[],
  clock: RotationClockTuple,
): RotationTrustSnapshot {
  if (extension.length === 0 || snapshot.revision >= ROTATION_MAX_ORDINAL || snapshot.keys.length + extension.length > ROTATION_MAX_RETAINED_KEYS) throw new RotationError("rotation_state_changed");
  const keys = [...snapshot.keys];
  const records = [...snapshot.records];
  let head = snapshot.head;
  for (const record of extension) {
    const tail = keys.pop();
    if (tail === undefined) throw new RotationError("rotation_state_unknown");
    keys.push(Object.freeze({ ...tail, knownCutoff: record.activatesAt }), Object.freeze({ ordinal: record.ordinal,
      kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null }));
    records.push(record.wire);
    head = Object.freeze({ ordinal: record.ordinal, hash: record.hash });
  }
  let pending = 0;
  let retired = 0;
  for (const key of keys) {
    if (key.notBefore > clock.highWater) pending++;
    else if (key.knownCutoff !== null && key.knownCutoff <= clock.highWater) retired++;
  }
  if (pending > 128 || retired > 1024) throw new RotationError("rotation_state_changed");
  return Object.freeze({ ...snapshot, records: Object.freeze(records), keys: Object.freeze(keys), head,
    revision: snapshot.revision + 1, clock });
}
