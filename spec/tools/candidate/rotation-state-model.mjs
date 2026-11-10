import { advanceAndCheckClock, initialClockGuard } from './clock-guard-model.mjs';
import { validateRefreshPreResponse } from './verification.mjs';
import { NONCE_LIMITS } from './durable-nonce-model.mjs';

export const ROTATION_LIMITS = Object.freeze({ pending: 128, retired: 1024, pageLinks: 16, recordBytes: 8192, bodyBytes: 256 * 1024 });
const cloneValue = (value) => {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value instanceof Map) return new Map([...value].map(([k, v]) => [k, cloneValue(v)]));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, cloneValue(v)]));
  return value;
};
const deny = (error, callbacks = 0, snapshot = null) => ({ accepted: false, error, callbacks, snapshot, committed: false });

export const newRotationSnapshot = ({ endpoint, aud, anchorKid, anchorPublicKey, window = 30, revision = 1, records = [], fence = false, clockGeneration = 1, configuredWindow = window, clockGuard = initialClockGuard({ binding: JSON.stringify([endpoint, aud]), window }) }) => {
  const kept = cloneValue(records);
  const keys = new Map([[anchorKid, Buffer.from(anchorPublicKey)]]);
  const ordinalByKid = new Map([[anchorKid, 0]]);
  const recordByOrdinal = new Map();
  for (const record of kept) {
    keys.set(record.newKid, Buffer.from(record.publicKey));
    ordinalByKid.set(record.newKid, record.ordinal);
    recordByOrdinal.set(record.ordinal, cloneValue(record));
  }
  return {
    endpoint, aud, anchorKid, anchorPublicKey: Buffer.from(anchorPublicKey), window, configuredWindow, revision,
    records: kept, keys, ordinalByKid, recordByOrdinal,
    ackOrdinal: kept.length ? kept[kept.length - 1].ordinal : 0,
    ackHash: kept.length ? kept[kept.length - 1].hash : '-',
    fence, clockGeneration, clockGuard: cloneValue(clockGuard),
  };
};

const rebuildIndexes = (snapshot) => {
  snapshot.keys = new Map([[snapshot.anchorKid, Buffer.from(snapshot.anchorPublicKey)]]);
  snapshot.ordinalByKid = new Map([[snapshot.anchorKid, 0]]);
  snapshot.recordByOrdinal = new Map();
  for (const record of snapshot.records) {
    snapshot.keys.set(record.newKid, Buffer.from(record.publicKey));
    snapshot.ordinalByKid.set(record.newKid, record.ordinal);
    snapshot.recordByOrdinal.set(record.ordinal, cloneValue(record));
  }
  snapshot.ackOrdinal = snapshot.records.length ? snapshot.records[snapshot.records.length - 1].ordinal : 0;
  snapshot.ackHash = snapshot.records.length ? snapshot.records[snapshot.records.length - 1].hash : '-';
};

const finalTimeError = (snapshot, ordinal, ts, now) => {
  const lower = ordinal === 0 ? undefined : snapshot.records[ordinal - 1]?.activatesAt;
  const cutoff = snapshot.records[ordinal]?.activatesAt;
  if ((ordinal > 0 && (lower === undefined || ts < lower)) || (cutoff !== undefined && (ts >= cutoff || now >= cutoff))) return 'rotation_key_interval';
  if (Math.abs(now - ts) > snapshot.window) return 'timestamp_out_of_window';
  return null;
};

export const acceptRefresh = ({ snapshot: original, response, expectedId, cursor, preCallbackNow, finalNow, finalClockGeneration, callbackOutcome = 'ack', writerBusy = false, staleSnapshot = false, textMirror, clockOutcome = 'confirmed' }) => {
  const snapshot = cloneValue(original);
  if (snapshot.fence) return deny('rotation_state_unknown', 0, snapshot);
  if (snapshot.configuredWindow !== snapshot.window) return deny('rotation_state_unknown', 0, snapshot);
  const checkClock = (target, now) => {
    if (!target.clockGuard || target.clockGuard.binding !== JSON.stringify([target.endpoint, target.aud])
      || target.clockGuard.window !== target.window) return 'rotation_clock_unavailable';
    const result = advanceAndCheckClock(target.clockGuard, now, { latchOutcome: clockOutcome });
    target.clockGuard = result.guard;
    if (!result.ok) {
      target.fence = true;
      return result.error;
    }
    return null;
  };
  const checked = validateRefreshPreResponse({ state: snapshot, response, expectedId, cursor, textMirror, checkClock: (now) => checkClock(snapshot, now) });
  if (!checked.ok) return { accepted: false, error: checked.error, callbacks: 0, snapshot, committed: false };
  if (checked.records.length > ROTATION_LIMITS.pageLinks || Buffer.byteLength(response.body) > ROTATION_LIMITS.bodyBytes) return { accepted: false, error: 'rotation_result_invalid', callbacks: 0, snapshot, committed: false };
  const duplicates = checked.records.filter((record) => record.ordinal <= snapshot.ackOrdinal);
  for (const record of duplicates) {
    const acknowledged = snapshot.recordByOrdinal.get(record.ordinal);
    if (!acknowledged) return deny('rotation_gap', 0, snapshot);
    if (acknowledged.hash !== record.hash || acknowledged.wire !== record.wire) return deny('rotation_conflict', 0, snapshot);
  }
  const extension = checked.records.filter((record) => record.ordinal > snapshot.ackOrdinal);
  if (extension.length === 0) {
    const clockError = checkClock(snapshot, finalNow);
    if (clockError) return deny(clockError, 0, snapshot);
    const finalError = finalTimeError(snapshot, checked.carrierOrdinal, response.ts, finalNow);
    const finalPassed = finalError === null
      && finalClockGeneration === snapshot.clockGeneration
      && !snapshot.fence;
    if (!finalPassed) return { accepted: false, error: finalError ?? 'rotation_state_changed', callbacks: 0, snapshot, committed: false };
    return { accepted: true, duplicate: true, callbacks: 0, snapshot, head: checked.head, complete: checked.complete, carrierTrusted: true, effects: { callback: 0, trustChanges: 0, deadlinesChanged: 0 } };
  }
  const next = snapshot.ackOrdinal + 1;
  if (extension[0].ordinal !== next || extension.some((record, index) => record.ordinal !== next + index)) return deny('rotation_gap', 0, snapshot);
  const preClockError = checkClock(snapshot, preCallbackNow);
  if (preClockError) return deny(preClockError, 0, snapshot);
  const preTimeError = finalTimeError(snapshot, checked.carrierOrdinal, response.ts, preCallbackNow);
  if (preTimeError) return deny(preTimeError, 0, snapshot);
  if (preCallbackNow >= extension[0].activatesAt) return { accepted: false, error: 'rotation_bridge_expired', callbacks: 0, snapshot, committed: false };
  if (checked.records.length > ROTATION_LIMITS.pageLinks) return { accepted: false, error: 'rotation_result_invalid', callbacks: 0, snapshot, committed: false };
  const fullBodyLength = Buffer.byteLength(response.body);
  if (fullBodyLength > ROTATION_LIMITS.bodyBytes) return { accepted: false, error: 'rotation_result_invalid', callbacks: 0, snapshot, committed: false };
  const pending = snapshot.records.filter((record) => record.activatesAt > preCallbackNow).length
    + extension.filter((record) => record.activatesAt > preCallbackNow).length;
  const retired = snapshot.records.filter((record) => record.retired === true).length;
  if (pending > ROTATION_LIMITS.pending || retired > ROTATION_LIMITS.retired) return { accepted: false, error: 'rotation_state_changed', callbacks: 0, snapshot, committed: false };
  if (writerBusy || staleSnapshot) return deny('rotation_state_changed', 0, snapshot);

  const desired = cloneValue(snapshot);
  desired.records = [...snapshot.records, ...extension.map(cloneValue)];
  desired.revision += 1;
  rebuildIndexes(desired);
  if (callbackOutcome === 'conflict') return deny('rotation_state_changed', 1, snapshot);
  if (callbackOutcome === 'unknown') {
    snapshot.fence = true;
    return deny('rotation_state_unknown', 1, snapshot);
  }
  if (callbackOutcome !== 'ack') return deny('rotation_state_changed', 1, snapshot);

  const finalClockError = checkClock(desired, finalNow);
  if (finalClockError) return { accepted: false, error: finalClockError, callbacks: 1, snapshot: desired, committed: true, carrierTrusted: false };
  const finalError = finalTimeError(desired, checked.carrierOrdinal, response.ts, finalNow);
  const finalGate = finalError === null
    && finalClockGeneration === snapshot.clockGeneration
    && !snapshot.fence;
  if (finalGate) return { accepted: true, error: null, callbacks: 1, snapshot: desired, committed: true, carrierTrusted: true, effects: { callback: 1, trustChanges: extension.length, deadlinesChanged: 0 } };
  return { accepted: false, error: finalError ?? 'rotation_state_changed', callbacks: 1, snapshot: desired, committed: true, carrierTrusted: false, effects: { callback: 1, trustChanges: extension.length, deadlinesChanged: 0 } };
};

export const finalServerEmission = ({ selectedKid, selectedOrdinal, signingTime, emissionTime, records, clockGenerationBefore, clockGenerationNow, fenced = false, signerReady = true }) => {
  const cutoff = records[selectedOrdinal]?.activatesAt;
  const lower = selectedOrdinal > 0 ? records[selectedOrdinal - 1]?.activatesAt : undefined;
  const eligible = (time) => (selectedOrdinal === 0 || (lower !== undefined && time >= lower)) && (cutoff === undefined || time < cutoff);
  const emit = eligible(signingTime) && eligible(emissionTime) && clockGenerationBefore === clockGenerationNow && !fenced && signerReady;
  return { emit, signatures: 1, resigns: 0, selectedKid, signingTime };
};

export const checkRotationCapacity = ({ records, bodyBytes }) => ({
  pendingAvailable: records.filter((record) => record.activatesAt > record.trustedNow).length < ROTATION_LIMITS.pending,
  retiredAvailable: records.filter((record) => record.retired).length <= ROTATION_LIMITS.retired,
  pageAvailable: records.length <= ROTATION_LIMITS.pageLinks,
  eachRecordAvailable: records.every((record) => record.bytes <= ROTATION_LIMITS.recordBytes),
  bodyAvailable: bodyBytes <= ROTATION_LIMITS.bodyBytes,
});

export const limits = Object.freeze({ nonce: NONCE_LIMITS, rotation: ROTATION_LIMITS });
