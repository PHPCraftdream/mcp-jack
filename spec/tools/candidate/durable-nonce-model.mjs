import { durableIntentIdentity } from './verification.mjs';
import { MAX_TIMESTAMP } from './rotation-codec.mjs';

export const NONCE_LIMITS = Object.freeze({ livePlusIntent: 4096, unresolved: 64, purgeRows: 128 });
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const pairKey = (kid, nonce) => `${kid}:${nonce}`;
const abs = (value) => value < 0 ? -value : value;
const copy = (value) => structuredClone(value);

const findLive = (state, key) => {
  const limit = Math.min(state.live.length, NONCE_LIMITS.livePlusIntent);
  for (let index = 0; index < limit; index += 1) {
    if (state.live[index].key === key) return state.live[index];
  }
  return undefined;
};

const hasExpiredLive = (state, now) => {
  const limit = Math.min(state.live.length, NONCE_LIMITS.livePlusIntent);
  for (let index = 0; index < limit; index += 1) {
    if (now > state.live[index].retainUntil) return true;
  }
  return false;
};

const purgeExpiredLive = (state, now, exactKey) => {
  const limit = Math.min(state.live.length, NONCE_LIMITS.livePlusIntent);
  const retained = [];
  let purged = 0;
  let changed = false;
  for (let index = 0; index < limit; index += 1) {
    const row = state.live[index];
    const expired = now > row.retainUntil;
    if (expired && row.key === exactKey) {
      changed = true;
      continue;
    }
    if (expired && purged < NONCE_LIMITS.purgeRows) {
      purged += 1;
      changed = true;
      continue;
    }
    retained.push(row);
  }
  if (!changed) return false;
  state.live = [...retained, ...state.live.slice(limit)];
  return true;
};

export const initialNonceState = (overrides = {}) => ({
  version: 1, deployment: 'candidate-test-deployment', generation: 1, window: 30, highWater: 0,
  clockUnsafe: false, fenced: false, intents: [], live: [], tombstones: [],
  effects: { authorization: 0, handler: 0, stateMutation: 0 },
  ...copy(overrides),
});

const operationFields = (state, op) => {
  if (op.operationId && op.requestSigningBytes && op.signatureRaw) {
    return {
      intentId: durableIntentIdentity({
        deploymentId: state.deployment,
        kidRaw: Buffer.from(op.kid, 'base64url'),
        nonceRaw: Buffer.from(op.nonce, 'base64url'),
        signatureRaw: Buffer.from(op.signatureRaw),
        signingBytes: Buffer.from(op.requestSigningBytes),
        operationId: Buffer.from(op.operationId),
      }),
      operationId: Buffer.from(op.operationId).toString('base64url'),
    };
  }
  return { intentId: op.intentId ?? `${state.deployment}:${op.kid}:${op.nonce}:${op.requestIdentity}`, operationId: op.operationId ?? 'candidate-test-operation' };
};

export const reserveNonce = (input, op) => {
  const state = copy(input);
  let callbacks = 0;
  let writes = 0;
  let dispatches = 0;
  const finish = (status, code, extra = {}) => ({
    response: { status, code }, callbacks, writes, dispatches, state,
    persisted: { highWater: state.highWater, intents: copy(state.intents), live: copy(state.live), tombstones: copy(state.tombstones), fenced: state.fenced, clockUnsafe: state.clockUnsafe },
    effects: copy(state.effects), ...extra,
  });
  const noWrite = (status, code, extra = {}) => finish(status, code, extra);
  const failClock = (rawNow) => {
    state.clockUnsafe = true;
    state.fenced = true;
    if (op.rollbackLatch === 'unknown') {
      return noWrite(503, 'clock_unsafe', { latchedRaw: rawNow, latchPersistence: 'unknown' });
    }
    callbacks += 1;
    writes += 1;
    return finish(503, 'clock_unsafe', { latchedRaw: rawNow });
  };

  if (op.authenticated !== true) return noWrite(op.preAuthStatus ?? 401, op.preAuthCode ?? 'bad_signature');
  if (state.fenced || state.clockUnsafe) return noWrite(503, 'durability_unavailable');
  if (op.window !== state.window || op.ownerGeneration !== state.generation || !equal(op.captured, op.cryptoSnapshot)) return noWrite(503, 'state_changed');
  if (!Number.isSafeInteger(op.ts) || op.ts < 0 || op.ts > MAX_TIMESTAMP) return noWrite(401, 'timestamp_out_of_window');
  const entryNow = op.entryNow ?? op.intentNow ?? op.rawNow;
  if (!Number.isSafeInteger(entryNow) || entryNow < 0 || entryNow > MAX_TIMESTAMP) return failClock(entryNow);
  if (entryNow < state.highWater) return failClock(entryNow);
  if (abs(entryNow - op.ts) > state.window) return noWrite(401, 'timestamp_out_of_window');
  const retainUntil = op.ts + state.window;
  if (!Number.isSafeInteger(retainUntil) || retainUntil > MAX_TIMESTAMP) return noWrite(401, 'timestamp_out_of_window');

  const intentNow = op.intentNow ?? op.rawNow;
  if (!Number.isSafeInteger(intentNow) || intentNow < 0 || intentNow > MAX_TIMESTAMP) return failClock(intentNow);
  if (intentNow < state.highWater) return failClock(intentNow);
  if (abs(intentNow - op.ts) > state.window) return noWrite(401, 'timestamp_out_of_window');
  if (op.clockOutcome === 'unknown') {
    state.clockUnsafe = true;
    state.fenced = true;
    return noWrite(503, 'durability_unavailable', { latchPersistence: 'unknown' });
  }
  if (op.clockOutcome === 'definite_failure') return noWrite(503, 'durability_unavailable');

  const key = pairKey(op.kid, op.nonce);
  const knownIntent = state.intents.find((row) => row.key === key);
  if (knownIntent) return noWrite(503, 'durability_unavailable');
  const existing = findLive(state, key);
  if (existing && intentNow <= existing.retainUntil) return noWrite(401, 'replayed_nonce');

  const hasExpiredRows = hasExpiredLive(state, intentNow);
  const needsHighWater = intentNow > state.highWater;
  const clockTxn = needsHighWater || hasExpiredRows;
  if (state.tombstones.length >= NONCE_LIMITS.unresolved) return noWrite(503, 'capacity_exhausted');
  if (state.live.length + state.intents.length >= NONCE_LIMITS.livePlusIntent && !hasExpiredRows) {
    return noWrite(503, 'capacity_exhausted');
  }
  if (clockTxn && op.clockOutcome === 'conflict') return noWrite(503, 'durability_unavailable', { disposition: 'clock_compare_conflict' });

  const ids = operationFields(state, op);
  const intent = {
    key, intentId: ids.intentId, operationId: ids.operationId,
    requestSigningBytes: op.requestSigningBytes ? Buffer.from(op.requestSigningBytes).toString('base64url') : null,
    signatureRaw: op.signatureRaw ? Buffer.from(op.signatureRaw).toString('base64url') : null,
    requestIdentity: op.requestIdentity, ts: op.ts, retainUntil, generation: state.generation,
  };
  if (op.intentOutcome === 'aborted') return noWrite(503, 'durability_unavailable', { disposition: 'intent_definitely_not_committed' });
  if (clockTxn) {
    if (needsHighWater) state.highWater = intentNow;
    purgeExpiredLive(state, intentNow, key);
  }
  if (state.live.length + state.intents.length >= NONCE_LIMITS.livePlusIntent) {
    if (clockTxn) {
      callbacks += 1;
      writes += 1;
    }
    return finish(503, 'capacity_exhausted');
  }
  if (op.intentOutcome === 'unknown') {
    state.fenced = true;
    if (op.intentFound !== false) state.tombstones.push({ ...intent, outcome: 'unknown_intent' });
    callbacks += 1;
    writes += 1;
    return finish(503, 'durability_unavailable', { reconciliation: op.intentFound === false ? 'manual_fence' : 'no_redelivery' });
  }
  state.intents.push(intent);
  callbacks += 1;
  writes += 1;

  const finalNow = op.finalNow ?? intentNow;
  const generationChanged = state.generation !== intent.generation
    || (op.finalOwnerGeneration !== undefined && op.finalOwnerGeneration !== state.generation)
    || (op.finalWindow !== undefined && op.finalWindow !== state.window)
    || (op.finalSnapshot !== undefined && !equal(op.captured, op.finalSnapshot));
  if (generationChanged) {
    state.intents = state.intents.filter((row) => row.intentId !== intent.intentId);
    callbacks += 1;
    writes += 1;
    return finish(503, 'state_changed', { disposition: 'confirmed_cleanup_no_nonce' });
  }
  if (!Number.isSafeInteger(finalNow) || finalNow < 0 || finalNow > MAX_TIMESTAMP) return failClock(finalNow);
  if (finalNow < state.highWater) return failClock(finalNow);
  if (abs(finalNow - op.ts) > state.window) {
    state.intents = state.intents.filter((row) => row.intentId !== intent.intentId);
    callbacks += 1;
    writes += 1;
    return finish(401, 'timestamp_out_of_window', { disposition: 'confirmed_cleanup_no_nonce' });
  }
  if (op.finalOutcome === 'unknown') {
    state.intents = state.intents.filter((row) => row.intentId !== intent.intentId);
    state.tombstones.push({ ...intent, outcome: op.reservationFound === true ? 'unknown_found' : 'unknown_absent' });
    state.fenced = true;
    callbacks += 1;
    writes += 1;
    return finish(503, 'durability_unavailable', { reconciliation: 'no_redelivery' });
  }
  if (op.finalOutcome === 'aborted') {
    if (op.cleanupOutcome === 'confirmed') {
      state.intents = state.intents.filter((row) => row.intentId !== intent.intentId);
      callbacks += 1;
      writes += 1;
      return finish(503, 'durability_unavailable', { disposition: 'definitely_not_committed' });
    }
    state.fenced = true;
    state.tombstones.push({ ...intent, outcome: 'cleanup_unknown' });
    callbacks += 1;
    writes += 1;
    return finish(503, 'durability_unavailable', { disposition: 'unknown' });
  }
  if (op.finalOutcome !== 'committed') return noWrite(503, 'durability_unavailable');

  state.intents = state.intents.filter((row) => row.intentId !== intent.intentId);
  state.highWater = finalNow;
  purgeExpiredLive(state, finalNow, key);
  state.live.push({ key, intentId: intent.intentId, operationId: intent.operationId, requestIdentity: intent.requestIdentity, ts: intent.ts, retainUntil: intent.retainUntil });
  callbacks += 1;
  writes += 1;
  if (op.crashAfterCommit === true) return finish(503, 'durability_unavailable', { disposition: 'committed_no_dispatch' });
  state.effects.authorization += 1;
  if (op.authorization === 'refused') return finish(403, 'authorization_refused', { disposition: 'committed_consumed' });
  if (op.handlerEffect === 'stateMutation') state.effects.stateMutation += 1;
  if (op.dispatch === true) {
    state.effects.handler += 1;
    dispatches = 1;
  }
  return finish(200, 'committed', { disposition: 'committed_dispatched' });
};

export const reconcileNonceRestart = (persistedInput, { operation, reservationPresent, intentPresent }) => {
  const state = copy(persistedInput);
  state.fenced = true;
  const tombstone = state.tombstones.find((row) => row.intentId === operation);
  if (tombstone || intentPresent || reservationPresent) {
    if (!tombstone) state.tombstones.push({ intentId: operation, outcome: reservationPresent ? 'unknown_found' : 'unknown_absent' });
    return { state, admission: false, redeliver: false, reason: 'no_redelivery' };
  }
  return { state, admission: false, redeliver: false, reason: 'absence_is_not_retry_permission' };
};
