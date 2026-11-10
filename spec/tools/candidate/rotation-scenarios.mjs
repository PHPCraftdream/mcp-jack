import { base64url, sha256, signSeed } from './crypto.mjs';
import { ROTATION_KEYS, rotationRecordsForVerification, ROTATION_KEYS_PUBLIC, ENDPOINT, AUDIENCE } from './rotation-cases.mjs';
import { signRecord } from './rotation-encode.mjs';

const signResponse = ({ signer, ts, now, envelope, invalidBody = false, id = 7, padBodyTo }) => {
  let body = Buffer.from(invalidBody ? '{not-json' : JSON.stringify({
    jsonrpc: '2.0', id,
    result: { content: [{ type: 'text', text: JSON.stringify(envelope) }], structuredContent: envelope, isError: false },
  }));
  if (Number.isInteger(padBodyTo) && body.length < padBodyTo) body = Buffer.concat([body, Buffer.alloc(padBodyTo - body.length, 0x20)]);
  const requestSig = 'candidate-event-request-signature';
  const bytes = Buffer.from(['mcp-jack/v1/response', '200', requestSig, signer.kid, String(ts), base64url(sha256(body))].join('\n'));
  return {
    status: 200, requestSig, kid: signer.kid, ts, now,
    body_b64u: base64url(body), signature: base64url(signSeed(signer.seed, bytes)),
  };
};
const recordBytes = (records) => records.map((record) => record.wireText);
const envelope = (current, records, head, complete = true) => ({
  current: { kid: current.kid, public_key: current.publicKeyB64u }, records, head, complete,
});
const baseSnapshot = (records = []) => ({
  endpoint: ENDPOINT, aud: AUDIENCE,
  anchor: ROTATION_KEYS_PUBLIC.anchor,
  records: recordBytes(records), window: 30, revision: 1, fence: false, clockGeneration: 1,
});
const caseInput = ({ id, records = [], signer, carrierRecords, head, complete = true, ts, now = ts, cursorOrdinal = 0, cursorHash = '-', preCallbackNow = now, finalNow = now, callbackOutcome = 'ack', writerBusy = false, staleSnapshot = false, invalidBody = false, padBodyTo, expect }) => {
  const snapshotRecords = records;
  const bodyEnvelope = envelope(signer, carrierRecords, head, complete);
  const response = signResponse({ signer, ts, now, envelope: bodyEnvelope, invalidBody, padBodyTo });
  return {
    id,
    input: {
      snapshot: baseSnapshot(snapshotRecords),
      response,
      expectedId: 7,
      cursor: { ordinal: cursorOrdinal, hash: cursorHash },
      preCallbackNow, finalNow, finalClockGeneration: 1,
      callbackOutcome, writerBusy, staleSnapshot,
    },
    expect,
  };
};
const { r1, r2, tieR1, tieR2 } = rotationRecordsForVerification;
const conflictingR1 = signRecord({ endpoint: ENDPOINT, aud: AUDIENCE, ordinal: 1, previousHash: '-', oldSigner: ROTATION_KEYS.anchor, newSigner: ROTATION_KEYS.next3, publishedAt: 1000 });
const next1 = ROTATION_KEYS.next1;
const anchor = ROTATION_KEYS.anchor;

// Expected outcomes are hand-stated. Inputs include the exact signed response
// carrier and complete record bytes so the disk runner can execute the model.
export const ROTATION_CLIENT_CASES = Object.freeze([
  caseInput({ id: 'first-bridge-before-cutoff', signer: anchor, carrierRecords: recordBytes([r1]), head: { ordinal: 1, hash: r1.hash }, ts: 173799, now: 173799, preCallbackNow: 173799, finalNow: 173799, expect: { error: null, callbacks: 1, committed: true, ackOrdinal: 1, carrierTrusted: true } }),
  caseInput({ id: 'first-bridge-at-cutoff', signer: anchor, carrierRecords: recordBytes([r1]), head: { ordinal: 1, hash: r1.hash }, ts: 173799, now: 173799, preCallbackNow: 173800, finalNow: 173800, expect: { error: 'rotation_bridge_expired', callbacks: 0, committed: false, ackOrdinal: 0 } }),
  caseInput({ id: 'unknown-outer-before-invalid-payload', signer: ROTATION_KEYS.next2, carrierRecords: [], head: { ordinal: 0, hash: '-' }, ts: 1000, now: 1000, invalidBody: true, expect: { error: 'unknown_server_key', callbacks: 0, committed: false, ackOrdinal: 0 } }),
  caseInput({ id: 'exact-duplicate-at-new-key-lower-bound', records: [r1], signer: next1, carrierRecords: recordBytes([r1]), head: { ordinal: 1, hash: r1.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, expect: { error: null, callbacks: 0, duplicate: true, ackOrdinal: 1, carrierTrusted: true } }),
  caseInput({ id: 'new-key-lower-bound-minus-one-is-stale', records: [r1], signer: next1, carrierRecords: recordBytes([r1]), head: { ordinal: 1, hash: r1.hash }, ts: 173800, now: 173769, cursorOrdinal: 1, cursorHash: r1.hash, expect: { error: 'timestamp_out_of_window', callbacks: 0, committed: false, ackOrdinal: 1 } }),
  caseInput({ id: 'duplicate-prefix-then-extension', records: [r1], signer: next1, carrierRecords: recordBytes([r1, r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, expect: { error: null, callbacks: 1, committed: true, ackOrdinal: 2, carrierTrusted: true } }),
  caseInput({ id: 'trust-callback-definite-conflict', records: [r1], signer: next1, carrierRecords: recordBytes([r1, r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, callbackOutcome: 'conflict', expect: { error: 'rotation_state_changed', callbacks: 1, committed: false, ackOrdinal: 1 } }),
  caseInput({ id: 'trust-callback-unknown-fences', records: [r1], signer: next1, carrierRecords: recordBytes([r1, r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, callbackOutcome: 'unknown', expect: { error: 'rotation_state_unknown', callbacks: 1, committed: false, ackOrdinal: 1, fenced: true } }),
  caseInput({ id: 'late-callback-ack-retains-snapshot-but-rejects-carrier', signer: anchor, carrierRecords: recordBytes([r1]), head: { ordinal: 1, hash: r1.hash }, ts: 173799, now: 173799, preCallbackNow: 173799, finalNow: 173800, expect: { error: 'rotation_key_interval', callbacks: 1, committed: true, ackOrdinal: 1, carrierTrusted: false } }),
  caseInput({ id: 'conflicting-duplicate-prefix-is-not-adopted', records: [r1], signer: next1, carrierRecords: recordBytes([conflictingR1]), head: { ordinal: 1, hash: conflictingR1.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, expect: { error: 'rotation_conflict', callbacks: 0, committed: false, ackOrdinal: 1 } }),
  caseInput({ id: 'gapped-prefix-cannot-be-claimed-by-head', signer: anchor, carrierRecords: recordBytes([r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173799, now: 173799, cursorOrdinal: 0, cursorHash: '-', expect: { error: 'rotation_gap', callbacks: 0, committed: false, ackOrdinal: 0 } }),
  caseInput({ id: 'busy-writer-stops-before-trust-callback', records: [r1], signer: next1, carrierRecords: recordBytes([r1, r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, writerBusy: true, expect: { error: 'rotation_state_changed', callbacks: 0, committed: false, ackOrdinal: 1 } }),
  caseInput({ id: 'stale-whole-snapshot-stops-before-callback', records: [r1], signer: next1, carrierRecords: recordBytes([r1, r2]), head: { ordinal: 2, hash: r2.hash }, ts: 173800, now: 173800, cursorOrdinal: 1, cursorHash: r1.hash, staleSnapshot: true, expect: { error: 'rotation_state_changed', callbacks: 0, committed: false, ackOrdinal: 1 } }),
  caseInput({ id: 'whole-response-body-cap-plus-one', signer: anchor, carrierRecords: [], head: { ordinal: 0, hash: '-' }, ts: 1000, now: 1000, padBodyTo: 262145, expect: { error: 'rotation_result_invalid', callbacks: 0, committed: false, ackOrdinal: 0 } }),
]);

export const ROTATION_EVENT_CASES = Object.freeze([
  { id: 'same-second-greatest-ordinal-wins', input: { kind: 'selection', records: recordBytes([tieR1, tieR2]), before: 173799, at: 173800, after: 173801 }, expect: { selectedBefore: 0, selectedAt: 2, selectedAfter: 2 } },
  { id: 'clock-rollback-latches', input: { kind: 'clock', guard: { binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 }, rawNow: 173799 }, expect: { error: 'rotation_clock_unsafe', highWater: 173800, unsafe: true, writes: 1, callbacks: 1 } },
  { id: 'clock-equal-is-noop', input: { kind: 'clock', guard: { binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 }, rawNow: 173800 }, expect: { error: null, highWater: 173800, revision: 4, unsafe: false, writes: 0, callbacks: 0 } },
  { id: 'clock-rollback-latch-unknown-is-unavailable', input: { kind: 'clock', guard: { binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 }, rawNow: 173799, latch: 'unknown' }, expect: { error: 'rotation_clock_unavailable', highWater: 173800, unsafe: false, revision: 4, writes: 1, callbacks: 1 } },
  { id: 'clock-advance-persists-revision', input: { kind: 'clock', guard: { binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 }, rawNow: 173801 }, expect: { error: null, highWater: 173801, revision: 5, writes: 1, callbacks: 1 } },
  { id: 'server-final-eligible-single-signature', input: { kind: 'emission', selectedKid: anchor.kid, selectedOrdinal: 0, signingTime: 173799, emissionTime: 173799, records: recordBytes([r1]), clockGenerationBefore: 1, clockGenerationNow: 1 }, expect: { emit: true, signatures: 1, resigns: 0 } },
  { id: 'server-final-cutoff-no-resign', input: { kind: 'emission', selectedKid: next1.kid, selectedOrdinal: 1, signingTime: 177399, emissionTime: 177400, records: recordBytes([r1, r2]), clockGenerationBefore: 1, clockGenerationNow: 1, fenced: false, signerReady: true }, expect: { emit: false, signatures: 1, resigns: 0 } },
  { id: 'server-final-generation-fence-no-fallback', input: { kind: 'emission', selectedKid: next1.kid, selectedOrdinal: 1, signingTime: 173800, emissionTime: 173800, records: recordBytes([r1, r2]), clockGenerationBefore: 1, clockGenerationNow: 2 }, expect: { emit: false, signatures: 1, resigns: 0 } },
]);
