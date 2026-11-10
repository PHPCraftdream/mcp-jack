import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyOnDiskFixtures } from '../../tools/candidate/semantic-verify.mjs';
import { GENERATED } from '../../tools/candidate/fixture-build.mjs';
import { base64url, keyId, publicFromSeed, sha256, signSeed, testSeed, verifyNode, RFC8032_TEST } from '../../tools/candidate/crypto.mjs';
import { pureVerifier, runCryptoKats } from '../../tools/candidate/independent-checks.mjs';
import { ENDPOINT, AUDIENCE, ROTATION_KEYS_PUBLIC, ROTATION_NEGATIVE, ROTATION_VALID, rotationRecordsForVerification } from '../../tools/candidate/rotation-cases.mjs';
import { verifyChain, parseRecord, selectedOrdinal, assignmentValid, encodeB } from '../../tools/candidate/rotation-codec.mjs';
import { parseRefreshArguments, parseCandidateResponseBody, durableIntentIdentity, verifyRequestSignature, verifyResponseSignature, validateRefreshPreResponse } from '../../tools/candidate/verification.mjs';
import { acceptRefresh, newRotationSnapshot } from '../../tools/candidate/rotation-state-model.mjs';
import { NONCE_EVENTS } from '../../tools/candidate/scenario-data.mjs';
import { initialNonceState, reserveNonce } from '../../tools/candidate/durable-nonce-model.mjs';
import { advanceAndCheckClock, initialClockGuard, trustClockCAS } from '../../tools/candidate/clock-guard-model.mjs';

const named = (name) => {
  const seed = testSeed(name);
  const publicKey = publicFromSeed(seed);
  return { name, seed, publicKey, publicKeyB64u: base64url(publicKey), kid: keyId(publicKey) };
};
const makeEnvelope = (records, signer, head, complete = true) => ({ current: { kid: signer.kid, public_key: signer.publicKeyB64u }, records, head, complete });
const responseBody = (envelope, id = 7) => Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(envelope) }], structuredContent: envelope, isError: false }));
const signedResponse = ({ signer, ts, now = ts, body, id = 'request-signature' }) => {
  const signatureMessage = Buffer.from(['mcp-jack/v1/response', '200', id, signer.kid, String(ts), base64url(sha256(body))].join('\n'), 'utf8');
  const signature = base64url(signSeed(signer.seed, signatureMessage));
  return { status: 200, requestSig: id, kid: signer.kid, ts, now, body, signature };
};

test('RFC 8032 empty-message KAT and independent pure verifier', () => {
  assert.equal(runCryptoKats().signature, RFC8032_TEST.signature);
  const seed = Buffer.from(RFC8032_TEST.seed, 'hex');
  const publicKey = publicFromSeed(seed);
  const signature = Buffer.from(RFC8032_TEST.signature, 'hex');
  assert.equal(publicKey.toString('hex'), RFC8032_TEST.publicKey);
  assert.equal(verifyNode(publicKey, Buffer.alloc(0), signature), true);
  assert.equal(pureVerifier(publicKey, Buffer.alloc(0), signature), true);
});

test('all candidate deterministic key seeds use SHA256 named-string convention', () => {
  for (const [name, vector] of Object.entries(ROTATION_KEYS_PUBLIC)) {
    const seed = testSeed(`candidate-server-${name}`);
    assert.equal(base64url(publicFromSeed(seed)), vector.public_key);
    assert.equal(keyId(publicFromSeed(seed)), vector.kid);
  }
});

test('valid overlapping and tie chains use exact B/R bytes and ordinal tie selection', () => {
  const anchor = Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url');
  const options = { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor };
  const overlap = verifyChain(ROTATION_VALID.overlapping.map((wire) => Buffer.from(wire, 'ascii')), options);
  assert.equal(overlap.ok, true);
  assert.deepEqual(overlap.records.map((record) => [record.ordinal, record.publishedAt, record.activatesAt]), [[1, 1000, 173800], [2, 4600, 177400]]);
  const tie = verifyChain(ROTATION_VALID.tie.map((wire) => Buffer.from(wire, 'ascii')), options);
  assert.equal(tie.ok, true);
  assert.equal(selectedOrdinal(tie.records, 173799), 0);
  assert.equal(selectedOrdinal(tie.records, 173800), 2);
  assert.equal(assignmentValid(tie.records, 1, 173800), false);
  const r1 = rotationRecordsForVerification.r1;
  assert.equal(r1.b.toString('ascii').split('\n').length, 10);
  assert.equal(r1.wireText.split('\n').length, 12);
  assert.equal(r1.wireText.endsWith('\n'), false);
  assert.equal(encodeB({ endpoint: ENDPOINT, aud: AUDIENCE, ...r1.fields, newPublicKey: r1.fields.publicKey }).equals(r1.b), true);
  assert.equal(r1.hash, base64url(sha256(r1.wire)));
});

test('all source-stated negative rotation vectors reject at their exact first failure', () => {
  const anchor = Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url');
  const authorizers = new Map(Object.values(ROTATION_KEYS_PUBLIC).map((entry) => [entry.kid, Buffer.from(entry.public_key, 'base64url')]));
  for (const row of ROTATION_NEGATIVE) {
    const bytes = Buffer.from(row.wire_b64u, 'base64url');
    const binding = row.binding;
    let result;
    if (row.setup === 'chain') result = verifyChain([bytes], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
    else if (row.setup === 'after-r1') result = verifyChain([Buffer.from(ROTATION_VALID.overlapping[0], 'ascii'), bytes], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
    else if (row.setup === 'decreasing') result = verifyChain([Buffer.from(rotationRecordsForVerification.wrongP.wireText, 'ascii'), bytes], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
    else result = parseRecord(bytes, { endpoint: binding.endpoint, aud: binding.aud, authorizers });
    assert.deepEqual({ ok: result.ok, code: result.code }, { ok: false, code: row.expected }, row.id);
  }
  const reused = rotationRecordsForVerification.reusedAnchor;
  const acceptedProofs = parseRecord(reused.wire, { endpoint: ENDPOINT, aud: AUDIENCE, authorizers: new Map([[ROTATION_KEYS_PUBLIC.anchor.kid, anchor]]) });
  assert.equal(acceptedProofs.ok, true);
  assert.equal(verifyChain([reused.wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor }).code, 'key_reuse');
});

test('strict jack.server.key argument parser preserves integer lexemes and rejects duplicate keys', () => {
  assert.deepEqual(parseRefreshArguments('{"after_ordinal":0,"after_hash":"-"}').value, { after_ordinal: 0, after_hash: '-' });
  for (const raw of ['{"after_ordinal":0,"after_hash":"-","after_hash":"-"}', '{"after_ordinal":1e0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":1.0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":0,"after_hash":"-","extra":true}']) assert.equal(parseRefreshArguments(raw).code, 'invalid_params');
});

test('durable operation identity binds exact deployment, S, signature, key/nonce and 16-byte operation id', () => {
  const input = { deploymentId: 'deployment-A', kidRaw: Buffer.alloc(32, 1), nonceRaw: Buffer.alloc(16, 2), signatureRaw: Buffer.alloc(64, 3), signingBytes: Buffer.from('exact v1 eight-line S'), operationId: Buffer.alloc(16, 4) };
  const digest = durableIntentIdentity(input);
  assert.equal(digest.length, 43);
  for (const changed of [
    { ...input, deploymentId: 'deployment-B' },
    { ...input, signingBytes: Buffer.from('changed S') },
    { ...input, signatureRaw: Buffer.alloc(64, 5) },
    { ...input, operationId: Buffer.alloc(16, 6) },
  ]) assert.notEqual(digest, durableIntentIdentity(changed));
});

test('request and response signing bytes are independently assembled and verified', () => {
  const signer = named('candidate-raw-signature');
  const nonce = base64url(Buffer.alloc(16, 6));
  const body = Buffer.from('request bytes', 'utf8');
  const requestMessage = Buffer.from(['mcp-jack/v1/request', 'POST', '/mcp?raw=1', AUDIENCE, signer.kid, '1000', nonce, base64url(sha256(body))].join('\n'), 'utf8');
  const requestSignature = signSeed(signer.seed, requestMessage);
  const request = { method: 'POST', target: '/mcp?raw=1', aud: AUDIENCE, kid: signer.kid, ts: 1000, nonce, body, signature: base64url(requestSignature) };
  const requestVerified = verifyRequestSignature({ request, publicKey: signer.publicKey });
  assert.equal(requestVerified.ok, true);
  assert.deepEqual(requestVerified.signingBytes, requestMessage);
  assert.equal(pureVerifier(signer.publicKey, requestMessage, requestSignature), true);
  const responseBody = Buffer.from('response bytes', 'utf8');
  const responseMessage = Buffer.from(['mcp-jack/v1/response', '200', request.signature, signer.kid, '1000', base64url(sha256(responseBody))].join('\n'), 'utf8');
  const responseSignature = signSeed(signer.seed, responseMessage);
  const response = { status: 200, requestSig: request.signature, kid: signer.kid, ts: 1000, body: responseBody, signature: base64url(responseSignature) };
  assert.equal(verifyResponseSignature({ response, publicKey: signer.publicKey }).ok, true);
  assert.equal(pureVerifier(signer.publicKey, responseMessage, responseSignature), true);
});

test('raw signed response precedence rejects unknown carrier before invalid bytes and invalid signature before payload', () => {
  const anchor = named('candidate-server-anchor');
  const r1 = rotationRecordsForVerification.r1;
  const result = makeEnvelope([r1.wireText], anchor, { ordinal: 1, hash: r1.hash });
  const body = responseBody(result);
  const response = signedResponse({ signer: anchor, ts: 1000, body });
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: anchor.kid, anchorPublicKey: anchor.publicKey });
  assert.equal(validateRefreshPreResponse({ state: snapshot, response, expectedId: 7, cursor: { ordinal: 0, hash: '-' } }).ok, true);
  const invalidCarrier = validateRefreshPreResponse({ state: snapshot, response: { ...response, kid: ROTATION_KEYS_PUBLIC.next1.kid, body: Buffer.from('{not-json'), signature: 'not-a-signature' }, expectedId: 7, cursor: { ordinal: 0, hash: '-' } });
  assert.equal(invalidCarrier.error, 'unknown_server_key');
  const badSig = validateRefreshPreResponse({ state: snapshot, response: { ...response, body: Buffer.from('{not-json'), signature: base64url(Buffer.alloc(64)) }, expectedId: 7, cursor: { ordinal: 0, hash: '-' } });
  assert.equal(badSig.error, 'bad_signature');
});

test('bridge at A-1 commits; bridge equality is local rotation_bridge_expired with zero trust CAS', () => {
  const anchor = named('candidate-server-anchor');
  const r1 = rotationRecordsForVerification.r1;
  const result = makeEnvelope([r1.wireText], anchor, { ordinal: 1, hash: r1.hash });
  const body = responseBody(result);
  const response = signedResponse({ signer: anchor, ts: 173770, now: 173770, body });
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: anchor.kid, anchorPublicKey: anchor.publicKey });
  const before = acceptRefresh({ snapshot, response, expectedId: 7, cursor: { ordinal: 0, hash: '-' }, preCallbackNow: 173799, finalNow: 173799, finalClockGeneration: 1 });
  assert.deepEqual({ accepted: before.accepted, callbacks: before.callbacks, ack: before.snapshot.ackOrdinal }, { accepted: true, callbacks: 1, ack: 1 });
  const at = acceptRefresh({ snapshot, response, expectedId: 7, cursor: { ordinal: 0, hash: '-' }, preCallbackNow: 173800, finalNow: 173800, finalClockGeneration: 1 });
  assert.deepEqual({ error: at.error, callbacks: at.callbacks, committed: at.committed }, { error: 'rotation_bridge_expired', callbacks: 0, committed: false });
});

test('exact duplicate checks signature, current tuple and cutoff before zero trust callback', () => {
  const r1 = rotationRecordsForVerification.r1;
  const first = verifyChain([r1.wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url') });
  const next = named('candidate-server-next1');
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url'), records: first.records });
  const result = makeEnvelope([r1.wireText], next, { ordinal: 1, hash: r1.hash });
  const body = responseBody(result);
  const response = signedResponse({ signer: next, ts: 173800, now: 173800, body });
  const duplicate = acceptRefresh({ snapshot, response, expectedId: 7, cursor: { ordinal: 1, hash: r1.hash }, preCallbackNow: 173800, finalNow: 173800, finalClockGeneration: 1 });
  assert.deepEqual({ accepted: duplicate.accepted, callbacks: duplicate.callbacks, ack: duplicate.snapshot.ackOrdinal, deadlineDelta: duplicate.effects.deadlinesChanged }, { accepted: true, callbacks: 0, ack: 1, deadlineDelta: 0 });
  const changedCurrent = makeEnvelope([r1.wireText], named('candidate-server-anchor'), { ordinal: 1, hash: r1.hash });
  const wrong = signedResponse({ signer: next, ts: 173800, body: responseBody(changedCurrent) });
  const rejected = acceptRefresh({ snapshot, response: wrong, expectedId: 7, cursor: { ordinal: 1, hash: r1.hash }, preCallbackNow: 173800, finalNow: 173800, finalClockGeneration: 1 });
  assert.equal(rejected.error, 'rotation_result_invalid');
  assert.equal(rejected.callbacks, 0);
});

test('valid extension preserves committed revision and one callback regardless of links', () => {
  const r1 = rotationRecordsForVerification.r1;
  const r2 = rotationRecordsForVerification.r2;
  const chain = verifyChain([r1.wire, r2.wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url') });
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url'), records: [chain.records[0]] });
  const next = named('candidate-server-next1');
  const result = makeEnvelope([r1.wireText, r2.wireText], next, { ordinal: 2, hash: r2.hash });
  const response = signedResponse({ signer: next, ts: 173800, now: 173800, body: responseBody(result) });
  const accepted = acceptRefresh({ snapshot, response, expectedId: 7, cursor: { ordinal: 1, hash: r1.hash }, preCallbackNow: 173800, finalNow: 173800, finalClockGeneration: 1 });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.callbacks, 1);
  assert.equal(accepted.effects.trustChanges, 1);
});
test('old signer cutoff A2 is strict at equality and does not call the trust callback', () => {
  const chain = verifyChain([rotationRecordsForVerification.r1.wire, rotationRecordsForVerification.r2.wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url') });
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url'), records: chain.records });
  const next = named('candidate-server-next1');
  const body = responseBody(makeEnvelope([rotationRecordsForVerification.r1.wireText, rotationRecordsForVerification.r2.wireText], next, { ordinal: 2, hash: rotationRecordsForVerification.r2.hash }));
  const response = signedResponse({ signer: next, ts: 177399, now: 177399, body });
  const rejected = acceptRefresh({ snapshot, response, expectedId: 7, cursor: { ordinal: 2, hash: rotationRecordsForVerification.r2.hash }, preCallbackNow: 177399, finalNow: 177400, finalClockGeneration: 1 });
  assert.deepEqual({ error: rejected.error, callbacks: rejected.callbacks, ack: rejected.snapshot.ackOrdinal }, { error: 'rotation_key_interval', callbacks: 0, ack: 2 });
});

test('ClockGuard high-water, rollback latch, and clock tuple CAS are separate from trust callbacks', () => {
  const guard = initialClockGuard({ binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 });
  const same = advanceAndCheckClock(guard, 173800);
  assert.deepEqual([same.ok, same.writes, same.callbacks], [true, 0, 0]);
  const greater = advanceAndCheckClock(guard, 173801);
  assert.deepEqual([greater.ok, greater.guard.highWater, greater.guard.revision, greater.callbacks], [true, 173801, 5, 1]);
  const stale = advanceAndCheckClock(guard, 173799);
  assert.deepEqual([stale.error, stale.guard.unsafe, stale.guard.highWater, stale.writes], ['rotation_clock_unsafe', true, 173800, 1]);
  const trust = { binding: ENDPOINT, revision: 1, head: { ordinal: 0, hash: '-' } };
  const conflict = trustClockCAS({ expectedTrust: trust, desiredTrust: { ...trust, revision: 2 }, expectedClock: guard, actualClock: greater.guard });
  assert.deepEqual([conflict.callbacks, conflict.committed, conflict.error, conflict.trust.revision], [1, false, 'rotation_state_changed', 1]);
});

test('ClockGuard unknown unsafe-latch outcome remains unavailable and is not treated as confirmed fence', () => {
  const guard = initialClockGuard({ binding: ENDPOINT, window: 30, highWater: 173800, revision: 4 });
  const unknown = advanceAndCheckClock(guard, 173799, { latchOutcome: 'unknown' });
  assert.deepEqual([unknown.error, unknown.guard.unsafe, unknown.guard.highWater, unknown.writes, unknown.callbacks], ['rotation_clock_unavailable', false, 173800, 1, 1]);
});
test('hand-stated nonce cases replay callbacks, H, live rows, intents, tombstones, and effects', () => {
  const badSignature = NONCE_EVENTS.find((item) => item.id === 'bad-signature-zero-writes');
  const rejected = reserveNonce(badSignature.state, badSignature.event);
  assert.deepEqual([rejected.callbacks, rejected.writes, rejected.dispatches], [0, 0, 0]);
  const counterfactual = reserveNonce(badSignature.state, { ...badSignature.event, authenticated: true, dispatch: true });
  assert.notDeepEqual([counterfactual.callbacks, counterfactual.writes, counterfactual.dispatches], [0, 0, 0]);
  const edge = NONCE_EVENTS.find((item) => item.id === 'expiry-equality');
  assert.equal(reserveNonce(edge.state, edge.event).response.code, 'replayed_nonce');
  assert.notEqual(reserveNonce(edge.state, { ...edge.event, ts: 131, entryNow: 131, intentNow: 131, finalNow: 131 }).response.code, 'replayed_nonce');
});

test('candidate response parser rejects duplicate members in the actual verification path', () => {
  const duplicate = Buffer.from('{"jsonrpc":"2.0","jsonrpc":"2.0","id":7,"result":{}}');
  assert.equal(parseCandidateResponseBody({ body: duplicate }, 7).error, 'rotation_result_invalid');
});

test('refresh rejects Unicode aliases before record signature verification', () => {
  const anchor = named('candidate-server-anchor');
  const r1 = rotationRecordsForVerification.r1;
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: anchor.kid, anchorPublicKey: anchor.publicKey });
  const record = r1.wireText.replace(/^m/, 'ŭ');
  const body = responseBody(makeEnvelope([record], anchor, { ordinal: 1, hash: r1.hash }));
  const response = signedResponse({ signer: anchor, ts: 1000, body });
  assert.equal(validateRefreshPreResponse({ state: snapshot, response, expectedId: 7, cursor: { ordinal: 0, hash: '-' } }).error, 'rotation_record_invalid');
});

test('candidate head ordinal rejects exponent and fraction lexemes in both representations', () => {
  const anchor = named('candidate-server-anchor');
  const envelope = makeEnvelope([], anchor, { ordinal: 0, hash: '-' });
  for (const rawOrdinal of ['0e0', '0.0']) {
    const text = JSON.stringify(envelope).replace('"ordinal":0', `"ordinal":${rawOrdinal}`);
    const structured = JSON.stringify(envelope).replace('"ordinal":0', `"ordinal":${rawOrdinal}`);
    const body = Buffer.from(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":${JSON.stringify(text)}}],"structuredContent":${structured},"isError":false}}`);
    assert.equal(parseCandidateResponseBody({ body }, 7).error, 'rotation_result_invalid');
  }
});
test('serialized durable nonce arrival source cases are exercised by the dedicated model suite', () => {
  assert.equal(NONCE_EVENTS.filter((item) => item.sequence).length, 2);
});

test('refresh path enforces persisted clock rollback and uncertain forward writes before trust CAS', () => {
  const anchor = named('candidate-server-anchor');
  const r1 = rotationRecordsForVerification.r1;
  const snapshot = newRotationSnapshot({ endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: anchor.kid, anchorPublicKey: anchor.publicKey });
  const response = signedResponse({ signer: anchor, ts: 1000, body: responseBody(makeEnvelope([r1.wireText], anchor, { ordinal: 1, hash: r1.hash })) });
  const input = { snapshot, response, expectedId: 7, cursor: { ordinal: 0, hash: '-' }, preCallbackNow: 1000, finalNow: 1000, finalClockGeneration: 1 };
  const uncertain = acceptRefresh({ ...input, clockOutcome: 'unknown' });
  assert.deepEqual([uncertain.error, uncertain.callbacks, uncertain.snapshot.fence], ['rotation_clock_unavailable', 0, true]);
  snapshot.clockGuard.highWater = 1001;
  const rollback = acceptRefresh(input);
  assert.deepEqual([rollback.error, rollback.callbacks, rollback.snapshot.clockGuard.unsafe], ['rotation_clock_unsafe', 0, true]);
});

test('generated candidate vector bytes match source and saved cases execute', () => {
  const currentRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
  for (const [relative, expected] of Object.entries(GENERATED)) assert.equal(readFileSync(join(currentRoot, 'spec', relative), 'utf8'), expected);
  const counts = verifyOnDiskFixtures();
  assert.equal(counts.codec, ROTATION_NEGATIVE.length);
  assert.equal(counts.nonce, NONCE_EVENTS.length);
  assert.equal(counts.rotationClient, 14);
  assert.equal(counts.rotationEvents, 8);
});
