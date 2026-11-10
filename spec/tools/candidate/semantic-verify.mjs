import { readFileSync } from 'node:fs';

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyChain, parseRecord, selectedOrdinal } from './rotation-codec.mjs';
import { ROTATION_KEYS_PUBLIC } from './rotation-cases.mjs';
import { reserveNonce, initialNonceState } from './durable-nonce-model.mjs';
import { advanceAndCheckClock, initialClockGuard, trustClockCAS } from './clock-guard-model.mjs';
import { acceptRefresh, finalServerEmission, newRotationSnapshot } from './rotation-state-model.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const readJson = (path) => JSON.parse(readFileSync(resolve(ROOT, path), 'utf8'));
const check = (condition, message) => { if (!condition) throw new Error(message); };
const anchor = ROTATION_KEYS_PUBLIC.anchor;
const endpoint = 'https://svc.example.test/mcp';
const audience = 'https://svc.example.test';
const compare = (actual, expected, message) => check(JSON.stringify(actual) === JSON.stringify(expected), `${message}: got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);

const verifyRotationFixture = (fixture) => {
  const publicKeys = new Map(Object.values(fixture.keys).map((entry) => [entry.kid, Buffer.from(entry.public_key, 'base64url')]));
  for (const item of fixture.malformed) {
    const wire = Buffer.from(item.wire_b64u, 'base64url');
    const options = { endpoint, aud: audience, anchorKid: anchor.kid, anchorPublicKey: Buffer.from(anchor.public_key, 'base64url') };
    let got;
    if (item.setup === 'chain') got = verifyChain([wire], options);
    else if (item.setup === 'after-r1') got = verifyChain([Buffer.from(fixture.valid_chains.overlapping[0], 'ascii'), wire], options);
    else if (item.setup === 'decreasing') got = verifyChain([Buffer.from(fixture.source_controls.decreasing_prefix, 'ascii'), wire], options);
    else got = parseRecord(wire, { endpoint: item.binding.endpoint, aud: item.binding.aud, authorizers: publicKeys });
    check(!got.ok && got.code === item.expected, `${item.id}: expected ${item.expected}, got ${got.code}`);
  }
  for (const [id, chain] of Object.entries(fixture.valid_chains)) {
    const got = verifyChain(chain.map((wire) => Buffer.from(wire, 'ascii')), { endpoint, aud: audience, anchorKid: anchor.kid, anchorPublicKey: Buffer.from(anchor.public_key, 'base64url') });
    check(got.ok, `${id}: valid chain rejected: ${got.code}`);
  }
};

const verifyNonceFixture = (fixture) => {
  for (const row of fixture.cases) {
    if (row.sequence) {
      let state = initialNonceState();
      const got = row.sequence.map((event) => {
        const result = reserveNonce(state, event);
        state = result.state;
        return result;
      });
      compare(got.map((result) => [result.response.status, result.response.code]), row.expect.statuses, `${row.id}: serialized outcomes`);
      compare(got.map((result) => result.callbacks), row.expect.callbacks, `${row.id}: serialized callbacks`);
      compare(got.map((result) => result.writes), row.expect.writes, `${row.id}: serialized writes`);
      compare(got.map((result) => result.dispatches), row.expect.dispatches, `${row.id}: serialized dispatches`);
      compare(state.live.length, row.expect.liveCount, `${row.id}: live rows`);
      compare(state.intents.length, row.expect.intentCount, `${row.id}: intent rows`);
      compare(state.tombstones.length, row.expect.tombstoneCount, `${row.id}: tombstone rows`);
      compare(state.highWater, row.expect.highWater, `${row.id}: H`);
      compare(state.effects, row.expect.effects, `${row.id}: side effects`);
      compare(got.filter((result) => result.disposition === 'committed_dispatched').length, row.expect.confirmedCommits, `${row.id}: confirmed final commits`);
      continue;
    }
    const got = reserveNonce(row.state, row.event);
    const want = row.expect;
    check(got.response.status === want.status && got.response.code === want.code, `${row.id}: status/code`);
    check(got.callbacks === want.callbacks && got.writes === want.writes && got.dispatches === want.dispatches, `${row.id}: callbacks/writes/dispatch`);
    compare(got.state.live.length, want.liveCount, `${row.id}: live-count`);
    compare(got.state.intents.length, want.intentCount, `${row.id}: intent-count`);
    compare(got.state.tombstones.length, want.tombstoneCount, `${row.id}: tombstone-count`);
    compare(got.state.highWater, want.highWater, `${row.id}: high-water`);
    compare(got.state.fenced, want.fenced, `${row.id}: fence`);
    compare(got.effects, want.effects, `${row.id}: effects`);
    if (want.tombstoneOutcome) check(got.state.tombstones.some((entry) => entry.outcome === want.tombstoneOutcome), `${row.id}: terminal outcome`);
    if (want.preserveLive) compare(got.state.live, row.state.live, `${row.id}: exact live rows preserved`);
    if (want.preserveTombstones) compare(got.state.tombstones, row.state.tombstones, `${row.id}: exact tombstones preserved`);
    if (want.reconciliation) check(got.reconciliation === want.reconciliation, `${row.id}: reconciliation disposition`);
  }
};

const snapshotForCase = (raw) => {
  const parsed = raw.records.length === 0
    ? { ok: true, records: [] }
    : verifyChain(raw.records.map((wire) => Buffer.from(wire, 'ascii')), {
      endpoint: raw.endpoint, aud: raw.aud, anchorKid: raw.anchor.kid,
      anchorPublicKey: Buffer.from(raw.anchor.public_key, 'base64url'),
    });
  check(parsed.ok, `input snapshot chain invalid: ${parsed.code}`);
  check(parsed.records.length === raw.records.length, 'snapshot must contain complete contiguous record bytes');
  return newRotationSnapshot({
    endpoint: raw.endpoint, aud: raw.aud,
    anchorKid: raw.anchor.kid, anchorPublicKey: Buffer.from(raw.anchor.public_key, 'base64url'),
    window: raw.window, configuredWindow: raw.window, revision: raw.revision,
    records: parsed.records, fence: raw.fence, clockGeneration: raw.clockGeneration,
  });
};
const verifyRotationCase = (row) => {
  const input = row.input;
  const response = { ...input.response, body: Buffer.from(input.response.body_b64u, 'base64url') };
  const result = acceptRefresh({
    snapshot: snapshotForCase(input.snapshot), response, expectedId: input.expectedId,
    cursor: input.cursor, preCallbackNow: input.preCallbackNow, finalNow: input.finalNow,
    finalClockGeneration: input.finalClockGeneration, callbackOutcome: input.callbackOutcome,
    writerBusy: input.writerBusy, staleSnapshot: input.staleSnapshot,
  });
  const want = row.expect;
  compare(result.error ?? null, want.error, `${row.id}: local error`);
  check(result.callbacks === want.callbacks, `${row.id}: trust callback count`);
  if (want.committed !== undefined) check(result.committed === want.committed, `${row.id}: committed`);
  if (want.ackOrdinal !== undefined) check(result.snapshot.ackOrdinal === want.ackOrdinal, `${row.id}: acknowledged head`);
  if (want.duplicate !== undefined) check(result.duplicate === want.duplicate, `${row.id}: duplicate result`);
  if (want.carrierTrusted !== undefined) check(result.carrierTrusted === want.carrierTrusted, `${row.id}: carrier trust`);
  if (want.fenced !== undefined) check(result.snapshot.fence === want.fenced, `${row.id}: fence`);
  if (input.callbackOutcome === 'ack' && result.callbacks === 1) check(result.snapshot.revision === input.snapshot.revision + 1, `${row.id}: one full-snapshot revision advance`);
};
const verifyRotationEvent = (row) => {
  const input = row.input;
  const want = row.expect;
  if (input.kind === 'clock') {
    const got = advanceAndCheckClock(initialClockGuard(input.guard), input.rawNow, { latchOutcome: input.latch });
    compare(got.error ?? null, want.error, `${row.id}: clock error`);
    if (want.unsafe !== undefined) check(got.guard.unsafe === want.unsafe, `${row.id}: clock unsafe fence`);
    if (want.highWater !== undefined) check(got.guard.highWater === want.highWater, `${row.id}: clock high-water`);
    if (want.revision !== undefined) check(got.guard.revision === want.revision, `${row.id}: clock revision`);
    check(got.writes === want.writes && got.callbacks === want.callbacks, `${row.id}: clock writes/callbacks`);
    return;
  }
  if (input.kind === 'emission') {
    const chain = verifyChain(input.records.map((wire) => Buffer.from(wire, 'ascii')), {
      endpoint, aud: audience, anchorKid: anchor.kid, anchorPublicKey: Buffer.from(anchor.public_key, 'base64url'),
    });
    check(chain.ok, `${row.id}: invalid rotation event chain`);
    const got = finalServerEmission({ ...input, records: chain.records });
    compare({ emit: got.emit, signatures: got.signatures, resigns: got.resigns }, want, `${row.id}: final emission`);
    return;
  }
  if (input.kind === 'selection') {
    const records = verifyChain(input.records.map((wire) => Buffer.from(wire, 'ascii')), {
      endpoint, aud: audience, anchorKid: anchor.kid, anchorPublicKey: Buffer.from(anchor.public_key, 'base64url'),
    });
    check(records.ok, `${row.id}: selection chain`);
    compare({ selectedBefore: selectedOrdinal(records.records, input.before), selectedAt: selectedOrdinal(records.records, input.at), selectedAfter: selectedOrdinal(records.records, input.after) }, want, `${row.id}: selected ordinal`);
    return;
  }
  throw new Error(`${row.id}: unsupported event input kind ${input.kind}`);
};

const verifyRotationState = (fixture) => {
  const expectedLocalErrors = ['rotation_result_invalid', 'rotation_record_invalid', 'rotation_conflict', 'rotation_gap', 'rotation_bridge_expired', 'rotation_state_changed', 'rotation_state_unknown', 'rotation_key_interval', 'rotation_clock_unsafe', 'rotation_clock_unavailable'];
  check(JSON.stringify(fixture.client_local_errors) === JSON.stringify(expectedLocalErrors), 'client local error vocabulary');
  check(fixture.tool === 'jack.server.key', 'candidate tool name');
  check(fixture.arguments.exact_fields.join(',') === 'after_ordinal,after_hash', 'strict request fields');
  check(fixture.result.exact_fields.join(',') === 'current,records,head,complete', 'result tuple fields');
  check(fixture.server_errors.invalid_params === 400 && fixture.server_errors.rotation_checkpoint_unavailable === 409 && fixture.server_errors.rotation_state_unavailable === 503, 'candidate server status mapping');
  check(fixture.client_local_errors.every((name) => name.startsWith('rotation_')), 'client-local errors must not be HTTP status values');
  for (const row of fixture.client_cases) {
    check(row.input && row.input.response && row.input.snapshot && Object.hasOwn(row, 'expect'), `${row.id}: executable signed input/oracle`);
    verifyRotationCase(row);
  }
  for (const row of fixture.event_cases) verifyRotationEvent(row);
  check(fixture.client_cases.length === 14 && fixture.event_cases.length === 8, 'candidate rotation case counts');
};

const verifyOnDiskFixtures = () => {
  const rotation = readJson('spec/fixtures/candidate/rotation-vectors.json');
  const nonce = readJson('spec/fixtures/candidate/nonce-vectors.json');
  const state = readJson('spec/fixtures/candidate/rotation-state-vectors.json');
  verifyRotationFixture(rotation);
  verifyNonceFixture(nonce);
  verifyRotationState(state);
  const clock = initialClockGuard({ binding: endpoint, window: 30, highWater: 173800, revision: 4 });
  const oldCutoff = advanceAndCheckClock(clock, 173799);
  check(!oldCutoff.ok && oldCutoff.error === 'rotation_clock_unsafe' && oldCutoff.guard.unsafe && oldCutoff.guard.highWater === 173800, 'ClockGuard rollback latch');
  const duplicate = advanceAndCheckClock(clock, 173800);
  check(duplicate.ok && duplicate.writes === 0 && duplicate.callbacks === 0, 'ClockGuard duplicate sample');
  const advance = advanceAndCheckClock(clock, 173801);
  check(advance.ok && advance.guard.highWater === 173801 && advance.guard.revision === 5, 'ClockGuard H/revision advance');
  const trust = { binding: endpoint, revision: 2, head: { ordinal: 0, hash: '-' } };
  const cas = trustClockCAS({ expectedTrust: trust, desiredTrust: { ...trust, revision: 3 }, expectedClock: clock, actualClock: advance.guard });
  check(cas.callbacks === 1 && !cas.committed && cas.error === 'rotation_state_changed' && cas.trust.revision === 2, 'ClockGuard tuple CAS conflict');
  const caseCounts = { codec: rotation.malformed.length, nonce: nonce.cases.length, rotationClient: state.client_cases.length, rotationEvents: state.event_cases.length, rotationState: state.client_cases.length + state.event_cases.length };
  check(caseCounts.codec === 19 && caseCounts.nonce === 24 && caseCounts.rotationClient === 14 && caseCounts.rotationEvents === 8, 'candidate source case counts');
  return caseCounts;
};

export { verifyOnDiskFixtures };
