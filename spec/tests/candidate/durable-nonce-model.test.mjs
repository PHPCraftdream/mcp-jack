import test from 'node:test';
import assert from 'node:assert/strict';
import { NONCE_EVENTS } from '../../tools/candidate/scenario-data.mjs';
import { initialNonceState, reserveNonce, reconcileNonceRestart } from '../../tools/candidate/durable-nonce-model.mjs';

test('hand-stated durable nonce cases execute status, callback, persistence, and effects oracles', () => {
  for (const item of NONCE_EVENTS.filter((row) => !row.sequence)) {
    const result = reserveNonce(item.state, item.event);
    assert.deepEqual([result.response.status, result.response.code, result.callbacks, result.writes, result.dispatches], [item.expect.status, item.expect.code, item.expect.callbacks, item.expect.writes, item.expect.dispatches], item.id);
    assert.deepEqual([result.state.highWater, result.state.live.length, result.state.intents.length, result.state.tombstones.length, result.state.fenced], [item.expect.highWater, item.expect.liveCount, item.expect.intentCount, item.expect.tombstoneCount, item.expect.fenced], item.id);
    assert.deepEqual(result.effects, item.expect.effects, item.id);
    if (item.expect.preserveLive) assert.deepEqual(result.state.live, item.state.live, `${item.id}: live rows`);
    if (item.expect.preserveTombstones) assert.deepEqual(result.state.tombstones, item.state.tombstones, `${item.id}: tombstones`);
    if (item.expect.tombstoneOutcome) assert.ok(result.state.tombstones.some((row) => row.outcome === item.expect.tombstoneOutcome), item.id);
    if (item.expect.reconciliation) assert.equal(result.reconciliation, item.expect.reconciliation, item.id);
  }
});

test('serialized two-arrival model records exactly one committed winner, not process concurrency evidence', () => {
  for (const item of NONCE_EVENTS.filter((row) => row.sequence)) {
    let state = initialNonceState();
    const results = item.sequence.map((event) => {
      const result = reserveNonce(state, event);
      state = result.state;
      return result;
    });
    assert.deepEqual(results.map((row) => [row.response.status, row.response.code]), item.expect.statuses, item.id);
    assert.deepEqual(results.map((row) => row.callbacks), item.expect.callbacks, item.id);
    assert.deepEqual(results.map((row) => row.writes), item.expect.writes, item.id);
    assert.deepEqual(results.map((row) => row.dispatches), item.expect.dispatches, item.id);
    assert.equal(results.filter((result) => result.disposition === 'committed_dispatched').length, item.expect.confirmedCommits, item.id);
    assert.equal(state.live.length, item.expect.liveCount, item.id);
    assert.deepEqual(state.effects, item.expect.effects, item.id);
  }
});

test('changing authentication or expiry boundary changes executed nonce behavior', () => {
  const invalid = NONCE_EVENTS.find((row) => row.id === 'bad-signature-zero-writes');
  const rejected = reserveNonce(invalid.state, invalid.event);
  assert.deepEqual([rejected.callbacks, rejected.writes, rejected.dispatches], [0, 0, 0]);
  const counterfactual = reserveNonce(invalid.state, { ...invalid.event, authenticated: true, dispatch: true });
  assert.notDeepEqual([counterfactual.callbacks, counterfactual.writes, counterfactual.dispatches], [0, 0, 0]);
  const expiry = NONCE_EVENTS.find((row) => row.id === 'expiry-equality');
  assert.equal(reserveNonce(expiry.state, expiry.event).response.code, 'replayed_nonce');
  assert.notEqual(reserveNonce(expiry.state, { ...expiry.event, ts: 131, entryNow: 131, intentNow: 131, finalNow: 131 }).response.code, 'replayed_nonce');
});

test('unknown exact intent never gains retry permission from absent state', () => {
  const row = NONCE_EVENTS.find((item) => item.id === 'unknown-intent-absent');
  const committed = reserveNonce(row.state, row.event);
  const restarted = reconcileNonceRestart(committed.state, { operation: 'candidate-test-deployment:kid-alice:nonce-unknown-intent:identity-alice', reservationPresent: false, intentPresent: false });
  assert.equal(restarted.admission, false);
  assert.equal(restarted.redeliver, false);
  assert.equal(restarted.state.fenced, true);
});
