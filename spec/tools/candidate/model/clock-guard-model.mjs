export const initialClockGuard = ({ binding = 'candidate-test-binding', window = 30, highWater = 0, revision = 0, unsafe = false } = {}) => ({ binding, window, highWater, revision, unsafe });

export const advanceAndCheckClock = (input, rawNow, { latchOutcome = 'confirmed' } = {}) => {
  const guard = structuredClone(input);
  if (guard.unsafe) return { ok: false, error: 'rotation_clock_unsafe', writes: 0, callbacks: 0, guard };
  if (!Number.isSafeInteger(rawNow) || rawNow < 0 || rawNow > 999999999999) {
    if (latchOutcome !== 'confirmed') return { ok: false, error: 'rotation_clock_unavailable', writes: 1, callbacks: 1, guard };
    guard.unsafe = true;
    guard.revision += 1;
    return { ok: false, error: 'rotation_clock_unsafe', writes: 1, callbacks: 1, guard, durableFence: true };
  }
  if (rawNow < guard.highWater) {
    if (latchOutcome !== 'confirmed') return { ok: false, error: 'rotation_clock_unavailable', writes: 1, callbacks: 1, guard };
    guard.unsafe = true;
    guard.revision += 1;
    return { ok: false, error: 'rotation_clock_unsafe', writes: 1, callbacks: 1, guard, durableFence: true };
  }
  if (rawNow === guard.highWater) return { ok: true, now: rawNow, writes: 0, callbacks: 0, guard };
  if (latchOutcome !== 'confirmed') return { ok: false, error: 'rotation_clock_unavailable', writes: 1, callbacks: 1, guard };
  guard.highWater = rawNow;
  guard.revision += 1;
  return { ok: true, now: rawNow, writes: 1, callbacks: 1, guard };
};

export const compareTrustClockTuple = (expected, actual) => expected.binding === actual.binding
  && expected.window === actual.window
  && expected.highWater === actual.highWater
  && expected.revision === actual.revision
  && expected.unsafe === actual.unsafe;

export const trustClockCAS = ({ expectedTrust, desiredTrust, expectedClock, actualClock, callbackOutcome = 'ack' }) => {
  if (!compareTrustClockTuple(expectedClock, actualClock)) return { callbacks: 1, committed: false, error: 'rotation_state_changed', trust: structuredClone(expectedTrust), clock: structuredClone(actualClock) };
  if (callbackOutcome === 'unknown') return { callbacks: 1, committed: false, error: 'rotation_state_unknown', trust: structuredClone(expectedTrust), clock: structuredClone(actualClock), fenced: true };
  if (callbackOutcome !== 'ack') return { callbacks: 1, committed: false, error: 'rotation_state_changed', trust: structuredClone(expectedTrust), clock: structuredClone(actualClock) };
  return { callbacks: 1, committed: true, error: null, trust: structuredClone(desiredTrust), clock: structuredClone(actualClock) };
};
