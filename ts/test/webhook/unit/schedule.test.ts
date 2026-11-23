import assert from "node:assert/strict";
import { test } from "node:test";
import { lastErrorOf, retrySchedule, senderDecision } from "../../../src/webhook/receiver/core.js";

const FIRST_ATTEMPT = { attempt: 1, t0: 1000, responseTime: 1000 };
const SERVER_ERRORS = Array.from({ length: 100 }, (_, index) => 500 + index);

test("retrySchedule has four increasing slots within 900 seconds", () => {
  for (const t0 of [0, 1767225600, 2 ** 31]) {
    const slots = retrySchedule(t0);
    assert.equal(slots.length, 4);
    assert.deepEqual(slots.map((at) => at - t0), [0, 30, 270, 870]);
    assert.ok(slots.every((at, index) => index === 0 || at > (slots[index - 1] ?? Infinity)));
    const last = slots[3] ?? Infinity;
    assert.equal(last, t0 + 870);
    assert.ok(last <= t0 + 900);
  }
});

test("senderDecision classifies HTTP outcomes and preserves the error category", () => {
  const statuses = [200, 201, 202, 203, 204, 300, 301, 400, 404, 410, 413, 425, 429, ...SERVER_ERRORS];
  for (const status of statuses) {
    const actual = senderDecision({ ...FIRST_ATTEMPT, status });
    const label = `HTTP ${status}`;
    if (status >= 200 && status < 300) {
      assert.deepEqual(actual, { action: "accept" }, label);
    } else if (status === 425 || status === 429 || status >= 500) {
      const lastError = status >= 500 ? "http_5xx" : "http_4xx";
      assert.deepEqual(actual, { action: "retry", nextAt: 1030, lastError }, label);
    } else {
      assert.deepEqual(actual, { action: "final", lastError: "http_4xx" }, label);
    }
  }
});

test("retryable HTTP statuses still retry on attempt three but stop on attempt four", () => {
  for (const status of [425, 429, ...SERVER_ERRORS]) {
    const lastError = status >= 500 ? "http_5xx" : "http_4xx";
    assert.deepEqual(
      senderDecision({ ...FIRST_ATTEMPT, attempt: 3, status, responseTime: 1270 }),
      { action: "retry", nextAt: 1870, lastError },
      `HTTP ${status}, attempt 3`,
    );
    assert.deepEqual(
      senderDecision({ ...FIRST_ATTEMPT, attempt: 4, status, responseTime: 1870 }),
      { action: "final", lastError },
      `HTTP ${status}, attempt 4`,
    );
  }
});

test("Retry-After postpones a retry without advancing it or exceeding the cap", () => {
  // The API takes seconds; pass a date through the type boundary to exercise its runtime guard.
  const httpDate = "Thu, 01 Jan 1970 00:18:40 GMT" as unknown as number;
  const cases = [[120, 1120], [1000, 1900], [5, 1030], [120.5, 1030], [httpDate, 1030]] as const;
  for (const [retryAfter, nextAt] of cases) {
    assert.deepEqual(
      senderDecision({ ...FIRST_ATTEMPT, status: 503, retryAfter }),
      { action: "retry", nextAt, lastError: "http_5xx" },
      `Retry-After ${retryAfter}`,
    );
  }
});

test("transport failures preserve their category until the final attempt", () => {
  for (const transport of ["timeout", "tls_error", "connection_refused", "http_4xx"]) {
    assert.deepEqual(
      senderDecision({ ...FIRST_ATTEMPT, transport }),
      { action: "retry", nextAt: 1030, lastError: transport },
    );
    assert.deepEqual(
      senderDecision({ ...FIRST_ATTEMPT, attempt: 4, responseTime: 1870, transport }),
      { action: "final", lastError: transport },
    );
  }
});

test("lastErrorOf covers each HTTP status range and ignores out-of-range values", () => {
  for (let status = 200; status < 300; status++) assert.equal(lastErrorOf(status), null, `HTTP ${status}`);
  for (let status = 300; status < 500; status++) assert.equal(lastErrorOf(status), "http_4xx", `HTTP ${status}`);
  for (const status of SERVER_ERRORS) assert.equal(lastErrorOf(status), "http_5xx", `HTTP ${status}`);
  for (const status of [0, 199, 600]) assert.equal(lastErrorOf(status), null, `HTTP ${status}`);
});
