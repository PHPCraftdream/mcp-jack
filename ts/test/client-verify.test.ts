/** verifyResponse tests, ported from Go client/verify_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyResponse } from "../src/client/auth.js";
import { JackError } from "../src/errors.js";
import { decodeBase64URL, decodeBase64URLFixed } from "../src/encoding.js";
import { loadResponseVectors } from "./fixtures.js";
import type { HeaderPair } from "./fixtures.js";

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

test("response vectors: every case executed", () => {
  const cases = loadResponseVectors().cases;
  let executed = 0;
  for (const c of cases) {
    const pin = decodeBase64URLFixed(c.state.pinnedServerPublicKey, 32);
    const values = jackAuthValues(c.response.headers);
    const body = decodeBase64URL(c.response.bodyB64u);
    let err: unknown;
    try {
      verifyResponse(pin, c.response.status, values, c.state.requestSig, body, c.state.now, c.state.windowSeconds);
    } catch (caught) {
      err = caught;
    }
    if (c.expect.result === "accept") {
      assert.equal(err, undefined, `case ${c.id}: got error ${String(err)}, want accept`);
    } else {
      assert.ok(err instanceof JackError, `case ${c.id}: got error ${String(err)}, not a JackError`);
      assert.equal(err.code, c.expect.code, `case ${c.id}: code`);
    }
    executed++;
  }
  assert.ok(executed > 0, "no response cases executed");
});

test("default window at the +30/+31 boundary", () => {
  // res-accept's response ts equals state.now = 1767225600, so with the default
  // window (windowSeconds 0 -> DEFAULT_WINDOW_SECONDS = 30): |30| <= 30 accepts,
  // |31| > 30 rejects.
  const tc = loadResponseVectors().cases.find((c) => c.id === "res-accept");
  assert.ok(tc !== undefined, "res-accept case not found");
  const pin = decodeBase64URLFixed(tc.state.pinnedServerPublicKey, 32);
  const values = jackAuthValues(tc.response.headers);
  const body = decodeBase64URL(tc.response.bodyB64u);

  let late: unknown;
  try {
    verifyResponse(pin, tc.response.status, values, tc.state.requestSig, body, tc.state.now + 30, 0);
  } catch (err) {
    late = err;
  }
  assert.equal(late, undefined, "window <= 0 at +30s boundary: got error, want accept");

  let tooLate: unknown;
  try {
    verifyResponse(pin, tc.response.status, values, tc.state.requestSig, body, tc.state.now + 31, 0);
  } catch (err) {
    tooLate = err;
  }
  assert.ok(tooLate instanceof JackError, "window <= 0 at +31s: got no error, want JackError");
  assert.equal(tooLate.code, "timestamp_out_of_window", "window <= 0 at +31s: code");
});
