/** Tests for the Jack-Auth header grammar, ported from Go's TestAuthHeaderGrammarUnit plus extensions. */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatRequestAuth,
  formatResponseAuth,
  parseRequestAuth,
  parseResponseAuth,
} from "../src/auth-header.js";
import { Code, JackError } from "../src/errors.js";
import { encodeBase64URL } from "../src/encoding.js";
import { loadRequestVectors } from "./fixtures.js";

/** A well-formed request header value built from canonical base64url parts. */
function wellFormed(): { v: string; kid: string; nonce: string; sig: string } {
  const kid = encodeBase64URL(new Uint8Array(32).fill(1));
  const nonce = encodeBase64URL(new Uint8Array(16).fill(2));
  const sig = encodeBase64URL(new Uint8Array(64).fill(3));
  const v = formatRequestAuth({ kid, ts: 1, nonce, sig });
  return { v, kid, nonce, sig };
}

/** Asserts fn throws a JackError with exactly the given code and HTTP status 401. */
function assertAuthError(fn: () => unknown, wantCode: string, what: string): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof JackError, `${what}: expected JackError, got ${String(err)}`);
    assert.equal(err.code, wantCode, `${what}: code`);
    assert.equal(err.httpStatus, 401, `${what}: httpStatus`);
    return true;
  }, what);
}

test("grammar rejections", () => {
  const { v, kid } = wellFormed();
  assertAuthError(() => parseRequestAuth([]), Code.MISSING_AUTH, "missing");
  assertAuthError(() => parseRequestAuth([v, v]), Code.MALFORMED_AUTH, "duplicate");
  assertAuthError(() => parseRequestAuth([v.replace("v1", "v2")]), Code.UNSUPPORTED_VERSION, "v2");
  assertAuthError(() => parseRequestAuth([v.replace("v1", "V1")]), Code.MALFORMED_AUTH, "V1");
  // Extensions over the Go unit table:
  assertAuthError(() => parseRequestAuth([v.replace("v1", "v10")]), Code.UNSUPPORTED_VERSION, "v10");
  assertAuthError(() => parseRequestAuth([`${v},extra=1`]), Code.MALFORMED_AUTH, "unknown param");
  assertAuthError(() => parseRequestAuth([`${v},kid=${kid}`]), Code.MALFORMED_AUTH, "repeated param");
  assertAuthError(() => parseRequestAuth([v.replace(`kid=${kid}`, `kid=${kid.slice(0, 42)}`)]), Code.MALFORMED_AUTH, "42-char kid");
  assertAuthError(() => parseRequestAuth([v.replace("ts=1,", "ts=01,")]), Code.MALFORMED_AUTH, "ts=01");
  assertAuthError(() => parseRequestAuth([v.replace("ts=1,", "ts=1234567890123,")]), Code.MALFORMED_AUTH, "13-digit ts");
  assertAuthError(() => parseRequestAuth([v.replace("ts=1,", "ts=+1,")]), Code.MALFORMED_AUTH, "ts=+1");
  assertAuthError(() => parseRequestAuth([`${v.slice(0, v.indexOf("sig="))}sig=${encodeBase64URL(new Uint8Array(64).fill(3)).slice(0, 85)}`]), Code.MALFORMED_AUTH, "85-char sig");
  assertAuthError(() => parseRequestAuth(["v1 "]), Code.MALFORMED_AUTH, "bare scheme");
  // The request-shaped value has a nonce, which is unknown for responses.
  assertAuthError(() => parseResponseAuth([v]), Code.MALFORMED_AUTH, "response parser rejects request header");
});

test("request header round trip", () => {
  const { v, kid, nonce, sig } = wellFormed();
  const parsed = parseRequestAuth([v]);
  assert.deepEqual(parsed, { kid, ts: 1, nonce, sig });
  assert.equal(formatRequestAuth(parsed), v);
});

test("response header round trip", () => {
  const kid = encodeBase64URL(new Uint8Array(32).fill(4));
  const sig = encodeBase64URL(new Uint8Array(64).fill(5));
  const v = formatResponseAuth({ kid, ts: 7, sig });
  const parsed = parseResponseAuth([v]);
  assert.deepEqual(parsed, { kid, ts: 7, sig });
  assert.equal(formatResponseAuth(parsed), v);
});

test("every request-vectors accept header parses and formats back identically", () => {
  const vectors = loadRequestVectors();
  let checked = 0;
  for (const c of vectors.cases) {
    const values = c.request.headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
    let parsed: ReturnType<typeof parseRequestAuth> | undefined;
    try {
      parsed = parseRequestAuth(values);
    } catch (err) {
      if (c.expect.result === "accept") {
        throw new Error(`case ${c.id}: ParseRequestAuth failed on an accept case: ${String(err)}`);
      }
      continue;
    }
    if (c.expect.result === "accept" && values.length === 1) {
      assert.ok(parsed !== undefined, `case ${c.id}: parsed auth is undefined`);
      assert.equal(formatRequestAuth(parsed), values[0], `case ${c.id}: round trip`);
      checked++;
    }
  }
  assert.ok(checked > 0, "expected at least one accept case with a single header");
});
