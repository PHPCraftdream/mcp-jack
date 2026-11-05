/**
 * Response vector runner: every case is executed through the public client-side
 * verifyResponse (ts/src/client/auth.ts), the client-side mirror of spec 01
 * section 5. The old locally-duplicated verification steps are gone; every
 * reject case must still throw a JackError with httpStatus 0. Ported from Go's
 * client/verify_test.go TestVerifyResponseVectors.
 */
import assert from "node:assert/strict";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { formatResponseAuth, parseResponseAuth } from "../src/auth-header.js";
import type { ResponseAuth } from "../src/auth-header.js";
import { decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { JackError } from "../src/errors.js";
import { responseSigningString } from "../src/signing.js";
import { verifyResponse } from "../src/client/auth.js";
import { loadKeys, loadResponseVectors } from "./fixtures.js";
import type { HeaderPair, ResponseCase, TestKey } from "./fixtures.js";

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

/** Ed25519 private key from a keys.json entry, via node:crypto PKCS8 DER. */
function privateKeyFor(key: TestKey): KeyObject {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.from(key.seedHex, "hex")]), format: "der", type: "pkcs8" });
}

/** Map from kid to keys.json entry. */
function keysByKid(): Map<string, TestKey> {
  const map = new Map<string, TestKey>();
  for (const key of loadKeys().keys) {
    map.set(key.kid, key);
  }
  return map;
}

/**
 * Runs one response case through the public verifyResponse. Throws a JackError
 * with the case's expected code on reject (httpStatus 0), completes on accept.
 */
function verifyResponseCase(c: ResponseCase): ResponseAuth {
  const values = jackAuthValues(c.response.headers);
  const pin = decodeBase64URLFixed(c.state.pinnedServerPublicKey, 32);
  const body = decodeBase64URL(c.response.bodyB64u);
  verifyResponse(pin, c.response.status, values, c.state.requestSig, body, c.state.now, c.state.windowSeconds);
  return parseResponseAuth(values);
}

test("response vectors: every case", () => {
  const byKid = keysByKid();
  for (const c of loadResponseVectors().cases) {
    let parsed: ResponseAuth | undefined;
    let err: unknown;
    try {
      parsed = verifyResponseCase(c);
    } catch (caught) {
      err = caught;
    }
    if (c.expect.result === "accept") {
      assert.equal(err, undefined, `case ${c.id}: unexpected error ${String(err)}`);
      assert.ok(parsed !== undefined, `case ${c.id}: no result`);
      const values = jackAuthValues(c.response.headers);
      const first = values[0];
      assert.ok(first !== undefined, `case ${c.id}: no Jack-Auth value`);
      // Round trip through the canonical formatter.
      assert.equal(formatResponseAuth(parsed), first, `case ${c.id}: FormatResponseAuth round trip`);
      // Deterministic Ed25519: re-signing from the pinned key's seed reproduces the header sig string.
      const key = byKid.get(c.state.pinnedServerKid);
      assert.ok(key !== undefined, `case ${c.id}: no test key for kid ${c.state.pinnedServerKid}`);
      const priv = privateKeyFor(key);
      const body = decodeBase64URL(c.response.bodyB64u);
      const msg = responseSigningString(c.response.status, c.state.requestSig, parsed.kid, parsed.ts, body);
      const resigned = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), priv)));
      assert.equal(resigned, parsed.sig, `case ${c.id}: re-signed sig`);
      continue;
    }
    assert.ok(err instanceof JackError, `case ${c.id}: expected JackError, got ${String(err)}`);
    assert.equal(err.code, c.expect.code, `case ${c.id}: code`);
    // The client-side mirror of spec 01 section 5: client-side failures never carry an HTTP status.
    assert.equal(err.httpStatus, 0, `case ${c.id}: httpStatus`);
  }
});
