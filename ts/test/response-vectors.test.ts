/** Response vector runner mirroring the client-side VerifyResponse order, ported from Go's client/verify_test.go TestVerifyResponseVectors. */
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { formatResponseAuth, parseResponseAuth } from "../src/auth-header.js";
import type { ResponseAuth } from "../src/auth-header.js";
import { BadBase64UrlError, decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { verify } from "../src/ed25519.js";
import { Code, JackError } from "../src/errors.js";
import { responseSigningString } from "../src/signing.js";
import { loadKeys, loadResponseVectors } from "./fixtures.js";
import type { HeaderPair, ResponseCase, TestKey } from "./fixtures.js";

const encoder = new TextEncoder();

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
 * The client-side runner, in the exact VerifyResponse order. Throws a
 * JackError with the case's expected code on reject, completes on accept.
 */
function verifyResponseCase(c: ResponseCase): { parsed: ResponseAuth; values: readonly string[] } {
  const values = jackAuthValues(c.response.headers);
  const state = c.state;
  // Step 1: header grammar. A parse failure carries its own code.
  const parsed = parseResponseAuth(values);
  // Step 2: the response must be signed by the pinned server key.
  if (parsed.kid !== state.pinnedServerKid) {
    throw new JackError(0, Code.UNKNOWN_SERVER_KEY, "response signed by an unpinned key");
  }
  // Step 3: timestamp within the acceptance window.
  if (Math.abs(state.now - parsed.ts) > state.windowSeconds) {
    throw new JackError(0, Code.TIMESTAMP_OUT_OF_WINDOW, "response timestamp outside the acceptance window");
  }
  // Step 4: strict 64-byte sig decode. The parser already enforces a
  // canonical 64-byte sig, so any BadBase64UrlError here can only be a
  // signature mismatch, not a malformed header (mirrors Go's comment).
  let sig: Uint8Array;
  try {
    sig = decodeBase64URLFixed(parsed.sig, 64);
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      throw new JackError(0, Code.BAD_SIGNATURE, "malformed response signature");
    }
    throw err;
  }
  // Step 5: verify over the recomputed response signing string.
  const body = decodeBase64URL(c.response.bodyB64u);
  const msg = responseSigningString(c.response.status, state.requestSig, parsed.kid, parsed.ts, body);
  const pin = decodeBase64URLFixed(state.pinnedServerPublicKey, 32);
  if (!verify(pin, encoder.encode(msg), sig)) {
    throw new JackError(0, Code.BAD_SIGNATURE, "response signature does not verify");
  }
  return { parsed, values };
}

test("response vectors: every case", () => {
  const byKid = keysByKid();
  for (const c of loadResponseVectors().cases) {
    let result: { parsed: ResponseAuth; values: readonly string[] } | undefined;
    let err: unknown;
    try {
      result = verifyResponseCase(c);
    } catch (caught) {
      err = caught;
    }
    if (c.expect.result === "accept") {
      assert.equal(err, undefined, `case ${c.id}: unexpected error ${String(err)}`);
      assert.ok(result !== undefined, `case ${c.id}: no result`);
      const { parsed, values } = result;
      // Round trip through the canonical formatter.
      assert.equal(formatResponseAuth(parsed), values[0], `case ${c.id}: FormatResponseAuth round trip`);
      // Deterministic Ed25519: re-signing from the pinned key's seed
      // reproduces the header sig string.
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
  }
});
