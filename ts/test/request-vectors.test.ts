/** Request vector runner: header parsing, accept-case re-signing and the strict S >= L fixture, ported from Go's header_test.go. */
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { formatRequestAuth, parseRequestAuth } from "../src/auth-header.js";
import { decodeBase64URL, decodeBase64URLFixed, encodeBase64URL, keyId } from "../src/encoding.js";
import { validatePublicKey, verify } from "../src/ed25519.js";
import { Code, JackError } from "../src/errors.js";
import { requestSigningString } from "../src/signing.js";
import { loadKeys, loadRequestVectors } from "./fixtures.js";
import type { HeaderPair, RequestCase, TestKey } from "./fixtures.js";

const encoder = new TextEncoder();

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

/** True for codes the header parser itself can produce. */
function isParseCode(code: string | undefined): boolean {
  return code === Code.MISSING_AUTH || code === Code.MALFORMED_AUTH || code === Code.UNSUPPORTED_VERSION;
}

/** Ed25519 private key from a keys.json entry, via node:crypto PKCS8 DER. */
function privateKeyFor(key: TestKey): KeyObject {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.from(key.seedHex, "hex")]), format: "der", type: "pkcs8" });
}

/** Raw 32-byte Ed25519 public key of priv. */
function publicKeyOf(priv: KeyObject): Uint8Array {
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(12));
}

/** Map from kid to keys.json entry. */
function keysByKid(): Map<string, TestKey> {
  const map = new Map<string, TestKey>();
  for (const key of loadKeys().keys) {
    map.set(key.kid, key);
  }
  return map;
}

test("request header parsing: every case", () => {
  for (const c of loadRequestVectors().cases) {
    const values = jackAuthValues(c.request.headers);
    let parsed: ReturnType<typeof parseRequestAuth> | undefined;
    let parseErr: unknown;
    try {
      parsed = parseRequestAuth(values);
    } catch (err) {
      parseErr = err;
    }
    if (c.expect.result === "reject" && isParseCode(c.expect.code)) {
      assert.ok(parseErr instanceof JackError, `case ${c.id}: expected JackError, got ${String(parseErr)}`);
      assert.equal(parseErr.code, c.expect.code, `case ${c.id}: code`);
      assert.equal(parseErr.httpStatus, 401, `case ${c.id}: httpStatus`);
      continue;
    }
    assert.equal(parseErr, undefined, `case ${c.id}: unexpected parse error`);
    assert.ok(parsed !== undefined, `case ${c.id}: parsed auth is undefined`);
  }
});

test("request accept cases: signing string, key, verify, re-sign and format round trip", () => {
  const byKid = keysByKid();
  for (const c of loadRequestVectors().cases) {
    if (c.expect.result !== "accept") {
      continue;
    }
    const values = jackAuthValues(c.request.headers);
    const a = parseRequestAuth(values);
    const key = byKid.get(a.kid);
    assert.ok(key !== undefined, `case ${c.id}: no test key for kid ${a.kid}`);
    const priv = privateKeyFor(key);
    const pub = publicKeyOf(priv);
    assert.equal(validatePublicKey(pub), null, `case ${c.id}: ValidatePublicKey`);
    assert.equal(keyId(pub), a.kid, `case ${c.id}: KeyID`);
    const sig = decodeBase64URLFixed(a.sig, 64);
    const body = decodeBase64URL(c.request.bodyB64u);
    const msg = requestSigningString(c.request.method, c.request.target, c.state.aud, a.kid, a.ts, a.nonce, body);
    assert.equal(msg, c.debug.signingStringLines.join("\n"), `case ${c.id}: signing string`);
    assert.equal(verify(pub, encoder.encode(msg), sig), true, `case ${c.id}: Verify`);
    // Deterministic Ed25519: re-signing from the seed reproduces the header sig.
    const resigned = new Uint8Array(nodeSign(null, Buffer.from(msg), priv));
    assert.equal(encodeBase64URL(resigned), a.sig, `case ${c.id}: re-signed sig`);
    assert.equal(formatRequestAuth(a), values[0], `case ${c.id}: FormatRequestAuth round trip`);
  }
});

test("sig-noncanonical-s: parse succeeds but verify rejects the non-canonical S", () => {
  const cases = loadRequestVectors().cases;
  const found = cases.filter((c: RequestCase) => c.id === "sig-noncanonical-s");
  assert.ok(found.length > 0, "case sig-noncanonical-s not found in request vectors");
  const byKid = keysByKid();
  for (const c of found) {
    const a = parseRequestAuth(jackAuthValues(c.request.headers));
    const key = byKid.get(a.kid);
    assert.ok(key !== undefined, `case ${c.id}: no test key for kid ${a.kid}`);
    const pub = publicKeyOf(privateKeyFor(key));
    const sig = decodeBase64URLFixed(a.sig, 64);
    const body = decodeBase64URL(c.request.bodyB64u);
    const msg = requestSigningString(c.request.method, c.request.target, c.state.aud, a.kid, a.ts, a.nonce, body);
    assert.equal(verify(pub, encoder.encode(msg), sig), false, `case ${c.id}: Verify accepted a non-canonical (S >= L) signature`);
  }
});
