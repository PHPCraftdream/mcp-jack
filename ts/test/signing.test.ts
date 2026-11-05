/** Tests for signing-string construction: spec line order and fixture oracles. */
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { parseRequestAuth, parseResponseAuth } from "../src/auth-header.js";
import { bodyHash, decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { verify } from "../src/ed25519.js";
import { requestSigningString, responseSigningString, rotateProofString } from "../src/signing.js";
import { loadKeys, loadRequestVectors, loadResponseVectors } from "./fixtures.js";
import type { HeaderPair, TestKey } from "./fixtures.js";

const encoder = new TextEncoder();

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

/** Deterministic Ed25519 signature of message under priv. */
function signBytes(priv: KeyObject, message: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(message), priv));
}

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

test("requestSigningString matches the spec line order exactly", () => {
  const body = encoder.encode("hello");
  const kid = encodeBase64URL(new Uint8Array(32).fill(1));
  const nonce = encodeBase64URL(new Uint8Array(16).fill(2));
  const got = requestSigningString("POST", "/tools/list", "aud", kid, 1700000000, nonce, body);
  // The oracle is the spec line order, not a hash.
  const want = [
    "mcp-jack/v1/request",
    "POST",
    "/tools/list",
    "aud",
    kid,
    String(1700000000),
    nonce,
    bodyHash(body),
  ].join("\n");
  assert.equal(got, want);
  assert.equal(got.endsWith("\n"), false, "no trailing LF");
  assert.equal(got.split("\n").length, 8);
});

test("responseSigningString matches the spec line order exactly", () => {
  const body = encoder.encode("resp");
  const kid = encodeBase64URL(new Uint8Array(32).fill(1));
  const requestSig = encodeBase64URL(new Uint8Array(64).fill(3));
  const got = responseSigningString(200, requestSig, kid, 1700000001, body);
  const want = [
    "mcp-jack/v1/response",
    String(200),
    requestSig,
    kid,
    String(1700000001),
    bodyHash(body),
  ].join("\n");
  assert.equal(got, want);
  assert.equal(got.endsWith("\n"), false, "no trailing LF");
  assert.equal(got.split("\n").length, 6);
});

test("rotateProofString matches the spec line order exactly", () => {
  const got = rotateProofString("aud", "old-kid", "new-kid", 1700000002);
  const want = ["mcp-jack/v1/rotate", "aud", "old-kid", "new-kid", String(1700000002)].join("\n");
  assert.equal(got, want);
  assert.equal(got.endsWith("\n"), false, "no trailing LF");
  assert.equal(got.split("\n").length, 5);
});

test("every accept request case reproduces debug.signingStringLines", () => {
  for (const c of loadRequestVectors().cases) {
    if (c.expect.result !== "accept") {
      continue;
    }
    const parsed = parseRequestAuth(jackAuthValues(c.request.headers));
    const body = decodeBase64URL(c.request.bodyB64u);
    const got = requestSigningString(c.request.method, c.request.target, c.state.aud, parsed.kid, parsed.ts, parsed.nonce, body);
    assert.equal(got, c.debug.signingStringLines.join("\n"), `case ${c.id}: signing string`);
  }
});

test("every accept request case re-signs byte-identically from keys.json", () => {
  const byKid = new Map<string, TestKey>();
  for (const key of loadKeys().keys) {
    byKid.set(key.kid, key);
  }
  let checked = 0;
  for (const c of loadRequestVectors().cases) {
    if (c.expect.result !== "accept") {
      continue;
    }
    const parsed = parseRequestAuth(jackAuthValues(c.request.headers));
    const key = byKid.get(parsed.kid);
    assert.ok(key !== undefined, `case ${c.id}: no test key for kid ${parsed.kid}`);
    const priv = privateKeyFor(key);
    const pub = publicKeyOf(priv);
    const body = decodeBase64URL(c.request.bodyB64u);
    const msg = requestSigningString(c.request.method, c.request.target, c.state.aud, parsed.kid, parsed.ts, parsed.nonce, body);
    const resigned = encodeBase64URL(signBytes(priv, encoder.encode(msg)));
    assert.equal(resigned, parsed.sig, `case ${c.id}: re-signed sig`);
    assert.equal(verify(pub, encoder.encode(msg), decodeBase64URLFixed(parsed.sig, 64)), true, `case ${c.id}: verify`);
    checked++;
  }
  assert.ok(checked > 0, "expected at least one accept case");
});

test("every accept response case recomputes a message that verifies", () => {
  for (const c of loadResponseVectors().cases) {
    if (c.expect.result !== "accept") {
      continue;
    }
    const parsed = parseResponseAuth(jackAuthValues(c.response.headers));
    assert.equal(parsed.kid, c.state.pinnedServerKid, `case ${c.id}: kid`);
    const body = decodeBase64URL(c.response.bodyB64u);
    const msg = responseSigningString(c.response.status, c.state.requestSig, parsed.kid, parsed.ts, body);
    const pin = decodeBase64URLFixed(c.state.pinnedServerPublicKey, 32);
    const sig = decodeBase64URLFixed(parsed.sig, 64);
    assert.equal(verify(pin, encoder.encode(msg), sig), true, `case ${c.id}: signature`);
  }
});
