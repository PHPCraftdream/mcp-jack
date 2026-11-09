/** signRequest tests against the request vectors, ported from Go client/sign_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRequestAuth } from "../src/auth-header.js";
import type { RequestAuth } from "../src/auth-header.js";
import { verify } from "../src/ed25519.js";
import { decodeBase64URL, decodeBase64URLFixed } from "../src/encoding.js";
import { requestSigningString } from "../src/signing.js";
import { signRequest } from "../src/client/auth.js";
import type { InMemorySigner } from "../src/client/signer.js";
import { seedSignerByKid } from "./client-harness.js";
import { loadKeys, loadRequestVectors } from "./fixtures.js";
import type { HeaderPair, RequestCase, TestKey } from "./fixtures.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Jack-Auth values from fixture headers (header names are case-insensitive). */
function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "jack-auth").map((h) => h.value);
}

/** Map from kid to keys.json entry. */
function keysByKid(): Map<string, TestKey> {
  const map = new Map<string, TestKey>();
  for (const key of loadKeys().keys) {
    map.set(key.kid, key);
  }
  return map;
}

/** One fixture accept case that is fully reproducible: parseable header, known kid, decodable nonce/body. */
interface MatchedCase {
  tc: RequestCase;
  auth: RequestAuth;
  signer: InMemorySigner;
  body: Uint8Array;
  nonce: Uint8Array;
  headerValue: string;
}

/** matchedAcceptCases returns the accept cases whose header, kid, nonce and body are all derivable. */
function matchedAcceptCases(): MatchedCase[] {
  const keys = keysByKid();
  const matched: MatchedCase[] = [];
  for (const tc of loadRequestVectors().cases) {
    if (tc.expect.result !== "accept") {
      continue;
    }
    const values = jackAuthValues(tc.request.headers);
    if (values.length === 0) {
      continue; // no Jack-Auth header to reproduce
    }
    // A throw here fails the test: accept-case headers must parse.
    const auth = parseRequestAuth(values);
    if (!keys.has(auth.kid)) {
      continue; // kid not derivable from keys.json
    }
    // Throws fail the test: accept-case nonce/body must decode.
    const nonce = decodeBase64URLFixed(auth.nonce, 16);
    const body = decodeBase64URL(tc.request.bodyB64u);
    const headerValue = values[0];
    assert.ok(headerValue !== undefined, `case ${tc.id}: empty Jack-Auth values`);
    matched.push({ tc, auth, signer: seedSignerByKid(auth.kid), body, nonce, headerValue });
  }
  return matched;
}

test("signRequest reproduces every derivable accept fixture header", () => {
  const matched = matchedAcceptCases();
  // Pinned derivation: request-vectors.json carries 23 accept cases (the 17
  // accept-* cases + admin-gate-admin-accept + whoami-nonadmin and whoami-admin
  // + the duplicate-member accepts dup-method-tools-call-first-invalid,
  // dup-tool-name-first-deny-last-allow and dup-jsonrpc-first-wrong-last-
  // right); every one has a canonical header, a keys.json kid and decodable
  // nonce/body, so the matcher must not hide any of them. The duplicate-
  // member accepts re-sign the exact duplicate-bearing bytes: a signer that
  // re-serializes the body fails here (spec 02 section 4, README D13).
  assert.equal(matched.length, 23, "the matcher must derive every accept case");
  assert.ok(matched.length > 0, "no derivable accept cases matched");
  for (const m of matched) {
    // The clock is the header's own ts (auth.ts), not tc.state.now.
    const header = signRequest(m.signer, m.tc.state.aud, m.tc.request.method, m.tc.request.target, m.body, m.nonce, m.auth.ts);
    assert.equal(header, m.headerValue, `case ${m.tc.id}: header mismatch`);
  }
});

test("signing string matches fixture debug lines", () => {
  const matched = matchedAcceptCases();
  assert.ok(matched.length > 0, "no derivable accept cases checked");
  for (const m of matched) {
    const got = requestSigningString(m.tc.request.method, m.tc.request.target, m.tc.state.aud, m.auth.kid, m.auth.ts, m.auth.nonce, m.body);
    assert.equal(got, m.tc.debug.signingStringLines.join("\n"), `case ${m.tc.id}: signing string mismatch`);
  }
});

test("fixture signatures verify over the recomputed signing string", () => {
  const matched = matchedAcceptCases();
  for (const m of matched) {
    const str = requestSigningString(m.tc.request.method, m.tc.request.target, m.tc.state.aud, m.auth.kid, m.auth.ts, m.auth.nonce, m.body);
    const sigBytes = decodeBase64URLFixed(m.auth.sig, 64);
    assert.equal(verify(m.signer.publicKey(), utf8(str), sigBytes), true, `case ${m.tc.id}: fixture sig does not verify over recomputed string`);
  }
});

test("tampering one body byte changes the header", () => {
  const matched = matchedAcceptCases();
  assert.ok(matched.length > 0, "no derivable accept cases");
  const m = matched[0];
  assert.ok(m !== undefined && m.body.length > 0, `case ${m?.tc.id ?? "??"}: empty body, tamper case skipped`);
  const body2 = new Uint8Array(m.body);
  body2[body2.length - 1] = (body2[body2.length - 1] ?? 0) ^ 0x01;
  const header = signRequest(m.signer, m.tc.state.aud, m.tc.request.method, m.tc.request.target, m.body, m.nonce, m.auth.ts);
  const header2 = signRequest(m.signer, m.tc.state.aud, m.tc.request.method, m.tc.request.target, body2, m.nonce, m.auth.ts);
  assert.notEqual(header2, header, `case ${m.tc.id}: tampered body produced identical header`);
});

test("derivable reject cases reproduce exactly when their fixture signature is valid", () => {
  // Go's TestSignRequestTamperDetection demands the first derivable reject case NOT reproduce; against the pinned
  // fixtures that fails — "unknown-key" carries a valid mallory signature (gen-fixtures.mjs line "valid signature
  // from a key not in the registry"), state.now equals its header ts, so signRequest reproduces it byte for byte
  // and its signature verifies; its rejection is registry-level (spec 01 section 4 step 4), which a client cannot
  // and must not encode into its bytes. The honest invariant is the biconditional asserted here.
  const keys = keysByKid();
  let found = 0;
  for (const tc of loadRequestVectors().cases) {
    if (tc.expect.result !== "reject") {
      continue;
    }
    const values = jackAuthValues(tc.request.headers);
    if (values.length === 0) {
      continue;
    }
    let auth: RequestAuth;
    try {
      auth = parseRequestAuth(values);
    } catch {
      continue; // header itself is the rejection; nothing to derive
    }
    if (!keys.has(auth.kid)) {
      continue;
    }
    let nonce: Uint8Array;
    let body: Uint8Array;
    let sigBytes: Uint8Array;
    try {
      nonce = decodeBase64URLFixed(auth.nonce, 16);
      body = decodeBase64URL(tc.request.bodyB64u);
      sigBytes = decodeBase64URLFixed(auth.sig, 64);
    } catch {
      continue;
    }
    const signer = seedSignerByKid(auth.kid);
    const headerValue = values[0];
    assert.ok(headerValue !== undefined, `case ${tc.id}: empty Jack-Auth values`);
    const header = signRequest(signer, tc.state.aud, tc.request.method, tc.request.target, body, nonce, auth.ts);
    const str = requestSigningString(tc.request.method, tc.request.target, tc.state.aud, auth.kid, auth.ts, auth.nonce, body);
    const sigOk = verify(signer.publicKey(), utf8(str), sigBytes);
    assert.equal(header === headerValue, sigOk, `case ${tc.id}: a reject case's bytes reproduce exactly when its signature is valid`);
    found++;
  }
  assert.ok(found > 0, "no derivable reject case found");
});
