import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { client, Code, encodeBase64URL, formatResponseAuth, JackError, parseRequestAuth, responseSigningString, rotation } from "../src/index.js";

function signer(label: string): client.InMemorySigner {
  return new client.InMemorySigner(createHash("sha256").update(`mcp-jack public carrier fixture ${label}`).digest());
}
function header(key: client.Signer, requestSig: string, ts: number, body: Uint8Array): string[] {
  const message = responseSigningString(200, requestSig, key.kid(), ts, body);
  return [formatResponseAuth({ kid: key.kid(), ts, sig: encodeBase64URL(key.sign(Buffer.from(message))) })];
}
function denied(code: string): (error: unknown) => boolean {
  return (error) => (error instanceof JackError || error instanceof rotation.RotationError) && error.code === code;
}

test("known carrier: unknown key precedes stale/bad signature and body inspection", () => {
  const key = signer("known");
  const other = signer("unknown");
  const user = signer("user");
  const request = client.signRequest(user, "public-aud", "POST", "/mcp", new Uint8Array(), new Uint8Array(16), 100);
  // Response binds the actual request signature, не request ID или response body guess.
  const signature = parseRequestAuth([request]).sig;
  const known = new Map<string, client.RotationResponseKey>([[key.kid(), { publicKeyB64u: encodeBase64URL(key.publicKey()), notBefore: 0, knownCutoff: 110 }]]);
  const body = Buffer.from("{not-json");
  const info = client.verifyRotationCarrier(known, 200, header(key, signature, 109, body), signature, body, 109, 30);
  assert.deepEqual(info, { kid: key.kid(), timestamp: 109 });
  assert.ok(Object.isFrozen(info));
  const unknown = [formatResponseAuth({ kid: other.kid(), ts: 0, sig: encodeBase64URL(new Uint8Array(64)) })];
  assert.throws(() => client.verifyRotationCarrier(known, 200, unknown, signature, body, 1000, 30), denied(Code.UNKNOWN_SERVER_KEY));
  const staleBad = [formatResponseAuth({ kid: key.kid(), ts: 0, sig: encodeBase64URL(new Uint8Array(64)) })];
  assert.throws(() => client.verifyRotationCarrier(known, 200, staleBad, signature, body, 1000, 30), denied(Code.TIMESTAMP_OUT_OF_WINDOW));
  const freshBad = [formatResponseAuth({ kid: key.kid(), ts: 109, sig: encodeBase64URL(new Uint8Array(64)) })];
  assert.throws(() => client.verifyRotationCarrier(known, 200, freshBad, signature, body, 109, 30), denied(Code.BAD_SIGNATURE));
  assert.throws(() => client.verifyRotationCarrier(known, 200, header(key, signature, 109, body), signature, Buffer.from("changed"), 109, 30), denied(Code.BAD_SIGNATURE));
});

test("known carrier: lower bound inclusive, known cutoff strict in signed and supplied time", () => {
  const key = signer("interval");
  const known = new Map<string, client.RotationResponseKey>([[key.kid(), { publicKeyB64u: encodeBase64URL(key.publicKey()), notBefore: 100, knownCutoff: 110 }]]);
  const body = Buffer.from("public response bytes");
  const requestSig = "request-signature";
  const verify = (ts: number, now: number) => client.verifyRotationCarrier(known, 200, header(key, requestSig, ts, body), requestSig, body, now, 30);
  assert.equal(verify(100, 100).timestamp, 100);
  assert.equal(verify(100, 99).timestamp, 100);
  assert.throws(() => verify(99, 100), denied("rotation_key_interval"));
  assert.throws(() => verify(109, 110), denied("rotation_key_interval"));
  assert.throws(() => verify(110, 109), denied("rotation_key_interval"));
  known.set(key.kid(), { publicKeyB64u: encodeBase64URL(key.publicKey()), notBefore: 110, knownCutoff: 110 });
  assert.throws(() => verify(110, 110), denied("rotation_key_interval"));
  for (const invalid of [NaN, Infinity, -1, 0.5]) assert.throws(() => verify(110, invalid), denied("rotation_clock_unavailable"));
});

test("known carrier: invalid local window/key snapshot fails closed without changing static verifier", () => {
  const key = signer("configuration");
  const body = Buffer.from("public body");
  const requestSig = "request-signature";
  const values = header(key, requestSig, 100, body);
  const known = new Map<string, client.RotationResponseKey>([[key.kid(), { publicKeyB64u: encodeBase64URL(key.publicKey()), notBefore: 0 }]]);
  for (const window of [0, 0.5, 121, NaN]) assert.throws(() => client.verifyRotationCarrier(known, 200, values, requestSig, body, 100, window), denied("rotation_state_unknown"));
  known.set(key.kid(), { publicKeyB64u: "bad", notBefore: 0 });
  assert.throws(() => client.verifyRotationCarrier(known, 200, values, requestSig, body, 100, 30), denied("rotation_state_unknown"));
  assert.doesNotThrow(() => client.verifyResponse(key.publicKey(), 200, values, requestSig, body, 100, 30));
});
