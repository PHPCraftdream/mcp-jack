/** Profile save/load tests, ported from Go client/profile_test.go. The alice key is used for
 * validity instead of Go's random ed25519.GenerateKey: deterministic and fixture-derived. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { keyId, encodeBase64URL } from "../src/encoding.js";
import { Code, JackError } from "../src/errors.js";
import { Client, clientFromProfile, loadProfile, profileServerKeyBytes, profileToJSON, saveProfile } from "../src/client/index.js";
import type { Profile } from "../src/client/index.js";
import { seedSignerByName } from "./client-harness.js";

/** Whether the two byte strings are identical. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

const pub = seedSignerByName("alice").publicKey();

/** newValidTestProfile returns a valid profile over the alice public key. */
function newValidTestProfile(): Profile {
  return {
    url: "https://svc.example.test/mcp",
    aud: "https://svc.example.test",
    serverPublicKey: encodeBase64URL(pub),
    kid: keyId(pub),
    name: "alice-laptop",
  };
}

/** The compact wire document of a valid profile, the string-surgery base for the rejection table. */
function newValidProfileDoc(): string {
  return JSON.stringify(profileToJSON(newValidTestProfile()));
}

test("profile round trip", () => {
  const p = newValidTestProfile();
  const saved = saveProfile(p);
  assert.ok(saved.endsWith("\n"), "saveProfile output does not end with newline");
  const loaded = loadProfile(saved);
  assert.equal(JSON.stringify(profileToJSON(loaded)), JSON.stringify(profileToJSON(p)), "round trip mismatch");
  assert.equal(bytesEqual(profileServerKeyBytes(loaded), pub), true, "server key bytes mismatch");
});

test("profile JSON has no private key material", () => {
  const saved = saveProfile(newValidTestProfile());
  assert.equal(saved.includes("private"), false, "profile JSON contains 'private'");
  assert.equal(saved.includes("seed"), false, "profile JSON contains 'seed'");
});

test("loadProfile rejects invalid documents", () => {
  const shortKey = encodeBase64URL(new Uint8Array(16)); // 22 chars decoding to 16 bytes: fixed-length decode rejects
  const alicePubB64 = encodeBase64URL(pub);
  const aliceKid = keyId(pub);
  const doc = newValidProfileDoc();
  const cases: readonly { readonly name: string; readonly doc: string; readonly why: string }[] = [
    { name: "unknown field", doc: doc.replace(/}$/, ',"extra":1}'), why: "unknown keys are rejected (Go DisallowUnknownFields)" },
    { name: "server key wrong length", doc: doc.replace(alicePubB64, shortKey), why: "decodeBase64URLFixed(_, 32) rejects 16 decoded bytes" },
    { name: "padded server key", doc: doc.replace(alicePubB64, alicePubB64 + "="), why: "the strict decoder rejects padding" },
    { name: "kid not 32-byte base64url", doc: doc.replace(`"kid":"${aliceKid}"`, '"kid":"short"'), why: "decodeBase64URLFixed('short', 32) rejects" },
    // WHATWG new URL("https://") throws: after the "//" of a special scheme an
    // empty authority at end-of-input is a parse failure.
    { name: "url missing host", doc: doc.replace('"url":"https://svc.example.test/mcp"', '"url":"https://"'), why: "new URL throws (empty authority for a special scheme)" },
    // WHATWG would normalize "https:///mcp" to https://mcp/ (host "mcp");
    // Go rejects the empty authority, so the raw-text check rejects it.
    { name: "url empty authority", doc: doc.replace('"url":"https://svc.example.test/mcp"', '"url":"https:///mcp"'), why: 'the raw-text authority check mirrors Go\'s Host == ""' },
    { name: "url without scheme", doc: doc.replace('"url":"https://svc.example.test/mcp"', '"url":"mcp"'), why: "new URL throws (no scheme)" },
    { name: "url wrong scheme", doc: doc.replace('"url":"https://svc.example.test/mcp"', '"url":"ftp://host/mcp"'), why: "the raw-text check only accepts http/https" },
    { name: "aud empty", doc: doc.replace('"aud":"https://svc.example.test"', '"aud":""'), why: "aud must be non-empty" },
    { name: "kid wrong type", doc: doc.replace(`"kid":"${aliceKid}"`, '"kid":123'), why: "a present non-string kid is a decode error (Go typed decode)" },
    { name: "name wrong type", doc: doc.replace('"name":"alice-laptop"', '"name":{}'), why: "a present non-string name is a decode error (Go typed decode)" },
    { name: "trailing data", doc: doc + " {}", why: "JSON.parse rejects trailing non-whitespace, covering Go's io.EOF check" },
  ];
  for (const tc of cases) {
    assert.throws(() => loadProfile(tc.doc), () => true, `case ${tc.name}: accepted invalid document (${tc.why})`);
  }
});

test("clientFromProfile", () => {
  const c = clientFromProfile(newValidTestProfile(), seedSignerByName("alice"));
  assert.ok(c instanceof Client, "clientFromProfile did not return a Client");
  assert.throws(
    () =>
      clientFromProfile(
        {
          url: "https://svc.example.test/mcp",
          aud: "https://svc.example.test",
          serverPublicKey: encodeBase64URL(new Uint8Array(16)),
        },
        seedSignerByName("alice"),
      ),
    () => true,
    "expected error for invalid server public key",
  );
});

test("client-side server-key rejection carries no HTTP status", () => {
  // The identity-point encoding decodes to exactly 32 bytes and fails the
  // spec 03 section 2 key rules: the local admission is key_rejected with
  // httpStatus 0 — the shared validator's wire 400 must not leak into the
  // client error (httpStatus 0 = never an HTTP response, per JackError).
  const identity = new Uint8Array(32);
  identity[0] = 1;
  const signer = seedSignerByName("alice");
  const badProfile: Profile = { ...newValidTestProfile(), serverPublicKey: encodeBase64URL(identity) };
  const badDoc = JSON.stringify(profileToJSON(badProfile));
  const cases: readonly (() => unknown)[] = [
    () => loadProfile(badDoc),
    () => clientFromProfile(badProfile, signer),
    () => new Client({ baseUrl: badProfile.url, aud: badProfile.aud, signer, serverKey: identity }),
  ];
  for (const run of cases) {
    assert.throws(
      run,
      (err: unknown) => err instanceof JackError && err.code === Code.KEY_REJECTED && err.httpStatus === 0,
      "expected JackError key_rejected with httpStatus 0",
    );
  }
});
