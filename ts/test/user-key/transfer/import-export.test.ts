import assert from "node:assert/strict";
import { test } from "node:test";
import { IssuedUserKeyCredential, exportUserKeyPublicEnvelope, importClientUserKeyCredential, importClientUserKeyPrivateEnvelope, importServerUserKeyPublicEnvelope, importUserKeyPublicEnvelope, issueUserKeyCredential, validateUserKeyCredentialForServer, type ExpectedServerIdentity } from "../../../src/user-key/transfer.js";
import { ClientUserKey, ServerUserKey, generateClientUserKey } from "../../../src/user-key/key.js";
import { Client } from "../../../src/client/rpc.js";
import { fixtureNow, newTestServer, queuedNonce, rpcResultBody } from "../../support/client-harness.js";
import { formatResponseAuth, parseRequestAuth } from "../../../src/core/auth-header.js";
import { responseSigningString } from "../../../src/core/signing.js";
import { InMemorySigner, type Signer } from "../../../src/client/signing/signer.js";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { verify } from "../../../src/core/ed25519.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { rawBytes } from "../../support/fixtures/index.js";
import { must, utf8, sameBytes, canonEq, fx, keys, keyByName, alice, bob, svc, pos, neg, posEnvelope, negCase, pubAliceBytes, credAliceBytes, svcTuple, rejectVectorBytes, buildPublicEnvelope, buildPrivateEnvelope, composeCredential, expectClass, counterRandom, composedWrongServer } from "./support.js";

test("fixture table shape: 66 shared cases (14 positives, 51 negatives, 1 context case)", () => {
  assert.equal(fx.schema, "user-key-transfer-fixtures/1");
  assert.equal(fx.positives.length, 14, "positives count");
  assert.equal(fx.negatives.length, 51, "negatives count");
  assert.equal(fx.contextCases.length, 1, "context cases count");
  assert.equal(fx.positives.length + fx.negatives.length + fx.contextCases.length, 66, "total shared cases");
  // The trusted tuple's kid is independently pinned before any test relies on it.
  assert.equal(svc.kid, keyId(decodeBase64URLFixed(svc.publicKey, 32)), "svc kid equals keyId(decoded server_public_key)");
  // keys.json is the independent seed/public/kid oracle for the pinned trio.
  for (const key of [alice, bob, must(keyByName.get("carol"), "keys.json carol")]) {
    const seed = new Uint8Array(Buffer.from(key.seedHex, "hex"));
    assert.equal(encodeBase64URL(seed).length, 43, `${key.name}: seed encodes to 43 chars`);
  }
});

test("row 1: client generate + exportPublic reproduces the exact pub-alice/pub-bob/pub-carol fixture bytes", () => {
  const pinned: ReadonlyArray<[string, string, string]> = [
    ["alice", "pub-alice", alice.publicKey],
    ["bob", "pub-bob", bob.publicKey],
    ["carol", "pub-carol", must(keyByName.get("carol"), "carol").publicKey],
  ];
  for (const [name, posId, pinnedPub] of pinned) {
    const signer = new ClientUserKey(new Uint8Array(Buffer.from(must(keyByName.get(name), name).seedHex, "hex")));
    const exported = exportUserKeyPublicEnvelope(signer);
    assert.ok(canonEq(exported, rawBytes(posEnvelope(posId))), `${posId}: exported bytes equal fixture string bytes`);
    assert.equal(signer.kid(), keyId(signer.publicKey()), `${name}: kid equals keyId(pub)`);
    assert.equal(signer.kid(), must(keyByName.get(name), name).kid, `${name}: kid equals keys.json kid`);
    // x independently pinned to keys.json public_key, never just self-consistent.
    assert.equal(encodeBase64URL(signer.publicKey()), pinnedPub, `${name}: x equals keys.json public_key`);
  }

  // Row 1 also exercises a GENERATED ordinary client key: export and public
  // import round-trip the same kid/pub32, and the canonical template
  // recomposes the generated document (boolean-safe comparison).
  const generated = generateClientUserKey();
  const exportedGenerated = exportUserKeyPublicEnvelope(generated);
  const admittedGenerated = importUserKeyPublicEnvelope(exportedGenerated);
  assert.equal(admittedGenerated.kid, generated.kid(), "generated kid round-trips through the public envelope");
  assert.ok(canonEq(admittedGenerated.pub32, generated.publicKey()), "generated pub32 round-trips through the public envelope");
  assert.ok(
    new TextDecoder().decode(exportedGenerated) ===
      new TextDecoder().decode(utf8(buildPublicEnvelope(admittedGenerated.kid, encodeBase64URL(admittedGenerated.pub32)))),
    "generated document recomposes from the canonical template",
  );
});

test("row 2: importPrivateEnvelope of all pinned priv documents matches oracles and signs deterministically", () => {
  const privCases: ReadonlyArray<[string, string]> = [
    ["priv-alice", "alice"],
    ["priv-bob", "bob"],
    ["priv-carol", "carol"],
  ];
  let tamperChecked = false;
  for (const [posId, keyName] of privCases) {
    const envelopeStr = posEnvelope(posId);
    const signer = importClientUserKeyPrivateEnvelope(rawBytes(envelopeStr));
    const parsed = JSON.parse(envelopeStr) as { readonly d: string; readonly x: string; readonly kid: string };
    const oracle = must(keyByName.get(keyName), keyName);
    // CI obligation: decoded d raw bytes equal keys.json seed_hex bytes (boolean compare).
    assert.ok(sameBytes(decodeBase64URLFixed(parsed.d, 32), new Uint8Array(Buffer.from(oracle.seedHex, "hex"))), `${posId}: d equals seed_hex bytes`);
    // x and kid independently pinned to keys.json AND to the kid formula.
    assert.equal(parsed.x, oracle.publicKey, `${posId}: x equals keys.json public_key`);
    assert.equal(parsed.kid, oracle.kid, `${posId}: kid equals keys.json kid`);
    assert.equal(parsed.kid, keyId(decodeBase64URLFixed(parsed.x, 32)), `${posId}: kid equals keyId(decoded x)`);
    assert.ok(canonEq(signer.publicKey(), decodeBase64URLFixed(parsed.x, 32)), `${posId}: imported pub matches oracle`);
    assert.equal(signer.kid(), parsed.kid, `${posId}: imported kid matches oracle`);
    // deterministic signature equals InMemorySigner bytes and verifies under the pinned public.
    const msg = utf8(`${posId} fixed message`);
    const sig = signer.sign(msg);
    assert.equal(sig.length, 64, `${posId}: signature length`);
    assert.ok(canonEq(sig, new InMemorySigner(new Uint8Array(Buffer.from(oracle.seedHex, "hex"))).sign(msg)), `${posId}: signature equals InMemorySigner bytes`);
    assert.equal(verify(decodeBase64URLFixed(oracle.publicKey, 32), msg, sig), true, `${posId}: signature verifies under pinned public`);
    if (keyName === "alice") {
      // Signature controls: the verify() oracle must actually discriminate.
      const flippedMsg = new Uint8Array(msg);
      flippedMsg[0] = (flippedMsg[0] ?? 0) ^ 0xff;
      assert.equal(verify(decodeBase64URLFixed(oracle.publicKey, 32), flippedMsg, sig), false, "flipped message byte fails verification");
      const flippedSig = new Uint8Array(sig);
      flippedSig[0] = (flippedSig[0] ?? 0) ^ 0xff;
      assert.equal(verify(decodeBase64URLFixed(oracle.publicKey, 32), msg, flippedSig), false, "flipped signature byte fails verification");
      assert.equal(verify(decodeBase64URLFixed(bob.publicKey, 32), msg, sig), false, "bob's pinned public key fails verification");
      assert.equal(verify(decodeBase64URLFixed(oracle.publicKey, 32), msg, sig.subarray(0, 63)), false, "truncated 63-byte signature fails verification without throwing");
    }
    // canonical template recompose reproduces the fixture bytes exactly
    // (boolean-safe: neither operand is passed as an assertion actual).
    const recomposed = buildPrivateEnvelope(parsed.d, parsed.kid, parsed.x);
    assert.ok(recomposed === envelopeStr, `${posId}: canonical recompose`);
    if (!tamperChecked) {
      tamperChecked = true;
      expectClass(
        () => importClientUserKeyPrivateEnvelope(rawBytes(must(negCase("neg-seed-pub-mismatch").envelope, "tamper doc"))),
        "seed_pub_mismatch",
        "tampered private envelope",
      );
    }
  }
});

test("row 2: priv-rfc8032-test1 composed from RFC 8032 7.1 TEST 1 / RFC 8037 A.1 hex", () => {
  // The hex spellings come FROM THE FIXTURE compose fields, not from literals here.
  const compose = must(pos.get("priv-rfc8032-test1"), "priv-rfc8032-test1").compose;
  const seedHex = must(compose?.["seed_b64u_of_hex"], "priv-rfc8032-test1 compose.seed_b64u_of_hex") as string;
  const pubHex = must(compose?.["public_key_b64u_of_hex"], "priv-rfc8032-test1 compose.public_key_b64u_of_hex") as string;
  assert.ok(seedHex.length === 64, "fixture seed spelling is 64 hex characters");
  assert.ok(pubHex.length === 64, "fixture public spelling is 64 hex characters");
  const seed = new Uint8Array(Buffer.from(seedHex, "hex"));
  const pub = new Uint8Array(Buffer.from(pubHex, "hex"));
  // The runner's own base64url encodings MUST equal the RFC strings
  // (boolean-safe: the seed encoding is never an assertion actual).
  assert.ok(encodeBase64URL(seed) === "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", "RFC 8037 A.1 d string");
  assert.ok(encodeBase64URL(pub) === "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "RFC 8037 A.1 x string");
  const kid = keyId(pub);
  const doc = utf8(buildPrivateEnvelope(encodeBase64URL(seed), kid, encodeBase64URL(pub)));
  const signer = importClientUserKeyPrivateEnvelope(doc);
  assert.ok(canonEq(signer.publicKey(), pub), "imported public equals RFC pinned public");
  assert.equal(signer.kid(), kid, "kid computed with keyId");
  const msg = utf8("RFC 8032 section 7.1 TEST 1 message");
  const sig = signer.sign(msg);
  assert.ok(canonEq(sig, new InMemorySigner(seed).sign(msg)), "signature equals InMemorySigner output");
  // Independent oracle: verify under the RFC pinned public key bytes.
  assert.equal(verify(pub, msg, sig), true, "signature verifies under RFC pinned public");
});

test("positives: structural self-consistency on the mapped sink with pinned x/kid", () => {
  let credentialCount = 0;
  for (const p of fx.positives) {
    if (p.kind === "public_envelope" && p.envelope !== undefined) {
      const imported = importUserKeyPublicEnvelope(rawBytes(p.envelope));
      assert.equal(imported.kid, must(p.expectKid, p.id), `${p.id}: kid`);
      assert.ok(canonEq(imported.pub32, decodeBase64URLFixed(must(p.expectX, p.id), 32)), `${p.id}: pub32`);
      assert.equal(
        new TextDecoder().decode(utf8(buildPublicEnvelope(imported.kid, encodeBase64URL(imported.pub32)))),
        p.envelope,
        `${p.id}: canonical recompose equals fixture string`,
      );
    } else if (p.kind === "private_envelope") {
      continue; // covered by the row 2 tests (incl. the composed RFC case)
    } else if (p.kind === "client_credential" && p.envelope !== undefined) {
      credentialCount += 1;
      // Per-fixture INDEPENDENTLY chosen expected tuple: the pinned aud comes
      // from the fixture when present (cred-aud-html-sensitive), else the
      // trusted tuple's aud.
      const expectedAud = p.expectAud !== undefined ? p.expectAud : svcTuple.aud;
      const expected: ExpectedServerIdentity = {
        url: svcTuple.url,
        aud: expectedAud,
        server_public_key: svcTuple.server_public_key,
        server_kid: svcTuple.server_kid,
      };
      const { signer, connection } = importClientUserKeyCredential(rawBytes(p.envelope), expected);
      const parsed = JSON.parse(p.envelope) as { readonly client_key: string; readonly aud: string };
      // Embedded client_key equals the exact referenced private envelope string
      // (boolean-safe: the secret-bearing strings are never assertion actuals).
      const innerRef = p.id === "cred-bob" ? posEnvelope("priv-bob") : posEnvelope("priv-alice");
      assert.ok(parsed.client_key === innerRef, `${p.id}: embedded client_key exact envelope string`);
      assert.equal(signer.kid(), must(p.expectClientKid, p.id), `${p.id}: client kid`);
      assert.equal(connection.server_kid, must(p.expectServerKid, p.id), `${p.id}: server kid`);
      assert.ok(connection.aud === expectedAud, `${p.id}: decoded aud equals the independently chosen expected aud`);
      assert.equal(connection.url, svcTuple.url, `${p.id}: url`);
      assert.ok(sameBytes(connection.serverKey, decodeBase64URLFixed(svc.publicKey, 32)), `${p.id}: serverKey bytes`);
    }
  }
  assert.equal(credentialCount, 3, "literal credential positives (cred-alice, cred-bob, cred-aud-html-sensitive)");

  // Context case cred-wrong-server: structural acceptance proven by importing
  // against the embedded identity, trust evaluated separately against svc.
  const ctx = must(fx.contextCases[0], "context case");
  assert.equal(ctx.id, "cred-wrong-server");
  assert.equal(ctx.structuralOutcome, "accepted_by_import_pipeline");
  assert.equal(ctx.trustOutcome, "server_identity_mismatch");
  const embeddedTuple: ExpectedServerIdentity = {
    url: "https://svc.example.test",
    aud: "https://svc.example.test",
    server_public_key: alice.publicKey,
    server_kid: alice.kid,
  };
  const accepted = importClientUserKeyCredential(composedWrongServer(), embeddedTuple);
  assert.equal(accepted.signer.kid(), alice.kid, "cred-wrong-server structural import yields alice's key");
  expectClass(() => importClientUserKeyCredential(composedWrongServer(), svcTuple), "server_identity_mismatch", "cred-wrong-server trust");
  expectClass(() => validateUserKeyCredentialForServer(composedWrongServer(), svcTuple), "server_identity_mismatch", "cred-wrong-server server validator");
});

test("row 3: issuance is byte-deterministic with a fixed random source and has no secret surface", () => {
  const first = counterRandom();
  const issued = issueUserKeyCredential(svcTuple, first.source);
  const credential = issued.exportCredential();
  // Independent recomposition of the credential from the same seed.
  const seed = first.last();
  const derived = new ClientUserKey(seed);
  const inner = buildPrivateEnvelope(encodeBase64URL(seed), derived.kid(), encodeBase64URL(derived.publicKey()));
  const expected = composeCredential(svcTuple.aud, inner, svc.kid, svc.publicKey, svcTuple.url);
  assert.ok(canonEq(credential, expected), "credential bytes equal the composed template for same inputs");
  // Twice identical.
  const second = counterRandom();
  const issuedAgain = issueUserKeyCredential(svcTuple, second.source);
  assert.ok(canonEq(issuedAgain.exportCredential(), credential), "issuing twice with the same random gives identical bytes");

  // Prototype exposes exactly exportCredential/publicIdentity/toString; no Sign/seed/kid accessor.
  const members = Object.getOwnPropertyNames(IssuedUserKeyCredential.prototype)
    .filter((m) => m !== "constructor")
    .sort();
  assert.deepEqual(members, ["exportCredential", "publicIdentity", "toString"], "prototype member surface");
  const probe = issued as unknown as Record<string, unknown>;
  for (const forbidden of ["sign", "Sign", "seed", "exportSeed", "kid", "credential"]) {
    assert.equal(typeof probe[forbidden], "undefined", `no ${forbidden} accessor on issuance result`);
  }

  // Oversized aud config and invalid tuple config throw matching classes.
  expectClass(() => issueUserKeyCredential({ ...svcTuple, aud: "a".repeat(4200) }, first.source), "oversized_envelope", "oversized aud config");
  expectClass(() => issueUserKeyCredential({ ...svcTuple, server_kid: alice.kid }, first.source), "kid_mismatch", "kid-mismatched config");
  expectClass(
    () => issueUserKeyCredential({ ...svcTuple, server_public_key: encodeBase64URL(rejectVectorBytes("reject-identity")) }, first.source),
    "invalid_public_key",
    "invalid server public key config",
  );
  expectClass(() => issueUserKeyCredential({ ...svcTuple, url: "http://svc.example.test" }, first.source), "bad_url", "bad url config");
});

test("row 3/8: exportCredential returns fresh equal copies; mutating the ORIGINAL buffer leaves everything else unchanged", () => {
  const { source } = counterRandom();
  const issued = issueUserKeyCredential(svcTuple, source);
  const original = issued.exportCredential();
  // The oracle is an independent copy of the ORIGINAL bytes, NEVER mutated.
  const oracle = new Uint8Array(original);
  // Snapshot identity bytes AND hand a signer from a copy of the ORIGINAL
  // bytes BEFORE any mutation.
  const identitySnapshot = new Uint8Array(issued.publicIdentity().publicKey());
  const handed = importClientUserKeyCredential(new Uint8Array(original), svcTuple);
  const msg = utf8("mutation isolation probe");
  const sigBefore = new Uint8Array(handed.signer.sign(msg));
  // Take the second copy BEFORE any mutation.
  const secondCopy = issued.exportCredential();
  assert.ok(secondCopy !== original, "copies are independent instances");
  // FULLY mutate the original buffer (complete fill, not one byte).
  original.fill(0xff);
  // The pre-mutation copy is unchanged BEFORE the next accessor runs.
  assert.ok(canonEq(secondCopy, oracle), "the pre-mutation copy is unchanged by mutating the original buffer");
  const thirdCopy = issued.exportCredential();
  assert.ok(canonEq(thirdCopy, oracle), "a post-mutation copy still equals the oracle");
  assert.ok(canonEq(issued.publicIdentity().publicKey(), identitySnapshot), "publicIdentity unchanged after the original buffer was mutated");
  assert.ok(canonEq(handed.signer.sign(msg), sigBefore), "the imported signer still signs unchanged");
  assert.ok(canonEq(issued.exportCredential(), oracle), "exportCredential still equals the oracle after mutation");
});

test("row 4: issued credential hands off to a working client signer and its public identity admits publicly", () => {
  const { source } = counterRandom();
  const issued = issueUserKeyCredential(svcTuple, source);
  const credential = issued.exportCredential();
  const handed = importClientUserKeyCredential(credential, svcTuple);
  const msg = utf8("handoff message");
  const sig = handed.signer.sign(msg);
  assert.equal(verify(handed.signer.publicKey(), msg, sig), true, "handed-off signer signs and verifies");
  const identity = issued.publicIdentity();
  const admitted = importServerUserKeyPublicEnvelope(
    utf8(buildPublicEnvelope(keyId(identity.publicKey()), encodeBase64URL(identity.publicKey()))),
  );
  // ServerUserKey exposes ONLY kid(): string and publicKey(): Uint8Array.
  assert.equal(admitted.kid(), identity.kid(), "public identity admits through the public-only path");
  assert.ok(canonEq(admitted.publicKey(), identity.publicKey()), "admitted public bytes match");
});

/**
 * Structural Signer assignment is proven by row 4's handoff; THIS roundtrip is
 * the compatibility proof: the imported credential signer drives a real,
 * existing-client signed call through the existing harness transport (no
 * network, no harness or source changes), and the server answers under the
 * credential's pinned server identity.
 */
test("row 4 compatibility: real existing-client signed roundtrip over the harness transport with the imported signer", async () => {
  // The svc private key from keys.json, built via the fixed PKCS8 DER prefix.
  const svcPriv = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(svc.seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
  const server = newTestServer();
  const { signer: handedSigner, connection } = importClientUserKeyCredential(credAliceBytes, svcTuple);
  const client = new Client({
    baseUrl: connection.url,
    aud: connection.aud,
    signer: handedSigner,
    serverKey: connection.serverKey,
    fetchImpl: server.fetch,
    clock: () => fixtureNow,
    windowSeconds: 30,
    nonceSource: queuedNonce([encodeBase64URL(new Uint8Array(16).fill(0xab))]),
  });
  // The exact response body is built ONCE: the response-signing bytes, the
  // status 200, the request signature echo (auth.sig) and the returned bytes
  // all refer to this single buffer.
  const responseBody = rpcResultBody('{"ok":true}');
  server.handle = (auth, body) => {
    const msg = utf8(responseSigningString(200, auth.sig, svc.kid, fixtureNow, responseBody));
    const sig = new Uint8Array(nodeSign(null, Buffer.from(msg), svcPriv));
    return new Response(responseBody, {
      status: 200,
      headers: { "content-type": "application/json", "jack-auth": formatResponseAuth({ kid: svc.kid, ts: fixtureNow, sig: encodeBase64URL(sig) }) },
    });
  };
  const res = await client.callTool("anything");
  assert.deepEqual(res, { ok: true });
  // Prove the request really used the imported signer.
  const last = server.lastRequest;
  assert.ok(last !== null, "the harness recorded the request");
  assert.ok(last.header !== null, "the request carried a Jack-Auth header");
  const parsedAuth = parseRequestAuth([last.header]);
  assert.equal(parsedAuth.kid, handedSigner.kid(), "the request was signed by the imported credential signer");
});

test("row 5: importPublic yields pub/kid only; no sign method and no secret capability exist", () => {
  const imported = importUserKeyPublicEnvelope(pubAliceBytes);
  assert.equal(imported.kid, must(must(pos.get("pub-alice"), "pub-alice").expectKid, "pub-alice kid"));
  assert.ok(canonEq(imported.pub32, decodeBase64URLFixed(must(must(pos.get("pub-alice"), "pub-alice").expectX, "pub-alice x"), 32)));
  const surface = Object.keys(imported).sort();
  assert.deepEqual(surface, ["kid", "pub32"], "method/data surface is exactly pub32 and kid");
  const probe = imported as unknown as Record<string, unknown>;
  for (const forbidden of ["sign", "exportSeed", "seed", "d"]) {
    assert.equal(typeof probe[forbidden], "undefined", `public identity has no ${forbidden} capability`);
  }
});
