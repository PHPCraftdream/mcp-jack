import assert from "node:assert/strict";
import { test } from "node:test";
import { IssuedUserKeyCredential, exportUserKeyPublicEnvelope, importClientUserKeyCredential, importClientUserKeyPrivateEnvelope, importServerUserKeyPublicEnvelope, importUserKeyPublicEnvelope, issueUserKeyCredential, validateUserKeyCredentialForServer, type ExpectedServerIdentity } from "../../../src/user-key/transfer.js";
import { ClientUserKey, ServerUserKey } from "../../../src/user-key/key.js";


import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { rawBytes } from "../../support/fixtures/index.js";
import { must, utf8, sameBytes, canonEq, bytesInclude, fx, keys, alice, bob, svc, neg, posEnvelope, negCase, pubAliceBytes, privAliceBytes, privAliceStr, credAliceBytes, aliceSeed, aliceSeedB64u, svcTuple, rejectVectorBytes, composeCredential, audFromCodepoints, padTo, composeRecipe, recipeString, resolvePrivateEnvelopeReference, negBytes, type Sink, importOn, expectClass, counterRandom, composedWrongServer, expectPlainError } from "./support.js";

test("row 12: trust policy — trusted tuple required, pipeline class beats identity mismatch, refusals change nothing", () => {
  // Every aud positive (row 14) and the two base credentials import with the trusted tuple.
  assert.ok(importClientUserKeyCredential(credAliceBytes, svcTuple).signer.kid() === alice.kid, "cred-alice imports with the trusted svc tuple");

  // Wrong url / aud / server_public_key / server_kid / differing expected identity.
  const mismatches: ReadonlyArray<[string, ExpectedServerIdentity]> = [
    ["wrong url", { ...svcTuple, url: "https://other.example.test" }],
    ["wrong aud", { ...svcTuple, aud: "https://other.example.test" }],
    ["wrong server_public_key", { ...svcTuple, server_public_key: bob.publicKey }],
    ["wrong server_kid", { ...svcTuple, server_kid: bob.kid }],
    ["differing expected identity", { url: "https://other.example.test", aud: "x", server_public_key: bob.publicKey, server_kid: bob.kid }],
  ];
  for (const [label, expected] of mismatches) {
    expectClass(() => importClientUserKeyCredential(credAliceBytes, expected), "server_identity_mismatch", label);
  }

  // Missing/null/undefined/extra-member/non-object/incomplete/bad-encoding/invalid-key tuples.
  const badTuples: ReadonlyArray<[string, unknown]> = [
    ["missing server_kid member", { url: svcTuple.url, aud: svcTuple.aud, server_public_key: svc.publicKey }],
    ["null tuple", null],
    ["undefined tuple", undefined],
    ["extra-member tuple", { ...svcTuple, extra: 1 }],
    ["non-object tuple", "https://svc.example.test"],
    ["incomplete tuple", { url: svcTuple.url, aud: svcTuple.aud }],
    ["bad-encoding tuple", { ...svcTuple, server_public_key: "short!!" }],
    ["invalid-key tuple", { ...svcTuple, server_public_key: encodeBase64URL(rejectVectorBytes("reject-identity")) }],
  ];
  for (const [label, tuple] of badTuples) {
    expectClass(
      () => importClientUserKeyCredential(credAliceBytes, tuple as ExpectedServerIdentity),
      "server_identity_mismatch",
      `${label} (after document validation)`,
    );
  }

  // Ordering proof: pipeline classes survive even when the expected tuple is also wrong.
  const wrongTuple: ExpectedServerIdentity = mismatches[4]?.[1] ?? {
    url: "https://other.example.test",
    aud: "x",
    server_public_key: bob.publicKey,
    server_kid: bob.kid,
  };
  expectClass(
    () => importClientUserKeyCredential(rawBytes(must(negCase("neg-cred-server-kid-mismatch").envelope, "kid-mismatch doc")), wrongTuple),
    "kid_mismatch",
    "kid_mismatch beats server_identity_mismatch",
  );
  expectClass(
    () => importClientUserKeyCredential(rawBytes(must(negCase("neg-cred-bad-url").envelope, "bad-url doc")), wrongTuple),
    "bad_url",
    "bad_url is not converted to server_identity_mismatch",
  );

  // Server-side validator: accepts the svc credential, refuses cred-wrong-server.
  validateUserKeyCredentialForServer(credAliceBytes, svcTuple);
  expectClass(() => validateUserKeyCredentialForServer(composedWrongServer(), svcTuple), "server_identity_mismatch", "validator refuses wrong server");

  // Refusal leaves caller state unchanged.
  const tupleSnapshot: ReadonlyArray<[keyof ExpectedServerIdentity, string]> = [
    ["url", svcTuple.url],
    ["aud", svcTuple.aud],
    ["server_public_key", svcTuple.server_public_key],
    ["server_kid", svcTuple.server_kid],
  ];
  const probeSigner = new ClientUserKey(aliceSeed);
  const probeMsg = utf8("state probe");
  const probeSig = new Uint8Array(probeSigner.sign(probeMsg));
  expectClass(() => importClientUserKeyCredential(composedWrongServer(), svcTuple), "server_identity_mismatch", "refusal");
  for (const [field, value] of tupleSnapshot) {
    assert.equal(svcTuple[field], value, `expected tuple field ${field} unchanged after refusal`);
  }
  assert.ok(canonEq(probeSigner.sign(probeMsg), probeSig), "previously constructed signer untouched by refusal");
});

test("row 13: size boundaries across sinks, invalid UTF-8, and exact public round trips", () => {
  const bases: ReadonlyArray<[string, Uint8Array, Sink]> = [
    ["public", pubAliceBytes, "public"],
    ["private", privAliceBytes, "private"],
    ["credential", credAliceBytes, "credential"],
  ];
  for (const [label, base, sink] of bases) {
    expectClass(() => importOn(sink, padTo(base, 4097)), "oversized_envelope", `${label} base padded to 4097`);
    expectClass(() => importOn(sink, padTo(base, 4096)), "non_canonical_bytes", `${label} base padded to 4096`);
  }
  // 4097 fires at step 1 before any parsing, on every sink, regardless of base kind.
  expectClass(() => importUserKeyPublicEnvelope(padTo(privAliceBytes, 4097)), "oversized_envelope", "priv base on public sink at 4097");
  expectClass(() => importClientUserKeyCredential(padTo(privAliceBytes, 4097), svcTuple), "oversized_envelope", "priv base on credential sink at 4097");

  // The fixture's own composed boundary and UTF-8 cases on the private sink.
  expectClass(() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-size-boundary-4096"))), "non_canonical_bytes", "neg-size-boundary-4096");
  expectClass(() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-size-boundary-4097"))), "oversized_envelope", "neg-size-boundary-4097");
  expectClass(() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-invalid-utf8"))), "malformed_json", "neg-invalid-utf8");

  // Exact import->export round trips byte-identical to the fixture strings,
  // via the REAL export path through the public-only server identity.
  for (const id of ["pub-alice", "pub-bob", "pub-carol"]) {
    const fixtureBytes = rawBytes(posEnvelope(id));
    const identity = importServerUserKeyPublicEnvelope(fixtureBytes);
    assert.ok(canonEq(exportUserKeyPublicEnvelope(identity), fixtureBytes), `${id}: import->export round trip byte-identical`);
  }
});

test("constructor boundary: IssuedUserKeyCredential admits valid credentials and enforces its ordered guards", () => {
  // Positive: legitimate issuance then reconstruction — a valid credential
  // plus its own identity constructs and exports equal bytes.
  const { source } = counterRandom();
  const issued = issueUserKeyCredential(svcTuple, source);
  const bytes = issued.exportCredential();
  const reconstructed = new IssuedUserKeyCredential(bytes, issued.publicIdentity());
  assert.ok(canonEq(reconstructed.exportCredential(), bytes), "constructor accepts a valid credential and exports equal bytes");

  // Oversized padded credential (>4096): oversized_envelope fires before any copy/parsing.
  expectClass(() => new IssuedUserKeyCredential(padTo(bytes, 4097), issued.publicIdentity()), "oversized_envelope", "oversized padded credential");

  // A single trailing space keeps the document valid UTF-8/JSON so steps 1-14
  // pass and only the canonical-bytes gate rejects the spelling.
  const tampered = padTo(bytes, bytes.length + 1);
  expectClass(() => new IssuedUserKeyCredential(tampered, issued.publicIdentity()), "non_canonical_bytes", "space-padded credential");

  // Wrong CLIENT identity (bob public identity vs cred-alice's issued alice
  // client key): the constructor pins the identity to validated.signer, so
  // this is server_identity_mismatch.
  const bobIdentity = new ServerUserKey(decodeBase64URLFixed(bob.publicKey, 32));
  expectClass(() => new IssuedUserKeyCredential(new Uint8Array(credAliceBytes), bobIdentity), "server_identity_mismatch", "mismatched identity");

  // Server pin supplied as the client identity: cred-alice's issued client
  // key is alice, the pinned identity is the SERVER key, so
  // server_identity_mismatch (inner client alice != svc pin).
  const serverPinIdentity = new ServerUserKey(decodeBase64URLFixed(svc.publicKey, 32));
  expectClass(
    () => new IssuedUserKeyCredential(new Uint8Array(credAliceBytes), serverPinIdentity),
    "server_identity_mismatch",
    "server pin as client identity",
  );

  // Non-Uint8Array credential: plain Error with the exact message.
  expectPlainError(
    () => new IssuedUserKeyCredential("not bytes" as unknown as Uint8Array, issued.publicIdentity()),
    "jack user-key: credential must be a Uint8Array",
    "non-Uint8Array credential",
  );

  // Identity that is not a ServerUserKey (plain object cast): plain Error with the exact message.
  expectPlainError(
    () => new IssuedUserKeyCredential(new Uint8Array(credAliceBytes), {} as unknown as ServerUserKey),
    "jack user-key: identity must be a ServerUserKey",
    "identity is not a ServerUserKey",
  );

  // Public-envelope bytes fed to the credential sink: wrong_envelope_type.
  expectClass(() => new IssuedUserKeyCredential(new Uint8Array(pubAliceBytes), issued.publicIdentity()), "wrong_envelope_type", "public bytes on the credential sink");
});

test("row 14: aud/JCS positives decode exactly and compose canonically; surrogate and duplicate controls hold", () => {
  const audPositives = fx.positives.filter((p) => p.id.startsWith("cred-aud-"));
  assert.equal(audPositives.length, 5, "five cred-aud positive cases");
  // Expected client identity is independently pinned to keys.json alice even
  // when the aud credential itself is composed from its recipe.
  for (const positive of audPositives) {
    assert.ok(must(positive.expectClientKid, `${positive.id}.expect_client_kid`) === alice.kid, `${positive.id}: expected client kid is independently pinned to keys.json alice`);
    const codepoints = positive.compose?.["aud_codepoints"];
    let aud: string;
    if (codepoints !== undefined) {
      assert.ok(Array.isArray(codepoints), `${positive.id}.compose.aud_codepoints must be an array`);
      for (const value of codepoints) {
        const stringScalar = typeof value === "string" && [...value].length === 1 ? value.codePointAt(0) : undefined;
        const validNumber =
          typeof value === "number" &&
          Number.isInteger(value) &&
          value >= 0 &&
          value <= 0x10ffff &&
          !(value >= 0xd800 && value <= 0xdfff);
        const validString =
          typeof value === "string" &&
          [...value].length === 1 &&
          stringScalar !== undefined &&
          !(stringScalar >= 0xd800 && stringScalar <= 0xdfff);
        assert.ok(validNumber || validString, `${positive.id}: each aud_codepoints item is exactly one Unicode scalar`);
      }
      aud = audFromCodepoints(codepoints as readonly (string | number)[]);
    } else {
      aud = must(positive.expectAud, `${positive.id}.expect_aud`);
    }
    const bytes =
      positive.envelope !== undefined
        ? rawBytes(positive.envelope)
        : (() => {
            const recipe = composeRecipe(positive);
            const composeClientKey = resolvePrivateEnvelopeReference(recipe, "client_key", `${positive.id}.compose.client_key`);
            const inner = JSON.parse(composeClientKey) as Record<string, unknown>;
            assert.ok(
              typeof inner["d"] === "string" && sameBytes(decodeBase64URLFixed(inner["d"], 32), aliceSeed),
              `${positive.id}: resolved inner raw d bytes equal independently pinned keys.json alice.seedHex`,
            );
            assert.ok(inner["x"] === alice.publicKey, `${positive.id}: resolved inner x equals keys.json alice.publicKey`);
            assert.ok(inner["kid"] === alice.kid, `${positive.id}: resolved inner kid equals keys.json alice.kid`);
            const composeServerPublicKey = recipeString(recipe, "server_public_key", `${positive.id}.compose.server_public_key`);
            const composeServerKid = recipeString(recipe, "server_kid", `${positive.id}.compose.server_kid`);
            const composeUrl = recipeString(recipe, "url", `${positive.id}.compose.url`);
            assert.ok(composeServerPublicKey === svc.publicKey, `${positive.id}: composed server public key equals independent keys.json pin`);
            assert.ok(composeServerKid === svc.kid, `${positive.id}: composed server kid equals independent keys.json pin`);
            assert.ok(
              composeServerKid === keyId(decodeBase64URLFixed(composeServerPublicKey, 32)),
              `${positive.id}: composed server kid equals keyId(decoded composed server public key)`,
            );
            return composeCredential(aud, composeClientKey, composeServerKid, composeServerPublicKey, composeUrl);
          })();
    // Expected tuple uses THAT exact aud, supplied independently.
    const { signer, connection } = importClientUserKeyCredential(bytes, { ...svcTuple, aud });
    assert.equal(connection.aud, aud, `${positive.id}: decoded aud exact string equality`);
    assert.equal(signer.kid(), must(positive.expectClientKid, `${positive.id}.expect_client_kid`), `${positive.id}: client kid`);
    assert.equal(connection.server_kid, must(positive.expectServerKid, `${positive.id}.expect_server_kid`), `${positive.id}: server kid`);
    const text = new TextDecoder().decode(bytes);
    if (positive.id === "cred-aud-control") {
      assert.ok(text.includes("\\u0001"), "U+0001 emitted as the six-character lowercase escape");
      assert.ok(!text.includes("\\u0001".toUpperCase()), "control escape must be lowercase");
    }
    if (positive.id === "cred-aud-separators") {
      assert.ok(bytesInclude(bytes, "a\u2028b\u2029"), "U+2028/U+2029 carried as literal UTF-8");
      assert.ok(!text.includes("\\u2028"), "separators must not be escaped");
    }
    if (positive.id === "cred-aud-replacement-char") {
      assert.ok(bytesInclude(bytes, "a\uFFFDb"), "literal U+FFFD carried as UTF-8");
    }
    if (positive.id === "cred-aud-codepoints") {
      assert.ok(bytesInclude(bytes, "\u00e9\ud83d\ude00"), "e-acute and U+1F600 carried as literal UTF-8");
    }
  }

  // Lone surrogate escapes are malformed_json; the escaped pair fails canonical bytes.
  expectClass(() => importClientUserKeyCredential(negBytes(negCase("neg-cred-aud-lone-surrogate-escape")), svcTuple), "malformed_json", "lone high surrogate escape");
  expectClass(() => importClientUserKeyCredential(negBytes(negCase("neg-cred-aud-lone-low-surrogate-escape")), svcTuple), "malformed_json", "lone low surrogate escape");
  expectClass(() => importClientUserKeyCredential(negBytes(negCase("neg-cred-aud-escaped-surrogate-pair")), svcTuple), "non_canonical_bytes", "escaped surrogate pair");
  // Section 5 duplicate-member behavior: escaped-equivalent duplicate and inner duplicate.
  expectClass(() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-dup-member-escaped"))), "non_canonical_bytes", "escaped-equivalent duplicate member");
  expectClass(() => importClientUserKeyCredential(negBytes(negCase("neg-cred-dup-inner-member")), svcTuple), "non_canonical_bytes", "credential duplicate inner member");
  expectClass(() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-dup-member-last-mismatched"))), "kid_mismatch", "duplicate with mismatched last value");

  // Repeated export freshness.
  const { source } = counterRandom();
  const issuer = issueUserKeyCredential(svcTuple, source);
  assert.ok(canonEq(issuer.exportCredential(), issuer.exportCredential()), "repeated export is fresh and equal");
});

test("error messages carry class/member/length only across a sample of classes", () => {
  const secrets = [aliceSeedB64u, alice.seedHex, privAliceStr.slice(0, 24), posEnvelope("cred-alice").slice(0, 24)];
  const samples: ReadonlyArray<[() => void, string]> = [
    [() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-truncated"))), "malformed_json"],
    [() => importClientUserKeyPrivateEnvelope(padTo(privAliceBytes, 4097)), "oversized_envelope"],
    [() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-dup-member"))), "non_canonical_bytes"],
    [() => importClientUserKeyPrivateEnvelope(negBytes(negCase("neg-kid-mismatch"))), "kid_mismatch"],
    [() => importClientUserKeyCredential(negBytes(negCase("neg-cred-bad-url")), svcTuple), "bad_url"],
    [() => importServerUserKeyPublicEnvelope(privAliceBytes), "private_material_rejected"],
    [() => importClientUserKeyCredential(composedWrongServer(), svcTuple), "server_identity_mismatch"],
  ];
  for (const [fn, code] of samples) {
    const err = expectClass(fn, code, code);
    assert.ok(err.message.startsWith("jack user-key: "), `${code}: message prefix carries only the class frame`);
    for (const secret of secrets) {
      assert.equal(err.message.includes(secret), false, `${code}: message must never contain fixture/secret bytes`);
    }
  }
});
