import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";
import { exportUserKeyPublicEnvelope, importClientUserKeyCredential, importClientUserKeyPrivateEnvelope, importServerUserKeyPublicEnvelope, importUserKeyPublicEnvelope, issueUserKeyCredential, validateUserKeyCredentialForServer } from "../../../src/user-key/transfer.js";
import { ClientUserKey } from "../../../src/user-key/key.js";

import { type Signer } from "../../../src/client/signing/signer.js";
import { verify } from "../../../src/core/ed25519.js";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { rawBytes } from "../../support/fixtures/index.js";
import { must, utf8, sameBytes, canonEq, bytesInclude, fx, keys, alice, bob, svc, neg, posEnvelope, negCase, pubAliceBytes, privAliceBytes, privAliceStr, credAliceBytes, aliceSeed, aliceSeedB64u, svcTuple, vectors, buildPrivateEnvelope, flipFirstByte, negBytes, sinkFor, importOn, expectClass, counterRandom } from "./support.js";

test("row 6: every fixture case lands on its intended sink with the exact first-failure class", () => {
  assert.equal(fx.negatives.length, 51, "all negatives materialized");

  // Baseline prerequisites: every parseable literal negative referencing a
  // positive fixture must equal that baseline on every member NOT named as
  // its declared mutation, so the class observed below is attributable to
  // exactly the mutated members. All comparisons are boolean-safe (=== with
  // fixed labels; secret-bearing values are never assertion actuals).
  const privBaseline = JSON.parse(privAliceStr) as Record<string, unknown>;
  const pubBaseline = JSON.parse(posEnvelope("pub-alice")) as Record<string, unknown>;
  const credBaseline = JSON.parse(posEnvelope("cred-alice")) as Record<string, unknown>;
  const baselineChecked = (
    id: string,
    baseline: Record<string, unknown>,
    declarations: {
      readonly changed?: Record<string, (doc: Record<string, unknown>) => boolean>;
      readonly removed?: readonly string[];
      readonly added?: readonly string[];
    } = {},
  ): void => {
    const parsed = JSON.parse(must(negCase(id).envelope, `${id}.envelope`)) as Record<string, unknown>;
    const changed = declarations.changed ?? {};
    const removed = declarations.removed ?? [];
    const added = declarations.added ?? [];
    const allowed = new Set([...Object.keys(baseline), ...Object.keys(changed), ...removed, ...added]);
    for (const member of Object.keys(parsed)) {
      assert.ok(allowed.has(member), `${id}: member ${member} is declared by the baseline or mutation`);
    }
    for (const member of Object.keys(baseline)) {
      if (removed.includes(member)) {
        assert.ok(!Object.hasOwn(parsed, member), `${id}: declared-removed member ${member} is absent`);
      } else if (Object.hasOwn(changed, member)) {
        assert.ok(changed[member]?.(parsed) === true, `${id}: declared mutation validator accepts member ${member}`);
      } else {
        assert.ok(parsed[member] === baseline[member], `${id}: unmutated member ${member} equals the baseline`);
      }
    }
    for (const member of added) {
      assert.ok(Object.hasOwn(parsed, member), `${id}: declared addition ${member} is present`);
    }
  };
  // Private-envelope literals vs priv-alice.
  baselineChecked("neg-unknown-version", privBaseline, { changed: { v: (doc) => doc["v"] === 2 } });
  baselineChecked("neg-unknown-type", privBaseline, { changed: { type: (doc) => doc["type"] === "user-key/secret" } });
  baselineChecked("neg-bad-kty", privBaseline, { changed: { kty: (doc) => doc["kty"] === "EC" } });
  baselineChecked("neg-bad-crv", privBaseline, { changed: { crv: (doc) => doc["crv"] === "Ed448" } });
  baselineChecked("neg-empty-d", privBaseline, { changed: { d: (doc) => doc["d"] === "" } });
  baselineChecked("neg-seed-pub-mismatch", privBaseline, {
    changed: { x: (doc) => doc["x"] === bob.publicKey, kid: (doc) => doc["kid"] === bob.kid },
  });
  baselineChecked("neg-kid-mismatch", privBaseline, { changed: { kid: (doc) => doc["kid"] === bob.kid } });
  baselineChecked("neg-dup-member", privBaseline);
  baselineChecked("neg-dup-member-last-mismatched", privBaseline, { changed: { kid: (doc) => doc["kid"] === bob.kid } });
  baselineChecked("neg-dup-member-escaped", privBaseline);
  baselineChecked("neg-noncanonical-ws", privBaseline);
  baselineChecked("neg-key-reorder", privBaseline);
  baselineChecked("neg-v-float", privBaseline);
  // Public-envelope literals vs pub-alice.
  baselineChecked("neg-unknown-field", pubBaseline, { added: ["comment"] });
  assert.ok(JSON.parse(must(negCase("neg-unknown-field").envelope, "neg-unknown-field envelope"))["comment"] === "hi", "neg-unknown-field: added comment is exactly hi");
  baselineChecked("neg-missing-kid", pubBaseline, { removed: ["kid"] });
  baselineChecked("neg-wrong-field-type", pubBaseline, { changed: { kid: (doc) => doc["kid"] === 123 } });
  baselineChecked("neg-null-field", pubBaseline, { changed: { x: (doc) => doc["x"] === null } });
  baselineChecked("neg-b64-padding", pubBaseline, {
    changed: { x: (doc) => typeof pubBaseline["x"] === "string" && doc["x"] === `${pubBaseline["x"]}=` },
  });
  baselineChecked("neg-b64-char", pubBaseline, {
    changed: { kid: (doc) => typeof pubBaseline["kid"] === "string" && doc["kid"] === pubBaseline["kid"].replace("m8UN", "m+UN") },
  });
  baselineChecked("neg-len-short", pubBaseline, {
    changed: { x: (doc) => typeof pubBaseline["x"] === "string" && doc["x"] === pubBaseline["x"].slice(0, -1) },
  });
  // neg-len-long's fixture bytes mutate KID; the declared validator preserves that parent-observed spelling.
  baselineChecked("neg-len-long", pubBaseline, {
    changed: { kid: (doc) => typeof pubBaseline["kid"] === "string" && doc["kid"] === `${pubBaseline["kid"]}A` },
  });
  baselineChecked("neg-b64-trailing-bits", pubBaseline, {
    changed: {
      x: (doc) =>
        typeof pubBaseline["x"] === "string" &&
        typeof doc["x"] === "string" &&
        doc["x"] === `${pubBaseline["x"].slice(0, -1)}F` &&
        sameBytes(Buffer.from(doc["x"], "base64url"), Buffer.from(pubBaseline["x"], "base64url")),
    },
  });
  baselineChecked("neg-escaped-member-name", pubBaseline);
  // Credential literals vs cred-alice.
  baselineChecked("neg-cred-unknown-version", credBaseline, { changed: { v: (doc) => doc["v"] === 2 } });
  baselineChecked("neg-cred-unknown-type", credBaseline, { changed: { type: (doc) => doc["type"] === "user-key/credential/server" } });
  baselineChecked("neg-cred-missing-server-kid", credBaseline, { removed: ["server_kid"] });
  baselineChecked("neg-cred-extra-server-private-key", credBaseline, { added: ["server_private_key"] });
  assert.ok(
    JSON.parse(must(negCase("neg-cred-extra-server-private-key").envelope, "neg-cred-extra-server-private-key envelope"))["server_private_key"] === bob.publicKey,
    "neg-cred-extra-server-private-key: added value is exactly keys.json bob.publicKey",
  );
  baselineChecked("neg-cred-server-kid-mismatch", credBaseline, { changed: { server_kid: (doc) => doc["server_kid"] === alice.kid } });
  baselineChecked("neg-cred-bad-url", credBaseline, { changed: { url: (doc) => doc["url"] === "http://svc.example.test" } });
  baselineChecked("neg-cred-empty-aud", credBaseline, { changed: { aud: (doc) => doc["aud"] === "" } });
  baselineChecked("neg-escaped-url-slash", credBaseline);
  assert.ok(must(negCase("neg-escaped-url-slash").envelope, "neg-escaped-url-slash envelope").includes("https:\\/\\/svc"), "neg-escaped-url-slash: raw envelope contains escaped solidus spelling");
  baselineChecked("neg-cred-client-key-noncanonical", credBaseline, {
    changed: { client_key: (doc) => doc["client_key"] === privAliceStr.replace("{", "{ ") },
  });
  baselineChecked("neg-cred-client-key-public", credBaseline, {
    changed: { client_key: (doc) => doc["client_key"] === posEnvelope("pub-alice") },
  });
  assert.ok(
    must(negCase("neg-dup-member").envelope, "neg-dup-member envelope").split(`"kid":"${alice.kid}"`).length === 3,
    "neg-dup-member: exact alice kid member occurs twice in the raw envelope",
  );
  assert.ok(
    must(negCase("neg-dup-member-escaped").envelope, "neg-dup-member-escaped envelope").includes('"\\u006b\\u0069\\u0064"'),
    "neg-dup-member-escaped: raw envelope includes the escaped duplicate kid name",
  );
  assert.ok(must(negCase("neg-noncanonical-ws").envelope, "neg-noncanonical-ws envelope").startsWith("{ "), "neg-noncanonical-ws: raw envelope has whitespace after opening brace");
  assert.ok(must(negCase("neg-key-reorder").envelope, "neg-key-reorder envelope").startsWith('{"type":"user-key/private"'), "neg-key-reorder: raw envelope starts with reordered type member");
  assert.ok(must(negCase("neg-v-float").envelope, "neg-v-float envelope").includes('"v":1.0'), "neg-v-float: raw envelope preserves decimal numeric spelling");
  assert.ok(must(negCase("neg-escaped-member-name").envelope, "neg-escaped-member-name envelope").includes('"\\u0063rv"'), "neg-escaped-member-name: raw envelope contains escaped crv member spelling");
  // Declared-mutation cross-checks (boolean; never assertion actuals).
  const seedMismatch = JSON.parse(must(negCase("neg-seed-pub-mismatch").envelope, "neg-seed-pub-mismatch envelope")) as { readonly d: string; readonly x: string; readonly kid: string };
  assert.ok(seedMismatch.d === privBaseline.d, "neg-seed-pub-mismatch: d stays alice's");
  assert.ok(seedMismatch.x === bob.publicKey && seedMismatch.kid === bob.kid, "neg-seed-pub-mismatch: declared mutation is bob's x/kid");
  const kidMismatch = JSON.parse(must(negCase("neg-kid-mismatch").envelope, "neg-kid-mismatch envelope")) as { readonly d: string; readonly x: string };
  assert.ok(kidMismatch.d === privBaseline.d && kidMismatch.x === privBaseline.x, "neg-kid-mismatch: d/x stay alice's");
  const dupLast = JSON.parse(must(negCase("neg-dup-member-last-mismatched").envelope, "neg-dup-member-last-mismatched envelope")) as { readonly kid: string };
  assert.ok(dupLast.kid === bob.kid, "neg-dup-member-last-mismatched: last kid is bob's");
  assert.ok(!("kid" in (JSON.parse(must(negCase("neg-missing-kid").envelope, "neg-missing-kid envelope")) as object)), "neg-missing-kid: kid is absent");
  assert.ok(
    !("server_kid" in (JSON.parse(must(negCase("neg-cred-missing-server-kid").envelope, "neg-cred-missing-server-kid envelope")) as object)),
    "neg-cred-missing-server-kid: server_kid is absent",
  );
  assert.ok(
    "server_private_key" in (JSON.parse(must(negCase("neg-cred-extra-server-private-key").envelope, "neg-cred-extra-server-private-key envelope")) as object),
    "neg-cred-extra-server-private-key: server_private_key is present",
  );
  // Literal baseline comparison is intentionally omitted only for input forms
  // that are truncated, not JSON objects, or rejected at the size gate:
  // neg-truncated, neg-empty-input, neg-null-input, neg-root-array,
  // neg-root-string, neg-oversized-envelope. Generated inputs are instead
  // guarded by their recipe-specific structural prerequisites in negBytes:
  // size boundaries, invalid UTF-8, invalid public vectors, surrogate auds,
  // nested duplicate member, and invalid server public key.

  for (const n of fx.negatives) {
    const bytes = negBytes(n);
    const sink = sinkFor(n);
    const code = must(n.expectClass, `${n.id}.expect_class`);
    expectClass(() => importOn(sink, bytes), code, `${n.id} (${sink} sink)`);
    // Pipeline class must beat server_identity_mismatch: re-run all credential
    // negatives through the server validator expecting the SAME class.
    if (sink === "credential") {
      expectClass(() => validateUserKeyCredentialForServer(bytes, svcTuple), code, `${n.id} (server validator)`);
    }
  }
});

test("row 7: public export has no d member and no seed occurrence; credentials never carry server private keys; issuance redacts", () => {
  const aliceSigner = new ClientUserKey(aliceSeed);
  const exported = exportUserKeyPublicEnvelope(aliceSigner);
  const parsed = JSON.parse(new TextDecoder().decode(exported)) as Record<string, unknown>;
  assert.equal(Object.hasOwn(parsed, "d"), false, "public export contains no d member");
  // No occurrence of the seed anywhere (hex or base64url spelling), boolean comparison.
  assert.equal(bytesInclude(exported, alice.seedHex), false, "no seed hex substring");
  assert.equal(bytesInclude(exported, aliceSeedB64u), false, "no seed base64url substring");

  // neg-cred-extra-server-private-key: raw doc carries the member name; import refuses bad_member_set.
  const smuggle = negCase("neg-cred-extra-server-private-key");
  const smuggleBytes = rawBytes(must(smuggle.envelope, "smuggle envelope"));
  assert.ok(new TextDecoder().decode(smuggleBytes).includes('"server_private_key"'), "raw doc contains the server_private_key member name");
  expectClass(() => importClientUserKeyCredential(smuggleBytes, svcTuple), must(smuggle.expectClass, "smuggle class"), "smuggled server private key");

  // Issuance result redacts by default (boolean-safe form).
  const { source, last } = counterRandom();
  const issuer = issueUserKeyCredential(svcTuple, source);
  assert.ok(JSON.stringify(issuer) === "{}", "default JSON serialization is empty");
  const credentialText = new TextDecoder().decode(issuer.exportCredential());
  const issuedSeed = last();
  const derivedSigner = new ClientUserKey(issuedSeed);
  const innerEnvelope = buildPrivateEnvelope(encodeBase64URL(issuedSeed), derivedSigner.kid(), encodeBase64URL(derivedSigner.publicKey()));
  const inspection = inspect(issuer, { depth: Infinity });
  assert.equal(inspection.includes(credentialText), false, "inspect output contains no credential raw JSON string");
  assert.equal(inspection.includes(innerEnvelope), false, "inspect output contains no inner envelope");
  assert.equal(inspection.includes(encodeBase64URL(issuedSeed)), false, "inspect output contains no issued-seed base64url spelling");
  assert.equal(inspection.includes(Buffer.from(issuedSeed).toString("hex")), false, "inspect output contains no issued-seed hex spelling");
  assert.ok(issuer.toString().endsWith("[redacted]"), "toString redacts");
});

test("row 9: toString/inspect/JSON of signer, server identity and issuer show kid/public only", () => {
  // Imported signer and server identity are checked against ALICE's spellings;
  // the issuer is checked against ITS OWN issued spellings (never against
  // alice's secrets, which would make the check vacuous).
  const aliceSpellings = [alice.seedHex, aliceSeedB64u, privAliceStr, posEnvelope("cred-alice").slice(0, 32)];
  const importedSigner = importClientUserKeyPrivateEnvelope(privAliceBytes);
  const serverIdentity = importServerUserKeyPublicEnvelope(pubAliceBytes);
  const publicHolders: ReadonlyArray<[string, () => string[]]> = [
    ["imported signer", () => [String(importedSigner), inspect(importedSigner, { depth: Infinity }), JSON.stringify(importedSigner)]],
    ["server identity", () => [String(serverIdentity), inspect(serverIdentity, { depth: Infinity }), JSON.stringify(serverIdentity)]],
  ];
  for (const [label, renderers] of publicHolders) {
    for (const text of renderers()) {
      for (const secret of aliceSpellings) {
        assert.equal(text.includes(secret), false, `${label} rendering must not contain alice secret spelling`);
      }
    }
  }
  // Redacted forms still admit the public identity: kid is visible where expected.
  assert.ok(inspect(importedSigner).includes("ClientUserKey"), "imported signer inspect names its type");

  // The issuer's ACTUAL secrets, derived independently from the counter random.
  const { source, last } = counterRandom();
  const issuer = issueUserKeyCredential(svcTuple, source);
  const issuedSeed = last();
  const derivedSigner = new ClientUserKey(issuedSeed);
  const innerEnvelope = buildPrivateEnvelope(
    encodeBase64URL(issuedSeed),
    derivedSigner.kid(),
    encodeBase64URL(derivedSigner.publicKey()),
  );
  const credentialText = new TextDecoder().decode(issuer.exportCredential());
  // Detector positive controls: prove includes() discriminates on exactly
  // these strings before asserting absence in the redacted renderings.
  assert.ok(issuedSeed.length === 32, "issued seed oracle is populated");
  assert.ok(credentialText.includes(JSON.stringify(innerEnvelope)), "detector positive control: the quoted inner envelope occurs inside the credential text");
  const issuedSpellings = [
    Buffer.from(issuedSeed).toString("hex"),
    encodeBase64URL(issuedSeed),
    Array.from(issuedSeed).join(","),
    innerEnvelope,
    JSON.stringify(innerEnvelope),
    credentialText,
    Array.from(issuer.exportCredential()).join(","),
    credentialText.slice(0, 32),
  ];
  const issuerRenderings = [String(issuer), inspect(issuer, { depth: Infinity, maxArrayLength: Infinity }), JSON.stringify(issuer), inspect(Object.getOwnPropertyDescriptors(issuer), { depth: Infinity, maxArrayLength: Infinity })];
  for (const text of issuerRenderings) {
    for (const secret of issuedSpellings) {
      assert.equal(text.includes(secret), false, "issuer rendering must not contain issued-secret spelling");
      assert.equal(text.replace(/\s+/gu, "").includes(secret.replace(/\s+/gu, "")), false, "issuer rendering must not contain whitespace-formatted issued-secret spelling");
    }
  }
});

test("row 8: mutability isolation for imports and issuance outputs with pre-mutation snapshots", () => {
  // Public identity pub32 copy.
  const imported = importUserKeyPublicEnvelope(pubAliceBytes);
  const pubSnapshot = new Uint8Array(imported.pub32);
  flipFirstByte(imported.pub32);
  const reimported = importUserKeyPublicEnvelope(pubAliceBytes);
  assert.ok(canonEq(reimported.pub32, pubSnapshot), "re-import reproduces the original pub bytes");

  // Connection serverKey copy.
  const handed = importClientUserKeyCredential(credAliceBytes, svcTuple);
  const keySnapshot = new Uint8Array(handed.connection.serverKey);
  assert.equal(handed.connection.serverKey.length, 32, "serverKey length");
  flipFirstByte(handed.connection.serverKey);
  const handedAgain = importClientUserKeyCredential(credAliceBytes, svcTuple);
  assert.ok(canonEq(handedAgain.connection.serverKey, keySnapshot), "re-import reproduces the original serverKey bytes");

  // Exported public envelope copy; re-export reproduces original bytes and the signer still signs.
  const aliceSigner = new ClientUserKey(aliceSeed);
  const exported = exportUserKeyPublicEnvelope(aliceSigner);
  const exportSnapshot = new Uint8Array(exported);
  flipFirstByte(exported);
  assert.ok(canonEq(exportUserKeyPublicEnvelope(aliceSigner), exportSnapshot), "re-export reproduces the original bytes");
  const msg = utf8("mutability isolation");
  assert.equal(verify(aliceSigner.publicKey(), msg, aliceSigner.sign(msg)), true, "signer still signs after external mutation");
});

test("row 10: a test-only signer implementing only the general Signer interface exports its public envelope", () => {
  const helper = new ClientUserKey(aliceSeed);
  const bareSigner: Signer = {
    sign: (message: Uint8Array) => helper.sign(message),
    publicKey: () => helper.publicKey(),
    kid: () => helper.kid(),
  };
  assert.deepEqual(Object.keys(bareSigner).sort(), ["kid", "publicKey", "sign"], "test-only signer exposes no extra methods");
  const exported = exportUserKeyPublicEnvelope(bareSigner);
  assert.ok(canonEq(exported, pubAliceBytes), "public envelope of an interface-only signer equals pub-alice");
  // ClientUserKey satisfies the existing client Signer unchanged.
  const asSigner: Signer = importClientUserKeyPrivateEnvelope(privAliceBytes);
  assert.equal(asSigner.kid(), alice.kid, "ClientUserKey still satisfies Signer");
});

test("row 11: wrong sinks answer with the security class, not a generic failure", () => {
  expectClass(() => importUserKeyPublicEnvelope(privAliceBytes), "wrong_envelope_type", "client public sink with private material");
  expectClass(() => importServerUserKeyPublicEnvelope(privAliceBytes), "private_material_rejected", "server public sink with private material");
  expectClass(() => importServerUserKeyPublicEnvelope(credAliceBytes), "private_material_rejected", "server public sink with credential material");
  expectClass(
    () => importClientUserKeyCredential(rawBytes(must(negCase("neg-cred-client-key-public").envelope, "inner-public doc")), svcTuple),
    "wrong_envelope_type",
    "credential sink with public inner envelope",
  );
});
