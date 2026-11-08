/**
 * Task24 tests for user-key-transfer.ts against the shared normative fixture
 * table spec/fixtures/user-key-transfer.json (docs/design/user-keys.md
 * sections 5, 6, 11, 12.3). All 66 shared cases (14 positives, 51 negatives,
 * 1 context case) are materialized with first-failure semantics; the 14-row
 * acceptance table of section 12.3 is realized below. Secret material is
 * compared ONLY via boolean helpers so failure diagnostics never carry seed
 * or credential bytes; public byte comparisons normalize prototypes with
 * Buffer.compare.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";
import {
  IssuedUserKeyCredential,
  exportUserKeyPublicEnvelope,
  importClientUserKeyCredential,
  importClientUserKeyPrivateEnvelope,
  importServerUserKeyPublicEnvelope,
  importUserKeyPublicEnvelope,
  issueUserKeyCredential,
  validateUserKeyCredentialForServer,
  type ExpectedServerIdentity,
} from "../src/user-key-transfer.js";
import { ClientUserKey, ServerUserKey, generateClientUserKey } from "../src/user-key.js";
import { Client } from "../src/client/rpc.js";
import { fixtureNow, newTestServer, queuedNonce, rpcResultBody } from "./client-harness.js";
import { formatResponseAuth, parseRequestAuth } from "../src/auth-header.js";
import { responseSigningString } from "../src/signing.js";
import { InMemorySigner, type Signer } from "../src/client/signer.js";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { verify } from "../src/ed25519.js";
import { JackError } from "../src/errors.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../src/encoding.js";
import {
  loadKeyVectors,
  loadKeys,
  loadUserKeyTransfer,
  rawBytes,
  type UserKeyTransferCase,
} from "./fixtures.js";

// -- safe helpers -------------------------------------------------------------

/** Guard for indexed/optional fixture access; keeps assertion messages free of material. */
function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`${what}: missing`);
  }
  return value;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Boolean-only content comparison for secret bytes (never deepEqual, never echoed). */
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) {
      return false;
    }
  }
  return true;
};

/** Prototype-normalizing byte equality for PUBLIC values (Buffer.compare, never deepEqual). */
const canonEq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Boolean contains: does haystack bytes include the needle bytes/string? */
const bytesInclude = (haystack: Uint8Array, needle: Uint8Array | string): boolean =>
  Buffer.from(haystack).includes(Buffer.from(typeof needle === "string" ? utf8(needle) : needle));

// -- fixtures and oracles -----------------------------------------------------

const fx = loadUserKeyTransfer();
const keys = loadKeys().keys;
const keyByName = new Map(keys.map((k) => [k.name, k]));
const alice = must(keyByName.get("alice"), "keys.json alice");
const bob = must(keyByName.get("bob"), "keys.json bob");
const svc = must(keyByName.get("svc"), "keys.json svc");

const pos = new Map(fx.positives.map((p) => [p.id, p]));
const neg = new Map(fx.negatives.map((n) => [n.id, n]));

function posEnvelope(id: string): string {
  return must(must(pos.get(id), id).envelope, `${id}.envelope`);
}
function negCase(id: string): UserKeyTransferCase {
  return must(neg.get(id), id);
}

const pubAliceBytes = rawBytes(posEnvelope("pub-alice"));
const privAliceBytes = rawBytes(posEnvelope("priv-alice"));
const privAliceStr = posEnvelope("priv-alice");
const credAliceBytes = rawBytes(posEnvelope("cred-alice"));
const aliceSeed = new Uint8Array(Buffer.from(alice.seedHex, "hex"));
const aliceSeedB64u = encodeBase64URL(aliceSeed);

/**
 * The independently trusted server tuple, built ONLY from keys.json svc.
 * Its kid is independently asserted against keyId(decoded server_public_key)
 * before any test relies on it.
 */
const svcTuple: ExpectedServerIdentity = {
  url: "https://svc.example.test",
  aud: "https://svc.example.test",
  server_public_key: svc.publicKey,
  server_kid: svc.kid,
};

const vectors = loadKeyVectors().cases;
function rejectVectorBytes(name: string): Uint8Array {
  const found = vectors.find((v) => v.id === name);
  return new Uint8Array(Buffer.from(must(found, `key-vectors ${name}`).publicKeyHex, "hex"));
}

// -- composition recipes (docs design section 11) -----------------------------

function buildPublicEnvelope(kid: string, x: string): string {
  return must(fx.documentTemplates.publicEnvelope, "template").replace("<KID43>", kid).replace("<PUB43>", x);
}
function buildPrivateEnvelope(d: string, kid: string, x: string): string {
  return must(fx.documentTemplates.privateEnvelope, "template")
    .replace("<SEED43>", d)
    .replace("<KID43>", kid)
    .replace("<PUB43>", x);
}

/** Canonical credential per section 4/11: member order aud,client_key,server_kid,server_public_key,type,url,v; JSON.stringify string emission (literal UTF-8 incl. <>&, U+2028/2029, U+FFFD; lowercase six-char \u00xx for other controls; no solidus escaping). */
function composeCredential(aud: string, clientKey: string, serverKid: string, serverPublicKey: string, url: string): Uint8Array {
  return utf8(
    `{"aud":${JSON.stringify(aud)},"client_key":${JSON.stringify(clientKey)},"server_kid":${JSON.stringify(serverKid)},"server_public_key":${JSON.stringify(serverPublicKey)},"type":"user-key/credential/client","url":${JSON.stringify(url)},"v":1}`,
  );
}

/** aud_codepoints: integers are Unicode scalars, single-char strings are that character. */
function audFromCodepoints(list: readonly (string | number)[]): string {
  let aud = "";
  for (const item of list) {
    aud += typeof item === "number" ? String.fromCodePoint(item) : item;
  }
  return aud;
}

/** aud_replacement escape spelling: backslash, lowercase u, then the four hex digits. */
const unicodeEscape = (hex4: string): string => `\\u${hex4}`;

/** aud_replacement: replace the aud JSON STRING CONTENT between the quotes with literal escape sequences. */
function replaceAudContent(credText: string, audContent: string): Uint8Array {
  const prefix = '{"aud":"';
  assert.ok(credText.startsWith(prefix), "cred-alice envelope must start with the aud member");
  const end = credText.indexOf('"', prefix.length);
  assert.ok(end > prefix.length, "cred-alice aud string must terminate");
  return utf8(prefix + audContent + credText.slice(end));
}

const padTo = (base: Uint8Array, total: number): Uint8Array => {
  assert.ok(base.length <= total, "padding target below base length");
  const out = new Uint8Array(total);
  out.set(base);
  out.fill(0x20, base.length);
  return out;
};

const flipFirstByte = (b: Uint8Array): void => {
  b[0] = (b[0] ?? 0) ^ 0xff;
};

function composeRecipe(n: UserKeyTransferCase): NonNullable<UserKeyTransferCase["compose"]> {
  return must(n.compose, `${n.id} compose`);
}

function recipeString(recipe: NonNullable<UserKeyTransferCase["compose"]>, key: string, what: string): string {
  const value = must(recipe[key], what);
  assert.ok(typeof value === "string", `${what} must be a string`);
  return value as string;
}

/** Resolve an exact positive private-envelope reference from a fixture recipe. */
function resolvePrivateEnvelopeReference(
  recipe: NonNullable<UserKeyTransferCase["compose"]>,
  key: string,
  what: string,
): string {
  const reference = recipeString(recipe, key, what);
  const match = /^the exact ([A-Za-z0-9-]+) envelope string$/u.exec(reference);
  assert.ok(match !== null, `${what} must name an exact positive envelope reference`);
  const referencedId = match?.[1] ?? "";
  const referenced = must(pos.get(referencedId), `${referencedId} positive`);
  assert.ok(referenced.kind === "private_envelope", `${referencedId}: reference resolves to a private envelope`);
  const envelope = must(referenced.envelope, `${referencedId}.envelope`);
  assert.ok(typeof envelope === "string", `${referencedId}: private envelope exists as an exact string`);
  return envelope;
}

function recipeInteger(recipe: NonNullable<UserKeyTransferCase["compose"]>, key: string, expected: number, what: string): number {
  const value = must(recipe[key], what);
  assert.ok(typeof value === "number" && Number.isInteger(value) && value === expected, `${what} must be integer ${expected}`);
  return value as number;
}

/** Resolve a negative case to its exact bytes, applying ONLY the named mutation. */
function negBytes(n: UserKeyTransferCase): Uint8Array {
  if (n.envelope !== undefined) {
    return rawBytes(n.envelope);
  }
  switch (n.id) {
    case "neg-size-boundary-4096":
    case "neg-size-boundary-4097": {
      const expected = n.id === "neg-size-boundary-4096" ? 4096 : 4097;
      const recipe = composeRecipe(n);
      const kind = recipeString(recipe, "kind", `${n.id}.compose.kind`);
      assert.ok(kind.includes("priv-alice") && kind.includes("trailing spaces"), `${n.id}: recipe names priv-alice followed by trailing spaces`);
      const total = recipeInteger(recipe, "total_input_bytes", expected, `${n.id}.compose.total_input_bytes`);
      const bytes = padTo(privAliceBytes, total);
      assert.equal(bytes.length === total, true, `${n.id}: produced input length equals recipe total`);
      return bytes;
    }
    case "neg-invalid-utf8": {
      const recipe = composeRecipe(n);
      const kind = recipeString(recipe, "kind", `${n.id}.compose.kind`);
      assert.ok(kind.includes("priv-alice") && kind.includes("0xFF") && kind.includes("byte length unchanged"), `${n.id}: recipe declares a final-byte UTF-8 mutation with preserved length`);
      const b = new Uint8Array(privAliceBytes);
      const originalLength = b.length;
      const last = b.length - 1;
      assert.equal(b[last], 0x7d, `${n.id}: final byte must be the closing brace 0x7D`);
      b[last] = 0xff;
      assert.ok(b.length === originalLength && b.length === privAliceBytes.length, `${n.id}: invalid UTF-8 flip preserves total length`);
      return b;
    }
    case "neg-cred-aud-lone-surrogate-escape":
    case "neg-cred-aud-lone-low-surrogate-escape":
    case "neg-cred-aud-escaped-surrogate-pair": {
      const recipe = composeRecipe(n);
      const baseId = recipeString(recipe, "base", `${n.id}.compose.base`);
      assert.ok(baseId === "cred-alice", `${n.id}: recipe base is cred-alice`);
      const description = recipeString(recipe, "aud_replacement", `${n.id}.compose.aud_replacement`);
      const countMatch = /\b(six|twelve)-character\b/u.exec(description);
      assert.ok(countMatch !== null, `${n.id}: recipe declares a recognized character count`);
      const declaredCount = countMatch?.[1] === "six" ? 6 : 12;
      const tokenMatch = /\(([^()]*)\)/u.exec(description);
      assert.ok(tokenMatch !== null, `${n.id}: recipe declares escape tokens`);
      const tokens = (tokenMatch?.[1] ?? "").split(", ");
      const hexGroups: string[] = [];
      let tokenIndex = 0;
      while (tokenIndex < tokens.length) {
        assert.ok(tokens[tokenIndex] === "backslash" && tokens[tokenIndex + 1] === "lowercase u", `${n.id}: each declared escape starts with backslash, lowercase u`);
        tokenIndex += 2;
        const chars = tokens.slice(tokenIndex, tokenIndex + 4);
        assert.ok(chars.length === 4 && chars.every((char) => /^[0-9a-f]$/u.test(char)), `${n.id}: each escape declares four lowercase hex digits`);
        const hex4 = chars.join("");
        assert.ok(description.includes(chars.join(", ")), `${n.id}: declared hex group appears in its token description`);
        hexGroups.push(hex4);
        tokenIndex += 4;
      }
      assert.ok(hexGroups.length > 0, `${n.id}: recipe declares at least one escape group`);
      const codeUnits = hexGroups.map((hex4) => Number.parseInt(hex4, 16));
      if (n.id === "neg-cred-aud-lone-surrogate-escape") {
        assert.ok(codeUnits.length === 1 && codeUnits[0] !== undefined && codeUnits[0] >= 0xd800 && codeUnits[0] <= 0xdbff, `${n.id}: recipe is exactly one high-surrogate code unit`);
      } else if (n.id === "neg-cred-aud-lone-low-surrogate-escape") {
        assert.ok(codeUnits.length === 1 && codeUnits[0] !== undefined && codeUnits[0] >= 0xdc00 && codeUnits[0] <= 0xdfff, `${n.id}: recipe is exactly one low-surrogate code unit`);
      } else {
        assert.ok(
          codeUnits.length === 2 &&
            codeUnits[0] !== undefined && codeUnits[0] >= 0xd800 && codeUnits[0] <= 0xdbff &&
            codeUnits[1] !== undefined && codeUnits[1] >= 0xdc00 && codeUnits[1] <= 0xdfff,
          `${n.id}: recipe is one valid high/low surrogate pair`,
        );
      }
      const audContent = hexGroups.map((hex4) => unicodeEscape(hex4)).join("");
      assert.ok(audContent.length === declaredCount, `${n.id}: derived escape content matches declared character count`);

      const baseText = posEnvelope(baseId);
      const prefix = '{"aud":"';
      const prefixLen = prefix.length;
      assert.ok(baseText.startsWith(prefix), `${n.id}: base credential starts with the aud member`);
      const baseAudEnd = baseText.indexOf('"', prefixLen);
      assert.ok(baseAudEnd >= prefixLen, `${n.id}: base credential aud string terminates`);
      const baseAudContent = baseText.slice(prefixLen, baseAudEnd);
      const composed = new TextDecoder().decode(replaceAudContent(baseText, audContent));
      assert.ok(composed.startsWith('{"aud":"' + audContent), `${n.id}: composed credential begins with declared aud content`);
      assert.ok(
        composed.slice(prefixLen + audContent.length) === baseText.slice(prefixLen + baseAudContent.length),
        `${n.id}: composed credential preserves every byte after the aud content`,
      );
      return utf8(composed);
    }
    case "neg-cred-dup-inner-member": {
      // client_key_replacement is resolved from the fixture; composeCredential's
      // single JSON.stringify is the ONLY quoting, preserving exact inner bytes.
      const recipe = composeRecipe(n);
      const baseId = recipeString(recipe, "base", `${n.id}.compose.base`);
      assert.ok(baseId === "cred-alice", `${n.id}: recipe base is cred-alice`);
      const replacement = recipeString(recipe, "client_key_replacement", `${n.id}.compose.client_key_replacement`);
      const referenceMatch = /^the exact ([A-Za-z0-9-]+) envelope string$/u.exec(replacement);
      assert.ok(referenceMatch !== null, `${n.id}: client_key_replacement names an exact envelope reference`);
      const referencedId = referenceMatch?.[1] ?? "";
      const referenced = negCase(referencedId);
      const dupEnvelope = must(referenced.envelope, `${referencedId}.envelope`);
      // Prerequisite (boolean-only): the referenced envelope carries alice's d/x/kid and duplicated kid member.
      assert.ok(dupEnvelope.includes(encodeBase64URL(aliceSeed)), `${referencedId}: envelope carries alice's d`);
      assert.ok(dupEnvelope.includes(alice.publicKey), `${referencedId}: envelope carries alice's x`);
      assert.ok(dupEnvelope.includes(alice.kid), `${referencedId}: envelope carries alice's kid`);
      const kidMember = `"kid":"${alice.kid}"`;
      let kidMemberCount = 0;
      let kidAt = dupEnvelope.indexOf(kidMember);
      while (kidAt >= 0) {
        kidMemberCount += 1;
        kidAt = dupEnvelope.indexOf(kidMember, kidAt + 1);
      }
      assert.ok(kidMemberCount > 1, `${referencedId}: envelope contains a duplicated kid member`);
      const bytes = composeCredential(svcTuple.aud, dupEnvelope, svc.kid, svc.publicKey, svcTuple.url);
      const outer = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
      const baseline = JSON.parse(posEnvelope(baseId)) as Record<string, unknown>;
      for (const member of ["aud", "server_kid", "server_public_key", "type", "url", "v"]) {
        assert.ok(outer[member] === baseline[member], `${n.id}: outer ${member} equals cred-alice baseline`);
      }
      assert.ok(outer["client_key"] === dupEnvelope, `${n.id}: outer client_key equals the exact referenced envelope string`);
      return bytes;
    }
    case "neg-cred-invalid-server-pub": {
      const recipe = composeRecipe(n);
      const vectorId = recipeString(recipe, "server_public_key_from_key_vector", `${n.id}.compose.server_public_key_from_key_vector`);
      const serverBytes = rejectVectorBytes(vectorId);
      const clientKey = resolvePrivateEnvelopeReference(recipe, "client_key", `${n.id}.compose.client_key`);
      assert.ok(clientKey === privAliceStr, `${n.id}: recipe client_key is independently pinned to exact priv-alice`);
      const aud = recipeString(recipe, "aud", `${n.id}.compose.aud`);
      const url = recipeString(recipe, "url", `${n.id}.compose.url`);
      const bytes = composeCredential(aud, clientKey, keyId(serverBytes), encodeBase64URL(serverBytes), url);
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
      assert.ok(parsed["client_key"] === privAliceStr, `${n.id}: client_key is exact independently pinned priv-alice envelope string`);
      assert.ok(parsed["aud"] === aud && parsed["url"] === url, `${n.id}: aud and url equal compose fields`);
      assert.ok(parsed["type"] === "user-key/credential/client" && parsed["v"] === 1, `${n.id}: credential type and version remain canonical`);
      assert.ok(parsed["server_public_key"] === encodeBase64URL(serverBytes), `${n.id}: server_public_key encodes the named reject-vector bytes`);
      assert.ok(parsed["server_kid"] === keyId(serverBytes), `${n.id}: server_kid is computed from the composed invalid server key`);
      return bytes;
    }
    default:
      break;
  }
  const compose = n.compose;
  if (compose !== undefined && compose["template"] === "public_envelope") {
    const vectorId = recipeString(compose, "x_from_key_vector", `${n.id}.compose.x_from_key_vector`);
    const x = rejectVectorBytes(vectorId);
    const xText = encodeBase64URL(x);
    const kid = keyId(x);
    const bytes = utf8(buildPublicEnvelope(kid, xText));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    assert.ok(parsed["crv"] === "Ed25519", `${n.id}: crv remains canonical`);
    assert.ok(parsed["kty"] === "OKP", `${n.id}: kty remains canonical`);
    assert.ok(parsed["type"] === "user-key/public", `${n.id}: type remains canonical`);
    assert.ok(parsed["v"] === 1, `${n.id}: version remains canonical`);
    assert.ok(parsed["kid"] === keyId(x), `${n.id}: kid is computed from vector bytes`);
    assert.ok(typeof parsed["x"] === "string" && parsed["x"] === xText, `${n.id}: x exactly encodes named reject-vector bytes`);
    assert.ok(sameBytes(decodeBase64URLFixed(parsed["x"] as string, 32), x), `${n.id}: decoded x equals named reject-vector bytes`);
    return bytes;
  }
  throw new Error(`${n.id}: no composition recipe implemented`);
}

type Sink = "public" | "private" | "credential";

function sinkFor(n: UserKeyTransferCase): Sink {
  if (n.envelope !== undefined) {
    if (n.envelope.includes('"type":"user-key/credential/')) {
      return "credential";
    }
    if (n.envelope.includes('"type":"user-key/public"')) {
      return "public";
    }
    return "private";
  }
  if (n.id.startsWith("neg-invalid-pub-")) {
    return "public";
  }
  if (n.id.startsWith("neg-cred-")) {
    return "credential";
  }
  return "private";
}

function importOn(sink: Sink, input: Uint8Array, expected: ExpectedServerIdentity = svcTuple): unknown {
  if (sink === "public") {
    return importUserKeyPublicEnvelope(input);
  }
  if (sink === "private") {
    return importClientUserKeyPrivateEnvelope(input);
  }
  return importClientUserKeyCredential(input, expected);
}

/** First-failure matcher: reads ONLY err.code/httpStatus so no secret bytes reach diagnostics. */
function expectClass(fn: () => unknown, code: string, label: string): JackError {
  let caught: unknown;
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    caught = err;
  }
  assert.ok(threw, `${label}: expected throw, got none`);
  assert.ok(caught instanceof JackError, `${label}: expected JackError, got ${(caught as Error)?.name ?? "non-error"}`);
  const jack = caught as JackError;
  assert.equal(jack.httpStatus, 0, `${label}: httpStatus must be 0`);
  assert.equal(jack.code, code, `${label}: code`);
  return jack;
}

/** Deterministic injected random source (counter pattern), exposing the last batch for independent composition. */
function counterRandom(): { source: (n: number) => Uint8Array; last: () => Uint8Array } {
  let counter = 0;
  let current = new Uint8Array(0);
  return {
    source: (n: number): Uint8Array => {
      counter += 1;
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        out[i] = (counter * 7 + i * 13) & 0xff;
      }
      current = out;
      return out;
    },
    last: () => new Uint8Array(current),
  };
}

function composedWrongServer(): Uint8Array {
  // Resolve client_key from the context case's recipe, then independently pin
  // the resulting exact string to priv-alice.
  const recipe = must(must(fx.contextCases[0], "context case").compose, "context compose");
  const clientKey = resolvePrivateEnvelopeReference(recipe, "client_key", "context compose.client_key");
  assert.ok(clientKey === privAliceStr, "context recipe client_key is independently pinned to exact priv-alice");
  return composeCredential(
    recipeString(recipe, "aud", "context compose.aud"),
    clientKey,
    recipeString(recipe, "server_kid", "context compose.server_kid"),
    recipeString(recipe, "server_public_key", "context compose.server_public_key"),
    recipeString(recipe, "url", "context compose.url"),
  );
}

// -- fixture shape guard ------------------------------------------------------

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

// -- row 1 --------------------------------------------------------------------

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

// -- row 2 --------------------------------------------------------------------

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

// -- positives (structural self-consistency; 13 of 14 here, RFC case above) ---

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

// -- row 3 --------------------------------------------------------------------

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

// -- row 4 --------------------------------------------------------------------

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

// -- row 4 compatibility ------------------------------------------------------

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

// -- row 6 / all 66 cases -----------------------------------------------------

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

// -- row 7 / row 9 ------------------------------------------------------------

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

// -- row 8 --------------------------------------------------------------------

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

// -- row 10 -------------------------------------------------------------------

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

// -- row 11 -------------------------------------------------------------------

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

// -- row 12 -------------------------------------------------------------------

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

// -- row 13 -------------------------------------------------------------------

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

// -- constructor boundary -----------------------------------------------------

/** Plain-Error matcher for the constructor's JS-boundary guards (exact message, never a JackError). */
function expectPlainError(fn: () => unknown, message: string, label: string): void {
  let caught: unknown;
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    caught = err;
  }
  assert.ok(threw, `${label}: expected throw, got none`);
  assert.ok(!(caught instanceof JackError), `${label}: must be a plain Error, not a JackError`);
  assert.ok(caught instanceof Error, `${label}: expected an Error`);
  const actualMessage = (caught as Error).message;
  assert.ok(actualMessage === message, `${label}: exact message`);
}

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

// -- row 14 -------------------------------------------------------------------

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

// -- message hygiene ----------------------------------------------------------

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
