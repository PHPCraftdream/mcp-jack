import assert from "node:assert/strict";
import { test } from "node:test";
import { importClientUserKeyCredential, importClientUserKeyPrivateEnvelope, importUserKeyPublicEnvelope, type ExpectedServerIdentity } from "../../../src/user-key/transfer.js";


import { JackError } from "../../../src/core/errors.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { loadKeyVectors, loadKeys, loadUserKeyTransfer, rawBytes, type UserKeyTransferCase } from "../../support/fixtures/index.js";


// -- safe helpers -------------------------------------------------------------

/** Guard for indexed/optional fixture access; keeps assertion messages free of material. */
export function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`${what}: missing`);
  }
  return value;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Boolean-only content comparison for secret bytes (never deepEqual, never echoed). */
export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
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
export const canonEq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** Boolean contains: does haystack bytes include the needle bytes/string? */
export const bytesInclude = (haystack: Uint8Array, needle: Uint8Array | string): boolean =>
  Buffer.from(haystack).includes(Buffer.from(typeof needle === "string" ? utf8(needle) : needle));

// -- fixtures and oracles -----------------------------------------------------

export const fx = loadUserKeyTransfer();
export const keys = loadKeys().keys;
export const keyByName = new Map(keys.map((k) => [k.name, k]));
export const alice = must(keyByName.get("alice"), "keys.json alice");
export const bob = must(keyByName.get("bob"), "keys.json bob");
export const svc = must(keyByName.get("svc"), "keys.json svc");

export const pos = new Map(fx.positives.map((p) => [p.id, p]));
export const neg = new Map(fx.negatives.map((n) => [n.id, n]));

export function posEnvelope(id: string): string {
  return must(must(pos.get(id), id).envelope, `${id}.envelope`);
}
export function negCase(id: string): UserKeyTransferCase {
  return must(neg.get(id), id);
}

export const pubAliceBytes = rawBytes(posEnvelope("pub-alice"));
export const privAliceBytes = rawBytes(posEnvelope("priv-alice"));
export const privAliceStr = posEnvelope("priv-alice");
export const credAliceBytes = rawBytes(posEnvelope("cred-alice"));
export const aliceSeed = new Uint8Array(Buffer.from(alice.seedHex, "hex"));
export const aliceSeedB64u = encodeBase64URL(aliceSeed);

/**
 * The independently trusted server tuple, built ONLY from keys.json svc.
 * Its kid is independently asserted against keyId(decoded server_public_key)
 * before any test relies on it.
 */
export const svcTuple: ExpectedServerIdentity = {
  url: "https://svc.example.test",
  aud: "https://svc.example.test",
  server_public_key: svc.publicKey,
  server_kid: svc.kid,
};

export const vectors = loadKeyVectors().cases;
export function rejectVectorBytes(name: string): Uint8Array {
  const found = vectors.find((v) => v.id === name);
  return new Uint8Array(Buffer.from(must(found, `key-vectors ${name}`).publicKeyHex, "hex"));
}

// -- composition recipes (docs design section 11) -----------------------------

export function buildPublicEnvelope(kid: string, x: string): string {
  return must(fx.documentTemplates.publicEnvelope, "template").replace("<KID43>", kid).replace("<PUB43>", x);
}
export function buildPrivateEnvelope(d: string, kid: string, x: string): string {
  return must(fx.documentTemplates.privateEnvelope, "template")
    .replace("<SEED43>", d)
    .replace("<KID43>", kid)
    .replace("<PUB43>", x);
}

/** Canonical credential per section 4/11: member order aud,client_key,server_kid,server_public_key,type,url,v; JSON.stringify string emission (literal UTF-8 incl. <>&, U+2028/2029, U+FFFD; lowercase six-char \u00xx for other controls; no solidus escaping). */
export function composeCredential(aud: string, clientKey: string, serverKid: string, serverPublicKey: string, url: string): Uint8Array {
  return utf8(
    `{"aud":${JSON.stringify(aud)},"client_key":${JSON.stringify(clientKey)},"server_kid":${JSON.stringify(serverKid)},"server_public_key":${JSON.stringify(serverPublicKey)},"type":"user-key/credential/client","url":${JSON.stringify(url)},"v":1}`,
  );
}

/** aud_codepoints: integers are Unicode scalars, single-char strings are that character. */
export function audFromCodepoints(list: readonly (string | number)[]): string {
  let aud = "";
  for (const item of list) {
    aud += typeof item === "number" ? String.fromCodePoint(item) : item;
  }
  return aud;
}

/** aud_replacement escape spelling: backslash, lowercase u, then the four hex digits. */
export const unicodeEscape = (hex4: string): string => `\\u${hex4}`;

/** aud_replacement: replace the aud JSON STRING CONTENT between the quotes with literal escape sequences. */
export function replaceAudContent(credText: string, audContent: string): Uint8Array {
  const prefix = '{"aud":"';
  assert.ok(credText.startsWith(prefix), "cred-alice envelope must start with the aud member");
  const end = credText.indexOf('"', prefix.length);
  assert.ok(end > prefix.length, "cred-alice aud string must terminate");
  return utf8(prefix + audContent + credText.slice(end));
}

export const padTo = (base: Uint8Array, total: number): Uint8Array => {
  assert.ok(base.length <= total, "padding target below base length");
  const out = new Uint8Array(total);
  out.set(base);
  out.fill(0x20, base.length);
  return out;
};

export const flipFirstByte = (b: Uint8Array): void => {
  b[0] = (b[0] ?? 0) ^ 0xff;
};

export function composeRecipe(n: UserKeyTransferCase): NonNullable<UserKeyTransferCase["compose"]> {
  return must(n.compose, `${n.id} compose`);
}

export function recipeString(recipe: NonNullable<UserKeyTransferCase["compose"]>, key: string, what: string): string {
  const value = must(recipe[key], what);
  assert.ok(typeof value === "string", `${what} must be a string`);
  return value as string;
}

/** Resolve an exact positive private-envelope reference from a fixture recipe. */
export function resolvePrivateEnvelopeReference(
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

export function recipeInteger(recipe: NonNullable<UserKeyTransferCase["compose"]>, key: string, expected: number, what: string): number {
  const value = must(recipe[key], what);
  assert.ok(typeof value === "number" && Number.isInteger(value) && value === expected, `${what} must be integer ${expected}`);
  return value as number;
}

/** Resolve a negative case to its exact bytes, applying ONLY the named mutation. */
export function negBytes(n: UserKeyTransferCase): Uint8Array {
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

export type Sink = "public" | "private" | "credential";

export function sinkFor(n: UserKeyTransferCase): Sink {
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

export function importOn(sink: Sink, input: Uint8Array, expected: ExpectedServerIdentity = svcTuple): unknown {
  if (sink === "public") {
    return importUserKeyPublicEnvelope(input);
  }
  if (sink === "private") {
    return importClientUserKeyPrivateEnvelope(input);
  }
  return importClientUserKeyCredential(input, expected);
}

/** First-failure matcher: reads ONLY err.code/httpStatus so no secret bytes reach diagnostics. */
export function expectClass(fn: () => unknown, code: string, label: string): JackError {
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
export function counterRandom(): { source: (n: number) => Uint8Array; last: () => Uint8Array } {
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

export function composedWrongServer(): Uint8Array {
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

// -- row 1 --------------------------------------------------------------------

// -- row 2 --------------------------------------------------------------------

// -- positives (structural self-consistency; 13 of 14 here, RFC case above) ---

// -- row 3 --------------------------------------------------------------------

// -- row 4 --------------------------------------------------------------------

// -- row 4 compatibility ------------------------------------------------------

// -- row 6 / all 66 cases -----------------------------------------------------

// -- row 7 / row 9 ------------------------------------------------------------

// -- row 8 --------------------------------------------------------------------

// -- row 10 -------------------------------------------------------------------

// -- row 11 -------------------------------------------------------------------

// -- row 12 -------------------------------------------------------------------

// -- row 13 -------------------------------------------------------------------

// -- constructor boundary -----------------------------------------------------

/** Plain-Error matcher for the constructor's JS-boundary guards (exact message, never a JackError). */
export function expectPlainError(fn: () => unknown, message: string, label: string): void {
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

// -- row 14 -------------------------------------------------------------------

// -- message hygiene ----------------------------------------------------------
