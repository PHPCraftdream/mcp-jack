/** Webhook signatures, the Jack w1 header and the emission set of spec 06 sections 2, 3 and 4; pure, node:crypto plus core modules only. */
import { createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import { encodeBase64URL, keyId } from "../../core/encoding.js";
import { verify } from "../../core/ed25519.js";
import {
  constTimeEqual,
  decodeBase64StdStrict,
  decodeBase64UrlStrict,
  encodeBase64Std,
  hmacSha256,
  sha256Bytes,
} from "./primitives.js";

/** The PKCS8 DER prefix that wraps a 32-byte Ed25519 seed. */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Ed25519 seeds and raw public keys are 32 bytes. */
const SEED_LEN = 32;

/** v1 MAC entries carry 32 bytes; v1a and v2a signatures carry 64. */
const SIG_LEN_HMAC = 32;
const SIG_LEN_ASYM = 64;

/** The single space that separates entries and w1 parameters (spec 06 R2.4). */
const SP = " ";

/** The schemes a signature header may carry (spec 06 R3.11). */
const SIGNATURE_SCHEMES: ReadonlySet<string> = new Set(["v1", "v1a", "v2a"]);

/** Lengths of the base64url kid and signature parameters of a w1 header (spec 06 R4.1). */
const KID_LEN = 43;
const W1_SIG_LEN = 86;

/** The Jack header scheme name. */
const W1_SCHEME = "w1";

/** The signed payload of a v1 or v1a delivery: webhook id, timestamp and raw body. */
export interface WebhookMessageParts {
  readonly webhookId: string;
  readonly timestamp: string;
  readonly body: Uint8Array;
}

/** The signed payload of a v2a delivery, which also binds the endpoint id. */
export interface V2aMessageParts extends WebhookMessageParts {
  readonly endpointId: string;
}

/** A webhook signing key: its kid, raw Ed25519 public key and a signer over raw message bytes. */
export interface WebhookSigningKey {
  readonly kid: string;
  readonly publicKey: Uint8Array;
  readonly sign: (message: Uint8Array) => Uint8Array;
}

/** A signing key as a card publishes it: current keys sign, previous keys only verify. */
export interface VersionedSigningKey {
  readonly key: WebhookSigningKey;
  readonly current: boolean;
}

/** A symmetric delivery secret with its rotation state. */
export interface ActiveSecret {
  readonly secret: Uint8Array;
  readonly current: boolean;
}

/** An accepted webhook public key (spec 06 R7.3); raw holds the same 32 bytes x and publicKey encode. */
export interface AcceptedWebhookKey {
  readonly kid: string;
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
  readonly publicKey: string;
  readonly raw: Uint8Array;
}

/** The signature schemes a header may carry (spec 06 R3.11). */
export type SignatureScheme = "v1" | "v1a" | "v2a";

/** One scheme,value pair of a signature header, still base64-encoded. */
export interface SignatureEntry {
  readonly scheme: string;
  readonly value: string;
}

/** One decoded signature header entry. */
export interface DecodedSignatureEntry {
  readonly scheme: SignatureScheme;
  readonly sig: Uint8Array;
}

/** The parsed shape of a signature header, still base64-encoded. */
export type SignatureHeaderParse =
  | { readonly ok: true; readonly entries: readonly SignatureEntry[] }
  | { readonly ok: false; readonly code: "malformed_signature_header" };

/** The scheme-check decision (spec 06 R3.11). */
export type SchemeCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: "unsupported_signature_scheme" };

/** The decoded signature header entries. */
export type SignatureEntriesDecode =
  | { readonly ok: true; readonly entries: readonly DecodedSignatureEntry[] }
  | { readonly ok: false; readonly code: "malformed_signature" };

/** A v1 verification decision (spec 06 R3.13). */
export type V1VerifyResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: "bad_signature" };

/** An asymmetric verification decision; kid names the key that verified (spec 06 R3.14). */
export type AsymVerifyResult =
  | { readonly ok: true; readonly kid: string }
  | { readonly ok: false; readonly code: "bad_server_signature" };

/** The signed payload of a Jack delivery (spec 06 R4.2). */
export interface W1Parts {
  readonly aud: string;
  readonly subscriptionId: string;
  readonly webhookId: string;
  readonly timestamp: string;
  readonly callbackUrl: string;
  readonly body: Uint8Array;
}

/** The two parameters of a Jack header value (spec 06 R4.1). */
export interface W1HeaderParts {
  readonly kid: string;
  readonly sig: string;
}

/** The reasons w1Verify rejects a Jack header (spec 06 R3.15, R4.4, R4.5). */
export type W1FailureCode =
  | "malformed_jack_auth"
  | "webhook_key_is_server_key"
  | "unknown_webhook_key"
  | "jack_timestamp_out_of_window"
  | "bad_jack_signature";

/** The parsed Jack header. */
export type W1HeaderParse =
  | { readonly ok: true; readonly kid: string; readonly sig: string }
  | { readonly ok: false; readonly code: "malformed_jack_auth" };

/** The w1 verification inputs: accepted keys, the clock, the window and the server's own kid. */
export interface W1VerifyOptions {
  readonly keys: readonly AcceptedWebhookKey[];
  readonly now: number;
  readonly window: number;
  readonly mcpServerKid?: string | null;
}

/** A w1 verification decision; kid names the key that verified (spec 06 R4.5). */
export type W1VerifyResult =
  | { readonly ok: true; readonly kid: string }
  | { readonly ok: false; readonly code: W1FailureCode };

/** The emission inputs: the active secrets and keys plus the delivery being signed (spec 06 R2.8). */
export interface EmissionOptions {
  readonly secrets?: readonly ActiveSecret[];
  readonly keys?: readonly VersionedSigningKey[];
  readonly webhookId: string;
  readonly timestamp: string;
  readonly body: Uint8Array;
  readonly endpointId?: string;
}

/** Joins a dot-terminated text prefix with the raw body bytes. */
function textThenBody(text: string, body: Uint8Array): Uint8Array {
  return Buffer.concat([Buffer.from(`${text}.`, "utf8"), Buffer.from(body)]);
}

/** Derives an Ed25519 signing key from a 32-byte seed (spec 06 R4.5, R7.3); kid = base64url(SHA-256(public key)). */
export function webhookSigningKeyFromSeed(seed: Uint8Array): WebhookSigningKey {
  const raw = Buffer.from(seed);
  if (raw.length !== SEED_LEN) {
    throw new Error("webhookSigningKeyFromSeed requires a 32-byte seed");
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = new Uint8Array(spki.subarray(-SEED_LEN));
  return {
    kid: keyId(publicKey),
    publicKey,
    sign: (message: Uint8Array): Uint8Array => cryptoSign(null, Buffer.from(message), privateKey),
  };
}

/** The v1 and v1a content: id, timestamp and raw body joined by dots as UTF-8 bytes (spec 06 R2.2). */
export function v1Content(parts: WebhookMessageParts): Uint8Array {
  return textThenBody(`${parts.webhookId}.${parts.timestamp}`, parts.body);
}

/** A v1 header entry: the base64 HMAC-SHA256 of the v1 content under the secret bytes (spec 06 R2.2). */
export function v1Sign(secret: Uint8Array, parts: WebhookMessageParts): string {
  return `v1,${encodeBase64Std(hmacSha256(secret, v1Content(parts)))}`;
}

/** A v1a header entry: an Ed25519 signature over the v1 content (spec 06 R2.5). */
export function v1aSign(key: WebhookSigningKey, parts: WebhookMessageParts): string {
  return `v1a,${encodeBase64Std(key.sign(v1Content(parts)))}`;
}

/** The v2a content: endpoint id, id, timestamp and body hashed once with SHA-256 (spec 06 R2.6). */
export function v2aContent(parts: V2aMessageParts): Uint8Array {
  return sha256Bytes(textThenBody(`${parts.endpointId}.${parts.webhookId}.${parts.timestamp}`, parts.body));
}

/** A v2a header entry: an Ed25519 signature over the SHA-256 digest (spec 06 R2.6). */
export function v2aSign(key: WebhookSigningKey, parts: V2aMessageParts): string {
  return `v2a,${encodeBase64Std(key.sign(v2aContent(parts)))}`;
}

/** Splits the header into scheme and value pairs without decoding (spec 06 R2.4). */
export function parseSignatureHeader(value: string): SignatureHeaderParse {
  const bad: SignatureHeaderParse = { ok: false, code: "malformed_signature_header" };
  if (value.length === 0) {
    return bad;
  }
  if (/^\s/.test(value) || /\s$/.test(value)) {
    return bad;
  }
  const entries: SignatureEntry[] = [];
  for (const part of value.split(SP)) {
    if (part.length === 0 || /\s/.test(part)) {
      return bad;
    }
    const comma = part.indexOf(",");
    if (comma <= 0 || comma === part.length - 1) {
      return bad;
    }
    const scheme = part.slice(0, comma);
    const entry = part.slice(comma + 1);
    if (!/^[A-Za-z0-9]+$/.test(scheme)) {
      return bad;
    }
    if (entry.includes(",") || /\s/.test(entry)) {
      return bad;
    }
    entries.push({ scheme, value: entry });
  }
  return { ok: true, entries };
}

/** Every scheme must be v1, v1a or v2a (spec 06 R3.11). */
export function checkSignatureSchemes(entries: readonly SignatureEntry[]): SchemeCheck {
  return entries.every((entry) => SIGNATURE_SCHEMES.has(entry.scheme))
    ? { ok: true }
    : { ok: false, code: "unsupported_signature_scheme" };
}

/** Decodes canonical standard base64 of exactly 32 bytes for v1 and 64 for v1a and v2a (spec 06 R3.12). */
export function decodeSignatureEntries(entries: readonly SignatureEntry[]): SignatureEntriesDecode {
  const bad: SignatureEntriesDecode = { ok: false, code: "malformed_signature" };
  const out: DecodedSignatureEntry[] = [];
  for (const entry of entries) {
    // The scheme narrows the entry type; an unknown scheme is never accepted
    // here, and checkSignatureSchemes rejects it before this point anyway.
    if (entry.scheme !== "v1" && entry.scheme !== "v1a" && entry.scheme !== "v2a") {
      return bad;
    }
    const sig = decodeBase64StdStrict(entry.value);
    if (sig === null) {
      return bad;
    }
    if (sig.length !== (entry.scheme === "v1" ? SIG_LEN_HMAC : SIG_LEN_ASYM)) {
      return bad;
    }
    out.push({ scheme: entry.scheme, sig });
  }
  return { ok: true, entries: out };
}

/** Accepts when any v1 entry equals the HMAC of the v1 content (spec 06 R3.13). */
export function v1Verify(
  entries: readonly DecodedSignatureEntry[],
  secret: Uint8Array,
  parts: WebhookMessageParts,
): V1VerifyResult {
  const mac = hmacSha256(secret, v1Content(parts));
  const ok = entries.some((entry) => entry.scheme === "v1" && constTimeEqual(entry.sig, mac));
  return ok ? { ok: true } : { ok: false, code: "bad_signature" };
}

/** Accepts when any v1a or v2a entry verifies under an accepted key, returning that key's kid (spec 06 R3.14). */
export function asymVerify(
  entries: readonly DecodedSignatureEntry[],
  keys: readonly AcceptedWebhookKey[],
  parts: V2aMessageParts,
): AsymVerifyResult {
  const v1aMessage = v1Content(parts);
  const v2aMessage = v2aContent(parts);
  for (const key of keys) {
    for (const entry of entries) {
      if (entry.scheme !== "v1a" && entry.scheme !== "v2a") {
        continue;
      }
      const message = entry.scheme === "v1a" ? v1aMessage : v2aMessage;
      let ok: boolean;
      try {
        ok = verify(key.raw, message, entry.sig);
      } catch {
        // A key node:crypto refuses verifies nothing (spec 06 R3.14).
        ok = false;
      }
      if (ok) {
        return { ok: true, kid: key.kid };
      }
    }
  }
  return { ok: false, code: "bad_server_signature" };
}

/** Seven LF-joined signing-string lines with no trailing LF; the last is base64url(SHA-256(body)) (spec 06 R4.2). */
export function w1SigningString(parts: W1Parts): string {
  return [
    "mcp-jack/webhook1/delivery",
    parts.aud,
    parts.subscriptionId,
    parts.webhookId,
    String(parts.timestamp),
    parts.callbackUrl,
    encodeBase64URL(sha256Bytes(parts.body)),
  ].join("\n");
}

/** The Jack header value from its two parameters (spec 06 R4.1). */
export function w1HeaderValue(parts: W1HeaderParts): string {
  return `${W1_SCHEME} kid=${parts.kid},sig=${parts.sig}`;
}

/** Signs the signing string and renders the Jack header value (spec 06 R4.2). */
export function w1Sign(key: WebhookSigningKey, parts: W1Parts): string {
  // Runtime guard kept from the reference: an untyped caller can hand over a key without a kid.
  if (typeof key.kid !== "string") {
    throw new Error("w1Sign requires a key with a kid");
  }
  const sig = encodeBase64URL(key.sign(Buffer.from(w1SigningString(parts), "utf8")));
  return w1HeaderValue({ kid: key.kid, sig });
}

/** Parses the Jack header grammar: w1, one SP, kid and sig once each, base64url values of fixed length (spec 06 R4.1). */
export function parseW1Header(value: string): W1HeaderParse {
  const bad: W1HeaderParse = { ok: false, code: "malformed_jack_auth" };
  if (!value.startsWith(`${W1_SCHEME} `)) {
    return bad;
  }
  const rest = value.slice(W1_SCHEME.length + 1);
  if (rest.length === 0 || /\s/.test(rest)) {
    return bad;
  }
  const params = new Map<string, string>();
  for (const part of rest.split(",")) {
    if (part.length === 0) {
      return bad;
    }
    const eq = part.indexOf("=");
    if (eq <= 0 || eq === part.length - 1) {
      return bad;
    }
    const name = part.slice(0, eq);
    const paramValue = part.slice(eq + 1);
    if ((name !== "kid" && name !== "sig") || params.has(name)) {
      return bad;
    }
    if (!/^[A-Za-z0-9_-]+$/.test(paramValue)) {
      return bad;
    }
    params.set(name, paramValue);
  }
  const kid = params.get("kid");
  const sig = params.get("sig");
  if (kid === undefined || sig === undefined || kid.length !== KID_LEN || sig.length !== W1_SIG_LEN) {
    return bad;
  }
  return { ok: true, kid, sig };
}

/** Parses, refuses the MCP server key id, looks up the kid, checks the window, then verifies (spec 06 R3.15, R4.4, R4.5). */
export function w1Verify(headerValue: string, parts: W1Parts, options: W1VerifyOptions): W1VerifyResult {
  const parsed = parseW1Header(headerValue);
  if (!parsed.ok) {
    return { ok: false, code: "malformed_jack_auth" };
  }
  const serverKid = options.mcpServerKid ?? null;
  if (serverKid !== null && parsed.kid === serverKid) {
    return { ok: false, code: "webhook_key_is_server_key" };
  }
  const key = options.keys.find((candidate) => candidate.kid === parsed.kid);
  if (key === undefined) {
    return { ok: false, code: "unknown_webhook_key" };
  }
  if (Math.abs(options.now - Number(parts.timestamp)) > options.window) {
    return { ok: false, code: "jack_timestamp_out_of_window" };
  }
  const sig = decodeBase64UrlStrict(parsed.sig);
  if (sig === null) {
    return { ok: false, code: "bad_jack_signature" };
  }
  const message = Buffer.from(w1SigningString(parts), "utf8");
  let ok: boolean;
  try {
    ok = verify(key.raw, message, sig);
  } catch {
    // A key node:crypto refuses verifies nothing (spec 06 R4.5).
    ok = false;
  }
  if (!ok) {
    return { ok: false, code: "bad_jack_signature" };
  }
  return { ok: true, kid: parsed.kid };
}

/** Current v1, previous v1, current v1a and v2a, then previous v1a and v2a, in that order (spec 06 R2.8). */
export function emissionEntries(options: EmissionOptions): string[] {
  const parts: V2aMessageParts = {
    webhookId: options.webhookId,
    timestamp: options.timestamp,
    body: options.body,
    endpointId: options.endpointId ?? "",
  };
  const secrets = options.secrets ?? [];
  const keys = options.keys ?? [];
  const out: string[] = [];
  const currentSecret = secrets.find((entry) => entry.current);
  const previousSecret = secrets.find((entry) => !entry.current);
  const currentKey = keys.find((entry) => entry.current);
  const previousKey = keys.find((entry) => !entry.current);
  if (currentSecret !== undefined) {
    out.push(v1Sign(currentSecret.secret, parts));
  }
  if (previousSecret !== undefined) {
    out.push(v1Sign(previousSecret.secret, parts));
  }
  if (currentKey !== undefined) {
    out.push(v1aSign(currentKey.key, parts), v2aSign(currentKey.key, parts));
  }
  if (previousKey !== undefined) {
    out.push(v1aSign(previousKey.key, parts), v2aSign(previousKey.key, parts));
  }
  return out;
}

/** The emission set as one space-delimited header value (spec 06 R2.8). */
export function emissionHeader(options: EmissionOptions): string {
  return emissionEntries(options).join(SP);
}
