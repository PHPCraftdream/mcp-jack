import { randomBytes } from "node:crypto";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "./encoding.js";
import { validatePublicKey } from "./ed25519.js";
import { JackError } from "./errors.js";
import { ClientUserKey, ServerUserKey } from "./user-key.js";
import type { Signer } from "./client/signer.js";
import { checkDestination } from "./client/url-policy.js";

const MAX_USER_KEY_DOCUMENT_BYTES = 4096;
const PUBLIC_ENVELOPE_TYPE = "user-key/public";
const PRIVATE_ENVELOPE_TYPE = "user-key/private";
const CLIENT_CREDENTIAL_TYPE = "user-key/credential/client";
const PUBLIC_MEMBERS = ["crv", "kid", "kty", "type", "v", "x"] as const;
const PRIVATE_MEMBERS = ["crv", "d", "kid", "kty", "type", "v", "x"] as const;
const CREDENTIAL_MEMBERS = ["aud", "client_key", "server_kid", "server_public_key", "type", "url", "v"] as const;
const EXPECTED_IDENTITY_MEMBERS = ["url", "aud", "server_public_key", "server_kid"] as const;
const HEX4 = /^[0-9a-fA-F]{4}$/;

export interface ImportedUserKeyPublic {
  readonly pub32: Uint8Array;
  readonly kid: string;
}

export interface ExpectedServerIdentity {
  readonly url: string;
  readonly aud: string;
  readonly server_public_key: string;
  readonly server_kid: string;
}

export type UserKeyCredentialConfig = ExpectedServerIdentity;

export interface UserKeyConnection extends ExpectedServerIdentity {
  readonly baseUrl: string;
  readonly serverKey: Uint8Array;
}

export interface ImportedUserKeyCredential {
  readonly signer: ClientUserKey;
  readonly connection: UserKeyConnection;
}

interface PublicEnvelopeData {
  readonly pub: Uint8Array;
  readonly kid: string;
}

interface PrivateEnvelopeData extends PublicEnvelopeData {
  readonly signer: ClientUserKey;
}

interface CredentialData {
  readonly aud: string;
  readonly url: string;
  readonly serverKid: string;
  readonly serverPublicKey: string;
  readonly serverBytes: Uint8Array;
  readonly signer: ClientUserKey;
}

interface ValidatedIdentity {
  readonly url: string;
  readonly aud: string;
  readonly serverPublicKey: string;
  readonly serverKid: string;
  readonly serverBytes: Uint8Array;
}

type UserKeyErrorClass =
  | "malformed_json"
  | "wrong_root_type"
  | "oversized_envelope"
  | "unknown_version"
  | "unknown_type"
  | "bad_member_set"
  | "wrong_field_type"
  | "bad_encoding"
  | "bad_url"
  | "invalid_public_key"
  | "seed_pub_mismatch"
  | "kid_mismatch"
  | "non_canonical_bytes"
  | "wrong_envelope_type"
  | "private_material_rejected"
  | "not_private"
  | "server_identity_mismatch";

function userKeyError(errorClass: UserKeyErrorClass, member?: string, length?: number): JackError {
  const details = [member === undefined ? "" : `member=${member}`, length === undefined ? "" : `length=${length}`].filter(Boolean);
  return new JackError(0, errorClass, `jack user-key: ${errorClass}${details.length === 0 ? "" : ` (${details.join(" ")})`}`);
}

function fail(errorClass: UserKeyErrorClass, member?: string, length?: number): never {
  throw userKeyError(errorClass, member, length);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactMembers(value: Record<string, unknown>, members: readonly string[]): boolean {
  const memberNames = Object.keys(value);
  return memberNames.length === members.length && memberNames.every((name) => (members as readonly string[]).includes(name));
}

function isScalarString(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function malformed(): never {
  return fail("malformed_json");
}

function validateRawStringEscapes(text: string): void {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (!inString) {
      if (code === 0x22) {
        inString = true;
      }
      continue;
    }
    if (code === 0x22) {
      inString = false;
      continue;
    }
    if (code < 0x20) {
      malformed();
    }
    if (code !== 0x5c) {
      continue;
    }
    const next = text.charCodeAt(i + 1);
    if (next === 0x22 || next === 0x5c || next === 0x2f || next === 0x62 || next === 0x66 || next === 0x6e || next === 0x72 || next === 0x74) {
      i++;
      continue;
    }
    if (next !== 0x75) {
      malformed();
    }
    const firstHex = text.slice(i + 2, i + 6);
    if (!HEX4.test(firstHex)) {
      malformed();
    }
    const first = Number.parseInt(firstHex, 16);
    if (first >= 0xdc00 && first <= 0xdfff) {
      malformed();
    }
    if (first >= 0xd800 && first <= 0xdbff) {
      const secondStart = i + 6;
      if (text.charCodeAt(secondStart) !== 0x5c || text.charCodeAt(secondStart + 1) !== 0x75) {
        malformed();
      }
      const secondHex = text.slice(secondStart + 2, secondStart + 6);
      if (!HEX4.test(secondHex)) {
        malformed();
      }
      const second = Number.parseInt(secondHex, 16);
      if (second < 0xdc00 || second > 0xdfff) {
        malformed();
      }
      i = secondStart + 5;
      continue;
    }
    i += 5;
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

function decodeFixed(value: string, member: string): Uint8Array {
  try {
    return decodeBase64URLFixed(value, 32);
  } catch {
    fail("bad_encoding", member, value.length);
  }
}

function requireString(record: Record<string, unknown>, member: string): string {
  const value = record[member];
  if (typeof value !== "string") {
    fail("wrong_field_type", member);
  }
  return value;
}

function decodeDocument(input: Uint8Array): { readonly bytes: Uint8Array; readonly value: unknown } {
  if (!(input instanceof Uint8Array)) {
    return malformed();
  }
  if (input.length > MAX_USER_KEY_DOCUMENT_BYTES) { fail("oversized_envelope", undefined, input.length); }
  const bytes = new Uint8Array(input);
  if (bytes.length > MAX_USER_KEY_DOCUMENT_BYTES) {
    fail("oversized_envelope", undefined, bytes.length);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return malformed();
  }
  validateRawStringEscapes(text);
  let value: unknown;
  try {
    value = JSON.parse(text.startsWith("\uFEFF") ? text.slice(1) : text) as unknown;
  } catch {
    return malformed();
  }
  return { bytes, value };
}

function checkVersion(record: Record<string, unknown>): void {
  if (typeof record["v"] !== "number" || record["v"] !== 1) {
    fail("unknown_version", "v");
  }
}

function canonicalPublicEnvelope(kid: string, pub: Uint8Array): Uint8Array {
  return new TextEncoder().encode(`{"crv":"Ed25519","kid":${JSON.stringify(kid)},"kty":"OKP","type":"${PUBLIC_ENVELOPE_TYPE}","v":1,"x":${JSON.stringify(encodeBase64URL(pub))}}`);
}

function canonicalPrivateEnvelope(kid: string, seed: Uint8Array, pub: Uint8Array): Uint8Array {
  return new TextEncoder().encode(`{"crv":"Ed25519","d":${JSON.stringify(encodeBase64URL(seed))},"kid":${JSON.stringify(kid)},"kty":"OKP","type":"${PRIVATE_ENVELOPE_TYPE}","v":1,"x":${JSON.stringify(encodeBase64URL(pub))}}`);
}

function canonicalCredential(aud: string, clientKey: string, serverKid: string, serverPublicKey: string, url: string): Uint8Array {
  if (!isScalarString(aud) || !isScalarString(clientKey) || !isScalarString(serverKid) || !isScalarString(serverPublicKey) || !isScalarString(url)) {
    fail("wrong_field_type");
  }
  return new TextEncoder().encode(`{"aud":${JSON.stringify(aud)},"client_key":${JSON.stringify(clientKey)},"server_kid":${JSON.stringify(serverKid)},"server_public_key":${JSON.stringify(serverPublicKey)},"type":"${CLIENT_CREDENTIAL_TYPE}","url":${JSON.stringify(url)},"v":1}`);
}

function checkCanonical(input: Uint8Array, canonical: Uint8Array): void {
  if (!equalBytes(input, canonical)) {
    fail("non_canonical_bytes", undefined, input.length);
  }
}

function importPublicDocument(input: Uint8Array, serverSink: boolean): PublicEnvelopeData {
  const parsed = decodeDocument(input);
  if (!isRecord(parsed.value)) {
    fail("wrong_root_type");
  }
  const record = parsed.value;
  checkVersion(record);
  const type = record["type"];
  if (type !== PUBLIC_ENVELOPE_TYPE && type !== PRIVATE_ENVELOPE_TYPE && type !== CLIENT_CREDENTIAL_TYPE) {
    fail("unknown_type", "type");
  }
  if (serverSink && (type === PRIVATE_ENVELOPE_TYPE || type === CLIENT_CREDENTIAL_TYPE)) {
    fail("private_material_rejected", "type");
  }
  if (type !== PUBLIC_ENVELOPE_TYPE) {
    fail("wrong_envelope_type", "type");
  }
  if (!hasExactMembers(record, PUBLIC_MEMBERS)) {
    fail("bad_member_set");
  }
  const kty = record["kty"];
  if (typeof kty !== "string") {
    fail("wrong_field_type", "kty");
  }
  if (kty !== "OKP") {
    fail("unknown_type", "kty");
  }
  const crv = record["crv"];
  if (typeof crv !== "string") {
    fail("wrong_field_type", "crv");
  }
  if (crv !== "Ed25519") {
    fail("unknown_type", "crv");
  }
  const kid = requireString(record, "kid");
  const x = requireString(record, "x");
  const pub = decodeFixed(x, "x");
  const kidBytes = decodeFixed(kid, "kid");
  const publicKeyValidationError = validatePublicKey(pub);
  if (publicKeyValidationError !== null) {
    fail("invalid_public_key", "x", pub.length);
  }
  const publicKeyId = keyId(pub);
  if (publicKeyId !== encodeBase64URL(kidBytes)) {
    fail("kid_mismatch", "kid", kid.length);
  }
  checkCanonical(parsed.bytes, canonicalPublicEnvelope(kid, pub));
  return { pub, kid };
}

function importPrivateDocument(input: Uint8Array): PrivateEnvelopeData {
  const parsed = decodeDocument(input);
  if (!isRecord(parsed.value)) {
    fail("wrong_root_type");
  }
  const record = parsed.value;
  checkVersion(record);
  const type = record["type"];
  if (type !== PUBLIC_ENVELOPE_TYPE && type !== PRIVATE_ENVELOPE_TYPE && type !== CLIENT_CREDENTIAL_TYPE) {
    fail("unknown_type", "type");
  }
  if (type === CLIENT_CREDENTIAL_TYPE) {
    fail("wrong_envelope_type", "type");
  }
  if (type !== PRIVATE_ENVELOPE_TYPE) {
    fail("wrong_envelope_type", "type");
  }
  if (!hasExactMembers(record, PRIVATE_MEMBERS)) {
    fail("bad_member_set");
  }
  const kty = record["kty"];
  if (typeof kty !== "string") {
    fail("wrong_field_type", "kty");
  }
  if (kty !== "OKP") {
    fail("unknown_type", "kty");
  }
  const crv = record["crv"];
  if (typeof crv !== "string") {
    fail("wrong_field_type", "crv");
  }
  if (crv !== "Ed25519") {
    fail("unknown_type", "crv");
  }
  const d = requireString(record, "d");
  const kid = requireString(record, "kid");
  const x = requireString(record, "x");
  const seed = decodeFixed(d, "d");
  const pub = decodeFixed(x, "x");
  const keyIdBytes = decodeFixed(kid, "kid");
  const publicValidationError = validatePublicKey(pub);
  if (publicValidationError !== null) {
    fail("invalid_public_key", "x", pub.length);
  }
  let derived: Uint8Array;
  try {
    derived = new ClientUserKey(seed).publicKey();
  } catch {
    fail("bad_encoding", "d", d.length);
  }
  if (!equalBytes(derived, pub)) {
    fail("seed_pub_mismatch", "d", d.length);
  }
  if (keyId(pub) !== encodeBase64URL(keyIdBytes)) {
    fail("kid_mismatch", "kid", kid.length);
  }
  checkCanonical(parsed.bytes, canonicalPrivateEnvelope(kid, seed, pub));
  return { pub, kid, signer: new ClientUserKey(seed) };
}

function importCredentialDocument(input: Uint8Array): CredentialData {
  const parsed = decodeDocument(input);
  if (!isRecord(parsed.value)) {
    fail("wrong_root_type");
  }
  const record = parsed.value;
  checkVersion(record);
  const type = record["type"];
  if (type !== PUBLIC_ENVELOPE_TYPE && type !== PRIVATE_ENVELOPE_TYPE && type !== CLIENT_CREDENTIAL_TYPE) {
    fail("unknown_type", "type");
  }
  if (type !== CLIENT_CREDENTIAL_TYPE) {
    fail("wrong_envelope_type", "type");
  }
  if (!hasExactMembers(record, CREDENTIAL_MEMBERS)) {
    fail("bad_member_set");
  }
  const aud = requireString(record, "aud");
  const clientKey = requireString(record, "client_key");
  const serverKid = requireString(record, "server_kid");
  const serverPublicKey = requireString(record, "server_public_key");
  const url = requireString(record, "url");
  for (const [member, value] of [["aud", aud], ["client_key", clientKey], ["server_kid", serverKid], ["server_public_key", serverPublicKey], ["url", url]] as const) {
    if (!isScalarString(value)) {
      fail("wrong_field_type", member);
    }
  }
  if (aud.length === 0) {
    fail("wrong_field_type", "aud", aud.length);
  }
  try {
    checkDestination(url);
  } catch {
    fail("bad_url", "url");
  }
  const serverKidBytes = decodeFixed(serverKid, "server_kid");
  const serverBytes = decodeFixed(serverPublicKey, "server_public_key");
  const serverPublicKeyValidationError = validatePublicKey(serverBytes);
  if (serverPublicKeyValidationError !== null) {
    fail("invalid_public_key", "server_public_key", serverBytes.length);
  }
  if (keyId(serverBytes) !== encodeBase64URL(serverKidBytes)) {
    fail("kid_mismatch", "server_kid", serverKid.length);
  }
  const inner = importPrivateDocument(new TextEncoder().encode(clientKey));
  checkCanonical(parsed.bytes, canonicalCredential(aud, clientKey, serverKid, serverPublicKey, url));
  return { aud, url, serverKid, serverPublicKey, serverBytes, signer: inner.signer };
}

function validateIdentityTuple(input: unknown, mismatch: boolean): ValidatedIdentity {
  const reject = (errorClass: UserKeyErrorClass, member?: string, length?: number): never => {
    if (mismatch) {
      fail("server_identity_mismatch");
    }
    fail(errorClass, member, length);
  };
  if (!isRecord(input)) {
    reject("wrong_field_type");
  }
  let memberNames: string[];
  try {
    memberNames = Object.keys(input);
  } catch {
    reject("wrong_field_type");
  }
  if (memberNames.length !== EXPECTED_IDENTITY_MEMBERS.length || !memberNames.every((member) => EXPECTED_IDENTITY_MEMBERS.includes(member as (typeof EXPECTED_IDENTITY_MEMBERS)[number]))) {
    reject("wrong_field_type");
  }
  try {
    if (!EXPECTED_IDENTITY_MEMBERS.every((member) => Object.hasOwn(input, member))) {
      reject("wrong_field_type");
    }
  } catch {
    reject("wrong_field_type");
  }
  let url: unknown;
  let aud: unknown;
  let serverPublicKey: unknown;
  let serverKid: unknown;
  try {
    url = input["url"];
    aud = input["aud"];
    serverPublicKey = input["server_public_key"];
    serverKid = input["server_kid"];
  } catch {
    reject("wrong_field_type");
  }
  if (typeof url !== "string") {
    reject("wrong_field_type", "url");
  }
  if (typeof aud !== "string" || aud.length === 0 || !isScalarString(aud)) {
    reject("wrong_field_type", "aud");
  }
  if (typeof serverPublicKey !== "string") {
    reject("wrong_field_type", "server_public_key");
  }
  if (typeof serverKid !== "string") {
    reject("wrong_field_type", "server_kid");
  }
  try {
    checkDestination(url);
  } catch {
    reject("bad_url", "url");
  }
  let serverPublicKeyBytes: Uint8Array;
  let kidBytes: Uint8Array;
  try {
    serverPublicKeyBytes = decodeFixed(serverPublicKey, "server_public_key");
  } catch {
    reject("bad_encoding", "server_public_key");
  }
  try {
    kidBytes = decodeFixed(serverKid, "server_kid");
  } catch {
    reject("bad_encoding", "server_kid");
  }
  const validationError = validatePublicKey(serverPublicKeyBytes);
  if (validationError !== null) {
    reject("invalid_public_key", "server_public_key");
  }
  if (keyId(serverPublicKeyBytes) !== encodeBase64URL(kidBytes)) {
    reject("kid_mismatch", "server_kid");
  }
  return { url, aud, serverPublicKey, serverKid, serverBytes: serverPublicKeyBytes };
}

function checkExpectedIdentity(credential: CredentialData, expected: ExpectedServerIdentity): void {
  const trusted = validateIdentityTuple(expected, true);
  if (
    credential.url !== trusted.url ||
    credential.aud !== trusted.aud ||
    credential.serverKid !== trusted.serverKid ||
    credential.serverPublicKey !== trusted.serverPublicKey ||
    !equalBytes(credential.serverBytes, trusted.serverBytes)
  ) {
    fail("server_identity_mismatch");
  }
}

function connectionFromCredential(credential: CredentialData): UserKeyConnection {
  return {
    url: credential.url,
    aud: credential.aud,
    server_public_key: credential.serverPublicKey,
    server_kid: credential.serverKid,
    baseUrl: credential.url,
    serverKey: new Uint8Array(credential.serverBytes),
  };
}

export function exportUserKeyPublicEnvelope(signer: Pick<Signer, "publicKey" | "kid">): Uint8Array {
  const suppliedPublicKey = signer.publicKey();
  if (!(suppliedPublicKey instanceof Uint8Array)) {
    fail("invalid_public_key", "x");
  }
  const pub = new Uint8Array(suppliedPublicKey);
  let suppliedKid: unknown;
  try {
    suppliedKid = signer.kid();
  } catch {
    fail("wrong_field_type", "kid");
  }
  if (typeof suppliedKid !== "string") {
    fail("wrong_field_type", "kid");
  }
  const kid = suppliedKid;
  const validationError = validatePublicKey(pub);
  if (validationError !== null) {
    fail("invalid_public_key", "x", pub.length);
  }
  const computedKid = keyId(pub);
  if (kid !== computedKid) {
    fail("kid_mismatch", "kid", kid.length);
  }
  return canonicalPublicEnvelope(computedKid, pub);
}

export function importUserKeyPublicEnvelope(bytes: Uint8Array): ImportedUserKeyPublic {
  const imported = importPublicDocument(bytes, false);
  return {
    pub32: new Uint8Array(imported.pub),
    kid: imported.kid,
  };
}

export function importServerUserKeyPublicEnvelope(bytes: Uint8Array): ServerUserKey {
  const imported = importPublicDocument(bytes, true);
  return new ServerUserKey(imported.pub);
}

export function importClientUserKeyPrivateEnvelope(bytes: Uint8Array): ClientUserKey {
  return importPrivateDocument(bytes).signer;
}

export function importClientUserKeyCredential(bytes: Uint8Array, expected: ExpectedServerIdentity): ImportedUserKeyCredential {
  const credential = importCredentialDocument(bytes);
  checkExpectedIdentity(credential, expected);
  const connection = connectionFromCredential(credential);
  return { signer: credential.signer, connection };
}

export function validateUserKeyCredentialForServer(bytes: Uint8Array, expected: ExpectedServerIdentity): void {
  const credential = importCredentialDocument(bytes);
  checkExpectedIdentity(credential, expected);
}

export class IssuedUserKeyCredential {
  #credential: Uint8Array;
  #identity: ServerUserKey;

  constructor(credential: Uint8Array, identity: ServerUserKey) {
    if (!(credential instanceof Uint8Array)) {
      throw new Error("jack user-key: credential must be a Uint8Array");
    }
    if (credential.length > MAX_USER_KEY_DOCUMENT_BYTES) {
      fail("oversized_envelope");
    }
    const owned = new Uint8Array(credential);
    const validated = importCredentialDocument(owned);
    if (!(identity instanceof ServerUserKey)) {
      throw new Error("jack user-key: identity must be a ServerUserKey");
    }
    if (validated.signer.kid() !== identity.kid() || !equalBytes(validated.signer.publicKey(), identity.publicKey())) {
      fail("server_identity_mismatch");
    }
    this.#credential = owned;
    this.#identity = identity;
  }

  exportCredential(): Uint8Array {
    return new Uint8Array(this.#credential);
  }

  publicIdentity(): ServerUserKey {
    return this.#identity;
  }

  toString(): string {
    return "IssuedUserKeyCredential [redacted]";
  }
}

export function issueUserKeyCredential(
  config: UserKeyCredentialConfig,
  randomSource: (n: number) => Uint8Array = (n) => randomBytes(n),
): IssuedUserKeyCredential {
  const identity = validateIdentityTuple(config, false);
  let supplied: unknown;
  try {
    supplied = randomSource(32);
  } catch {
    fail("bad_encoding", "d");
  }
  if (!(supplied instanceof Uint8Array)) {
    fail("bad_encoding", "d");
  }
  const seed = new Uint8Array(supplied);
  if (seed.length !== 32) {
    fail("bad_encoding", "d", seed.length);
  }
  const signer = new ClientUserKey(seed);
  const pub = signer.publicKey();
  const kid = signer.kid();
  const inner = canonicalPrivateEnvelope(kid, seed, pub);
  const clientKey = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(inner);
  const credential = canonicalCredential(identity.aud, clientKey, identity.serverKid, identity.serverPublicKey, identity.url);
  if (credential.length > MAX_USER_KEY_DOCUMENT_BYTES) {
    fail("oversized_envelope", undefined, credential.length);
  }
  return new IssuedUserKeyCredential(credential, new ServerUserKey(pub));
}
