/**
 * Strict typed loaders for the shared normative fixtures in spec/fixtures,
 * mirroring the admin-only contract of spec/tests/README.md (test-only):
 * forwarded accepts carry the frozen verified-identity snapshot
 * (`expect.identity` = {kid, name, admin}) and every sequence step's
 * `expect.after` is the FULL durable state (users with admin/bounds always
 * present; invites as records, implementation-created ids scrubbed to
 * "<b64u43>").
 */
import { type JsonValue, type Mutable, type KeyFile, type RegistryDocument, type RequestVectors, type AdminVectors, type ResponseVectors, type KeyVectors, type LoadVectors, type StateFileVectors } from "./types.js";
import { fixture, asObject, rejectUnknownKeys, requireField, optionalField, asString, asArray, optString, optObject } from "./decode-base.js";
import { decodeKeyFile, decodeRegistryDocument, decodeRequestVectors, decodeAdminVectors } from "./decode-requests.js";
import { decodeResponseVectors, decodeKeyVectors, decodeLoadVectors, decodeStateFileVectors } from "./decode-responses.js";
export type { JsonValue, TestKey, KeyFile, RegistryEntry, RegistryDocument, HeaderPair, NonceCacheEntry, RequestState, FixtureRequest, AuditExpect, AfterUser, AfterInvite, AfterState, Expect, Debug, RequestCase, RequestVectors, InviteRecord, SequenceState, Step, AdminCase, AdminVectors, ResponseState, FixtureResponse, ResponseExpect, ResponseCase, ResponseVectors, KeyCase, KeyVectors, LoadCase, LoadVectors, StateFileCase, StateFileVectors } from "./types.js";
export { fixture } from "./decode-base.js";


/** keys.json. */
export function loadKeys(): KeyFile {
  return decodeKeyFile(fixture("keys.json"), "keys.json");
}

/** registry.json. */
export function loadRegistry(): RegistryDocument {
  return decodeRegistryDocument(fixture("registry.json"), "registry.json");
}

/** request-vectors.json. */
export function loadRequestVectors(): RequestVectors {
  return decodeRequestVectors(fixture("request-vectors.json"), "request-vectors.json");
}

/** admin-vectors.json. */
export function loadAdminVectors(): AdminVectors {
  return decodeAdminVectors(fixture("admin-vectors.json"), "admin-vectors.json");
}

/** response-vectors.json. */
export function loadResponseVectors(): ResponseVectors {
  return decodeResponseVectors(fixture("response-vectors.json"), "response-vectors.json");
}

/** key-vectors.json. */
export function loadKeyVectors(): KeyVectors {
  return decodeKeyVectors(fixture("key-vectors.json"), "key-vectors.json");
}

/** load-vectors.json. */
export function loadLoadVectors(): LoadVectors {
  return decodeLoadVectors(fixture("load-vectors.json"), "load-vectors.json");
}

/** state-file-vectors.json. */
export function loadStateFileVectors(): StateFileVectors {
  return decodeStateFileVectors(fixture("state-file-vectors.json"), "state-file-vectors.json");
}

// ---------------------------------------------------------------------------
// user-key-transfer.json (docs/design/user-keys.md section 11 shared table)
// ---------------------------------------------------------------------------

/** One entry of user-key-transfer.json; compose members stay raw because their fields vary per recipe. */
export interface UserKeyTransferCase {
  readonly id: string;
  readonly kind?: string;
  readonly envelope?: string;
  readonly note?: string;
  readonly expectClass?: string;
  readonly expectWhy?: string;
  readonly expectX?: string;
  readonly expectKid?: string;
  readonly expectAud?: string;
  readonly expectClientKid?: string;
  readonly expectServerKid?: string;
  readonly structuralOutcome?: string;
  readonly trustOutcome?: string;
  readonly compose?: { readonly [key: string]: JsonValue };
}

/** The fixed canonical byte templates a runner composes from. */
export interface UserKeyTransferTemplates {
  readonly publicEnvelope: string;
  readonly privateEnvelope: string;
  readonly clientCredential: string;
}

/** user-key-transfer.json with envelope strings exposed verbatim; composition happens in the runner. */
export interface UserKeyTransferFixtures {
  readonly note: string;
  readonly schema: string;
  readonly documentTemplates: UserKeyTransferTemplates;
  readonly positives: readonly UserKeyTransferCase[];
  readonly negatives: readonly UserKeyTransferCase[];
  readonly contextCases: readonly UserKeyTransferCase[];
}

function decodeUserKeyTransferCase(entry: JsonValue, what: string): UserKeyTransferCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(
    obj,
    [
      "id",
      "kind",
      "envelope",
      "note",
      "expect_class",
      "expect_why",
      "expect_x",
      "expect_kid",
      "expect_aud",
      "expect_client_kid",
      "expect_server_kid",
      "structural_outcome",
      "trust_outcome",
      "compose",
    ],
    what,
  );
  const decoded: Mutable<UserKeyTransferCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
  };
  const kind = optString(obj, "kind", `${what}.kind`);
  if (kind !== undefined) {
    decoded.kind = kind;
  }
  const envelope = optionalField(obj, "envelope", `${what}.envelope`);
  if (envelope !== undefined) {
    decoded.envelope = asString(envelope, `${what}.envelope`);
  }
  const note = optString(obj, "note", `${what}.note`);
  if (note !== undefined) {
    decoded.note = note;
  }
  const expectClass = optString(obj, "expect_class", `${what}.expect_class`);
  if (expectClass !== undefined) {
    decoded.expectClass = expectClass;
  }
  const expectWhy = optString(obj, "expect_why", `${what}.expect_why`);
  if (expectWhy !== undefined) {
    decoded.expectWhy = expectWhy;
  }
  const expectX = optString(obj, "expect_x", `${what}.expect_x`);
  if (expectX !== undefined) {
    decoded.expectX = expectX;
  }
  const expectKid = optString(obj, "expect_kid", `${what}.expect_kid`);
  if (expectKid !== undefined) {
    decoded.expectKid = expectKid;
  }
  const expectAud = optString(obj, "expect_aud", `${what}.expect_aud`);
  if (expectAud !== undefined) {
    decoded.expectAud = expectAud;
  }
  const expectClientKid = optString(obj, "expect_client_kid", `${what}.expect_client_kid`);
  if (expectClientKid !== undefined) {
    decoded.expectClientKid = expectClientKid;
  }
  const expectServerKid = optString(obj, "expect_server_kid", `${what}.expect_server_kid`);
  if (expectServerKid !== undefined) {
    decoded.expectServerKid = expectServerKid;
  }
  const structuralOutcome = optString(obj, "structural_outcome", `${what}.structural_outcome`);
  if (structuralOutcome !== undefined) {
    decoded.structuralOutcome = structuralOutcome;
  }
  const trustOutcome = optString(obj, "trust_outcome", `${what}.trust_outcome`);
  if (trustOutcome !== undefined) {
    decoded.trustOutcome = trustOutcome;
  }
  const compose = optObject(obj, "compose", `${what}.compose`);
  if (compose !== undefined) {
    decoded.compose = compose;
  }
  return decoded;
}

/** user-key-transfer.json. */
export function loadUserKeyTransfer(): UserKeyTransferFixtures {
  const entry = fixture("user-key-transfer.json");
  const what = "user-key-transfer.json";
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["note", "schema", "document_templates", "provenance", "positives", "negatives", "context_cases"], what);
  const templatesObj = asObject(requireField(obj, "document_templates", what), `${what}.document_templates`);
  rejectUnknownKeys(templatesObj, ["public_envelope", "private_envelope", "client_credential"], `${what}.document_templates`);
  return {
    note: asString(requireField(obj, "note", what), `${what}.note`),
    schema: asString(requireField(obj, "schema", what), `${what}.schema`),
    documentTemplates: {
      publicEnvelope: asString(requireField(templatesObj, "public_envelope", `${what}.document_templates`), `${what}.document_templates.public_envelope`),
      privateEnvelope: asString(requireField(templatesObj, "private_envelope", `${what}.document_templates`), `${what}.document_templates.private_envelope`),
      clientCredential: asString(requireField(templatesObj, "client_credential", `${what}.document_templates`), `${what}.document_templates.client_credential`),
    },
    positives: asArray(requireField(obj, "positives", what), `${what}.positives`).map((item, index) =>
      decodeUserKeyTransferCase(item, `${what}.positives[${index}]`),
    ),
    negatives: asArray(requireField(obj, "negatives", what), `${what}.negatives`).map((item, index) =>
      decodeUserKeyTransferCase(item, `${what}.negatives[${index}]`),
    ),
    contextCases: asArray(requireField(obj, "context_cases", what), `${what}.context_cases`).map((item, index) =>
      decodeUserKeyTransferCase(item, `${what}.context_cases[${index}]`),
    ),
  };
}

/** Exact UTF-8 bytes of a fixture envelope/composed string (the byte form every sink consumes). */
export function rawBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
