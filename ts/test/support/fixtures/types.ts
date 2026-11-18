import { fixture } from "./decode-base.js";

/** Any JSON value, exactly as JSON.parse can produce. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

/** Builder form of a readonly fixture type: optional fields are assigned after decoding. */
export type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** One entry of keys.json. Test only: seeds are derived from public strings. */
export interface TestKey {
  readonly name: string;
  readonly seedHex: string;
  readonly publicKey: string;
  readonly kid: string;
}

/** KeyFile is keys.json. */
export interface KeyFile {
  readonly note: string;
  readonly keys: readonly TestKey[];
}

/** One key of a registry document; admin is a strict boolean when present and validity bounds may be omitted or null (unbounded). */
export interface RegistryEntry {
  readonly kid: string;
  readonly publicKey: string;
  readonly name: string;
  /** Absent means not an admin (false); when present it must be exactly true or false. */
  readonly admin?: boolean;
  readonly notBefore?: number | null;
  readonly notAfter?: number | null;
}

/** RegistryDocument is registry.json. */
export interface RegistryDocument {
  readonly version: number;
  readonly aud: string;
  readonly keys: readonly RegistryEntry[];
}

/** One [name, value] pair; the list form keeps repeated headers representable. */
export interface HeaderPair {
  readonly name: string;
  readonly value: string;
}

/** A pre-seeded (kid, nonce) cache entry in a case state. */
export interface NonceCacheEntry {
  readonly kid: string;
  readonly nonce: string;
  readonly retainUntil: number;
}

/** RequestState is the per-case state of request vectors. */
export interface RequestState {
  readonly now: number;
  readonly windowSeconds: number;
  readonly aud: string;
  readonly nonceCache: readonly NonceCacheEntry[];
}

/** FixtureRequest is the HTTP request under test; bodyText is informative only, bodyB64u is the exact signed bytes. */
export interface FixtureRequest {
  readonly method: string;
  readonly target: string;
  readonly headers: readonly HeaderPair[];
  readonly bodyB64u: string;
  readonly bodyText?: string;
}

/** AuditExpect is the expected audit record for protocol-native tool calls. */
export interface AuditExpect {
  readonly tool: string;
  readonly outcome: string;
  readonly code?: string | null;
  readonly actorKid: string;
}

/** AfterUser is one entry of an after.users expectation: the FULL durable user entry, admin and bounds always present. */
export interface AfterUser {
  readonly kid: string;
  readonly publicKey: string;
  readonly name: string;
  readonly admin: boolean;
  readonly notBefore: number | null;
  readonly notAfter: number | null;
}

/** AfterInvite is one entry of an after.invites expectation: a full invite record; key_ttl_seconds is absent when unset, never null. */
export interface AfterInvite {
  readonly inviteId: string;
  readonly admin: boolean;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly keyTtlSeconds?: number;
}

/** AfterState is the full durable state after a sequence step ran. */
export interface AfterState {
  readonly users: readonly AfterUser[];
  readonly invites: readonly AfterInvite[];
}

/** Expect is the shared outcome expectation; structured stays raw JSON because its shape varies per tool.
 *
 * identity is the frozen {kid, name, admin} snapshot a forwarded accept hands to the wrapped
 * handler; kid/http_status/code carry an explicit JSON null in fixtures where they do not apply,
 * and a null decodes as ABSENT here. audit keeps code as string|null: null means the event has
 * no code field, which is asserted, not dropped.
 */
export interface Expect {
  readonly result: string;
  readonly kid?: string;
  readonly structured?: JsonValue;
  readonly identity?: { readonly kid: string; readonly name: string; readonly admin: boolean };
  readonly httpStatus?: number;
  readonly code?: string;
  readonly audit?: AuditExpect;
  readonly nonceRecorded?: boolean;
  readonly after?: AfterState;
}

/** Debug carries the signing string the generator signed, line by line. */
export interface Debug {
  readonly signingStringLines: readonly string[];
}

/** RequestCase is one single-request vector. */
export interface RequestCase {
  readonly id: string;
  readonly description?: string;
  readonly state: RequestState;
  readonly request: FixtureRequest;
  readonly expect: Expect;
  readonly debug: Debug;
}

/** RequestVectors is request-vectors.json. */
export interface RequestVectors {
  readonly registry: string;
  readonly cases: readonly RequestCase[];
}

/** InviteRecord is a stored invite in a sequence state; keyTtlSeconds is absent when unset, never null. */
export interface InviteRecord {
  readonly inviteId: string;
  /** Absent means not an admin invite (false); strict boolean when present. */
  readonly admin?: boolean;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly keyTtlSeconds?: number;
}

/** SequenceState is the initial state of an admin sequence case. */
export interface SequenceState extends RequestState {
  readonly registry: readonly RegistryEntry[];
  readonly invites: readonly InviteRecord[];
}

/** Step is one request of a sequence; steps share state in order. */
export interface Step {
  readonly request: FixtureRequest;
  readonly expect: Expect;
  readonly debug: Debug;
}

/** AdminCase is one ordered sequence of state-changing requests. */
export interface AdminCase {
  readonly id: string;
  readonly description?: string;
  readonly state: SequenceState;
  readonly steps: readonly Step[];
}

/** AdminVectors is admin-vectors.json. */
export interface AdminVectors {
  readonly cases: readonly AdminCase[];
}

/** ResponseState is the per-case state of response vectors. */
export interface ResponseState {
  readonly now: number;
  readonly windowSeconds: number;
  readonly pinnedServerKid: string;
  readonly pinnedServerPublicKey: string;
  readonly requestSig: string;
}

/** FixtureResponse is the signed response under test. */
export interface FixtureResponse {
  readonly status: number;
  readonly headers: readonly HeaderPair[];
  readonly bodyB64u: string;
  readonly bodyText?: string;
}

/** ResponseExpect is the outcome expectation of a response case. */
export interface ResponseExpect {
  readonly result: string;
  readonly code?: string;
}

/** ResponseCase is one client-side response verification vector. */
export interface ResponseCase {
  readonly id: string;
  readonly description?: string;
  readonly state: ResponseState;
  readonly response: FixtureResponse;
  readonly expect: ResponseExpect;
}

/** ResponseVectors is response-vectors.json. */
export interface ResponseVectors {
  readonly cases: readonly ResponseCase[];
}

/** KeyCase is one strict-Ed25519 public-key validity vector. */
export interface KeyCase {
  readonly id: string;
  readonly publicKeyHex: string;
  readonly expect: string;
  readonly reason?: string;
}

/** KeyVectors is key-vectors.json. */
export interface KeyVectors {
  readonly cases: readonly KeyCase[];
}

/** LoadCase is one load-time validation vector; document stays raw JSON because the invalid cases are intentionally untypeable. */
export interface LoadCase {
  readonly id: string;
  readonly document: JsonValue;
  readonly expect: string;
  readonly reason?: string;
}

/** LoadVectors is load-vectors.json. */
export interface LoadVectors {
  readonly registries: readonly LoadCase[];
}

/** StateFileCase is one state-file load-time validation vector; document stays raw JSON because the invalid cases are intentionally untypeable. */
export interface StateFileCase {
  readonly id: string;
  readonly document: JsonValue;
  readonly expect: string;
  readonly reason?: string;
}

/** StateFileVectors is state-file-vectors.json. */
export interface StateFileVectors {
  readonly cases: readonly StateFileCase[];
}
