/** Strict typed loaders for the shared normative fixtures in spec/fixtures, mirroring spec/spec.go (test-only). */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Any JSON value, exactly as JSON.parse can produce. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

/** Builder form of a readonly fixture type: optional fields are assigned after decoding. */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

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

/** One key of a registry document; kind and validity bounds may be omitted or null (unbounded). */
export interface RegistryEntry {
  readonly kid: string;
  readonly publicKey: string;
  readonly name: string;
  readonly kind?: string | null;
  readonly scopes: readonly string[];
  readonly notBefore?: number | null;
  readonly notAfter?: number | null;
}

/** RegistryDocument is registry.json. */
export interface RegistryDocument {
  readonly version: number;
  readonly aud: string;
  readonly keys: readonly RegistryEntry[];
}

/** PolicyDocument is policy.json / policy-wildcard.json with rules left as raw JSON values: policy parsing is a later step. */
export interface PolicyDocument {
  readonly version: number;
  readonly rules: readonly JsonValue[];
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
  readonly policy: string;
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

/** UserSummary is one entry of an after.users expectation. */
export interface UserSummary {
  readonly name: string;
  readonly kid: string;
  readonly kind: string;
  readonly scopes: readonly string[];
  readonly notBefore?: number | null;
  readonly notAfter?: number | null;
}

/** AfterState summarizes the sequence state after a step ran. */
export interface AfterState {
  readonly users: readonly UserSummary[];
  readonly invites: number;
}

/** Expect is the shared outcome expectation; structured stays raw JSON because its shape varies per tool. */
export interface Expect {
  readonly result: string;
  readonly kid?: string;
  readonly structured?: JsonValue;
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

/** RequestVectors is request-vectors.json; policies maps a case's state.policy name to the file that holds it. */
export interface RequestVectors {
  readonly registry: string;
  readonly policies: { readonly [name: string]: string };
  readonly cases: readonly RequestCase[];
}

/** InviteRecord is a stored invite in a sequence state; keyTtlSeconds is null when the key never expires. */
export interface InviteRecord {
  readonly inviteId: string;
  readonly scopes: readonly string[];
  readonly kind?: string | null;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly keyTtlSeconds?: number | null;
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
  readonly policies: readonly LoadCase[];
  readonly registries: readonly LoadCase[];
}

/** PatternCase is one policy pattern matching vector; * matches any run of characters including none and newlines. */
export interface PatternCase {
  readonly id: string;
  readonly pattern: string;
  readonly input: string;
  readonly match: boolean;
}

/** PatternVectors is pattern-vectors.json. */
export interface PatternVectors {
  readonly cases: readonly PatternCase[];
}

let cachedRoot: string | undefined;

/** Walk up from this file (source or compiled) to the directory that contains spec/fixtures. */
function repoRoot(): string {
  if (cachedRoot !== undefined) {
    return cachedRoot;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "spec", "fixtures"))) {
      cachedRoot = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(`fixture root not found: no spec/fixtures above ${dir}`);
    }
    dir = parent;
  }
}

/** Raw access to one fixture file, mirroring Go's spec.Fixture. */
export function fixture(name: string): JsonValue {
  let text: string;
  try {
    text = readFileSync(join(repoRoot(), "spec", "fixtures", name), "utf8");
  } catch (err) {
    throw new Error(`fixture ${name}: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(text) as JsonValue;
  } catch (err) {
    throw new Error(`fixture ${name}: ${(err as Error).message}`);
  }
}

// Strict decode helpers: unknown fields, wrong types, nulls where Go rejects
// them, and missing fields are all load errors (Go's DisallowUnknownFields).

function asObject(value: JsonValue, what: string): Record<string, JsonValue> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${what}: expected a JSON object`);
  }
  return value as Record<string, JsonValue>;
}

function rejectUnknownKeys(obj: Record<string, JsonValue>, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw new Error(`${what}: unknown field "${key}"`);
    }
  }
}

function requireField(obj: Record<string, JsonValue>, key: string, what: string): JsonValue {
  if (!Object.hasOwn(obj, key)) {
    throw new Error(`${what}: missing field "${key}"`);
  }
  const value = obj[key];
  if (value === undefined) {
    throw new Error(`${what}: field "${key}" is not valid JSON`);
  }
  return value;
}

function optionalField(obj: Record<string, JsonValue>, key: string, what: string): JsonValue | undefined {
  if (!Object.hasOwn(obj, key)) {
    return undefined;
  }
  const value = obj[key];
  if (value === undefined) {
    throw new Error(`${what}: field "${key}" is not valid JSON`);
  }
  return value;
}

function asString(value: JsonValue, what: string): string {
  if (typeof value !== "string") {
    throw new Error(`${what}: expected a string`);
  }
  return value;
}

function asInt(value: JsonValue, what: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`${what}: expected an integer`);
  }
  return value;
}

function asBool(value: JsonValue, what: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${what}: expected a boolean`);
  }
  return value;
}

function asArray(value: JsonValue, what: string): readonly JsonValue[] {
  if (!Array.isArray(value)) {
    throw new Error(`${what}: expected an array`);
  }
  return value;
}

function asStringArray(value: JsonValue, what: string): readonly string[] {
  return asArray(value, what).map((item) => asString(item, `${what}[]`));
}

function optString(obj: Record<string, JsonValue>, key: string, what: string): string | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asString(value, what);
}

function optInt(obj: Record<string, JsonValue>, key: string, what: string): number | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asInt(value, what);
}

function optBool(obj: Record<string, JsonValue>, key: string, what: string): boolean | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asBool(value, what);
}

function optObject(obj: Record<string, JsonValue>, key: string, what: string): Record<string, JsonValue> | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asObject(value, what);
}

function optNullableString(obj: Record<string, JsonValue>, key: string, what: string): string | null | undefined {
  const value = optionalField(obj, key, what);
  if (value === undefined) {
    return undefined;
  }
  return value === null ? null : asString(value, what);
}

function optNullableInt(obj: Record<string, JsonValue>, key: string, what: string): number | null | undefined {
  const value = optionalField(obj, key, what);
  if (value === undefined) {
    return undefined;
  }
  return value === null ? null : asInt(value, what);
}

function asHeaderPair(entry: JsonValue, what: string): HeaderPair {
  const pair = asArray(entry, what);
  if (pair.length !== 2) {
    throw new Error(`${what}: header pair must have exactly 2 elements, got ${pair.length}`);
  }
  const name = pair[0];
  const headerValue = pair[1];
  if (typeof name !== "string" || typeof headerValue !== "string") {
    throw new Error(`${what}: header pair elements must be strings, got null`);
  }
  return { name, value: headerValue };
}

function asHeaders(value: JsonValue, what: string): readonly HeaderPair[] {
  return asArray(value, what).map((item, index) => asHeaderPair(item, `${what}[${index}]`));
}

function decodeTestKey(entry: JsonValue, what: string): TestKey {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["name", "seed_hex", "public_key", "kid"], what);
  return {
    name: asString(requireField(obj, "name", what), `${what}.name`),
    seedHex: asString(requireField(obj, "seed_hex", what), `${what}.seed_hex`),
    publicKey: asString(requireField(obj, "public_key", what), `${what}.public_key`),
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
  };
}

function decodeKeyFile(entry: JsonValue, what: string): KeyFile {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["note", "keys"], what);
  return {
    note: asString(requireField(obj, "note", what), `${what}.note`),
    keys: asArray(requireField(obj, "keys", what), `${what}.keys`).map((item, index) =>
      decodeTestKey(item, `${what}.keys[${index}]`),
    ),
  };
}

function decodeRegistryEntry(entry: JsonValue, what: string): RegistryEntry {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["kid", "public_key", "name", "kind", "scopes", "not_before", "not_after"], what);
  const decoded: Mutable<RegistryEntry> = {
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    publicKey: asString(requireField(obj, "public_key", what), `${what}.public_key`),
    name: asString(requireField(obj, "name", what), `${what}.name`),
    scopes: asStringArray(requireField(obj, "scopes", what), `${what}.scopes`),
  };
  const kind = optNullableString(obj, "kind", `${what}.kind`);
  if (kind !== undefined) {
    decoded.kind = kind;
  }
  const notBefore = optNullableInt(obj, "not_before", `${what}.not_before`);
  if (notBefore !== undefined) {
    decoded.notBefore = notBefore;
  }
  const notAfter = optNullableInt(obj, "not_after", `${what}.not_after`);
  if (notAfter !== undefined) {
    decoded.notAfter = notAfter;
  }
  return decoded;
}

function decodeRegistryDocument(entry: JsonValue, what: string): RegistryDocument {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["version", "aud", "keys"], what);
  return {
    version: asInt(requireField(obj, "version", what), `${what}.version`),
    aud: asString(requireField(obj, "aud", what), `${what}.aud`),
    keys: asArray(requireField(obj, "keys", what), `${what}.keys`).map((item, index) =>
      decodeRegistryEntry(item, `${what}.keys[${index}]`),
    ),
  };
}

function decodePolicyDocument(entry: JsonValue, what: string): PolicyDocument {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["version", "rules"], what);
  return {
    version: asInt(requireField(obj, "version", what), `${what}.version`),
    rules: asArray(requireField(obj, "rules", what), `${what}.rules`),
  };
}

function decodeNonceCacheEntry(entry: JsonValue, what: string): NonceCacheEntry {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["kid", "nonce", "retain_until"], what);
  return {
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    nonce: asString(requireField(obj, "nonce", what), `${what}.nonce`),
    retainUntil: asInt(requireField(obj, "retain_until", what), `${what}.retain_until`),
  };
}

function decodeRequestState(entry: JsonValue, what: string): RequestState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["now", "window_seconds", "aud", "policy", "nonce_cache"], what);
  return {
    now: asInt(requireField(obj, "now", what), `${what}.now`),
    windowSeconds: asInt(requireField(obj, "window_seconds", what), `${what}.window_seconds`),
    aud: asString(requireField(obj, "aud", what), `${what}.aud`),
    policy: asString(requireField(obj, "policy", what), `${what}.policy`),
    nonceCache: asArray(requireField(obj, "nonce_cache", what), `${what}.nonce_cache`).map((item, index) =>
      decodeNonceCacheEntry(item, `${what}.nonce_cache[${index}]`),
    ),
  };
}

function decodeFixtureRequest(entry: JsonValue, what: string): FixtureRequest {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["method", "target", "headers", "body_b64u", "body_text"], what);
  const decoded: Mutable<FixtureRequest> = {
    method: asString(requireField(obj, "method", what), `${what}.method`),
    target: asString(requireField(obj, "target", what), `${what}.target`),
    headers: asHeaders(requireField(obj, "headers", what), `${what}.headers`),
    bodyB64u: asString(requireField(obj, "body_b64u", what), `${what}.body_b64u`),
  };
  const bodyText = optString(obj, "body_text", `${what}.body_text`);
  if (bodyText !== undefined) {
    decoded.bodyText = bodyText;
  }
  return decoded;
}

function decodeAuditExpect(entry: JsonValue, what: string): AuditExpect {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["tool", "outcome", "code", "actor_kid"], what);
  const decoded: Mutable<AuditExpect> = {
    tool: asString(requireField(obj, "tool", what), `${what}.tool`),
    outcome: asString(requireField(obj, "outcome", what), `${what}.outcome`),
    actorKid: asString(requireField(obj, "actor_kid", what), `${what}.actor_kid`),
  };
  const code = optNullableString(obj, "code", `${what}.code`);
  if (code !== undefined) {
    decoded.code = code;
  }
  return decoded;
}

function decodeUserSummary(entry: JsonValue, what: string): UserSummary {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["name", "kid", "kind", "scopes", "not_before", "not_after"], what);
  const decoded: Mutable<UserSummary> = {
    name: asString(requireField(obj, "name", what), `${what}.name`),
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    kind: asString(requireField(obj, "kind", what), `${what}.kind`),
    scopes: asStringArray(requireField(obj, "scopes", what), `${what}.scopes`),
  };
  const notBefore = optNullableInt(obj, "not_before", `${what}.not_before`);
  if (notBefore !== undefined) {
    decoded.notBefore = notBefore;
  }
  const notAfter = optNullableInt(obj, "not_after", `${what}.not_after`);
  if (notAfter !== undefined) {
    decoded.notAfter = notAfter;
  }
  return decoded;
}

function decodeAfterState(entry: JsonValue, what: string): AfterState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["users", "invites"], what);
  return {
    users: asArray(requireField(obj, "users", what), `${what}.users`).map((item, index) =>
      decodeUserSummary(item, `${what}.users[${index}]`),
    ),
    invites: asInt(requireField(obj, "invites", what), `${what}.invites`),
  };
}

function decodeExpect(entry: JsonValue, what: string): Expect {
  const obj = asObject(entry, what);
  rejectUnknownKeys(
    obj,
    ["result", "kid", "structured", "http_status", "code", "audit", "nonce_recorded", "after"],
    what,
  );
  const decoded: Mutable<Expect> = {
    result: asString(requireField(obj, "result", what), `${what}.result`),
  };
  const kid = optString(obj, "kid", `${what}.kid`);
  if (kid !== undefined) {
    decoded.kid = kid;
  }
  const structured = optionalField(obj, "structured", `${what}.structured`);
  if (structured !== undefined) {
    decoded.structured = structured;
  }
  const httpStatus = optInt(obj, "http_status", `${what}.http_status`);
  if (httpStatus !== undefined) {
    decoded.httpStatus = httpStatus;
  }
  const code = optString(obj, "code", `${what}.code`);
  if (code !== undefined) {
    decoded.code = code;
  }
  const audit = optObject(obj, "audit", `${what}.audit`);
  if (audit !== undefined) {
    decoded.audit = decodeAuditExpect(audit, `${what}.audit`);
  }
  const nonceRecorded = optBool(obj, "nonce_recorded", `${what}.nonce_recorded`);
  if (nonceRecorded !== undefined) {
    decoded.nonceRecorded = nonceRecorded;
  }
  const after = optObject(obj, "after", `${what}.after`);
  if (after !== undefined) {
    decoded.after = decodeAfterState(after, `${what}.after`);
  }
  return decoded;
}

function decodeDebug(entry: JsonValue, what: string): Debug {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["signing_string_lines"], what);
  return {
    signingStringLines: asStringArray(requireField(obj, "signing_string_lines", what), `${what}.signing_string_lines`),
  };
}

function decodeRequestCase(entry: JsonValue, what: string): RequestCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "description", "state", "request", "expect", "debug"], what);
  const decoded: Mutable<RequestCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    state: decodeRequestState(requireField(obj, "state", what), `${what}.state`),
    request: decodeFixtureRequest(requireField(obj, "request", what), `${what}.request`),
    expect: decodeExpect(requireField(obj, "expect", what), `${what}.expect`),
    debug: decodeDebug(requireField(obj, "debug", what), `${what}.debug`),
  };
  const description = optString(obj, "description", `${what}.description`);
  if (description !== undefined) {
    decoded.description = description;
  }
  return decoded;
}

function decodeRequestVectors(entry: JsonValue, what: string): RequestVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["registry", "policies", "cases"], what);
  const policiesObj = asObject(requireField(obj, "policies", what), `${what}.policies`);
  const policies: { [name: string]: string } = {};
  for (const policyName of Object.keys(policiesObj)) {
    const fileName = policiesObj[policyName];
    if (fileName === undefined) {
      throw new Error(`${what}.policies: key "${policyName}" is not valid JSON`);
    }
    policies[policyName] = asString(fileName, `${what}.policies["${policyName}"]`);
  }
  return {
    registry: asString(requireField(obj, "registry", what), `${what}.registry`),
    policies,
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeRequestCase(item, `${what}.cases[${index}]`),
    ),
  };
}

function decodeInviteRecord(entry: JsonValue, what: string): InviteRecord {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["invite_id", "scopes", "kind", "created_by", "created_at", "expires_at", "key_ttl_seconds"], what);
  const decoded: Mutable<InviteRecord> = {
    inviteId: asString(requireField(obj, "invite_id", what), `${what}.invite_id`),
    scopes: asStringArray(requireField(obj, "scopes", what), `${what}.scopes`),
    createdBy: asString(requireField(obj, "created_by", what), `${what}.created_by`),
    createdAt: asInt(requireField(obj, "created_at", what), `${what}.created_at`),
    expiresAt: asInt(requireField(obj, "expires_at", what), `${what}.expires_at`),
  };
  const kind = optNullableString(obj, "kind", `${what}.kind`);
  if (kind !== undefined) {
    decoded.kind = kind;
  }
  const keyTtlSeconds = optNullableInt(obj, "key_ttl_seconds", `${what}.key_ttl_seconds`);
  if (keyTtlSeconds !== undefined) {
    decoded.keyTtlSeconds = keyTtlSeconds;
  }
  return decoded;
}

function decodeSequenceState(entry: JsonValue, what: string): SequenceState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["now", "window_seconds", "aud", "policy", "nonce_cache", "registry", "invites"], what);
  return {
    now: asInt(requireField(obj, "now", what), `${what}.now`),
    windowSeconds: asInt(requireField(obj, "window_seconds", what), `${what}.window_seconds`),
    aud: asString(requireField(obj, "aud", what), `${what}.aud`),
    policy: asString(requireField(obj, "policy", what), `${what}.policy`),
    nonceCache: asArray(requireField(obj, "nonce_cache", what), `${what}.nonce_cache`).map((item, index) =>
      decodeNonceCacheEntry(item, `${what}.nonce_cache[${index}]`),
    ),
    registry: asArray(requireField(obj, "registry", what), `${what}.registry`).map((item, index) =>
      decodeRegistryEntry(item, `${what}.registry[${index}]`),
    ),
    invites: asArray(requireField(obj, "invites", what), `${what}.invites`).map((item, index) =>
      decodeInviteRecord(item, `${what}.invites[${index}]`),
    ),
  };
}

function decodeStep(entry: JsonValue, what: string): Step {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["request", "expect", "debug"], what);
  return {
    request: decodeFixtureRequest(requireField(obj, "request", what), `${what}.request`),
    expect: decodeExpect(requireField(obj, "expect", what), `${what}.expect`),
    debug: decodeDebug(requireField(obj, "debug", what), `${what}.debug`),
  };
}

function decodeAdminCase(entry: JsonValue, what: string): AdminCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "description", "state", "steps"], what);
  const decoded: Mutable<AdminCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    state: decodeSequenceState(requireField(obj, "state", what), `${what}.state`),
    steps: asArray(requireField(obj, "steps", what), `${what}.steps`).map((item, index) =>
      decodeStep(item, `${what}.steps[${index}]`),
    ),
  };
  const description = optString(obj, "description", `${what}.description`);
  if (description !== undefined) {
    decoded.description = description;
  }
  return decoded;
}

function decodeAdminVectors(entry: JsonValue, what: string): AdminVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeAdminCase(item, `${what}.cases[${index}]`),
    ),
  };
}

function decodeResponseState(entry: JsonValue, what: string): ResponseState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(
    obj,
    ["now", "window_seconds", "pinned_server_kid", "pinned_server_public_key", "request_sig"],
    what,
  );
  return {
    now: asInt(requireField(obj, "now", what), `${what}.now`),
    windowSeconds: asInt(requireField(obj, "window_seconds", what), `${what}.window_seconds`),
    pinnedServerKid: asString(requireField(obj, "pinned_server_kid", what), `${what}.pinned_server_kid`),
    pinnedServerPublicKey: asString(
      requireField(obj, "pinned_server_public_key", what),
      `${what}.pinned_server_public_key`,
    ),
    requestSig: asString(requireField(obj, "request_sig", what), `${what}.request_sig`),
  };
}

function decodeFixtureResponse(entry: JsonValue, what: string): FixtureResponse {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["status", "headers", "body_b64u", "body_text"], what);
  const decoded: Mutable<FixtureResponse> = {
    status: asInt(requireField(obj, "status", what), `${what}.status`),
    headers: asHeaders(requireField(obj, "headers", what), `${what}.headers`),
    bodyB64u: asString(requireField(obj, "body_b64u", what), `${what}.body_b64u`),
  };
  const bodyText = optString(obj, "body_text", `${what}.body_text`);
  if (bodyText !== undefined) {
    decoded.bodyText = bodyText;
  }
  return decoded;
}

function decodeResponseExpect(entry: JsonValue, what: string): ResponseExpect {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["result", "code"], what);
  const decoded: Mutable<ResponseExpect> = {
    result: asString(requireField(obj, "result", what), `${what}.result`),
  };
  const code = optString(obj, "code", `${what}.code`);
  if (code !== undefined) {
    decoded.code = code;
  }
  return decoded;
}

function decodeResponseCase(entry: JsonValue, what: string): ResponseCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "description", "state", "response", "expect"], what);
  const decoded: Mutable<ResponseCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    state: decodeResponseState(requireField(obj, "state", what), `${what}.state`),
    response: decodeFixtureResponse(requireField(obj, "response", what), `${what}.response`),
    expect: decodeResponseExpect(requireField(obj, "expect", what), `${what}.expect`),
  };
  const description = optString(obj, "description", `${what}.description`);
  if (description !== undefined) {
    decoded.description = description;
  }
  return decoded;
}

function decodeResponseVectors(entry: JsonValue, what: string): ResponseVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeResponseCase(item, `${what}.cases[${index}]`),
    ),
  };
}

function decodeKeyCase(entry: JsonValue, what: string): KeyCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "public_key_hex", "expect", "reason"], what);
  const decoded: Mutable<KeyCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    publicKeyHex: asString(requireField(obj, "public_key_hex", what), `${what}.public_key_hex`),
    expect: asString(requireField(obj, "expect", what), `${what}.expect`),
  };
  const reason = optString(obj, "reason", `${what}.reason`);
  if (reason !== undefined) {
    decoded.reason = reason;
  }
  return decoded;
}

function decodeKeyVectors(entry: JsonValue, what: string): KeyVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeKeyCase(item, `${what}.cases[${index}]`),
    ),
  };
}

function decodeLoadCase(entry: JsonValue, what: string): LoadCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "document", "expect", "reason"], what);
  const decoded: Mutable<LoadCase> = {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    document: requireField(obj, "document", what),
    expect: asString(requireField(obj, "expect", what), `${what}.expect`),
  };
  const reason = optString(obj, "reason", `${what}.reason`);
  if (reason !== undefined) {
    decoded.reason = reason;
  }
  return decoded;
}

function decodeLoadVectors(entry: JsonValue, what: string): LoadVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["policies", "registries"], what);
  return {
    policies: asArray(requireField(obj, "policies", what), `${what}.policies`).map((item, index) =>
      decodeLoadCase(item, `${what}.policies[${index}]`),
    ),
    registries: asArray(requireField(obj, "registries", what), `${what}.registries`).map((item, index) =>
      decodeLoadCase(item, `${what}.registries[${index}]`),
    ),
  };
}

function decodePatternCase(entry: JsonValue, what: string): PatternCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "pattern", "input", "match"], what);
  return {
    id: asString(requireField(obj, "id", what), `${what}.id`),
    pattern: asString(requireField(obj, "pattern", what), `${what}.pattern`),
    input: asString(requireField(obj, "input", what), `${what}.input`),
    match: asBool(requireField(obj, "match", what), `${what}.match`),
  };
}

function decodePatternVectors(entry: JsonValue, what: string): PatternVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodePatternCase(item, `${what}.cases[${index}]`),
    ),
  };
}

/** keys.json. */
export function loadKeys(): KeyFile {
  return decodeKeyFile(fixture("keys.json"), "keys.json");
}

/** registry.json. */
export function loadRegistry(): RegistryDocument {
  return decodeRegistryDocument(fixture("registry.json"), "registry.json");
}

/** policy.json. */
export function loadDefaultPolicy(): PolicyDocument {
  return decodePolicyDocument(fixture("policy.json"), "policy.json");
}

/** policy-wildcard.json. */
export function loadWildcardPolicy(): PolicyDocument {
  return decodePolicyDocument(fixture("policy-wildcard.json"), "policy-wildcard.json");
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

/** pattern-vectors.json. */
export function loadPatternVectors(): PatternVectors {
  return decodePatternVectors(fixture("pattern-vectors.json"), "pattern-vectors.json");
}
