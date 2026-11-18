import { type JsonValue, type Mutable, type TestKey, type KeyFile, type RegistryEntry, type RegistryDocument, type NonceCacheEntry, type RequestState, type FixtureRequest, type AuditExpect, type AfterUser, type AfterInvite, type AfterState, type Expect, type Debug, type RequestCase, type RequestVectors, type InviteRecord, type SequenceState, type Step, type AdminCase, type AdminVectors } from "./types.js";
import { asObject, rejectUnknownKeys, requireField, optionalField, asString, asInt, asBool, asArray, asStringArray, optString, optInt, optBool, optObject, optNullableString, optNullableInt, asHeaders } from "./decode-base.js";

export function decodeTestKey(entry: JsonValue, what: string): TestKey {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["name", "seed_hex", "public_key", "kid"], what);
  return {
    name: asString(requireField(obj, "name", what), `${what}.name`),
    seedHex: asString(requireField(obj, "seed_hex", what), `${what}.seed_hex`),
    publicKey: asString(requireField(obj, "public_key", what), `${what}.public_key`),
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
  };
}

export function decodeKeyFile(entry: JsonValue, what: string): KeyFile {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["note", "keys"], what);
  return {
    note: asString(requireField(obj, "note", what), `${what}.note`),
    keys: asArray(requireField(obj, "keys", what), `${what}.keys`).map((item, index) =>
      decodeTestKey(item, `${what}.keys[${index}]`),
    ),
  };
}

export function decodeRegistryEntry(entry: JsonValue, what: string): RegistryEntry {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["kid", "public_key", "name", "admin", "not_before", "not_after"], what);
  const decoded: Mutable<RegistryEntry> = {
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    publicKey: asString(requireField(obj, "public_key", what), `${what}.public_key`),
    name: asString(requireField(obj, "name", what), `${what}.name`),
  };
  const admin = optBool(obj, "admin", `${what}.admin`);
  if (admin !== undefined) {
    decoded.admin = admin;
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

export function decodeRegistryDocument(entry: JsonValue, what: string): RegistryDocument {
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

export function decodeNonceCacheEntry(entry: JsonValue, what: string): NonceCacheEntry {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["kid", "nonce", "retain_until"], what);
  return {
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    nonce: asString(requireField(obj, "nonce", what), `${what}.nonce`),
    retainUntil: asInt(requireField(obj, "retain_until", what), `${what}.retain_until`),
  };
}

export function decodeRequestState(entry: JsonValue, what: string): RequestState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["now", "window_seconds", "aud", "nonce_cache"], what);
  return {
    now: asInt(requireField(obj, "now", what), `${what}.now`),
    windowSeconds: asInt(requireField(obj, "window_seconds", what), `${what}.window_seconds`),
    aud: asString(requireField(obj, "aud", what), `${what}.aud`),
    nonceCache: asArray(requireField(obj, "nonce_cache", what), `${what}.nonce_cache`).map((item, index) =>
      decodeNonceCacheEntry(item, `${what}.nonce_cache[${index}]`),
    ),
  };
}

export function decodeFixtureRequest(entry: JsonValue, what: string): FixtureRequest {
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

export function decodeAuditExpect(entry: JsonValue, what: string): AuditExpect {
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

export function decodeAfterUser(entry: JsonValue, what: string): AfterUser {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["kid", "public_key", "name", "admin", "not_before", "not_after"], what);
  return {
    kid: asString(requireField(obj, "kid", what), `${what}.kid`),
    publicKey: asString(requireField(obj, "public_key", what), `${what}.public_key`),
    name: asString(requireField(obj, "name", what), `${what}.name`),
    admin: asBool(requireField(obj, "admin", what), `${what}.admin`),
    notBefore: optNullableInt(obj, "not_before", `${what}.not_before`) ?? null,
    notAfter: optNullableInt(obj, "not_after", `${what}.not_after`) ?? null,
  };
}

export function decodeAfterInvite(entry: JsonValue, what: string): AfterInvite {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["invite_id", "admin", "created_by", "created_at", "expires_at", "key_ttl_seconds"], what);
  const decoded: Mutable<AfterInvite> = {
    inviteId: asString(requireField(obj, "invite_id", what), `${what}.invite_id`),
    admin: asBool(requireField(obj, "admin", what), `${what}.admin`),
    createdBy: asString(requireField(obj, "created_by", what), `${what}.created_by`),
    createdAt: asInt(requireField(obj, "created_at", what), `${what}.created_at`),
    expiresAt: asInt(requireField(obj, "expires_at", what), `${what}.expires_at`),
  };
  // key_ttl_seconds: absent or an integer; null is a decode error naming the field.
  const keyTtlSeconds = optInt(obj, "key_ttl_seconds", `${what}.key_ttl_seconds`);
  if (keyTtlSeconds !== undefined) {
    decoded.keyTtlSeconds = keyTtlSeconds;
  }
  return decoded;
}

export function decodeAfterState(entry: JsonValue, what: string): AfterState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["users", "invites"], what);
  return {
    users: asArray(requireField(obj, "users", what), `${what}.users`).map((item, index) =>
      decodeAfterUser(item, `${what}.users[${index}]`),
    ),
    invites: asArray(requireField(obj, "invites", what), `${what}.invites`).map((item, index) =>
      decodeAfterInvite(item, `${what}.invites[${index}]`),
    ),
  };
}

export function decodeExpect(entry: JsonValue, what: string): Expect {
  const obj = asObject(entry, what);
  rejectUnknownKeys(
    obj,
    ["result", "kid", "structured", "identity", "http_status", "code", "audit", "nonce_recorded", "after"],
    what,
  );
  const decoded: Mutable<Expect> = {
    result: asString(requireField(obj, "result", what), `${what}.result`),
  };
  // kid/http_status/code are explicit null in fixtures where they do not apply: a null decodes as ABSENT.
  const kid = optNullableString(obj, "kid", `${what}.kid`);
  if (kid !== undefined && kid !== null) {
    decoded.kid = kid;
  }
  const structured = optionalField(obj, "structured", `${what}.structured`);
  if (structured !== undefined) {
    decoded.structured = structured;
  }
  const identity = optObject(obj, "identity", `${what}.identity`);
  if (identity !== undefined) {
    decoded.identity = {
      kid: asString(requireField(identity, "kid", `${what}.identity`), `${what}.identity.kid`),
      name: asString(requireField(identity, "name", `${what}.identity`), `${what}.identity.name`),
      admin: asBool(requireField(identity, "admin", `${what}.identity`), `${what}.identity.admin`),
    };
  }
  const httpStatus = optNullableInt(obj, "http_status", `${what}.http_status`);
  if (httpStatus !== undefined && httpStatus !== null) {
    decoded.httpStatus = httpStatus;
  }
  const code = optNullableString(obj, "code", `${what}.code`);
  if (code !== undefined && code !== null) {
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

export function decodeDebug(entry: JsonValue, what: string): Debug {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["signing_string_lines"], what);
  return {
    signingStringLines: asStringArray(requireField(obj, "signing_string_lines", what), `${what}.signing_string_lines`),
  };
}

export function decodeRequestCase(entry: JsonValue, what: string): RequestCase {
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

export function decodeRequestVectors(entry: JsonValue, what: string): RequestVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["registry", "cases"], what);
  return {
    registry: asString(requireField(obj, "registry", what), `${what}.registry`),
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeRequestCase(item, `${what}.cases[${index}]`),
    ),
  };
}

export function decodeInviteRecord(entry: JsonValue, what: string): InviteRecord {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["invite_id", "admin", "created_by", "created_at", "expires_at", "key_ttl_seconds"], what);
  const decoded: Mutable<InviteRecord> = {
    inviteId: asString(requireField(obj, "invite_id", what), `${what}.invite_id`),
    createdBy: asString(requireField(obj, "created_by", what), `${what}.created_by`),
    createdAt: asInt(requireField(obj, "created_at", what), `${what}.created_at`),
    expiresAt: asInt(requireField(obj, "expires_at", what), `${what}.expires_at`),
  };
  const admin = optBool(obj, "admin", `${what}.admin`);
  if (admin !== undefined) {
    decoded.admin = admin;
  }
  // key_ttl_seconds: absent or an integer; null is a decode error naming the field.
  const keyTtlSeconds = optInt(obj, "key_ttl_seconds", `${what}.key_ttl_seconds`);
  if (keyTtlSeconds !== undefined) {
    decoded.keyTtlSeconds = keyTtlSeconds;
  }
  return decoded;
}

export function decodeSequenceState(entry: JsonValue, what: string): SequenceState {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["now", "window_seconds", "aud", "nonce_cache", "registry", "invites"], what);
  return {
    now: asInt(requireField(obj, "now", what), `${what}.now`),
    windowSeconds: asInt(requireField(obj, "window_seconds", what), `${what}.window_seconds`),
    aud: asString(requireField(obj, "aud", what), `${what}.aud`),
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

export function decodeStep(entry: JsonValue, what: string): Step {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["request", "expect", "debug"], what);
  return {
    request: decodeFixtureRequest(requireField(obj, "request", what), `${what}.request`),
    expect: decodeExpect(requireField(obj, "expect", what), `${what}.expect`),
    debug: decodeDebug(requireField(obj, "debug", what), `${what}.debug`),
  };
}

export function decodeAdminCase(entry: JsonValue, what: string): AdminCase {
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

export function decodeAdminVectors(entry: JsonValue, what: string): AdminVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeAdminCase(item, `${what}.cases[${index}]`),
    ),
  };
}