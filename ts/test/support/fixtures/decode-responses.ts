import { type JsonValue, type Mutable, type ResponseState, type FixtureResponse, type ResponseExpect, type ResponseCase, type ResponseVectors, type KeyCase, type KeyVectors, type LoadCase, type LoadVectors, type StateFileCase, type StateFileVectors } from "./types.js";
import { asObject, rejectUnknownKeys, requireField, asString, asInt, asArray, optString, asHeaders } from "./decode-base.js";


export function decodeResponseState(entry: JsonValue, what: string): ResponseState {
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

export function decodeFixtureResponse(entry: JsonValue, what: string): FixtureResponse {
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

export function decodeResponseExpect(entry: JsonValue, what: string): ResponseExpect {
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

export function decodeResponseCase(entry: JsonValue, what: string): ResponseCase {
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

export function decodeResponseVectors(entry: JsonValue, what: string): ResponseVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeResponseCase(item, `${what}.cases[${index}]`),
    ),
  };
}

export function decodeKeyCase(entry: JsonValue, what: string): KeyCase {
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

export function decodeKeyVectors(entry: JsonValue, what: string): KeyVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeKeyCase(item, `${what}.cases[${index}]`),
    ),
  };
}

export function decodeLoadCase(entry: JsonValue, what: string): LoadCase {
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

export function decodeLoadVectors(entry: JsonValue, what: string): LoadVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["registries"], what);
  return {
    registries: asArray(requireField(obj, "registries", what), `${what}.registries`).map((item, index) =>
      decodeLoadCase(item, `${what}.registries[${index}]`),
    ),
  };
}

export function decodeStateFileCase(entry: JsonValue, what: string): StateFileCase {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["id", "document", "expect", "reason"], what);
  const decoded: Mutable<StateFileCase> = {
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

export function decodeStateFileVectors(entry: JsonValue, what: string): StateFileVectors {
  const obj = asObject(entry, what);
  rejectUnknownKeys(obj, ["cases"], what);
  return {
    cases: asArray(requireField(obj, "cases", what), `${what}.cases`).map((item, index) =>
      decodeStateFileCase(item, `${what}.cases[${index}]`),
    ),
  };
}