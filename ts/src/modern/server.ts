/**
 * Server rules S1-S12 of the modern profile of spec 04 section 5 (MCP
 * 2026-07-28): the era decision and the mirror-header checks of one request.
 * Port of `classifyRequest` in
 * `spec/tools/modern/headers/reference/server.mjs`; the fixed refusal messages
 * are transcribed from `spec/tools/modern/headers/spec-data.mjs`.
 *
 * The request is already authenticated and its body already acceptable under
 * spec 02 section 2, so anything else is a caller bug, not an outcome.
 */

import { parseJsonRaw } from "../core/json-raw.js";
import type { JsonValue, RawJsonNode } from "../core/json-raw.js";
import { decodeHeaderValue, isFieldValue, isModernVersion, isVersion, nameSourceOf } from "./values.js";
import type { HeaderPair } from "./values.js";

/** Which eras a server accepts: the legacy path only, the modern path only, or both with the S3 signal deciding. */
export type ServerProfile = "legacy" | "modern" | "both";

/** Every server profile, in the order the spec names them. */
export const SERVER_PROFILES: readonly ServerProfile[] = ["legacy", "modern", "both"];

/** Jack's implementation name and version, reported in `result._meta["io.modelcontextprotocol/serverInfo"]` (spec 04 C7). */
export const JACK_SERVER_INFO: { readonly name: string; readonly version: string } = { name: "mcp-jack", version: "0.1.0" };

/** The closed list of fixed reasons a modern-era request can be refused. */
export type ModernRefusalReason =
  | "method_not_allowed"
  | "header_value_invalid"
  | "header_repeated"
  | "version_header_missing"
  | "version_header_malformed"
  | "version_meta_missing"
  | "version_mismatch"
  | "method_header_missing"
  | "method_header_mismatch"
  | "name_header_not_applicable"
  | "name_source_missing"
  | "name_header_missing"
  | "name_header_bad_encoding"
  | "name_header_mismatch";

/** One row of the refusal table: the HTTP status, the JSON-RPC error code and the verbatim message. */
export interface ModernRefusalTableEntry {
  /** The HTTP status a refusal with this reason is answered with. */
  readonly httpStatus: number;
  /** The JSON-RPC error code written into the refusal body. */
  readonly code: number;
  /** The fixed error message; no trailing period, no echoed value. */
  readonly message: string;
}

/** The refusal table of section 5.1, verbatim: one row per reason. */
export const MODERN_REFUSALS: Readonly<Record<ModernRefusalReason, ModernRefusalTableEntry>> = {
  method_not_allowed: {
    httpStatus: 405,
    code: -32600,
    message: "HTTP method not allowed",
  },
  header_value_invalid: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax",
  },
  header_repeated: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: a request metadata header appears more than once",
  },
  version_header_missing: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: MCP-Protocol-Version is missing",
  },
  version_header_malformed: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: MCP-Protocol-Version is malformed",
  },
  version_meta_missing: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: params._meta protocolVersion is missing",
  },
  version_mismatch: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion",
  },
  method_header_missing: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Method is missing",
  },
  method_header_mismatch: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Method does not match the body method",
  },
  name_header_not_applicable: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Name is not defined for this method",
  },
  name_source_missing: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: the body has no string value for the Mcp-Name source field",
  },
  name_header_missing: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Name is missing",
  },
  name_header_bad_encoding: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Name is not a valid base64 sentinel encoding",
  },
  name_header_mismatch: {
    httpStatus: 400,
    code: -32020,
    message: "Header mismatch: Mcp-Name does not match the body value",
  },
};

/** The fixed message of the classification refusal of spec 02 section 2 item 4. */
export const INVALID_TOOL_NAME_MESSAGE = "tools/call requires a string params.name";

/** One inbound request as the server sees it: the offered profile, the method, target, headers and the raw body text. */
export interface ModernRequestInput {
  /** The profile the server offers; `both` lets the S3 signal choose the era. */
  readonly profile: ServerProfile;
  /** The HTTP method of the request. */
  readonly method: string;
  /** The request target, forwarded unchanged. */
  readonly target: string;
  /** The header fields in received order and casing. */
  readonly headers: readonly (readonly [string, string])[];
  /** The raw body text; absent or empty means there is no body. */
  readonly bodyText?: string;
}

/** A request the server forwards downstream: method, target and the (filtered) header list. */
export interface ModernForward {
  /** The HTTP method, unchanged. */
  readonly method: string;
  /** The request target, unchanged. */
  readonly target: string;
  /** The forwarded header fields, in received order and casing. */
  readonly headers: readonly (readonly [string, string])[];
}

/** The outcome of classifying one request: forwarded in an era, refused by a section 5 rule, or refused at classification. */
export type ModernRequestDecision =
  | { readonly outcome: "forward"; readonly era: "legacy" | "modern"; readonly forward: ModernForward }
  | {
      readonly outcome: "refuse";
      readonly era: "modern";
      readonly httpStatus: number;
      readonly code: number;
      readonly message: string;
      readonly allowPost: boolean;
      readonly idText: string;
    }
  | {
      readonly outcome: "refuse_invalid_request";
      readonly httpStatus: 400;
      readonly code: "invalid_request";
      readonly message: string;
    };

/** The `_meta` key carrying the protocol version (spec 04 section 4, M). */
const META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";

/** The three headers that mirror a body field; a duplicate of any of them is S1. */
const MIRROR_NAMES: readonly string[] = ["mcp-protocol-version", "mcp-method", "mcp-name"];

/** The lowercased prefix of a recognised `Mcp-Param-{Name}` header. */
const PARAM_PREFIX = "mcp-param-";

/** Headers that never reach the handler in the modern era (S8). */
const SESSION_HEADER = "mcp-session-id";
const RESUME_HEADER = "last-event-id";

/** The caller-bug message for a body that is not a JSON-RPC object. */
const BODY_ERROR = "modern profile: the body is not an acceptable JSON-RPC object";

/** The caller-bug message for a modern POST without a body. */
const NO_BODY_ERROR = "modern profile: the modern era requires a classified body";

/** A plain JSON object view: the only shape an own member is read from. */
type JsonObjectView = { readonly [key: string]: JsonValue };

/** The parsed body: its kind, its string method (only for request/notification), its id text and its object. */
type BodyView =
  | { readonly kind: "none"; readonly method: undefined; readonly idText: "null"; readonly obj: undefined }
  | { readonly kind: "response"; readonly method: undefined; readonly idText: "null"; readonly obj: JsonObjectView }
  | { readonly kind: "request"; readonly method: string; readonly idText: string; readonly obj: JsonObjectView }
  | { readonly kind: "notification"; readonly method: string; readonly idText: "null"; readonly obj: JsonObjectView };

/** True for a plain JSON object: non-null, not an array. */
function isPlainObject(value: JsonValue | undefined): value is JsonObjectView {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** An own member of a plain object, or undefined; a prototype member never counts. */
function ownMember(obj: JsonObjectView | undefined, key: string): JsonValue | undefined {
  if (obj === undefined || !Object.hasOwn(obj, key)) return undefined;
  return obj[key];
}

/** The own `params` object of a body, when it is a plain object. */
function paramsOf(obj: JsonObjectView): JsonObjectView | undefined {
  const params = ownMember(obj, "params");
  return isPlainObject(params) ? params : undefined;
}

/**
 * Step 1 and step 2: parse the body text into a {@link BodyView}. No body is
 * kind `none`; a missing string `method` is a response; a present `id` member
 * makes it a request (JSON-RPC 2.0: a notification has no `id` member at all),
 * anything else a notification. S10: the request id text is the raw source text
 * of the top-level `id` member when that id is a string or an integer, and
 * `"null"` for any other id, a fractional number included.
 */
function readBody(bodyText: string | undefined): BodyView {
  if (bodyText === undefined || bodyText === "") {
    return { kind: "none", method: undefined, idText: "null", obj: undefined };
  }
  let source: RawJsonNode;
  try {
    source = parseJsonRaw(bodyText).source;
  } catch {
    throw new Error(BODY_ERROR);
  }
  const root = source.value;
  if (!isPlainObject(root)) throw new Error(BODY_ERROR);
  const method = ownMember(root, "method");
  if (typeof method !== "string") {
    return { kind: "response", method: undefined, idText: "null", obj: root };
  }
  // JSON-RPC 2.0: a notification is a request object WITHOUT an `id` member, so
  // any present `id` (the JSON null included) makes the body a request.
  const idNode = source.members?.get("id");
  if (idNode === undefined) {
    return { kind: "notification", method, idText: "null", obj: root };
  }
  // S10: a refusal echoes a string or integer id and answers null for any
  // other id, so a fractional or non-scalar id never leaks into the body.
  const scalar = typeof idNode.value === "string"
    || (typeof idNode.value === "number" && Number.isInteger(idNode.value));
  return { kind: "request", method, idText: scalar ? idNode.text : "null", obj: root };
}

/**
 * M: the version member of `params._meta`, read only for request and
 * notification bodies and only from plain objects; a non-string counts as
 * absent. A root-level `_meta` is never a mirror.
 */
function metaVersion(body: BodyView): string | null {
  if (body.kind !== "request" && body.kind !== "notification") return null;
  const params = paramsOf(body.obj);
  if (params === undefined) return null;
  const meta = ownMember(params, "_meta");
  if (!isPlainObject(meta)) return null;
  const value = ownMember(meta, META_VERSION_KEY);
  return typeof value === "string" ? value : null;
}

/**
 * S1-S12 of spec 04 section 5: classify one request. The era decision (S3)
 * runs first; the legacy era forwards unchanged, and every later rule runs
 * only in the modern era, in reference order.
 *
 * A non-POST request has no body, so — spec 04 section 3, "Non-POST under
 * `both`: there is no body, so only `H` counts" — its body text is NEVER read
 * or parsed: classification never throws on a non-JSON body, the era-neutral
 * `tools/call` classification refusal never applies to it, the era comes from
 * the `MCP-Protocol-Version` header alone (no `_meta`), `S1` still runs and
 * `S2` refuses it with `method_not_allowed`, `idText` "null" and
 * `allowPost: true`.
 *
 * A POST body that is not a JSON-RPC object, or a modern POST without a body,
 * is a caller bug and throws.
 */
export function classifyModernRequest(input: ModernRequestInput): ModernRequestDecision {
  const find = (name: string): readonly HeaderPair[] => input.headers.filter(([n]) => n.toLowerCase() === name);
  const refuse = (reason: ModernRefusalReason, idText: string, allowPost: boolean): ModernRequestDecision => {
    const entry = MODERN_REFUSALS[reason];
    return {
      outcome: "refuse",
      era: "modern",
      httpStatus: entry.httpStatus,
      code: entry.code,
      message: entry.message,
      allowPost,
      idText,
    };
  };
  const forward = (era: "legacy" | "modern", headers: readonly HeaderPair[]): ModernRequestDecision => ({
    outcome: "forward",
    era,
    forward: { method: input.method, target: input.target, headers },
  });

  // A non-POST request carries no body in the modern rules (spec 04 section
  // 3): it is never read or parsed, so a non-JSON body cannot make this throw
  // and the classification refusal below never applies to it.
  const nonPost = input.method !== "POST";
  const body: BodyView = nonPost
    ? { kind: "none", method: undefined, idText: "null", obj: undefined }
    : readBody(input.bodyText);

  // Spec 02 section 2 item 4 runs before any rule of section 5: a tools/call
  // whose params.name is not a string is refused era-neutrally at classification.
  if (
    (body.kind === "request" || body.kind === "notification") &&
    body.method === "tools/call" &&
    typeof ownMember(paramsOf(body.obj), "name") !== "string"
  ) {
    return {
      outcome: "refuse_invalid_request",
      httpStatus: 400,
      code: "invalid_request",
      message: INVALID_TOOL_NAME_MESSAGE,
    };
  }

  // S3 runs first: any well-formed modern version in a header instance or in
  // the _meta version selects the modern era; ambiguity never buys legacy.
  const versions = find("mcp-protocol-version");
  const meta = metaVersion(body);
  let era: "legacy" | "modern";
  if (input.profile === "legacy") era = "legacy";
  else if (input.profile === "modern") era = "modern";
  else era = versions.some(([, value]) => isModernVersion(value)) || isModernVersion(meta) ? "modern" : "legacy";

  // Legacy era: spec 01 and 02 apply byte-identically, so the header list is
  // forwarded unfiltered.
  if (era === "legacy") return forward("legacy", input.headers);

  if (body.kind === "none" && input.method === "POST") {
    // A POST always has a body: spec 02 section 2 refuses an unacceptable one first.
    throw new Error(NO_BODY_ERROR);
  }

  // S1: header syntax, modern era only.
  for (const name of MIRROR_NAMES) {
    if (find(name).length > 1) return refuse("header_repeated", body.idText, false);
  }
  for (const [name, value] of input.headers) {
    const lower = name.toLowerCase();
    // "mcp-param-" alone has an empty {Name}, so it is not a recognised header.
    const recognisedParam = lower.startsWith(PARAM_PREFIX) && lower.length > PARAM_PREFIX.length;
    if (!MIRROR_NAMES.includes(lower) && !recognisedParam) continue;
    if (!isFieldValue(value)) return refuse("header_value_invalid", body.idText, false);
  }

  // S2: only POST is defined by the modern era.
  if (input.method !== "POST") return refuse("method_not_allowed", "null", true);

  const isRequest = body.kind === "request";

  // S12: a client-sent response object has no mirror obligation.
  if (body.kind !== "none" && body.kind !== "response") {
    const version = versions.length === 0 ? undefined : versions[0]?.[1];
    if (version === undefined) {
      if (isRequest) return refuse("version_header_missing", body.idText, false);
    } else {
      if (!isVersion(version)) return refuse("version_header_malformed", body.idText, false);
      if (meta === null) return refuse("version_meta_missing", body.idText, false);
      if (version !== meta) return refuse("version_mismatch", body.idText, false);
    }

    const methods = find("mcp-method");
    const methodHeader = methods.length === 0 ? undefined : methods[0]?.[1];
    if (methodHeader === undefined) {
      if (isRequest) return refuse("method_header_missing", body.idText, false);
    } else if (methodHeader !== body.method) {
      return refuse("method_header_mismatch", body.idText, false);
    }

    // S6: the source table is closed, so a method without a row must not carry
    // the header.
    const names = find("mcp-name");
    const source = nameSourceOf(body.method);
    if (source === null) {
      if (names.length > 0) return refuse("name_header_not_applicable", body.idText, false);
    } else {
      const sourceValue = ownMember(paramsOf(body.obj), source);
      // The mirror cannot be validated without a string source value.
      if (typeof sourceValue !== "string") return refuse("name_source_missing", body.idText, false);
      const nameHeader = names.length === 0 ? undefined : names[0]?.[1];
      if (nameHeader === undefined) {
        if (isRequest) return refuse("name_header_missing", body.idText, false);
      } else {
        const decoded = decodeHeaderValue(nameHeader);
        if (!decoded.ok) return refuse("name_header_bad_encoding", body.idText, false);
        if (decoded.text !== sourceValue) return refuse("name_header_mismatch", body.idText, false);
      }
    }
  }

  // S8: session and resume headers never reach the handler in the modern era.
  const forwardHeaders = input.headers.filter(([name]) => {
    const lower = name.toLowerCase();
    return lower !== SESSION_HEADER && lower !== RESUME_HEADER;
  });
  // S9: everything else forwarded unchanged, casing and order preserved.
  return forward("modern", forwardHeaders);
}

/**
 * True when any `MCP-Protocol-Version` instance (case-insensitive name) is a
 * well-formed version at or after the modern minimum; this is the S3 signal a
 * `both` profile uses.
 */
export function isModernHeaderSignal(headers: readonly (readonly [string, string])[]): boolean {
  return headers.some(([name, value]) => name.toLowerCase() === "mcp-protocol-version" && isModernVersion(value));
}

/**
 * True when the body is a plain object with string method `tools/call` and a
 * `params.name` that is not a string: the classification refusal of spec 02
 * section 2 item 4. No body or unparsable body is false.
 */
export function toolsCallNameInvalid(bodyText: string | undefined): boolean {
  if (bodyText === undefined || bodyText === "") return false;
  let source: RawJsonNode;
  try {
    source = parseJsonRaw(bodyText).source;
  } catch {
    return false;
  }
  const root = source.value;
  if (!isPlainObject(root)) return false;
  if (ownMember(root, "method") !== "tools/call") return false;
  return typeof ownMember(paramsOf(root), "name") !== "string";
}

/** The signed JSON-RPC refusal body of a section 5 refusal: the raw id text, the code and the JSON-quoted message. */
export function refusalBodyText(idText: string, code: number, message: string): string {
  return '{"jsonrpc":"2.0","id":' + idText + ',"error":{"code":' + code + ',"message":' + JSON.stringify(message) + "}}";
}

/** The spec 01 section 4 envelope body of a classification refusal: the string code and the message. */
export function envelopeBodyText(code: string, message: string): string {
  return JSON.stringify({ error: { code, message } });
}
