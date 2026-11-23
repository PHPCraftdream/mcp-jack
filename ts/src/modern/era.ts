/**
 * C9 of spec 04 section 6 (MCP 2026-07-28): era detection from the verified
 * response only. Port of `parseBody`, `recognisedError` and `detectEra` in
 * `spec/tools/modern/headers/reference/client.mjs`.
 */

/** The era a client speaks (spec 04 C9): the 0.1.x wire, the modern wire, or one detected per origin from a verified probe. */
export type ClientEra = "legacy" | "modern" | "auto";

/** What the verified response says about which era the endpoint speaks. */
export type EraSignal = "modern" | "legacy" | "none";

/** What the client does next, given the era signal. */
export type EraAction = "stay_modern" | "fallback_initialize" | "retry_with_supported" | "abort";

/** Why the era signal and action were chosen; null where nothing needed explaining. */
export type EraReason =
  | "unverified"
  | "no_modern_error"
  | "jack_envelope"
  | "modern_method_not_found"
  | "unsupported_version_no_overlap"
  | "no_era_signal";

/** The outcome of era detection: the signal, the next action, the reason and, for a version retry, the mutual versions. */
export interface EraDetection {
  readonly era: EraSignal;
  readonly action: EraAction;
  readonly reason: EraReason | null;
  readonly supported?: readonly string[];
}

/** The parts of a probe response that era detection reads: verification, status and the body text of a 400 or 404. */
export interface EraProbe {
  readonly verified: boolean;
  readonly status: number;
  readonly bodyText?: string;
}

/** JSON-RPC error codes that signal the modern era: unsupported protocol version, missing client capabilities and unsupported version with a server list. */
export const MODERN_ERA_ERROR_CODES: readonly number[] = [-32020, -32021, -32022];

/** The version-mismatch code whose `error.data.supported` list can be retried against. */
const UNSUPPORTED_VERSION_CODE = -32022;

/** The JSON-RPC method-not-found code, a modern signal only on a 404. */
const METHOD_NOT_FOUND_CODE = -32601;

/** True for a non-null, non-array object, the only shapes that carry a JSON-RPC member. */
function isContainer(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A body that is missing, empty, non-JSON or not an object carries no signal. */
function parseBody(text: string | undefined): Record<string, unknown> | null {
  if (typeof text !== "string" || text.trim() === "") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return null;
  }
  return isContainer(parsed) ? parsed : null;
}

/** True for an array whose every element is a string; a mixed or non-array value is not a usable list. */
function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((element) => typeof element === "string");
}

/** Reads `error.data.supported` the way optional chaining does: absent data, or data that is not an object, yields undefined. */
function readSupported(data: unknown): unknown {
  if (data === null || (typeof data !== "object" && typeof data !== "function")) return undefined;
  return (data as Record<string, unknown>)["supported"];
}

/**
 * A recognised JSON-RPC error: jsonrpc "2.0", an id member (null allowed) and an
 * error object with an integer code and a string message. Anything else is not a
 * signal: a bare {"error":{"code":...}} object is what a legacy endpoint or an
 * intermediary can produce.
 */
function recognisedError(text: string | undefined): { readonly code: number; readonly data: unknown } | null {
  const body = parseBody(text);
  if (body === null || body["jsonrpc"] !== "2.0") return null;
  if (!Object.hasOwn(body, "id")) return null;
  const id = body["id"];
  const idType = typeof id;
  if (!(id === null || idType === "string" || idType === "number")) return null;
  const error = body["error"];
  if (!isContainer(error)) return null;
  const code = error["code"];
  if (typeof code !== "number" || !Number.isInteger(code)) return null;
  if (typeof error["message"] !== "string") return null;
  return { code, data: error["data"] };
}

/** C9: era detection from the verified response only. */
export function detectEra(probe: EraProbe, clientVersions: readonly string[]): EraDetection {
  if (probe.verified !== true) return { era: "none", action: "abort", reason: "unverified" };
  const status = probe.status;
  if (status >= 200 && status <= 299) return { era: "modern", action: "stay_modern", reason: null };
  if (status === 400) {
    const error = recognisedError(probe.bodyText);
    if (error !== null && MODERN_ERA_ERROR_CODES.includes(error.code)) {
      if (error.code !== UNSUPPORTED_VERSION_CODE) return { era: "modern", action: "stay_modern", reason: null };
      const supported = readSupported(error.data);
      // A usable list is an array whose elements are all strings; a mixed array, a
      // non-array, an empty array or a missing member is not usable at all.
      const usable = isStringArray(supported) ? supported : [];
      const mutual = usable.filter((version) => clientVersions.includes(version));
      return mutual.length > 0
        ? { era: "modern", action: "retry_with_supported", reason: null, supported: mutual }
        : { era: "modern", action: "abort", reason: "unsupported_version_no_overlap" };
    }
    const body = parseBody(probe.bodyText);
    const errorMember = body === null ? null : body["error"];
    // Jack's own envelope has no jsonrpc member at all; a body that carries one
    // (any value, including "1.0") is not Jack's envelope.
    const jackEnvelope =
      body !== null &&
      isContainer(errorMember) &&
      typeof errorMember["code"] === "string" &&
      !Object.hasOwn(body, "jsonrpc");
    return { era: "legacy", action: "fallback_initialize", reason: jackEnvelope ? "jack_envelope" : "no_modern_error" };
  }
  if (status === 404) {
    const error = recognisedError(probe.bodyText);
    if (error !== null && error.code === METHOD_NOT_FOUND_CODE) {
      return { era: "modern", action: "stay_modern", reason: "modern_method_not_found" };
    }
    return { era: "legacy", action: "fallback_initialize", reason: "no_modern_error" };
  }
  if (status === 405) return { era: "legacy", action: "fallback_initialize", reason: "no_modern_error" };
  return { era: "none", action: "abort", reason: "no_era_signal" };
}
