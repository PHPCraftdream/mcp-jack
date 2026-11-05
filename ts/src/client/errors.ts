/** Client-facing error types mirroring the error envelopes of spec 01 section 5 and JSON-RPC (port of Go client/errors.go). */

/** HTTPError reports a non-2xx response whose verified body carried {"error":{code,message}}. */
export class HTTPError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = "HTTPError";
  }
}

/** RPCError reports the JSON-RPC error member of an otherwise successful call. */
export class RPCError extends Error {
  readonly code: number;
  /** Undefined when the error member carried no data. */
  readonly data: unknown;

  constructor(code: number, message: string, data: unknown) {
    super(message);
    this.code = code;
    this.data = data;
    this.name = "RPCError";
  }
}

/** ToolError reports an MCP result with isError true. */
export class ToolError extends Error {
  /** Undefined when the result carried no structuredContent. */
  readonly structured: unknown;

  constructor(message: string, structured: unknown) {
    super(message);
    this.structured = structured;
    this.name = "ToolError";
  }
}

/** Whether v is a JSON string. */
function isString(v: unknown): v is string {
  return typeof v === "string";
}

/**
 * Tolerant decode of {"error":{"code":string,"message":string}}: unparsable
 * JSON or a non-object `error` yields both fields empty; otherwise code and
 * message each fall back to "" independently. (Go's typed decode fails the
 * whole body when either field has the wrong type, yielding both empty — a
 * deliberate divergence kept here so one bad field never hides the other.)
 */
export function parseErrorBody(body: Uint8Array): { code: string; message: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return { code: "", message: "" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { code: "", message: "" };
  }
  const error = (parsed as { readonly [key: string]: unknown })["error"];
  if (typeof error !== "object" || error === null || Array.isArray(error)) {
    return { code: "", message: "" };
  }
  const record = error as { readonly [key: string]: unknown };
  const code = record["code"];
  const message = record["message"];
  return {
    code: isString(code) ? code : "",
    message: isString(message) ? message : "",
  };
}
