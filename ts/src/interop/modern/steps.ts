// The pinned request kinds of the matrix client (contract 4.4 and section 5):
// hand-built request bodies and mirror headers sent through the SDK signing
// fetch, which owns the signature, the deterministic nonce and the response
// verification. Nothing here signs or verifies by itself.
import { createSigningFetch, UnauthenticatedResponseError } from "../../client/transport/transport.js";
import type { SigningFetchInit } from "../../client/transport/transport.js";
import type { Signer } from "../../client/signing/signer.js";
import { verifyResponse } from "../../client/signing/auth.js";
import { parseRequestAuth } from "../../core/auth-header.js";
import { JackError } from "../../core/errors.js";
import { buildRequestMirrors } from "../../modern/request.js";
import type { JsonValue } from "../../core/json-raw.js";
import { CLIENT_INFO, TARGET_PATH, b64u, isJsonObject, ownMember } from "./common.js";
import type { Capture, Captured, Exchange, HeaderPair, Reply, Step, StepTrust, Transport } from "./wire.js";

/** Everything one request needs that the process flags supply. */
export interface SenderOptions {
  readonly origin: string; // e.g. "http://127.0.0.1:4321" (no trailing slash)
  readonly aud: string;
  readonly signer: Signer;
  readonly anchor: Uint8Array; // the pinned 32-byte server public key
  readonly clock: () => number; // reads the fixed clock file
  readonly nonce: () => Uint8Array; // the deterministic nonce source, one call per new request
  readonly transport: Transport;
}

/** One request the scenario asks for. */
export interface SendSpec {
  readonly name: string; // the step name of contract 4.4
  readonly jsonrpcMethod: string | null; // reported as jsonrpc_method; null for GET/HEAD
  readonly httpMethod: "POST" | "GET" | "HEAD";
  readonly body: string; // "" means no body
  readonly headers: readonly HeaderPair[]; // application and mirror headers, WITHOUT Jack-Auth
  readonly era: "legacy" | "modern";
}

/** One finished step: the recorded step, the classified reply, the capture and the era of the request. */
export interface SendResult {
  readonly step: Step;
  readonly reply: Reply;
  readonly capture: Capture;
  readonly era: "legacy" | "modern";
}

/** Signs and sends one new request, or replays already-sent bytes unchanged. */
export interface Sender {
  send(spec: SendSpec): Promise<SendResult>;
  replay(spec: SendSpec, source: Captured, requestSig: string | null): Promise<SendResult>;
}

/**
 * A request that never produced an HTTP answer (connection refused, reset,
 * timeout, truncated response). Before any answer in the run it is a process
 * failure (contract 4.2, exit 1); after one it is a reported `client_error`
 * step with null response members, so an earlier answer is never the verdict.
 */
export class TransportFailure extends Error {
  readonly spec: SendSpec;

  constructor(spec: SendSpec, cause: unknown) {
    super(`modern: request '${spec.name}' produced no HTTP answer: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "TransportFailure";
    this.spec = spec;
  }
}

/** The code a reply gets when the client itself could not trust the answer. */
const MISSING_AUTH = "missing_auth";

/**
 * The only response family that may lack `Jack-Auth`: a 401 carrying one of
 * these spec 01 section 5 codes (interop/modern/matrix.mjs `UNSIGNED_401_CODES`).
 * Every other unsigned response is a `client_error`.
 */
export const UNSIGNED_401_CODES: readonly string[] = [
  "missing_auth",
  "malformed_auth",
  "unsupported_version",
  "unknown_key",
  "key_inactive",
  "timestamp_out_of_window",
  "bad_signature",
  "replayed_nonce",
];

/** A JSON body as a value, or undefined when it is empty or not JSON at all. */
function parseJSON(text: string): JsonValue | undefined {
  if (text === "") return undefined;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return undefined;
  }
}

/** The first value of the header `lowerName` (already lowercased), else null; names compare case-insensitively. */
function headerValue(headers: readonly HeaderPair[], lowerName: string): string | null {
  for (const [name, value] of headers) {
    if (name.toLowerCase() === lowerName) return value;
  }
  return null;
}

/** True for the only response family that may lack `Jack-Auth`: 401 plus one of the spec 01 section 5 codes. */
export function isUnsignedRefusal(response: Exchange): boolean {
  if (response.status !== 401) return false;
  const error = ownMember(parseJSON(new TextDecoder().decode(response.body)), "error");
  if (!isJsonObject(error)) return false;
  const code = ownMember(error, "code");
  return typeof code === "string" && UNSIGNED_401_CODES.includes(code);
}

/** Every response `Jack-Auth` instance in received order; a duplicate must reach the verifier, which refuses it. */
export function jackAuthValues(headers: readonly HeaderPair[]): string[] {
  const values: string[] = [];
  for (const [name, value] of headers) if (name.toLowerCase() === "jack-auth") values.push(value);
  return values;
}

/** The `sig` of the captured request Jack-Auth header, or null when it is absent or does not parse. */
export function requestSignature(request: Captured): string | null {
  const header = headerValue(request.headers, "jack-auth");
  if (header === null) return null;
  try {
    return parseRequestAuth([header]).sig;
  } catch {
    return null;
  }
}

/** One response as the client reports it (contract 4.2): the bytes, their text and JSON, and how far the SDK trusted them. */
function buildReply(response: Exchange, trust: StepTrust, clientCode: string | null): Reply {
  const text = new TextDecoder().decode(response.body);
  return {
    status: response.status,
    headers: response.headers,
    body: response.body,
    text,
    json: parseJSON(text),
    trust,
    clientCode,
  };
}

/** One step of the result line (contract 4.2, every member present); the request members come from the wire capture. */
export function stepFrom(
  spec: { readonly name: string; readonly jsonrpcMethod: string | null; readonly era: "legacy" | "modern" },
  request: Captured,
  requestSig: string | null,
  response: Exchange,
  reply: Reply,
): Step {
  const id = ownMember(reply.json, "id");
  return {
    name: spec.name,
    http_method: request.method,
    http_target: request.target,
    jsonrpc_method: spec.jsonrpcMethod,
    http_status: response.status,
    // An absent own `id` member is reported as null, never invented.
    id: id === undefined ? null : id,
    request_headers: request.headers,
    request_body_b64u: b64u(request.body),
    request_sig: requestSig,
    response_auth: headerValue(response.headers, "jack-auth"),
    response_content_type: headerValue(response.headers, "content-type"),
    response_allow: headerValue(response.headers, "allow"),
    response_session_id: headerValue(response.headers, "mcp-session-id"),
    response_body_b64u: b64u(response.body),
  };
}

/** The JSON-RPC `method` of a captured request body, or null when the body is empty or not JSON. */
export function jsonrpcMethodOf(body: Uint8Array): string | null {
  const method = ownMember(parseJSON(new TextDecoder().decode(body)), "method");
  return typeof method === "string" ? method : null;
}

/**
 * One capture as a reply, verified with the SDK's own verifier against the
 * pinned anchor only (spec 01 section 5): a present `Jack-Auth` decides the
 * trust, the unsigned-allowed 401 family is `unsigned`, and anything else is
 * `unverified` with the client code.
 */
export function classifyCapture(options: SenderOptions, capture: Capture, requestSig: string | null): Reply {
  const values = jackAuthValues(capture.response.headers);
  if (values.length === 0) {
    return isUnsignedRefusal(capture.response)
      ? buildReply(capture.response, "unsigned", null)
      : buildReply(capture.response, "unverified", MISSING_AUTH);
  }
  try {
    verifyResponse(options.anchor, capture.response.status, values, requestSig ?? "", capture.response.body, options.clock(), 0);
    return buildReply(capture.response, "verified", null);
  } catch (err) {
    if (!(err instanceof JackError)) throw err;
    return buildReply(capture.response, "unverified", err.code);
  }
}

/**
 * The steps of one SDK-driven phase, labelled with the contract 4.4 step names
 * from the request bodies: the first `server/discover` is `probe`, a second one
 * `probe-retry`, `initialize`/`notifications/initialized` keep their names and a
 * `tools/call` is the operation `call`.
 */
export function stepsFromCaptures(
  options: SenderOptions,
  callEra: "legacy" | "modern",
  captures: readonly Capture[],
): { readonly steps: readonly Step[]; readonly lastReply: Reply | null } {
  const steps: Step[] = [];
  let discovers = 0;
  let lastReply: Reply | null = null;
  for (const capture of captures) {
    const method = jsonrpcMethodOf(capture.request.body);
    const name = method === "server/discover"
      ? (discovers++ === 0 ? "probe" : "probe-retry")
      : method === "notifications/initialized"
        ? "initialized"
        : method === "tools/call"
          ? "call"
          : (method ?? "request");
    const reply = classifyCapture(options, capture, requestSignature(capture.request));
    const era: "legacy" | "modern" = method === "server/discover" ? "modern" : method === "tools/call" ? callEra : "legacy";
    steps.push(stepFrom({ name, jsonrpcMethod: method, era }, capture.request, requestSignature(capture.request), capture.response, reply));
    lastReply = reply;
  }
  return { steps, lastReply };
}

/** Signs and sends one new request, or replays already-sent bytes unchanged. */
export function createSender(options: SenderOptions): Sender {
  // One signing fetch for the whole process: it owns the signature, the
  // deterministic nonce and the response verification of every new request.
  const signingFetch = createSigningFetch(
    {
      aud: options.aud,
      signer: options.signer,
      serverKey: options.anchor,
      clock: options.clock,
      nonceSource: options.nonce,
    },
    options.transport.fetchImpl,
  );

  const send = async (spec: SendSpec): Promise<SendResult> => {
    // The previous exchange must never be reported for this one.
    options.transport.reset();
    let caught: unknown;
    let failed = false;
    try {
      // A JSON-RPC POST carries the application header like every MCP client; a
      // body-less GET or HEAD is signed over empty bytes and carries no body.
      const headers: HeaderPair[] = spec.httpMethod === "POST"
        ? [["content-type", "application/json"], ...spec.headers]
        : [...spec.headers];
      const init: SigningFetchInit = {
        method: spec.httpMethod,
        headers: headers.map(([name, value]): [string, string] => [name, value]),
        ...(spec.body !== "" ? { body: new TextEncoder().encode(spec.body) } : {}),
      };
      const resp = await signingFetch(options.origin + TARGET_PATH, init);
      // The verified bytes; the capture already holds the same bytes.
      await resp.arrayBuffer();
    } catch (err) {
      failed = true;
      caught = err;
    }
    const capture = options.transport.last();
    // No exchange happened at all (connection refused, unresolvable host, a
    // redirect refusal before anything was sent): the caller decides whether
    // that is a process failure or a reported step (contract 4.2).
    if (capture === undefined) throw new TransportFailure(spec, failed ? caught : "no capture");
    let trust: StepTrust;
    let clientCode: string | null = null;
    if (!failed) {
      trust = "verified";
    } else if (caught instanceof UnauthenticatedResponseError) {
      // The SDK hands the unsigned 401 family over as status-only: the body is
      // trusted only when it is the spec 01 section 5 envelope the contract
      // allows to lack Jack-Auth.
      if (isUnsignedRefusal(capture.response)) {
        trust = "unsigned";
      } else {
        trust = "unverified";
        clientCode = MISSING_AUTH;
      }
    } else if (caught instanceof JackError) {
      trust = "unverified";
      clientCode = caught.code;
    } else {
      trust = "unverified";
      clientCode = MISSING_AUTH;
    }
    const reply = buildReply(capture.response, trust, clientCode);
    const step = stepFrom(spec, capture.request, requestSignature(capture.request), capture.response, reply);
    return { step, reply, capture, era: spec.era };
  };

  const replay = async (spec: SendSpec, source: Captured, requestSig: string | null): Promise<SendResult> => {
    options.transport.reset();
    let response: Exchange;
    try {
      // A replay is not a new request: the source bytes, signature and nonce go
      // on the wire unchanged and nothing is signed again (contract 2).
      response = await options.transport.exchange(options.origin + TARGET_PATH, source.method, source.headers, source.body);
    } catch (err) {
      // Without an answer there is no step to report; the caller decides whether
      // that is a process failure or a reported step (contract 4.2).
      throw new TransportFailure(spec, err);
    }
    const values = jackAuthValues(response.headers);
    let trust: StepTrust = "unverified";
    let clientCode: string | null = null;
    if (values.length > 0) {
      // The SDK's own verifier, pinned to --anchor only: no TOFU, no learned key,
      // and every instance goes in, so a duplicate is refused like the parser does.
      try {
        verifyResponse(options.anchor, response.status, values, requestSig ?? "", response.body, options.clock(), 0);
        trust = "verified";
      } catch (err) {
        if (!(err instanceof JackError)) throw err;
        clientCode = err.code;
      }
    } else if (isUnsignedRefusal(response)) {
      trust = "unsigned";
    } else {
      clientCode = MISSING_AUTH;
    }
    const reply = buildReply(response, trust, clientCode);
    const step = stepFrom(spec, source, requestSig, response, reply);
    // The replay path bypasses the signing fetch, so the capture is the source
    // request plus this answer rather than the transport slot.
    return { step, reply, capture: { request: source, response }, era: spec.era };
  };

  return { send, replay };
}

/** The JSON-RPC `id` text of a request body: inserted verbatim, so `1`, `"abc"`, `null` and `1.5` all round-trip (contract 4.1). */
export function requestBody(idText: string, method: string, params?: string): string {
  return (
    '{"jsonrpc":"2.0","id":' + idText + ',"method":' + JSON.stringify(method) + (params === undefined ? "}" : ',"params":' + params + "}")
  );
}

/** The `_meta` member text and the C2 mirror header list of one modern request (spec 04 C1/C2, contract section 5). */
export function modernMirrors(method: string, version: string, params?: JsonValue): { readonly meta: JsonValue; readonly headers: readonly HeaderPair[] } {
  const mirrors = buildRequestMirrors({
    version,
    method,
    ...(params !== undefined ? { params } : {}),
    clientInfo: CLIENT_INFO,
    clientCapabilities: {},
  });
  return { meta: mirrors.meta, headers: mirrors.headers };
}
