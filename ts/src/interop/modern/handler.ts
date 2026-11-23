// The wrapped MCP handler of the modern interop server: the fixed answer table
// of contract 3.4 and the request log of contract 3.3. Everything that is the
// SDK wrapper's job (authentication, era decision, mirror rules S1-S12,
// refusals, stripping, signing) is deliberately absent here: this handler only
// answers requests the wrapper already authenticated and dispatched, so it
// stays era-neutral apart from the profile checks the contract pins.
import { appendFileSync } from "node:fs";
import { parseJsonRaw } from "../../core/json-raw.js";
import type { JsonValue } from "../../core/json-raw.js";
import { META_PROTOCOL_VERSION } from "../../modern/request.js";
import type { ServerProfile } from "../../modern/server.js";
import { jackHeaders } from "../../server/http/fetch.js";
import { REGION_ECHO_SCHEMA, jsonText, ownMember } from "./common.js";

/** How `server/discover` refuses: contract 3.5, per process. */
export type DiscoverVersionMode = "supported" | "refuse-first" | "refuse-always";

/** Everything the handler answers from; every member is fixed by the process flags. */
export interface HandlerOptions {
  readonly profile: ServerProfile;
  readonly supportedVersions: readonly string[];
  readonly discoverVersionMode: DiscoverVersionMode;
  /** The request-log file of contract 3.3; null disables the log. */
  readonly requestLog: string | null;
}

/** The request members the answer table dispatches on; the id keeps its exact source text. */
interface ParsedRequest {
  readonly idText: string;
  readonly method: string | null;
  readonly params: JsonValue | undefined;
}

/** The one serverInfo both roles agree on (contract 3.4). */
const SERVER_INFO = '{"name":"mcp-jack-interop-modern","version":"1.0.0"}';

/** Contract 3.4 (b): the spec 01 section 4 envelope, so it never selects the modern era. */
const DISCOVER_NOT_ALLOWED =
  '{"error":{"code":"method_not_allowed","message":"server/discover is not available in the legacy profile"}}';

/**
 * Parses the body tolerantly: a body the wrapper would already have refused
 * answers as a null id with an unknown method rather than throwing.
 */
function parseRequest(text: string): ParsedRequest {
  try {
    const parsed = parseJsonRaw(text);
    // The exact source slice keeps `1`, `"abc"`, `null` and `1.5` round-tripping.
    const idText = parsed.source.members?.get("id")?.text ?? "null";
    const method = ownMember(parsed.value, "method");
    return {
      idText,
      method: typeof method === "string" ? method : null,
      params: ownMember(parsed.value, "params"),
    };
  } catch {
    return { idText: "null", method: null, params: undefined };
  }
}

/** Envelopes are composed by string so the request's raw id text round-trips. */
function envelopeResult(idText: string, resultJson: string): string {
  return `{"jsonrpc":"2.0","id":${idText},"result":${resultJson}}`;
}

function methodNotFound(idText: string): Response {
  return jsonResponse(200, `{"jsonrpc":"2.0","id":${idText},"error":{"code":-32601,"message":"method not found"}}`);
}

function jsonResponse(status: number, text: string, headers?: Readonly<Record<string, string>>): Response {
  return new Response(text, { status, headers: { "content-type": "application/json", ...headers } });
}

/** The requested version of a discover: `params._meta`'s protocol version when it is a string. */
function requestedVersion(params: JsonValue | undefined): string | null {
  const version = ownMember(ownMember(params, "_meta"), META_PROTOCOL_VERSION);
  return typeof version === "string" ? version : null;
}

/** Contract 3.4 (c): the `-32022` retry answer every refusal mode answers with. */
function refusedDiscover(idText: string, supported: readonly string[], requested: string | null): Response {
  const requestedText = requested === null ? "null" : JSON.stringify(requested);
  const body = `{"jsonrpc":"2.0","id":${idText},"error":{"code":-32022,"message":"Unsupported protocol version",`
    + `"data":{"supported":${JSON.stringify(supported)},"requested":${requestedText}}}}`;
  return jsonResponse(400, body);
}

function answerDiscover(options: HandlerOptions, body: ParsedRequest, takeDiscover: () => boolean): Response {
  if (options.profile === "legacy") {
    // Refused before the counter moves: the legacy answer is not the
    // `server/discover` the `refuse-first` mode counts (contract 3.4 (b)).
    return jsonResponse(405, DISCOVER_NOT_ALLOWED);
  }
  const first = takeDiscover();
  const requested = requestedVersion(body.params);
  const refused = options.discoverVersionMode === "refuse-always"
    || (options.discoverVersionMode === "refuse-first" && first)
    || requested === null
    || !options.supportedVersions.includes(requested);
  if (refused) return refusedDiscover(body.idText, options.supportedVersions, requested);
  const result = `{"resultType":"complete","supportedVersions":${JSON.stringify(options.supportedVersions)},`
    + `"capabilities":{},"serverInfo":${SERVER_INFO}}`;
  return jsonResponse(200, envelopeResult(body.idText, result));
}

function answerToolCall(body: ParsedRequest, req: Request): Response {
  if (ownMember(body.params, "name") !== "region.echo") return methodNotFound(body.idText);
  // Contract 3.4 (e): one line per received header instance in received
  // order. The legacy era forwards no instance list, so the Headers view is
  // the best available echo there.
  const instances: readonly (readonly [string, string])[] = jackHeaders(req) ?? [...req.headers];
  const echo = instances.map(([name, value]) => `${name}: ${value}`).join("\n");
  return jsonResponse(200, envelopeResult(body.idText, `{"content":[{"type":"text","text":${jsonText(echo)}}]}`));
}

function answerInitialize(options: HandlerOptions, body: ParsedRequest): Response {
  const requested = ownMember(body.params, "protocolVersion");
  // Contract 3.4 (f): echo a supported request, otherwise the legacy fallback.
  const negotiated =
    typeof requested === "string" && options.supportedVersions.includes(requested) ? requested : "2025-11-25";
  const result = `{"protocolVersion":${JSON.stringify(negotiated)},"capabilities":{},"serverInfo":${SERVER_INFO}}`;
  // The only session id the server ever mints.
  return jsonResponse(200, envelopeResult(body.idText, result), { "mcp-session-id": "sess-1" });
}

function answer(options: HandlerOptions, body: ParsedRequest, req: Request, takeDiscover: () => boolean): Response {
  switch (body.method) {
    case "server/discover":
      return answerDiscover(options, body, takeDiscover);
    case "tools/list": {
      const result = `{"tools":[{"name":"region.echo","inputSchema":${jsonText(REGION_ECHO_SCHEMA)}}]}`;
      return jsonResponse(200, envelopeResult(body.idText, result));
    }
    case "tools/call":
      return answerToolCall(body, req);
    case "initialize":
      return answerInitialize(options, body);
    case "notifications/initialized":
      // 202 with a null body (contract 3.4 (g)); the wrapper signs the (empty) bytes.
      return new Response(null, { status: 202, headers: { "content-type": "application/json" } });
    default:
      return methodNotFound(body.idText);
  }
}

/**
 * Builds the handler of one process. The wrapper never hands it a refused or
 * protocol-native call, so every invocation produces exactly one logged row.
 */
export function createHandler(options: HandlerOptions): (req: Request) => Promise<Response> {
  // Contract 3.5: `refuse-first` must know which discover is the process's
  // first, so the count lives as long as the handler.
  let discovers = 0;
  const takeDiscover = (): boolean => {
    const first = discovers === 0;
    discovers += 1;
    return first;
  };
  return async (req: Request): Promise<Response> => {
    const text = req.method === "POST" ? new TextDecoder().decode(new Uint8Array(await req.arrayBuffer())) : "";
    const body = parseRequest(text);
    const response = answer(options, body, req, takeDiscover);
    if (options.requestLog !== null) {
      // Written before returning: the wrapper only writes the response after
      // this call resolves, so the row is flushed ahead of the signed answer.
      appendFileSync(options.requestLog, JSON.stringify({ method: body.method, http_status: response.status }) + "\n");
    }
    return response;
  };
}
