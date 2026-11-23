/**
 * C1 and C2 of the modern profile of spec 04 section 6 (MCP 2026-07-28): the
 * request `_meta` member and its mirror headers in C2 order. Port of
 * `buildMirrors` in `spec/tools/modern/headers/reference/client.mjs`.
 */

import type { JsonValue } from "../core/json-raw.js";
import { encodeHeaderValue, nameSourceOf } from "./values.js";
import type { HeaderPair } from "./values.js";

/** The `_meta` key carrying the protocol version (C1). */
export const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";

/** The `_meta` key carrying the client capabilities (C1). */
export const META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";

/** The `_meta` key carrying the client name and version (C1). */
export const META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo";

/** The client identity a modern request may advertise in `_meta`. */
export interface ClientInfo {
  readonly name: string;
  readonly version: string;
}

/** Everything the request mirrors are built from: the version, the method, the params and the optional client identity. */
export interface RequestMirrorsInput {
  /** The negotiated protocol version, written to `_meta` and to `MCP-Protocol-Version`. */
  readonly version: string;
  /** The JSON-RPC method, written to `Mcp-Method` and used to look up the `Mcp-Name` source. */
  readonly method: string;
  /** The params object of the request; its `name`/`uri` member is mirrored into Mcp-Name. */
  readonly params?: JsonValue;
  /** The client identity, added to `_meta` only when supplied. */
  readonly clientInfo?: ClientInfo;
  /** The client capabilities; `{}` when not supplied. */
  readonly clientCapabilities?: JsonValue;
}

/** The C1 `_meta` object and the C2 headers of one modern request. */
export interface RequestMirrors {
  /** params._meta: protocolVersion, then clientInfo when given, then clientCapabilities ({} by default). */
  readonly meta: { readonly [key: string]: JsonValue };
  /** The C2 headers in C2 order. */
  readonly headers: readonly HeaderPair[];
}

/** True for a plain JSON object, the only shape an own member is read from. */
function isContainer(value: JsonValue | undefined): value is { readonly [key: string]: JsonValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * C1 and C2: the request `_meta` and its mirror headers in C2 order. A `Mcp-Name`
 * source field whose body value is not a string is a caller bug, not a skip.
 */
export function buildRequestMirrors(input: RequestMirrorsInput): RequestMirrors {
  const meta: { [key: string]: JsonValue } = { [META_PROTOCOL_VERSION]: input.version };
  if (input.clientInfo !== undefined) {
    meta[META_CLIENT_INFO] = { name: input.clientInfo.name, version: input.clientInfo.version };
  }
  meta[META_CLIENT_CAPABILITIES] = input.clientCapabilities ?? {};
  const headers: HeaderPair[] = [
    ["MCP-Protocol-Version", input.version],
    ["Mcp-Method", input.method],
  ];
  const source = nameSourceOf(input.method);
  if (source !== null) {
    const params = input.params;
    const value = isContainer(params) && Object.hasOwn(params, source) ? params[source] : undefined;
    if (typeof value !== "string") {
      throw new Error("modern profile: params." + source + " must be a string for " + input.method);
    }
    headers.push(["Mcp-Name", encodeHeaderValue(value)]);
  }
  return { meta, headers };
}
