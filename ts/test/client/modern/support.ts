/**
 * Shared helpers (no test() calls) for the CLIENT side of the modern profile
 * (spec 04): a fake in-process server that verifies every signed request with
 * the fixture client keys and signs its answers, plus the body/header
 * builders the C8 cache tests need. The shape mirrors newTestServer in
 * test/support/client-harness.ts, restricted to what the modern client uses.
 */
import { sign as nodeSign } from "node:crypto";
import { formatResponseAuth, parseRequestAuth } from "../../../src/core/auth-header.js";
import type { RequestAuth } from "../../../src/core/auth-header.js";
import { verify } from "../../../src/core/ed25519.js";
import { decodeBase64URLFixed, encodeBase64URL } from "../../../src/core/encoding.js";
import { requestSigningString, responseSigningString } from "../../../src/core/signing.js";
import { Client } from "../../../src/client/rpc.js";
import type { JsonValue } from "../../../src/client/rpc.js";
import { randomNonce } from "../../../src/client/signing/auth.js";
import { fixtureAud, fixtureKeys, fixtureNow, generateKeypair, seedSignerByName } from "../../support/client-harness.js";

/** Local UTF-8 encoder; the signing strings are signed over their exact UTF-8 bytes. */
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** One request the fake server received, with the header list copied pair by pair in wire order. */
export interface RecordedRequest {
  /** HTTP method as received. */
  readonly method: string;
  /** Origin-form target (path plus query). */
  readonly target: string;
  /** The request body as text. */
  readonly body: string;
  /** Every header as a name/value pair, in the order the client sent them. */
  readonly headers: readonly (readonly [string, string])[];
  /** The parsed Jack-Auth parameters of the request. */
  readonly auth: RequestAuth;
}

/** A fake server that verifies requests and signs responses with its own key pair. */
export interface ModernServer {
  /** The fake fetch: verifies each request (401 when it does not verify), records it, then delegates to handle. */
  readonly fetch: typeof fetch;
  /** Every accepted request, in arrival order. */
  readonly requests: RecordedRequest[];
  /** Raw 32-byte server public key the client pins. */
  readonly pub: Uint8Array;
  /** keyId(pub) of the server key. */
  readonly kid: string;
  /** Per-test response logic; a null handler answers an unsigned 500. */
  handle: ((req: RecordedRequest) => Response | Promise<Response>) | null;
  /** Signs status + auth.sig + kid + fixtureNow + body with the server key (spec 01 section 5). */
  sign(status: number, auth: RequestAuth, body: string | Uint8Array): Response;
}

/** The header values of one recorded request whose name matches case-insensitively, in order. */
function valuesOf(headers: readonly (readonly [string, string])[], name: string): string[] {
  const want = name.toLowerCase();
  return headers.filter((pair) => pair[0].toLowerCase() === want).map((pair) => pair[1]);
}

/** headerValues returns the values of every pair whose name equals name case-insensitively, in order. */
export function headerValues(req: RecordedRequest, name: string): string[] {
  return valuesOf(req.headers, name);
}

/** bodyOf parses the recorded request body as a JSON object; anything else is a test bug. */
export function bodyOf(req: RecordedRequest): { readonly [key: string]: JsonValue } {
  const parsed: unknown = JSON.parse(req.body);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("modern client test: request body is not a JSON object");
  }
  return parsed as { readonly [key: string]: JsonValue };
}

/** JSON text of one value, never undefined (JSON.stringify of a JsonValue always yields a string). */
function stringify(value: JsonValue): string {
  const text = JSON.stringify(value);
  return text === undefined ? "null" : text;
}

/** rpcResult builds a JSON-RPC 2.0 success body with the given id and result. */
export function rpcResult(id: number, result: JsonValue): string {
  return stringify({ jsonrpc: "2.0", id, result });
}

/** rpcError builds a JSON-RPC 2.0 error body; the data member is omitted when undefined. */
export function rpcError(id: number, code: number, message: string, data?: JsonValue): string {
  const error: { [key: string]: JsonValue } = { code, message };
  if (data !== undefined) {
    error["data"] = data;
  }
  return stringify({ jsonrpc: "2.0", id, error });
}

/** newModernServer builds a fake server that verifies requests with the fixture client keys and signs with a fresh key pair. */
export function newModernServer(): ModernServer {
  const { priv, pub, kid } = generateKeypair();
  // The client key map is built once at creation, not per request.
  const keys = fixtureKeys();
  const unauthorizedBody = utf8('{"error":{"code":"unknown_key","message":"verification failed"}}');

  const writeUnsignedJSON = (status: number, body: Uint8Array): Response =>
    new Response(body, { status, headers: { "content-type": "application/json" } });

  const sign = (status: number, auth: RequestAuth, body: string | Uint8Array): Response => {
    const bytes = typeof body === "string" ? utf8(body) : body;
    const msg = utf8(responseSigningString(status, auth.sig, kid, fixtureNow, bytes));
    const sig = new Uint8Array(nodeSign(null, msg, priv));
    // A null body for an empty payload: some statuses (304) reject any body, even zero-length.
    return new Response(bytes.length > 0 ? bytes : null, {
      status,
      headers: { "content-type": "application/json", "jack-auth": formatResponseAuth({ kid, ts: fixtureNow, sig: encodeBase64URL(sig) }) },
    });
  };

  const fetchImpl = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    // The client hands its headers over as a pair list; copy it pair by pair so
    // the recorded order and spelling survive (a Headers input is copied too).
    const recorded: [string, string][] = [];
    const rawHeaders = init?.headers;
    if (Array.isArray(rawHeaders)) {
      for (const pair of rawHeaders) {
        const name = pair[0];
        const value = pair[1];
        if (typeof name === "string" && typeof value === "string") {
          recorded.push([name, value]);
        }
      }
    } else if (rawHeaders !== undefined) {
      new Headers(rawHeaders).forEach((value: string, name: string) => {
        recorded.push([name, value]);
      });
    }
    // The client's body is the exact signed text; bytes are accepted as well so
    // the fake works with either transport shape.
    const rawBody = init?.body;
    let bodyBytes: Uint8Array;
    if (typeof rawBody === "string") {
      bodyBytes = utf8(rawBody);
    } else if (rawBody instanceof Uint8Array) {
      bodyBytes = rawBody;
    } else if (rawBody instanceof ArrayBuffer) {
      bodyBytes = new Uint8Array(rawBody);
    } else {
      bodyBytes = new Uint8Array(0);
    }
    const target = url.pathname + url.search;

    let auth: RequestAuth;
    try {
      auth = parseRequestAuth(valuesOf(recorded, "jack-auth"));
    } catch {
      return writeUnsignedJSON(401, unauthorizedBody);
    }
    const clientPub = keys.get(auth.kid);
    const msg = utf8(requestSigningString(method, target, fixtureAud, auth.kid, auth.ts, auth.nonce, bodyBytes));
    let sig: Uint8Array;
    try {
      sig = decodeBase64URLFixed(auth.sig, 64);
    } catch {
      sig = new Uint8Array(0);
    }
    if (clientPub === undefined || !verify(clientPub, msg, sig)) {
      return writeUnsignedJSON(401, unauthorizedBody);
    }

    const request: RecordedRequest = { method, target, body: new TextDecoder().decode(bodyBytes), headers: recorded, auth };
    server.requests.push(request);
    if (server.handle === null) {
      return writeUnsignedJSON(500, utf8('{"error":{"code":"internal","message":"no handler"}}'));
    }
    return server.handle(request);
  };

  const server: ModernServer = { fetch: fetchImpl, requests: [], pub, kid, handle: null, sign };
  return server;
}

/** newModernClient builds a Client pinned to the fake server, speaking the requested era (default: the client default). */
export function newModernClient(server: ModernServer, era?: "legacy" | "modern" | "auto"): Client {
  // "https://mcp.test/mcp" is never connected: the fake fetch intercepts it.
  return new Client({
    baseUrl: "https://mcp.test/mcp",
    aud: fixtureAud,
    signer: seedSignerByName("alice"),
    serverKey: server.pub,
    fetchImpl: server.fetch,
    clock: () => fixtureNow,
    windowSeconds: 30,
    nonceSource: () => randomNonce(),
    ...(era !== undefined ? { era } : {}),
  });
}
