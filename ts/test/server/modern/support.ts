/**
 * Shared helpers (no test() calls) for the server side of the modern profile
 * (spec 04): a fetch adapter wired with the fixture registry, the REAL native
 * tools and an explicit deployment profile, plus request/body/header builders
 * for the modern era.
 */
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { randomNonce, signRequest } from "../../../src/client/signing/auth.js";
import type { InMemorySigner } from "../../../src/client/signing/signer.js";
import { MemoryAuditSink } from "../../../src/server/audit.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { Verifier } from "../../../src/server/verify.js";
import { jackFetchHandler, jackHeaders } from "../../../src/server/http/fetch.js";
import type { HandlerConfig } from "../../../src/server/http/fetch.js";
import type { ServerProfile } from "../../../src/modern/server.js";
import { fixtureAud, fixtureNow } from "../../support/client-harness.js";
import { newRegistryState, seedByName, utf8 } from "../http/fetch/support.js";

// The 0.1.x fetch helpers are reused verbatim, so the modern-profile tests
// judge the SAME bytes and signatures as the existing adapter tests.
export { assertSigned, errorCode, newRegistryState, toolCallBody, utf8 } from "../http/fetch/support.js";
export { fixtureAud, fixtureNow, seedSignerByName } from "../../support/client-harness.js";

/** The modern protocol version of spec 04 (MCP 2026-07-28). */
export const MODERN = "2026-07-28";

export interface ModernHarness {
  handle(req: Request): Promise<Response>;
  seen: {
    calls: number;
    body: Uint8Array | null;
    headers: readonly (readonly [string, string])[] | null;
    /** The exact forwarded instances the wrapped handler read with jackHeaders (S9), or null when it carried none. */
    rawHeaders: readonly (readonly [string, string])[] | null;
  };
  serverPub: Uint8Array;
}

/** The default wrapped handler: a plain forwarded JSON-RPC result. */
const forwardedAnswer = (): Response =>
  new Response('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', { headers: { "content-type": "application/json" } });

/**
 * Like newHarness in ../http/fetch/support.js, but with an explicit
 * deployment profile (spec 04 section 3): `undefined` means the option is not
 * passed at all, so the adapter keeps its own legacy default. The wrapped
 * handler records the forwarded header instances (both the Headers view and
 * the exact jackHeaders list) and body bytes.
 */
export function newModernHarness(profile: ServerProfile | undefined, next?: (req: Request) => Promise<Response>): ModernHarness {
  const state = newRegistryState();
  const audit = new MemoryAuditSink();
  const svc = seedByName("svc");
  const verifier = new Verifier({
    aud: fixtureAud,
    state,
    nonces: new NonceStore(),
    audit,
    native: new Native(),
    now: () => fixtureNow,
  });
  const seen: ModernHarness["seen"] = { calls: 0, body: null, headers: null, rawHeaders: null };
  const upstream = next ?? (async (): Promise<Response> => forwardedAnswer());
  const wrapped = async (req: Request): Promise<Response> => {
    seen.calls += 1;
    seen.headers = [...req.headers];
    seen.rawHeaders = jackHeaders(req) ?? null;
    seen.body = new Uint8Array(await req.arrayBuffer());
    return upstream(req);
  };
  const config: HandlerConfig = {
    verifier,
    serverKey: svc.seed,
    ...(profile !== undefined ? { profile } : {}),
  };
  return { handle: jackFetchHandler(config, wrapped), seen, serverPub: svc.signer.publicKey() };
}

export interface ModernRequestOptions {
  readonly method?: string;
  readonly target?: string;
  readonly body?: Uint8Array;
  readonly headers?: readonly (readonly [string, string])[];
}

/**
 * Builds a fresh-nonce signed modern-era Request plus its request signature.
 * The extra headers are appended after the Jack-Auth header, in the order
 * given; the body is only attached for methods that can carry one.
 */
export function modernRequest(signer: InMemorySigner, options?: ModernRequestOptions): { request: Request; sig: string } {
  const method = options?.method ?? "POST";
  const target = options?.target ?? "/mcp";
  const body = options?.body ?? new Uint8Array(0);
  const header = signRequest(signer, fixtureAud, method, target, body, randomNonce(), fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const headerList: [string, string][] = [["jack-auth", header]];
  for (const [name, value] of options?.headers ?? []) headerList.push([name, value]);
  const request = new Request("http://localhost" + target, {
    method,
    headers: headerList,
    ...(method !== "GET" && body.length > 0 ? { body } : {}),
  });
  return { request, sig };
}

/**
 * A modern-era tools/call body: the JSON-RPC id as RAW text, the tool name
 * JSON-quoted, the arguments as raw JSON text and the C1 `_meta` members of
 * spec 04.
 */
export function modernToolCallBody(idText: string, name: string, argsJson = "{}"): Uint8Array {
  return utf8(
    '{"jsonrpc":"2.0","id":' +
      idText +
      ',"method":"tools/call","params":{"name":' +
      JSON.stringify(name) +
      ',"arguments":' +
      argsJson +
      ',"_meta":{"io.modelcontextprotocol/protocolVersion":"' +
      MODERN +
      '","io.modelcontextprotocol/clientCapabilities":{}}}}',
  );
}

/** The full mirror header set of S4/S5/S6, in the spec's spelling. */
export function mirrorsFor(method: string, name: string): [string, string][] {
  return [
    ["MCP-Protocol-Version", MODERN],
    ["Mcp-Method", method],
    ["Mcp-Name", name],
  ];
}
