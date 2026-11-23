/**
 * Spec 04 C9: the WHOLE legacy fallback against the repo's own `both`-profile
 * server wrapper. The probe is a modern request and is answered with a 405 (a
 * legacy endpoint does not implement `server/discover`); `initialize` carries
 * no `MCP-Protocol-Version` header, so the wrapper serves it as legacy and
 * forwards it; the negotiated version and the assigned session then travel on
 * `notifications/initialized` and on the operation. This is the regression
 * proof that the fallback does not look modern to a `both`-profile server.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ModernClient } from "../../../src/client/modern.js";
import { Client } from "../../../src/client/rpc.js";
import { randomNonce } from "../../../src/client/signing/auth.js";
import { fixtureAud, fixtureNow, newModernHarness, seedSignerByName } from "../../server/modern/support.js";

/** The legacy version the wrapped handler negotiates. */
const NEGOTIATED_VERSION = "2025-11-25";

/** The session id the wrapped handler assigns on the initialize answer. */
const SESSION_ID = "sess-1";

/** One request the wrapped handler saw: its JSON-RPC method and forwarded header instances. */
interface ForwardedRequest {
  /** The JSON-RPC `method` member, "" when the body carries none. */
  readonly method: string;
  /** The forwarded header instances, as the Fetch `Headers` view yields them (lowercased names). */
  readonly headers: readonly (readonly [string, string])[];
}

/** The values of every header whose name matches case-insensitively, in order. */
function headerValues(headers: readonly (readonly [string, string])[], name: string): string[] {
  const want = name.toLowerCase();
  return headers.filter(([key]) => key.toLowerCase() === want).map(([, value]) => value);
}

/** The request at index; a missing one is a test bug, not a result. */
function at(requests: readonly ForwardedRequest[], index: number): ForwardedRequest {
  const request = requests[index];
  if (request === undefined) throw new Error("real-server fallback test: no request at index " + String(index));
  return request;
}

/** The members of a JSON body, or an empty object when it is not one. */
function membersOf(text: string): { readonly [key: string]: unknown } {
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  return parsed as { readonly [key: string]: unknown };
}

test("era negotiation: the whole fallback is served as legacy by a both-profile server", async () => {
  const forwarded: ForwardedRequest[] = [];
  const server = newModernHarness("both", async (req: Request): Promise<Response> => {
    // The harness reads the restored body before it hands the request on, so
    // the bytes are taken from `seen` instead of a second (unusable) read.
    const raw = server.seen.body;
    const body = membersOf(raw === null ? "{}" : new TextDecoder().decode(raw));
    const method = typeof body["method"] === "string" ? body["method"] : "";
    forwarded.push({ method, headers: [...req.headers] });
    const id = body["id"];
    const idText = typeof id === "number" ? String(id) : "null";
    if (method === "server/discover") return new Response(null, { status: 405 });
    if (method === "initialize") {
      // The server decides the legacy era from the ABSENT version header; the
      // assigned session travels back as an unsigned response header.
      return new Response(
        '{"jsonrpc":"2.0","id":' +
          idText +
          ',"result":{"protocolVersion":"' +
          NEGOTIATED_VERSION +
          '","capabilities":{},"serverInfo":{"name":"legacy","version":"1"}}}',
        { headers: { "content-type": "application/json", "Mcp-Session-Id": SESSION_ID } },
      );
    }
    if (method === "notifications/initialized") {
      return new Response("{}", { headers: { "content-type": "application/json" } });
    }
    return new Response('{"jsonrpc":"2.0","id":' + idText + ',"result":{"ok":true}}', {
      headers: { "content-type": "application/json" },
    });
  });

  // Adapt the real handler to the Client's fetch shape: the client hands over a
  // URL and an init whose body is the exact signed bytes and whose headers are
  // a pair list (or a Headers view).
  const fetchImpl = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    const body = init?.body;
    const bytes =
      typeof body === "string" ? new TextEncoder().encode(body) : body instanceof Uint8Array ? body : new Uint8Array(0);
    const headers = Array.isArray(init?.headers) ? (init.headers as [string, string][]) : new Headers(init?.headers);
    const req = new Request(String(input), {
      method: init?.method ?? "POST",
      headers,
      ...(bytes.length > 0 ? { body: bytes } : {}),
    });
    return server.handle(req);
  };

  const modern = new ModernClient(
    new Client({
      baseUrl: "https://mcp.test/mcp",
      aud: fixtureAud,
      signer: seedSignerByName("alice"),
      serverKey: server.serverPub,
      fetchImpl,
      clock: () => fixtureNow,
      windowSeconds: 30,
      nonceSource: () => randomNonce(),
      era: "auto",
    }),
  );

  assert.deepEqual(await modern.call("tools/list"), { ok: true }, "the fallback operation answers its result");
  assert.equal(modern.era, "legacy", "the whole fallback adopts the legacy era");

  assert.equal(server.seen.calls, 4, "the both-profile adapter forwarded the probe, the handshake and the operation");
  assert.deepEqual(
    forwarded.map((request) => request.method),
    ["server/discover", "initialize", "notifications/initialized", "tools/list"],
    "the fallback dialogue reaches the wrapped handler in order",
  );

  const probe = at(forwarded, 0);
  assert.deepEqual(headerValues(probe.headers, "mcp-protocol-version"), ["2026-07-28"], "the probe is a modern request");

  const initialize = at(forwarded, 1);
  // The regression: with a version header the both-profile adapter would have
  // read this request as modern and refused it instead of forwarding it.
  assert.deepEqual(headerValues(initialize.headers, "mcp-protocol-version"), [], "initialize carries no version header");

  const initialized = at(forwarded, 2);
  assert.deepEqual(
    headerValues(initialized.headers, "mcp-protocol-version"),
    [NEGOTIATED_VERSION],
    "the notification carries the negotiated version",
  );
  assert.deepEqual(
    headerValues(initialized.headers, "mcp-session-id"),
    [SESSION_ID],
    "the notification carries the assigned session",
  );

  const operation = at(forwarded, 3);
  assert.deepEqual(
    headerValues(operation.headers, "mcp-protocol-version"),
    [NEGOTIATED_VERSION],
    "the operation carries the negotiated version",
  );
  assert.deepEqual(
    headerValues(operation.headers, "mcp-session-id"),
    [SESSION_ID],
    "the operation carries the assigned session",
  );
});
