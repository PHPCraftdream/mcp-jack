/**
 * End-to-end over a real node:http server with the header lines put on the
 * wire exactly as listed: serveNode(jackFetchHandler(...)) must see the TRUE
 * repeated instances and their received casing (spec 04 S1/S9), which a bare
 * Fetch Request cannot carry. Modelled on ../http/node-http.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { randomNonce, signRequest, verifyResponse } from "../../../src/client/signing/auth.js";
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { MemoryAuditSink } from "../../../src/server/audit.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { Verifier } from "../../../src/server/verify.js";
import { serveNode } from "../../../src/server/http/node.js";
import { jackFetchHandler, jackHeaders } from "../../../src/server/http/fetch.js";
import type { HandlerConfig } from "../../../src/server/http/fetch.js";
import { newRegistryState, seedByName, utf8 } from "../http/fetch/support.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "../../support/client-harness.js";

const noop = (): void => {};

/** The modern protocol version of spec 04 (MCP 2026-07-28). */
const MODERN = "2026-07-28";

/** The fixed answer the wrapped handler gives. */
const nextJson = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

/** A tools/call body with the C1 `_meta` members (spec 04 section 6). */
const toolCallBody = (name: string): Uint8Array =>
  utf8(
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"' +
      name +
      '","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"' +
      MODERN +
      '","io.modelcontextprotocol/clientCapabilities":{}}}}',
  );

/** A tools/list body with the C1 `_meta` members. */
const toolsListBody = (): Uint8Array =>
  utf8(
    '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"' +
      MODERN +
      '","io.modelcontextprotocol/clientCapabilities":{}}}}',
  );

/** Result of one raw node:http request: status, headers as received, exact body bytes. */
interface RawResult {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

/**
 * Sends one raw node:http request. `rawHeaders` is a FLAT [name, value, ...]
 * list, which node:http writes line by line: repeats and the exact casing of
 * each name go on the wire (an object form would merge names that differ only
 * in case).
 */
function rawRequest(port: number, rawHeaders: readonly string[], body: Buffer): Promise<RawResult> {
  return new Promise<RawResult>((resolve, reject) => {
    let sawResponse = false;
    const req = httpRequest({
      host: "127.0.0.1",
      port,
      method: "POST",
      path: "/mcp",
      headers: rawHeaders,
      // A fresh connection per request, like the adapter tests.
      agent: false,
      // A server that never answers must fail after 2s instead of hanging.
      signal: AbortSignal.timeout(2000),
    });
    const chunks: Buffer[] = [];
    req.on("response", (res) => {
      sawResponse = true;
      res.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
      });
      const settle = (): void => {
        // Deterministic socket release; settle is idempotent.
        req.destroy();
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) });
      };
      res.on("end", settle);
      res.on("error", settle);
      res.on("close", settle);
    });
    req.on("error", (err) => {
      if (!sawResponse) reject(err);
      else noop();
    });
    if (body.length > 0) req.write(body);
    req.end();
  });
}

/** Normalizes the response jack-auth header (string | string[] | undefined) to its values in order. */
function jackAuthValues(headers: IncomingHttpHeaders): readonly string[] {
  const v = headers["jack-auth"];
  if (v === undefined) {
    return [];
  }
  return Array.isArray(v) ? v : [v];
}

// -- Wiring: real node:http server on 127.0.0.1:0, profile modern. --

const svc = seedByName("svc");
const serverPub = svc.signer.publicKey();

const verifier = new Verifier({
  aud: fixtureAud,
  state: newRegistryState(),
  nonces: new NonceStore(),
  audit: new MemoryAuditSink(),
  native: new Native(),
  now: () => fixtureNow,
});

/** The exact instances the wrapped handler read, through jackHeaders (S9). */
let seenRaw: readonly (readonly [string, string])[] | null = null;

const next = async (req: Request): Promise<Response> => {
  seenRaw = jackHeaders(req) ?? null;
  return new Response(nextJson, { headers: { "content-type": "application/json" } });
};

const config: HandlerConfig = { verifier, serverKey: svc.seed, profile: "modern" };
const server = createServer(serveNode(jackFetchHandler(config, next)));

const port = await new Promise<number>((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const addr = server.address();
    if (addr === null || typeof addr === "string") {
      reject(new Error("server has no AddressInfo"));
      return;
    }
    resolve((addr as AddressInfo).port);
  });
});

after(() => {
  server.close();
  // A stalled keep-alive connection must not block teardown.
  server.closeAllConnections();
});

test("modern profile: repeated mirror instances are refused over node:http", { timeout: 5000 }, async () => {
  // Two MCP-Protocol-Version lines arrive as two raw instances (a Headers
  // object would have merged them): S1 refuses the repetition with a signed
  // 400 and the wrapped handler never runs.
  seenRaw = null;
  const alice = seedSignerByName("alice");
  const body = toolsListBody();
  const header = signRequest(alice, fixtureAud, "POST", "/mcp", body, randomNonce(), fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const res = await rawRequest(
    port,
    ["MCP-Protocol-Version", MODERN, "MCP-Protocol-Version", MODERN, "Mcp-Method", "tools/list", "jack-auth", header],
    Buffer.from(body),
  );

  assert.equal(res.status, 400);
  assert.equal(res.headers["allow"], undefined, "only the 405 refusal carries Allow");
  // verifyResponse THROWS unless the refusal was signed over these exact bytes.
  verifyResponse(serverPub, res.status, jackAuthValues(res.headers), sig, new Uint8Array(res.body), fixtureNow, 30);
  assert.deepEqual(JSON.parse(res.body.toString("utf-8")), {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32020, message: "Header mismatch: a request metadata header appears more than once" },
  });
  assert.equal(seenRaw, null, "a refused request never reaches the wrapped handler");
});

test("modern profile: node:http forwards the raw header instances", { timeout: 5000 }, async () => {
  // Mixed-case repeated Mcp-Param-Region lines plus a session header: the
  // wrapped handler reads the exact forwarded instances through jackHeaders,
  // so both values survive in received order and casing while S8 removes the
  // session header.
  seenRaw = null;
  const alice = seedSignerByName("alice");
  const body = toolCallBody("svc.status");
  const header = signRequest(alice, fixtureAud, "POST", "/mcp", body, randomNonce(), fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const res = await rawRequest(
    port,
    [
      "MCP-Protocol-Version",
      MODERN,
      "Mcp-Method",
      "tools/call",
      "Mcp-Name",
      "svc.status",
      "Mcp-Param-Region",
      "eu",
      "mcp-param-region",
      "us",
      "Mcp-Session-Id",
      "sess-1",
      "jack-auth",
      header,
    ],
    Buffer.from(body),
  );

  assert.equal(res.status, 200);
  verifyResponse(serverPub, res.status, jackAuthValues(res.headers), sig, new Uint8Array(res.body), fixtureNow, 30);
  assert.equal(res.body.toString("utf-8"), nextJson);
  const raw: readonly (readonly [string, string])[] = seenRaw ?? [];
  const eu = raw.findIndex(([n, v]) => n === "Mcp-Param-Region" && v === "eu");
  const us = raw.findIndex(([n, v]) => n === "mcp-param-region" && v === "us");
  assert.ok(eu >= 0, `the first instance keeps its received casing: ${JSON.stringify(raw)}`);
  assert.ok(us > eu, `the second instance follows the first: ${JSON.stringify(raw)}`);
  assert.deepEqual(
    raw.filter(([n]) => n.toLowerCase() === "mcp-session-id"),
    [],
    "S8 removes Mcp-Session-Id",
  );
});
