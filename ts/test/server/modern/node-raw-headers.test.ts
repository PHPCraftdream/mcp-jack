/**
 * End-to-end over a real node:http server with the header lines put on the
 * wire exactly as listed: serveNode(jackFetchHandler(...)) must see the TRUE
 * repeated instances and their received casing (spec 04 S1/S9), which a bare
 * Fetch Request cannot carry. The requests themselves are written as exact
 * bytes over TCP (node:net), because http.request only takes an object map of
 * headers. Modelled on ../http/node-http.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import { connect as netConnect } from "node:net";
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
 * Sends one raw request as exact bytes over TCP: `headerLines` is a list of
 * [name, value] PAIRS, and one `name: value` line per pair goes on the wire in
 * the order and with the casing given, repeats included. A raw socket is used
 * because http.request only takes an object map of headers (OutgoingHttpHeaders)
 * - the flat name/value array form is defined for response.writeHead alone, so
 * passing it to http.request would put index-named headers on the wire instead
 * of the real ones. `method` defaults to POST; a HEAD request carries no body.
 */
function rawRequest(
  port: number,
  headerLines: readonly (readonly [string, string])[],
  body: Buffer,
  method = "POST",
): Promise<RawResult> {
  return new Promise<RawResult>((resolve, reject) => {
    let head = method + " /mcp HTTP/1.1\r\n";
    for (const [name, value] of headerLines) {
      head += name + ": " + value + "\r\n";
    }
    head += "Host: 127.0.0.1:" + port + "\r\n";
    head += "Content-Length: " + body.length + "\r\n";
    head += "Connection: close\r\n\r\n";

    const socket = netConnect(port, "127.0.0.1");
    const chunks: Buffer[] = [];
    // A server that never answers must fail after 2s instead of hanging.
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("raw request timed out after 2000 ms with no complete response"));
    }, 2000);
    socket.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });
    // Connection: close means the response is complete once the socket ends.
    socket.on("end", () => {
      clearTimeout(timer);
      const raw = Buffer.concat(chunks);
      const split = raw.indexOf("\r\n\r\n");
      if (split < 0) {
        reject(new Error("raw response carried no complete head"));
        return;
      }
      const headLines = raw.subarray(0, split).toString("utf-8").split("\r\n");
      const statusLine = headLines[0];
      if (statusLine === undefined || statusLine.length === 0) {
        reject(new Error("raw response carried no status line"));
        return;
      }
      const headers: IncomingHttpHeaders = {};
      for (const line of headLines.slice(1)) {
        const colon = line.indexOf(":");
        if (colon <= 0) {
          continue;
        }
        const name = line.slice(0, colon).trim().toLowerCase();
        const value = line.slice(colon + 1).trim();
        const prev = headers[name];
        if (prev === undefined) {
          headers[name] = value;
        } else if (Array.isArray(prev)) {
          prev.push(value);
        } else {
          headers[name] = [prev, value];
        }
      }
      resolve({ status: Number(statusLine.split(" ")[1]), headers, body: raw.subarray(split + 4) });
    });
    socket.write(head);
    if (body.length > 0) socket.write(body);
    socket.end();
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
    [
      ["MCP-Protocol-Version", MODERN],
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/list"],
      ["jack-auth", header],
    ],
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
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/call"],
      ["Mcp-Name", "svc.status"],
      ["Mcp-Param-Region", "eu"],
      ["mcp-param-region", "us"],
      ["Mcp-Session-Id", "sess-1"],
      ["jack-auth", header],
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

test("modern profile: a HEAD refusal is signed over the empty body", { timeout: 5000 }, async () => {
  // A HEAD response carries no content, so the refusal's JSON body is never
  // transmitted; the signature therefore covers the empty bytes the client
  // actually receives, and verifyResponse must accept exactly those.
  seenRaw = null;
  const alice = seedSignerByName("alice");
  const emptyBody = new Uint8Array(0);
  const header = signRequest(alice, fixtureAud, "HEAD", "/mcp", emptyBody, randomNonce(), fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const res = await rawRequest(
    port,
    [
      ["MCP-Protocol-Version", MODERN],
      ["jack-auth", header],
    ],
    Buffer.alloc(0),
    "HEAD",
  );

  assert.equal(res.status, 405);
  assert.equal(res.headers["allow"], "POST");
  assert.equal(res.headers["content-length"], "0", "content-length: 0 goes with no body");
  assert.equal(res.body.length, 0, "a HEAD response carries no body");
  verifyResponse(serverPub, 405, jackAuthValues(res.headers), sig, new Uint8Array(0), fixtureNow, 30);
  assert.equal(seenRaw, null, "a refused request never reaches the wrapped handler");
});
