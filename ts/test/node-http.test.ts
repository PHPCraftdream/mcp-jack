/** End-to-end over a real node:http server: serveNode(jackFetchHandler(...)) exercised with the repo's own client plus a raw client. */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { UnauthenticatedResponseError, createSigningFetch } from "../src/client/transport.js";
import { Client } from "../src/client/rpc.js";
import { HTTPError } from "../src/client/errors.js";
import { signRequest, randomNonce, verifyResponse } from "../src/client/auth.js";
import { parseRequestAuth } from "../src/auth-header.js";
import { MemoryAuditSink } from "../src/server/audit.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { parsePolicy } from "../src/server/policy.js";
import type { RegistryEntry as StateRegistryEntry } from "../src/server/state.js";
import { MemoryState } from "../src/server/state.js";
import { Verifier } from "../src/server/verify.js";
import { serveNode } from "../src/server/node.js";
import { jackFetchHandler } from "../src/server/fetch.js";
import type { HandlerConfig } from "../src/server/fetch.js";
import { loadDefaultPolicy, loadRegistry, type RegistryEntry as FixtureRegistryEntry } from "./fixtures.js";
import { fixtureAud, fixtureNow, seedSignerByName, generateKeypair } from "./client-harness.js";

const noop = (): void => {};

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** The ping body every simple test sends. */
const pingBody = '{"jsonrpc":"2.0","id":1,"method":"ping"}';

/** The fixed answer next gives for everything but /events and /cookies. */
const nextJson = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

/** Fixture registry entry -> src registry entry; optional fields assigned only when defined (exactOptionalPropertyTypes). */
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

function toStateEntry(e: FixtureRegistryEntry): StateRegistryEntry {
  const out: Mutable<StateRegistryEntry> = {
    kid: e.kid,
    publicKey: e.publicKey,
    name: e.name,
    scopes: e.scopes,
  };
  if (e.kind !== undefined) {
    out.kind = e.kind;
  }
  if (e.notBefore !== undefined) {
    out.notBefore = e.notBefore;
  }
  if (e.notAfter !== undefined) {
    out.notAfter = e.notAfter;
  }
  return out;
}

/** Fresh registry state seeded from the fixture (MemoryState is created empty). */
function newRegistryState(): MemoryState {
  const st = new MemoryState();
  st.update((edit) => {
    for (const e of loadRegistry().keys) edit.putKey(toStateEntry(e));
  });
  return st;
}

/** Result of one raw node:http request: status, headers as received, exact body bytes. */
interface RawResult {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

/**
 * Sends one raw node:http request; the request line and headers go on the wire
 * byte-for-byte (no undici URL normalization), so targets like /mcp/../mcp
 * reach the server exactly as signed. Expected server resets after an early
 * 413 must not reject the promise; a response that ends early still resolves
 * with the partial bytes.
 */
function rawRequest(port: number, method: string, path: string, headers: Record<string, string>, body: Buffer): Promise<RawResult> {
  return new Promise<RawResult>((resolve, reject) => {
    let sawResponse = false;
    const req = httpRequest({
      host: "127.0.0.1",
      port,
      method,
      path,
      headers,
      // A fresh connection per request: E8 leaves a connection whose declared
      // body was never sent, and a pooled reuse would feed E9 into it.
      agent: false,
      // A server that never answers (e.g. a regression that lost the early
      // content-length rejection) must fail after 2s instead of hanging.
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
      // Headers arrived but the socket died before end: resolve with what we have.
      res.on("error", settle);
      res.on("close", settle);
    });
    req.on("error", (err) => {
      // The server resets the socket right after an early 413; that must not
      // reject (the response above already resolved). Before any response, an
      // error is a real failure the test must see.
      if (!sawResponse) reject(err);
      else noop();
    });
    if (body.length > 0) {
      req.write(body);
    }
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

// -- Wiring: real node:http server on 127.0.0.1:0. --

// Server key from generateKeypair exercises the KeyObject branch of HandlerConfig.
const kp = generateKeypair();
const serverPub = kp.pub;

const verifier = new Verifier({
  aud: fixtureAud,
  state: newRegistryState(),
  nonces: new NonceStore(),
  policy: parsePolicy(JSON.stringify(loadDefaultPolicy())),
  audit: new MemoryAuditSink(),
  native: new Native(),
  now: () => fixtureNow,
});

const next = async (req: Request): Promise<Response> => {
  const { pathname } = new URL(req.url);
  if (pathname === "/events") {
    return new Response("data: x\n\n", { headers: { "content-type": "text/event-stream" } });
  }
  if (pathname === "/cookies") {
    return new Response("{}", {
      headers: [
        ["content-type", "application/json"],
        ["set-cookie", "a=1"],
        ["set-cookie", "b=2"],
      ],
    });
  }
  return new Response(nextJson, { headers: { "content-type": "application/json" } });
};

const config: HandlerConfig = { verifier, serverKey: kp.priv };
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

after(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
    // A stalled keep-alive connection must not block teardown.
    server.closeAllConnections();
  });
});

test("E1 ping round trip over a real socket", { timeout: 5000 }, async () => {
  // Pipeline: verify (fixture policy rule 1 allows ping with scope null; alice
  // registered+active at fixtureNow, fresh nonce) -> forward to next -> signed
  // 200. createSigningFetch THROWS unless the response was signed by
  // serverPub at fixtureNow, so the non-throw IS the verification assertion.
  const alice = seedSignerByName("alice");
  const sf = createSigningFetch({ aud: fixtureAud, signer: alice, serverKey: serverPub, clock: () => fixtureNow });
  const resp = await sf(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: utf8(pingBody),
  });
  assert.equal(resp.status, 200);
  const text = Buffer.from(new Uint8Array(await resp.arrayBuffer())).toString("utf-8");
  assert.equal(text, nextJson);
  assert.ok(resp.headers.get("jack-auth") !== null, "the signed answer carries jack-auth");
});

test("E2 whoami through the Client", { timeout: 5000 }, async () => {
  // Pipeline: verify -> native branch (jack.whoami bypasses the policy) ->
  // signed 200 CallToolResult; client/tools.ts maps snake_case to camelCase.
  const root = seedSignerByName("root");
  const client = new Client({
    baseUrl: `http://127.0.0.1:${port}/mcp`,
    aud: fixtureAud,
    signer: root,
    serverKey: serverPub,
    clock: () => fixtureNow,
    windowSeconds: 30,
  });
  const who = await client.whoAmI();
  assert.equal(who.name, "root");
  assert.equal(who.kid, root.kid());
  assert.equal(who.kind, "human");
  assert.equal(who.notBefore, null);
  assert.equal(who.notAfter, null);
  assert.ok(who.scopes.includes("admin"));
});

test("E3 denied tool surfaces HTTPError after signature verification", { timeout: 5000 }, async () => {
  // Pipeline: verify authenticates alice -> policy denies svc.restart
  // (needs lifecycle, alice has read) -> SIGNED 403 (nonce was recorded).
  // createSigningFetch verifies the 403 BEFORE the caller sees it, so an
  // HTTPError (not a JackError/UnauthenticatedResponseError) proves the
  // signature check ran.
  const alice = seedSignerByName("alice");
  const clientAlice = new Client({
    baseUrl: `http://127.0.0.1:${port}/mcp`,
    aud: fixtureAud,
    signer: alice,
    serverKey: serverPub,
    clock: () => fixtureNow,
    windowSeconds: 30,
  });
  await assert.rejects(clientAlice.callTool("svc.restart"), (err: unknown) => {
    assert.ok(err instanceof HTTPError);
    assert.equal((err as HTTPError).status, 403);
    assert.equal((err as HTTPError).code, "insufficient_scope");
    return true;
  });
});

test("E4 replaying the same bytes", { timeout: 5000 }, async () => {
  // Pipeline: the first request verifies (step 8 records the pair) -> accepted
  // -> SIGNED 200. The replay stops at verify step 8 -> rejected(): the helper
  // sets nonceRecorded false and requestSig "", so the 401 is UNSIGNED (spec
  // 01 section 5: an authentication failure is not signed). The signing client
  // therefore refuses the answer (UnauthenticatedResponseError, status 401,
  // the body code surfaced as an untrusted hint); the raw client sees 401 with
  // WWW-Authenticate, the replayed_nonce body and NO Jack-Auth response header.
  const bob = seedSignerByName("bob");
  const fixedNonce = randomNonce();
  const sf2 = createSigningFetch({ aud: fixtureAud, signer: bob, serverKey: serverPub, clock: () => fixtureNow, nonceSource: () => fixedNonce });
  const first = await sf2(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: utf8(pingBody),
  });
  assert.equal(first.status, 200);
  await assert.rejects(
    sf2(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: utf8(pingBody) }),
    (err: unknown) => {
      assert.ok(err instanceof UnauthenticatedResponseError);
      assert.equal((err as UnauthenticatedResponseError).status, 401);
      assert.equal((err as UnauthenticatedResponseError).code, "replayed_nonce");
      return true;
    },
  );

  // The identical bytes through a raw socket with a FRESH nonce: the first
  // use is accepted, the replay is the unsigned 401 above.
  const rawNonce = randomNonce();
  const header = signRequest(bob, fixtureAud, "POST", "/mcp", utf8(pingBody), rawNonce, fixtureNow);
  const rawHeaders = { "jack-auth": header, "content-type": "application/json" };
  const rawBody = Buffer.from(pingBody, "utf-8");
  const firstRaw = await rawRequest(port, "POST", "/mcp", rawHeaders, rawBody);
  assert.equal(firstRaw.status, 200);
  const secondRaw = await rawRequest(port, "POST", "/mcp", rawHeaders, rawBody);
  assert.equal(secondRaw.status, 401);
  assert.equal(jackAuthValues(secondRaw.headers).length, 0, "an authentication failure is never signed");
  assert.equal(secondRaw.headers["www-authenticate"], "Jack-Auth");
  const parsed = JSON.parse(secondRaw.body.toString("utf-8")) as { error?: { code?: string } };
  assert.equal(parsed.error?.code, "replayed_nonce");
});

test("E5 percent-encoded query survives the real socket", { timeout: 5000 }, async () => {
  // Pipeline: verify over the target undici sends — it leaves existing %XX
  // escapes untouched, node's req.url is the same bytes, fetch.ts re-derives
  // pathname+search byte-identically; any re-encoding would fail step 7 with
  // bad_signature.
  const alice = seedSignerByName("alice");
  const sf = createSigningFetch({ aud: fixtureAud, signer: alice, serverKey: serverPub, clock: () => fixtureNow });
  const resp = await sf(`http://127.0.0.1:${port}/mcp?x=%7e&y=a%2Fb`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: utf8(pingBody),
  });
  assert.equal(resp.status, 200);
  assert.equal(Buffer.from(new Uint8Array(await resp.arrayBuffer())).toString("utf-8"), nextJson);
});

test("E6 dot segments reach the verifier through the raw adapter", { timeout: 5000 }, async () => {
  // Pipeline: verify. node:http sends the request line byte-for-byte, so
  // req.url === "/mcp/../mcp?dot=1"; WITHOUT RAW_TARGET_SYMBOL, fetch.ts's
  // new URL(req.url).pathname would be "/mcp?dot=1" — a DIFFERENT signed
  // string -> bad_signature. This test is the proof of the symbol mechanism.
  const alice = seedSignerByName("alice");
  const header = signRequest(alice, fixtureAud, "GET", "/mcp/../mcp?dot=1", new Uint8Array(0), randomNonce(), fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const res = await rawRequest(port, "GET", "/mcp/../mcp?dot=1", { "jack-auth": header }, Buffer.alloc(0));
  assert.equal(res.status, 200);
  assert.equal(res.body.toString("utf-8"), nextJson);
  verifyResponse(serverPub, res.status, jackAuthValues(res.headers), sig, res.body, fixtureNow, 30);
});

test("E7 event-stream endpoint refused with 501", { timeout: 5000 }, async () => {
  // Pipeline: GET authorized by authentication alone -> forward -> next
  // answers text/event-stream -> adapter buffers and answers SIGNED 501
  // streaming_unsupported (a stream cannot be body-hashed, spec README Q1).
  const alice = seedSignerByName("alice");
  const sf = createSigningFetch({ aud: fixtureAud, signer: alice, serverKey: serverPub, clock: () => fixtureNow });
  const resp = await sf(`http://127.0.0.1:${port}/events`);
  assert.equal(resp.status, 501);
  const parsed = JSON.parse(Buffer.from(new Uint8Array(await resp.arrayBuffer())).toString("utf-8")) as { error?: { code?: string } };
  assert.equal(parsed.error?.code, "streaming_unsupported");
  // createSigningFetch verified the answer; an unsigned 501 would have thrown
  // JackError missing_auth with httpStatus 0 instead of returning.
  assert.ok(resp.headers.get("jack-auth") !== null);
});

test("E8 oversized declared body answered before reading", { timeout: 5000 }, async () => {
  // Pipeline: node.ts's content-length check (2000000 > 1048576) fires on
  // HEADERS, before any body read and before authentication -> UNSIGNED
  // writeError. Only 10 of the 2000000 declared bytes ever arrive, so an
  // implementation without the early check cannot answer 413 at all.
  const res = await rawRequest(port, "POST", "/mcp", { "content-length": "2000000" }, Buffer.alloc(10, 120));
  assert.equal(res.status, 413);
  const parsed = JSON.parse(res.body.toString("utf-8")) as { error?: { code?: string } };
  assert.equal(parsed.error?.code, "invalid_request");
  assert.equal(jackAuthValues(res.headers).length, 0, "the early 413 is unsigned");
});

test("E9 oversized chunked body answered mid-read", { timeout: 5000 }, async () => {
  // Pipeline: no content-length -> node sends chunked; readBody accumulates
  // until total > limit, pauses, answers UNSIGNED 413, then req.resume()
  // drains so the client can finish writing and read the answer.
  const res = await rawRequest(port, "POST", "/mcp", {}, Buffer.alloc((1 << 20) + 1, 120));
  assert.equal(res.status, 413);
  const parsed = JSON.parse(res.body.toString("utf-8")) as { error?: { code?: string } };
  assert.equal(parsed.error?.code, "invalid_request");
  assert.equal(jackAuthValues(res.headers).length, 0, "the mid-read 413 is unsigned");
});

test("E10 repeated Set-Cookie headers preserved", { timeout: 5000 }, async () => {
  // Pipeline: verify -> forward -> next's Response carries two set-cookie
  // values; node.ts writes them as an ARRAY via setHeader (one header line
  // each); undici reparses both in order.
  const alice = seedSignerByName("alice");
  const sf = createSigningFetch({ aud: fixtureAud, signer: alice, serverKey: serverPub, clock: () => fixtureNow });
  const resp = await sf(`http://127.0.0.1:${port}/cookies`);
  assert.equal(resp.status, 200);
  assert.deepEqual(resp.headers.getSetCookie(), ["a=1", "b=2"]);
});
