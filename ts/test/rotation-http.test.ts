import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { client, decodeBase64URLFixed, encodeBase64URL, formatResponseAuth, JackError,
  parseRequestAuth, requestSigningString, responseSigningString, rotation, verify } from "../src/index.js";

const linux = process.platform === "linux";
const denied = (code: string) => (error: unknown): boolean => error instanceof JackError && error.httpStatus === 0 && error.code === code;
const signer = (name: string) => new client.InMemorySigner(createHash("sha256").update(`rotation HTTP fixture ${name}`).digest());

type Peer = (environment: Environment, request: IncomingMessage, response: ServerResponse, body: Buffer, signature: string) => void;
interface Environment {
  key: client.InMemorySigner;
  user: client.InMemorySigner;
  next: client.InMemorySigner;
  binding: rotation.RotationBinding;
  checkpoint: rotation.RotationCheckpoint;
  clock: { now: number; calls: number; hook?: () => number };
  store: rotation.RotationTrustStore;
  sender: rotation.RotationHTTPClient;
  requests: number;
  connections: number;
  nonces: Set<string>;
}

async function setup(context: TestContext, peer: Peer, timeoutMs = 10000): Promise<Environment> {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "jack-rotation-http-")));
  chmodSync(root, 0o700);
  let environment: Environment | undefined;
  let failure: unknown;
  const server = createServer((request, response) => {
    response.on("error", () => { /* Ожидаемый client abort не становится unhandled error. */ });
    void (async () => {
      const state = environment;
      assert.ok(state);
      state.requests++;
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of request) {
        size += Buffer.byteLength(chunk);
        assert.ok(size <= 1024 * 1024);
        chunks.push(Buffer.from(chunk));
      }
      const body = Buffer.concat(chunks);
      const raw = request.headers["jack-auth"];
      assert.equal(typeof raw, "string");
      const auth = parseRequestAuth([raw as string]);
      assert.equal(auth.kid, state.user.kid());
      assert.ok(!state.nonces.has(auth.nonce));
      state.nonces.add(auth.nonce);
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/a/../mcp?exact=%2F&v=1");
      assert.equal(request.headers["connection"], "close");
      assert.equal(request.headers["accept-encoding"], "identity");
      assert.ok(verify(state.user.publicKey(), Buffer.from(requestSigningString("POST", request.url as string,
        state.binding.aud, auth.kid, auth.ts, auth.nonce, body)), decodeBase64URLFixed(auth.sig, 64)));
      peer(state, request, response, body, auth.sig);
    })().catch((error: unknown) => { failure = error; response.destroy(); });
  });
  server.on("connection", () => { if (environment !== undefined) environment.connections++; });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  context.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => { server.close(() => resolve()); });
    try { environment?.store.close(); } catch { /* Только test-owned artifacts. */ }
    rmSync(root, { recursive: true, force: true });
    assert.equal(failure, undefined);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  const key = signer("anchor");
  const binding = { endpoint: `http://127.0.0.1:${address.port}/a/../mcp?exact=%2F&v=1`, aud: "http-rotation-audience" };
  const checkpoint = { ordinal: 0, hash: "-", kid: key.kid(), publicKeyB64u: encodeBase64URL(key.publicKey()), publishedAt: 0 };
  const clock: Environment["clock"] = { now: 1000, calls: 0 };
  const options = { binding, checkpoint, window: 30, now: () => { clock.calls++; return clock.hook?.() ?? clock.now; } };
  const path = join(root, "trust");
  rotation.RotationTrustStore.initializeUnused(path, options);
  const store = rotation.RotationTrustStore.open(path, options);
  const user = signer("user");
  environment = { key, user, next: signer("next"), binding, checkpoint, clock, store,
    sender: new rotation.RotationHTTPClient(store, user, timeoutMs), requests: 0, connections: 0, nonces: new Set() };
  return environment;
}

function reply(environment: Environment, response: ServerResponse, signature: string, body: Buffer, key: client.Signer = environment.key): void {
  const signing = responseSigningString(200, signature, key.kid(), environment.clock.now, body);
  response.setHeader("Jack-Auth", formatResponseAuth({ kid: key.kid(), ts: environment.clock.now, sig: encodeBase64URL(key.sign(Buffer.from(signing))) }));
  response.end(body);
}

test("rotation HTTP: actual exact request/response bytes, raw target, fresh nonce and one connection per call", { skip: !linux }, async (context) => {
  const environment = await setup(context, (state, _request, response, body, signature) => reply(state, response, signature, body));
  const body = Buffer.from([0xff, 0, 13, 10]);
  const expected = Buffer.from(body);
  const pending = environment.sender.call(body);
  body.fill(0);
  const first = await pending;
  assert.equal(first.status, 200);
  assert.deepEqual(Buffer.from(first.body), expected);
  assert.deepEqual(Buffer.from((await environment.sender.call(expected)).body), expected);
  assert.equal(environment.requests, 2);
  assert.equal(environment.connections, 2);
  assert.equal(environment.nonces.size, 2);
  assert.equal(environment.store.snapshot().snapshot.revision, 1);
  assert.ok(!("RotationDeadline" in rotation) && !("exchange" in rotation) && !("requestError" in rotation));
});

test("rotation HTTP: explicit refresh is one native request; ordinary call never decodes an announcement", { skip: !linux }, async (context) => {
  let page = Buffer.alloc(0);
  const environment = await setup(context, (state, _request, response, body, signature) => {
    const request = JSON.parse(body.toString("utf8")) as { id: number; params: { name: string; arguments: { after_ordinal: number; after_hash: string } } };
    assert.equal(request.params.name, "jack.server.key");
    assert.deepEqual(request.params.arguments, { after_ordinal: 0, after_hash: "-" });
    const record = rotation.createRotationRecord(state.binding, state.checkpoint, state.key, state.next, 1000);
    const payload = { current: { kid: state.key.kid(), public_key: encodeBase64URL(state.key.publicKey()) },
      records: [record.wire], head: { ordinal: 1, hash: record.hash }, complete: true };
    page = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: request.id,
      result: { content: [{ type: "text", text: JSON.stringify(payload) }], structuredContent: payload, isError: false } }));
    reply(state, response, signature, page);
  });
  const ordinary = await environment.sender.call(Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "jack.server.key", arguments: { after_ordinal: 0, after_hash: "-" } } })));
  assert.deepEqual(Buffer.from(ordinary.body), page);
  assert.equal(environment.store.snapshot().snapshot.revision, 1);
  assert.equal(environment.requests, 1);
  const result = await environment.sender.refresh();
  assert.equal(result.committed, true);
  assert.equal(result.terminal.ordinal, 1);
  assert.equal(environment.requests, 2);
  assert.equal(environment.store.snapshot().snapshot.revision, 2);
  assert.ok(page.length > 0);
});

test("rotation HTTP: redirect, compression, stream, header/body limits and reset refuse without retry", { skip: !linux }, async (context) => {
  for (const mode of ["redirect", "encoding", "stream", "headers", "body", "refresh-body", "reset", "unknown", "duplicate-auth", "tamper"]) {
    await context.test(mode, async (child) => {
      let before = 0;
      const environment = await setup(child, (state, _request, response, _body, signature) => {
        before = state.clock.calls;
        if (mode === "redirect") { response.writeHead(302, { Location: "/elsewhere" }); response.end(); }
        else if (mode === "encoding") { response.setHeader("Content-Encoding", "gzip"); response.end("not compressed"); }
        else if (mode === "stream") { response.setHeader("Content-Type", "text/event-stream"); response.end("data: refused\n\n"); }
        else if (mode === "headers") { response.setHeader("X-Large", "x".repeat(20000)); response.end(); }
        else if (mode === "body") reply(state, response, signature, Buffer.alloc(1024 * 1024 + 1));
        else if (mode === "refresh-body") reply(state, response, signature, Buffer.alloc(256 * 1024 + 1));
        else if (mode === "reset") response.destroy();
        else if (mode === "unknown") reply(state, response, signature, Buffer.from("opaque"), signer("unknown"));
        else if (mode === "duplicate-auth") {
          const body = Buffer.from("opaque");
          const signing = responseSigningString(200, signature, state.key.kid(), state.clock.now, body);
          const header = formatResponseAuth({ kid: state.key.kid(), ts: state.clock.now, sig: encodeBase64URL(state.key.sign(Buffer.from(signing))) });
          response.setHeader("Jack-Auth", [header, header]); response.end(body);
        }
        else {
          const body = Buffer.from("tampered");
          const signing = responseSigningString(200, signature, state.key.kid(), state.clock.now, Buffer.from("original"));
          response.setHeader("Jack-Auth", formatResponseAuth({ kid: state.key.kid(), ts: state.clock.now, sig: encodeBase64URL(state.key.sign(Buffer.from(signing))) }));
          response.end(body);
        }
      });
      const code = mode === "redirect" ? "rotation_redirect_refused" : mode === "headers" || mode === "reset" ? "rotation_request_unavailable"
        : mode === "unknown" ? "unknown_server_key" : mode === "duplicate-auth" ? "malformed_auth" : mode === "tamper" ? "bad_signature" : "rotation_result_invalid";
      await assert.rejects(mode === "refresh-body" ? environment.sender.refresh() : environment.sender.call(Buffer.from("request")), denied(code));
      assert.equal(environment.requests, 1);
      assert.equal(environment.store.snapshot().snapshot.revision, 1);
      if (mode === "unknown" || mode === "duplicate-auth") assert.equal(environment.clock.calls, before);
    });
  }
});

test("rotation HTTP: total deadline defeats a body drip; cancellation and close never return body", { skip: !linux, timeout: 15000 }, async (context) => {
  await context.test("deadline", async (child) => {
    const environment = await setup(child, (_state, _request, response) => {
      response.writeHead(200);
      const timer = setInterval(() => response.write("x"), 25);
      response.once("close", () => clearInterval(timer));
    }, 2000);
    await assert.rejects(environment.sender.call(Buffer.from("request")), denied("rotation_request_unavailable"));
    assert.equal(environment.requests, 1);
  });
  await context.test("pre-aborted", async (child) => {
    const environment = await setup(child, () => assert.fail("no physical request"));
    const abort = new AbortController(); abort.abort();
    const calls = environment.clock.calls;
    await assert.rejects(environment.sender.call(Buffer.from("request"), abort.signal), denied("rotation_request_unavailable"));
    assert.equal(environment.requests, 0);
    assert.equal(environment.clock.calls, calls);
  });
  await context.test("abort at final response gate", async (child) => {
    const abort = new AbortController();
    let samples = 0;
    const environment = await setup(child, (state, _request, response, body, signature) => {
      state.clock.hook = () => { if (++samples === 3) abort.abort(); return state.clock.now; };
      reply(state, response, signature, body);
    });
    await assert.rejects(environment.sender.call(Buffer.from("never return"), abort.signal), denied("rotation_request_unavailable"));
    assert.equal(samples, 3);
    assert.equal(environment.requests, 1);
  });
  await context.test("store closed in flight", async (child) => {
    const environment = await setup(child, (state, _request, response, body, signature) => {
      state.store.close();
      reply(state, response, signature, body);
    });
    await assert.rejects(environment.sender.call(Buffer.from("request")), denied("rotation_state_unavailable"));
    assert.equal(environment.requests, 1);
  });
});

test("rotation HTTP: signer lifetime loss prevents dispatch, and abort cleanup invokes no caller override", { skip: !linux }, async (context) => {
  const environment = await setup(context, (state, _request, response, body, signature) => reply(state, response, signature, body));
  for (const timeout of [0, -1, 30001, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
    assert.throws(() => new rotation.RotationHTTPClient(environment.store, environment.user, timeout), denied("rotation_state_unknown"));
  }
  await assert.rejects(environment.sender.call(Buffer.alloc(1024 * 1024 + 1)), denied("rotation_result_invalid"));
  assert.equal(environment.requests, 0);
  const abort = new AbortController();
  Object.defineProperty(abort.signal, "removeEventListener", { value() { throw new Error("private cleanup detail"); } });
  const foreign = new Proxy(abort.signal, { getPrototypeOf() { throw new Error("private abort detail"); } });
  await assert.rejects(environment.sender.call(Buffer.from("never dispatch"), foreign),
    (error: unknown) => denied("rotation_request_unavailable")(error) && !String(error).includes("private abort detail"));
  assert.equal(environment.requests, 0);
  assert.deepEqual(Buffer.from((await environment.sender.call(Buffer.from("safe"), abort.signal)).body), Buffer.from("safe"));
  const wrapped: client.Signer = { kid: () => environment.user.kid(), publicKey: () => environment.user.publicKey(),
    sign: (message) => { environment.store.close(); return environment.user.sign(message); } };
  const sender = new rotation.RotationHTTPClient(environment.store, wrapped, 10000);
  await assert.rejects(sender.call(Buffer.from("never dispatch")), denied("rotation_clock_unavailable"));
  assert.equal(environment.requests, 1);
});
