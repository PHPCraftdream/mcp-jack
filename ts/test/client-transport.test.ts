/** createSigningFetch tests, ported from Go client/transport_test.go (using the harness TestServer). */
import assert from "node:assert/strict";
import { sign as nodeSign } from "node:crypto";
import { test } from "node:test";
import { formatResponseAuth } from "../src/auth-header.js";
import { encodeBase64URL } from "../src/encoding.js";
import { responseSigningString } from "../src/signing.js";
import { JackError } from "../src/errors.js";
import { createSigningFetch, readBodyCapped, StreamingUnsupportedError, UnauthenticatedResponseError } from "../src/client/transport.js";
import type { SigningFetch } from "../src/client/transport.js";
import type { Clock } from "../src/client/auth.js";
import { fixtureAud, fixtureNow, generateKeypair, newTestServer, rpcResultBody, seedSignerByName } from "./client-harness.js";
import type { TestServer } from "./client-harness.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** newTransport builds a signing fetch pinned to the test server key with fixed clock and alice as signer; nonceSource is omitted so randomNonce is used, like Go's newTransport. */
const newTransport = (server: TestServer, clock?: Clock): SigningFetch =>
  createSigningFetch(
    {
      aud: fixtureAud,
      signer: seedSignerByName("alice"),
      serverKey: server.pub,
      clock: clock ?? (() => fixtureNow),
      windowSeconds: 30,
    },
    server.fetch,
  );

/** postMCP issues a signed POST of {"ping":1} to the fake server's /mcp target. */
const postMCP = (f: SigningFetch): Promise<Response> =>
  f("http://mcp.test/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: utf8('{"ping":1}') });

test("transport round trip happy path", async () => {
  const server = newTestServer();
  // One string constant reused for both the response bytes and the expected body text:
  // fetch has no ContentLength, so Go's ContentLength assertion is dropped here.
  const wantBodyText = new TextDecoder().decode(rpcResultBody('{"ok":true}'));
  let gotKid = "";
  let gotTS = 0;
  const alice = seedSignerByName("alice");
  server.handle = (auth) => {
    gotKid = auth.kid;
    gotTS = auth.ts;
    return server.writeSignedJSON(auth, 200, utf8(wantBodyText));
  };

  const resp = await postMCP(newTransport(server));
  assert.equal(resp.status, 200, "status");
  assert.equal(await resp.text(), wantBodyText, "body");
  assert.equal(gotKid, alice.kid(), "server saw the wrong kid");
  assert.equal(gotTS, fixtureNow, "server saw the wrong ts");
});

test("unsigned 401 surfaces UnauthenticatedResponseError", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeUnsignedJSON(401, utf8('{"error":{"code":"unknown_key","message":"nope"}}'));
  const call = postMCP(newTransport(server));
  await assert.rejects(
    call,
    (err: unknown) =>
      err instanceof UnauthenticatedResponseError && err.status === 401 && !("code" in err),
  );
});

test("signed 401 passes through", async () => {
  const server = newTestServer();
  const wantBodyText = '{"error":{"code":"unknown_key","message":"expired"}}';
  server.handle = (auth) => server.writeSignedJSON(auth, 401, utf8(wantBodyText));

  const resp = await postMCP(newTransport(server));
  assert.equal(resp.status, 401, "status");
  assert.equal(await resp.text(), wantBodyText, "body");
});

test("streaming response refused", async () => {
  const server = newTestServer();
  // Unsigned suffices: the streaming guard fires before verification.
  server.handle = () => new Response("data: x\n\n", { headers: { "content-type": "text/event-stream" } });
  await assert.rejects(postMCP(newTransport(server)), (err: unknown) => err instanceof StreamingUnsupportedError);
});

test("tampered body detected", async () => {
  const server = newTestServer();
  server.handle = (auth) => {
    const bodyA = rpcResultBody('{"ok":true}');
    const msg = utf8(responseSigningString(200, auth.sig, server.kid, server.now, bodyA));
    const sig = nodeSign(null, Buffer.from(msg), server.priv);
    const header = formatResponseAuth({ kid: server.kid, ts: server.now, sig: encodeBase64URL(new Uint8Array(sig)) });
    // Same length, different content: set the second-to-last byte to 'X'.
    const bodyB = new Uint8Array(bodyA);
    bodyB[bodyB.length - 2] = 0x58;
    return new Response(bodyB, { status: 200, headers: { "content-type": "application/json", "jack-auth": header } });
  };
  await assert.rejects(
    postMCP(newTransport(server)),
    (err: unknown) => err instanceof JackError && err.code === "bad_signature" && err.httpStatus === 0,
  );
});

test("unpinned server key rejected", async () => {
  const server = newTestServer();
  const wrongKey = generateKeypair();
  const tr = createSigningFetch(
    {
      aud: fixtureAud,
      signer: seedSignerByName("alice"),
      serverKey: wrongKey.pub,
      clock: () => fixtureNow,
      windowSeconds: 30,
    },
    server.fetch,
  );
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  await assert.rejects(
    postMCP(tr),
    (err: unknown) => err instanceof JackError && err.code === "unknown_server_key" && err.httpStatus === 0,
  );
});

test("stale timestamp rejected", async () => {
  const server = newTestServer();
  // The response is signed at server.now = fixtureNow; the transport's clock is
  // +3600s, so |3600| > windowSeconds 30 and the response ts is out of window.
  const tr = newTransport(server, () => fixtureNow + 3600);
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  await assert.rejects(
    postMCP(tr),
    (err: unknown) => err instanceof JackError && err.code === "timestamp_out_of_window" && err.httpStatus === 0,
  );
});

test("response verification reads the clock after the network call", async () => {
  const server = newTestServer();
  let clockNow = fixtureNow;
  server.handle = (auth) => {
    // Advance the injected clock WHILE the request is in flight: the response
    // (ts fixtureNow) must be verified against the NEW time, so it is stale.
    clockNow += 3600;
    return server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  };
  const tr = createSigningFetch(
    { aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => clockNow, windowSeconds: 30 },
    server.fetch,
  );
  await assert.rejects(
    postMCP(tr),
    (err: unknown) => err instanceof JackError && err.code === "timestamp_out_of_window" && err.httpStatus === 0,
  );
});

test("response verification mapping table", async () => {
  const rows: readonly {
    readonly name: string;
    readonly status: number;
    readonly headers: Record<string, string>;
    readonly serverKey?: Uint8Array;
    readonly expect: (err: unknown) => boolean;
  }[] = [
    {
      name: "unsigned 401 -> UnauthenticatedResponseError (status only)",
      status: 401,
      headers: { "content-type": "application/json" },
      expect: (err) => err instanceof UnauthenticatedResponseError && err.status === 401 && !("code" in err),
    },
    {
      name: "unsigned 200 -> missing_auth",
      status: 200,
      headers: { "content-type": "application/json" },
      expect: (err) => err instanceof JackError && err.code === "missing_auth" && err.httpStatus === 0,
    },
    {
      name: "malformed Jack-Auth on 401 -> malformed_auth (Go maps only missing_auth)",
      status: 401,
      headers: { "content-type": "application/json", "jack-auth": "Bearer nope" },
      expect: (err) => err instanceof JackError && err.code === "malformed_auth" && err.httpStatus === 0,
    },
    {
      name: "v2 scheme -> unsupported_version (scheme checked first)",
      status: 200,
      headers: { "content-type": "application/json", "jack-auth": "v2 kid=TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs,ts=1767225600,sig=x" },
      expect: (err) => err instanceof JackError && err.code === "unsupported_version" && err.httpStatus === 0,
    },
    {
      name: "misconfigured pinned key (16 bytes) -> plain Error, not a protocol rejection",
      status: 200,
      headers: { "content-type": "application/json" },
      serverKey: new Uint8Array(16),
      expect: (err) =>
        err instanceof Error && !(err instanceof JackError) && err.message.includes("pinned server key must be exactly 32 bytes"),
    },
  ];
  for (const row of rows) {
    const server = newTestServer();
    server.handle = () =>
      new Response(utf8('{"error":{"code":"hint_code","message":"hint message"}}'), { status: row.status, headers: row.headers });
    let caught: unknown;
    // verifyResponse checks the pinned key length BEFORE header parsing and
    // throws a plain Error, so the row's key (not the server's) drives this test.
    const transportKey = row.serverKey ?? server.pub;
    const tr = createSigningFetch(
      { aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: transportKey, clock: () => fixtureNow, windowSeconds: 30 },
      server.fetch,
    );
    try {
      await postMCP(tr);
    } catch (err) {
      caught = err;
    }
    assert.ok(row.expect(caught), `row "${row.name}": unexpected error ${String(caught)}`);
  }
});

test("forwards signal and forces redirect to error", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  const controller = new AbortController();
  // Recorded as an array with a declared element type: a closure-assigned
  // `let x: T | null = null` cannot be relied on for narrowing afterwards.
  const calls: RequestInit[] = [];
  const base = server.fetch;
  // Observe exactly what the signing fetch passes to the underlying fetch.
  server.fetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    calls.push(init ?? {});
    return base(input, init);
  };
  const resp = await newTransport(server)("http://mcp.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: utf8('{"ping":1}'),
    signal: controller.signal,
  });
  assert.equal(resp.status, 200, "status");
  assert.equal(calls.length, 1, "the underlying fetch must be called exactly once");
  const seen = calls[0];
  assert.ok(seen !== undefined, "the underlying fetch was not called");
  assert.equal(seen.signal, controller.signal, "signal must be forwarded");
  assert.equal(seen.redirect, "error", "redirect must be forced to error");
});

test("an explicit null signal overrides a Request signal", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  const calls: RequestInit[] = [];
  const base = server.fetch;
  server.fetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    calls.push(init ?? {});
    return base(input, init);
  };
  const requestSignal = new AbortController().signal;
  const request = new Request("http://mcp.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"ping":1}',
    signal: requestSignal,
  });
  const resp = await newTransport(server)(request, { signal: null });
  assert.equal(resp.status, 200, "status");
  assert.equal(calls.length, 1, "the underlying fetch must be called exactly once");
  const seen = calls[0];
  assert.ok(seen !== undefined, "the underlying fetch was not called");
  assert.ok("signal" in seen, "signal must be forwarded explicitly");
  assert.equal(seen.signal, null, "an explicit null signal must override the Request signal");
});

test("streaming refusal cancels the response body", async () => {
  const server = newTestServer();
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(utf8("data: x\n\n"));
    },
    cancel() {
      cancelled = true;
    },
  });
  server.handle = () => new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } });
  await assert.rejects(postMCP(newTransport(server)), (err: unknown) => err instanceof StreamingUnsupportedError);
  assert.equal(cancelled, true, "the refused stream must be cancelled");
});

test("readBodyCapped cancels the stream when the cap is exceeded", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(utf8("12345"));
      controller.enqueue(utf8("67890"));
    },
    cancel() {
      cancelled = true;
    },
  });
  const resp = new Response(stream);
  await assert.rejects(readBodyCapped(resp, 8), /response body exceeds 8 bytes/);
  assert.equal(cancelled, true, "the over-cap stream must be cancelled");
  // getReader throws while the stream is locked: a second reader proves the lock was released.
  assert.doesNotThrow(() => resp.body?.getReader(), "the lock must be released after overflow");
});

test("readBodyCapped releases the lock on success", async () => {
  const resp = new Response(utf8("abc"));
  const out = await readBodyCapped(resp, 8);
  assert.equal(new TextDecoder().decode(out), "abc", "body bytes");
  // getReader throws while the stream is locked: a second reader proves the lock was released.
  assert.doesNotThrow(() => resp.body?.getReader(), "the lock must be released on success");
});

test("readBodyCapped propagates a rejected read and releases the lock", async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(new Error("read failed"));
    },
  });
  const resp = new Response(stream);
  await assert.rejects(readBodyCapped(resp, 8), /read failed/);
  // The rejection is surfaced, not swallowed; node would report any additional
  // unhandled rejection as a crash. The second reader proves the lock is free.
  assert.doesNotThrow(() => resp.body?.getReader(), "the lock must be released after a rejected read");
});
