/** Focused real-socket controls for the interop raw-path HTTP adapter. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { parseRequestAuth } from "../src/auth-header.js";
import { verifyResponse, signRequest, randomNonce } from "../src/client/auth.js";
import { rawPathRequest, finalizeRawPathResponse } from "../src/interop/client.js";
import { fixtureAud, fixtureNow, newTestServer, seedSignerByName } from "./client-harness.js";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const responseLimit = 1024 * 1024;

type PeerHandler = (req: IncomingMessage, res: ServerResponse) => void;

async function withPeer(handler: PeerHandler, run: (baseURL: string) => Promise<void>): Promise<void> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address !== "string");
    await run(`http://127.0.0.1:${(address as AddressInfo).port}`);
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      // Also closes the intentionally stalled response used by the deadline control.
      server.closeAllConnections();
    });
  }
}

function bounded<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bound = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("outer test bound exceeded")), milliseconds);
  });
  return Promise.race([promise, bound]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

test("rawPathRequest accepts exactly 1 MiB and rejects the next byte", { timeout: 5000 }, async () => {
  await withPeer((_req, res) => {
    const size = _req.url === "/boundary" ? responseLimit : responseLimit + 1;
    res.writeHead(200, { "content-length": String(size) });
    res.end(Buffer.alloc(size, 0x61));
  }, async (baseURL) => {
    const accepted = await rawPathRequest(baseURL, "GET", "/boundary", "test", new Uint8Array(0));
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.arrayBuffer()).byteLength, responseLimit);
    await assert.rejects(
      rawPathRequest(baseURL, "GET", "/overflow", "test", new Uint8Array(0)),
      /raw target request: response exceeds 1 MiB/,
    );
  });
});

test("rawPathRequest enforces its own deadline and destroys a peer that never responds", { timeout: 10000 }, async () => {
  let peerSocketClosed: (() => void) | undefined;
  let peerRequestSeen: ((target: string) => void) | undefined;
  const socketClosed = new Promise<void>((resolve) => {
    peerSocketClosed = resolve;
  });
  const requestSeen = new Promise<string>((resolve) => {
    peerRequestSeen = resolve;
  });
  await withPeer((req) => {
    req.socket.once("close", () => peerSocketClosed?.());
    peerRequestSeen?.(req.url ?? "");
  }, async (baseURL) => {
    const rejected = assert.rejects(
      bounded(rawPathRequest(baseURL, "GET", "/never", "test", new Uint8Array(0), { deadlineMs: 1000 }), 5000),
      /raw target request: deadline exceeded/,
    );
    await Promise.all([
      rejected,
      bounded(requestSeen, 5000).then((target) => assert.equal(target, "/never")),
    ]);
    await bounded(socketClosed, 2000);
  });
});

test("rawPathRequest deadline covers a response stalled after headers", { timeout: 10000 }, async () => {
  let peerSocketClosed: (() => void) | undefined;
  let peerResponseStarted: ((target: string) => void) | undefined;
  const socketClosed = new Promise<void>((resolve) => {
    peerSocketClosed = resolve;
  });
  const responseStarted = new Promise<string>((resolve) => {
    peerResponseStarted = resolve;
  });
  await withPeer((req, res) => {
    req.socket.once("close", () => peerSocketClosed?.());
    res.writeHead(200, { "content-length": "64" });
    res.flushHeaders();
    peerResponseStarted?.(req.url ?? "");
    res.write("partial", (error) => {
      if (error !== undefined && error !== null) res.destroy();
    });
  }, async (baseURL) => {
    const rejected = assert.rejects(
      bounded(rawPathRequest(baseURL, "GET", "/stalled-body", "test", new Uint8Array(0), { deadlineMs: 1000 }), 5000),
      /raw target request: deadline exceeded/,
    );
    await Promise.all([
      rejected,
      bounded(responseStarted, 5000).then((target) => assert.equal(target, "/stalled-body")),
    ]);
    await bounded(socketClosed, 2000);
  });
});

test("rawPathRequest retains literal dot path and shared response signature verification", { timeout: 5000 }, async () => {
  const peer = newTestServer();
  const signer = seedSignerByName("alice");
  const target = "/a/../identity?x=%2F";
  const body = utf8('{"ok":true}');
  const requestHeader = signRequest(signer, fixtureAud, "GET", target, new Uint8Array(0), randomNonce(), fixtureNow);
  const requestSig = parseRequestAuth([requestHeader]).sig;
  let observedTarget: string | undefined;
  let observedHeader: string | string[] | undefined;

  await withPeer((req, res) => {
    observedTarget = req.url;
    observedHeader = req.headers["jack-auth"];
    const signed = peer.writeSignedJSON(parseRequestAuth([requestHeader]), 200, body);
    res.writeHead(signed.status, { "jack-auth": signed.headers.get("jack-auth") ?? "" });
    res.end(body);
  }, async (baseURL) => {
    const response = await rawPathRequest(baseURL, "GET", target, requestHeader, new Uint8Array(0));
    const responseBody = new Uint8Array(await response.arrayBuffer());
    const responseAuth = response.headers.get("jack-auth");
    assert.equal(observedTarget, target);
    assert.equal(observedHeader, requestHeader);
    assert.notEqual(responseAuth, null);
    verifyResponse(peer.pub, response.status, [responseAuth as string], requestSig, responseBody, fixtureNow, 30);
    assert.throws(() => verifyResponse(seedSignerByName("alice").publicKey(), response.status, [responseAuth as string], requestSig, responseBody, fixtureNow, 30));
    assert.deepEqual(responseBody, body);
  });
});

test("raw response finalization accepts complete responses", async () => {
  const complete = finalizeRawPathResponse(true, 200, ["content-length", "8"], [utf8("complete")]);
  assert.equal(complete.status, 200);
  assert.deepEqual(new Uint8Array(await complete.arrayBuffer()), utf8("complete"));
});

test("raw response finalization explicitly rejects incomplete declared-length responses", () => {
  // Node's HTTP parser also reports an aborted response on this wire failure;
  // exercise the production finalizer directly so the completeness guard is
  // independently discriminating rather than relying only on Node's rejection.
  assert.throws(
    () => finalizeRawPathResponse(false, 200, ["content-length", "64"], [utf8("partial")]),
    /raw target request: response incomplete/,
  );
});

test("rawPathRequest rejects a real truncated declared-length response", { timeout: 5000 }, async () => {
  await withPeer((_req, res) => {
    res.writeHead(200, { "content-length": "64" });
    res.flushHeaders();
    const socket = res.socket;
    res.write("partial", () => socket?.destroy());
  }, async (baseURL) => {
    await assert.rejects(
      rawPathRequest(baseURL, "GET", "/truncated", "test", new Uint8Array(0), { deadlineMs: 1000 }),
      /raw target request: response (incomplete|aborted|closed before completion)/,
    );
  });
});
