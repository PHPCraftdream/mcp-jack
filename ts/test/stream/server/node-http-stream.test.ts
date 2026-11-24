/*
 * The node adapter over a real loopback socket (spec 05 2.1/3.7): a signed
 * stream reaches the client frame by frame while the handler body is still
 * open, and a client disconnect cancels the handler. The signed request is
 * built by the shared harness, so the Fetch handler runs exactly as with any
 * other client.
 */
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { serveNode } from "../../../src/server/http/node.js";
import { jackStream } from "../../../src/server/http/stream.js";
import { newStreamServer, signedPost, sseResponse } from "../support/stream-harness.js";

const noop = (): void => {};
const MESSAGE = '{"jsonrpc":"2.0","method":"notifications/events/active"}';
const messageEvent = (data: string): string => "event: message\ndata: " + data + "\n\n";
const FIRST_FRAME = "event: message\ndata: ";

async function waitFor(predicate: () => boolean): Promise<boolean> {
  for (let i = 0; i < 50; i += 1) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return predicate();
}

test("stream server: the node adapter streams frames and cancels the handler on a client disconnect", { timeout: 30_000 }, async () => {
  const harness = newStreamServer();
  let handlerSignal: AbortSignal | undefined;
  let handlerCancelled = false;
  harness.setNext(async (req) => {
    handlerSignal = jackStream(req)?.signal;
    return sseResponse([messageEvent(MESSAGE)], {
      stayOpen: true,
      onCancel: (): void => { handlerCancelled = true; },
    });
  });
  const serve = serveNode(harness.handler);
  const sockets = new Set<Socket>();
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    sockets.add(req.socket);
    req.socket.on("close", () => { sockets.delete(req.socket); });
    serve(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const signed = signedPost({ jackAccept: "s1" });
  const headers: Record<string, string> = {};
  signed.request.headers.forEach((value: string, name: string) => { headers[name] = value; });
  headers["jack-accept"] = "s1";
  headers["content-length"] = String(Buffer.byteLength(signed.body, "utf-8"));
  const clientRequest = httpRequest({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers, agent: false });
  clientRequest.on("error", noop);
  let status = 0;
  let contentType: string | undefined;
  let jackAuth: string | undefined;
  let received = "";
  clientRequest.on("response", (res: IncomingMessage) => {
    status = res.statusCode ?? 0;
    const value = res.headers["content-type"];
    contentType = typeof value === "string" ? value : undefined;
    const open = res.headers["jack-auth"];
    jackAuth = typeof open === "string" ? open : undefined;
    res.on("error", noop);
    res.on("data", (chunk: Buffer) => { received += chunk.toString("utf-8"); });
  });
  try {
    clientRequest.end(Buffer.from(signed.body, "utf-8"));
    assert.equal(await waitFor(() => status === 200 && received.includes(FIRST_FRAME)), true,
      "the first signed frame reached the client before the stream closed");
    assert.equal(status, 200);
    assert.equal(contentType, "text/event-stream");
    assert.ok(jackAuth !== undefined && jackAuth.startsWith("s1 "));
    assert.equal(handlerCancelled, false);
    const signal = handlerSignal;
    assert.ok(signal !== undefined);
    assert.equal(signal.aborted, false);
    clientRequest.destroy();
    assert.equal(await waitFor(() => signal.aborted && handlerCancelled), true,
      "the disconnect aborts the handler signal and cancels its body (3.7)");
  } finally {
    clientRequest.destroy();
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

type Deferred<T> = { readonly promise: Promise<T>; readonly resolve: (value: T) => void };
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function fakeNodeRequest(): IncomingMessage {
  const req = new EventEmitter() as IncomingMessage;
  Object.assign(req, { headers: { "content-length": "0" }, rawHeaders: [], url: "/mcp", method: "POST", complete: true });
  return req;
}
function fakeNodeResponse(onWrite: (chunk: Uint8Array) => boolean): ServerResponse {
  const res = new EventEmitter() as ServerResponse;
  Object.assign(res, {
    destroyed: false, writableEnded: false, statusCode: 200, statusMessage: "", setHeader: noop, flushHeaders: noop,
    write: onWrite,
    end: (): void => { Object.assign(res, { writableEnded: true }); },
    destroy: (): void => { Object.assign(res, { destroyed: true }); },
  });
  return res;
}

test("stream server: node adapter waits for drain before reading or writing another chunk", { timeout: 30_000 }, async () => {
  let pulls = 0;
  const source = new ReadableStream<Uint8Array>({
    pull(controller): void { pulls += 1; controller.enqueue(new Uint8Array([pulls])); },
  }, { highWaterMark: 0 });
  const firstWrite = deferred<void>();
  const secondWrite = deferred<void>();
  let writes = 0;
  const res = fakeNodeResponse(() => { writes += 1; (writes === 1 ? firstWrite : secondWrite).resolve(); return false; });
  const req = fakeNodeRequest();
  serveNode(async () => new Response(source, { headers: { "content-type": "text/event-stream" } }))(req, res);
  req.emit("end");
  await firstWrite.promise;
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(pulls, 1);
  assert.equal(writes, 1, "a false write parks the adapter until drain");
  res.emit("drain");
  await secondWrite.promise;
  assert.equal(writes, 2);
  assert.equal(pulls, 2);
});

test("stream server: node adapter cancels a drain wait on close and request abort", { timeout: 30_000 }, async () => {
  for (const event of ["close", "aborted"] as const) {
    const req = fakeNodeRequest();
    let cancelled = false;
    const source = new ReadableStream<Uint8Array>({
      pull(controller): void { controller.enqueue(new Uint8Array([1])); },
      cancel(): void { cancelled = true; },
    }, { highWaterMark: 0 });
    const written = deferred<void>();
    const res = fakeNodeResponse(() => { written.resolve(); return false; });
    serveNode(async () => new Response(source, { headers: { "content-type": "text/event-stream" } }))(req, res);
    req.emit("end");
    await written.promise;
    if (event === "close") res.emit("close");
    else req.emit("aborted");
    for (let i = 0; i < 20 && !cancelled; i += 1) await Promise.resolve();
    assert.equal(cancelled, true, `${event} cancels the stream body`);
    assert.equal((res as unknown as { writableEnded: boolean }).writableEnded, false);
  }
});

test("stream server: node adapter ends and cancels when the injected drain deadline fires", { timeout: 30_000 }, async () => {
  const req = fakeNodeRequest();
  let cancelled = false;
  const source = new ReadableStream<Uint8Array>({
    pull(controller): void { controller.enqueue(new Uint8Array([1])); },
    cancel(): void { cancelled = true; },
  }, { highWaterMark: 0 });
  const written = deferred<void>();
  const res = fakeNodeResponse(() => { written.resolve(); return false; });
  let fireDeadline: (() => void) | undefined;
  let scheduledMs = 0;
  serveNode(async () => new Response(source, { headers: { "content-type": "text/event-stream" } }), {
    streamDrainDeadlineMs: 25,
    scheduleDrainDeadline(callback, delayMs) {
      scheduledMs = delayMs;
      fireDeadline = callback;
      return () => { fireDeadline = undefined; };
    },
  })(req, res);
  req.emit("end");
  await written.promise;
  assert.ok(scheduledMs >= 0 && scheduledMs <= 25, `remaining deadline is within 0..25ms, got ${scheduledMs}`);
  fireDeadline?.();
  for (let i = 0; i < 20 && !cancelled; i += 1) await Promise.resolve();
  assert.equal(cancelled, true);
  assert.equal((res as unknown as { writableEnded: boolean }).writableEnded, true);
});
