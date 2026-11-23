/**
 * The node adapter over a real loopback socket (spec 05 2.1/3.7): a signed
 * stream reaches the client frame by frame while the handler body is still
 * open, and a client disconnect cancels the handler. The signed request is
 * built by the shared harness, so the Fetch handler runs exactly as with any
 * other client.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { serveNode } from "../../../src/server/http/node.js";
import { jackStream } from "../../../src/server/http/stream.js";
import { newStreamServer, signedPost, sseResponse } from "../support/stream-harness.js";

const noop = (): void => {};

/** The one ordinary notification the handler forwards in this test. */
const MESSAGE = '{"jsonrpc":"2.0","method":"notifications/events/active"}';

/** One 2.6 `message` event carrying `data`. */
const messageEvent = (data: string): string => "event: message\ndata: " + data + "\n\n";

/** The first frame of the stream, as it starts on the wire. */
const FIRST_FRAME = "event: message\ndata: ";

/**
 * Bounded polling: at most 50 steps of 10 ms, so the test stays fast and never
 * sleeps longer than that.
 */
async function waitFor(predicate: () => boolean): Promise<boolean> {
  for (let i = 0; i < 50; i += 1) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return predicate();
}

test("stream server: the node adapter streams frames and cancels the handler on a client disconnect", async () => {
  const harness = newStreamServer();
  let handlerSignal: AbortSignal | undefined;
  let handlerCancelled = false;
  harness.setNext(async (req) => {
    // 3.7: the handler reads its own stream context while it runs.
    handlerSignal = jackStream(req)?.signal;
    // `stayOpen` never closes the body; `onCancel` reports the 3.7 cancel.
    return sseResponse([messageEvent(MESSAGE)], {
      stayOpen: true,
      onCancel: (): void => {
        handlerCancelled = true;
      },
    });
  });

  const serve = serveNode(harness.handler);
  const sockets = new Set<Socket>();
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    sockets.add(req.socket);
    req.socket.on("close", () => {
      sockets.delete(req.socket);
    });
    serve(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  // The exact signed bytes a real client would put on the wire.
  const signed = signedPost({ jackAccept: "s1" });
  const headers: Record<string, string> = {};
  signed.request.headers.forEach((value: string, name: string) => {
    headers[name] = value;
  });
  headers["jack-accept"] = "s1";
  headers["content-length"] = String(Buffer.byteLength(signed.body, "utf-8"));

  const clientRequest = httpRequest({
    host: "127.0.0.1",
    port,
    path: "/mcp",
    method: "POST",
    headers,
    agent: false,
  });
  // The destroy() below ends the socket with an error that is expected.
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
    res.on("data", (chunk: Buffer) => {
      received += chunk.toString("utf-8");
    });
  });

  try {
    clientRequest.end(Buffer.from(signed.body, "utf-8"));

    // The frame arrives while the handler stream is still open: the adapter
    // wrote the headers and the chunk instead of buffering the body.
    assert.equal(
      await waitFor(() => status === 200 && received.includes(FIRST_FRAME)),
      true,
      "the first signed frame reached the client before the stream closed",
    );
    assert.equal(status, 200, "the stream answered 200");
    assert.equal(contentType, "text/event-stream", "the answer is an SSE stream");
    assert.ok(jackAuth !== undefined && jackAuth.startsWith("s1 "), "the open Jack-Auth header arrived with the frame");
    assert.equal(handlerCancelled, false, "the handler body was still open when the frame arrived");
    const signal = handlerSignal;
    assert.ok(signal !== undefined, "the handler captured its 3.7 signal");
    assert.equal(signal.aborted, false, "the handler signal is live while the client reads");

    clientRequest.destroy();

    assert.equal(
      await waitFor(() => signal.aborted && handlerCancelled),
      true,
      "the disconnect aborts the handler signal and cancels its body (3.7)",
    );
  } finally {
    clientRequest.destroy();
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
