/**
 * Server-side admission and context tests for signed streams (spec 05,
 * sections 3.3, 3.5, 3.6 and 3.7). Every assertion is observable from the
 * wire or from the handler's own `jackStream()` context: response bytes,
 * parsed frames, `Jack-Auth`, `signal.aborted` and the verified messages.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { verifyResponse } from "../../../src/client/signing/auth.js";
import { DurableNonceAdmission } from "../../../src/server/durable/admission.js";
import { DurableNonceStore } from "../../../src/server/durable/store.js";
import { jackStream } from "../../../src/server/http/stream.js";
import { fixtureNow, seedSignerByName } from "../../support/client-harness.js";
import { authOf, newStreamServer, parseFrames, readAll, signedPost, sseResponse, verifyBody } from "../support/stream-harness.js";

/** The one ordinary notification the handler forwards in these tests. */
const MESSAGE = '{"jsonrpc":"2.0","method":"notifications/events/active"}';

/** One 2.6 `message` event carrying `data`. */
const messageEvent = (data: string): string => "event: message\ndata: " + data + "\n\n";

/** UTF-8 text of response bytes. */
const textOf = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** The pinned `svc` public key the client verifies the refusal signatures against (4.2 step 4). */
const SVC_PUBLIC_KEY = seedSignerByName("svc").publicKey();

/** The durable store deployment binding and its immutable window W (spec section 2). */
const DEPLOYMENT = "stream-admission-test-deployment";
const DURABLE_WINDOW = 30;

/** The durable store is Linux-gated like the rotation stores (private owner marker). */
const linux = process.platform === "linux";

test("stream server: the per-identity concurrent stream limit refuses before any byte", { timeout: 30_000 }, async () => {
  const harness = newStreamServer({ streams: { maxConcurrentStreams: 1 } });
  let calls = 0;
  harness.setNext(async () => {
    calls += 1;
    return calls === 1 ? sseResponse([messageEvent(MESSAGE)], { stayOpen: true }) : sseResponse([messageEvent(MESSAGE)]);
  });

  const first = signedPost({ id: 1, jackAccept: "s1" });
  const held = await harness.handler(first.request);
  assert.equal(held.status, 200, "the first stream is admitted");
  assert.equal(held.headers.get("content-type"), "text/event-stream");

  // Same identity (alice), fresh nonce, still at the limit of one stream.
  const second = signedPost({ id: 7, jackAccept: "s1" });
  const refused = await harness.handler(second.request);
  assert.equal(refused.status, 429, "the 3.3 limit answers 429");
  assert.equal(refused.headers.get("content-type"), "application/json");
  // Spec 05 defines no retry-after on the 3.3 refusal.
  assert.equal(refused.headers.get("retry-after"), null, "the 3.3 refusal carries no retry-after");
  const refusalAuth = authOf(refused);
  assert.ok(refusalAuth !== undefined, "the 3.3 refusal is a signed v1 response");

  const refusedBytes = await readAll(refused);
  const refusedText = textOf(refusedBytes);
  assert.equal(
    refusedText,
    '{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"stream_limit_exceeded"}}',
    "the refusal body is exactly the 3.3 JSON-RPC error with the request id",
  );
  assert.ok(!refusedText.includes("event:"), "no stream byte precedes the refusal");
  // 01 section 5: the 429 verifies as a v1 response over the request's own sig.
  const refusalAuthValue = refusalAuth ?? "";
  assert.ok(refusalAuthValue.length > 0, "the 3.3 refusal is a signed v1 response");
  verifyResponse(SVC_PUBLIC_KEY, 429, [refusalAuthValue], second.requestSig, refusedBytes, harness.clock(), 0);

  // Releasing the slot (client disconnect) frees it again (3.3).
  const heldBody = held.body;
  assert.ok(heldBody !== null);
  await heldBody.cancel();

  const third = signedPost({ id: 2, jackAccept: "s1" });
  const opened = await harness.handler(third.request);
  assert.equal(opened.status, 200, "a released stream frees its slot");
  const openedBytes = await readAll(opened);
  const frames = parseFrames(openedBytes);
  const head = frames[0];
  if (head === undefined) throw new Error("the reopened stream carries a frame");
  assert.equal(head.kind, "message");
  assert.equal(head.seq, 0, "the first signed frame starts the chain at seq 0");
  assert.ok(textOf(openedBytes).startsWith("event: message\n"), "the body starts with a signed message frame");
});

test("stream server: heartbeats are granted, clamped and delivered as signed frames", { timeout: 30_000 }, async () => {
  const heartbeat = '{"jsonrpc":"2.0","method":"notifications/events/heartbeat","params":{"cursor":null}}';
  const harness = newStreamServer({ streams: { windowSeconds: 30, heartbeatMs: 60000, frameMaxBytes: 4096 } });
  let heartbeatMs: number | undefined;
  let frameMaxBytes: number | undefined;
  let handlerSawContext = false;
  harness.setNext(async (req) => {
    const ctx = jackStream(req);
    if (ctx === undefined) throw new Error("the handler sees its stream context");
    handlerSawContext = true;
    heartbeatMs = ctx.heartbeatMs;
    frameMaxBytes = ctx.frameMaxBytes;
    return sseResponse([messageEvent(heartbeat), ": keep-alive\n"]);
  });
  const signed = signedPost({ jackAccept: "s1" });
  const response = await harness.handler(signed.request);
  assert.equal(response.status, 200);
  const jackAuth = authOf(response) ?? "";
  assert.ok(jackAuth.length > 0, "the stream carries its open Jack-Auth");
  const bytes = await readAll(response);

  assert.equal(handlerSawContext, true, "the signed request traversed the wrapped handler with jackStream context");
  assert.equal(heartbeatMs, 15000, "3.5 clamps 60000 ms to floor(30 * 500)");
  assert.equal(frameMaxBytes, 4096, "the handler sees the configured 3.2 cap");

  const result = verifyBody(bytes, signed.requestSig, { jackAuth, windowSeconds: 30, frameMaxBytes: 4096 });
  assert.deepEqual(result.messages, [heartbeat], "the heartbeat is delivered and the comment is dropped");
  assert.deepEqual(result.terminal, { state: "ok" }, "the handler body ended with a verified end frame");
});

test("stream server: the nonce is reserved before the stream opens and the replay is refused", { timeout: 30_000 }, async () => {
  const harness = newStreamServer();
  harness.setNext(async (req) => {
    assert.ok(jackStream(req) !== undefined, "the first request opens a real stream");
    return sseResponse([messageEvent(MESSAGE)]);
  });
  const first = signedPost({ jackAccept: "s1" });
  const opened = await harness.handler(first.request);
  assert.equal(opened.status, 200);
  assert.equal(opened.headers.get("content-type"), "text/event-stream");
  const firstBytes = await readAll(opened);
  assert.ok(parseFrames(firstBytes).length >= 1, "the stream delivered at least one frame before the replay");

  // The byte-identical request: same nonce, same signed target and body.
  const replayRequest = new Request(first.request.url, {
    method: "POST",
    headers: first.request.headers,
    body: first.body,
  });
  const replay = await harness.handler(replayRequest);

  // Spec 01 section 5: an authentication failure (step 8, replayed_nonce) is
  // never signed, so the refusal is the v1 envelope with no Jack-Auth; the
  // important part for 3.6 is that it is not a stream.
  assert.equal(replay.status, 401, "a consumed nonce is refused before any stream opens");
  assert.equal(replay.headers.get("content-type"), "application/json", "a refusal is a v1 answer, never text/event-stream");
  assert.equal(replay.headers.get("www-authenticate"), "Jack-Auth", "the 401 names the Jack-Auth scheme");
  assert.equal(authOf(replay), undefined, "an authentication failure carries no Jack-Auth response header");
  const replayBody = textOf(await readAll(replay));
  assert.ok(replayBody.includes("replayed_nonce"), "the refusal names the 3.6 replay");
  assert.ok(!replayBody.includes("event:"), "the refusal body is not a stream");
  assert.ok(!replayBody.includes("jack:"), "the refusal body carries no signed frame");
});

test("stream server: a durable-store replay is refused while the first handler still runs", { skip: !linux, timeout: 30_000 }, async () => {
  // A fresh private temp directory for the durable store, as in
  // ts/test/server/durable/admission.test.ts (owner marker, 0700 directory).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-stream-admission-")));
  chmodSync(dir, 0o700);
  const path = join(dir, "nonce-store");
  const clock = (): number => fixtureNow;
  DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: DURABLE_WINDOW, now: clock });
  const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: DURABLE_WINDOW, now: clock });
  // The harness verifier reserves in this store and wires no volatile one.
  const harness = newStreamServer({
    clock: fixtureNow,
    durable: new DurableNonceAdmission({ store, now: clock }),
  });

  // 3.6: the nonce is committed before the first response byte, so the first
  // handler can still be running when the replay arrives.
  let releaseFirst: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let signalEntered: () => void = () => undefined;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  let firstStarted = false;
  let firstBodyUsed = false;
  harness.setNext(async (req) => {
    assert.ok(jackStream(req) !== undefined, "the first request begins a signed stream");
    firstStarted = true;
    signalEntered();
    await gate; // blocks here until the replay has been refused
    firstBodyUsed = true;
    return sseResponse([messageEvent(MESSAGE)]);
  });

  const first = signedPost({ jackAccept: "s1" });
  const firstPending = harness.handler(first.request);
  let opened: Response | undefined;
  try {
    await entered;
    assert.equal(firstStarted, true, "the first handler is running before the replay");

    assert.equal(firstBodyUsed, false, "the blocked handler has not returned a response body or emitted a byte");
    // Byte-identical: same nonce, same signed target and body.
    const replayRequest = new Request(first.request.url, {
      method: "POST",
      headers: first.request.headers,
      body: first.body,
    });
    const replay = await harness.handler(replayRequest);

    assert.equal(replay.status, 401, "the durable store refuses the replayed nonce");
    assert.equal(replay.headers.get("content-type"), "application/json", "a refusal is a v1 answer, never text/event-stream");
    assert.equal(authOf(replay), undefined, "an authentication failure carries no Jack-Auth response header");
    const replayBody = textOf(await readAll(replay));
    assert.ok(replayBody.includes("replayed_nonce"), "the refusal names the 3.6 replay");
    assert.ok(!replayBody.includes("event:"), "the refusal body is not a stream");
  } finally {
    releaseFirst();
    try {
      opened = await firstPending;
    } catch {
      opened = undefined;
    }
    if (opened !== undefined) {
      await opened.body?.cancel();
    }
    try {
      store.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
