/**
 * Server-side close-path tests for signed streams (spec 05, sections 1.1, 1.2,
 * 3.2, 3.4, 3.8, 5.1 and 6.3). Every close shape is observed on the wire:
 * status, headers, response bytes, parsed frames, the delivered messages, the
 * terminal state of the client verifier and the 3.7 cancel hook.
 */
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fixtureNow } from "../../support/client-harness.js";
import { loadKeys } from "../../support/fixtures/index.js";
import { jackFetchHandler } from "../../../src/server/http/fetch.js";
import { authOf, newStreamServer, parseFrames, readAll, signedPost, sseResponse, verifyBody } from "../support/stream-harness.js";
import type { StreamHarness } from "../support/stream-harness.js";

// The default pump timers are unref'd: keep the loop alive while a test waits for one.
const keepAlive = setInterval(() => undefined, 50);
after(() => {
  clearInterval(keepAlive);
});

/** The one ordinary notification a handler forwards in these tests. */
const NOTIFICATION = '{"jsonrpc":"2.0","method":"notifications/events/active"}';

/** One 2.6 `message` event carrying `data`. */
const messageEvent = (data: string): string => "event: message\ndata: " + data + "\n\n";

/** UTF-8 text of response bytes. */
const textOf = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** The modern protocol version of spec 04 S12, mirrored in `params._meta` and `MCP-Protocol-Version`. */
const MODERN_VERSION = "2026-07-28";

/** The `params.name` of the `events/stream` request; spec 04 S6 mirrors it into `Mcp-Name`. */
const STREAM_NAME = "events-1";

/** A modern `events/stream` request with id 1: only this method has a 6.3 final response. */
const EVENTS_STREAM_BODY =
  '{"jsonrpc":"2.0","id":1,"method":"events/stream","params":{"name":"' +
  STREAM_NAME +
  '","_meta":{"io.modelcontextprotocol/protocolVersion":"' +
  MODERN_VERSION +
  '"}}}';

/** The 6.3 final response of that request, exactly as the server composes it. */
const COMPLETION =
  '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}';

/** A modern JSON-RPC notification: no `id`, so it can never open a stream (3.8). */
const NOTIFICATION_BODY =
  '{"jsonrpc":"2.0","method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"' +
  MODERN_VERSION +
  '"}}}';

/** The 2.18 transport signal of a stream capped at 1024 bytes (3.2). */
const SIGNAL_1024 =
  '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1024}}';

/**
 * The `Jack-Auth` open value of a stream, as a plain string: a `?? ""` plus a
 * length assertion narrows without `assert.ok` on a value passed as a
 * non-optional option.
 */
function openAuth(response: Response): string {
  const jackAuth = authOf(response) ?? "";
  assert.ok(jackAuth.length > 0, "the stream carries its open Jack-Auth");
  return jackAuth;
}

/** 1.1/1.2: the signed v1 501 of a request that may not open a stream. */
async function assertStreamingUnsupported(response: Response): Promise<void> {
  assert.equal(response.status, 501, "the answer is the v1 501 of an unopted-in request");
  assert.equal(response.headers.get("content-type"), "application/json", "the 501 is a plain JSON answer");
  // The identity is authenticated, so even the refusal is signed (01 section 5).
  openAuth(response);
  const text = textOf(await readAll(response));
  assert.ok(text.includes("streaming_unsupported"), "the 501 names streaming_unsupported");
  assert.ok(!text.includes("event:"), "the 501 body carries no stream frame");
}

/** One signed POST with the given `Jack-Accept` value; undefined leaves the header out (1.1). */
async function post(harness: StreamHarness, jackAccept: string | undefined): Promise<Response> {
  const signed = jackAccept === undefined ? signedPost() : signedPost({ jackAccept });
  return harness.handler(signed.request);
}

test("stream server: trailing lone-CR and EOF events are signed before the end frame", { timeout: 30_000 }, async () => {
  const cases = [
    { name: "final lone CR", wire: "event: message\ndata: " + NOTIFICATION + "\r\r" },
    { name: "blank-line event completed before EOF", wire: "event: message\ndata: " + NOTIFICATION + "\n\n" },
  ] as const;
  for (const { name, wire } of cases) {
    const harness = newStreamServer();
    harness.setNext(async () => new Response(new TextEncoder().encode(wire), {
      status: 200, headers: { "content-type": "text/event-stream" },
    }));
    const signed = signedPost({ jackAccept: "s1" });
    const response = await harness.handler(signed.request);
    const frames = parseFrames(await readAll(response));
    assert.deepEqual(frames.map((frame) => frame.kind), ["message", "jack-end"], `${name}: source event is signed before jack-end`);
    assert.equal(frames[0]?.data, NOTIFICATION, `${name}: the source event data survives`);
    assert.ok(frames[0]?.sig.length, `${name}: source event has a signature`);
  }
});

test("stream server: the signed pump waits for downstream pulls when one input chunk completes multiple events", { timeout: 30_000 }, async () => {
  const harness = newStreamServer();
  let sourcePulls = 0;
  let sourceCancelled = false;
  const encoder = new TextEncoder();
  harness.setNext(async () => {
    const source = new ReadableStream<Uint8Array>({
      pull(controller): void {
        sourcePulls += 1;
        if (sourcePulls === 1) {
          controller.enqueue(encoder.encode(messageEvent(NOTIFICATION) + messageEvent(NOTIFICATION)));
        } else {
          controller.close();
        }
      },
      cancel(): void { sourceCancelled = true; },
    }, { highWaterMark: 0 });
    return new Response(source, { headers: { "content-type": "text/event-stream" } });
  });
  const signed = signedPost({ jackAccept: "s1" });
  const response = await harness.handler(signed.request);
  const body = response.body;
  assert.ok(body !== null);
  const reader = body.getReader();
  const first = await reader.read();
  assert.equal(first.done, false);
  assert.equal(sourcePulls, 1, "the second completed event stays behind output backpressure");
  const second = await reader.read();
  assert.equal(second.done, false, "a downstream pull resumes the pending event");
  await reader.cancel();
  assert.equal(sourceCancelled, true, "consumer cancellation releases the source reader");
});

test("stream server: the maximum duration closes with the final response and the end frame", { timeout: 30_000 }, async () => {
  const harness = newStreamServer({ streams: { maxStreamDurationMs: 40 } });
  // stayOpen: only the 3.4 timer may close this stream, never the handler body.
  harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)], { stayOpen: true }));
  const signed = signedPost({ jackAccept: "s1", body: EVENTS_STREAM_BODY });
  // Spec 04 S6: an `events/stream` request mirrors `params.name` into `Mcp-Name`,
  // which is not signed (01 section 5 covers method, target and body only).
  const headers = new Headers(signed.request.headers);
  headers.set("mcp-name", STREAM_NAME);
  const request = new Request(signed.request.url, { method: "POST", headers, body: signed.body });
  const response = await harness.handler(request);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  const jackAuth = openAuth(response);
  const bytes = await readAll(response);

  const frames = parseFrames(bytes);
  assert.deepEqual(
    frames.map((frame) => frame.kind),
    ["message", "message", "jack-end"],
    "3.4: the forwarded notification, the 6.3 final response, then the end frame",
  );
  const lastFrame = frames[frames.length - 1];
  assert.equal(lastFrame?.kind, "jack-end", "the last parsed frame is the end frame (2.16)");
  assert.equal(frames.filter((frame) => frame.kind === "jack-end").length, 1, "6.3: no frame follows the end frame");

  const result = verifyBody(bytes, signed.requestSig, { jackAuth, requestId: 1 });
  assert.deepEqual(result.messages, [NOTIFICATION, COMPLETION], "the duration close writes the final response last");
  assert.deepEqual(result.terminal, { state: "ok" }, "3.4: the duration close is a complete Jack stream");
});

test("stream server: an oversize message produces the transport-signal frame then the end frame", { timeout: 30_000 }, async () => {
  const harness = newStreamServer({ streams: { frameMaxBytes: 1024 } });
  const oversize = "x".repeat(1025); // 2.10: a legal non-JSON data value, one byte over the 3.2 cap
  let cancels = 0;
  // stayOpen: the pump's 3.7 cancellation is the only thing that ends this body.
  harness.setNext(async () =>
    sseResponse([messageEvent(oversize)], {
      stayOpen: true,
      onCancel: () => {
        cancels += 1;
      },
    }),
  );
  const signed = signedPost({ jackAccept: "s1" });
  const response = await harness.handler(signed.request);

  assert.equal(response.status, 200);
  const jackAuth = openAuth(response);
  const bytes = await readAll(response);

  const frames = parseFrames(bytes);
  assert.deepEqual(
    frames.map((frame) => ({ kind: frame.kind, data: frame.data })),
    [
      { kind: "message", data: SIGNAL_1024 },
      { kind: "jack-end", data: "" },
    ],
    "3.2: the oversize signal is the last message, then the end frame",
  );

  const result = verifyBody(bytes, signed.requestSig, { jackAuth, frameMaxBytes: 1024 });
  assert.deepEqual(result.messages, [], "the 2.18 signal is never delivered to the MCP layer");
  assert.deepEqual(
    result.terminal,
    { state: "error", code: "stream_frame_too_large", framesVerified: 1 },
    "4.3 step 6: the signal frame verifies and ends the stream",
  );
  assert.equal(cancels, 1, "3.7: the oversize close cancels the handler body");
});

test("stream server: the stream closes before the key's successor activation", { timeout: 30_000 }, async () => {
  const cutoff = fixtureNow + 1;
  const scheduled: Array<{ callback: () => void; delayMs: number; cancelled: boolean }> = [];
  let scheduledOnce: () => void = () => undefined;
  const armed = new Promise<void>((resolve) => { scheduledOnce = resolve; });
  const harness = newStreamServer({
    streams: {
      successorActivation: () => cutoff,
      schedule: (callback, delayMs) => {
        scheduled.push({ callback, delayMs, cancelled: false });
        scheduledOnce();
        return scheduled.length - 1;
      },
      cancelSchedule: (handle) => {
        const item = scheduled[handle as number];
        if (item !== undefined) item.cancelled = true;
      },
    },
    clock: fixtureNow,
  });
  let cancels = 0;
  harness.setNext(async () => sseResponse([], { stayOpen: true, onCancel: () => { cancels += 1; } }));
  const signed = signedPost({ jackAccept: "s1" });
  const response = await harness.handler(signed.request);
  assert.equal(response.status, 200);
  const jackAuth = openAuth(response);
  const body = response.body;
  assert.ok(body !== null);
  const reader = body.getReader();
  const pendingRead = reader.read();
  await armed;
  const cutoffTimer = scheduled.find((item) => item.delayMs === 0);
  assert.ok(cutoffTimer !== undefined, "the known cutoff arms its scheduler callback");
  assert.equal(cutoffTimer.delayMs, 0, "a cutoff one second away schedules the final callback immediately");
  assert.ok(harness.clock() < cutoff, "the injected clock remains strictly before activation when the callback runs");
  cutoffTimer.callback();
  const result = await pendingRead;
  assert.equal(result.done, false, "the quiet stream writes an end frame");
  const terminal = await reader.read();
  assert.equal(terminal.done, true, "the physical response body closes after the end frame");
  const frames = parseFrames(result.value);
  assert.deepEqual(frames.map((frame) => frame.kind), ["jack-end"], "an idle stream still signs its end frame");
  const end = frames[0];
  assert.ok(end !== undefined);
  assert.ok(end.ts < cutoff, "5.1: end timestamp is strictly below activation");
  assert.equal(end.ts, fixtureNow, "end timestamp is sampled below cutoff without advancing to equality");
  assert.equal(cancels, 1, "3.7: cutoff closes and cancels the quiet handler body");
  const verified = verifyBody(result.value, signed.requestSig, { jackAuth, successorActivation: cutoff });
  assert.deepEqual(verified.terminal, { state: "ok" });
});

test("stream server: a successor learned on bounded recheck closes a quiet stream", { timeout: 30_000 }, async () => {
  const cutoff = fixtureNow + 1;
  let activation: number | undefined;
  const scheduled: Array<{ callback: () => void; delayMs: number; cancelled: boolean; fired: boolean }> = [];
  let armedResolve: () => void = () => undefined;
  const armed = new Promise<void>((resolve) => { armedResolve = resolve; });
  const harness = newStreamServer({ clock: fixtureNow, streams: {
    successorActivation: () => activation,
    schedule: (callback, delayMs) => {
      let item: { callback: () => void; delayMs: number; cancelled: boolean; fired: boolean };
      item = { callback: () => { item.fired = true; callback(); }, delayMs, cancelled: false, fired: false };
      scheduled.push(item);
      armedResolve();
      return scheduled.length - 1;
    },
    cancelSchedule: (handle) => {
      const item = scheduled[handle as number];
      if (item !== undefined) item.cancelled = true;
    },
  } });
  harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)], { stayOpen: true }));
  const response = await harness.handler(signedPost({ jackAccept: "s1" }).request);
  const reader = response.body?.getReader();
  assert.ok(reader !== undefined);
  const priorChunk = await reader.read();
  assert.equal(priorChunk.done, false);
  const prior = parseFrames(priorChunk.value)[0];
  assert.ok(prior !== undefined);
  const pending = reader.read();
  await armed;
  const recheck = scheduled.find((item) => item.delayMs === 1000 && !item.cancelled && !item.fired);
  assert.ok(recheck !== undefined, "unknown activation is rechecked on bounded schedule");
  activation = cutoff;
  assert.ok(harness.clock() < cutoff, "the injected clock remains before the newly learned activation");
  recheck.callback();
  const closeTimer = scheduled.find((item) => item.delayMs === 0 && !item.cancelled && !item.fired);
  assert.ok(closeTimer !== undefined, "learning the activation arms its real close deadline");
  assert.equal(scheduled.filter((item) => item.delayMs === 0 && !item.cancelled && !item.fired).length, 1, "exactly one unfired cutoff schedule remains armed");
  assert.ok(harness.clock() < cutoff, "the close callback runs while the injected clock is still below cutoff");
  closeTimer.callback();
  const frame = await pending;
  assert.equal(frame.done, false);
  assert.ok(frame.value !== undefined);
  const frames = parseFrames(frame.value);
  assert.deepEqual(frames.map((item) => item.kind), ["jack-end"]);
  assert.ok(frames[0] !== undefined);
  assert.ok(frames[0].ts < cutoff);
  assert.ok(frames[0].ts >= fixtureNow);
  assert.equal((await reader.read()).done, true);
});

test("stream server: an impossible cutoff closes without signing an invalid end frame", { timeout: 30_000 }, async () => {
  let activation: number | undefined;
  const scheduled: Array<{ callback: () => void; delayMs: number; cancelled: boolean; fired: boolean }> = [];
  const harness = newStreamServer({ clock: fixtureNow, streams: {
    successorActivation: () => activation,
    schedule: (callback, delayMs) => {
      let item: { callback: () => void; delayMs: number; cancelled: boolean; fired: boolean };
      item = { callback: () => { item.fired = true; callback(); }, delayMs, cancelled: false, fired: false };
      scheduled.push(item);
      return scheduled.length - 1;
    },
    cancelSchedule: (handle) => {
      const item = scheduled[handle as number];
      if (item !== undefined) item.cancelled = true;
    },
  } });
  harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)], { stayOpen: true }));
  const signed = signedPost({ jackAccept: "s1" });
  const response = await harness.handler(signed.request);
  const reader = response.body?.getReader();
  assert.ok(reader !== undefined);
  const first = await reader.read();
  assert.equal(first.done, false);
  const prior = parseFrames(first.value)[0];
  assert.ok(prior !== undefined);
  activation = prior.ts;
  harness.setNow(prior.ts);
  const recheck = scheduled.find((item) => item.delayMs === 1000 && !item.cancelled && !item.fired);
  assert.ok(recheck !== undefined);
  recheck.callback();
  const closeTimer = scheduled.find((item) => item.delayMs === 0 && !item.cancelled && !item.fired);
  assert.ok(closeTimer !== undefined, "the learned activation arms a separate close callback");
  closeTimer.callback();
  assert.equal((await reader.read()).done, true, "the impossible-safe path physically closes");
  const all = new Uint8Array(first.value);
  const frames = parseFrames(all);
  assert.deepEqual(frames.map((item) => item.kind), ["message"], "the prior message is retained and no end frame is signed");
  assert.equal(frames.filter((item) => item.kind === "jack-end").length, 0);
  const priorMessage = frames.find((item) => item.kind === "message");
  assert.ok(priorMessage !== undefined);
  assert.equal(priorMessage.ts, activation);
});
test("stream server: no s1 stream without the Jack-Accept opt-in", { timeout: 30_000 }, async () => {
  const harness = newStreamServer();
  harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)]));

  // 1.1: an absent header, another scheme, a token with a stray character and
  // a case-wrong registered token all leave the stream disabled.
  for (const offer of [undefined, "s2", "s1x", "S1"] as const) {
    await assertStreamingUnsupported(await post(harness, offer));
  }

  // 1.2: a legacy-profile server ignores Jack-Accept entirely.
  const legacy = newStreamServer({ profile: "legacy" });
  legacy.setNext(async () => sseResponse([messageEvent(NOTIFICATION)]));
  await assertStreamingUnsupported(await post(legacy, "s1"));
});

test("stream server: notification SSE keeps the legacy signed 501 unless modern opt-in is present", { timeout: 30_000 }, async () => {
  const expected = '{"error":{"code":"streaming_unsupported","message":"streaming responses cannot be signed in v0.1"}}';
  const disabled = newStreamServer({ profile: "modern" });
  const serverSeed = loadKeys().keys.find((key) => key.name === "svc");
  assert.ok(serverSeed !== undefined, "the fixture server key exists");
  const disabledHandler = jackFetchHandler({
    verifier: disabled.verifier,
    serverKey: new Uint8Array(Buffer.from(serverSeed.seedHex, "hex")),
    profile: "modern",
  }, async () => sseResponse([messageEvent(NOTIFICATION)]));
  const disabledRequest = signedPost({ body: NOTIFICATION_BODY, jackAccept: "s1" });
  const disabledResponse = await disabledHandler(disabledRequest.request);
  assert.equal(disabledResponse.status, 501, "streams-disabled modern notifications keep the legacy refusal");
  assert.ok(authOf(disabledResponse) !== undefined, "the compatibility refusal is signed");
  assert.deepEqual(await readAll(disabledResponse), new TextEncoder().encode(expected), "the refusal bytes are exactly the legacy v1 body");

  for (const settings of [
    { profile: "modern" as const, jackAccept: undefined },
    { profile: "legacy" as const, jackAccept: "s1" },
  ]) {
    const harness = newStreamServer({ profile: settings.profile });
    harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)]));
    const signed = signedPost({ body: NOTIFICATION_BODY, ...(settings.jackAccept === undefined ? {} : { jackAccept: settings.jackAccept }) });
    const response = await harness.handler(signed.request);
    assert.equal(response.status, 501, "notifications outside the opted-in modern stream profile remain unsupported");
    assert.ok(authOf(response) !== undefined, "the compatibility refusal is signed");
    assert.equal(textOf(await readAll(response)), expected, "the legacy v1 refusal bytes are unchanged");
  }
  const optedIn = newStreamServer();
  optedIn.setNext(async () => sseResponse([messageEvent(NOTIFICATION)]));
  const signed = signedPost({ body: NOTIFICATION_BODY, jackAccept: "s1" });
  const response = await optedIn.handler(signed.request);
  assert.equal(response.status, 202, "a modern opted-in notification that attempts SSE gets the signed 202");
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.ok(authOf(response) !== undefined);
  assert.equal((await readAll(response)).length, 0);
});

test("stream server: a notification request never opens a stream", { timeout: 30_000 }, async () => {
  const harness = newStreamServer();
  harness.setNext(async () => sseResponse([messageEvent(NOTIFICATION)]));
  // 3.8: a JSON-RPC notification has no id, so it can never become an s1
  // stream: its text/event-stream answer is discarded and replaced by the
  // signed v1 202 with an empty body.
  const signed = signedPost({ jackAccept: "s1", body: NOTIFICATION_BODY });
  const response = await harness.handler(signed.request);

  assert.equal(response.status, 202, "3.8: a notification answer that tried to stream is a 202");
  assert.equal(response.headers.get("content-type"), "application/json", "the 202 is a plain JSON answer");
  // The identity is authenticated, so the 202 is a signed v1 answer.
  openAuth(response);
  const bytes = await readAll(response);
  assert.equal(bytes.length, 0, "3.8: the 202 carries an empty body");
  const text = textOf(bytes);
  assert.ok(!text.includes("event:"), "the 202 body carries no stream frame");
  assert.ok(!text.includes("jack:"), "the 202 body carries no signed frame field");
});
