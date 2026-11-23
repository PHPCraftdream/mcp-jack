/**
 * Server-side close-path tests for signed streams (spec 05, sections 1.1, 1.2,
 * 3.2, 3.4, 3.8, 5.1 and 6.3). Every close shape is observed on the wire:
 * status, headers, response bytes, parsed frames, the delivered messages, the
 * terminal state of the client verifier and the 3.7 cancel hook.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { fixtureNow } from "../../support/client-harness.js";
import { authOf, newStreamServer, parseFrames, readAll, signedPost, sseResponse, verifyBody } from "../support/stream-harness.js";
import type { StreamHarness } from "../support/stream-harness.js";

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

test("stream server: the maximum duration closes with the final response and the end frame", async () => {
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

test("stream server: an oversize message produces the transport-signal frame then the end frame", async () => {
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

test("stream server: the stream closes before the key's successor activation", async () => {
  // The handler forwards one event and then stays quiet, so nothing but the
  // pump's own cutoff timer can close this stream. Remove the 5.1 enforcement
  // and the body never ends: the bounded wait below then fails the test.
  const cutoff = fixtureNow + 1; // 2.2 ts is whole seconds: the nearest cutoff above the open clock
  const harness = newStreamServer({ streams: { successorActivation: () => cutoff }, clock: fixtureNow });
  let cancels = 0;
  harness.setNext(async () =>
    sseResponse([messageEvent(NOTIFICATION)], {
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

  // The default scheduler is a real timer of (cutoff - clock) * 1000 ms, so the
  // close is timer-driven and not handler-driven: the injected clock only
  // decides when the armed timer fires.
  const timedOut = Symbol("read timed out");
  const pause = (ms: number): Promise<typeof timedOut> =>
    new Promise((resolve) => {
      setTimeout(() => {
        resolve(timedOut);
      }, ms);
    });
  const body = response.body;
  assert.ok(body !== null, "the stream carries a body");
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let pending = reader.read();
  let advanced = false;
  let waitedMs = 0;
  for (;;) {
    const step = await Promise.race([pending, pause(100)]);
    if (step === timedOut) {
      waitedMs += 100;
      assert.ok(waitedMs < 2000, "the cutoff timer closes the quiet body on its own");
      continue;
    }
    if (step.done) {
      break;
    }
    chunks.push(step.value);
    if (!advanced) {
      // The first frame is through; the arm already waits (cutoff - clock) ms.
      advanced = true;
      harness.setNow(cutoff);
    }
    pending = reader.read();
  }
  assert.ok(advanced, "the first frame arrived before the clock moved to the cutoff");
  const bytes = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }

  const frames = parseFrames(bytes);
  assert.deepEqual(
    frames.map((frame) => frame.kind),
    ["message", "jack-end"],
    "5.1: the cutoff close signs only the end frame, after the one message frame",
  );
  const message = frames[0];
  const end = frames[1];
  assert.ok(message !== undefined && end !== undefined, "the body carries the message then the end frame");
  if (message === undefined || end === undefined) {
    throw new Error("unreachable: the frame count was asserted above");
  }
  assert.ok(end.ts < cutoff, "5.1: the end frame is signed below the successor activation");
  assert.ok(end.ts >= message.ts, "4.3 step 3: the end frame never goes below the previous frame's ts");
  assert.equal(cancels, 1, "3.7: the cutoff close cancels a handler body that never ended on its own");

  const result = verifyBody(bytes, signed.requestSig, { jackAuth, successorActivation: cutoff });
  assert.deepEqual(result.messages, [NOTIFICATION], "the one forwarded message is delivered");
  assert.deepEqual(result.terminal, { state: "ok" }, "5.1: the stream ends below the cutoff and is complete");
});

test("stream server: no s1 stream without the Jack-Accept opt-in", async () => {
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

test("stream server: a notification request never opens a stream", async () => {
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
