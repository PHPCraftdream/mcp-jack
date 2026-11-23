/**
 * Client-side tests of signed streams (spec 05 sections 1.1, 1.4, 2.6, 2.16,
 * 4.2-4.6, 5.2 and 6.1): the idle deadline on the injected clock, the
 * successor-activation cutoff, caller cancellation of an open stream and the
 * opt-in rule of the re-emitting transport.
 *
 * Every stream here is built by the SDK's own `StreamSigner` over the `svc`
 * fixture key, opened over the request `sig` the fake server parsed from the
 * request's `Jack-Auth` (2.5). Assertions are observable only: verified
 * messages, terminal codes, re-emitted bytes, request headers and the abort
 * signal the fake server recorded.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { openSignedStream } from "../../../src/client/stream/session.js";
import { createSigningFetch, StreamingUnsupportedError } from "../../../src/client/transport/transport.js";
import { StreamVerifyError } from "../../../src/stream/codes.js";
import { StreamSigner } from "../../../src/stream/signer.js";
import { StreamVerifier, verifySignedStream } from "../../../src/stream/verify.js";
import type { StreamServerKey, StreamVerifyChunk } from "../../../src/stream/verify.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "../../support/client-harness.js";

/** One ordinary verified notification (2.6 `message` frame). */
const MESSAGE_ONE = '{"jsonrpc":"2.0","method":"notifications/events/active"}';

/** One ordinary verified result message. */
const MESSAGE_TWO = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

/** The SDK URL the signed fetch is pointed at; the fake fetch intercepts it. */
const URL_UNDER_TEST = "https://mcp.test/mcp";

/** The server side of these streams: the `svc` fixture key (2.5, 3.1). */
const svcSigner = seedSignerByName("svc");

/** The client side: another fixture user key, which signs the requests. */
const clientSigner = seedSignerByName("alice");

/** The pinned `svc` key the client trusts (4.2 step 4). */
const SVC_PUBLIC_KEY = svcSigner.publicKey();
const SVC_KID = svcSigner.kid();

/**
 * The `sig` of a v1 request, which the open header binds the stream to (2.5).
 * The injected-clock and cutoff tests build no request, so any canonical
 * 64-byte value stands in for it.
 */
const REQUEST_SIG = encodeBase64URL(new Uint8Array(64));

/** 16 fresh bytes as canonical base64url: the 2.4 `sid` of one stream. */
function freshSid(): string {
  return encodeBase64URL(new Uint8Array(randomBytes(16)));
}

/** One signer over the `svc` key whose open header carries `openerTs`. */
function streamSigner(openerTs: number): StreamSigner {
  return new StreamSigner({ key: svcSigner, requestSig: REQUEST_SIG, sid: freshSid(), openerTs, status: 200 });
}

/** The headers of a 200 `text/event-stream` answer with its `Jack-Auth` open value (1.4, 2.1). */
function openHeaders(signer: StreamSigner): readonly (readonly [string, string])[] {
  return [
    ["content-type", "text/event-stream"],
    ["jack-auth", signer.openAuthValue()],
  ] as const;
}

/** Concatenates byte arrays in order. */
function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** The key lookup of one pinned `svc` key with no known successor activation. */
function pinnedSvc(kid: string): StreamServerKey | undefined {
  return kid === SVC_KID ? { kid, publicKey: SVC_PUBLIC_KEY } : undefined;
}

/** The key lookup of one `svc` key whose successor activates at `activation` (5.2). */
function cutAt(activation: number): (kid: string) => StreamServerKey | undefined {
  return (kid) => (kid === SVC_KID ? { kid, publicKey: SVC_PUBLIC_KEY, successorActivation: activation } : undefined);
}

/** An empty chunk: the body reaches this arrival time without completing a frame. */
function noBytes(): Uint8Array {
  return new Uint8Array(0);
}

test("stream client: the idle timeout runs on the injected clock", () => {
  const signer = streamSigner(fixtureNow);
  const message = signer.frame(MESSAGE_ONE, fixtureNow);
  const headers = openHeaders(signer);
  const options = { status: 200, headers, resolveKey: pinnedSvc, now: (): number => fixtureNow, requestSig: REQUEST_SIG };

  // 4.5: a silence exactly equal to streamIdleMs is still alive, so the ended
  // body is the 4.4 truncation and the verified frame stays delivered.
  const equalSilence: readonly StreamVerifyChunk[] = [
    { bytes: message.bytes, arrivedAtMs: 0 },
    { bytes: noBytes(), arrivedAtMs: 90000 },
  ];
  const alive = verifySignedStream({ ...options, chunks: equalSilence });
  assert.deepEqual(alive.messages, [MESSAGE_ONE]);
  assert.deepEqual(alive.terminal, { state: "error", code: "stream_truncated", framesVerified: 1 });

  // One millisecond more is idle.
  const oneMore = verifySignedStream({
    ...options,
    chunks: [
      { bytes: message.bytes, arrivedAtMs: 0 },
      { bytes: noBytes(), arrivedAtMs: 90001 },
    ],
  });
  assert.deepEqual(oneMore.terminal, { state: "error", code: "stream_idle", framesVerified: 1 });

  // A frame whose chunk arrives after the deadline is not verified at all.
  const late = verifySignedStream({ ...options, chunks: [{ bytes: message.bytes, arrivedAtMs: 90001 }] });
  assert.deepEqual(late.messages, []);
  assert.deepEqual(late.terminal, { state: "error", code: "stream_idle", framesVerified: 0 });

  // The verifier's own standing-context check agrees at the same boundary.
  const verifier = new StreamVerifier({ resolveKey: pinnedSvc, now: (): number => fixtureNow, requestSig: REQUEST_SIG });
  verifier.open(200, headers);
  verifier.idle(90000); // an equal silence does not throw
  let idleError: unknown;
  try {
    verifier.idle(90001);
  } catch (err) {
    idleError = err;
  }
  if (!(idleError instanceof StreamVerifyError)) {
    throw new Error(`idle(90001) must throw a StreamVerifyError, got ${String(idleError)}`);
  }
  assert.equal(idleError.code, "stream_idle");
  assert.equal(idleError.framesVerified, 0);
});

test("stream client: a frame at or after the known successor activation is rejected", () => {
  const activation = fixtureNow + 5;
  const base = { status: 200, resolveKey: cutAt(activation), now: (): number => fixtureNow, requestSig: REQUEST_SIG };

  // 4.3 step 4: a message frame at A is rejected although its signature verifies.
  const messageSigner = streamSigner(fixtureNow);
  const atCutoff = messageSigner.frame(MESSAGE_ONE, activation);
  const frameCase = verifySignedStream({
    ...base,
    headers: openHeaders(messageSigner),
    chunks: [{ bytes: atCutoff.bytes, arrivedAtMs: 0 }],
  });
  assert.deepEqual(frameCase.messages, []);
  assert.deepEqual(frameCase.terminal, { state: "error", code: "stream_after_cutoff", framesVerified: 0 });

  // 5.2: an end frame at A after a good message is the cutoff, not the
  // truncation the missing end frame would otherwise report.
  const endSigner = streamSigner(fixtureNow);
  const good = endSigner.frame(MESSAGE_ONE, fixtureNow);
  const lateEnd = endSigner.end(activation);
  const endCase = verifySignedStream({
    ...base,
    headers: openHeaders(endSigner),
    chunks: [{ bytes: concatBytes(good.bytes, lateEnd.bytes), arrivedAtMs: 0 }],
  });
  assert.deepEqual(endCase.messages, [MESSAGE_ONE]);
  assert.deepEqual(endCase.terminal, { state: "error", code: "stream_after_cutoff", framesVerified: 1 });

  // 4.2 step 6: an open header at A never opens the stream, so no frame is read.
  const openSigner = streamSigner(activation);
  const openCase = verifySignedStream({
    ...base,
    headers: openHeaders(openSigner),
    chunks: [{ bytes: openSigner.frame(MESSAGE_ONE, activation).bytes, arrivedAtMs: 0 }],
  });
  assert.deepEqual(openCase.messages, []);
  assert.deepEqual(openCase.terminal, { state: "error", code: "stream_after_cutoff", framesVerified: 0 });
});

test("stream client: the caller can cancel an open stream", async () => {
  let recordedAccept: string | null = null;
  let recordedSignal: AbortSignal | null = null;
  let openedSid = "";
  let bodyCancelled = false;

  const fakeFetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    recordedAccept = headers.get("jack-accept");
    recordedSignal = init?.signal ?? null;
    const authValue = headers.get("jack-auth");
    assert.ok(authValue !== null, "the signed request carries Jack-Auth");
    // 2.5: the stream is opened over this request's own sig.
    const opener = new StreamSigner({
      key: svcSigner,
      requestSig: parseRequestAuth([authValue]).sig,
      sid: freshSid(),
      openerTs: fixtureNow,
      status: 200,
    });
    openedSid = opener.sid;
    const frame = opener.frame(MESSAGE_ONE, fixtureNow);
    const body = new ReadableStream<Uint8Array>({
      start(controller: ReadableStreamDefaultController<Uint8Array>): void {
        controller.enqueue(frame.bytes); // one verified frame, then silence
      },
      cancel: (): void => {
        bodyCancelled = true;
      },
    });
    return new Response(body, {
      status: 200,
      headers: { "content-type": "text/event-stream", "jack-auth": opener.openAuthValue() },
    });
  };

  const session = await openSignedStream(
    { aud: fixtureAud, signer: clientSigner, serverKey: SVC_PUBLIC_KEY, clock: (): number => fixtureNow },
    URL_UNDER_TEST,
    { method: "POST" },
    fakeFetch,
  );
  assert.equal(recordedAccept, "s1", "1.1: an opt-in request carries Jack-Accept: s1");
  assert.equal(session.sid, openedSid);

  const messages = session.messages();
  const first = await messages.next();
  assert.deepEqual(first, { value: MESSAGE_ONE, done: false });

  await session.cancel();
  const signal = recordedSignal;
  assert.ok(signal !== null, "the fake fetch recorded the request signal");
  assert.equal(signal.aborted, true, "cancel aborts the connection");
  assert.equal(bodyCancelled, true, "cancel closes the response body");
  // 4.4: a cancelled body never saw an end frame, so the terminal is the
  // truncation. The pump no longer retains history: verified values travel
  // through the messages()/sse() views while `done` carries the terminal.
  assert.deepEqual((await session.done).terminal, { state: "error", code: "stream_truncated", framesVerified: 1 });

  // 4.4: the verified message was delivered; the view then reports the failure
  // instead of yielding a second message, and the iterator finishes.
  let nextError: unknown;
  try {
    await messages.next();
  } catch (err) {
    nextError = err;
  }
  if (!(nextError instanceof StreamVerifyError)) {
    throw new Error(`the iterator must report the terminal failure, got ${String(nextError)}`);
  }
  assert.equal(nextError.code, "stream_truncated");
  assert.equal(nextError.framesVerified, 1);
  const after = await messages.next();
  assert.equal(after.done, true);
  assert.equal(after.value, undefined);
});

test("stream client: an s1 stream is refused unless the client opted in", async () => {
  // Without `streams` the v1 guard answers a text/event-stream with
  // StreamingUnsupportedError, discards the body and sends no opt-in header.
  let refusedAccept: string | null = null;
  let refusedCancelled = false;
  const refusedFetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    refusedAccept = new Headers(init?.headers).get("jack-accept");
    const body = new ReadableStream<Uint8Array>({
      start(controller: ReadableStreamDefaultController<Uint8Array>): void {
        controller.enqueue(new TextEncoder().encode("event: message\ndata: {}\n\n"));
      },
      cancel: (): void => {
        refusedCancelled = true;
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
  };
  const refusing = createSigningFetch(
    { aud: fixtureAud, signer: clientSigner, serverKey: SVC_PUBLIC_KEY, clock: (): number => fixtureNow },
    refusedFetch,
  );
  let refusal: unknown;
  try {
    await refusing(URL_UNDER_TEST, { method: "POST" });
  } catch (err) {
    refusal = err;
  }
  assert.ok(refusal instanceof StreamingUnsupportedError, "an unopted text/event-stream is refused");
  assert.equal(refusedCancelled, true, "the refused body is cancelled");
  assert.equal(refusedAccept, null, "1.1: no Jack-Accept without the opt-in");

  // With `streams: {}` the opt-in header is sent and the verified data values
  // come back as the 6.1 bytes, one event per verified message frame. The
  // expected bytes are written out independently of the production serializer.
  const expected =
    'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/events/active"}\n\n' +
    'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n';
  let optedAccept: string | null = null;
  const optedFetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    optedAccept = headers.get("jack-accept");
    const authValue = headers.get("jack-auth");
    assert.ok(authValue !== null, "the opted-in request carries Jack-Auth");
    // 2.5: the stream is opened over this request's own sig, never a stand-in.
    const requestSig = parseRequestAuth([authValue]).sig;
    const signer = new StreamSigner({ key: svcSigner, requestSig, sid: freshSid(), openerTs: fixtureNow, status: 200 });
    const optedBody = concatBytes(
      signer.frame(MESSAGE_ONE, fixtureNow).bytes,
      signer.frame(MESSAGE_TWO, fixtureNow).bytes,
      signer.end(fixtureNow).bytes,
    );
    return new Response(optedBody, {
      status: 200,
      headers: { "content-type": "text/event-stream", "jack-auth": signer.openAuthValue() },
    });
  };
  const opting = createSigningFetch(
    { aud: fixtureAud, signer: clientSigner, serverKey: SVC_PUBLIC_KEY, clock: (): number => fixtureNow, streams: {} },
    optedFetch,
  );
  const reemitted = await opting(URL_UNDER_TEST, { method: "POST" });
  assert.equal(optedAccept, "s1");
  assert.equal(reemitted.status, 200);
  assert.deepEqual(new Uint8Array(await reemitted.arrayBuffer()), new TextEncoder().encode(expected));

  // A tampered last frame fails 4.3 step 5: the bytes that already verified
  // stay readable and reading the rest rejects (4.4).
  const tamperedFetch = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    const authValue = headers.get("jack-auth");
    assert.ok(authValue !== null, "the tampered request carries Jack-Auth");
    // 2.5: the pre-signature frames also bind to this request's own sig.
    const requestSig = parseRequestAuth([authValue]).sig;
    const tamperedSigner = new StreamSigner({ key: svcSigner, requestSig, sid: freshSid(), openerTs: fixtureNow, status: 200 });
    const verifiedFrame = tamperedSigner.frame(MESSAGE_ONE, fixtureNow);
    const tamperedEnd = tamperedSigner.end(fixtureNow);
    const body = concatBytes(verifiedFrame.bytes, tamperFirstSigChar(tamperedEnd.bytes));
    return new Response(body, {
      status: 200,
      headers: { "content-type": "text/event-stream", "jack-auth": tamperedSigner.openAuthValue() },
    });
  };
  const watching = createSigningFetch(
    { aud: fixtureAud, signer: clientSigner, serverKey: SVC_PUBLIC_KEY, clock: (): number => fixtureNow, streams: {} },
    tamperedFetch,
  );
  const tampered = await watching(URL_UNDER_TEST, { method: "POST" });
  assert.ok(tampered.body !== null, "the re-emitted stream has a body");
  const reader = tampered.body.getReader();
  const firstBytes = await reader.read();
  assert.equal(firstBytes.done, false, "the verified message is readable");
  // 6.1 again, against the same independently written bytes.
  assert.equal(
    new TextDecoder().decode(firstBytes.value),
    'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/events/active"}\n\n',
  );
  let bodyError: unknown;
  try {
    await reader.read();
  } catch (err) {
    bodyError = err;
  }
  if (!(bodyError instanceof StreamVerifyError)) {
    throw new Error(`the tampered frame must error the body, got ${String(bodyError)}`);
  }
  assert.equal(bodyError.code, "stream_bad_signature");
  assert.equal(bodyError.framesVerified, 1);
});

/** Replaces the first character of the last `sig=` value with another base64url character. */
function tamperFirstSigChar(frameBytes: Uint8Array): Uint8Array {
  const text = new TextDecoder().decode(frameBytes);
  const marker = "sig=";
  const at = text.lastIndexOf(marker);
  assert.ok(at >= 0, "the tampered frame carries a sig parameter");
  const start = at + marker.length;
  const current = text.charAt(start);
  const replacement = current === "A" ? "B" : "A";
  return new TextEncoder().encode(text.slice(0, start) + replacement + text.slice(start + 1));
}
