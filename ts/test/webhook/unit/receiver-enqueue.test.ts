import assert from "node:assert/strict";
import { test } from "node:test";
import { v1Sign } from "../../../src/webhook/crypto/signatures.js";
import { adaptNodeRequest, createNodeHandler } from "../../../src/webhook/receiver/adapter.js";
import { WebhookReceiver } from "../../../src/webhook/receiver/core.js";
import type { EnqueueDelivered, ReceiverRequest, WebhookReceiverConfig } from "../../../src/webhook/receiver/core.js";
import { utf8 } from "../support/vectors.js";

const NOW = 1767225600;
const SUBSCRIPTION_ID = "sub_0123456789abcdef";
const WEBHOOK_ID = "msg_gap_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f";
const SECRET = new Uint8Array(32);
const NONCE = "KfROIaIYzOA4LouilLN_Jw";
const GAP = { type: "gap", cursor: null };

function receiverWith(enqueue: EnqueueDelivered): WebhookReceiver {
  return new WebhookReceiver({
    secrets: [{ secret: SECRET, subscriptionId: SUBSCRIPTION_ID }],
    routed: [SUBSCRIPTION_ID],
    enqueue,
  });
}

function signedRequest(message: Record<string, unknown>, webhookId = WEBHOOK_ID): ReceiverRequest {
  const body = utf8(JSON.stringify(message));
  const timestamp = String(NOW);
  return {
    now: NOW,
    headers: [
      ["webhook-id", webhookId],
      ["webhook-timestamp", timestamp],
      ["webhook-signature", v1Sign(SECRET, { webhookId, timestamp, body })],
      ["x-mcp-subscription-id", SUBSCRIPTION_ID],
    ],
    body,
  };
}

async function* streamOf(chunks: readonly Uint8Array[]): AsyncGenerator<Uint8Array, void, unknown> {
  yield* chunks;
}

test("a rejected durable enqueue leaves the same signed delivery retryable", async () => {
  let fail = true;
  const receiver = receiverWith(async () => {
    if (fail) throw new Error("durable enqueue failed");
  });
  const request = signedRequest(GAP);
  const rejected = await receiver.handle(request);
  assert.equal(rejected.status, 503);
  assert.equal(rejected.code, "enqueue_failed");
  assert.equal(rejected.recorded, false);
  assert.deepEqual(receiver.snapshot().accepted, []);

  fail = false;
  const accepted = await receiver.handle(request);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { status: "accepted" });
  assert.equal(accepted.recorded, true);
  assert.deepEqual(receiver.snapshot().accepted, [WEBHOOK_ID]);
});

test("the receiver waits for durable enqueue and never enqueues an acknowledged duplicate", async () => {
  let releaseEnqueue: () => void = () => {};
  const enqueued = new Promise<void>((resolve) => { releaseEnqueue = resolve; });
  let calls = 0;
  const receiver = receiverWith(async (messages) => {
    calls++;
    assert.deepEqual(messages, [GAP]);
    await enqueued;
  });
  const request = signedRequest(GAP);
  const pending = receiver.handle(request);
  assert.equal(calls, 1);
  assert.equal(await Promise.race([pending, Promise.resolve("pending")]), "pending");
  assert.deepEqual(receiver.snapshot().accepted, []);

  releaseEnqueue();
  const accepted = await pending;
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { status: "accepted" });
  assert.equal(accepted.recorded, true);
  assert.deepEqual(receiver.snapshot().accepted, [WEBHOOK_ID]);

  const duplicate = await receiver.handle(request);
  assert.equal(duplicate.status, 200);
  assert.deepEqual(duplicate.body, { status: "duplicate" });
  assert.equal(duplicate.recorded, false);
  assert.equal(calls, 1);
});

test("concurrent copies of a signed delivery enqueue once and acknowledge one duplicate", async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let calls = 0;
  const receiver = receiverWith(async () => {
    calls += 1;
    await gate;
  });
  const request = signedRequest(GAP);
  const first = receiver.handle(request);
  const second = receiver.handle(request);
  release();
  const [firstResult, secondResult] = await Promise.all([first, second]);
  const [accepted, duplicate] = firstResult.recorded ? [firstResult, secondResult] : [secondResult, firstResult];
  assert.equal(calls, 1);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { status: "accepted" });
  assert.equal(accepted.recorded, true);
  assert.equal(duplicate.status, 200);
  assert.deepEqual(duplicate.body, { status: "duplicate" });
  assert.equal(duplicate.recorded, false);
});

test("a waiting concurrent delivery retries a failed enqueue and records the id once", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => {
    calls += 1;
    if (calls === 1) throw new Error("durable enqueue failed");
  });
  const request = signedRequest(GAP);
  const [rejected, accepted] = await Promise.all([receiver.handle(request), receiver.handle(request)]);
  assert.equal(calls, 2);
  assert.equal(rejected.status, 503);
  assert.equal(rejected.code, "enqueue_failed");
  assert.equal(rejected.recorded, false);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { status: "accepted" });
  assert.equal(accepted.recorded, true);
  assert.deepEqual(receiver.snapshot().accepted, [WEBHOOK_ID]);
});

test("a waiting concurrent delivery calls enqueue only after the held first enqueue rejects, then once on its own", async () => {
  let rejectEnqueue: (error: Error) => void = () => {};
  const held = new Promise<void>((_resolve, reject) => { rejectEnqueue = reject; });
  let calls = 0;
  const receiver = receiverWith(async () => {
    calls += 1;
    if (calls === 1) await held;
  });
  const request = signedRequest(GAP);
  const first = receiver.handle(request);
  assert.equal(calls, 1, "the first delivery starts its enqueue immediately");
  const second = receiver.handle(request);
  assert.equal(await Promise.race([second, Promise.resolve("waiting")]), "waiting", "the copy waits for the first");
  assert.equal(calls, 1, "the waiting copy has not called enqueue");
  rejectEnqueue(new Error("durable enqueue failed"));
  const [rejected, accepted] = await Promise.all([first, second]);
  assert.equal(calls, 2, "the waiting copy performs exactly one fresh enqueue after the failure");
  assert.equal(rejected.status, 503);
  assert.equal(rejected.code, "enqueue_failed");
  assert.equal(rejected.recorded, false);
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.body, { status: "accepted" });
  assert.equal(accepted.recorded, true);
  assert.deepEqual(receiver.snapshot().accepted, [WEBHOOK_ID]);
});

test("verification echoes the challenge without enqueueing it", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls++; });
  const result = await receiver.handle(signedRequest(
    { type: "verification", challenge: NONCE },
    "msg_verification_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f",
  ));
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { challenge: NONCE });
  assert.equal(calls, 0);
});

test("receiver construction requires a durable enqueue callback", () => {
  assert.throws(
    () => new WebhookReceiver({ secrets: [] } as unknown as WebhookReceiverConfig),
    /requires an enqueue callback/,
  );
});

test("receiver construction rejects a Jack window above 120 seconds", () => {
  assert.throws(() => new WebhookReceiver({
    secrets: [],
    enqueue: async () => {},
    jack: { aud: "https://svc.example.test", window: 121, callbackUrls: {} },
  }), /jack window must be an integer from 1 through 120 seconds/);
});

test("the Node adapter rejects a stream over 262144 bytes without enqueueing", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls++; });
  const chunks = [new Uint8Array(262144), new Uint8Array(1)];
  const result = await adaptNodeRequest(receiver, { headers: {}, body: streamOf(chunks), now: NOW });
  const body = JSON.parse(result.body) as { error: { code: string } };
  assert.equal(result.status, 413);
  assert.equal(body.error.code, "body_too_large");
  assert.equal(calls, 0);
});

test("Node handler construction rejects a body limit above the protocol ceiling", () => {
  const receiver = receiverWith(async () => {});
  assert.throws(
    () => createNodeHandler(receiver, { maxBodyBytes: 262145 }),
    /maxBodyBytes must be an integer from 0 through 262144/,
  );
});

test("the Node adapter clamps an oversized body limit override to the protocol ceiling", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls += 1; });
  const result = await adaptNodeRequest(receiver, {
    headers: {},
    body: streamOf([new Uint8Array(262144), new Uint8Array(1)]),
    now: NOW,
    maxBodyBytes: 300000,
  });
  const body = JSON.parse(result.body) as { error: { code: string } };
  assert.equal(result.status, 413);
  assert.equal(body.error.code, "body_too_large");
  assert.equal(calls, 0);
});

test("the direct Node adapter rejects a NaN body limit", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls += 1; });
  await assert.rejects(adaptNodeRequest(receiver, {
    headers: {},
    body: streamOf([new Uint8Array(1)]),
    now: NOW,
    maxBodyBytes: Number.NaN,
  }), /maxBodyBytes must be an integer from 0 through 262144/);
  assert.equal(calls, 0);
});

test("the direct Node adapter rejects a negative body limit", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls += 1; });
  await assert.rejects(adaptNodeRequest(receiver, {
    headers: {},
    body: streamOf([new Uint8Array(1)]),
    now: NOW,
    maxBodyBytes: -1,
  }), /maxBodyBytes must be an integer from 0 through 262144/);
  assert.equal(calls, 0);
});

test("the direct Node adapter keeps clamping a limit above the protocol ceiling", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls += 1; });
  const result = await adaptNodeRequest(receiver, {
    headers: {},
    body: streamOf([new Uint8Array(262144), new Uint8Array(1)]),
    now: NOW,
    maxBodyBytes: 300000,
  });
  const body = JSON.parse(result.body) as { error: { code: string } };
  assert.equal(result.status, 413);
  assert.equal(body.error.code, "body_too_large");
  assert.equal(calls, 0);
});

test("the direct Node adapter rejects a fractional body limit", async () => {
  let calls = 0;
  const receiver = receiverWith(async () => { calls += 1; });
  await assert.rejects(adaptNodeRequest(receiver, {
    headers: {},
    body: streamOf([new Uint8Array(1)]),
    now: NOW,
    maxBodyBytes: 1024.5,
  }), /maxBodyBytes must be an integer from 0 through 262144/);
  assert.equal(calls, 0);
});

test("the Node adapter rejects an oversized Content-Length without reading the stream", async () => {
  let calls = 0;
  let iterated = false;
  const receiver = receiverWith(async () => { calls++; });
  async function* bodyStream() {
    iterated = true;
    yield new Uint8Array(1);
  }
  const result = await adaptNodeRequest(receiver, {
    headers: { "content-length": "262145" },
    body: bodyStream(),
    now: NOW,
  });
  const body = JSON.parse(result.body) as { error: { code: string } };
  assert.equal(result.status, 413);
  assert.equal(body.error.code, "body_too_large");
  assert.equal(iterated, false);
  assert.equal(calls, 0);
});
