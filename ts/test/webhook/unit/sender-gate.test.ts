import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";
import { WebhookSender } from "../../../src/webhook/sender/delivery.js";
import { eventMessage } from "../../../src/webhook/sender/message.js";
import { HardenedTransport } from "../../../src/webhook/ssrf/client.js";
import type { HardenedRequest } from "../../../src/webhook/ssrf/client.js";
import { EndpointVerifier, VerificationCache } from "../../../src/webhook/verification/routes.js";
import { utf8 } from "../support/vectors.js";

const NOW = 1767225600;
const NONCE = "KfROIaIYzOA4LouilLN_Jw";
const PAIR = { principal: "alice", canonicalUrl: "https://hooks.example.test/hooks/alice" };
const TARGET = {
  subscriptionId: "sub_0123456789abcdef",
  principal: PAIR.principal,
  callbackUrl: PAIR.canonicalUrl,
  secrets: [{ secret: new Uint8Array(32), current: true }],
};
const now = () => NOW;
const randomBytes = (length: number) => new Uint8Array(length);

function recordingTransport(answer: (request: HardenedRequest) => { status: number; body?: Uint8Array }) {
  const seen: HardenedRequest[] = [];
  const transport = new HardenedTransport({
    resolver: { async resolve() { return ["93.184.216.34"]; } },
    dialer: async (_target, request) => {
      seen.push(request);
      const { status, body = new Uint8Array(0) } = answer(request);
      return { status, headers: {}, body };
    },
  });
  return { transport, seen };
}

function setup() {
  const { transport, seen } = recordingTransport((request) => {
    if (request.method === "GET") return { status: 404 };
    // A matching echo would verify the pair; use an echo of the wrong nonce to exercise refusal.
    return { status: 200, body: utf8(JSON.stringify({ challenge: "A".repeat(22) })) };
  });
  const cache = new VerificationCache({ now });
  const verifier = new EndpointVerifier({ transport, cache, now, nonceSource: () => NONCE });
  const options = { transport, verifier, now, randomBytes };
  const sender = new WebhookSender(options);
  return { cache, sender, seen, options };
}

function sampleEvent() {
  return eventMessage(utf8(JSON.stringify({
    eventId: "evt_1",
    name: "incident.created",
    timestamp: "2026-01-01T00:00:00Z",
    data: {},
  })), randomBytes);
}

test("sender posts only a challenge before verification and delivers the same event once verified", async () => {
  const { cache, sender, seen } = setup();
  const message = sampleEvent();
  const refused = await sender.deliver(TARGET, message);
  assert.equal(refused.gate, "send-challenge");
  assert.equal(refused.accepted, false);
  assert.equal(refused.lastError, "challenge_failed");
  const posts = seen.filter((request) => request.method === "POST");
  assert.equal(posts.length, 1);
  const challengeBody = posts[0]?.body;
  if (challengeBody === undefined) throw new Error("Missing verification POST body");
  assert.deepEqual(JSON.parse(Buffer.from(challengeBody).toString("utf8")), {
    type: "verification",
    challenge: NONCE,
  });

  cache.set(PAIR, NOW + 3600);
  seen.length = 0;
  const delivered = await sender.deliver(TARGET, message);
  assert.equal(delivered.accepted, true);
  assert.equal(delivered.gate, "deliver");
  assert.deepEqual(seen.map((request) => request.method), ["POST"]);
  assert.deepEqual(seen[0]?.body, message.body);
});

test("sender refuses an oversized event without making any request", async () => {
  const { sender, seen } = setup();
  const message = eventMessage(new Uint8Array(262145), randomBytes);
  const result = await sender.deliver(TARGET, message);
  assert.equal(result.gate, "refuse");
  assert.equal(result.attempts, 0);
  assert.equal(result.lastError, "http_4xx");
  assert.deepEqual(seen, []);
});

test("sender construction requires an endpoint verifier", () => {
  assert.throws(() => new WebhookSender({} as never), /requires an EndpointVerifier/);
});

test("sender construction enforces the protocol body ceiling", () => {
  const { options } = setup();
  assert.throws(
    () => new WebhookSender({ ...options, maxBodyBytes: 262145 }),
    /maxBodyBytes must be an integer from 0 through 262144/,
  );
  assert.doesNotThrow(() => new WebhookSender({ ...options, maxBodyBytes: 262144 }));
});

test("sender does not start another attempt after sleeping past the retry deadline", async () => {
  let clock = NOW;
  const now = () => clock;
  const { transport, seen } = recordingTransport(() => ({ status: 503 }));
  const cache = new VerificationCache({ now });
  cache.set(PAIR, NOW + 3600);
  const verifier = new EndpointVerifier({ transport, cache, now, nonceSource: () => NONCE });
  const sender = new WebhookSender({
    transport, verifier, now, randomBytes,
    sleep: async () => { clock = NOW + 901; },
  });
  const message = sampleEvent();
  const { accepted, gate, attempts, lastError } = await sender.deliver(TARGET, message);
  assert.deepEqual({ accepted, gate, attempts, lastError }, {
    accepted: false, gate: "deliver", attempts: 1, lastError: "timeout",
  });
  assert.deepEqual(seen.map((request) => request.method), ["POST"]);
  assert.deepEqual(seen[0]?.body, message.body);
});

test("sender delivery calls the public gate and withholds the event when the challenge fails", async () => {
  const { sender, seen } = setup();
  const originalGate = sender.gate.bind(sender);
  let gateCalls = 0;
  sender.gate = async (target, message) => {
    gateCalls += 1;
    return originalGate(target, message);
  };
  const message = sampleEvent();
  const outcome = await sender.deliver(TARGET, message);
  assert.ok(gateCalls >= 1);
  assert.equal(outcome.gate, "send-challenge");
  const posts = seen.filter((request) => request.method === "POST");
  assert.equal(posts.length, 1);
  assert.equal(posts.some(({ body }) => body !== undefined && Buffer.from(body).equals(message.body)), false);
});
