import assert from "node:assert/strict";
import { test } from "node:test";
import { constTimeEqual, encodeBase64Std, parseWhsec } from "../../../src/webhook/crypto/primitives.js";
import { v1Sign, w1SigningString } from "../../../src/webhook/crypto/signatures.js";
import { WebhookReceiver } from "../../../src/webhook/receiver/core.js";

function secretOfLength(length: number, fill = 0): string {
  return `whsec_${encodeBase64Std(new Uint8Array(length).fill(fill))}`;
}

test("parseWhsec returns a reason without echoing the rejected value", () => {
  const valid = secretOfLength(32);
  const cases = [
    [valid.slice("whsec_".length), "prefix"],
    [`whsec_-${valid.slice("whsec_".length + 1)}`, "alphabet"],
    [valid.slice(0, -1), "padding"],
    [`${valid}=`, "padding"],
    [`${valid.slice(0, -2)}B=`, "canonical"], // Nonzero unused bits in the final base64 sextet.
    [secretOfLength(23), "length"],
    [secretOfLength(65), "length"],
  ] as const;
  for (const [value, reason] of cases) {
    const result = parseWhsec(value);
    assert.equal(JSON.stringify(result).includes(value), false, reason);
    assert.deepEqual(result, { ok: false, code: "invalid_secret", reason });
  }
});

test("parseWhsec accepts both decoded length limits and a 32-byte key", () => {
  for (const length of [24, 32, 64]) {
    const result = parseWhsec(secretOfLength(length, 0xa5));
    if (!result.ok) throw new Error(`Rejected ${length}-byte key: ${result.reason}`);
    assert.deepEqual(new Uint8Array(result.key), new Uint8Array(length).fill(0xa5));
  }
});

test("constTimeEqual compares byte contents and lengths, including empty inputs", () => {
  const bytes = Uint8Array.of(0, 1, 2);
  const empty = new Uint8Array();
  assert.equal(constTimeEqual(bytes, Uint8Array.of(0, 1, 2)), true);
  assert.equal(constTimeEqual(bytes, Uint8Array.of(0, 1, 3)), false);
  assert.equal(constTimeEqual(bytes, Uint8Array.of(0, 1)), false);
  assert.equal(constTimeEqual(bytes, empty), false);
  assert.equal(constTimeEqual(empty, new Uint8Array()), true);
});

test("receiver checks the v1 signature before applying the replay window", async () => {
  const now = 1767225600;
  const subscriptionId = "sub_0000000000000001";
  const secret = secretOfLength(32, 0xa5);
  const valid = parseWhsec(secret);
  const wrong = parseWhsec(secretOfLength(32, 0x5a));
  if (!valid.ok || !wrong.ok) throw new Error("Invalid signing fixture");
  const receiver = new WebhookReceiver({
    secrets: [{ secret, subscriptionId }],
    routed: [subscriptionId],
    enqueue: async () => {},
  });
  const message = { type: "gap", cursor: null };
  const body = Uint8Array.from(JSON.stringify(message), (character) => character.charCodeAt(0));
  const cases = [
    { offset: -300, key: valid.key, status: 200, code: null },
    { offset: -301, key: valid.key, status: 401, code: "stale_timestamp" },
    { offset: 301, key: valid.key, status: 401, code: "future_timestamp" },
    { offset: -301, key: wrong.key, status: 401, code: "bad_signature" },
  ] as const;
  for (const [index, { offset, key, status, code }] of cases.entries()) {
    const webhookId = `webhook_${index}`;
    const timestamp = String(now + offset);
    const result = await receiver.handle({
      now,
      headers: [
        ["webhook-id", webhookId],
        ["webhook-timestamp", timestamp],
        ["webhook-signature", v1Sign(key, { webhookId, timestamp, body })],
        ["x-mcp-subscription-id", subscriptionId],
      ],
      body,
    });
    assert.equal(result.status, status);
    assert.equal(result.code, code);
    assert.deepEqual(result.delivered, code === null ? [message] : []);
    if (code === "bad_signature") {
      const serialized = JSON.stringify(result);
      assert.equal(serialized.includes(secret), false);
      assert.equal(serialized.includes("whsec_"), false);
    }
  }
});

test("w1SigningString has seven lines and binds the exact body bytes", () => {
  const parts = {
    aud: "https://hooks.example.test/",
    subscriptionId: "sub_0000000000000001",
    webhookId: "webhook_1",
    timestamp: "1767225600",
    callbackUrl: "https://hooks.example.test/x",
    body: Uint8Array.of(0x7b, 0x7d),
  };
  const lines = w1SigningString(parts).split("\n");
  const changed = w1SigningString({ ...parts, body: Uint8Array.of(0x7b, 0x5d) }).split("\n");
  const firstSix = [
    "mcp-jack/webhook1/delivery", parts.aud, parts.subscriptionId, parts.webhookId, parts.timestamp, parts.callbackUrl,
  ];
  for (const candidate of [lines, changed]) {
    assert.equal(candidate.length, 7);
    assert.deepEqual(candidate.slice(0, 6), firstSix);
    assert.match(candidate[6] ?? "", /^[A-Za-z0-9_-]{43}$/);
  }
  assert.notEqual(changed[6], lines[6]);
});
