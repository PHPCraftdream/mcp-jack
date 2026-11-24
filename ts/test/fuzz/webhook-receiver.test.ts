import assert from "node:assert/strict";
import { test } from "node:test";
import { WebhookReceiver } from "../../src/webhook/receiver/core.js";
import { parseWhsec } from "../../src/webhook/crypto/primitives.js";
import { checkSignatureSchemes, decodeSignatureEntries, parseSignatureHeader, v1Sign, v1Verify } from "../../src/webhook/crypto/signatures.js";
import type { WebhookMessageParts } from "../../src/webhook/crypto/signatures.js";
import { fixture } from "../support/fixtures/index.js";
import { corpus, mutateBytes, random, runAsyncProperty, settings } from "./helper.js";

test("fuzz webhook receiver grammar and signature binding", async () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const boundaries = corpus("receiver-boundaries.json") as { ids: string[]; timestamps: string[]; subscriptions: string[]; bodies: string[] };
  const parsed = parseWhsec("whsec_" + Buffer.from(new Uint8Array(32).fill(7)).toString("base64"));
  assert.ok(parsed.ok);
  const secret = parsed.key;
  const validParts: WebhookMessageParts = { webhookId: "webhook_1", timestamp: "1767225600", body: new TextEncoder().encode("{\"data\":{},\"eventId\":\"e\",\"name\":\"n\",\"timestamp\":\"2024-01-01T00:00:00Z\"}") };
  const makeReceiver = () => new WebhookReceiver({ secrets: [{ secret, subscriptionId: "sub_0123456789abcdef" }], routed: ["sub_0123456789abcdef"], enqueue: async () => {} });
  const handle = async (iteration: number, request: Parameters<WebhookReceiver["handle"]>[0]) => {
    let result: Awaited<ReturnType<WebhookReceiver["handle"]>> | undefined;
    const raw = Buffer.from(request.body);
    const input = { headers: request.headers, body: raw.toString("utf8"), wire_hex: raw.toString("hex") };
    await runAsyncProperty(seed, iteration, input, async () => {
      result = await makeReceiver().handle(request);
      assert.ok(result !== undefined);
      if (result.status >= 200 && result.status < 300 && result.code === null) {
        const values = new Map<string, string | readonly string[]>(request.headers.map(([name, value]) => [name.toLowerCase(), value] as const));
        const requiredStringHeader = (name: string): string => {
          const value = values.get(name);
          if (typeof value !== "string") throw new TypeError(`Expected a single string value for ${name}`);
          return value;
        };
        const header = parseSignatureHeader(requiredStringHeader("webhook-signature"));
        assert.ok(header.ok);
        const schemes = checkSignatureSchemes(header.entries); assert.ok(schemes.ok);
        const decoded = decodeSignatureEntries(header.entries); assert.ok(decoded.ok);
        assert.equal(v1Verify(decoded.entries, secret, { webhookId: requiredStringHeader("webhook-id"), timestamp: requiredStringHeader("webhook-timestamp"), body: raw }).ok, true);
      }
    }, raw);
    return result!;
  };
  const vectors = fixture("modern/webhook-receiver-vectors.json") as { cases?: { input?: { steps?: { headers?: string[][]; body_text?: string }[] } }[] };
  const names = [...new Set((vectors.cases ?? []).flatMap((c) => c.input?.steps ?? []).flatMap((s) => s.headers ?? []).map(([name]) => name ?? "").filter((name) => /^x-[a-z0-9-]+$/i.test(name) && name.toLowerCase() !== "x-mcp-subscription-id"))].slice(0, 12);
  const unknownHeaders = names.length ? names : ["x-fuzz-unknown"];
  let accepted = false;
  for (let i = 0; i < iterations; i++) {
    const body = i === 0 ? boundaries.bodies.find((value) => { try { const parsed = JSON.parse(value) as Record<string, unknown>; return parsed.data !== undefined && typeof parsed.eventId === "string" && typeof parsed.name === "string" && typeof parsed.timestamp === "string"; } catch { return false; } }) ?? boundaries.bodies[0]! : boundaries.bodies[Math.floor(next() * boundaries.bodies.length)]!;
    const originalBody = new TextEncoder().encode(body);
    const bodyBytes = i === 0 ? originalBody : mutateBytes(originalBody, next);
    const parts: WebhookMessageParts = { ...validParts, body: bodyBytes };
    const signature = v1Sign(secret, parts);
    const signedHeaders = [["webhook-id", parts.webhookId], ["webhook-timestamp", parts.timestamp], ["webhook-signature", signature], ["x-mcp-subscription-id", "sub_0123456789abcdef"]] as const;
    const baseline = await handle(i, { now: 1767225600, headers: signedHeaders, body: bodyBytes });
    if (i === 0) { assert.equal(baseline.status, 200); assert.equal(baseline.body.status, "accepted"); accepted = true; }
    const extra = unknownHeaders[Math.floor(next() * unknownHeaders.length)]!;
    const unknownValue = Buffer.from(mutateBytes(new TextEncoder().encode("noise"), next)).toString("utf8");
    const withUnknown = await handle(i, { now: 1767225600, headers: [...signedHeaders, [extra, unknownValue]], body: bodyBytes });
    await runAsyncProperty(seed, i, { baseline: { headers: signedHeaders, body: bodyBytes.toString(), body_hex: Buffer.from(bodyBytes).toString("hex") }, with_unknown: { headers: [...signedHeaders, [extra, "noise"]], body: bodyBytes.toString(), body_hex: Buffer.from(bodyBytes).toString("hex") } }, async () => assert.deepEqual(withUnknown, baseline), bodyBytes);
    for (const badSignature of ["v1,@@@@", signature.slice(0, -1) + (signature.endsWith("A") ? "B" : "A"), "v2a," + signature.slice(3), Buffer.from(mutateBytes(new TextEncoder().encode(signature), next)).toString("utf8")]) {
      const headers = signedHeaders.map(([name, value]) => [name, name === "webhook-signature" ? badSignature : value] as const);
      const verdict = await handle(i, { now: 1767225600, headers, body: bodyBytes });
      await runAsyncProperty(seed, i, { headers, body: bodyBytes.toString(), body_hex: Buffer.from(bodyBytes).toString("hex") }, async () => assert.ok(verdict.status < 200 || verdict.status >= 300, `mutated signature accepted: ${badSignature}`), bodyBytes);
    }
    const malformedDuplicate = [["webhook-id", parts.webhookId], ["webhook-id", "invalid"], ["webhook-timestamp", parts.timestamp], ["webhook-signature", "not a signature"], ["x-mcp-subscription-id", "sub_0123456789abcdef"]] as const;
    const duplicate = await handle(i, { now: 1767225600, headers: malformedDuplicate, body: bodyBytes });
    await runAsyncProperty(seed, i, { headers: malformedDuplicate, body: bodyBytes.toString(), body_hex: Buffer.from(bodyBytes).toString("hex") }, async () => assert.equal(duplicate.code, "duplicate_webhook_header"), bodyBytes);
    const headerValue = Buffer.from(mutateBytes(new TextEncoder().encode(parts.webhookId), next)).toString("utf8");
    const mutatedRequired = signedHeaders.map(([name, value]) => [name, name === "webhook-id" ? headerValue : value] as const);
    const mutatedRequiredVerdict = await handle(i, { now: 1767225600, headers: mutatedRequired, body: bodyBytes });
    await runAsyncProperty(seed, i, { headers: mutatedRequired, body: bodyBytes.toString("utf8"), wire_hex: Buffer.from(bodyBytes).toString("hex") }, async () => {
      if (headerValue !== parts.webhookId) assert.ok(mutatedRequiredVerdict.status < 200 || mutatedRequiredVerdict.status >= 300);
    }, bodyBytes);
    const id = boundaries.ids[Math.floor(next() * boundaries.ids.length)]!;
    const timestamp = boundaries.timestamps[Math.floor(next() * boundaries.timestamps.length)]!;
    const subscription = boundaries.subscriptions[Math.floor(next() * boundaries.subscriptions.length)]!;
    const mutations = [
      { id, timestamp: parts.timestamp, subscription: "sub_0123456789abcdef", code: /^[A-Za-z0-9_-]{8,128}$/.test(id) ? null : "malformed_webhook_id" },
      { id: parts.webhookId, timestamp, subscription: "sub_0123456789abcdef", code: /^(0|[1-9][0-9]{0,11})$/.test(timestamp) ? null : "malformed_webhook_timestamp" },
      { id: parts.webhookId, timestamp: parts.timestamp, subscription, code: /^sub_[0-9a-f]{16}$/.test(subscription) ? null : "malformed_subscription_id" },
    ];
    for (const mutation of mutations) {
      const signed = v1Sign(secret, { ...parts, webhookId: mutation.id, timestamp: mutation.timestamp });
      const headers = [["webhook-id", mutation.id], ["webhook-timestamp", mutation.timestamp], ["webhook-signature", signed], ["x-mcp-subscription-id", mutation.subscription]] as const;
      const verdict = await handle(i, { now: 1767225600, headers, body: bodyBytes });
      await runAsyncProperty(seed, i, { headers, body: bodyBytes.toString(), body_hex: Buffer.from(bodyBytes).toString("hex"), expected_code: mutation.code }, async () => {
        if (mutation.code !== null) assert.equal(verdict.code, mutation.code);
        else assert.notEqual(verdict.code, "malformed_webhook_id");
      }, bodyBytes);
    }
  }
  assert.equal(accepted, true);
});
