/**
 * Spec 06 R7.2-R7.6 discovery and trust-set refresh (test-only):
 * a rejected card JWK stays visible in the discovery result, and the live
 * trust set is never served past its cache TTL under an injectable clock.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { crossCheckWebhookKey } from "../../../src/webhook/card/crosscheck.js";
import { fetchDecision } from "../../../src/webhook/card/fetch.js";
import { ServerCardKeySource } from "../../../src/webhook/card/source.js";
import type { ServerCardKeys } from "../../../src/webhook/card/source.js";
import type { HardenedOutcome, HardenedRequest } from "../../../src/webhook/ssrf/client.js";
import { acceptedKey, b64u, utf8 } from "../support/vectors.js";

const MCP_URL = "https://mcp.example.test/mcp";
const CARD_URL = "https://mcp.example.test/server-card";
const NOW = 1767225600;

function jwkOf(name: string) {
  const { kty, crv, x, kid } = acceptedKey(name);
  return { kid, kty, crv, x };
}

function cardOf(keys: readonly unknown[]) {
  return {
    remotes: [{
      type: "streamable-http",
      url: MCP_URL,
      extensionsInfo: {
        "io.modelcontextprotocol/events": {
          webhooks: { signingKeys: { keys }, egressIpRanges: ["203.0.113.0/24"] },
        },
      },
    }],
  };
}

interface TransportCall {
  readonly url: string;
  readonly request: HardenedRequest;
}

function fakeTransport(calls: TransportCall[], answer: () => HardenedOutcome) {
  return {
    async request(url: string, request: HardenedRequest): Promise<HardenedOutcome> {
      calls.push({ url, request });
      return answer();
    },
  };
}

function cardAnswer(card: unknown): HardenedOutcome {
  return {
    ok: true,
    response: { status: 200, headers: { "cache-control": "max-age=60" }, body: utf8(JSON.stringify(card)) },
  };
}

function accepted(result: ServerCardKeys): Extract<ServerCardKeys, { readonly ok: true }> {
  if (!result.ok) throw new Error(`unexpected card refusal: ${result.code}`);
  return result;
}

test("discovery keeps a rejected card JWK visible beside the accepted key", () => {
  const validJwk = jwkOf("alice");
  const rejectedJwk = { ...validJwk, kid: "not-alices-kid" };
  const card = cardOf([validJwk, rejectedJwk]);

  const verdict = fetchDecision({
    mcpUrl: MCP_URL,
    cardUrl: CARD_URL,
    response: { status: 200, headers: { "cache-control": "max-age=60" }, bodyB64u: b64u(utf8(JSON.stringify(card))) },
  });
  if (!verdict.ok) throw new Error(`unexpected card refusal: ${verdict.code}`);

  assert.equal(verdict.ok, true);
  assert.deepEqual(verdict.keys.map((key) => key.kid), [validJwk.kid]);
  assert.deepEqual(verdict.rejectedKeys, [{ kid: rejectedJwk.kid, reason: "kid_mismatch" }]);
  assert.deepEqual(verdict.egressIpRanges, [{ cidr: "203.0.113.0/24", family: "ipv4", prefix: 24 }]);
  assert.equal(verdict.cacheTtlSeconds, 60);
  // The regression oracle: raw card keys are published verbatim, rejected members included.
  assert.deepEqual(verdict.cardKeys, [validJwk, rejectedJwk]);

  // R7.6 validates BOTH sides with the R7.3 validator before comparing, so a raw set that still
  // carries the kid_mismatch member is a defined mismatch rather than silent agreement.
  assert.deepEqual(
    crossCheckWebhookKey({
      keys: verdict.cardKeys,
      toolResult: { webhook_key: { signing_keys: { keys: [validJwk, rejectedJwk] } } },
      require: true,
    }),
    { ok: false, code: "webhook_key_mismatch" },
  );
  // Narrows the card but never widens it: if discovery dropped the rejected member this would agree.
  assert.deepEqual(
    crossCheckWebhookKey({
      keys: verdict.cardKeys,
      toolResult: { webhook_key: { signing_keys: { keys: [validJwk] } } },
      require: true,
    }),
    { ok: false, code: "webhook_key_mismatch" },
  );
  // The accepted set alone does agree with a tool result that publishes only the accepted key.
  assert.deepEqual(
    crossCheckWebhookKey({
      keys: verdict.keys,
      toolResult: { webhook_key: { signing_keys: { keys: [validJwk] } } },
      require: true,
    }),
    { ok: true },
  );
});

test("the live trust set is not served past its TTL", async () => {
  const aliceJwk = jwkOf("alice");
  const bobJwk = jwkOf("bob");
  const calls: TransportCall[] = [];
  let clockMs = NOW * 1000;
  let reply: HardenedOutcome = cardAnswer(cardOf([aliceJwk]));
  const source = new ServerCardKeySource({
    mcpUrl: MCP_URL,
    transport: fakeTransport(calls, () => reply),
    now: () => clockMs,
  });

  const first = accepted(await source.keys(NOW));
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.url, "https://mcp.example.test/mcp/server-card");
  assert.equal(calls[0]?.request.method, "GET");
  assert.deepEqual(first.keys.map((key) => key.kid), [aliceJwk.kid]);
  assert.deepEqual(first.cardKeys, [aliceJwk]);

  const second = accepted(await source.keys(NOW + 59));
  assert.equal(calls.length, 1);
  assert.deepEqual(second.keys.map((key) => key.kid), [aliceJwk.kid]);
  assert.deepEqual(second.cardKeys, [aliceJwk]);

  clockMs = (NOW + 61) * 1000;
  reply = { ok: false, code: "connection_refused" };
  const refused = await source.keys(NOW + 61);
  assert.deepEqual(refused, { ok: false, code: "connection_refused" });
  assert.equal(calls.length, 2);

  clockMs = (NOW + 62) * 1000;
  reply = cardAnswer(cardOf([bobJwk]));
  const refreshed = accepted(await source.keys(NOW + 62));
  assert.equal(calls.length, 3);
  assert.deepEqual(refreshed.keys.map((key) => key.kid), [bobJwk.kid]);
  assert.deepEqual(refreshed.cardKeys, [bobJwk]);
  assert.equal(refreshed.keys.some((key) => key.kid === aliceJwk.kid), false);
  assert.equal(refreshed.cardKeys.some((entry) => (entry as { readonly kid?: unknown }).kid === aliceJwk.kid), false);
});
