import { test } from "node:test";
import { crossCheckWebhookKey } from "../../../src/webhook/card/crosscheck.js";
import { cardKeyForKid, fetchDecision } from "../../../src/webhook/card/fetch.js";
import type { CardResponse } from "../../../src/webhook/card/fetch.js";
import { acceptJwkSet, parseCidrList } from "../../../src/webhook/card/jwk.js";
import { selectRemote, webhookInfo } from "../../../src/webhook/card/remote.js";
import { acceptedKey, b64u, refusal, runCorpus, utf8 } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

interface WireResponse {
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>> | null;
  readonly card?: unknown;
  readonly raw?: string;
  readonly pad?: number;
}

function bodyOfResponse(response: WireResponse): string {
  if (response.card !== undefined) return b64u(utf8(JSON.stringify(response.card)));
  if (typeof response.raw === "string") return b64u(utf8(response.raw));
  if (typeof response.pad === "number") return b64u(utf8(" ".repeat(response.pad)));
  return "";
}

function responseOf(response: WireResponse): CardResponse {
  return { status: response.status, headers: response.headers ?? {}, bodyB64u: bodyOfResponse(response) };
}

function serverKeyOptions(input: VectorCase["input"]): NonNullable<Parameters<typeof acceptJwkSet>[1]> {
  return {
    ...(input.mcp_server_kid === undefined ? {} : { mcpServerKid: input.mcp_server_kid as string | null }),
    ...(input.mcp_server_public_key === undefined ? {} : { mcpServerPublicKey: input.mcp_server_public_key as string | null }),
  };
}

function jwkOf(name: string) {
  const { kty, crv, x, kid } = acceptedKey(name);
  return { kty, crv, x, kid };
}

function run(c: VectorCase): unknown {
  const { input } = c;
  switch (c.kind) {
    case "remote": {
      const verdict = selectRemote(input.card, { mcpUrl: input.mcpUrl as string });
      return verdict.ok ? { result: "accept", url: verdict.remote.url } : refusal(verdict.code);
    }
    case "info": {
      const verdict = webhookInfo(input.card, { mcpUrl: input.mcpUrl as string });
      if (!verdict.ok) return refusal(verdict.code);
      return { result: "accept", signing_keys: verdict.signingKeys, egress: verdict.egressIpRanges, remote_url: verdict.remoteUrl };
    }
    case "jwk-set": {
      const { accepted, rejected } = acceptJwkSet({ keys: input.signing_keys }, serverKeyOptions(input));
      return { accepted: accepted.map((key) => key.kid), rejected };
    }
    case "cidr-list": {
      const { accepted, rejected } = parseCidrList(input.values);
      return { accepted, rejected };
    }
    case "fetch": {
      const verdict = fetchDecision({
        mcpUrl: input.mcpUrl as string,
        cardUrl: input.cardUrl as string,
        ...(input.elapsed_ms === undefined ? {} : { elapsedMs: input.elapsed_ms as number }),
        ...serverKeyOptions(input),
        response: responseOf(input.response as WireResponse),
      });
      if (!verdict.ok) return refusal(verdict.code);
      return {
        result: "accept",
        keys: verdict.keys.map((key) => key.kid),
        egress: verdict.egressIpRanges.map((entry) => entry.cidr),
        rejected: verdict.rejectedKeys,
        cache_ttl: verdict.cacheTtlSeconds,
      };
    }
    case "kid": {
      const verdict = cardKeyForKid((input.keys as readonly string[]).map(acceptedKey), input.kid);
      return verdict.ok ? { result: "accept" } : refusal(verdict.code);
    }
    case "webhook-key-check": {
      const own = input.card_keys === undefined
        ? (input.keys as readonly string[]).map(jwkOf)
        : input.card_keys as readonly unknown[];
      const verdict = crossCheckWebhookKey({ keys: own, toolResult: input.toolResult, require: input.require as boolean });
      return verdict.ok ? { result: "accept" } : refusal(verdict.code);
    }
    case "webhook-key-discovery": {
      const verdict = fetchDecision({
        mcpUrl: input.mcpUrl as string,
        cardUrl: input.cardUrl as string,
        response: responseOf(input.response as WireResponse),
      });
      if (!verdict.ok) return refusal(verdict.code);
      const checked = crossCheckWebhookKey({ keys: verdict.cardKeys, toolResult: input.toolResult, require: true });
      return checked.ok ? { result: "accept" } : refusal(checked.code);
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("server-card-keys: every case", async () => {
  await runCorpus({ corpus: "server-card-keys", file: "server-card-keys-vectors.json", expectedCases: 43, run });
});
