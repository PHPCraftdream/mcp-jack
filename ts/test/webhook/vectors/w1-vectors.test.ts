import { test } from "node:test";
import { w1Sign, w1SigningString, w1Verify } from "../../../src/webhook/crypto/signatures.js";
import type { W1Parts } from "../../../src/webhook/crypto/signatures.js";
import { acceptedKey, b64u, bytes, refusal, runCorpus, signingKey, utf8 } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

interface WireParts {
  readonly aud: string;
  readonly subscription_id: string;
  readonly webhook_id: string;
  readonly webhook_timestamp: number;
  readonly callback_url: string;
  readonly body_b64u: string;
}

function partsOf(wire: WireParts): W1Parts {
  return {
    aud: wire.aud,
    subscriptionId: wire.subscription_id,
    webhookId: wire.webhook_id,
    timestamp: String(wire.webhook_timestamp),
    callbackUrl: wire.callback_url,
    body: bytes(wire.body_b64u),
  };
}

function run(c: VectorCase): unknown {
  switch (c.kind) {
    case "kat-w1": {
      const input = c.input as typeof c.input & WireParts & { readonly key: string };
      const parts = partsOf(input);
      return {
        result: "accept",
        header: w1Sign(signingKey(input.key), parts),
        signing_string_b64u: b64u(utf8(w1SigningString(parts))),
      };
    }
    case "verify-w1": {
      const input = c.input as {
        readonly header?: string | null;
        readonly parts: WireParts;
        readonly keys: readonly string[];
        readonly now: number;
        readonly window: number;
        readonly mcp_server_kid?: string | null;
      };
      if (input.header === null || input.header === undefined) return refusal("missing_jack_auth");
      const decided = w1Verify(input.header, partsOf(input.parts), {
        keys: input.keys.map(acceptedKey),
        now: input.now,
        window: input.window,
        mcpServerKid: input.mcp_server_kid ?? null,
      });
      return decided.ok ? { result: "accept" } : refusal(decided.code);
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("webhook-w1: every case", async () => {
  await runCorpus({ corpus: "webhook-w1", file: "webhook-w1-vectors.json", expectedCases: 25, run });
});
