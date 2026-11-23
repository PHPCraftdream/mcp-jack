import { test } from "node:test";
import { subscriptionKey } from "../../../src/webhook/subscription/canonical.js";
import { activeSecrets, cursorOk, gapEnvelope, terminatedEnvelope, ttlGrant } from "../../../src/webhook/subscription/lifecycle.js";
import type { TerminatedEnvelopeInput } from "../../../src/webhook/subscription/lifecycle.js";
import { refusal, runCorpus, secretBytes } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

function run(c: VectorCase): unknown {
  const { input } = c;
  switch (c.kind) {
    case "sub-id": {
      const text = input.arguments_text as string | null | undefined;
      const args: unknown = text === null || text === undefined ? null : JSON.parse(text);
      const decided = subscriptionKey({
        principal: input.principal as string,
        url: input.url as string,
        name: input.name as string,
        arguments: args,
      });
      if (!decided.ok) return refusal(decided.code, decided.reason);
      const { id, canonical_url, canonical_arguments, jcs_input } = decided;
      return { result: "accept", id, canonical_url, canonical_arguments, jcs_input };
    }
    case "ttl": {
      const granted = ttlGrant({
        now: input.now as number,
        ...("ttlMs" in input ? { ttlMs: input.ttlMs as number | null } : {}),
      });
      return granted.ok
        ? { result: "accept", grantMs: granted.grantMs, refreshBefore: granted.refreshBefore }
        : refusal(granted.code, granted.reason);
    }
    case "secrets": {
      const secrets = activeSecrets({
        current: secretBytes(input.current),
        ...(input.previous == null ? {} : { previous: secretBytes(input.previous) }),
        graceEndsAt: input.graceEndsAt as number,
        now: input.now as number,
      });
      return { result: "accept", order: secrets.map((entry) => entry.current ? "current" : "previous") };
    }
    case "envelope": {
      if (input.kind === "gap") return { result: "accept", body_text: gapEnvelope(input.cursor as string | null) };
      // Deliberately pass malformed wire fields through to the SDK serializer's runtime guards.
      const error = { code: input.code, message: input.message, ...("data" in input ? { data: input.data } : {}) };
      try {
        return { result: "accept", body_text: terminatedEnvelope(error as TerminatedEnvelopeInput) };
      } catch {
        return refusal("invalid_envelope");
      }
    }
    case "cursor":
      return { result: cursorOk(input.value) ? "accept" : "reject" };
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("webhook-subscription: every case", async () => {
  await runCorpus({ corpus: "webhook-subscription", file: "webhook-subscription-vectors.json", expectedCases: 49, run });
});
