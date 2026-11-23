import { test } from "node:test";
import { lastErrorOf, retrySchedule, senderDecision, WebhookReceiver } from "../../../src/webhook/receiver/core.js";
import type {
  HeaderPairs,
  ReceiverStepResult,
  SenderDecisionInput,
  WebhookReceiverConfig,
} from "../../../src/webhook/receiver/core.js";
import { acceptedKey, bytes, runCorpus } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

interface WireConfig {
  readonly secrets?: readonly {
    readonly secret: string;
    readonly subscription_id?: string | null;
    readonly callback_url?: string | null;
  }[];
  readonly routed?: readonly string[];
  readonly keys?: readonly string[];
  readonly jack?: {
    readonly aud: string;
    readonly window?: number;
    readonly callback_urls: Readonly<Record<string, string>>;
  } | null;
  readonly mcp_server_kid?: string | null;
  readonly mcp_server_public_key?: string | null;
  readonly webhook_key_check?: WebhookReceiverConfig["webhookKeyCheck"];
  readonly webhook_key_tool?: unknown;
  readonly window?: number;
  readonly max_body?: number;
  readonly dedup_retention?: number;
  readonly enforce_server_identity?: boolean;
}

interface WireStep {
  readonly now: number;
  readonly headers: HeaderPairs;
  readonly route?: readonly string[];
  readonly enqueue?: "ok" | "fail" | null;
  readonly body_text?: string;
  readonly body_b64u?: string;
  readonly body_repeat?: { readonly char: string; readonly count: number };
}

function configOf(config: WireConfig = {}): Omit<WebhookReceiverConfig, "enqueue"> {
  const { jack } = config;
  return {
    secrets: (config.secrets ?? []).map(({ secret, subscription_id, callback_url }) => ({
      secret,
      subscriptionId: subscription_id ?? null,
      ...(callback_url == null ? {} : { callbackUrl: callback_url }),
    })),
    routed: config.routed ?? [],
    keys: (config.keys ?? []).map(acceptedKey),
    jack: jack == null ? null : {
      aud: jack.aud,
      ...(jack.window === undefined ? {} : { window: jack.window }),
      callbackUrls: jack.callback_urls,
    },
    mcpServerKid: config.mcp_server_kid ?? null,
    mcpServerPublicKey: config.mcp_server_public_key ?? null,
    ...(config.webhook_key_check === undefined ? {} : { webhookKeyCheck: config.webhook_key_check }),
    webhookKeyToolResult: config.webhook_key_tool,
    ...(config.window === undefined ? {} : { window: config.window }),
    ...(config.max_body === undefined ? {} : { maxBodyBytes: config.max_body }),
    ...(config.dedup_retention === undefined ? {} : { dedupRetentionSeconds: config.dedup_retention }),
    ...(config.enforce_server_identity === undefined ? {} : { enforceServerIdentity: config.enforce_server_identity }),
  };
}

function bodyOf(step: WireStep): Uint8Array | string {
  if (typeof step.body_text === "string") return step.body_text;
  if (typeof step.body_b64u === "string") return bytes(step.body_b64u);
  const repeat = step.body_repeat;
  return repeat && typeof repeat.char === "string" && Number.isInteger(repeat.count)
    ? repeat.char.repeat(repeat.count)
    : "";
}

async function run(c: VectorCase): Promise<unknown> {
  const { input } = c;
  switch (c.kind) {
    case "sequence": {
      const wire = input as { readonly config?: WireConfig; readonly steps: readonly WireStep[] };
      let enqueueMode: "ok" | "fail" = "ok";
      const receiver = new WebhookReceiver({
        ...configOf(wire.config),
        enqueue: async () => {
          if (enqueueMode === "fail") throw new Error("durable enqueue failed");
        },
      });
      const steps: ReceiverStepResult[] = [];
      for (const step of wire.steps) {
        enqueueMode = step.enqueue === "fail" ? "fail" : "ok";
        if (step.route !== undefined) receiver.route(step.route);
        const out = await receiver.handle({ now: step.now, headers: step.headers, body: bodyOf(step) });
        const { status, body, delivered, code, recorded } = out;
        steps.push({ status, body, delivered, code, recorded });
      }
      const { routed, terminated, secrets, accepted } = receiver.snapshot();
      return {
        steps,
        final_state: {
          routed,
          terminated,
          secrets: secrets.map(({ subscriptionId, callbackUrl }) => ({ subscription_id: subscriptionId, callback_url: callbackUrl })),
          accepted,
        },
      };
    }
    case "sender":
      return senderDecision(input as SenderDecisionInput);
    case "schedule":
      return { times: retrySchedule(input.t0 as number) };
    case "last-error":
      return { lastError: lastErrorOf(input.status as number) };
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("webhook-receiver: every case", async () => {
  await runCorpus({ corpus: "webhook-receiver", file: "webhook-receiver-vectors.json", expectedCases: 107, run });
});
