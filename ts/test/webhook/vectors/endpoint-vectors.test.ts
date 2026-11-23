import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Std } from "../../../src/webhook/crypto/primitives.js";
import { WebhookSender } from "../../../src/webhook/sender/delivery.js";
import { eventMessage, gapMessage, terminatedMessage, verificationMessage } from "../../../src/webhook/sender/message.js";
import type { OutboundMessage } from "../../../src/webhook/sender/message.js";
import { HardenedTransport } from "../../../src/webhook/ssrf/client.js";
import type { HardenedRequest } from "../../../src/webhook/ssrf/client.js";
import { checkDelivery } from "../../../src/webhook/ssrf/delivery.js";
import type { DeliveryCheckInput } from "../../../src/webhook/ssrf/delivery.js";
import { checkCallbackUrl } from "../../../src/webhook/ssrf/url.js";
import { allowlistMatches, parseAllowlistEntry } from "../../../src/webhook/verification/allowlist.js";
import type { AllowlistEntry } from "../../../src/webhook/verification/allowlist.js";
import {
  checkReceiverDocFetch,
  docCacheTtl,
  parseReceiverDoc,
  receiverDocCovers,
  receiverDocRequest,
  wellKnownUrl,
} from "../../../src/webhook/verification/document.js";
import { acceptEcho, challengeEcho, nonceOk } from "../../../src/webhook/verification/nonce.js";
import type { ChallengeEcho } from "../../../src/webhook/verification/nonce.js";
import { EndpointVerifier, VerificationCache } from "../../../src/webhook/verification/routes.js";
import { refusal, runCorpus, secretBytes, utf8 } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

const HOOK = "https://hooks.example.test/hooks/alice";
const PAIR = { principal: "alice", canonicalUrl: HOOK };
const SUBSCRIPTION_ID = "sub_0123456789abcdef";
const SECRET = "whsec_" + encodeBase64Std(new Uint8Array(32));
const NOW = 1767225600;
const NONCE = "KfROIaIYzOA4LouilLN_Jw";

type AllowlistEntries = Parameters<typeof allowlistMatches>[0];

interface WireFetch {
  readonly status?: number;
  readonly bodyText?: string;
  readonly maxBody?: number;
}

interface WireEcho extends WireFetch {
  readonly nonce?: string;
}

type WireAcceptEcho = Omit<Parameters<typeof acceptEcho>[0], "ttlSeconds"> & { readonly ttl?: number };

function recordingTransport(
  answer: (request: HardenedRequest) => { status: number; body?: Uint8Array; headers?: Record<string, string> } =
    () => ({ status: 404 }),
  answers: readonly string[] = ["93.184.216.34"],
) {
  const seen: HardenedRequest[] = [];
  const transport = new HardenedTransport({
    resolver: { async resolve() { return answers; } },
    dialer: async (_target, request) => {
      seen.push(request);
      const { status, headers = {}, body = new Uint8Array(0) } = answer(request);
      return { status, headers, body };
    },
  });
  return { transport, seen };
}

function fetchFields(input: WireFetch) {
  return {
    ...(input.status === undefined ? {} : { status: input.status }),
    ...(input.bodyText === undefined ? {} : { bodyText: input.bodyText }),
  };
}

function fetchLimits(input: WireFetch) {
  return input.maxBody === undefined ? {} : { maxBodyBytes: input.maxBody };
}

function echoOf(input: WireEcho): ChallengeEcho {
  return challengeEcho({
    ...fetchFields(input),
    ...fetchLimits(input),
    ...(input.nonce === undefined ? {} : { nonce: input.nonce }),
  });
}

function postFields(input: DeliveryCheckInput): DeliveryCheckInput {
  const { url, answers, allowedRanges, recheck, redirect } = input;
  return {
    url,
    ...(answers === undefined ? {} : { answers }),
    ...(allowedRanges === undefined ? {} : { allowedRanges }),
    ...(recheck === undefined ? {} : { recheck }),
    ...(redirect === undefined ? {} : { redirect }),
  };
}

function docRequest(input: DeliveryCheckInput & WireFetch) {
  return receiverDocRequest({ ...postFields(input), ...fetchFields(input) });
}

function challengeResult(verdict: ChallengeEcho): unknown {
  return verdict.ok ? { result: "accept" } : refusal(verdict.code, verdict.reason);
}

function allowlistResult(entry: AllowlistEntry | null): unknown {
  if (entry === null) return { result: "reject" };
  return { result: "accept", host_pattern: entry.hostPattern, port: entry.port, path: entry.path };
}

async function run(c: VectorCase): Promise<unknown> {
  const { input } = c;
  switch (c.kind) {
    case "gate": {
      const cache = new VerificationCache({ now: () => NOW });
      if (input.verified === true) cache.set(PAIR, NOW + 3600);
      const { transport, seen } = recordingTransport();
      const verifier = new EndpointVerifier({ transport, cache, now: () => NOW, nonceSource: () => NONCE });
      const sender = new WebhookSender({ transport, verifier, now: () => NOW, randomBytes: () => new Uint8Array(24) });
      const target = {
        subscriptionId: SUBSCRIPTION_ID,
        principal: PAIR.principal,
        callbackUrl: HOOK,
        secrets: [{ secret: secretBytes(SECRET), current: true }],
      };
      let message: OutboundMessage;
      switch (input.message) {
        case "verification": message = verificationMessage(NONCE); break;
        case "gap": message = gapMessage(null); break;
        case "terminated": message = terminatedMessage({ code: -32024, message: "Forbidden" }); break;
        case "event": message = eventMessage(utf8("{}")); break;
        default: throw new Error(`${c.id}: unknown gate message ${String(input.message)}`);
      }
      const decision = await sender.gate(target, message);
      if (c.expect.action !== "deliver") {
        assert.equal(seen.filter((r) => r.method === "POST").length, 0, `${c.id}: gate must not POST`);
      }
      if (input.verified === true) assert.equal(seen.length, 0, `${c.id}: verified pair must not dial`);
      return { action: decision.action };
    }
    case "route": {
      const doc = input.doc as { status?: number; bodyText?: string; answers?: readonly string[]; path: string } | null;
      const challenge = input.challenge as { status?: number; bodyText?: string; nonce?: string } | null;
      const { transport, seen } = recordingTransport(
        (request) => request.method === "GET"
          ? { status: doc?.status ?? 404, body: utf8(doc?.bodyText ?? "") }
          : { status: challenge?.status ?? 500, body: utf8(challenge?.bodyText ?? "") },
        doc?.answers,
      );
      const cache = new VerificationCache({ now: () => NOW });
      if (input.cache === true) cache.set(PAIR, NOW + 3600);
      const allowlist = (input.allowlist as { entries: readonly string[] } | null)?.entries;
      const verifier = new EndpointVerifier({
        transport,
        ...(allowlist === undefined ? {} : { allowlist }),
        hook: () => input.hook === true ? true : input.hook === false ? false : null,
        cache,
        now: () => NOW,
        nonceSource: () => challenge?.nonce ?? NONCE,
      });
      const verdict = challenge === null
        ? await verifier.verify(PAIR, NOW + 3600)
        : await verifier.verify(PAIR, NOW + 3600, {
          challenge: ({ body }) => ({ url: HOOK, method: "POST", path: "/hooks/alice", headers: {}, body }),
        });
      if (c.expect.route === "cache" || c.expect.route === "allowlist" || c.expect.route === "out_of_band") {
        assert.equal(seen.length, 0, `${c.id}: early verification route must not dial`);
      }
      return { result: verdict.verified ? "accept" : "reject", route: verdict.route, reason: verdict.reason };
    }
    case "nonce":
      return { result: nonceOk(input.value) ? "accept" : "reject" };
    case "accept-echo": {
      const { nonce, expected, issuedAt, now, ttl, consumed, pair, expectedPair } = input as WireAcceptEcho;
      // acceptEcho uses the SDK's pairKey; preserve invalid wire pairs for that check.
      return challengeResult(acceptEcho({
        ...(nonce === undefined ? {} : { nonce }),
        ...(expected === undefined ? {} : { expected }),
        ...(issuedAt === undefined ? {} : { issuedAt }),
        ...(now === undefined ? {} : { now }),
        ...(ttl === undefined ? {} : { ttlSeconds: ttl }),
        ...(consumed === undefined ? {} : { consumed }),
        pair,
        expectedPair,
      }));
    }
    case "echo":
      return challengeResult(echoOf(input as WireEcho));
    case "allowlist-entry": {
      const entry = parseAllowlistEntry(input.entry);
      return allowlistResult(entry.ok ? entry : null);
    }
    case "allowlist": {
      const hit = allowlistMatches(input.entries as AllowlistEntries, input.url as string);
      return allowlistResult(hit.matched ? hit.entry : null);
    }
    case "doc": {
      const parsed = parseReceiverDoc(input.text as string);
      return parsed.ok ? { result: "accept", receivers: parsed.receivers } : refusal(parsed.code, parsed.reason);
    }
    case "ttl":
      return { result: "accept", ttl: docCacheTtl(input.maxAge as number | undefined) };
    case "wellknown-url": {
      const url = wellKnownUrl(input.url as string);
      return url === null ? { result: "reject" } : { result: "accept", url };
    }
    case "covers": {
      const parsed = parseReceiverDoc(input.text as string);
      return parsed.ok ? receiverDocCovers(parsed.receivers, input.path as string) : { covered: false, entry: null };
    }
    case "url-check": {
      const checked = checkCallbackUrl(input.url);
      return checked.ok ? { result: "accept", canonical: checked.canonical } : refusal(checked.code, checked.reason);
    }
    case "verification-post": {
      const checked = checkDelivery(postFields(input as typeof input & DeliveryCheckInput));
      return checked.decision === "allow" ? { result: "accept", address: checked.connect.address } : refusal(checked.code, checked.reason);
    }
    case "doc-fetch": {
      const wire = input as typeof input & WireFetch;
      const verdict = input.url === undefined
        ? checkReceiverDocFetch({ ...fetchFields(wire), ...fetchLimits(wire) })
        : docRequest(input as typeof input & DeliveryCheckInput & WireFetch);
      return verdict.ok ? { result: "accept", receivers: verdict.receivers } : refusal(verdict.code, verdict.reason);
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("webhook-endpoint-verification: every case", async () => {
  await runCorpus({ corpus: "webhook-endpoint-verification", file: "webhook-endpoint-verification-vectors.json", expectedCases: 93, run });
});
