import { Buffer } from "node:buffer";
import { test } from "node:test";
import { encodeBase64Std, parseWhsec } from "../../../src/webhook/crypto/primitives.js";
import {
  asymVerify,
  checkSignatureSchemes,
  decodeSignatureEntries,
  emissionHeader,
  parseSignatureHeader,
  v1Content,
  v1Sign,
  v1Verify,
  v1aSign,
  v2aContent,
  v2aSign,
  webhookSigningKeyFromSeed,
} from "../../../src/webhook/crypto/signatures.js";
import type { V2aMessageParts, WebhookMessageParts } from "../../../src/webhook/crypto/signatures.js";
import { acceptedKey, b64u, bytes, refusal, runCorpus, secretBytes, signingKey } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

interface WireParts {
  readonly webhook_id: string;
  readonly webhook_timestamp: number;
  readonly body_b64u: string;
}

interface EndpointParts extends WireParts {
  readonly endpoint_id: string;
}

interface VerifyInput {
  readonly envelope: EndpointParts & { readonly signature_header: string };
  readonly secrets: readonly string[];
  readonly keys: readonly string[];
  readonly now: number;
  readonly window: number;
  readonly enforce: string;
}

interface EmissionInput extends EndpointParts {
  readonly secrets: readonly { readonly secret: string; readonly current?: boolean }[];
  readonly keys: readonly { readonly key: string; readonly current?: boolean }[];
}

function partsOf(input: WireParts): WebhookMessageParts {
  return { webhookId: input.webhook_id, timestamp: String(input.webhook_timestamp), body: bytes(input.body_b64u) };
}

function endpointPartsOf(input: EndpointParts): V2aMessageParts {
  return { ...partsOf(input), endpointId: input.endpoint_id };
}

function pipeline(input: VerifyInput): unknown {
  const { envelope } = input;
  const parsed = parseSignatureHeader(envelope.signature_header);
  if (!parsed.ok) return refusal(parsed.code);
  const schemes = checkSignatureSchemes(parsed.entries);
  if (!schemes.ok) return refusal(schemes.code);
  const decoded = decodeSignatureEntries(parsed.entries);
  if (!decoded.ok) return refusal(decoded.code);
  const parts = endpointPartsOf(envelope);
  if (!input.secrets.some((secret) => v1Verify(decoded.entries, secretBytes(secret), parts).ok)) {
    return refusal("bad_signature");
  }
  const timestamp = Number(envelope.webhook_timestamp);
  if (input.now - timestamp > input.window) return refusal("stale_timestamp");
  if (timestamp - input.now > input.window) return refusal("future_timestamp");
  if (input.enforce === "server") {
    if (input.keys.length === 0) return refusal("no_server_keys");
    const asym = asymVerify(decoded.entries, input.keys.map(acceptedKey), parts);
    if (!asym.ok) return refusal(asym.code);
  }
  return { result: "accept" };
}

function run(c: VectorCase): unknown {
  const { input } = c;
  switch (c.kind) {
    case "secret": {
      const parsed = parseWhsec(input.value);
      return parsed.ok ? { result: "accept", key_b64u: b64u(parsed.key) } : refusal(parsed.code, parsed.reason);
    }
    case "kat-v1": {
      const parts = partsOf(input as typeof input & WireParts);
      return { result: "accept", signature: v1Sign(secretBytes(input.secret), parts), content_b64u: b64u(v1Content(parts)) };
    }
    case "kat-v1a": {
      const parts = partsOf(input as typeof input & WireParts);
      // The SDK uses v1Content for both v1 and v1a.
      return { result: "accept", signature: v1aSign(signingKey(input.key as string), parts), content_b64u: b64u(v1Content(parts)) };
    }
    case "kat-v2a": {
      const parts = endpointPartsOf(input as typeof input & EndpointParts);
      return { result: "accept", signature: v2aSign(signingKey(input.key as string), parts), content_b64u: b64u(v2aContent(parts)) };
    }
    case "emission": {
      const wire = input as typeof input & EmissionInput;
      const header = emissionHeader({
        ...endpointPartsOf(wire),
        secrets: wire.secrets.map(({ secret, current }) => ({ secret: secretBytes(secret), current: current === true })),
        keys: wire.keys.map(({ key, current }) => ({ key: signingKey(key), current: current === true })),
      });
      const parsed = parseSignatureHeader(header);
      if (!parsed.ok) throw new Error("an emitted header must parse as a signature header");
      return { result: "accept", header, schemes: parsed.entries.map((entry) => entry.scheme) };
    }
    case "verify":
      return pipeline(input as typeof input & VerifyInput);
    case "upstream-v2a":
    case "upstream-combined": {
      const key = webhookSigningKeyFromSeed(Buffer.from((input.private_key as string).slice("whsk_".length), "base64"));
      const parts = endpointPartsOf(input as typeof input & EndpointParts);
      const signature = v2aSign(key, parts);
      if (c.kind === "upstream-combined") {
        const { header } = c.upstream as { readonly header: string };
        const [v1Literal, publishedV2a] = header.split(" ");
        if (signature !== publishedV2a) throw new Error(`${c.id}: the upstream combined header disagrees on the v2a entry`);
        return { result: "accept", v1_literal: v1Literal, v2a: signature };
      }
      const upstream = c.upstream as {
        readonly public_key: string;
        readonly sha256_base64: string;
        readonly signature: string;
      };
      const publishedPublicKey = b64u(Buffer.from(upstream.public_key.slice("whpk_".length), "base64"));
      const wrong: string[] = [];
      if (b64u(key.publicKey) !== publishedPublicKey) wrong.push("public_key");
      if (encodeBase64Std(v2aContent(parts)) !== upstream.sha256_base64) wrong.push("sha256_base64");
      if (signature !== upstream.signature) wrong.push("signature");
      if (wrong.length > 0) throw new Error(`${c.id}: the upstream example disagrees on ${wrong.join(", ")}`);
      return { result: "accept" };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("webhook-signature: every case", async () => {
  await runCorpus({ corpus: "webhook-signature", file: "webhook-signature-vectors.json", expectedCases: 45, run });
});
