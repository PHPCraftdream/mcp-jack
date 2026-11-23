import { decodeBase64UrlStrict } from "../crypto/primitives.js";
import type { AcceptedWebhookKey } from "../crypto/signatures.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import { acceptJwkSet, parseCidrList } from "./jwk.js";
import type { EgressRange, RejectedJwk } from "./jwk.js";
import { sameOrigin, webhookInfo } from "./remote.js";

export { crossCheckWebhookKey } from "./crosscheck.js";

const MAX_CARD_BYTES = 65536;
const MAX_CARD_TTL = 300;
const MAX_ELAPSED_MS = 10000;

/** The observed response to a Server Card request. */
export interface CardResponse {
  readonly status?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly bodyB64u?: string;
  readonly redirectTo?: string | null;
  readonly tooLarge?: boolean;
}

/** The request URLs, observed response and optional MCP server key exclusions. */
export interface CardFetchInput {
  readonly mcpUrl: string;
  readonly cardUrl: string;
  readonly response: CardResponse;
  readonly elapsedMs?: number;
  readonly mcpServerKid?: string | null;
  readonly mcpServerPublicKey?: string | null;
}

/** Accepted keys, raw card keys, advisory ranges and cache lifetime, or the first fetch refusal. */
export type CardFetchDecision =
  | {
      readonly ok: true;
      readonly keys: readonly AcceptedWebhookKey[];
      readonly cardKeys: readonly unknown[];
      readonly egressIpRanges: readonly EgressRange[];
      readonly rejectedKeys: readonly RejectedJwk[];
      readonly cacheTtlSeconds: number;
    }
  | {
      readonly ok: false;
      readonly code:
        | "not_https"
        | "cross_origin"
        | "redirect_refused"
        | "http_status"
        | "timeout"
        | "too_large"
        | "bad_json"
        | "no_remote";
      readonly reason: string;
    };

function cardCacheTtl(headers: CardResponse["headers"]): number {
  const value = headers !== null && typeof headers === "object" ? headers["cache-control"] : undefined;
  if (typeof value === "string") {
    for (const part of value.split(",")) {
      const token = part.trim();
      if (/^max-age=[0-9]+$/.test(token)) return Math.min(Number(token.slice("max-age=".length)), MAX_CARD_TTL);
    }
  }
  return MAX_CARD_TTL;
}

/** Applies the Server Card fetch and key acceptance rules without performing I/O (spec 06 R7.2–R7.5). */
export function fetchDecision(input: CardFetchInput): CardFetchDecision {
  const { mcpUrl, cardUrl, response, elapsedMs, mcpServerKid = null, mcpServerPublicKey = null } = input;
  const card = checkCallbackUrl(cardUrl);
  if (!card.ok) return { ok: false, code: "not_https", reason: card.reason ?? card.code };
  if (!sameOrigin(cardUrl, mcpUrl)) return { ok: false, code: "cross_origin", reason: "origin_mismatch" };
  const answer: CardResponse = response !== null && typeof response === "object" ? response : {};
  const { status, redirectTo } = answer;
  if ((redirectTo !== undefined && redirectTo !== null) || (typeof status === "number" && status >= 300 && status <= 399)) {
    return { ok: false, code: "redirect_refused", reason: "redirect" };
  }
  if (answer.tooLarge === true) return { ok: false, code: "too_large", reason: "body" };
  if (!(typeof status === "number" && status >= 200 && status <= 299)) {
    return { ok: false, code: "http_status", reason: "status" };
  }
  if (typeof elapsedMs === "number" && elapsedMs > MAX_ELAPSED_MS) {
    return { ok: false, code: "timeout", reason: "elapsed" };
  }
  const { bodyB64u } = answer;
  const body = decodeBase64UrlStrict(typeof bodyB64u === "string" ? bodyB64u : "") ?? new Uint8Array(0);
  if (body.length > MAX_CARD_BYTES) return { ok: false, code: "too_large", reason: "body" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    return { ok: false, code: "bad_json", reason: "json" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "bad_json", reason: "shape" };
  }
  const info = webhookInfo(parsed, { mcpUrl });
  if (!info.ok) return { ok: false, code: info.code, reason: "no_remote" };
  const keys = acceptJwkSet(info.signingKeys, { mcpServerKid, mcpServerPublicKey });
  return {
    ok: true,
    keys: keys.accepted,
    cardKeys: info.cardKeys,
    egressIpRanges: parseCidrList(info.egressIpRanges).accepted,
    rejectedKeys: keys.rejected,
    cacheTtlSeconds: cardCacheTtl(answer.headers),
  };
}

/** Looks up an exact non-empty kid in the accepted card keys (spec 06 R7.2–R7.3). */
export function cardKeyForKid(keys: readonly AcceptedWebhookKey[], kid: unknown):
  | { readonly ok: true; readonly key: AcceptedWebhookKey }
  | { readonly ok: false; readonly code: "unknown_webhook_key" } {
  if (typeof kid !== "string" || kid.length === 0) return { ok: false, code: "unknown_webhook_key" };
  const list: readonly AcceptedWebhookKey[] = Array.isArray(keys) ? keys : [];
  const key = list.find((entry) => entry !== null && typeof entry === "object" && entry.kid === kid);
  return key === undefined ? { ok: false, code: "unknown_webhook_key" } : { ok: true, key };
}
