import { emissionHeader, w1Sign } from "../crypto/signatures.js";
import type { ActiveSecret, VersionedSigningKey, WebhookSigningKey } from "../crypto/signatures.js";
import { senderDecision } from "../receiver/core.js";
import type { HardenedOutcome, HardenedTransport } from "../ssrf/client.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import type { CallbackUrlCheck, CallbackUrlCode } from "../ssrf/url.js";
import type { ChallengeSigner, EndpointVerification, EndpointVerifier } from "../verification/routes.js";
import { newWebhookId } from "./message.js";
import type { OutboundMessage } from "./message.js";

const PROTOCOL_MAX_BODY_BYTES = 262144;
const RETRY_WINDOW_SECONDS = 900;

/** The subscription, verified Jack identity name and active credentials for one callback. */
export interface WebhookDeliveryTarget {
  readonly subscriptionId: string;
  readonly principal: string;
  readonly callbackUrl: string;
  readonly canonicalUrl?: string;
  readonly secrets: readonly ActiveSecret[];
  readonly signingKeys?: readonly VersionedSigningKey[];
  readonly verificationExpiresAt?: number;
}

/** The receiver audience and dedicated key for optional Jack w1 signatures. */
export interface SenderJackConfig {
  readonly aud: string;
  readonly signingKey: WebhookSigningKey;
}

/** What the sender may do after checking the endpoint. */
export type GateAction = "deliver" | "send-challenge" | "refuse";

/** The gate's decision and, on refusal, its reason. */
export interface GateDecision {
  readonly action: GateAction;
  readonly reason: string | null;
}

/** Sender dependencies; the clock returns Unix seconds and sleep takes milliseconds. */
export interface WebhookSenderOptions {
  readonly transport: HardenedTransport;
  readonly verifier: EndpointVerifier;
  readonly jack?: SenderJackConfig | null;
  readonly now: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly randomBytes?: (n: number) => Uint8Array;
  readonly maxBodyBytes?: number;
  readonly verificationTtlSeconds?: number;
}

/** The final outcome for one message, without response bodies or headers. */
export interface DeliveryOutcome {
  readonly webhookId: string;
  readonly attempts: number;
  readonly accepted: boolean;
  readonly lastError: string | null;
  readonly status: number | null;
  readonly gate: GateAction;
}

type TransportFailure = Extract<HardenedOutcome, { readonly ok: false }>["code"];

function checkTargetUrl({ callbackUrl, canonicalUrl }: WebhookDeliveryTarget): CallbackUrlCheck {
  const checked = checkCallbackUrl(callbackUrl);
  // A precomputed canonical URL cannot authorize sending to a different endpoint.
  if (checked.ok && canonicalUrl !== undefined && canonicalUrl !== checked.canonical) {
    return { ok: false, code: "invalid_callback_url" };
  }
  return checked;
}

function requestPath({ path, query }: Extract<CallbackUrlCheck, { readonly ok: true }>): string {
  return path + (query === "" ? "" : `?${query}`);
}

function callbackUrlError(code: CallbackUrlCode): "connection_refused" | "http_4xx" {
  // A non-HTTPS scheme is a connection refusal; malformed URLs (including dot segments) are http_4xx.
  return code === "scheme_not_https" ? "connection_refused" : "http_4xx";
}

function transportError(code: TransportFailure): "connection_refused" | "http_4xx" | "timeout" | "tls_error" {
  switch (code) {
    case "timeout":
    case "tls_error":
      return code;
    case "redirect_refused":
      return "http_4xx";
    case "connection_refused":
    case "blocked_address":
    case "dns_rebinding":
    case "no_answer":
      return "connection_refused";
    default:
      return callbackUrlError(code);
  }
}

function retryAfterSeconds(headers: Readonly<Record<string, string>>): number | undefined {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === "retry-after")?.[1];
  if (value === undefined || value.length === 0 || /[^0-9]/.test(value)) return undefined;
  return Math.min(Number(value), Number.MAX_SAFE_INTEGER);
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/** Verifies endpoints and sends signed messages without changing subscriptions. */
export class WebhookSender {
  readonly #maxBodyBytes: number;
  readonly #verificationTtlSeconds: number;

  /** Requires an endpoint verifier and a hardened transport. */
  constructor(private readonly options: WebhookSenderOptions) {
    if (options?.verifier == null) throw new Error("WebhookSender requires an EndpointVerifier");
    if (options.transport == null) throw new Error("WebhookSender requires a transport");
    const limit = options.maxBodyBytes ?? PROTOCOL_MAX_BODY_BYTES;
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > PROTOCOL_MAX_BODY_BYTES) {
      throw new Error("WebhookSender maxBodyBytes must be an integer from 0 through 262144");
    }
    this.#maxBodyBytes = limit;
    this.#verificationTtlSeconds = options.verificationTtlSeconds ?? 300;
  }

  /** Checks verification routes without sending a challenge or an event. */
  async gate(target: WebhookDeliveryTarget, message: OutboundMessage): Promise<GateDecision> {
    if (message.kind === "verification") return { action: "send-challenge", reason: null };
    const checked = checkTargetUrl(target);
    if (!checked.ok) return { action: "refuse", reason: callbackUrlError(checked.code) };
    const { principal, canonicalUrl = checked.canonical } = target;
    if (typeof principal !== "string" || principal.length === 0) return { action: "refuse", reason: "no_route" };
    const verification = await this.options.verifier.verify({ principal, canonicalUrl }, this.#expiresAt(target));
    return verification.verified
      ? { action: "deliver", reason: null }
      : { action: "refuse", reason: verification.reason ?? "no_route" };
  }

  /** Verifies the endpoint, allowing a signed challenge if earlier routes do not verify it. */
  async challenge(target: WebhookDeliveryTarget): Promise<EndpointVerification> {
    const challengeTarget = { ...target };
    const checked = checkTargetUrl(challengeTarget);
    if (!checked.ok) return { verified: false, route: null, reason: callbackUrlError(checked.code) };
    const { principal, canonicalUrl = checked.canonical } = challengeTarget;
    if (typeof principal !== "string" || principal.length === 0) {
      return { verified: false, route: null, reason: "no_route" };
    }
    const signer: ChallengeSigner = ({ body, destination }) => {
      const webhookId = newWebhookId("verification", this.options.randomBytes);
      const timestamp = String(Math.floor(this.options.now()));
      return { headers: this.#headers(challengeTarget, webhookId, timestamp, body) };
    };
    return this.options.verifier.verify({ principal, canonicalUrl }, this.#expiresAt(challengeTarget), { challenge: signer });
  }

  /**
   * Delivers a verified message, preserving its id and signing again on each retry.
   * An attempt starting after the R1.8 window is abandoned with `timeout`, using the injected clock, never wall time.
   */
  async deliver(target: WebhookDeliveryTarget, message: OutboundMessage): Promise<DeliveryOutcome> {
    const { webhookId, body } = message;
    const notSent = { webhookId, attempts: 0, accepted: false, status: null };
    if (body.length > this.#maxBodyBytes) return { ...notSent, lastError: "http_4xx", gate: "refuse" };
    if (message.kind === "verification") return { ...notSent, lastError: null, gate: "send-challenge" };

    // Keep the verified pair and send destination bound across awaits.
    const deliveryTarget = { ...target };
    const checked = checkTargetUrl(deliveryTarget);
    if (!checked.ok) return { ...notSent, lastError: callbackUrlError(checked.code), gate: "refuse" };
    const decision = await this.gate(deliveryTarget, message);
    if (decision.action === "send-challenge") return { ...notSent, lastError: null, gate: "send-challenge" };
    if (decision.action === "refuse" && !(await this.challenge(deliveryTarget)).verified) {
      return { ...notSent, lastError: "challenge_failed", gate: "send-challenge" };
    }

    const { transport, now } = this.options;
    const { callbackUrl } = deliveryTarget;
    const path = requestPath(checked);
    const wait = this.options.sleep ?? sleep;
    const t0 = now();
    // senderDecision ends the loop no later than attempt four.
    for (let attempt = 1; ; attempt += 1) {
      const startedAt = attempt === 1 ? t0 : now();
      if (startedAt > t0 + RETRY_WINDOW_SECONDS) {
        return { webhookId, attempts: attempt - 1, accepted: false, lastError: "timeout", status: null, gate: "deliver" };
      }
      const timestamp = String(Math.floor(startedAt));
      const headers = this.#headers(deliveryTarget, webhookId, timestamp, body);
      const result = await transport.request(callbackUrl, { method: "POST", path, headers, body });
      const responseTime = now();
      const status = result.ok ? result.response.status : null;
      const retryAfter = result.ok ? retryAfterSeconds(result.response.headers) : undefined;
      const retry = senderDecision({
        attempt,
        t0,
        responseTime,
        ...(status === null ? {} : { status }),
        ...(retryAfter === undefined ? {} : { retryAfter }),
        transport: result.ok ? null : transportError(result.code),
      });
      if (retry.action === "accept") {
        return { webhookId, attempts: attempt, accepted: true, lastError: null, status, gate: "deliver" };
      }
      // R1.9: policy refusals are final, even though ordinary connection failures can retry.
      if (retry.action === "final" || (!result.ok &&
          (result.code === "redirect_refused" || result.code === "blocked_address" || result.code === "dns_rebinding"))) {
        return { webhookId, attempts: attempt, accepted: false, lastError: retry.lastError, status, gate: "deliver" };
      }
      await wait((retry.nextAt - responseTime) * 1000);
    }
  }

  #expiresAt(target: WebhookDeliveryTarget): number {
    return target.verificationExpiresAt ?? Math.floor(this.options.now()) + this.#verificationTtlSeconds;
  }

  #headers(target: WebhookDeliveryTarget, webhookId: string, timestamp: string, body: Uint8Array): Record<string, string> {
    const { subscriptionId, callbackUrl, secrets, signingKeys } = target;
    const parts = { webhookId, timestamp, body };
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "webhook-id": webhookId,
      "webhook-timestamp": timestamp,
      "webhook-signature": emissionHeader({ ...parts, secrets, keys: signingKeys ?? [], endpointId: subscriptionId }),
      "X-MCP-Subscription-Id": subscriptionId,
    };
    const { jack } = this.options;
    if (jack != null) {
      headers["Jack-Webhook-Auth"] = w1Sign(jack.signingKey, { ...parts, aud: jack.aud, subscriptionId, callbackUrl });
    }
    return headers;
  }
}
