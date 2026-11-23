import { encodeBase64URL } from "../../core/encoding.js";
import { crossCheckWebhookKey } from "../card/crosscheck.js";
import { decodeBase64UrlStrict, parseWhsec, sha256Bytes } from "../crypto/primitives.js";
import {
  asymVerify,
  checkSignatureSchemes,
  decodeSignatureEntries,
  parseSignatureHeader,
  v1Verify,
  w1Verify,
} from "../crypto/signatures.js";
import type { AcceptedWebhookKey } from "../crypto/signatures.js";
import { parseWebhookBody } from "./envelope.js";

const H_ID = "webhook-id";
const H_TS = "webhook-timestamp";
const H_SIG = "webhook-signature";
const H_SUB = "x-mcp-subscription-id";
const H_JACK = "jack-webhook-auth";
const H_LEN = "content-length";
const REQUIRED = [H_ID, H_TS, H_SIG, H_SUB];
const ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const TS_RE = /^(0|[1-9][0-9]{0,11})$/;
const SUB_RE = /^sub_[0-9a-f]{16}$/;
const LEN_RE = /^[0-9]+$/;
const DEFAULT_WINDOW = 300;
const DEFAULT_MAX_BODY = 262144;
const DEFAULT_DEDUP = 1200;
const DEFAULT_JACK_WINDOW = 30;
const MAX_ATTEMPTS = 4;
const RETRY_CAP = 900;

const ERRORS = {
  missing_webhook_header: [400, "a required header is absent"],
  duplicate_webhook_header: [400, "a required header is repeated"],
  malformed_webhook_id: [400, "webhook-id grammar"],
  malformed_webhook_timestamp: [400, "webhook-timestamp grammar"],
  malformed_subscription_id: [400, "subscription id grammar"],
  body_too_large: [413, "body or declared length above the limit"],
  unknown_subscription: [401, "no secret applies to the subscription"],
  subscription_not_routed: [503, "the subscription is not routed"],
  subscription_terminated: [410, "the subscription is terminated"],
  stale_timestamp: [401, "timestamp too old"],
  future_timestamp: [401, "timestamp too far ahead"],
  malformed_signature_header: [400, "signature header grammar"],
  unsupported_signature_scheme: [400, "unsupported signature scheme"],
  malformed_signature: [400, "signature value length"],
  bad_signature: [401, "signature does not verify"],
  bad_server_signature: [401, "server signature does not verify"],
  no_server_keys: [503, "no accepted server key"],
  missing_jack_auth: [401, "jack header absent"],
  malformed_jack_auth: [400, "jack header grammar"],
  webhook_key_is_server_key: [401, "the webhook key is the mcp server key"],
  unknown_webhook_key: [401, "unknown webhook key"],
  jack_timestamp_out_of_window: [401, "jack timestamp outside the window"],
  bad_jack_signature: [401, "jack signature does not verify"],
  webhook_key_mismatch: [401, "the webhook key sources disagree"],
  webhook_key_missing: [401, "the webhook key source is missing"],
  enqueue_failed: [503, "durable enqueue failed"],
  malformed_body: [400, "body is not a json object"],
  unknown_envelope_type: [400, "unknown envelope type"],
} as const;

/** A registered secret or a pending secret awaiting verification. */
export interface ReceiverSecret {
  readonly secret: Uint8Array | string;
  readonly subscriptionId?: string | null;
  readonly callbackUrl?: string;
}

/** Jack verification settings, with the original callback URL for each routed subscription. */
export interface ReceiverJackConfig {
  readonly aud: string;
  readonly window?: number;
  readonly callbackUrls: Readonly<Record<string, string>>;
}

/** Persists forwarded messages, resolving only once the enqueue is durable. */
export type EnqueueDelivered = (delivered: readonly Record<string, unknown>[]) => Promise<void>;

/** Initial receiver limits, authentication settings, secrets and routing. */
export interface WebhookReceiverConfig {
  readonly window?: number;
  readonly maxBodyBytes?: number;
  readonly dedupRetentionSeconds?: number;
  readonly enforceServerIdentity?: boolean;
  readonly mcpServerKid?: string | null;
  readonly mcpServerPublicKey?: string | null;
  readonly keys?: readonly AcceptedWebhookKey[];
  readonly webhookKeyCheck?: "require" | "ignore";
  readonly webhookKeyToolResult?: unknown;
  /** Supplies raw Server Card JWK entries, including rejected entries, for the R7.6 cross-check. */
  readonly webhookKeyCardEntries?: readonly unknown[];
  readonly jack?: ReceiverJackConfig | null;
  readonly secrets: readonly ReceiverSecret[];
  readonly routed?: readonly string[];
  readonly enqueue: EnqueueDelivered;
}

/** Wire headers, retaining repeated values for case-insensitive grouping. */
export type HeaderPairs = readonly (readonly [string, string | readonly string[]])[];

/** One delivery with an explicit receiver clock in seconds. */
export interface ReceiverRequest {
  readonly now: number;
  readonly headers: HeaderPairs;
  readonly body: Uint8Array | string;
}

/** The HTTP response, forwarded messages and whether this step recorded the webhook id. */
export interface ReceiverStepResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly delivered: readonly Record<string, unknown>[];
  readonly code: string | null;
  readonly recorded: boolean;
}

/** The observable receiver state, without secret key bytes. */
export interface ReceiverSnapshot {
  readonly routed: readonly string[];
  readonly terminated: readonly string[];
  readonly secrets: readonly { readonly subscriptionId: string | null; readonly callbackUrl: string | null }[];
  readonly accepted: readonly string[];
}

interface SecretEntry {
  readonly key: Uint8Array;
  subscriptionId: string | null;
  readonly callbackUrl?: string;
}

function done(status: number, body: Record<string, unknown>, recorded: boolean): ReceiverStepResult {
  return { status, body, delivered: [], code: null, recorded };
}

function reject(code: keyof typeof ERRORS): ReceiverStepResult {
  const [status, message] = ERRORS[code];
  return { status, body: { error: { code, message } }, delivered: [], code, recorded: false };
}

function num(value: unknown, fallback: number): number {
  return typeof value === "number" ? value : fallback;
}

function arrayOrEmpty<T>(value: readonly T[] | undefined): readonly T[] {
  return Array.isArray(value) ? value : [];
}

function viewBytes(view: ArrayBufferView): Uint8Array {
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
}

function bodyBytes(body: ReceiverRequest["body"]): Uint8Array {
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (ArrayBuffer.isView(body)) return viewBytes(body);
  return new Uint8Array(0);
}

function collectHeaders(headers: HeaderPairs): Map<string, string[]> {
  const all = new Map<string, string[]>();
  for (const pair of arrayOrEmpty(headers)) {
    if (!Array.isArray(pair) || typeof pair[0] !== "string") continue;
    const [name, value] = pair;
    const lower = name.toLowerCase();
    const values = all.get(lower) ?? [];
    if (typeof value === "string") values.push(value);
    else if (Array.isArray(value)) {
      for (const item of value) if (typeof item === "string") values.push(item);
    }
    all.set(lower, values);
  }
  return all;
}

function secretKey(entry: ReceiverSecret): Uint8Array {
  const value = entry && typeof entry === "object" ? entry.secret : undefined;
  if (ArrayBuffer.isView(value)) return viewBytes(value);
  const parsed = parseWhsec(value);
  if (!parsed.ok) throw new Error(`receiver secret must be a Buffer or a whsec_ value: ${parsed.reason}`);
  return parsed.key;
}

function secretEntries(secrets: readonly ReceiverSecret[]): SecretEntry[] {
  return arrayOrEmpty(secrets).map((entry) => ({
    key: secretKey(entry),
    subscriptionId: typeof entry.subscriptionId === "string" ? entry.subscriptionId : null,
    ...(typeof entry.callbackUrl === "string" ? { callbackUrl: entry.callbackUrl } : {}),
  }));
}

function serverKidOf(publicKey: string | null): string | null {
  if (publicKey === null) return null;
  const raw = decodeBase64UrlStrict(publicKey);
  return raw === null ? null : encodeBase64URL(sha256Bytes(raw));
}

function acceptedKeys(
  keys: readonly AcceptedWebhookKey[] | undefined,
  serverKid: string | null,
  serverPublicKey: string | null,
): AcceptedWebhookKey[] {
  const out: AcceptedWebhookKey[] = [];
  for (const key of arrayOrEmpty(keys)) {
    if (key === null || typeof key !== "object" || Array.isArray(key)) continue;
    const { kid, publicKey } = key;
    if (serverKid !== null && kid === serverKid) continue;
    if (serverPublicKey !== null && publicKey === serverPublicKey) continue;
    const { kty, crv, x, raw } = key;
    out.push({ kid, kty, crv, x, publicKey, raw });
  }
  return out;
}

/** A deterministic webhook receiver with in-memory routing, termination and deduplication. */
export class WebhookReceiver {
  private readonly window: number;
  private readonly maxBody: number;
  private readonly retention: number;
  private readonly enforce: boolean;
  private readonly serverKeyId: string | null;
  private readonly keys: readonly AcceptedWebhookKey[];
  private readonly webhookKeyCheck: "require" | "ignore";
  private readonly webhookKeyTool: unknown;
  private readonly webhookKeyCardEntries: readonly unknown[] | undefined;
  private readonly jack: ReceiverJackConfig | null;
  private readonly jackWindow: number;
  private readonly entries: readonly SecretEntry[];
  private readonly routed: Set<string>;
  private readonly enqueue: EnqueueDelivered;
  private readonly terminated = new Set<string>();
  private readonly accepted = new Map<string, number>();

  /** Builds a receiver with its original callback URLs and initial routing. */
  constructor(config: WebhookReceiverConfig) {
    if (typeof config.enqueue !== "function") throw new Error("WebhookReceiver requires an enqueue callback");
    this.window = num(config.window, DEFAULT_WINDOW);
    this.maxBody = num(config.maxBodyBytes, DEFAULT_MAX_BODY);
    this.retention = num(config.dedupRetentionSeconds, DEFAULT_DEDUP);
    this.enforce = config.enforceServerIdentity === true;
    const serverKid = typeof config.mcpServerKid === "string" ? config.mcpServerKid : null;
    const serverPublicKey = typeof config.mcpServerPublicKey === "string" ? config.mcpServerPublicKey : null;
    this.serverKeyId = serverKid ?? serverKidOf(serverPublicKey);
    this.keys = acceptedKeys(config.keys, serverKid, serverPublicKey);
    this.webhookKeyCheck = config.webhookKeyCheck === "require" ? "require" : "ignore";
    this.webhookKeyTool = config.webhookKeyToolResult ?? null;
    this.webhookKeyCardEntries = config.webhookKeyCardEntries;
    this.jack = config.jack ?? null;
    const jackWindow = this.jack?.window;
    if (jackWindow !== undefined && (!Number.isInteger(jackWindow) || jackWindow < 1 || jackWindow > 120)) {
      throw new Error("jack window must be an integer from 1 through 120 seconds");
    }
    this.jackWindow = jackWindow ?? DEFAULT_JACK_WINDOW;
    this.enqueue = config.enqueue;
    this.entries = secretEntries(config.secrets);
    this.routed = new Set(arrayOrEmpty(config.routed));
  }

  /**
   * Verifies one delivery, stopping at the first refusal in the reference order.
   * For a forwarded message, returns 2xx only after the application's enqueue resolves;
   * a failed enqueue records nothing. Verification challenges are echoed in place.
   */
  async handle({ now, headers, body }: ReceiverRequest): Promise<ReceiverStepResult> {
    const raw = bodyBytes(body);
    const all = collectHeaders(headers);
    // R3.1 and R3.2: check absence for every required name before checking repeats.
    for (const name of REQUIRED) {
      if ((all.get(name)?.length ?? 0) === 0) return reject("missing_webhook_header");
    }
    for (const name of REQUIRED) {
      if ((all.get(name)?.length ?? 0) > 1) return reject("duplicate_webhook_header");
    }
    const webhookId = all.get(H_ID)?.[0] ?? "";
    const timestamp = all.get(H_TS)?.[0] ?? "";
    const subscriptionId = all.get(H_SUB)?.[0] ?? "";
    if (!ID_RE.test(webhookId)) return reject("malformed_webhook_id");
    if (!TS_RE.test(timestamp)) return reject("malformed_webhook_timestamp");
    if (!SUB_RE.test(subscriptionId)) return reject("malformed_subscription_id");
    if (raw.length > this.maxBody) return reject("body_too_large");
    const declared = all.get(H_LEN)?.[0];
    if (declared !== undefined && declared.length > 0 && (!LEN_RE.test(declared) || Number(declared) > this.maxBody)) {
      return reject("body_too_large");
    }

    const registered = this.entries.find((entry) => entry.subscriptionId === subscriptionId);
    const deferred = registered === undefined;
    const candidates = deferred ? this.entries.filter((entry) => entry.subscriptionId === null) : [registered];
    if (deferred && candidates.length === 0) return reject("unknown_subscription");
    if (!deferred && !this.routed.has(subscriptionId) && !this.terminated.has(subscriptionId)) {
      return reject("subscription_not_routed");
    }
    const parsedHeader = parseSignatureHeader(all.get(H_SIG)?.[0] ?? "");
    if (!parsedHeader.ok) return reject(parsedHeader.code);
    const schemes = checkSignatureSchemes(parsedHeader.entries);
    if (!schemes.ok) return reject(schemes.code);
    const decoded = decodeSignatureEntries(parsedHeader.entries);
    if (!decoded.ok) return reject(decoded.code);
    const parts = { webhookId, timestamp, body: raw };
    const matched = candidates.find((entry) => v1Verify(decoded.entries, entry.key, parts).ok);
    if (matched === undefined) return reject("bad_signature");

    // R3.9: freshness is only evaluated after the HMAC verifies.
    const seconds = Number(timestamp);
    if (now - seconds > this.window) return reject("stale_timestamp");
    if (seconds - now > this.window) return reject("future_timestamp");
    if (this.enforce) {
      if (this.keys.length === 0) return reject("no_server_keys");
      if (!asymVerify(decoded.entries, this.keys, { ...parts, endpointId: subscriptionId }).ok) {
        return reject("bad_server_signature");
      }
    }
    const jack = this.jack;
    if (jack !== null) {
      const header = all.get(H_JACK)?.[0];
      if (header === undefined) return reject("missing_jack_auth");
      const callbackUrl = deferred ? matched.callbackUrl : jack.callbackUrls?.[subscriptionId];
      const checked = w1Verify(
        header,
        { ...parts, aud: jack.aud, subscriptionId, callbackUrl: callbackUrl ?? "" },
        { keys: this.keys, now, window: this.jackWindow, mcpServerKid: this.serverKeyId },
      );
      if (!checked.ok) return reject(checked.code);
      // Joining an absent URL signs an empty line; absence is refused only after w1 verification.
      if (callbackUrl === undefined) return reject("bad_jack_signature");
    }
    if (this.webhookKeyCheck === "require") {
      const crossed = crossCheckWebhookKey({
        keys: this.webhookKeyCardEntries ?? this.keys,
        toolResult: this.webhookKeyTool ?? null,
        require: true,
      });
      if (!crossed.ok) return reject(crossed.code);
    }

    const seenAt = this.accepted.get(webhookId);
    if (seenAt !== undefined && now - seenAt <= this.retention) return done(200, { status: "duplicate" }, false);
    const parsed = parseWebhookBody(raw);
    if (!parsed.ok) return reject(parsed.code);
    const { type, message } = parsed.envelope;
    if (this.terminated.has(subscriptionId)) return reject("subscription_terminated");
    if (deferred && type !== "verification") return reject("subscription_not_routed");
    if (type !== "verification") {
      try {
        await this.enqueue([message]);
      } catch {
        return reject("enqueue_failed");
      }
    }
    this.accepted.set(webhookId, now);
    if (type === "verification") {
      if (deferred) {
        matched.subscriptionId = subscriptionId;
        this.routed.add(subscriptionId);
      }
      return done(200, { challenge: message.challenge }, true);
    }
    if (type === "terminated") {
      this.terminated.add(subscriptionId);
      this.routed.delete(subscriptionId);
    }
    return { status: 200, body: { status: "accepted" }, delivered: [message], code: null, recorded: true };
  }

  /** Adds subscription ids to the routing set without resetting receiver state. */
  route(ids: readonly string[]): void {
    for (const id of arrayOrEmpty(ids)) this.routed.add(id);
  }

  /** Returns routing, termination, secret bindings and accepted ids. */
  snapshot(): ReceiverSnapshot {
    return {
      routed: [...this.routed].sort(),
      terminated: [...this.terminated].sort(),
      secrets: this.entries.map((entry) => ({
        subscriptionId: entry.subscriptionId,
        callbackUrl: entry.callbackUrl ?? null,
      })),
      accepted: [...this.accepted.keys()].sort(),
    };
  }
}

/** The four delivery attempt offsets in seconds (spec 06 R1.8). */
export const RETRY_TIMES: readonly number[] = [0, 30, 270, 870];

/** Classifies an HTTP status as a receiver refusal or server failure, if applicable. */
export function lastErrorOf(status: number): "http_4xx" | "http_5xx" | null {
  if (!Number.isInteger(status)) return null;
  if (status >= 200 && status <= 299) return null;
  if (status >= 500 && status <= 599) return "http_5xx";
  if (status >= 300 && status <= 499) return "http_4xx";
  return null;
}

/** The sender outcome of a single attempt. */
export type SenderAction =
  | { readonly action: "accept" }
  | { readonly action: "final"; readonly lastError: string }
  | { readonly action: "retry"; readonly nextAt: number; readonly lastError: string };

/** An attempt outcome and retry timing inputs, in seconds. */
export interface SenderDecisionInput {
  readonly status?: number;
  readonly retryAfter?: number;
  readonly attempt?: number;
  readonly t0?: number;
  readonly responseTime?: number;
  readonly transport?: string | null;
}

/** Accepts, retries or abandons an attempt according to spec 06 R1.7–R1.9. */
export function senderDecision(input: SenderDecisionInput): SenderAction {
  const { status = NaN, retryAfter = NaN, attempt, t0 = NaN, responseTime = NaN } = input;
  const transport = typeof input.transport === "string" ? input.transport : null;
  const httpError = lastErrorOf(status);
  const lastError = transport ?? httpError ?? "http_4xx";
  const final = (): SenderAction => ({ action: "final", lastError });
  if (transport === null) {
    if (Number.isInteger(status) && status >= 200 && status <= 299) return { action: "accept" };
    if (status === 410 || status === 413) return final();
  }
  const retryable = transport !== null || status === 425 || status === 429 || httpError === "http_5xx";
  if (!retryable) return final();
  if (attempt === undefined || !Number.isInteger(attempt) || attempt >= MAX_ATTEMPTS) return final();
  let nextAt = t0 + (RETRY_TIMES[attempt] ?? NaN);
  if (Number.isInteger(retryAfter) && retryAfter > 0 && Number.isFinite(responseTime)) {
    const postponed = responseTime + retryAfter;
    if (postponed > nextAt) nextAt = postponed;
  }
  const cap = t0 + RETRY_CAP;
  if (nextAt > cap) nextAt = cap;
  if (nextAt <= responseTime) return final();
  return { action: "retry", nextAt, lastError };
}

/** The four absolute delivery attempt times from t0. */
export function retrySchedule(t0: number): readonly number[] {
  return RETRY_TIMES.map((delay) => t0 + delay);
}
