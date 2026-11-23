import { clearTimeout, setTimeout } from "node:timers";
import { encodeBase64URL } from "../../core/encoding.js";
import type { AcceptedWebhookKey } from "../crypto/signatures.js";
import type { HardenedOutcome, HardenedRequest } from "../ssrf/client.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import { fetchDecision } from "./fetch.js";
import type { EgressRange, RejectedJwk } from "./jwk.js";
import { defaultCardUrl, sameOrigin } from "./remote.js";

const CARD_TIMEOUT_MS = 10000;
const MAX_CARD_BYTES = 65536;

/** Server Card origin, hardened transport, millisecond fetch clock and MCP key exclusions. */
export interface ServerCardSourceOptions {
  readonly mcpUrl: string;
  readonly cardUrl?: string;
  readonly transport: { request(url: string, request: HardenedRequest): Promise<HardenedOutcome> };
  readonly now?: () => number;
  readonly mcpServerKid?: string | null;
  readonly mcpServerPublicKey?: string | null;
}

/** Accepted and raw Server Card keys, advisory ranges and rejected keys, or a fetch refusal. */
export type ServerCardKeys =
  | {
      readonly ok: true;
      readonly keys: readonly AcceptedWebhookKey[];
      readonly cardKeys: readonly unknown[];
      readonly egressIpRanges: readonly EgressRange[];
      readonly rejectedKeys: readonly RejectedJwk[];
    }
  | { readonly ok: false; readonly code: string };

/** Fetches and caches the Server Card key decision for a configured MCP endpoint. */
export class ServerCardKeySource {
  readonly #options: ServerCardSourceOptions;
  readonly #clock: () => number;
  #cached: { readonly until: number; readonly result: ServerCardKeys & { readonly ok: true } } | null = null;

  /** Configures one MCP endpoint and its hardened transport. */
  constructor(options: ServerCardSourceOptions) {
    this.#options = options;
    this.#clock = options.now ?? Date.now;
  }

  /** Returns the configured or default R7.2 card URL, or null if no default can be derived. */
  cardUrl(): string | null {
    return this.#options.cardUrl ?? defaultCardUrl(this.#options.mcpUrl);
  }

  /** Reads the keys, refreshing a missed or expired cache entry; `now` is in seconds. */
  async keys(now: number): Promise<ServerCardKeys> {
    if (this.#cached !== null && now < this.#cached.until) return this.#cached.result;
    this.#cached = null;
    const cardUrl = this.cardUrl();
    if (cardUrl === null) return { ok: false, code: "not_https" };
    const { mcpUrl, transport, mcpServerKid = null, mcpServerPublicKey = null } = this.#options;
    const checked = checkCallbackUrl(cardUrl);
    if (!checked.ok) return { ok: false, code: "not_https" };
    if (!sameOrigin(cardUrl, mcpUrl)) return { ok: false, code: "cross_origin" };
    const start = this.#clock();
    const controller = new AbortController();
    const timeout = { ok: false, code: "timeout" } as const;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let answer: HardenedOutcome;
    try {
      const deadline = new Promise<HardenedOutcome>((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(timeout);
        }, CARD_TIMEOUT_MS);
      });
      answer = await Promise.race([deadline, transport.request(cardUrl, {
        method: "GET",
        path: checked.path + (checked.query === "" ? "" : `?${checked.query}`),
        headers: { accept: "application/mcp-server-card+json" },
        connectTimeoutMs: CARD_TIMEOUT_MS,
        responseTimeoutMs: CARD_TIMEOUT_MS,
        maxResponseBytes: MAX_CARD_BYTES,
        abortSignal: controller.signal,
      })]);
    } catch {
      return controller.signal.aborted ? timeout : { ok: false, code: "connection_refused" };
    } finally {
      clearTimeout(timer);
    }
    if (controller.signal.aborted) return timeout;
    if (!answer.ok) return answer;
    const elapsedMs = this.#clock() - start;
    if (elapsedMs > CARD_TIMEOUT_MS) return timeout;
    const { status, headers, body } = answer.response;
    const decision = fetchDecision({
      mcpUrl,
      cardUrl,
      elapsedMs,
      mcpServerKid,
      mcpServerPublicKey,
      response: {
        status,
        headers,
        bodyB64u: encodeBase64URL(body),
        tooLarge: answer.response.tooLarge === true,
        ...(status >= 300 && status < 400 ? { redirectTo: "" } : {}),
      },
    });
    if (!decision.ok) return { ok: false, code: decision.code };
    const { keys, cardKeys, egressIpRanges, rejectedKeys, cacheTtlSeconds } = decision;
    const result = { ok: true, keys, cardKeys, egressIpRanges, rejectedKeys } as const;
    this.#cached = { until: now + cacheTtlSeconds, result };
    return result;
  }
}
