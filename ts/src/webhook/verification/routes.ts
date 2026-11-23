import type { HardenedOutcome, HardenedRequest } from "../ssrf/client.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import { allowlistMatches } from "./allowlist.js";
import { checkReceiverDocFetch, docCacheTtl, receiverDocCovers, WELL_KNOWN_PATH, wellKnownUrl } from "./document.js";
import { acceptEcho, challengeEcho, NONCE_MAX_AGE_SECONDS, pairKey, randomNonce } from "./nonce.js";
import type { EchoAcceptance } from "./nonce.js";

/** The principal and canonical callback URL to verify. */
export interface VerifiedPair {
  readonly principal: string;
  readonly canonicalUrl: string;
}

type VerificationPair = VerifiedPair;

interface IssuedChallenge {
  readonly pair: readonly [principal: string, url: string];
  readonly nonce: string;
  readonly issuedAt: number;
  readonly consumed: boolean;
}

/** The routes that can verify a callback (R5.2). */
export type VerificationRoute = "cache" | "allowlist" | "out_of_band" | "well_known" | "challenge";

/** The first successful route or the reason verification failed (R5.2). */
export type RouteDecision =
  | { readonly verified: true; readonly route: VerificationRoute; readonly reason: null }
  | { readonly verified: false; readonly route: null; readonly reason: string };

/** Selects the first successful route in spec order (R5.2). */
export function verificationRoute(input: {
  readonly cache?: boolean;
  readonly allowlist?: { readonly matched: boolean } | null;
  readonly hook?: boolean | null;
  readonly doc?: { readonly doc: unknown; readonly path: string } | null;
  readonly challenge?: { readonly ok: boolean; readonly reason?: string } | null;
}): RouteDecision {
  const { cache, allowlist, hook, doc, challenge } = input;
  const hit = (route: VerificationRoute): RouteDecision => ({ verified: true, route, reason: null });
  if (cache === true) return hit("cache");
  if (allowlist?.matched === true) return hit("allowlist");
  if (hook === true) return hit("out_of_band");
  if (doc && receiverDocCovers(doc.doc, doc.path).covered) return hit("well_known");
  if (challenge?.ok === true) return hit("challenge");
  return { verified: false, route: null, reason: challenge?.reason ?? "no_route" };
}

/** In-memory verification results keyed by principal and canonical URL (R5.2, R5.12). */
export class VerificationCache {
  readonly #now: () => number;
  readonly #entries = new Map<string, number>();

  /** Uses a clock measured in seconds, defaulting to Unix time. */
  constructor(options?: { readonly now?: () => number }) {
    this.#now = options?.now ?? nowSeconds;
  }

  /** Records verification until the given absolute expiration time, in seconds. */
  set(pair: VerificationPair, expiresAt: number): void {
    const key = pairKey([pair.principal, pair.canonicalUrl]);
    if (key !== null) this.#entries.set(key, expiresAt);
  }

  /** Returns whether the pair has an unexpired verification. */
  has(pair: VerificationPair): boolean {
    const key = pairKey([pair.principal, pair.canonicalUrl]);
    if (key === null) return false;
    const expiresAt = this.#entries.get(key);
    if (expiresAt === undefined) return false;
    if (this.#now() < expiresAt) return true;
    this.#entries.delete(key);
    return false;
  }

  /** Removes a cached verification. */
  delete(pair: VerificationPair): void {
    const key = pairKey([pair.principal, pair.canonicalUrl]);
    if (key !== null) this.#entries.delete(key);
  }
}

/** In-memory challenge attempts, with one current nonce per principal and canonical URL (R5.3). */
export class ChallengeStore {
  readonly #now: () => number;
  readonly #ttlSeconds: number;
  readonly #entries = new Map<string, IssuedChallenge>();

  /** Uses a clock measured in seconds and defaults to the spec's nonce lifetime. */
  constructor(options?: { readonly now?: () => number; readonly ttlSeconds?: number }) {
    this.#now = options?.now ?? nowSeconds;
    this.#ttlSeconds = options?.ttlSeconds ?? NONCE_MAX_AGE_SECONDS;
  }

  /** Records a fresh nonce, replacing any previous attempt for this pair. */
  issue(pair: VerificationPair, nonce: string): void {
    const attempt = [pair.principal, pair.canonicalUrl] as const;
    const key = pairKey(attempt);
    if (key !== null) {
      this.#entries.set(key, { pair: attempt, nonce, issuedAt: this.#now(), consumed: false });
    }
  }

  /** Validates an echo and consumes its nonce only on success. */
  accept(input: { readonly pair: VerificationPair; readonly nonce: string }): EchoAcceptance {
    const pair = [input.pair.principal, input.pair.canonicalUrl] as const;
    const key = pairKey(pair);
    if (key === null) return acceptEcho({ nonce: input.nonce });
    const attempt = this.#entries.get(key);
    if (attempt === undefined) return acceptEcho({ nonce: input.nonce });
    const result = acceptEcho({
      nonce: input.nonce,
      expected: attempt.nonce,
      issuedAt: attempt.issuedAt,
      now: this.#now(),
      ttlSeconds: this.#ttlSeconds,
      consumed: attempt.consumed,
      pair,
      expectedPair: attempt.pair,
    });
    if (result.ok) this.#entries.set(key, { ...attempt, consumed: true });
    return result;
  }
}

function nowSeconds(): number {
  return Date.now() / 1000;
}

/** An invalid endpoint verifier dependency. */
export class VerificationConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationConfigurationError";
  }
}

/** The canonical URL and request path for a verification challenge. */
export interface ChallengeDestination {
  readonly url: string;
  readonly path: string;
}

/** The headers for a signed verification POST. */
export interface ChallengeRequest {
  readonly headers: Readonly<Record<string, string>>;
}

/** Signs a fresh verification envelope for the given pair and destination. */
export type ChallengeSigner = (input: {
  readonly pair: VerifiedPair;
  readonly nonce: string;
  readonly body: Uint8Array;
  readonly destination: ChallengeDestination;
}) => ChallengeRequest;

/** The receiver paths from a successful document fetch, or the failure code and reason. */
export type DocumentFetchOutcome =
  | { readonly ok: true; readonly receivers: readonly string[] }
  | { readonly ok: false; readonly code: string; readonly reason: string };

/** The hardened HTTPS path shared by well-known fetches and challenge POSTs. */
export interface VerificationTransport {
  request(url: string, request: HardenedRequest): Promise<HardenedOutcome>;
}

/** Caches accepted receiver paths per HTTPS origin (R5.9). */
export class DocumentCache {
  readonly #now: () => number;
  readonly #entries = new Map<string, { readonly receivers: readonly string[]; readonly expiresAt: number }>();

  /** Uses a clock measured in seconds, defaulting to Unix time. */
  constructor(options?: { readonly now?: () => number }) {
    this.#now = options?.now ?? nowSeconds;
  }

  /** Returns unexpired receiver paths and drops expired entries. */
  get(origin: string): readonly string[] | undefined {
    const entry = this.#entries.get(origin);
    if (entry === undefined) return undefined;
    if (this.#now() < entry.expiresAt) return entry.receivers;
    this.#entries.delete(origin);
    return undefined;
  }

  /** Stores receiver paths for the given TTL in seconds. */
  set(origin: string, receivers: readonly string[], ttlSeconds: number): void {
    this.#entries.set(origin, { receivers: [...receivers], expiresAt: this.#now() + ttlSeconds });
  }

  /** Removes the receiver document for this origin. */
  delete(origin: string): void {
    this.#entries.delete(origin);
  }
}

/** Operator policy, stores and hardened I/O for endpoint verification. */
export interface EndpointVerificationDeps {
  readonly transport: VerificationTransport;
  readonly allowlist?: readonly string[];
  readonly hook?: (pair: VerifiedPair) => boolean | null;
  readonly cache?: VerificationCache;
  readonly challenges?: ChallengeStore;
  readonly documents?: DocumentCache;
  readonly now?: () => number;
  readonly nonceSource?: () => string;
}

/** The first successful route, or a reason no route verified the endpoint. */
export interface EndpointVerification {
  readonly verified: boolean;
  readonly route: VerificationRoute | null;
  readonly reason: string | null;
}

/** Checks verification routes in R5.2 order and caches the first success. */
export class EndpointVerifier {
  readonly #deps: EndpointVerificationDeps;
  readonly #cache: VerificationCache;
  readonly #challenges: ChallengeStore;
  readonly #documents: DocumentCache;

  /** Validates dependencies and uses the supplied stores or creates in-memory defaults. */
  constructor(deps: EndpointVerificationDeps) {
    if (!isObject(deps)) throw new VerificationConfigurationError("deps must be an object");
    if (!hasMethods(deps.transport, "request")) {
      throw new VerificationConfigurationError("deps.transport must be an object with a request function");
    }
    if (deps.allowlist !== undefined && !isStringArray(deps.allowlist)) {
      throw new VerificationConfigurationError("deps.allowlist must be an array of strings");
    }
    for (const member of ["hook", "nonceSource", "now"] as const) {
      if (deps[member] !== undefined && typeof deps[member] !== "function") {
        throw new VerificationConfigurationError(`deps.${member} must be a function`);
      }
    }
    for (const [member, first, second] of [
      ["cache", "has", "set"], ["challenges", "issue", "accept"], ["documents", "get", "set"],
    ] as const) {
      if (deps[member] !== undefined && !hasMethods(deps[member], first, second)) {
        throw new VerificationConfigurationError(`deps.${member} must be an object with ${first} and ${second} functions`);
      }
    }
    this.#deps = deps;
    const clock = { now: deps.now ?? nowSeconds };
    this.#cache = deps.cache ?? new VerificationCache(clock);
    this.#challenges = deps.challenges ?? new ChallengeStore(clock);
    this.#documents = deps.documents ?? new DocumentCache(clock);
  }

  /** Verifies the pair until the supplied Unix expiration time in seconds. */
  async verify(
    pair: VerifiedPair,
    expiresAt: number,
    options?: { readonly challenge?: ChallengeSigner },
  ): Promise<EndpointVerification> {
    const hit = (route: VerificationRoute): EndpointVerification => {
      this.#cache.set(pair, expiresAt);
      return { verified: true, route, reason: null };
    };
    if (this.#cache.has(pair)) return hit("cache");
    if (allowlistMatches(this.#deps.allowlist ?? [], pair.canonicalUrl).matched) return hit("allowlist");
    try {
      if (this.#deps.hook?.(pair) === true) return hit("out_of_band");
    } catch {
      // An unavailable hook does not verify the pair.
    }
    if (await this.#wellKnown(pair.canonicalUrl)) return hit("well_known");
    if (options?.challenge === undefined) return { verified: false, route: null, reason: "no_route" };
    const reason = await this.#challenge(pair, options.challenge);
    return reason === null ? hit("challenge") : { verified: false, route: null, reason };
  }

  /** Fetches and caches the origin's well-known receiver document over hardened HTTPS (R5.9). */
  async fetchDocument(canonicalUrl: string): Promise<DocumentFetchOutcome> {
    const checked = checkCallbackUrl(canonicalUrl);
    if (!checked.ok) return { ok: false, code: checked.code, reason: checked.reason ?? checked.code };
    const url = wellKnownUrl(checked.canonical);
    if (url === null) return { ok: false, code: "invalid_callback_url", reason: "well_known_url" };
    const origin = url.slice(0, -WELL_KNOWN_PATH.length);
    const receivers = this.#documents.get(origin);
    if (receivers !== undefined) return { ok: true, receivers };
    try {
      const outcome = await this.#deps.transport.request(url, {
        method: "GET",
        path: WELL_KNOWN_PATH,
        headers: { accept: "application/json" },
      });
      if (!outcome.ok) return { ok: false, code: outcome.code, reason: outcome.reason ?? outcome.code };
      if (outcome.response.tooLarge === true) return { ok: false, code: "document_fetch_failed", reason: "too_large" };
      const { status, body, headers } = outcome.response;
      const verdict = checkReceiverDocFetch({ status, bodyText: Buffer.from(body).toString("utf8") });
      if (verdict.ok) this.#documents.set(origin, verdict.receivers, docCacheTtl(cacheMaxAge(headers)));
      return verdict;
    } catch {
      return { ok: false, code: "document_fetch_failed", reason: "document_fetch_failed" };
    }
  }

  async #wellKnown(canonicalUrl: string): Promise<boolean> {
    const doc = await this.fetchDocument(canonicalUrl);
    if (!doc.ok) return false;
    const checked = checkCallbackUrl(canonicalUrl);
    if (!checked.ok) return false;
    return receiverDocCovers(doc.receivers, checked.path).covered;
  }

  async #challenge(pair: VerifiedPair, signer: ChallengeSigner): Promise<string | null> {
    const checked = checkCallbackUrl(pair.canonicalUrl);
    if (!checked.ok) return checked.reason ?? checked.code;
    const destination = { url: checked.canonical, path: checked.path + (checked.query === "" ? "" : `?${checked.query}`) };
    let nonce: string;
    let body: Uint8Array;
    let headers: Readonly<Record<string, string>>;
    try {
      nonce = this.#deps.nonceSource?.() ?? randomNonce();
      body = Buffer.from(JSON.stringify({ type: "verification", challenge: nonce }), "utf8");
      const signingPair = { principal: pair.principal, canonicalUrl: pair.canonicalUrl };
      const signed: unknown = signer({ pair: signingPair, nonce, body, destination: { ...destination } });
      if (!isObject(signed)) return "challenge_failed";
      const candidate = signed.headers;
      if (!isObject(candidate)) return "challenge_failed";
      const entries: [string, unknown][] = Object.entries(candidate);
      if (!entries.every((entry): entry is [string, string] => typeof entry[1] === "string")) {
        return "challenge_failed";
      }
      headers = Object.fromEntries(entries);
      this.#challenges.issue(pair, nonce);
    } catch {
      return "challenge_failed";
    }
    let answer: HardenedOutcome;
    try {
      answer = await this.#deps.transport.request(destination.url, { method: "POST", path: destination.path, headers, body });
    } catch {
      return "connection_refused";
    }
    if (!answer.ok) {
      return answer.code === "timeout" || answer.code === "tls_error" ? answer.code : "connection_refused";
    }
    if (answer.response.tooLarge === true) return "too_large";
    const { status, body: responseBody } = answer.response;
    const echo = challengeEcho({ status, bodyText: Buffer.from(responseBody).toString("utf8"), nonce });
    if (!echo.ok) return echo.reason;
    try {
      const consumed = this.#challenges.accept({ pair, nonce });
      return consumed.ok ? null : consumed.reason;
    } catch {
      return "challenge_failed";
    }
  }
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}

function hasMethods(value: unknown, ...methods: readonly string[]): boolean {
  return isObject(value) && methods.every((method) => typeof value[method] === "function");
}

function isStringArray(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  const entries: readonly unknown[] = value;
  for (let i = 0; i < entries.length; i += 1) {
    if (typeof entries[i] !== "string") return false;
  }
  return true;
}

function cacheMaxAge(headers: Readonly<Record<string, string>>): number | undefined {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === "cache-control")?.[1];
  if (value === undefined) return undefined;
  for (const [directive] of value.matchAll(/(?:[^,"]|"(?:[^"\\]|\\.)*")+/g)) {
    const match = /^max-age\s*=\s*(?:([0-9]+)|"([0-9]+)")$/i.exec(directive.trim());
    if (match !== null) return Number(match[1] ?? match[2]);
  }
  return undefined;
}
