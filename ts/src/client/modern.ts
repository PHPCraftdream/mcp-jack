/**
 * Modern-profile client layer of spec 04 section 6 (MCP 2026-07-28) on top of
 * the existing signed `Client` transport: C1/C2 request `_meta` and mirror
 * headers, C5/C11 catalog filtering of every `tools/list` and `events/list`
 * read, C6/C11 `x-mcp-header` projection, the C8 private result cache, C9
 * era detection and fallback, and the C10/C12 one-shot catalog resync.
 *
 * Nothing here signs, verifies or re-encodes a body: `Client.signedRequest`
 * owns the wire bytes and the response verification, and this layer only adds
 * the `_meta` member, the header list and the reading of a verified answer.
 *
 * C9 is a state machine, not a single request. An `"auto"` client first sends
 * a deterministic `server/discover` probe and decides from the VERIFIED reply
 * alone (spec 04 C9): a modern verdict is adopted, a `-32022` with a mutually
 * implemented version re-probes once with that version, a legacy verdict runs
 * the legacy `initialize` -> `notifications/initialized` handshake, and an
 * unusable verdict fails the operation with `EraNegotiationError` instead of
 * guessing. The probe is never the user's operation: a misread era is only
 * discovered from the operation's own verified refusal, which re-probes once
 * through `resetEra()`. The legacy handshake lives here and only here;
 * `Client.callWith` stays the byte-frozen 0.1.x call and never initializes.
 */

import { JackError } from "../core/errors.js";
import { HTTPError, RPCError } from "./errors.js";
import type { Client, JsonValue, SignedReply } from "./rpc.js";
import { replyHeaders } from "./rpc.js";
import { UnauthenticatedResponseError } from "./transport/transport.js";
import { MODERN_ERA_ERROR_CODES, detectEra } from "../modern/era.js";
import type { ClientEra, EraDetection, EraProbe } from "../modern/era.js";
import { buildRequestMirrors } from "../modern/request.js";
import type { ClientInfo } from "../modern/request.js";
import { PROJECTION_REASON, filterEventTypes, filterToolDefinitions, projectArguments } from "../modern/annotations.js";
import type { AnnotationReason } from "../modern/annotations.js";
import { MODERN_MIN, nameSourceOf } from "../modern/values.js";
import type { HeaderPair } from "../modern/values.js";

// ---------------------------------------------------------------------------
// Identity, versions and errors
// ---------------------------------------------------------------------------

/** Client identity advertised in `_meta` (C1): Jack's implementation name and version, as the server reports it in C7. */
export const JACK_CLIENT_INFO: ClientInfo = { name: "mcp-jack", version: "0.1.0" };

/** Protocol versions this client implements, modern first: the modern minimum and the 2025-11-25 legacy fallback a `-32022` retry may pick from. */
export const CLIENT_PROTOCOL_VERSIONS: readonly string[] = [MODERN_MIN, "2025-11-25"];

/** The newest legacy-era protocol version: the head of `LEGACY_PROTOCOL_VERSIONS` and the one `initialize` advertises. */
const NEWEST_LEGACY_VERSION = "2025-11-25";

/** The legacy-era protocol versions this client implements; the first entry is the newest and the one `initialize` advertises (spec 04 section 6). */
export const LEGACY_PROTOCOL_VERSIONS: readonly string[] = [NEWEST_LEGACY_VERSION];

/**
 * The client-side refusal of C6 and C11: an argument value does not match its
 * annotated type, so the request is not sent at all. Nothing was signed.
 */
export class HeaderProjectionError extends Error {
  /** The single C6/C11 reason token, `header_projection_invalid_value`. */
  readonly code: typeof PROJECTION_REASON = PROJECTION_REASON;

  constructor(message: string = "modern profile: " + PROJECTION_REASON) {
    super(message);
    this.name = "HeaderProjectionError";
  }
}

/**
 * The C9 negotiation gave no usable verdict; the operation fails. It is never
 * a silent downgrade: an unverified probe (`reason: "unverified"`), a network
 * failure (`reason: "no_era_signal"`) and a version list with no common
 * version (`reason: "unsupported_version_no_overlap"`) all end here, with the
 * detection that caused it.
 */
export class EraNegotiationError extends Error {
  /** The detection that carried no usable era, as `detectEra` returned it. */
  readonly detection: EraDetection;

  /** Wraps one unusable detection; `detection.reason` is the C9 vocabulary token. */
  constructor(detection: EraDetection) {
    super("modern profile: era negotiation failed (" + String(detection.reason) + ")");
    this.name = "EraNegotiationError";
    this.detection = detection;
  }
}

// ---------------------------------------------------------------------------
// C8: the private result cache
// ---------------------------------------------------------------------------

/**
 * The C8 cache key of one request within one era: era, method, the negotiated
 * version (when one is present) and the exact params text, NUL-separated. A
 * response is bound to exactly one signed request, so any change of method,
 * params, era or version is a different key.
 *
 * `paramsText` is the exact params text placed on the wire, after `_meta`
 * insertion for a modern request: that is the text the signature covers, so
 * it is the only text that identifies the request C8 requires.
 *
 * `version` is the negotiated version and defaults to "": a caller that has
 * none yet keys the version-agnostic entry of its era, method and params in
 * exactly the older three-part byte form (`era`, `method`, `paramsText`,
 * NUL-separated), so an entry written by the first release of this function
 * is still found. A negotiated version adds its own segment (`era`, `method`,
 * `version`, `paramsText`, NUL-separated): a version is a non-empty date
 * string and the params text is JSON, so the three-part and four-part shapes
 * cannot collide.
 */
export function resultCacheKey(method: string, paramsText: string, era: "legacy" | "modern", version = ""): string {
  return era + "\u0000" + method + "\u0000" + (version === "" ? paramsText : version + "\u0000" + paramsText);
}

/** One cached verified result and the instant it stops being usable (exclusive). */
interface CacheEntry {
  /** The C6-structured value the request answered with. */
  readonly value: JsonValue;
  /** `now()` must be below this for the entry to be served. */
  readonly expiresAt: number;
}

/**
 * The private C8 cache of verified results: an in-memory map owned by one
 * client. It is never shared between clients and has no API that could serve
 * a shared cache or an HTTP cache, whatever `cacheScope` the answering server
 * hinted: a Jack response is signed over the answering request's signature, so
 * serving it to any other request would present a response bound to another
 * signature.
 *
 * Every value is copied with `structuredClone` on the way in and on the way
 * out, so a caller that mutates a served value cannot change what a later
 * lookup returns and cannot corrupt the stored entry. Cached values are JSON
 * values only (they come from a verified JSON body), so the clone is exact.
 */
export class PrivateResultCache {
  readonly #now: () => number;
  readonly #entries = new Map<string, CacheEntry>();

  constructor(now: () => number = () => Date.now()) {
    this.#now = now;
  }

  /** Stores a defensive copy of one result for `ttlMs`; a lifetime that is not a finite positive number stores nothing, so `ttlMs: 0` is never reused. */
  put(key: string, value: JsonValue, ttlMs: number): void {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) return;
    this.#entries.set(key, { value: structuredClone(value), expiresAt: this.#now() + ttlMs });
  }

  /** Returns a defensive copy of a result while it is unexpired, dropping it from the private map once `now()` reaches its deadline. */
  get(key: string): JsonValue | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    if (this.#now() < entry.expiresAt) return structuredClone(entry.value);
    this.#entries.delete(key);
    return undefined;
  }

  /** Drops one entry, so a C10/C12 resync can re-read a catalog under the very key its stale answer was stored under. */
  delete(key: string): void {
    this.#entries.delete(key);
  }

  /** Drops every cached result; the map is private to this client and is never shared. */
  clear(): void {
    this.#entries.clear();
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** How a `ModernClient` behaves: the era it speaks, the version it advertises, its identity and its C8/C11 behaviour. */
export interface ModernClientOptions {
  /** Era to speak; defaults to `client.era`. `"auto"` probes once with `server/discover` and caches the outcome. */
  readonly era?: ClientEra;
  /** Protocol version written to `_meta` and `MCP-Protocol-Version`; defaults to `MODERN_MIN`. */
  readonly version?: string;
  /** Client identity added to `_meta`; defaults to `JACK_CLIENT_INFO`. */
  readonly clientInfo?: ClientInfo;
  /** Client capabilities added to `_meta`; defaults to `{}`. C1 requires a JSON object, so a non-object value makes every request throw. */
  readonly clientCapabilities?: JsonValue;
  /** Whether `call` uses the private C8 cache; off by default. */
  readonly cacheResults?: boolean;
  /** C5/C11 logging of an excluded tool or event type and the reason it was dropped. */
  readonly onExcluded?: (name: string, reason: AnnotationReason) => void;
}

// ---------------------------------------------------------------------------
// ModernClient
// ---------------------------------------------------------------------------

/** The `server/discover` probe method of C9. */
const DISCOVER_METHOD = "server/discover";

/** The four `events/*` methods whose arguments are projected from the `events/list` catalog (C11). */
const EVENTS_METHODS: ReadonlySet<string> = new Set([
  "events/poll",
  "events/stream",
  "events/subscribe",
  "events/unsubscribe",
]);

/**
 * The modern-profile client layer: era negotiation, `_meta` and mirror
 * headers, `x-mcp-header` projection and the private cache, over an existing
 * signed `Client`. It never sends a request the `Client` does not sign and
 * verify.
 *
 * The era is a per-client state machine (C9). The configured era is `"auto"`
 * unless the client pins `"legacy"` or `"modern"`. For `"auto"` the first
 * operation sends a `server/discover` probe whose VERIFIED reply decides:
 *
 * - a modern verdict (2xx, or a `400`/`404` carrying a recognised modern
 *   JSON-RPC error) adopts the modern era;
 * - a `-32022` re-probes ONCE with the first version this client implements
 *   that is not the one just attempted; a chosen modern version is probed,
 *   while a chosen legacy version is served by the legacy handshake at that
 *   version, because a legacy endpoint has no modern probe to answer;
 * - a legacy verdict (`400` with a non-modern body, `404` without `-32601`,
 *   `405`) adopts the legacy era and runs the `initialize` ->
 *   `notifications/initialized` handshake at the newest legacy version.
 *   `initialize` carries no `MCP-Protocol-Version` header (the header starts
 *   after negotiation); every request after it carries the negotiated version
 *   and, once assigned, `Mcp-Session-Id`;
 * - no verdict at all (unverified, no signal, or no mutually implemented
 *   version) throws `EraNegotiationError`; the operation is never guessed.
 *
 * A probe that later proves wrong is corrected once: `resetEra()` drops the
 * cached verdict and the legacy session, and an operation whose own verified
 * reply contradicts the chosen era re-probes and retries exactly once.
 *
 * The legacy handshake is performed by this modern client layer and only here:
 * `Client.callWith` stays the byte-frozen 0.1.x call and never initializes.
 */
export class ModernClient {
  readonly #client: Client;
  readonly #clientInfo: ClientInfo;
  readonly #clientCapabilities: JsonValue;
  readonly #cacheResults: boolean;
  readonly #onExcluded: ((name: string, reason: AnnotationReason) => void) | undefined;
  readonly #cache = new PrivateResultCache();
  /** The era this client was configured with: the state `resetEra()` returns to. */
  readonly #configuredEra: ClientEra;
  /** The version this client was configured with: the state `resetEra()` returns to. */
  readonly #baseVersion: string;
  #era: ClientEra;
  #version: string;
  #detection: EraDetection | undefined;
  /** The legacy `Mcp-Session-Id` the handshake assigned, while the server keeps the session. */
  #sessionId: string | undefined;
  /** True once this client ran the legacy handshake for the current era/version/session. */
  #legacyReady = false;
  #tools: JsonValue[] | undefined;
  #events: JsonValue[] | undefined;

  /** Wraps a client; every option falls back to the client's own era and to the modern defaults. */
  constructor(client: Client, options: ModernClientOptions = {}) {
    this.#client = client;
    this.#configuredEra = options.era ?? client.era;
    this.#baseVersion = options.version ?? MODERN_MIN;
    this.#era = this.#configuredEra;
    this.#version = this.#baseVersion;
    this.#clientInfo = options.clientInfo ?? JACK_CLIENT_INFO;
    this.#clientCapabilities = options.clientCapabilities ?? {};
    this.#cacheResults = options.cacheResults ?? false;
    this.#onExcluded = options.onExcluded;
  }

  /** The era this client currently speaks: the configured one until `"auto"` detection adopts the detected era. */
  get era(): ClientEra {
    return this.#era;
  }

  /**
   * C9: one negotiation round. The probe is a deterministic `server/discover`
   * request at the current version; the era is decided from the VERIFIED reply
   * alone (an unsigned, unparsable or network-failed probe is never a signal).
   *
   * The verdict is carried out here and returned as the FINAL detection: a
   * modern verdict adopts the modern era (after one re-probe with a mutually
   * implemented version when the server sent `-32022`), a legacy verdict runs
   * the `initialize` -> `notifications/initialized` handshake, keeps the
   * version it negotiates and the session id it is assigned (both then carried
   * by every later legacy request) and adopts the legacy era, and an unusable
   * verdict - no overlap, unverified, no signal - is returned unchanged so the
   * caller throws `EraNegotiationError`. The probe is never the user's
   * operation, and `resetEra()` is the way back to a fresh negotiation.
   */
  async detectEra(): Promise<EraDetection> {
    const first = await this.#probe();
    const detection = await this.#carryOut(first, true);
    this.#detection = detection;
    return detection;
  }

  /**
   * Drops the cached verdict and the legacy session state, so the next
   * operation re-probes: an `"auto"` client is back to its configured era and
   * version, with no session, no handshake credit and no cached results. The
   * era/version reset also invalidates the C8 cache, because an entry signed
   * under another era or version answers a different request, and it drops the
   * memoised `tools/list` and `events/list` catalogs, which were read under the
   * wire shape of the era and version this reset moves away from.
   */
  resetEra(): void {
    this.#detection = undefined;
    this.#era = this.#configuredEra;
    this.#version = this.#baseVersion;
    this.#legacyReady = false;
    this.#sessionId = undefined;
    this.#cache.clear();
    this.#tools = undefined;
    this.#events = undefined;
  }

  /**
   * C1/C2/C5/C6/C8/C11: one request in the resolved era, returning the
   * `structuredContent` of the answer (or the result itself). A `tools/list`
   * or `events/list` result is filtered exactly as `listTools`/`listEvents`
   * filter it. A cached verified result is served only for the exact same
   * request (method, wire params, era and negotiated version), and only while
   * its `ttlMs` allows reuse.
   */
  async call(method: string, params?: JsonValue): Promise<JsonValue> {
    return (await this.#request(method, params, { resync: true })).result;
  }

  /**
   * The `tools/list` catalog with every C5-invalid definition excluded, fetched
   * once and cached until a resync drops it. The era is resolved FIRST, before
   * the memoised catalog is read: an `"auto"` client whose era was reset or
   * renegotiated has to negotiate again - and may fail with
   * `EraNegotiationError` - instead of handing back the catalog of the era it
   * no longer speaks.
   */
  async listTools(): Promise<JsonValue[]> {
    await this.#eraOf();
    const cached = this.#tools;
    if (cached !== undefined) return cached;
    const result = await this.call("tools/list");
    const record = isJsonObject(result) ? result : undefined;
    const tools = record !== undefined ? record["tools"] : undefined;
    if (!Array.isArray(tools)) throw new Error("modern profile: tools/list result has no tools array");
    this.#tools = tools;
    return tools;
  }

  /**
   * The `events/list` catalog with every C11-invalid event type excluded, fetched
   * once and cached until a resync drops it. The era is resolved FIRST, before
   * the memoised catalog is read: an `"auto"` client whose era was reset or
   * renegotiated has to negotiate again - and may fail with
   * `EraNegotiationError` - instead of handing back the catalog of the era it
   * no longer speaks.
   */
  async listEvents(): Promise<JsonValue[]> {
    await this.#eraOf();
    const cached = this.#events;
    if (cached !== undefined) return cached;
    const result = await this.call("events/list");
    const record = isJsonObject(result) ? result : undefined;
    const events = record !== undefined ? record["events"] : undefined;
    if (!Array.isArray(events)) throw new Error("modern profile: events/list result has no events array");
    this.#events = events;
    return events;
  }

  // -- era ----------------------------------------------------------------

  /**
   * The era to speak now. A pinned client answers with its own era; an
   * `"auto"` client uses the cached verdict when there is one and negotiates
   * otherwise. A verdict that carries no usable era (unverified, no signal, or
   * no mutually implemented version) throws `EraNegotiationError`: the
   * operation fails instead of picking an era on a guess.
   */
  async #eraOf(): Promise<"legacy" | "modern"> {
    if (this.#era !== "auto") return this.#era;
    let detection = this.#detection;
    if (detection === undefined) detection = await this.detectEra();
    return eraVerdict(detection);
  }

  /**
   * C9: carries out one detection and returns the FINAL verdict. The probe is
   * never adopted on a guess:
   *
   * - `none` and `modern`/`abort` adopt nothing and are returned as they are,
   *   for the caller to refuse;
   * - `modern`/`retry_with_supported` scans the WHOLE supported list for the
   *   first version this client implements that is not the one just attempted;
   *   with no such overlap, or with the ONE-retry budget already spent, it
   *   returns `modern`/`abort` with `unsupported_version_no_overlap` and adopts
   *   no version: neither `#version` nor the cache is touched;
   * - a chosen MODERN version is adopted, the C8 cache is dropped (an entry
   *   signed under another version answers another request), probed ONCE and
   *   carried out with no further retry allowed; a retry whose verdict is
   *   `none` or `modern`/`abort` restores the version CONFIRMED before the
   *   candidate and drops the cache again, so a later `detectEra()` never
   *   starts from a version no verified answer confirmed;
   * - a chosen LEGACY version runs the legacy handshake at that version and
   *   adopts the legacy era: a legacy endpoint has no modern probe to answer;
   * - any other `modern` verdict adopts the modern era;
   * - a `legacy` verdict runs the `initialize` -> `notifications/initialized`
   *   handshake and adopts the legacy era.
   */
  async #carryOut(detection: EraDetection, allowRetry: boolean): Promise<EraDetection> {
    if (detection.era === "none") return detection;
    if (detection.era === "modern") {
      if (detection.action === "abort") return detection;
      if (detection.action === "retry_with_supported") {
        const chosen = detection.supported?.find(
          (version) => CLIENT_PROTOCOL_VERSIONS.includes(version) && version !== this.#version,
        );
        // No overlap, or the one allowed re-probe already happened: an
        // unconfirmed verdict must not adopt a version.
        if (chosen === undefined || !allowRetry) return noVersionOverlap(detection.supported);
        if (chosen >= MODERN_MIN) {
          // The confirmed version survives a retry that proves nothing: only a
          // usable second verdict may leave the candidate in place.
          const confirmed = this.#version;
          this.#version = chosen;
          this.#cache.clear();
          const again = await this.#probe(chosen);
          const verdict = await this.#carryOut(again, false);
          if (verdict.era === "none" || (verdict.era === "modern" && verdict.action === "abort")) {
            this.#version = confirmed;
            // The cache was dropped for the candidate; the restored version
            // must not reuse an entry keyed under the candidate either.
            this.#cache.clear();
          }
          return verdict;
        }
        await this.#handshake(chosen);
        this.#era = "legacy";
        return { era: "legacy", action: "fallback_initialize", reason: detection.reason };
      }
      this.#era = "modern";
      return detection;
    }
    await this.#handshake();
    this.#era = "legacy";
    return detection;
  }

  /**
   * C9: the deterministic `server/discover` probe at `version` (the current
   * one by default), sent with the C2 mirror headers of that version. Only a
   * VERIFIED reply is a signal: an unverified reply (an unsigned or bad
   * signature) is `unverified`, and any other error - a network failure, a
   * timeout - is no signal at all.
   */
  async #probe(version: string = this.#version): Promise<EraDetection> {
    const mirrors = buildRequestMirrors({
      version,
      method: DISCOVER_METHOD,
      params: {},
      clientInfo: this.#clientInfo,
      clientCapabilities: this.#clientCapabilities,
    });
    const paramsText = jsonText({ _meta: mirrors.meta });
    let probe: EraProbe;
    try {
      const reply = await this.#client.signedRequest(DISCOVER_METHOD, paramsText, mirrors.headers);
      probe = { verified: true, status: reply.status, ...(reply.bodyText !== "" ? { bodyText: reply.bodyText } : {}) };
    } catch (err) {
      // A verification failure still says "unverified"; a network failure says nothing at all.
      if (!(err instanceof JackError) && !(err instanceof UnauthenticatedResponseError)) {
        return { era: "none", action: "abort", reason: "no_era_signal" };
      }
      probe = { verified: false, status: 0 };
    }
    return detectEra(probe, CLIENT_PROTOCOL_VERSIONS);
  }

  // -- legacy handshake ---------------------------------------------------

  /**
   * C9 legacy fallback: the `initialize` -> `notifications/initialized`
   * handshake of a legacy session, at `legacyVersion` (the newest legacy
   * version by default). `initialize` carries NO `MCP-Protocol-Version` header
   * and advertises `params.protocolVersion` as that legacy version: the
   * version header starts only after negotiation, so a `both`-profile server
   * serves the request as legacy instead of reading a modern version from it.
   *
   * The negotiated version must be one of `LEGACY_PROTOCOL_VERSIONS`; it is
   * kept (and invalidates the C8 cache when it moves), `Mcp-Session-Id` is
   * recorded from the verified reply when the server assigns one, and every
   * later legacy request carries both headers. The version, the session id and
   * `#legacyReady` are committed together only after
   * `notifications/initialized` was accepted; a failure commits nothing and
   * clears the handshake credit, so the next call handshakes again instead of
   * running a legacy request that no handshake backs.
   *
   * This handshake is performed by this modern client layer and only here; a
   * `Client.callWith` stays the byte-frozen 0.1.x call and never initializes.
   * A reply that is not a usable `initialize` result is an error, never a
   * guessed version or session.
   */
  async #handshake(legacyVersion: string = NEWEST_LEGACY_VERSION): Promise<void> {
    let committed = false;
    try {
      const paramsText = jsonText({
        protocolVersion: legacyVersion,
        capabilities: {},
        clientInfo: { name: this.#clientInfo.name, version: this.#clientInfo.version },
      });
      // No MCP-Protocol-Version header: the header starts after negotiation.
      const reply = await this.#client.signedRequest("initialize", paramsText);
      if (reply.status < 200 || reply.status > 299) {
        throw new Error("modern profile: initialize answered HTTP " + String(reply.status));
      }
      const json = isJsonObject(reply.json) ? reply.json : undefined;
      if (json === undefined) throw new Error("modern profile: initialize reply has no protocolVersion");
      const error = json["error"];
      if (error !== undefined && error !== null) throw rpcErrorOf(error);
      const result = isJsonObject(json["result"]) ? json["result"] : undefined;
      const negotiated = result !== undefined ? result["protocolVersion"] : undefined;
      if (typeof negotiated !== "string" || negotiated === "") {
        throw new Error("modern profile: initialize reply has no protocolVersion");
      }
      if (!LEGACY_PROTOCOL_VERSIONS.includes(negotiated)) {
        throw new Error(
          "modern profile: initialize negotiated protocol version " +
            JSON.stringify(negotiated) +
            ", which is not a legacy version this client implements",
        );
      }
      // Fetch lowercases header names; an empty id is no session at all.
      let sessionId: string | undefined;
      for (const [name, value] of replyHeaders(reply)) {
        if (name.toLowerCase() === "mcp-session-id" && value !== "") sessionId = value;
      }
      // The notification carries the negotiated version and the assigned
      // session, which are not committed until it has been accepted.
      const initialized = await this.#client.signedNotify(
        "notifications/initialized",
        "{}",
        this.#legacyHeaders({ version: negotiated, sessionId }),
      );
      if (initialized.status < 200 || initialized.status > 299) {
        throw new Error("modern profile: notifications/initialized answered HTTP " + String(initialized.status));
      }
      if (negotiated !== this.#version) {
        this.#version = negotiated;
        this.#cache.clear();
      }
      this.#sessionId = sessionId;
      this.#legacyReady = true;
      committed = true;
    } finally {
      if (!committed) {
        this.#sessionId = undefined;
        this.#legacyReady = false;
      }
    }
  }

  /**
   * The legacy-era request headers: the negotiated `MCP-Protocol-Version` and,
   * while the server keeps the session, `Mcp-Session-Id`. Without `state` the
   * committed state is read; the handshake supplies its own not-yet-committed
   * negotiation for `notifications/initialized`, whose explicit `sessionId`
   * distinguishes "no session assigned" from the committed one. Neither header
   * is signed (spec 01 signs method, target, aud, kid, timestamp, nonce and the
   * exact body), so the signing string of a legacy request is unchanged by them
   * and a mismatch can be validated but never trusted.
   */
  #legacyHeaders(
    state?: { readonly version: string; readonly sessionId: string | undefined },
  ): readonly (readonly [string, string])[] {
    const version = state !== undefined ? state.version : this.#version;
    const sessionId = state !== undefined ? state.sessionId : this.#sessionId;
    const headers: (readonly [string, string])[] = [["MCP-Protocol-Version", version]];
    if (sessionId !== undefined) headers.push(["Mcp-Session-Id", sessionId]);
    return headers;
  }

  // -- requests -----------------------------------------------------------

  /**
   * One request in the resolved era, going through the C8 cache on the way.
   *
   * An `"auto"` client that chose the wrong era learns it from the OPERATION's
   * own verified refusal, never from the probe being retried as a guess: a
   * legacy attempt refused with a modern-era error, or a modern attempt
   * answered with a legacy signal, drops the cached verdict (`resetEra()`),
   * re-negotiates and retries the whole attempt EXACTLY ONCE. A second misread
   * is returned to the caller, so no operation is ever sent more than twice.
   */
  async #request(
    method: string,
    params: JsonValue | undefined,
    options: { readonly resync: boolean },
  ): Promise<RequestOutcome> {
    const era = await this.#eraOf();
    const first = await this.#attempt(method, params, options, era);
    // Only the era the user configured as "auto" may re-probe, and only once.
    if (!first.misread || this.#configuredEra !== "auto") return settleAttempt(first);
    this.resetEra();
    const again = await this.#eraOf();
    return settleAttempt(await this.#attempt(method, params, options, again));
  }

  /**
   * One attempt in one era, with the C8 cache in front of the send.
   *
   * In the legacy era the handshake runs first when it has not run yet, every
   * request carries `#legacyHeaders()`, and a `404` while this client still
   * knows its session id means the session expired: the handshake runs ONCE
   * more and the operation is re-sent ONCE - except `tools/call`, which keeps
   * the `404` so `interpretReply` surfaces it. A call is never blindly
   * replayed after a session `404` (docs/design/mcp-compatibility.md, row
   * `Session`), because the first attempt may already have run.
   *
   * `resync` allows the single C10/C12 retry after a `-32020` refusal: the
   * catalog is dropped, together with the cached `tools/list`/`events/list`
   * result it was read from, and re-read, so the retry projects the current
   * `inputSchema`. A second refusal is thrown, never retried again. The wire
   * params and the version do not change across that retry, so the cache key
   * computed before the first send stays valid for the stored answer.
   *
   * A reply that proves this client misread the era is returned as a misread
   * attempt instead of being interpreted, so `#request` can re-probe once
   * before the caller ever sees the refusal.
   */
  async #attempt(
    method: string,
    params: JsonValue | undefined,
    options: { readonly resync: boolean },
    era: "legacy" | "modern",
  ): Promise<EraAttempt> {
    if (era === "legacy") {
      if (!this.#legacyReady) await this.#handshake();
      const paramsText = paramText(params);
      const key = resultCacheKey(method, paramsText, "legacy", this.#version);
      const cached = this.#cached(key);
      if (cached !== undefined) return { outcome: cached, misread: false };
      let reply = await this.#client.signedRequest(method, paramsText, this.#legacyHeaders());
      if (reply.status === 404 && this.#sessionId !== undefined) {
        await this.#handshake();
        if (method !== "tools/call") reply = await this.#client.signedRequest(method, paramsText, this.#legacyHeaders());
      }
      if (isModernEraRefusal(reply)) return misreadAttempt(reply);
      const outcome = this.#interpreted(method, reply);
      this.#store(key, outcome);
      return { outcome, misread: false };
    }
    // The key is built from the text actually signed, `_meta` included.
    const built = await this.#buildModern(method, params);
    const paramsText = jsonText(built.wireParams);
    const key = resultCacheKey(method, paramsText, "modern", this.#version);
    const cached = this.#cached(key);
    if (cached !== undefined) return { outcome: cached, misread: false };
    let reply = await this.#client.signedRequest(method, paramsText, built.headers);
    if (options.resync && isResyncTarget(method) && isVersionRefusal(reply)) {
      // Rebuild so the retry projects the refreshed catalog. The wire params
      // text is unchanged (same params, same `_meta`), so the key still holds.
      await this.#resyncCatalogs(method, era);
      reply = await this.#sendModern(method, params);
    }
    if (isLegacySignal(reply)) return misreadAttempt(reply);
    const outcome = this.#interpreted(method, reply);
    this.#store(key, outcome);
    return { outcome, misread: false };
  }

  /** One modern-era request: the C1/C2/C6 wire params and header list, then the exact same text on the wire. */
  async #sendModern(method: string, params: JsonValue | undefined): Promise<SignedReply> {
    const { wireParams, headers } = await this.#buildModern(method, params);
    return this.#client.signedRequest(method, jsonText(wireParams), headers);
  }

  /**
   * The wire half of one modern-era request: `_meta` inserted last into the
   * params, the C2 mirror headers at the current `#version`, then the C6/C11
   * projected headers appended.
   */
  async #buildModern(
    method: string,
    params: JsonValue | undefined,
  ): Promise<{ wireParams: { [key: string]: JsonValue }; headers: readonly HeaderPair[] }> {
    const mirrors = buildRequestMirrors({
      version: this.#version,
      method,
      ...(params !== undefined ? { params } : {}),
      clientInfo: this.#clientInfo,
      clientCapabilities: this.#clientCapabilities,
    });
    const wireParams: { [key: string]: JsonValue } = {
      ...(isJsonObject(params) ? params : {}),
      _meta: mirrors.meta,
    };
    const projected = await this.#project(method, wireParams);
    const headers: readonly HeaderPair[] = [...mirrors.headers, ...projected];
    return { wireParams, headers };
  }

  /**
   * C8: a cached verified result for `key`, or undefined when caching is off
   * or nothing unexpired is stored. The returned outcome carries `ttlMs: 0`
   * because a served entry is never stored again.
   */
  #cached(key: string): RequestOutcome | undefined {
    if (!this.#cacheResults) return undefined;
    const result = this.#cache.get(key);
    return result === undefined ? undefined : { result, ttlMs: 0 };
  }

  /** C8: stores one verified result under `key` for the lifetime its own `ttlMs` allows; a no-op when caching is off. */
  #store(key: string, outcome: RequestOutcome): void {
    if (!this.#cacheResults) return;
    this.#cache.put(key, outcome.result, outcome.ttlMs);
  }

  /**
   * C10/C12: drops both memoised catalogs and the cached `tools/list` result -
   * plus the cached `events/list` result when `method` projects from it - so the
   * single retry re-reads the catalog from the wire. Clearing the in-memory
   * catalogs alone is not enough: `listTools()` re-reads through `call`, and the
   * C8 cache would answer with the entry stored before the catalog moved, so
   * the retry would project the very stale `inputSchema` the resync exists to
   * drop. `era` is the era the attempt is in, so each key is built exactly as
   * `#attempt` builds the key of that same request; no other entry is touched.
   */
  async #resyncCatalogs(method: string, era: "legacy" | "modern"): Promise<void> {
    this.#tools = undefined;
    this.#events = undefined;
    this.#cache.delete(await this.#catalogCacheKey("tools/list", era));
    if (EVENTS_METHODS.has(method)) this.#cache.delete(await this.#catalogCacheKey("events/list", era));
  }

  /** The C8 key a catalog read stores under in `era` at the current version: the key `#attempt` builds for that very request. */
  async #catalogCacheKey(catalog: "tools/list" | "events/list", era: "legacy" | "modern"): Promise<string> {
    if (era === "legacy") return resultCacheKey(catalog, paramText(undefined), "legacy", this.#version);
    // `tools/list` has no `Mcp-Name` source, so building its wire params reads no catalog and cannot recurse.
    const paramsText = jsonText((await this.#buildModern(catalog, undefined)).wireParams);
    return resultCacheKey(catalog, paramsText, "modern", this.#version);
  }

  /** Reads one verified answer and applies the C5/C11 catalog filter to its result before it is cached or returned. */
  #interpreted(method: string, reply: SignedReply): RequestOutcome {
    const outcome = interpretReply(reply);
    const result = this.#filterCatalog(method, outcome.result);
    return result === outcome.result ? outcome : { result, ttlMs: outcome.ttlMs };
  }

  /**
   * C5/C11: the catalog filter every `tools/list` and `events/list` result
   * goes through, whichever entry point read it. A non-object result, or one
   * whose member is missing or not an array, is left untouched; the excluded
   * definitions are reported through `#onExcluded` when configured.
   */
  #filterCatalog(method: string, value: JsonValue): JsonValue {
    if (method !== "tools/list" && method !== "events/list") return value;
    if (!isJsonObject(value)) return value;
    const member = method === "tools/list" ? "tools" : "events";
    const entries = value[member];
    if (!Array.isArray(entries)) return value;
    const onExcluded = this.#onExcluded;
    const filtered =
      method === "tools/list"
        ? onExcluded !== undefined
          ? filterToolDefinitions(entries, onExcluded)
          : filterToolDefinitions(entries)
        : onExcluded !== undefined
          ? filterEventTypes(entries, onExcluded)
          : filterEventTypes(entries);
    const next: { [key: string]: JsonValue } = {};
    for (const [name, entry] of Object.entries(value)) next[name] = entry;
    next[member] = filtered;
    return next;
  }

  /**
   * C6/C11: the `Mcp-Param-*` headers of one modern request, from the
   * `inputSchema` of the tool (`tools/call`) or event type (the four `events/*`
   * methods) named by `params.name`. A value that does not fit its annotated
   * type throws instead of sending; an unknown definition carries no
   * annotation information and adds nothing.
   */
  async #project(method: string, wireParams: { readonly [key: string]: JsonValue }): Promise<readonly HeaderPair[]> {
    // Only a params.name source can be looked up in a catalog; prompts/get and
    // resources/read have no catalog here.
    if (nameSourceOf(method) !== "name") return [];
    const name = wireParams["name"];
    if (typeof name !== "string") return [];
    const entries =
      method === "tools/call" ? await this.listTools() : EVENTS_METHODS.has(method) ? await this.listEvents() : undefined;
    if (entries === undefined) return [];
    const entry = entries.find((candidate) => isJsonObject(candidate) && candidate["name"] === name);
    if (entry === undefined) return [];
    const schema = isJsonObject(entry) && Object.hasOwn(entry, "inputSchema") ? entry["inputSchema"] : undefined;
    const outcome = projectArguments(schema, wireParams["arguments"]);
    if (outcome.outcome === "refuse") throw new HeaderProjectionError();
    return outcome.headers;
  }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/** One interpreted verified answer: the value the caller sees and the C8 lifetime in milliseconds (0 = not reusable). */
interface RequestOutcome {
  /** `structuredContent` when the result carries it, the result itself otherwise. */
  readonly result: JsonValue;
  /** A non-negative integer `result.ttlMs`, else 0. */
  readonly ttlMs: number;
}

/** One attempt in one era: what the caller would see, and whether the reply proved the era was misread. */
interface EraAttempt {
  /** The interpreted outcome, or undefined only when a misread refusal is left for the caller. */
  readonly outcome: RequestOutcome | undefined;
  /** True when the verified reply proved this client chose the wrong era (C9). */
  readonly misread: boolean;
  /** The error a misread reply raises once no retry replaces it; undefined otherwise. */
  readonly refusal?: unknown;
}

/** The outcome of one attempt: its interpreted result, or the refusal a misread attempt never retried raised. */
function settleAttempt(attempt: EraAttempt): RequestOutcome {
  if (attempt.outcome !== undefined) return attempt.outcome;
  throw attempt.refusal;
}

/** C9: the era one detection proves, refusing an unusable verdict instead of choosing one. */
function eraVerdict(detection: EraDetection): "legacy" | "modern" {
  if (detection.era === "none" || detection.action === "abort") throw new EraNegotiationError(detection);
  return detection.era;
}

/**
 * C9: the abort verdict of a `-32022` whose supported list offers no version
 * this client can retry at, or of a retry verdict that arrives after the one
 * allowed re-probe. `supported` is preserved when the detection carried one.
 */
function noVersionOverlap(supported: readonly string[] | undefined): EraDetection {
  return {
    era: "modern",
    action: "abort",
    reason: "unsupported_version_no_overlap",
    ...(supported !== undefined ? { supported } : {}),
  };
}

/**
 * The attempt of a reply that proved the era misread: its refusal is held back
 * so `#request` can re-probe once first, and raised unchanged when no retry
 * replaces it.
 */
function misreadAttempt(reply: SignedReply): EraAttempt {
  try {
    return { outcome: interpretReply(reply), misread: true };
  } catch (err) {
    return { outcome: undefined, misread: true, refusal: err };
  }
}

/** A JSON object: the object member of `JsonValue`, viewed through a read-only walk. */
type JsonObject = { readonly [key: string]: JsonValue };

/** True for a JSON object: non-null and not an array. */
function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The exact params text of a request: `{}` for no params, the JSON text otherwise (the C8 key is built from the same text). */
function paramText(params: JsonValue | undefined): string {
  return params === undefined ? "{}" : jsonText(params);
}

/** The JSON text of a JSON value; `JSON.stringify` of a parsed value is never undefined, the fallback only satisfies the type. */
function jsonText(value: JsonValue): string {
  return JSON.stringify(value) ?? "null";
}

/** The RPCError of an `error` member: an integer code and a string message are read, a malformed member falls back to 0 and "". */
function rpcErrorOf(error: JsonValue): RPCError {
  const record = isJsonObject(error) ? error : undefined;
  const rawCode = record !== undefined ? record["code"] : undefined;
  const code = typeof rawCode === "number" && Number.isInteger(rawCode) ? rawCode : 0;
  const rawMessage = record !== undefined ? record["message"] : undefined;
  const message = typeof rawMessage === "string" ? rawMessage : "";
  const data = record !== undefined ? record["data"] : undefined;
  return new RPCError(code, message, data === undefined || data === null ? undefined : data);
}

/** Reads one verified answer: 2xx carries `result` or refuses with `error`; any other status is an error or an unexpected HTTP status. */
function interpretReply(reply: SignedReply): RequestOutcome {
  const json = isJsonObject(reply.json) ? reply.json : undefined;
  if (reply.status >= 200 && reply.status <= 299) {
    if (json === undefined) throw new Error("modern profile: json-rpc response is not a JSON object");
    const error = json["error"];
    if (error !== undefined && error !== null) throw rpcErrorOf(error);
    if (!Object.hasOwn(json, "result")) throw new Error("modern profile: json-rpc response has neither result nor error");
    const result = json["result"] as JsonValue;
    const record = isJsonObject(result) ? result : undefined;
    const structured = record !== undefined ? record["structuredContent"] : undefined;
    const value = structured !== undefined && structured !== null ? structured : result;
    const rawTtl = record !== undefined ? record["ttlMs"] : undefined;
    const ttlMs = typeof rawTtl === "number" && Number.isInteger(rawTtl) && rawTtl >= 0 ? rawTtl : 0;
    return { result: value, ttlMs };
  }
  const error = json !== undefined ? json["error"] : undefined;
  const errorRecord = isJsonObject(error) ? error : undefined;
  const code = errorRecord !== undefined ? errorRecord["code"] : undefined;
  if (errorRecord !== undefined && typeof code === "number" && Number.isInteger(code)) throw rpcErrorOf(errorRecord);
  throw new HTTPError(reply.status, "", "modern profile: unexpected HTTP status " + String(reply.status));
}

/** C10/C12: whether a reply is the `-32020` JSON-RPC refusal that a catalog resync can fix. */
function isVersionRefusal(reply: SignedReply): boolean {
  if (reply.status !== 400) return false;
  const json = isJsonObject(reply.json) ? reply.json : undefined;
  const error = json !== undefined ? json["error"] : undefined;
  const errorRecord = isJsonObject(error) ? error : undefined;
  return errorRecord !== undefined && errorRecord["code"] === -32020;
}

/** C9: the modern-era JSON-RPC codes that a `400` answer can carry; a legacy endpoint never sends them. */
function isModernEraRefusal(reply: SignedReply): boolean {
  if (reply.status !== 400) return false;
  const json = isJsonObject(reply.json) ? reply.json : undefined;
  const error = json !== undefined ? json["error"] : undefined;
  const errorRecord = isJsonObject(error) ? error : undefined;
  const code = errorRecord !== undefined ? errorRecord["code"] : undefined;
  return typeof code === "number" && Number.isInteger(code) && MODERN_ERA_ERROR_CODES.includes(code);
}

/** C9: whether a modern-era answer is a legacy signal, decided by the same verified-reply detector as the probe. */
function isLegacySignal(reply: SignedReply): boolean {
  const bodyText = reply.bodyText !== "" ? { bodyText: reply.bodyText } : {};
  return detectEra({ verified: true, status: reply.status, ...bodyText }, CLIENT_PROTOCOL_VERSIONS).era === "legacy";
}

/** C10/C12: the retry applies only to `tools/call` and the four `events/*` methods, whose schema comes from a catalog; `tools/list`, `events/list`, `prompts/get` and `resources/read` have no catalog to re-read. */
function isResyncTarget(method: string): boolean {
  if (method === "tools/call") return true;
  return EVENTS_METHODS.has(method);
}
