/**
 * Modern-profile client layer of spec 04 section 6 (MCP 2026-07-28) on top of
 * the existing signed `Client` transport: C1/C2 request `_meta` and mirror
 * headers, C6/C11 `x-mcp-header` projection, the C8 private result cache, C9
 * era detection and fallback, and the C10/C12 one-shot catalog resync.
 *
 * Nothing here signs, verifies or re-encodes a body: `Client.signedRequest`
 * owns the wire bytes and the response verification, and this layer only adds
 * the `_meta` member, the header list and the reading of a verified answer.
 */

import { JackError } from "../core/errors.js";
import { HTTPError, RPCError } from "./errors.js";
import type { Client, JsonValue, SignedReply } from "./rpc.js";
import { UnauthenticatedResponseError } from "./transport/transport.js";
import { detectEra } from "../modern/era.js";
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
export const JACK_CLIENT_INFO: ClientInfo = { name: "mcp-jack", version: "0.2.0" };

/** Protocol versions this client implements, modern first: the modern minimum and the 2025-11-25 legacy fallback a `-32022` retry may pick from. */
export const CLIENT_PROTOCOL_VERSIONS: readonly string[] = [MODERN_MIN, "2025-11-25"];

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

// ---------------------------------------------------------------------------
// C8: the private result cache
// ---------------------------------------------------------------------------

/**
 * The C8 cache key of one request within one era: era, method and the exact
 * params text, NUL-separated. A response is bound to exactly one signed
 * request, so any change of method, params or era is a different key.
 */
export function resultCacheKey(method: string, paramsText: string, era: "legacy" | "modern"): string {
  return era + "\u0000" + method + "\u0000" + paramsText;
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
 */
export class PrivateResultCache {
  readonly #now: () => number;
  readonly #entries = new Map<string, CacheEntry>();

  constructor(now: () => number = () => Date.now()) {
    this.#now = now;
  }

  /** Stores one result for `ttlMs`; a lifetime that is not a finite positive number stores nothing, so `ttlMs: 0` is never reused. */
  put(key: string, value: JsonValue, ttlMs: number): void {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) return;
    this.#entries.set(key, { value, expiresAt: this.#now() + ttlMs });
  }

  /** Returns a result while it is unexpired, dropping it from the private map once `now()` reaches its deadline. */
  get(key: string): JsonValue | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    if (this.#now() < entry.expiresAt) return entry.value;
    this.#entries.delete(key);
    return undefined;
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
  /** Client capabilities added to `_meta`; defaults to `{}`. */
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
 * The modern-profile client layer: era detection, `_meta` and mirror headers,
 * `x-mcp-header` projection and the private cache, over an existing signed
 * `Client`. It never sends a request the `Client` does not sign and verify.
 */
export class ModernClient {
  readonly #client: Client;
  readonly #clientInfo: ClientInfo;
  readonly #clientCapabilities: JsonValue;
  readonly #cacheResults: boolean;
  readonly #onExcluded: ((name: string, reason: AnnotationReason) => void) | undefined;
  readonly #cache = new PrivateResultCache();
  #era: ClientEra;
  #version: string;
  #detection: EraDetection | undefined;
  #tools: JsonValue[] | undefined;
  #events: JsonValue[] | undefined;

  /** Wraps a client; every option falls back to the client's own era and to the modern defaults. */
  constructor(client: Client, options: ModernClientOptions = {}) {
    this.#client = client;
    this.#era = options.era ?? client.era;
    this.#version = options.version ?? MODERN_MIN;
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
   * C9: probes with a modern `server/discover` request and decides the era
   * from the verified answer alone. The outcome is remembered, and a `modern`
   * or `legacy` signal is adopted as this client's era; a version-mismatch
   * retry adopts the first mutually implemented version in the server's order.
   */
  async detectEra(): Promise<EraDetection> {
    const mirrors = buildRequestMirrors({
      version: this.#version,
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
        return this.#adopt({ era: "none", action: "abort", reason: "no_era_signal" });
      }
      probe = { verified: false, status: 0 };
    }
    return this.#adopt(detectEra(probe, CLIENT_PROTOCOL_VERSIONS));
  }

  /**
   * C1/C2/C6/C8: one request in the resolved era, returning the
   * `structuredContent` of the answer (or the result itself). A cached verified
   * result is served only for the exact same request and era, and only while
   * its `ttlMs` allows reuse.
   */
  async call(method: string, params?: JsonValue): Promise<JsonValue> {
    const era = await this.#eraOf();
    const paramsText = paramText(params);
    const key = resultCacheKey(method, paramsText, era);
    if (this.#cacheResults) {
      const cached = this.#cache.get(key);
      if (cached !== undefined) return cached;
    }
    const outcome = await this.#request(method, params, { resync: true });
    if (this.#cacheResults) this.#cache.put(key, outcome.result, outcome.ttlMs);
    return outcome.result;
  }

  /** The `tools/list` catalog with every C5-invalid definition excluded, fetched once and cached until a resync drops it. */
  async listTools(): Promise<JsonValue[]> {
    const cached = this.#tools;
    if (cached !== undefined) return cached;
    const outcome = await this.#request("tools/list", undefined, { resync: false });
    const result = isJsonObject(outcome.result) ? outcome.result : undefined;
    const tools = result !== undefined ? result["tools"] : undefined;
    if (!Array.isArray(tools)) throw new Error("modern profile: tools/list result has no tools array");
    const onExcluded = this.#onExcluded;
    const filtered = onExcluded !== undefined ? filterToolDefinitions(tools, onExcluded) : filterToolDefinitions(tools);
    this.#tools = filtered;
    return filtered;
  }

  /** The `events/list` catalog with every C11-invalid event type excluded, fetched once and cached until a resync drops it. */
  async listEvents(): Promise<JsonValue[]> {
    const cached = this.#events;
    if (cached !== undefined) return cached;
    const outcome = await this.#request("events/list", undefined, { resync: false });
    const result = isJsonObject(outcome.result) ? outcome.result : undefined;
    const events = result !== undefined ? result["events"] : undefined;
    if (!Array.isArray(events)) throw new Error("modern profile: events/list result has no events array");
    const onExcluded = this.#onExcluded;
    const filtered = onExcluded !== undefined ? filterEventTypes(events, onExcluded) : filterEventTypes(events);
    this.#events = filtered;
    return filtered;
  }

  // -- era ----------------------------------------------------------------

  /** The era to speak now: the configured one, or the cached `"auto"` detection, whose `none` outcome aborts the operation. */
  async #eraOf(): Promise<"legacy" | "modern"> {
    if (this.#era !== "auto") return this.#era;
    let detection = this.#detection;
    if (detection === undefined) {
      detection = await this.detectEra();
      // detectEra adopts every era signal, so "auto" only survives a "none".
      if (this.#era !== "auto") return this.#era;
    }
    if (detection.era === "none") {
      throw new Error("modern profile: era detection aborted (" + String(detection.reason) + ")");
    }
    return detection.era;
  }

  /** Remembers one detection and adopts the era it proves; a `none` signal leaves the configured era unchanged. */
  #adopt(detection: EraDetection): EraDetection {
    this.#detection = detection;
    if (detection.era === "modern") {
      this.#era = "modern";
      if (detection.action === "retry_with_supported") {
        const version = detection.supported?.[0];
        if (version !== undefined) this.#version = version;
      }
    } else if (detection.era === "legacy") {
      this.#era = "legacy";
    }
    return detection;
  }

  // -- requests -----------------------------------------------------------

  /**
   * One request in the resolved era. `resync` allows the single C10/C12 retry
   * after a `-32020` refusal: the catalog is dropped and re-read, so the retry
   * projects the current `inputSchema`. A second refusal is thrown, never
   * retried again.
   */
  async #request(
    method: string,
    params: JsonValue | undefined,
    options: { readonly resync: boolean },
  ): Promise<RequestOutcome> {
    const era = await this.#eraOf();
    if (era === "legacy") return interpretReply(await this.#client.signedRequest(method, paramText(params), []));
    const reply = await this.#sendModern(method, params);
    if (!options.resync || !isResyncTarget(method) || !isVersionRefusal(reply)) return interpretReply(reply);
    this.#tools = undefined;
    this.#events = undefined;
    return interpretReply(await this.#sendModern(method, params));
  }

  /** One modern-era request: `_meta` in the params, the C2 mirror headers and then the C6/C11 projected headers. */
  async #sendModern(method: string, params: JsonValue | undefined): Promise<SignedReply> {
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
    return this.#client.signedRequest(method, jsonText(wireParams), headers);
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

/** C10/C12: the retry applies only to `tools/call` and the four `events/*` methods, whose schema comes from a catalog; `tools/list`, `events/list`, `prompts/get` and `resources/read` have no catalog to re-read. */
function isResyncTarget(method: string): boolean {
  if (method === "tools/call") return true;
  return EVENTS_METHODS.has(method);
}
