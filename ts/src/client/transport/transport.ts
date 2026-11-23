/** Signing, response-verifying fetch wrapper (spec 01 sections 4 and 5; port of Go client/transport.go). */
import { parseRequestAuth } from "../../core/auth-header.js";
import { Code, JackError } from "../../core/errors.js";
import { STREAM_ACCEPT_HEADER, STREAM_SCHEME } from "../../stream/codes.js";
import { randomNonce, signRequest, verifyResponse } from "../signing/auth.js";
import type { Clock, NonceSource } from "../signing/auth.js";
import type { Signer } from "../signing/signer.js";
import { checkDestination } from "./url-policy.js";
import { RedirectRefusedError } from "../errors.js";
// Type-only, so the config field adds no runtime edge; the re-emitting path of
// spec 05 section 6.1 is the one value this module takes from the stream client.
// `pump.ts` imports nothing from here, so the runtime graph stays acyclic.
import type { StreamClientOptions } from "../stream/session.js";
import { streamVerifyOptions, verifiedStreamResponse } from "../stream/pump.js";

// The lib is ES2022 without DOM: derive the fetch types from the Node globals.
type HeadersInit = NonNullable<RequestInit["headers"]>;
type BodyInit = NonNullable<RequestInit["body"]>;
type ReferrerPolicy = NonNullable<RequestInit["referrerPolicy"]>;
type RequestMode = NonNullable<RequestInit["mode"]>;
type RequestCredentials = NonNullable<RequestInit["credentials"]>;
type RequestInfo = Parameters<typeof fetch>[0];

/** Returned when the server answers with a text/event-stream body: a stream cannot be read in full and therefore cannot be signature-verified (spec 01 section 5, open question Q1). */
export class StreamingUnsupportedError extends Error {
  constructor() {
    super("jack client: streaming responses cannot be verified and are refused (spec 01 section 5, open question Q1)");
    this.name = "StreamingUnsupportedError";
  }
}

/** Reports whether a (comma-joined) Content-Type value has a member whose media type is text/event-stream. */
function isEventStreamValue(value: string): boolean {
  return value.split(",").some((member) => {
    const base = (member.split(";")[0] ?? "").replace(/^[ \t]+|[ \t]+$/g, "");
    return base.replace(/[A-Z]/g, (c) => c.toLowerCase()) === "text/event-stream";
  });
}

/** Reports a 401 answered WITHOUT a verified Jack-Auth header: only the status is surfaced, the body is untrusted and never parsed (spec 01 section 5). */
export class UnauthenticatedResponseError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`jack client: unauthenticated ${status} response`);
    this.status = status;
    this.name = "UnauthenticatedResponseError";
  }
}

/** Caps response buffering so a hostile body cannot exhaust memory. */
export const MAX_BODY_BYTES = 1 << 20;

/** Default signing clock in unix seconds. */
function defaultClock(): number {
  return Math.floor(Date.now() / 1000);
}

/** Configuration for createSigningFetch. */
export interface SigningFetchConfig {
  /** Audience string bound into the signing string. */
  aud: string;
  /** Default signer for outgoing requests. */
  signer: Signer;
  /** Pinned 32-byte raw server public key. */
  serverKey: Uint8Array;
  /** Signing clock; defaults to wall-clock unix seconds. */
  clock?: Clock;
  /** Per-request nonce source; defaults to randomNonce. */
  nonceSource?: NonceSource;
  /** Response timestamp tolerance in seconds; <= 0/undefined means DEFAULT_WINDOW_SECONDS. */
  windowSeconds?: number;
  /**
   * Opt in to signed streams (spec 05 section 1.1): every request then carries
   * `Jack-Accept: s1` and a `200` `text/event-stream` answer is verified and
   * re-emitted (6.1) instead of being refused. Absent keeps the v1 behaviour
   * byte for byte, `StreamingUnsupportedError` included.
   */
  readonly streams?: StreamClientOptions;
}

/** Per-request init for the signing fetch: exactly these fields are accepted and each is forwarded to the underlying fetch (method/headers/body are consumed by signing). Deliberately NOT the whole RequestInit: anything not listed here fails to compile instead of being silently dropped. `redirect` is forced to "error" (a signed request must never be replayed to another origin through a redirect) and has no override; `window`, `duplex` and `dispatcher` have no field here, so the type cannot promise what the wrapper drops. */
export interface SigningFetchInit {
  method?: string;
  headers?: HeadersInit;
  body?: BodyInit | null;
  /** Forwarded as-is; an explicit null here overrides a signal inherited from a Request input. */
  signal?: AbortSignal | null;
  integrity?: string;
  referrer?: string;
  referrerPolicy?: ReferrerPolicy;
  mode?: RequestMode;
  credentials?: RequestCredentials;
  keepalive?: boolean;
  /** Per-request signer override (port of Go WithRequestSigner). */
  jackSigner?: Signer;
  /** Pin the signing clock for one request: pins ONLY the request ts — the rotate proof ts must equal the header ts (spec 03 section 3.1; port of Go withFixedNow); response freshness still reads the clock at verification time. */
  jackFixedNow?: number;
}

/** A fetch-like function that signs every request and verifies every response before the caller sees its body. */
export type SigningFetch = (input: RequestInfo | URL, init?: SigningFetchInit) => Promise<Response>;

/** The RequestInit fields the wrapper forwards — exactly those declared on SigningFetchInit; redirect is forced to "error" and is not part of the forwarded set. */
interface ForwardedFields {
  signal?: AbortSignal | null | undefined;
  integrity?: string | undefined;
  referrer?: string | undefined;
  referrerPolicy?: ReferrerPolicy | undefined;
  mode?: RequestMode | undefined;
  credentials?: RequestCredentials | undefined;
  keepalive?: boolean | undefined;
}

/** The normalized parts of one outbound request. */
interface NormalizedRequest {
  url: string;
  method: string;
  headers: Headers;
  body: Uint8Array;
  forwarded: ForwardedFields;
}

/**
 * Normalizes the fetch input to a URL, method, buffered body, headers and the
 * forwarded RequestInit fields. Fetch semantics: a Request provides defaults;
 * init overrides method/headers/body and wins on every forwarded field.
 */
async function normalizeInput(input: RequestInfo | URL, init?: SigningFetchInit): Promise<NormalizedRequest> {
  let url: string;
  let method: string;
  let headers: Headers;
  let body: BodyInit | null | undefined;
  let request: Request | undefined;
  if (input instanceof Request) {
    request = input;
    url = input.url;
    method = input.method;
    headers = new Headers(input.headers);
    body = input.body;
  } else {
    url = String(input);
    method = init?.method ?? "GET";
    headers = new Headers(init?.headers);
  }
  if (init?.method !== undefined) {
    method = init.method;
  }
  if (init?.headers !== undefined) {
    headers = new Headers(init.headers);
  }
  // Fetch semantics: init.body overrides the Request body; absent means empty.
  if (init?.body !== undefined && init.body !== null) {
    body = init.body;
  }
  // An EXPLICIT signal in init wins even when it is null (it must be able to
  // cancel a signal inherited from a Request input); absent means inherit.
  const initSignal = init !== undefined && "signal" in init ? init.signal : undefined;
  // init wins over the Request input on every forwarded field, like fetch itself.
  const forwarded: ForwardedFields = {
    signal: initSignal !== undefined ? initSignal : request?.signal,
    integrity: init?.integrity ?? request?.integrity,
    referrer: init?.referrer ?? request?.referrer,
    referrerPolicy: init?.referrerPolicy ?? request?.referrerPolicy,
    mode: init?.mode ?? request?.mode,
    credentials: init?.credentials ?? request?.credentials,
    keepalive: init?.keepalive ?? request?.keepalive,
  };
  return { url, method, headers, body: await toBytes(body), forwarded };
}

/** Converts any supported BodyInit into exact bytes. */
async function toBytes(body: BodyInit | null | undefined): Promise<Uint8Array> {
  if (body === null || body === undefined) {
    return new Uint8Array(0);
  }
  if (typeof body === "string") {
    return new TextEncoder().encode(body);
  }
  if (body instanceof Uint8Array) {
    return body;
  }
  if (body instanceof ArrayBuffer) {
    return new Uint8Array(body);
  }
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof Blob) {
    return new Uint8Array(await body.arrayBuffer());
  }
  if (body instanceof URLSearchParams) {
    return new TextEncoder().encode(String(body));
  }
  if (body instanceof ReadableStream) {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value !== undefined) {
          chunks.push(value);
          total += value.length;
        }
      }
    } finally {
      // Release the lock so the caller's stream is not left locked on a failed read.
      reader.releaseLock();
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
  // FormData cannot be serialized byte-exactly.
  throw new Error("jack client: form-data bodies cannot be signed byte-exactly");
}

/** @internal: Jack-Auth header values of one response (headers.get is case-insensitive; undici merges duplicates with ", "); shared with the v1 fallback of openSignedStream. */
export function jackAuthHeaderValues(headers: Headers): string[] {
  const v = headers.get("Jack-Auth");
  return v === null ? [] : v.split(", ");
}

/** Best-effort body cancellation on every refusal path, so refused streams do not linger. */
async function cancelBody(resp: Response): Promise<void> {
  try {
    await resp.body?.cancel();
  } catch {
    // Cancellation must not mask the refusal error.
  }
}

/** @internal: every response header as a name/value pair, in iteration order (Headers has already joined duplicates). */
export function headerPairs(headers: Headers): (readonly [string, string])[] {
  const pairs: (readonly [string, string])[] = [];
  headers.forEach((value, name) => {
    pairs.push([name, value]);
  });
  return pairs;
}

/**
 * @internal: forwards the caller's abort to a wrapper controller; the returned
 * function detaches the listener. `AbortSignal.any` is not on the minimum Node,
 * and an already-aborted caller signal (or an explicit null) is handled here.
 */
export function forwardAbort(signal: AbortSignal | null | undefined, controller: AbortController): () => void {
  if (signal === undefined || signal === null) {
    return () => undefined;
  }
  if (signal.aborted) {
    controller.abort();
    return () => undefined;
  }
  const abort = (): void => controller.abort();
  signal.addEventListener("abort", abort, { once: true });
  return () => signal.removeEventListener("abort", abort);
}

/** Response headers minus every Jack-Auth: the stream open value is consumed by the verifier and never re-exposed. */
function responseHeadersWithoutJackAuth(headers: Headers): Headers {
  const out = new Headers();
  headers.forEach((value, name) => {
    if (name.toLowerCase() !== "jack-auth") {
      out.set(name, value);
    }
  });
  return out;
}

/** One request signed by the single signing path, with the exact RequestInit to send. */
export interface PreparedSignedRequest {
  /** The URL exactly as signed and sent. */
  readonly url: string;
  /** The signed headers; an unsigned opt-in header may still be added (spec 05 section 1.1). */
  readonly headers: Headers;
  /** The exact RequestInit the wrapper sends. */
  readonly init: RequestInit;
  /** The `sig` parameter of the Jack-Auth value: the stream open binding of spec 05 section 2.5. */
  readonly requestSig: string;
  /** The effective caller signal (init or Request) before any wrapper override. */
  readonly callerSignal: AbortSignal | null | undefined;
}

/**
 * @internal
 * The one signing path, factored so `openSignedStream` sends a byte-identical
 * request: checkDestination first, then normalize, then the signer/clock/nonce,
 * then signRequest, then parseRequestAuth. `overrideSignal` replaces the
 * caller's signal in the returned init, so a stream path can own the response
 * lifetime through one AbortController.
 */
export async function prepareSignedRequest(
  config: SigningFetchConfig,
  input: RequestInfo | URL,
  init?: SigningFetchInit,
  overrideSignal?: AbortSignal,
): Promise<PreparedSignedRequest> {
  checkDestination(rawDestination(input));
  const normalized = await normalizeInput(input, init);
  const signer = init?.jackSigner ?? config.signer;
  const now = init?.jackFixedNow ?? (config.clock ?? defaultClock)();
  const nonce = await (config.nonceSource ?? randomNonce)();

  // The origin-form target exactly as sent on the wire: path plus ?query, no fragment.
  const u = new URL(normalized.url);
  const target = u.pathname + u.search;

  const headerVal = signRequest(signer, config.aud, normalized.method, target, normalized.body, nonce, now);
  // The request signature binds the response signing string (spec 01 section 5).
  const requestSig = parseRequestAuth([headerVal]).sig;

  normalized.headers.set("Jack-Auth", headerVal);
  // Send the exact buffered bytes that were signed. `redirect` is forced to
  // "error": a signed request must never be replayed to another origin through
  // a redirect. `window` (browser-only), `duplex` (bodies are buffered, never
  // streamed) and `dispatcher` (non-standard) are not forwarded. Conditional
  // spreads keep exactOptionalPropertyTypes happy.
  const signal = overrideSignal !== undefined ? overrideSignal : normalized.forwarded.signal;
  const requestInit: RequestInit = {
    method: normalized.method,
    headers: normalized.headers,
    redirect: "error",
    ...(signal !== undefined ? { signal } : {}),
    ...(normalized.forwarded.integrity !== undefined ? { integrity: normalized.forwarded.integrity } : {}),
    ...(normalized.forwarded.referrer !== undefined ? { referrer: normalized.forwarded.referrer } : {}),
    ...(normalized.forwarded.referrerPolicy !== undefined ? { referrerPolicy: normalized.forwarded.referrerPolicy } : {}),
    ...(normalized.forwarded.mode !== undefined ? { mode: normalized.forwarded.mode } : {}),
    ...(normalized.forwarded.credentials !== undefined ? { credentials: normalized.forwarded.credentials } : {}),
    ...(normalized.forwarded.keepalive !== undefined ? { keepalive: normalized.forwarded.keepalive } : {}),
    ...(normalized.body.length > 0 ? { body: normalized.body } : {}),
  };
  return { url: normalized.url, headers: normalized.headers, init: requestInit, requestSig, callerSignal: normalized.forwarded.signal };
}

/** The raw string form of a fetch input, as the URL policy sees it: a string as given, a URL by its serialised href, a Request by its (already normalised) url. */
function rawDestination(input: RequestInfo | URL): string {
  if (input instanceof Request) {
    return input.url;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return String(input);
}

/** The exact redirect statuses; 300 and 304 are not redirects and go through normal verification. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** The network destination of a URL string: its href without the fragment (a fragment is never sent and never appears in a real Response.url). Works on a parsed copy; the request URL and the signed target are untouched. */
function networkDestination(raw: string): string {
  const u = new URL(raw);
  u.hash = "";
  return u.href;
}

/**
 * Refuses any answer that is, or followed, a redirect, discarding its body
 * unverified. A no-follow guard so a signed request is never verified against
 * another target; not TLS enforcement. Redirect statuses are exactly 301, 302,
 * 303, 307 and 308 (plus type "opaqueredirect" and `redirected`). An injected
 * fetchImpl may leave `url` empty, so a final url is only compared when
 * non-empty, and the comparison ignores the fragment.
 */
async function refuseRedirected(resp: Response, requested: string): Promise<void> {
  let reason: string | undefined;
  if (resp.redirected) {
    reason = "the transport followed a redirect";
  } else if (resp.type === "opaqueredirect" || REDIRECT_STATUSES.has(resp.status)) {
    reason = `redirect answer (status ${resp.status})`;
  } else if (resp.url !== "") {
    try {
      if (networkDestination(resp.url) !== networkDestination(requested)) {
        reason = "the response url differs from the requested url";
      }
    } catch {
      reason = "the response url is not a valid url";
    }
  }
  if (reason !== undefined) {
    await cancelBody(resp);
    throw new RedirectRefusedError(reason);
  }
}

/**
 * createSigningFetch returns a fetch-like function that signs each request and
 * verifies each response (port of Go Transport.RoundTrip).
 *
 * Client URL policy: before anything else (before the body is read and before
 * any signer, nonce or fetchImpl is touched) the destination is checked by
 * checkDestination: https for any host, http only for a literal 127.x.y.z or
 * [::1]; otherwise DestinationRefusedError is thrown. Percent escapes are
 * refused in the authority only (which also refuses zone IDs); percent-encoded
 * path and query bytes are accepted and signed as given. The policy sees a string
 * input as given; a URL input is checked on its serialised `.href` and a
 * Request on its `.url` (both already WHATWG-normalised, and strictly
 * validated again by the policy). Redirects are never followed
 * (`redirect: "error"` is forced); an answer from an injected fetchImpl with
 * status 301, 302, 303, 307 or 308, type "opaqueredirect", `redirected` set or
 * a final url that differs (fragment ignored) is refused with
 * RedirectRefusedError. Other 3xx statuses (300, 304) are not redirects and
 * are verified normally. This is a no-follow guard so a signed request is
 * never verified against another target, not TLS enforcement. There is
 * no insecure opt-out. A caller-supplied fetchImpl must use TLS for https,
 * connect to exactly the URL it is given and not follow redirects; the SDK
 * cannot police an arbitrary custom fetch. Response mapping:
 * - verification passes -> the verified bytes are returned as a fresh Response;
 * - JackError missing_auth with status 401 (an unsigned 401) -> the body is
 *   ignored and UnauthenticatedResponseError{status} is thrown;
 * - every other verification failure (malformed_auth, unsupported_version,
 *   unknown_server_key, timestamp_out_of_window, bad_signature — all with
 *   httpStatus 0 per spec 01 section 5, as Go's RoundTrip does too) and every
 *   configuration error propagates unchanged.
 *
 * Signed streams (spec 05): only with `config.streams` set does every request
 * carry the unsigned `Jack-Accept: s1` opt-in header (never sent otherwise),
 * and only then is a `200` `text/event-stream` answer verified and re-emitted
 * instead of refused — the returned Response carries the 6.1 bytes, its own
 * cancellation closes the connection, and a failed open header throws
 * `StreamVerifyError` here (after the body is cancelled), exactly like a v1
 * verification error. Later stream failures surface through the returned
 * stream. Without `config.streams` nothing of that applies.
 */
export function createSigningFetch(config: SigningFetchConfig, fetchImpl: typeof fetch = globalThis.fetch): SigningFetch {
  return async (input: RequestInfo | URL, init?: SigningFetchInit): Promise<Response> => {
    // With streams opted in, one controller owns the response lifetime, so a
    // cancelled stream closes the connection; without it exactly the caller's
    // signal is forwarded, as before.
    const abort = config.streams !== undefined ? new AbortController() : undefined;
    const signed = await prepareSignedRequest(config, input, init, abort?.signal);
    // 1.1: the opt-in token is unsigned and appears in no signing string, so it
    // is set after signing; without `streams` no header is added.
    if (config.streams !== undefined) {
      signed.headers.set(STREAM_ACCEPT_HEADER, STREAM_SCHEME);
    }
    let unlink: () => void = () => undefined;
    if (abort !== undefined) {
      unlink = forwardAbort(signed.callerSignal, abort);
    }
    let keepLink = false;
    try {
      const resp = await fetchImpl(signed.url, signed.init);

      // Refuse redirect answers before anything is read or verified.
      await refuseRedirected(resp, signed.url);

      // Headers.get already joins duplicate Content-Type lines with ", ": any
      // member whose media type is text/event-stream (text before the first
      // ';', SP/HTAB trimmed, ASCII case-insensitive) matches.
      const contentType = resp.headers.get("content-type");
      const eventStream = contentType !== null && isEventStreamValue(contentType);

      // 1.4: a 200 with a text/event-stream media type is the signed stream.
      if (config.streams !== undefined && abort !== undefined && resp.status === 200 && eventStream) {
        const headers = headerPairs(resp.headers);
        const verified = verifiedStreamResponse({
          status: resp.status,
          headers,
          body: resp.body,
          requestSig: signed.requestSig,
          requestId: undefined,
          options: streamVerifyOptions(config, config.streams, signed.requestSig),
          abort,
        });
        void verified.done.then(unlink);
        keepLink = true;
        return new Response(verified.sse, {
          status: resp.status,
          statusText: resp.statusText,
          headers: responseHeadersWithoutJackAuth(resp.headers),
        });
      }

      // Streaming guard BEFORE buffering: a stream cannot be body-hashed, so it
      // cannot be verified (spec 01 section 5, open question Q1). Only the v1
      // path refuses, so streams-absent behaviour is unchanged.
      if (config.streams === undefined && eventStream) {
        await cancelBody(resp);
        throw new StreamingUnsupportedError();
      }

      const respBody = await readBodyCapped(resp, MAX_BODY_BYTES);

      try {
        // Response freshness reads the clock at verification time (Go calls the
        // clock again here), not at request time.
        const verifyNow = (config.clock ?? defaultClock)();
        verifyResponse(config.serverKey, resp.status, jackAuthHeaderValues(resp.headers), signed.requestSig, respBody, verifyNow, config.windowSeconds ?? 0);
      } catch (err) {
        if (err instanceof JackError && err.code === Code.MISSING_AUTH && resp.status === 401) {
          // The unsigned 401 body is never trusted: status only (spec 01 section 5).
          throw new UnauthenticatedResponseError(resp.status);
        }
        throw err;
      }

      // Hand the caller the verified bytes as a fresh Response. A null body is
      // required for statuses 204/205/304 (any body, even zero-length, throws
      // there), and carries no meaning for empty bodies otherwise.
      return new Response(respBody.length > 0 ? respBody : null, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
    } finally {
      // The link lives as long as the returned stream, else it ends with this call.
      if (!keepLink) {
        unlink();
      }
    }
  };
}

/** Reads the whole response body, throwing as soon as it exceeds cap bytes; the reader lock is released on every exit path; on overflow the stream is cancelled so the hostile remainder stops flowing. */
export async function readBodyCapped(resp: Response, cap: number): Promise<Uint8Array> {
  if (resp.body === null) {
    return new Uint8Array(0);
  }
  const reader = resp.body.getReader();
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value !== undefined) {
        total += value.length;
        if (total > cap) {
          // Cancel the stream so the hostile remainder stops flowing;
          // releaseLock runs in finally and must not mask the cap error.
          try {
            await reader.cancel();
          } catch {
            // Cancellation must not mask the cap error.
          }
          throw new Error(`jack client: response body exceeds ${cap} bytes`);
        }
        chunks.push(value);
      }
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  } finally {
    // Release the caller's body lock on every exit path (success, overflow,
    // rejected read); releaseLock never rejects.
    reader.releaseLock();
  }
}
