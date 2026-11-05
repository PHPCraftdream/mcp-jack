/** Signing, response-verifying fetch wrapper (spec 01 sections 4 and 5; port of Go client/transport.go). */
import { parseRequestAuth } from "../auth-header.js";
import { Code, JackError } from "../errors.js";
import { randomNonce, signRequest, verifyResponse } from "./auth.js";
import type { Clock, NonceSource } from "./auth.js";
import type { Signer } from "./signer.js";

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

/** Jack-Auth header values of one response (headers.get is case-insensitive; undici merges duplicates with ", "). */
function jackAuthHeaderValues(headers: Headers): string[] {
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

/**
 * createSigningFetch returns a fetch-like function that signs each request and
 * verifies each response (port of Go Transport.RoundTrip). Response mapping:
 * - verification passes -> the verified bytes are returned as a fresh Response;
 * - JackError missing_auth with status 401 (an unsigned 401) -> the body is
 *   ignored and UnauthenticatedResponseError{status} is thrown;
 * - every other verification failure (malformed_auth, unsupported_version,
 *   unknown_server_key, timestamp_out_of_window, bad_signature — all with
 *   httpStatus 0 per spec 01 section 5, where Go wrongly kept 401) and every
 *   configuration error propagates unchanged.
 */
export function createSigningFetch(config: SigningFetchConfig, fetchImpl: typeof fetch = globalThis.fetch): SigningFetch {
  return async (input: RequestInfo | URL, init?: SigningFetchInit): Promise<Response> => {
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
    // "error": a signed request must never be replayed to another origin
    // through a redirect. `window` (browser-only), `duplex` (bodies are
    // buffered, never streamed) and `dispatcher` (non-standard) are not
    // forwarded. Conditional spreads keep exactOptionalPropertyTypes happy.
    const resp = await fetchImpl(normalized.url, {
      method: normalized.method,
      headers: normalized.headers,
      redirect: "error",
      ...(normalized.forwarded.signal !== undefined ? { signal: normalized.forwarded.signal } : {}),
      ...(normalized.forwarded.integrity !== undefined ? { integrity: normalized.forwarded.integrity } : {}),
      ...(normalized.forwarded.referrer !== undefined ? { referrer: normalized.forwarded.referrer } : {}),
      ...(normalized.forwarded.referrerPolicy !== undefined ? { referrerPolicy: normalized.forwarded.referrerPolicy } : {}),
      ...(normalized.forwarded.mode !== undefined ? { mode: normalized.forwarded.mode } : {}),
      ...(normalized.forwarded.credentials !== undefined ? { credentials: normalized.forwarded.credentials } : {}),
      ...(normalized.forwarded.keepalive !== undefined ? { keepalive: normalized.forwarded.keepalive } : {}),
      ...(normalized.body.length > 0 ? { body: normalized.body } : {}),
    });

    // Streaming guard BEFORE buffering: a stream cannot be body-hashed, so it
    // cannot be verified (spec 01 section 5, open question Q1).
    const ct = resp.headers.get("content-type");
    if (ct !== null) {
      const mediaType = ct.split(";")[0]?.trim().toLowerCase();
      if (mediaType === "text/event-stream") {
        await cancelBody(resp);
        throw new StreamingUnsupportedError();
      }
    }

    const respBody = await readBodyCapped(resp, MAX_BODY_BYTES);

    try {
      // Response freshness reads the clock at verification time (Go calls the
      // clock again here), not at request time.
      const verifyNow = (config.clock ?? defaultClock)();
      verifyResponse(config.serverKey, resp.status, jackAuthHeaderValues(resp.headers), requestSig, respBody, verifyNow, config.windowSeconds ?? 0);
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
