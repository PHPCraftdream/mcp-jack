// The modern matrix client's HTTP wire: one node:http exchange per request, and
// the capture of the exact request and response bytes a step reports. Signing
// and response verification stay in the SDK: the SDK's signing fetch is wrapped
// around this exchange as its fetchImpl (contract 4.1).
import { request as httpRequest } from "node:http";
import type { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import type { JsonValue } from "../../core/json-raw.js";

// The lib is ES2022 without DOM: derive the fetch types from the Node globals.
type HeadersInit = NonNullable<RequestInit["headers"]>;
type BodyInit = NonNullable<RequestInit["body"]>;
type FetchInput = Parameters<typeof fetch>[0];
type FetchInit = Parameters<typeof fetch>[1];

/** One header instance: a received name/value pair, order and casing preserved. */
export type HeaderPair = readonly [string, string];

/** One HTTP response exactly as received. */
export interface Exchange {
  readonly status: number;
  readonly headers: readonly HeaderPair[];
  readonly body: Uint8Array;
}

/** One HTTP request exactly as sent (application, mirror and Jack-Auth headers; framing headers may be omitted). */
export interface Captured {
  readonly method: string;
  readonly target: string;
  readonly headers: readonly HeaderPair[];
  readonly body: Uint8Array;
}

/** The last exchange of one send. */
export interface Capture {
  readonly request: Captured;
  readonly response: Exchange;
}

/** How much of a reply the SDK trusted (contract 4.2). */
export type StepTrust = "verified" | "unsigned" | "unverified";

/** One response as the client reports and classifies it. */
export interface Reply {
  readonly status: number | null; // null only when no HTTP answer arrived
  readonly headers: readonly HeaderPair[];
  readonly body: Uint8Array;
  readonly text: string;
  readonly json: JsonValue | undefined;
  readonly trust: StepTrust;
  readonly clientCode: string | null; // set only for trust "unverified"
}

/** One request the client sent, exactly as contract 4.2 lists a step. */
export interface Step {
  readonly name: string;
  readonly http_method: string;
  readonly http_target: string;
  readonly jsonrpc_method: string | null;
  readonly http_status: number | null;
  readonly id: JsonValue | null;
  readonly request_headers: readonly HeaderPair[];
  readonly request_body_b64u: string;
  readonly request_sig: string | null;
  readonly response_auth: string | null;
  readonly response_content_type: string | null;
  readonly response_allow: string | null;
  readonly response_session_id: string | null;
  readonly response_body_b64u: string;
}

/** The process-wide wire: the SDK's signing fetch talks to `fetchImpl`, and every exchange is captured for the step report. */
export interface Transport {
  readonly fetchImpl: typeof fetch;
  /** The capture of the most recent send; undefined before the first one. */
  last(): Capture | undefined;
  /** Every capture since the previous take(), in send order: the SDK-driven phases report the requests they caused. */
  take(): Capture[];
  /** Drops the previous capture before a new send, so a stale exchange is never reported. */
  reset(): void;
  /** Sends prebuilt bytes WITHOUT signing: the contract-2 replay path, which must reuse the source request's exact bytes, signature and nonce. */
  exchange(url: string, method: string, headers: readonly HeaderPair[], body: Uint8Array): Promise<Exchange>;
}

/**
 * The capture slot of this client process. The SDK signing fetch reads and
 * verifies the body AFTER `fetchImpl` resolves, so a verification failure must
 * still find the bytes it failed on; the slot outlives the Response instead of
 * being handed back with it. One client process owns exactly one transport, so
 * a module-level slot is unambiguous.
 */
let captured: Capture | undefined;

/** Every capture since the previous `Transport.take()`, in send order. */
const queue: Capture[] = [];

/** Header pairs of `rawHeaders` (name, value, name, value, ...), so repeats and received order survive. */
function headerPairs(raw: readonly string[]): HeaderPair[] {
  const pairs: HeaderPair[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i];
    const value = raw[i + 1];
    if (name !== undefined && value !== undefined) pairs.push([name, value]);
  }
  return pairs;
}

/**
 * The Node request-option header form: one entry per first-seen name, with a
 * repeated name collected into an array value. WHY not Node's flat string
 * list: there a second occurrence of a name replaces the first, while an array
 * value emits every instance; object keys keep insertion order.
 */
function outgoingHeaders(headers: readonly HeaderPair[], bodyLength: number): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {};
  for (const [name, value] of headers) {
    const existing = out[name];
    if (existing === undefined) {
      out[name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      out[name] = [String(existing), value];
    }
  }
  // The body is not streamed, so its size is known up front: an explicit frame
  // keeps the head self-delimiting for the tamper proxy, which relays exactly
  // one request head per connection.
  if (bodyLength > 0) out["content-length"] = String(bodyLength);
  return out;
}

/** One raw HTTP exchange: exactly one request on its own socket, every received byte captured. */
function exchange(url: string, method: string, headers: readonly HeaderPair[], body: Uint8Array): Promise<Exchange> {
  const target = new URL(url);
  return new Promise<Exchange>((resolve, reject) => {
    const req = httpRequest(
      {
        host: target.hostname,
        port: target.port === "" ? 80 : Number(target.port),
        path: target.pathname + target.search,
        method,
        headers: outgoingHeaders(headers, body.length),
        // One socket per request: the tamper proxy relays exactly one request
        // head per connection, so a pooled keep-alive socket would strand it.
        agent: false,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: headerPairs(res.rawHeaders),
            body: new Uint8Array(Buffer.concat(chunks)),
          });
        });
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body.length > 0 ? Buffer.from(body) : undefined);
  });
}

/** The request URL: a string as given, a URL by its href, a Request by its url. */
function inputURL(input: FetchInput): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** The init headers as ordered pairs, in the order the SDK's Headers view yields them; the casing on the wire is then the transport's. */
function viewHeaderPairs(view: Headers): HeaderPair[] {
  const pairs: HeaderPair[] = [];
  view.forEach((value: string, name: string) => {
    pairs.push([name, value]);
  });
  return pairs;
}

/** The exact bytes of a fetch body; anything the signing fetch can hand over is accepted, absent means empty. */
function bodyBytes(body: BodyInit | null | undefined): Uint8Array {
  if (body === null || body === undefined) return new Uint8Array(0);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  // The SDK signs buffered bytes only, so an unexpected body kind is a caller bug rather than something to guess at.
  throw new Error("modern wire: unsupported request body type");
}

/** The received response headers, every pair appended in order (Headers folds repeats by name). */
function receivedHeaders(pairs: readonly HeaderPair[]): Headers {
  const headers = new Headers();
  for (const [name, value] of pairs) headers.append(name, value);
  return headers;
}

/** Builds the transport of one client process. */
export function createTransport(): Transport {
  const fetchImpl: typeof fetch = async (input: FetchInput, init?: FetchInit): Promise<Response> => {
    const url = new URL(inputURL(input));
    const method = init?.method ?? "GET";
    const view = init?.headers instanceof Headers ? init.headers : new Headers(init?.headers);
    const headers = viewHeaderPairs(view);
    const body = bodyBytes(init?.body);
    const response = await exchange(url.href, method, headers, body);
    // Store BEFORE returning the Response: the SDK reads and verifies the body
    // afterwards, so a verification failure must still leave the capture
    // available, and the captured target is the origin-form one.
    captured = {
      request: { method, target: url.pathname + url.search, headers, body },
      response,
    };
    queue.push(captured);
    // A null body is required for statuses 204/205/304 and means the same as an
    // empty one elsewhere, so an empty answer is reported without a body.
    return new Response(response.body.length > 0 ? response.body : null, {
      status: response.status,
      headers: receivedHeaders(response.headers),
    });
  };
  return {
    fetchImpl,
    last: (): Capture | undefined => captured,
    take: (): Capture[] => {
      const drained = queue.splice(0, queue.length);
      return drained;
    },
    reset: (): void => {
      captured = undefined;
    },
    exchange: (url: string, method: string, headers: readonly HeaderPair[], body: Uint8Array): Promise<Exchange> =>
      exchange(url, method, headers, body),
  };
}
