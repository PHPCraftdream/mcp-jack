import { lookup } from "node:dns/promises";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity } from "node:tls";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { classifyAddress } from "./address.js";
import { checkDelivery } from "./delivery.js";
import type { DeliveryFailureCode } from "./delivery.js";
import { checkCallbackUrl } from "./url.js";

const CONNECT_TIMEOUT_MS = 10000;
const RESPONSE_TIMEOUT_MS = 10000;
const ATTEMPT_TIMEOUT_MS = 20000;
const MAX_RESPONSE_BYTES = 262144;

/** Resolves a DNS name to all of its addresses, in resolver order. */
export interface WebhookResolver {
  resolve(host: string): Promise<readonly string[]>;
}

/** Uses the system resolver and returns bare address literals. */
export const defaultResolver: WebhookResolver = {
  async resolve(host) {
    const answers = await lookup(host, { all: true });
    return answers.map(({ address }: { readonly address: string }) => address);
  },
};

/** The pinned peer and original HTTP and TLS authority for a validated URL. */
export interface HardenedDialTarget {
  readonly address: string;
  readonly hostHeader: string;
  readonly sni: string | null;
  readonly port: number;
  readonly ipv6: boolean;
}

/** An outbound request with optional cancellation, phase limits and a response-body limit. */
export interface HardenedRequest {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  readonly connectTimeoutMs?: number;
  readonly responseTimeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly abortSignal?: AbortSignal;
}

/** The status, headers and raw bytes of an outbound HTTP response. */
export interface HardenedResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  readonly tooLarge?: boolean;
}

/** Opens HTTPS directly to the pinned peer, verifies it and does not follow redirects. */
export type HardenedDialer = (target: HardenedDialTarget, request: HardenedRequest) => Promise<HardenedResponse>;

/** Optional I/O seams, operator CIDR overrides and transport limits. */
export interface HardenedTransportOptions {
  readonly resolver?: WebhookResolver;
  readonly dialer?: HardenedDialer;
  readonly allowedRanges?: readonly string[];
  readonly connectTimeoutMs?: number;
  readonly responseTimeoutMs?: number;
  readonly attemptTimeoutMs?: number;
  readonly maxResponseBytes?: number;
}

/** A response or a refusal code and optional reason, without raw network error details. */
export type HardenedOutcome =
  | { readonly ok: true; readonly response: HardenedResponse }
  | {
      readonly ok: false;
      readonly code: DeliveryFailureCode | "connection_refused" | "tls_error" | "timeout";
      readonly reason?: string;
    };

type FailureCode = Extract<HardenedOutcome, { readonly ok: false }>["code"];

/** One outbound HTTPS path for deliveries, challenges and verification document fetches. */
export class HardenedTransport {
  readonly #options: HardenedTransportOptions;
  readonly #resolver: WebhookResolver;
  readonly #dialer: HardenedDialer;

  /** Uses the system resolver and pinned Node HTTPS dialer by default. */
  constructor(options: HardenedTransportOptions = {}) {
    this.#options = options;
    this.#resolver = options.resolver ?? defaultResolver;
    this.#dialer = options.dialer ?? defaultDialer;
  }

  /** Validates every resolved address, then dials the first one using the URL's path and query. */
  async request(url: string, request: HardenedRequest): Promise<HardenedOutcome> {
    const signal = request.abortSignal;
    if (signal?.aborted === true) return { ok: false, code: "timeout" };
    const deadline = performance.now() + (this.#options.attemptTimeoutMs ?? ATTEMPT_TIMEOUT_MS);
    const checked = checkCallbackUrl(url);
    if (!checked.ok) return { ok: false, code: checked.code };

    let answers: readonly string[] = [];
    if (checked.hostKind === "name") {
      try {
        answers = await within(() => this.#resolver.resolve(checked.hostValue), deadline - performance.now(), signal);
      } catch (error) {
        if (signal?.aborted) return { ok: false, code: "timeout" };
        const code = errorCode(error);
        return { ok: false, code: code === "ENOTFOUND" || code === "ENODATA" ? "no_answer" : mapError(error) };
      }
    }
    if (signal?.aborted) return { ok: false, code: "timeout" };
    const decision = checkDelivery({ url, answers, allowedRanges: this.#options.allowedRanges ?? [] });
    if (decision.decision !== "allow") {
      return decision.reason === undefined
        ? { ok: false, code: decision.code }
        : { ok: false, code: decision.code, reason: decision.reason };
    }

    const { address } = decision.connect;
    const target = { ...decision.connect, port: checked.port, ipv6: address.includes(":") };
    const dialRequest: HardenedRequest = {
      ...request,
      path: checked.path + (checked.query === "" ? "" : `?${checked.query}`),
      connectTimeoutMs: request.connectTimeoutMs ?? this.#options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS,
      responseTimeoutMs: request.responseTimeoutMs ?? this.#options.responseTimeoutMs ?? RESPONSE_TIMEOUT_MS,
      maxResponseBytes: request.maxResponseBytes ?? this.#options.maxResponseBytes ?? MAX_RESPONSE_BYTES,
    };
    try {
      const remaining = deadline - performance.now();
      if (remaining <= 0) return { ok: false, code: "timeout" };
      const usesDefaultDialer = this.#dialer === defaultDialer;
      const response = usesDefaultDialer
        ? await dialHttps(target, dialRequest, remaining)
        : await within(() => this.#dialer(target, dialRequest), remaining, signal);
      if (signal?.aborted || performance.now() >= deadline) return { ok: false, code: "timeout" };
      if (isRedirect(response.status)) return { ok: false, code: "redirect_refused" };
      if (!usesDefaultDialer && "tooLarge" in response) {
        const { status, headers, body } = response;
        return { ok: true, response: { status, headers, body } };
      }
      return { ok: true, response };
    } catch (error) {
      return { ok: false, code: signal?.aborted ? "timeout" : mapError(error) };
    }
  }
}

/** Dials the pinned address directly. Oversized responses become an empty synthetic HTTP 413. */
export const defaultDialer: HardenedDialer = (target, request) => dialHttps(target, request, ATTEMPT_TIMEOUT_MS);

function dialHttps(target: HardenedDialTarget, request: HardenedRequest, attemptTimeoutMs: number): Promise<HardenedResponse> {
  return new Promise((resolve, reject) => {
    const signal = request.abortSignal;
    if (signal?.aborted === true) {
      reject(codedError("ETIMEDOUT"));
      return;
    }
    if (classifyAddress(target.address).address !== target.address) {
      reject(codedError("dns_rebinding"));
      return;
    }
    const headers = Object.fromEntries(Object.entries(request.headers).filter(([name]) => name.toLowerCase() !== "host"));
    headers["Host"] = target.hostHeader;
    const cap = request.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    let done = false;
    let responseTimer: ReturnType<typeof setTimeout> | undefined;
    const req = httpsRequest({
      host: target.address,
      port: target.port,
      family: target.ipv6 ? 6 : 4,
      ...(target.sni === null ? {} : { servername: target.sni }),
      checkServerIdentity: (_name: string, cert: PeerCertificate) => checkServerIdentity(target.sni ?? target.address, cert),
      method: request.method,
      path: request.path,
      headers,
      rejectUnauthorized: true,
      agent: false,
    }, (res: IncomingMessage) => {
      res.once("error", fail);
      res.once("aborted", () => fail(codedError("ECONNRESET")));
      const status = res.statusCode ?? 0;
      if (isRedirect(status)) {
        succeed({ status, headers: {}, body: new Uint8Array(0) });
        req.destroy();
        return;
      }
      const chunks: Uint8Array[] = [];
      let size = 0;
      res.on("data", (chunk: Uint8Array) => {
        if (done) return;
        size += chunk.byteLength;
        if (size > cap) {
          succeed({ status: 413, headers: {}, body: new Uint8Array(0), tooLarge: true });
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.once("end", () => {
        if (done) return;
        const body = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          body.set(chunk, offset);
          offset += chunk.byteLength;
        }
        const responseHeaders: Record<string, string> = Object.create(null);
        for (const [name, value] of Object.entries(res.headers)) {
          if (typeof value === "string") responseHeaders[name] = value;
          else if (Array.isArray(value)) responseHeaders[name] = value.join(", ");
        }
        succeed({ status, headers: responseHeaders, body });
      });
    });
    const connectTimer = setTimeout(timeout, request.connectTimeoutMs ?? CONNECT_TIMEOUT_MS);
    const attemptTimer = setTimeout(timeout, attemptTimeoutMs);
    req.once("error", fail);
    req.once("socket", (socket: TLSSocket) => {
      socket.once("connect", () => { verifyPeer(socket); });
      socket.once("secureConnect", () => {
        if (verifyPeer(socket)) clearTimeout(connectTimer);
      });
    });
    req.once("finish", () => {
      if (!done) responseTimer = setTimeout(timeout, request.responseTimeoutMs ?? RESPONSE_TIMEOUT_MS);
    });
    signal?.addEventListener("abort", timeout, { once: true });
    if (signal?.aborted) {
      timeout();
      return;
    }
    try {
      req.end(request.body);
    } catch (error) {
      fail(error);
      req.destroy();
    }

    function verifyPeer(socket: TLSSocket): boolean {
      if (done) return false;
      if (classifyAddress(socket.remoteAddress ?? "").address === target.address) return true;
      const error = codedError("dns_rebinding");
      fail(error);
      req.destroy(error);
      return false;
    }

    function timeout(): void {
      const error = codedError("ETIMEDOUT");
      fail(error);
      req.destroy(error);
    }

    function finish(): boolean {
      if (done) return false;
      done = true;
      clearTimeout(connectTimer);
      clearTimeout(attemptTimer);
      clearTimeout(responseTimer);
      signal?.removeEventListener("abort", timeout);
      return true;
    }

    function fail(error: unknown): void {
      if (finish()) reject(error);
    }

    function succeed(response: HardenedResponse): void {
      if (finish()) resolve(response);
    }
  });
}

async function within<T>(operation: () => Promise<T>, ms: number, signal?: HardenedRequest["abortSignal"]): Promise<T> {
  if (ms <= 0 || signal?.aborted) throw codedError("ETIMEDOUT");
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  try {
    return await Promise.race([
      new Promise<never>((_resolve, reject) => {
        onAbort = () => reject(codedError("ETIMEDOUT"));
        timer = setTimeout(onAbort, ms);
        signal?.addEventListener("abort", onAbort, { once: true });
      }),
      Promise.resolve().then(() => {
        if (signal?.aborted) throw codedError("ETIMEDOUT");
        return operation();
      }),
    ]);
  } finally {
    clearTimeout(timer);
    if (onAbort !== undefined) signal?.removeEventListener("abort", onAbort);
  }
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

function codedError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code : "";
}

function mapError(error: unknown): FailureCode {
  const code = errorCode(error);
  if (code === "dns_rebinding") return code;
  if (code === "ETIMEDOUT" || code === "ERR_SOCKET_CONNECTION_TIMEOUT" || code === "timeout") return "timeout";
  if (code === "tls_error" || code === "EPROTO" ||
      /^(?:ERR_(?:TLS|SSL|OSSL)_|CERT_|DEPTH_|UNABLE_TO_|SELF_SIGNED_|INVALID_CA|PATH_LENGTH_EXCEEDED)/.test(code)) {
    return "tls_error";
  }
  return "connection_refused";
}
