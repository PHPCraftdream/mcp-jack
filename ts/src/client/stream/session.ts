/**
 * Client side of signed streams (spec 05 sections 4 and 5.2): the opening call
 * of one `s1` response and caller cancellation. The verifying pump and the
 * per-request option resolution live in `pump.ts`, which both this module and
 * the transport import (one runtime edge each, no cycle).
 *
 * The request itself goes through the transport's one signing path
 * (`prepareSignedRequest`), so the open binding of 2.5 is the same `request-sig`
 * the v1 path would have sent.
 */
import { Code, JackError } from "../../core/errors.js";
import { STREAM_ACCEPT_HEADER, STREAM_SCHEME, isStreamResponse } from "../../stream/codes.js";
import type { StreamServerKey, StreamVerifyResult } from "../../stream/verify.js";
import { verifyResponse } from "../signing/auth.js";
import {
  MAX_BODY_BYTES,
  UnauthenticatedResponseError,
  forwardAbort,
  headerPairs,
  jackAuthHeaderValues,
  prepareSignedRequest,
  readBodyCapped,
} from "../transport/transport.js";
import type { SigningFetchConfig, SigningFetchInit } from "../transport/transport.js";
import { startVerifiedStream, streamVerifyOptions, wallClockSeconds } from "./pump.js";

/** Per-request stream settings, alongside the transport configuration (spec 05 sections 4.5, 2.17, 5.2, 6.1/6.2 and 6.3). */
export interface StreamClientOptions {
  /** Idle deadline: no verified frame for this long ends the stream with `stream_idle` (4.5); default 90000, a positive safe integer. */
  readonly streamIdleMs?: number;
  /** Cap of one message frame's data value as UTF-8 (2.17); default 1048576, a safe integer of at least 1024. */
  readonly frameMaxBytes?: number;
  /** What the data values are re-emitted for, SSE bytes (6.1) or one stdout line each (6.2); default "mcp". */
  readonly consumer?: "mcp" | "stdio";
  /** Rotation-aware key lookup (5.2); the default pins `config.serverKey` and knows no successor activation. */
  readonly resolveKey?: (kid: string) => StreamServerKey | undefined;
  /** The opening request's JSON-RPC id (6.3), for a caller that decides MCP completion from the terminal. */
  readonly requestId?: unknown;
}

/** One open, verifying stream: the verified open header, both views over the verified data and the terminal. */
export interface SignedStreamSession {
  /** The `sid` of the verified open header (2.4). */
  readonly sid: string;
  /** The response status, always 200 for a stream (1.4). */
  readonly status: number;
  /** The response header pairs the open header was verified against. */
  readonly headers: readonly (readonly [string, string])[];
  /** The verified message data values, in order; throws the `StreamVerifyError` after the last one on failure (4.4). */
  messages(): AsyncIterableIterator<string>;
  /** The same data values as 6.1 bytes; errors after the bytes that already verified (4.4). */
  sse(): ReadableStream<Uint8Array>;
  /** Caller cancellation: closes the connection and resolves `done`; idempotent. */
  cancel(): Promise<void>;
  /** The final terminal; resolves once and never rejects. */
  readonly done: Promise<StreamVerifyResult>;
}

/**
 * Opens and verifies a signed stream (1.4 routing, 4.1-4.5). The request is
 * signed by the transport's single signing path, opts in with `Jack-Accept: s1`
 * (1.1) and is aborted through one controller whose signal a caller `init.signal`
 * still cancels.
 *
 * A non-stream answer is not a stream: it is verified as a v1 response exactly
 * like `createSigningFetch` does, and only then reported as misrouted. That is
 * how a signed `501`/`429` refusal reaches the caller (1.4).
 */
export async function openSignedStream(
  config: SigningFetchConfig & StreamClientOptions,
  url: string | URL | Request,
  init?: SigningFetchInit,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<SignedStreamSession> {
  const abort = new AbortController();
  let unlink: () => void = () => undefined;
  let keepLink = false;
  try {
    const signed = await prepareSignedRequest(config, url, init, abort.signal);
    unlink = forwardAbort(signed.callerSignal, abort);
    // 1.1: the token is unsigned and belongs to no signing string, so adding it
    // after signing leaves the signed bytes untouched.
    signed.headers.set(STREAM_ACCEPT_HEADER, STREAM_SCHEME);

    const resp = await fetchImpl(signed.url, signed.init);
    const headers = headerPairs(resp.headers);
    const status = resp.status;

    if (!isStreamResponse(status, headers)) {
      const respBody = await readBodyCapped(resp, MAX_BODY_BYTES);
      // Verified as a v1 response first, then reported as the 1.4 misroute.
      const verifyNow = (config.clock ?? wallClockSeconds)();
      try {
        verifyResponse(config.serverKey, status, jackAuthHeaderValues(resp.headers), signed.requestSig, respBody, verifyNow, config.windowSeconds ?? 0);
      } catch (err) {
        if (err instanceof JackError && err.code === Code.MISSING_AUTH && status === 401) {
          throw new UnauthenticatedResponseError(status);
        }
        throw err;
      }
      throw new Error("jack client: response is not an s1 response; verify it with the v1 response path");
    }

    const pump = startVerifiedStream({
      status,
      headers,
      body: resp.body,
      requestSig: signed.requestSig,
      requestId: config.requestId,
      options: streamVerifyOptions(config, config, signed.requestSig),
      abort,
    });
    keepLink = true;
    const session: SignedStreamSession = {
      sid: pump.sid,
      status,
      headers,
      messages: () => pump.messages(),
      sse: () => pump.sse,
      cancel: () => pump.cancel(),
      done: pump.done,
    };
    return session;
  } finally {
    if (!keepLink) {
      unlink();
    }
  }
}
