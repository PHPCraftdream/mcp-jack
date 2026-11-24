/**
 * Stream server options, the 3.3 admission gate and the 3.7 handler context of
 * signed streams (spec 05 sections 3.3, 3.5, 3.7 and 5.1).
 *
 * The signer (`../stream/signer.ts`) and the pump (`../stream/pipeline.ts`)
 * own the signed bytes; this module decides only what a stream may spend and
 * what the wrapped handler may observe about it: the concurrency slot per
 * authenticated identity (3.3), the heartbeat grant clamped to the server's
 * own response-verification window W (3.5), the 5.1 successor cutoff the pump
 * enforces, and the cancellation signal of 3.7. The `sid` bytes of 2.4 are
 * drawn through `sidSource`, so a test can inject a deterministic source
 * without weakening the CSPRNG default.
 *
 * `startSignedStream` builds the 2.1 stream response of one forwarded handler
 * answer, so fetch.ts keeps only the v1 signed bytes (01 section 5), the
 * 501/429/503 refusal bodies and the 1.4 routing decision.
 */
import { randomBytes } from "node:crypto";
import { StreamPump } from "../../stream/pipeline.js";
import { StreamSigner } from "../../stream/signer.js";
import type { StreamSigningKey } from "../../stream/signer.js";
import { classifyBody } from "../verify.js";
import {
  grantedHeartbeatMs,
  STREAM_DEFAULT_FRAME_MAX_BYTES,
  STREAM_DEFAULT_MAX_CONCURRENT_STREAMS,
  STREAM_DEFAULT_MAX_DURATION_MS,
  STREAM_DEFAULT_WINDOW_SECONDS,
  STREAM_MIN_FRAME_MAX_BYTES,
} from "../../stream/codes.js";

/** Raw stream settings of HandlerConfig.streams; every field is validated by resolveStreamOptions. */
export interface StreamServerOptions {
  /** Bounds the data value of one message frame (3.2); default 1048576, a safe integer of at least 1024. */
  readonly frameMaxBytes?: number;
  /** Concurrent streams per authenticated identity (3.3); default 4, a safe integer of at least 1. */
  readonly maxConcurrentStreams?: number;
  /** Lifetime of one stream (3.4); default 3600000 ms, a safe integer of at least 1. */
  readonly maxStreamDurationMs?: number;
  /** Heartbeat suggestion (3.5), a positive safe integer; default and ceiling are `floor(windowSeconds * 500)`. */
  readonly heartbeatMs?: number;
  /** The server's own response-verification window W; default 30 s, an integer in 1..120. */
  readonly windowSeconds?: number;
  /** The 5.1 successor activation of the opening key, or undefined when none is known. */
  readonly successorActivation?: (kid: string) => number | undefined;
  /** The 2.4 sid bytes: 16 CSPRNG bytes, drawn with `crypto.randomBytes(16)` by default; injectable for tests. */
  readonly sidSource?: () => Uint8Array;
  /** Stream scheduler; defaults to the pump's unref'd timer. */
  readonly schedule?: (callback: () => void, delayMs: number) => unknown;
  /** Cancels a handle returned by `schedule`; defaults to the pump timer cancellation. */
  readonly cancelSchedule?: (handle: unknown) => void;
}

/** Stream settings with every default applied and every limit checked. */
export interface ResolvedStreamOptions {
  readonly frameMaxBytes: number;
  readonly maxConcurrentStreams: number;
  readonly maxStreamDurationMs: number;
  /** The granted value: `min(requested ?? floor(W * 500), floor(W * 500))` (3.5). */
  readonly heartbeatMs: number;
  readonly windowSeconds: number;
  readonly successorActivation?: (kid: string) => number | undefined;
  readonly sidSource: () => Uint8Array;
  readonly schedule?: (callback: () => void, delayMs: number) => unknown;
  readonly cancelSchedule?: (handle: unknown) => void;
}

// 2.4: a sid is exactly 16 bytes.
const SID_BYTES = 16;
// 3.5: the window of 01 section 4 is configured in seconds, in this range.
const WINDOW_MIN_SECONDS = 1;
const WINDOW_MAX_SECONDS = 120;

/** The 16 CSPRNG bytes of one sid (2.4); a source that returns anything else is refused, never encoded short. */
function defaultSidSource(): Uint8Array {
  const bytes = new Uint8Array(randomBytes(SID_BYTES));
  if (bytes.length !== SID_BYTES) {
    throw new Error("server: stream sid must be 16 bytes");
  }
  return bytes;
}

/**
 * Validates every raw stream setting and applies the spec 05 defaults; absent
 * options mean the defaults. A limit that would silently disable itself (a
 * non-integer, zero, a negative or a non-safe number) is a configuration
 * error and throws like the other HandlerConfig validations.
 */
export function resolveStreamOptions(options: StreamServerOptions | undefined): ResolvedStreamOptions {
  const frameMaxBytes = options?.frameMaxBytes ?? STREAM_DEFAULT_FRAME_MAX_BYTES;
  if (!Number.isSafeInteger(frameMaxBytes) || frameMaxBytes < STREAM_MIN_FRAME_MAX_BYTES) {
    throw new Error("server: streams.frameMaxBytes must be a safe integer of at least 1024");
  }
  const maxConcurrentStreams = options?.maxConcurrentStreams ?? STREAM_DEFAULT_MAX_CONCURRENT_STREAMS;
  if (!Number.isSafeInteger(maxConcurrentStreams) || maxConcurrentStreams < 1) {
    throw new Error("server: streams.maxConcurrentStreams must be a positive safe integer");
  }
  const maxStreamDurationMs = options?.maxStreamDurationMs ?? STREAM_DEFAULT_MAX_DURATION_MS;
  if (!Number.isSafeInteger(maxStreamDurationMs) || maxStreamDurationMs < 1) {
    throw new Error("server: streams.maxStreamDurationMs must be a positive safe integer");
  }
  const windowSeconds = options?.windowSeconds ?? STREAM_DEFAULT_WINDOW_SECONDS;
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < WINDOW_MIN_SECONDS || windowSeconds > WINDOW_MAX_SECONDS) {
    throw new Error("server: streams.windowSeconds must be an integer between 1 and 120 seconds");
  }
  const requested = options?.heartbeatMs;
  if (requested !== undefined && (!Number.isSafeInteger(requested) || requested <= 0)) {
    throw new Error("server: streams.heartbeatMs must be a positive safe integer");
  }
  // 3.5: a suggestion above floor(W * 500) is clamped, never honoured.
  const heartbeatMs = grantedHeartbeatMs(requested, windowSeconds);
  const successorActivation = options?.successorActivation;
  if (successorActivation !== undefined && typeof successorActivation !== "function") {
    throw new Error("server: streams.successorActivation must be a function");
  }
  const supplied = options?.sidSource;
  if (supplied !== undefined && typeof supplied !== "function") {
    throw new Error("server: streams.sidSource must be a function");
  }
  const source = supplied ?? defaultSidSource;
  // 2.4: the length rule is enforced for injected sources as well, so no other
  // module has to re-check what a source claims to be.
  const sidSource = (): Uint8Array => {
    const bytes = source();
    if (!(bytes instanceof Uint8Array) || bytes.length !== SID_BYTES) {
      throw new Error("server: stream sid must be 16 bytes");
    }
    return bytes;
  };
  return {
    frameMaxBytes,
    maxConcurrentStreams,
    maxStreamDurationMs,
    heartbeatMs,
    windowSeconds,
    // A conditional spread keeps exactOptionalPropertyTypes satisfied.
    ...(successorActivation === undefined ? {} : { successorActivation }),
    sidSource,
    ...(options?.schedule === undefined ? {} : { schedule: options.schedule }),
    ...(options?.cancelSchedule === undefined ? {} : { cancelSchedule: options.cancelSchedule }),
  };
}

/**
 * The 3.3 concurrency limit per authenticated identity. A slot is taken before
 * the first stream byte and released by the stream's one close hook, so a
 * refusal can still be a signed v1 response; the returned release is
 * idempotent because every close path may reach it.
 */
export class StreamAdmission {
  private readonly max: number;
  private readonly active = new Map<string, number>();

  constructor(maxConcurrentStreams: number) {
    if (!Number.isSafeInteger(maxConcurrentStreams) || maxConcurrentStreams < 1) {
      throw new Error("server: maxConcurrentStreams must be a positive safe integer");
    }
    this.max = maxConcurrentStreams;
  }

  /** Takes one slot for `identity`; undefined when it is already at the limit, otherwise the idempotent release. */
  acquire(identity: string): (() => void) | undefined {
    const active = this.active.get(identity) ?? 0;
    if (active >= this.max) {
      return undefined;
    }
    this.active.set(identity, active + 1);
    let released = false;
    return (): void => {
      if (released) {
        return;
      }
      released = true;
      const current = this.active.get(identity) ?? 0;
      if (current <= 1) {
        // Drop the entry so identities that stopped streaming leave no state.
        this.active.delete(identity);
      } else {
        this.active.set(identity, current - 1);
      }
    };
  }
}

/**
 * The 3.3 refusal body, exactly the signed v1 JSON-RPC response the spec
 * names. `idText` is the request's raw id lexeme, never re-encoded.
 */
export function streamLimitBody(idText: string): Uint8Array {
  return new TextEncoder().encode(
    '{"jsonrpc":"2.0","id":' + idText + ',"error":{"code":-32603,"message":"stream_limit_exceeded"}}',
  );
}

/** What the wrapped handler observes about the one stream it is answering (3.5, 3.7). */
export interface JackStreamContext {
  /** The 2.4 stream identifier every frame is signed with. */
  readonly sid: string;
  /** The 3.5 grant the handler may use for its own heartbeat notifications. */
  readonly heartbeatMs: number;
  /** The 3.2 cap on one data value. */
  readonly frameMaxBytes: number;
  /** 3.7: aborted when the client disconnects or the stream closes. */
  readonly signal: AbortSignal;
}

/**
 * SDK-PRIVATE stream storage, keyed like `identities` in fetch.ts by the
 * request object the adapter hands to the wrapped handler: the same
 * association boundary, so a copied Request carries no stream context and
 * handler code can neither discover nor replace the entry.
 */
const contexts = new WeakMap<object, JackStreamContext>();

/** The stream context of a forwarded request the wrapped handler sees; undefined for any other request. */
export function jackStream(req: Request): JackStreamContext | undefined {
  return contexts.get(req);
}

/** @internal Associates one stream's context with the forwarded request the wrapped handler sees. */
export function attachJackStream(req: Request, context: JackStreamContext): void {
  contexts.set(req, context);
}

/**
 * Everything the stream response of one forwarded request needs from fetch.ts
 * (`forward`): the 3.3 slot and the identity that owns it, the 2.4 sid already
 * drawn for the handler, the 3.1/5.1 key opening, and fetch's own v1 refusal
 * answers, so that this module writes exactly the bytes the inline block did.
 */
export interface StreamHandoff {
  /** The resolved stream limits of the deployment (3.2, 3.4, 5.1). */
  readonly options: ResolvedStreamOptions;
  /** The 3.3 concurrency gate. */
  readonly admission: StreamAdmission;
  /** The authenticated identity whose slot the stream takes. */
  readonly identity: string;
  /** The 2.4 sid, drawn once and already exposed to the handler (3.5/3.7). */
  readonly sid: string;
  /** The opening request's raw JSON-RPC id lexeme (3.3, 6.3), never re-encoded. */
  readonly rpcId: string;
  /** 3.7: aborted on every close path, a stream that never opens included. */
  readonly abort: AbortController;
  /** The handler's 200 text/event-stream answer (1.4). */
  readonly handlerResponse: Response;
  /** The exact request body bytes, classified for the 6.3 completion. */
  readonly body: Uint8Array;
  /** Unix seconds of the server clock (2.5, 2.15). */
  readonly clock: () => number;
  /** The `sig` parameter of the v1 request that opened the stream (2.5). */
  readonly requestSig: string;
  /** The request's tool name, reported to the rotation response gate. */
  readonly tool: string;
  /** 3.1/5.1: the one key of this stream and its open timestamp; undefined is the unsigned 503. */
  readonly openKey: () => { readonly key: StreamSigningKey; readonly openerTs: number } | undefined;
  /** The signed v1 429 of an identity at its 3.3 limit. */
  readonly refuseLimit: () => Response;
  /** The unsigned 503 of a key that cannot be opened (writeAuthorized's refusal). */
  readonly refuseRotation: () => Response;
  /** 5.1: the successor activation of a kid, or undefined when none is known. */
  readonly successorActivation?: (kid: string) => number | undefined;
}

/**
 * Builds the 2.1 stream response of one forwarded 1.4 handler answer: the 3.3
 * slot first, then the 3.1/5.1 key opening, the 2.5 signer and the pump. Every
 * failure frees the slot, aborts the handler context (3.7) and cancels the
 * handler body, so no path leaks either; only the refusal bytes themselves stay
 * fetch.ts's, because those are v1 response bytes.
 */
export function startSignedStream(handoff: StreamHandoff): Response {
  const options = handoff.options;
  const rpcId = handoff.rpcId;
  const abort = handoff.abort;
  const resp = handoff.handlerResponse;
  // 3.7: a stream that never opens still cancels the handler body. The cancel is
  // not awaited: the refusal already in hand must never wait on it, and a
  // rejection cannot mask it.
  const cancelHandler = (): void => {
    try {
      void resp.body?.cancel().catch((): void => {
        /* the refusal already in hand must not be masked */
      });
    } catch {
      /* the same, for a cancel that throws synchronously */
    }
  };
  // 3.3: the slot is taken before a single stream byte exists, so an identity at
  // its limit still gets a complete signed v1 answer.
  const release = handoff.admission.acquire(handoff.identity);
  if (release === undefined) {
    const out = handoff.refuseLimit();
    abort.abort();
    cancelHandler();
    return out;
  }
  const failedOpen = (): Response => {
    // 3.3/3.7: a stream that fails to open frees the slot and cancels the
    // handler like every other close path does.
    release();
    abort.abort();
    cancelHandler();
    return handoff.refuseRotation();
  };
  // 3.1/5.1: one key signs the open header and every frame, and the open
  // timestamp is that key's. A stream whose key cannot be opened writes no byte.
  const opened = handoff.openKey();
  if (opened === undefined) {
    return failedOpen();
  }
  try {
    // 2.5: the signer of this one stream, on the sid already drawn.
    const signer = new StreamSigner({
      key: opened.key,
      requestSig: handoff.requestSig,
      sid: handoff.sid,
      openerTs: opened.openerTs,
      status: 200,
    });
    // 6.3: the final response a server-initiated close may still write. Only an
    // events/stream request has one; the id text is the request's own lexeme.
    const request = classifyBody(handoff.body);
    const completion = (): string | undefined =>
      request?.method === "events/stream"
        ? '{"jsonrpc":"2.0","id":' + rpcId + ',"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":' + rpcId + '}}}'
        : undefined;
    const requestId: unknown = JSON.parse(rpcId);
    const pump = new StreamPump({
      signer,
      limits: { frameMaxBytes: options.frameMaxBytes, maxStreamDurationMs: options.maxStreamDurationMs },
      now: handoff.clock,
      requestId,
      completion,
      // 5.1: the successor activation is re-read per frame, so a cutoff learned
      // while the stream runs still caps every later frame ts.
      successorActivation: (): number | undefined => handoff.successorActivation?.(signer.kid),
      ...(options.schedule === undefined ? {} : { schedule: options.schedule }),
      ...(options.cancelSchedule === undefined ? {} : { cancelSchedule: options.cancelSchedule }),
      // 3.3/3.7: the pump closes once, releasing the slot and cancelling the
      // handler whichever way the stream ends.
      onClose: (): void => {
        release();
        abort.abort();
      },
    });
    // 2.1: a stream carries only its own headers; the open value is the single
    // Jack-Auth the client verifies first. Nothing of the handler answer
    // survives, least of all a content-length, because the body bytes are the
    // signed frames.
    const headers = new Headers();
    headers.set("content-type", "text/event-stream");
    headers.set("x-accel-buffering", "no");
    headers.set("jack-auth", pump.openAuthValue);
    headers.delete("content-length");
    return new Response(pump.pump(resp.body), { status: 200, headers });
  } catch (error) {
    // A stream that cannot be built must not hold a slot or a handler.
    release();
    abort.abort();
    cancelHandler();
    throw error;
  }
}
