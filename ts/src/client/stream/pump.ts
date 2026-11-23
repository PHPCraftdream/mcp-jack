/**
 * Verified-stream machinery shared by both stream doors of the client (spec 05
 * sections 4.1 routing, 4.2 open header, 4.3 frames, 4.4 truncation, 4.5 idle,
 * 4.7 verify first and the 6.1 re-emitting view): the pump that verifies one
 * `s1` response and the option builder both doors use.
 *
 * One pump feeds two views over the same verified data values: `messages()`
 * yields the data values in order and `sse()` yields the 6.1 bytes. No byte of
 * the server body reaches a consumer before its frame passed 4.3 step 5, and a
 * failure stops the pump after the frames that already verified (4.4).
 *
 * No runtime import crosses into the transport: the config types arrive only
 * as erased type imports, so `session -> pump` and `transport -> pump` stay
 * acyclic.
 */
import { keyId } from "../../core/encoding.js";
import { STREAM_DEFAULT_IDLE_MS, StreamVerifyError } from "../../stream/codes.js";
import { StreamVerifier } from "../../stream/verify.js";
import type { StreamServerKey, StreamVerifyOptions, StreamVerifyResult } from "../../stream/verify.js";
import type { SigningFetchConfig } from "../transport/transport.js";
import { reemitSseMessage } from "./sse.js";
import type { StreamClientOptions } from "./session.js";

/**
 * @internal: the StreamVerifyOptions of both stream doors (the transport's
 * re-emitting path and openSignedStream), from the transport config, the stream
 * options and the request signature of 2.5.
 *
 * `resolveKey` defaults to the pinned server key; `now` is the transport clock
 * so the 4.2/4.3 window agrees with the v1 response path. Limits are passed
 * through unvalidated: StreamVerifier validates them and applies the defaults.
 */
export function streamVerifyOptions(config: SigningFetchConfig, streams: StreamClientOptions, requestSig: string): StreamVerifyOptions {
  const pinnedKid = keyId(config.serverKey);
  const resolveKey =
    streams.resolveKey ??
    ((kid: string): StreamServerKey | undefined => (kid === pinnedKid ? { kid, publicKey: config.serverKey } : undefined));
  // The v1 window treats <= 0 as the default; the stream verifier rejects 0, so
  // only a positive value is forwarded and the verifier keeps its own default.
  const windowSeconds = config.windowSeconds !== undefined && config.windowSeconds > 0 ? config.windowSeconds : undefined;
  return {
    resolveKey,
    now: config.clock ?? wallClockSeconds,
    requestSig,
    ...(windowSeconds !== undefined ? { windowSeconds } : {}),
    ...(streams.streamIdleMs !== undefined ? { streamIdleMs: streams.streamIdleMs } : {}),
    ...(streams.frameMaxBytes !== undefined ? { frameMaxBytes: streams.frameMaxBytes } : {}),
    ...(streams.consumer !== undefined ? { consumer: streams.consumer } : {}),
  };
}

/**
 * @internal: the transport's re-emitting path, shared with openSignedStream.
 * Verifies the open header (a failure throws here, after closing the body) and
 * returns the 6.1 stream plus the never-rejecting terminal promise.
 */
export function verifiedStreamResponse(input: {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: ReadableStream<Uint8Array> | null;
  readonly requestSig: string;
  readonly requestId?: unknown;
  readonly options: StreamVerifyOptions;
  readonly abort: AbortController;
}): { readonly sse: ReadableStream<Uint8Array>; readonly done: Promise<StreamVerifyResult> } {
  // `requestId` is 6.3 bookkeeping for the caller: the pump never parses data
  // (4.7), so it only has to keep the terminal honest.
  const pump = startVerifiedStream(input);
  return { sse: pump.sse, done: pump.done };
}

/** The response and settings one pump verifies. */
export interface VerifiedStreamInput {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: ReadableStream<Uint8Array> | null;
  readonly requestSig: string;
  /** The opening request's JSON-RPC id (6.3): caller bookkeeping only, the pump never parses data (4.7). */
  readonly requestId?: unknown;
  readonly options: StreamVerifyOptions;
  readonly abort: AbortController;
}

/** @internal: creates and starts the one pump of a response; a failed open header closes the body and throws (4.1). */
export function startVerifiedStream(input: VerifiedStreamInput): StreamPump {
  try {
    const pump = new StreamPump(input);
    pump.start();
    return pump;
  } catch (err) {
    // 4.1: no frame is read when the open header failed, and the connection closes.
    input.abort.abort();
    const body = input.body;
    if (body !== null) {
      void body.cancel().catch(() => undefined);
    }
    throw err;
  }
}

/** @internal: one verified stream, the verifier, the two views over its data values, and the terminal. */
export class StreamPump {
  readonly sid: string;
  readonly sse: ReadableStream<Uint8Array>;
  readonly done: Promise<StreamVerifyResult>;

  private readonly verifier: StreamVerifier;
  private readonly body: ReadableStream<Uint8Array> | null;
  private readonly abort: AbortController;
  private readonly idleMs: number;
  private readonly startedAt: number;
  private readonly settled = deferred<StreamVerifyResult>();
  // One queue, two independently activated cursors. A late view starts at the
  // retained queue's beginning; it cannot recover entries already dropped.
  private readonly values: string[] = [];
  private readonly waiters: (() => void)[] = [];
  // A parked body read: demand() resolves this when the consumer catches up.
  private readonly demanders: (() => void)[] = [];
  private sseNext = 0;
  private messageNext = 0;
  private messagesActive = false;
  private sseActive = false;
  private lastVerifiedMs = 0; // 0 is the moment the open header verified (4.5)
  private parkedMs = 0; // backpressure time in demand(): our own pause, not server silence (4.5)
  private verifiedFrames = 0;
  private reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  private failure: StreamVerifyError | undefined;
  private finished = false;
  private cancelled = false;
  private cancelling: Promise<void> | undefined;

  constructor(input: VerifiedStreamInput) {
    // The sink is an arrow field, so it is bound before the constructor body
    // runs: the verifier pushes each verified value into this queue and keeps
    // no history of its own.
    this.verifier = new StreamVerifier({ ...input.options, requestSig: input.requestSig, onMessage: this.onVerified });
    this.idleMs = input.options.streamIdleMs ?? STREAM_DEFAULT_IDLE_MS;
    this.body = input.body;
    this.abort = input.abort;
    this.sid = this.verifier.open(input.status, input.headers);
    this.startedAt = nowMs();
    this.done = this.settled.promise;
    // High water mark 0 keeps the whole stream a pure view: one chunk is
    // enqueued per pending read, so a failure errors only after the verified
    // bytes have been read out instead of discarding them.
    this.sse = new ReadableStream<Uint8Array>(
      {
        pull: (controller) => this.pullSse(controller),
        cancel: () => this.cancel(),
      },
      { highWaterMark: 0 },
    );
  }

  /** The verifier sink: one verified data value straight into the shared queue (4.7). */
  private readonly onVerified = (data: string): void => {
    this.values.push(data);
    this.notify();
  };

  /** Starts the body pump; both views drain what it verifies. */
  start(): void {
    void this.run();
  }

  messages(): AsyncIterableIterator<string> {
    if (!this.messagesActive) {
      this.messagesActive = true;
      this.messageNext = 0;
      this.wakeDemand();
    }
    return this.iterate();
  }

  /** Closes the connection, stops the body and resolves `done`; idempotent. */
  cancel(): Promise<void> {
    if (this.cancelling === undefined) {
      this.cancelling = this.doCancel();
    }
    return this.cancelling;
  }

  private async doCancel(): Promise<void> {
    this.cancelled = true;
    this.abort.abort();
    // A parked body read must not outlive the cancel.
    this.wakeDemand();
    const reader = this.reader;
    if (reader !== undefined) {
      try {
        await reader.cancel();
      } catch {
        // The body may already be closed; `done` still resolves.
      }
    }
    // 4.4: a cancelled body never saw an end frame, so it ends truncated.
    this.finish(this.elapsed());
  }

  /** The body loop: read, verify, deliver, repeat until the terminal. */
  private async run(): Promise<void> {
    const body = this.body;
    if (body === null) {
      // An empty body has no end frame: 4.4 truncation, measured at 0 ms.
      this.finish(0);
      return;
    }
    const reader = body.getReader();
    this.reader = reader;
    try {
      for (;;) {
        // Backpressure: wait for the consumer before reading (and before the
        // idle timer arms), so an idle consumer never sees network reads.
        const parkedAt = nowMs();
        await this.demand();
        this.parkedMs += nowMs() - parkedAt; // a parked pump must not look like a silent server
        if (this.finished) {
          return; // cancelled while parked; `done` already stands
        }
        // 4.5: the deadline runs from the last verified frame, so the wait is
        // what is left of it; +1 ms because a silence equal to it is alive.
        const remaining = this.idleMs - (this.elapsed() - this.lastVerifiedMs);
        const read = await readBeforeIdle(reader, Math.max(1, remaining + 1));
        if (read.kind === "idle") {
          // idle() throws stream_idle; it returns only when the end frame is in.
          let idleError: unknown;
          try {
            this.verifier.idle(this.elapsed());
          } catch (err) {
            idleError = err;
          }
          if (idleError === undefined) {
            this.finish(this.elapsed());
          } else {
            this.stop(idleError, reader);
          }
          return;
        }
        if (read.kind === "end") {
          this.finish(this.elapsed());
          return;
        }
        const arrived = this.elapsed();
        let frameError: unknown;
        try {
          this.verifier.push(read.value, arrived);
        } catch (err) {
          frameError = err;
        }
        // 4.4: frames that verified inside this chunk already reached the queue
        // through the sink, also when a later event of the same chunk failed.
        if (frameError !== undefined) {
          this.stop(frameError, reader);
          return;
        }
        if (this.verifier.framesVerified !== this.verifiedFrames) {
          this.verifiedFrames = this.verifier.framesVerified;
          this.lastVerifiedMs = arrived; // only a verified frame restarts 4.5
        }
      }
    } catch {
      // A read error ends the body without an end frame (4.4 truncation).
      this.finish(this.elapsed());
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // The reader may still hold the abandoned read of an idle exit.
      }
    }
  }

  /** Stops after the failing frame: the connection closes and no later byte is read. */
  private stop(err: unknown, reader: ReadableStreamDefaultReader<Uint8Array>): void {
    this.abort.abort();
    void reader.cancel().catch(() => undefined);
    if (err instanceof StreamVerifyError) {
      // The verifier already latched this terminal and throws it to the views.
      this.finish(this.elapsed(), err);
      return;
    }
    // Not a stream code (a transport error): the body ended incomplete.
    this.finish(this.elapsed());
  }

  /** Latches the terminal once; `done` resolves with verifier.end(...) and never rejects. */
  private finish(arrivedAtMs: number, failure?: StreamVerifyError): void {
    if (this.finished) {
      return;
    }
    this.finished = true;
    const result = this.verifier.end(arrivedAtMs);
    this.failure =
      failure ?? (result.terminal.state === "error" ? new StreamVerifyError(result.terminal.code, result.terminal.framesVerified) : undefined);
    // end() may sink the frames the reader still held, so trim once here too.
    this.trim();
    this.notify();
    this.wakeDemand();
    this.settled.resolve(result);
  }

  /**
   * Resolves once the body may read again: immediately while the unconsumed
   * queue is under the high-water mark, a view is waiting, or the stream is
   * over; otherwise it parks until a consume, a waiting view or the terminal.
   */
  private demand(): Promise<void> {
    if (this.finished || this.cancelled || this.waiters.length > 0) {
      return Promise.resolve();
    }
    const active = this.messagesActive || this.sseActive;
    const messagesBelowLimit = !this.messagesActive || this.values.length - this.messageNext < QUEUE_HIGH_WATER_MARK;
    const sseBelowLimit = !this.sseActive || this.values.length - this.sseNext < QUEUE_HIGH_WATER_MARK;
    if (active && messagesBelowLimit && sseBelowLimit) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.demanders.push(resolve);
    });
  }

  /** Releases every parked body read so it re-evaluates demand(). */
  private wakeDemand(): void {
    const parked = this.demanders.splice(0);
    for (const wake of parked) {
      wake();
    }
  }

  /** One 6.1 event per verified message; queued bytes go out before a failure errors the view. */
  private async pullSse(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
    if (!this.sseActive) {
      this.sseActive = true;
      this.sseNext = 0;
      this.wakeDemand();
    }
    for (;;) {
      if (this.cancelled) {
        return; // the consumer cancelled the view; the controller is closed
      }
      const data = this.values[this.sseNext];
      if (data !== undefined) {
        this.sseNext += 1;
        this.trim();
        this.wakeDemand();
        controller.enqueue(reemitSseMessage(data));
        return;
      }
      if (this.finished) {
        const failure = this.failure;
        if (failure !== undefined) {
          controller.error(failure); // after every byte that already verified
        } else {
          controller.close();
        }
        return;
      }
      await this.wait();
    }
  }

  private async *iterate(): AsyncGenerator<string, void, undefined> {
    for (;;) {
      const data = this.nextMessage();
      if (data !== undefined) {
        yield data;
        continue;
      }
      if (this.finished) {
        const failure = this.failure;
        if (failure !== undefined) {
          throw failure; // after every message that already verified (4.4)
        }
        return;
      }
      await this.wait();
    }
  }

  /** The next verified data value, or undefined while the queue is empty (2.9 keeps message data non-empty). */
  private nextMessage(): string | undefined {
    const data = this.values[this.messageNext];
    if (data === undefined) {
      return undefined;
    }
    this.messageNext += 1;
    this.trim();
    this.wakeDemand();
    return data;
  }

  /** Drops the prefix consumed by active views so a long stream stays bounded. */
  private trim(): void {
    let passed = 0;
    if (this.messagesActive && this.sseActive) {
      passed = Math.min(this.messageNext, this.sseNext);
    } else if (this.messagesActive) {
      passed = this.messageNext;
      this.sseNext = 0;
    } else if (this.sseActive) {
      passed = this.sseNext;
      this.messageNext = 0;
    }
    if (passed > 0) {
      this.values.splice(0, passed);
      if (this.messagesActive) {
        this.messageNext -= passed;
      } else {
        this.messageNext = 0;
      }
      if (this.sseActive) {
        this.sseNext -= passed;
      } else {
        this.sseNext = 0;
      }
    }
  }

  /** Wakes every view waiting for the next verified value or for the terminal. */
  private notify(): void {
    const waiters = this.waiters.splice(0);
    for (const wake of waiters) {
      wake();
    }
  }

  private wait(): Promise<void> {
    const waiting = new Promise<void>((resolve) => {
      this.waiters.push(resolve);
    });
    // A view that wants data is a consumer: the body may read again.
    this.wakeDemand();
    return waiting;
  }

  /** Milliseconds since the open header verified, minus parked time: the origin of the 4.5 deadline. */
  private elapsed(): number {
    return nowMs() - this.startedAt - this.parkedMs;
  }
}

/** Verified values kept ahead of an idle consumer before the pump parks (bounded memory). */
const QUEUE_HIGH_WATER_MARK = 8;

/** Outcome of one body read raced against the 4.5 deadline. */
type VerifiedRead =
  | { readonly kind: "chunk"; readonly value: Uint8Array }
  | { readonly kind: "end" }
  | { readonly kind: "idle" };

/** One body read raced against the idle deadline; the timer is cleared on every exit that still owns it. */
function readBeforeIdle(reader: ReadableStreamDefaultReader<Uint8Array>, waitMs: number): Promise<VerifiedRead> {
  return new Promise<VerifiedRead>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      resolve({ kind: "idle" });
    }, waitMs);
    (timer as { unref?: () => void }).unref?.();
    reader.read().then(
      (result) => {
        if (settled) {
          return; // past the deadline the late chunk is never verified (4.5)
        }
        settled = true;
        clearTimeout(timer);
        if (result.done) {
          resolve({ kind: "end" });
          return;
        }
        resolve({ kind: "chunk", value: result.value ?? new Uint8Array(0) });
      },
      (err: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/** A promise and its resolver: `done` is resolved once and never rejected. */
function deferred<T>(): { readonly promise: Promise<T>; readonly resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

/** One sampling point for 4.5, which only ever compares differences. */
function nowMs(): number {
  return Date.now();
}

/** @internal: the signing clock default, the same wall-clock seconds the v1 response path reads. */
export function wallClockSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
