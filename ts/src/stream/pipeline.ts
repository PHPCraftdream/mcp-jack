/**
 * Server-side stream pump of signed streams (spec 05 sections 2.12, 2.17, 2.18,
 * 3.2, 3.4, 3.7, 5.1 and 6.3).
 *
 * The pump turns a wrapped handler's `text/event-stream` body into the signed
 * `s1` body: every completed handler event is plain SSE, not a signed frame,
 * and is re-signed by a `StreamSigner`, so no handler byte reaches the wire
 * unsigned. The pump owns the end frame (2.16), and every close shape is one
 * of the three the spec names: the 3.2 oversize signal, the 3.4 duration close
 * and the 6.3 final response. Comments (2.12) and handler `jack-end` events
 * are dropped.
 *
 * The open header is a response header, so the pump only exposes its value
 * (`Jack-Auth` of 2.1). Section 5.1 caps every signature below the opening
 * key's successor activation, per frame and by an armed timer, so a stream
 * that falls quiet still ends below the cutoff; 3.7 cancels the handler body
 * on every exit path, and `onClose` releases the 3.3 concurrency slot once.
 */
import { clearTimeout, setTimeout } from "node:timers";
import type { SignedStreamFrame, StreamSigner } from "./signer.js";
import type { StreamLine } from "./wire.js";
import {
  decodeUtf8Strict,
  StreamEventOverflow,
  StreamEventReader,
  streamEventMaxBytes,
  streamFinalResponseFor,
} from "./wire.js";

const ENCODER = new TextEncoder();

/** The 2.17/3.2 and 3.4 budgets of one stream. */
export interface StreamPumpLimits {
  /** Bounds the UTF-8 data value of a message frame (2.17/3.2). */
  readonly frameMaxBytes: number;
  /** The maximum lifetime of the stream in milliseconds (3.4). */
  readonly maxStreamDurationMs: number;
}

/** Everything the pump needs: the signer, the budgets, the clock and the 6.3 close hooks. */
export interface StreamPumpOptions {
  readonly signer: StreamSigner;
  readonly limits: StreamPumpLimits;
  /** Unix seconds, sampled once per signed frame. */
  readonly now: () => number;
  /** The JSON-RPC id of the opening request; only this id completes it (6.3). */
  readonly requestId?: unknown;
  /** The 6.3 final-response data value, or undefined when none can be written. */
  readonly completion?: () => string | undefined;
  /**
   * The successor activation of the opening key (5.1), or undefined when none
   * is known. A callback because the activation can be learned or moved while
   * the stream runs: the pump re-reads it per frame, per armed timer and at close.
   */
  readonly successorActivation?: () => number | undefined;
  /** Schedules `callback` after `delayMs`; defaults to `setTimeout` of `node:timers`. */
  readonly schedule?: (callback: () => void, delayMs: number) => unknown;
  /** Cancels a handle `schedule` returned; defaults to `clearTimeout` of `node:timers`. */
  readonly cancelSchedule?: (handle: unknown) => void;
  /** Runs exactly once on every path, closing or cancelled; releases the 3.3 slot. */
  readonly onClose?: () => void;
}

/** The part of a stream controller the pump uses. */
interface ByteController {
  enqueue(chunk: Uint8Array): void;
  close(): void;
}

/** The part of a body reader the pump uses: 3.7 only needs to cancel it. */
interface Cancelable {
  cancel(): Promise<void>;
}

/** What one handler event becomes: a signable message, nothing, or the 6.3 close. */
type HandlerEvent =
  | { readonly kind: "message"; readonly data: string }
  | { readonly drop: true }
  | { readonly close: true };

/**
 * Parses one handler event from the handler's side of 2.8-2.13. The handler
 * emits ordinary SSE and never a `jack` line (the server owns the signature),
 * so `jack`, `id` and `retry` are dropped instead of required or rejected.
 */
function parseHandlerEvent(lines: readonly StreamLine[]): HandlerEvent {
  let kind: "message" | "jack-end" | null = null;
  const data: string[] = [];
  for (const line of lines) {
    const value = decodeUtf8Strict(line.value);
    if (value === null) {
      // 2.10: a value that is not valid UTF-8 can never be signed.
      return { close: true };
    }
    if (line.name === "event") {
      if (kind !== null || (value !== "message" && value !== "jack-end")) {
        return { close: true }; // 2.8: a duplicate or unknown event name is a handler bug.
      }
      kind = value;
    } else if (line.name === "data") {
      data.push(value);
    }
    // 2.11-2.13: `jack` carries no data and `id`, `retry` and unknown fields are never forwarded.
  }
  const dataValue = data.join("\n"); // 2.10
  if (kind === "jack-end" || dataValue === "") {
    // 2.16: the pump writes the end frame; 2.9 keeps a message frame's data non-empty.
    return { drop: true };
  }
  return { kind: "message", data: dataValue };
}

/** Signs a handler's SSE body into the `s1` stream body of spec 05. */
export class StreamPump {
  private readonly signer: StreamSigner;
  private readonly frameMaxBytes: number;
  private readonly maxDurationMs: number;
  private readonly clock: () => number;
  private readonly requestId: unknown;
  private readonly completion: (() => string | undefined) | undefined;
  private readonly cutoffOf: () => number | undefined;
  private readonly schedule: (callback: () => void, delayMs: number) => unknown;
  private readonly cancelSchedule: (handle: unknown) => void;
  private readonly onClose: (() => void) | undefined;

  constructor(options: StreamPumpOptions) {
    const signer = options.signer;
    if (signer === undefined || signer === null) {
      throw new Error("server: StreamPumpOptions.signer must be set");
    }
    const limits = options.limits;
    if (limits === undefined || limits === null) {
      throw new Error("server: StreamPumpOptions.limits must be set");
    }
    if (!Number.isSafeInteger(limits.frameMaxBytes) || limits.frameMaxBytes < 0) {
      throw new Error("server: frameMaxBytes must be a non-negative safe integer");
    }
    if (!Number.isSafeInteger(limits.maxStreamDurationMs) || limits.maxStreamDurationMs < 0) {
      throw new Error("server: maxStreamDurationMs must be a non-negative safe integer");
    }
    if (typeof options.now !== "function") {
      throw new Error("server: StreamPumpOptions.now must be a function");
    }
    const cutoffOf = options.successorActivation;
    if (cutoffOf !== undefined && typeof cutoffOf !== "function") {
      throw new Error("server: StreamPumpOptions.successorActivation must be a function");
    }
    const schedule = options.schedule ?? ((callback: () => void, delayMs: number): unknown => setTimeout(callback, delayMs));
    const cancelSchedule = options.cancelSchedule ?? ((handle: unknown): void => {
      clearTimeout(handle as Parameters<typeof clearTimeout>[0]);
    });
    if (typeof schedule !== "function" || typeof cancelSchedule !== "function") {
      throw new Error("server: StreamPumpOptions.schedule and cancelSchedule must be functions");
    }
    this.signer = signer;
    this.frameMaxBytes = limits.frameMaxBytes;
    this.maxDurationMs = limits.maxStreamDurationMs;
    this.clock = options.now;
    this.requestId = options.requestId;
    this.completion = options.completion;
    // Absent means no known cutoff (5.1): every frame is signable and no timer is armed.
    this.cutoffOf = cutoffOf ?? ((): number | undefined => undefined);
    this.schedule = schedule;
    this.cancelSchedule = cancelSchedule;
    this.onClose = options.onClose;
  }

  /** The stream identifier every frame of this stream is signed with (2.4). */
  get sid(): string {
    return this.signer.sid;
  }

  /** The single kid of the open header and of every frame (3.1). */
  get kid(): string {
    return this.signer.kid;
  }

  /** The 2.1 `Jack-Auth` response header value; the pump never writes it into the body. */
  get openAuthValue(): string {
    return this.signer.openAuthValue();
  }

  /**
   * Pumps `body` into a stream of signed frame bytes. The returned stream
   * carries no open header and no unsigned byte; `null` is an empty stream that
   * still gets its end frame.
   */
  pump(body: ReadableStream<Uint8Array> | null): ReadableStream<Uint8Array> {
    const signer = this.signer;
    const frameMaxBytes = this.frameMaxBytes;
    const maxDurationMs = this.maxDurationMs;
    const clock = this.clock;
    const requestId = this.requestId;
    const completion = this.completion;
    const cutoffOf = this.cutoffOf;
    const schedule = this.schedule;
    const cancelSchedule = this.cancelSchedule;
    const onClose = this.onClose;

    // 2.17/3.2: the reader caps one event's wire size, so an oversize event is
    // signalled instead of buffered unboundedly.
    const events = new StreamEventReader({ maxEventBytes: streamEventMaxBytes(frameMaxBytes) });
    let controller: ByteController | null = null;
    let bodyReader: Cancelable | null = null;
    let durationHandle: unknown;
    let cutoffHandle: unknown;
    // The ts of the last frame written, so the end frame never goes below it (4.3 step 3).
    let previousTs: number | undefined;
    let finalDelivered = false;
    let ended = false; // 2.16: no byte may follow the end frame
    let finished = false; // the stream is closed and the slot released
    let cancelled = false; // the client went away (3.7)

    function stopDuration(): void {
      if (durationHandle !== undefined) {
        cancelSchedule(durationHandle);
        durationHandle = undefined;
      }
    }

    function stopCutoff(): void {
      if (cutoffHandle !== undefined) {
        cancelSchedule(cutoffHandle);
        cutoffHandle = undefined;
      }
    }

    /** Closes once: no byte after this, handler body cancelled (3.7), slot released (3.3). */
    function finish(): void {
      if (finished) {
        return;
      }
      finished = true;
      ended = true;
      stopDuration();
      stopCutoff();
      if (!cancelled && controller !== null) {
        try {
          controller.close();
        } catch {
          // The consumer already closed or errored the stream; nothing is left to close.
        }
      }
      controller = null;
      const reader = bodyReader;
      bodyReader = null;
      if (reader !== null) {
        // 3.7: after the end frame, and on every other exit, the handler is cancelled.
        void reader.cancel().catch(() => {
          // The body is being discarded; a failed cancel changes nothing.
        });
      }
      if (onClose !== undefined) {
        try {
          onClose();
        } catch {
          // A slot release must not turn into a stream failure.
        }
      }
    }

    /** 5.1: at equality the old key is already ineligible, so only ts < cutoff is signable. */
    function signable(ts: number): boolean {
      const a = cutoffOf();
      return a === undefined || ts < a;
    }

    /** The end frame ts: fresh, never below the previous frame, never at or after the cutoff. */
    function endFrameTs(): number {
      const a = cutoffOf();
      const t = clock();
      if (a === undefined || t < a) {
        return previousTs === undefined ? t : Math.max(t, previousTs);
      }
      const below = a - 1;
      return previousTs === undefined ? below : Math.max(previousTs, below);
    }

    /** 5.1: the remaining time to the cutoff, in milliseconds, from the injected clock. */
    function cutoffDelay(a: number): number {
      return Math.max(0, (a - clock()) * 1000);
    }

    /**
     * 5.1: keeps exactly one cutoff timer armed. The activation is re-read here,
     * so a cutoff learned after the open still closes a quiet stream.
     */
    function armCutoff(): void {
      stopCutoff();
      const a = cutoffOf();
      if (a === undefined) {
        return;
      }
      cutoffHandle = schedule(onCutoff, cutoffDelay(a));
    }

    /** 5.1: closes at the cutoff, or re-arms when the activation moved past the clock. */
    function onCutoff(): void {
      cutoffHandle = undefined;
      const a = cutoffOf();
      if (a === undefined) {
        return;
      }
      if (clock() >= a) {
        closeAtCutoff(a);
        return;
      }
      // At least 1 ms, so a stalled clock cannot spin the scheduler.
      cutoffHandle = schedule(onCutoff, Math.max(1, cutoffDelay(a)));
    }

    /** Signs and enqueues one frame; a failing signer closes the stream instead of throwing. */
    function emit(build: () => SignedStreamFrame): boolean {
      if (ended || cancelled) {
        return false;
      }
      let frame: SignedStreamFrame;
      try {
        frame = build();
      } catch {
        // An unbuildable frame must not become an uncaught error out of the stream.
        finish();
        return false;
      }
      if (controller === null) {
        finish();
        return false;
      }
      try {
        controller.enqueue(frame.bytes);
      } catch {
        // The stream left the readable state under us; nothing may be written any more.
        finish();
        return false;
      }
      previousTs = frame.ts;
      // 5.1: every signed frame restarts the wait for the opening key's cutoff.
      armCutoff();
      return true;
    }

    /**
     * 5.1: the cutoff is reached. No message frame is signed now; the stream
     * ends with an end frame below the cutoff and releases the handler body.
     * It runs even when no message frame was ever forwarded.
     */
    function closeAtCutoff(a: number): void {
      if (ended || cancelled) {
        return;
      }
      const below = a - 1;
      // Without a legal ts below the cutoff (a - 1 < 0) the body closes with no end frame.
      const ts = previousTs === undefined ? below : Math.max(previousTs, below);
      if (below < 0 || !Number.isSafeInteger(ts) || ts < 0) {
        finish();
        return;
      }
      emit(() => signer.end(ts));
      finish();
    }

    /** 2.16: the end frame is the last byte of every complete stream. */
    function endStream(): void {
      if (ended || cancelled) {
        return;
      }
      const ts = endFrameTs();
      if (!Number.isSafeInteger(ts) || ts < 0) {
        // No legal ts exists (a cutoff at or below zero); no end frame is better than a bad one.
        finish();
        return;
      }
      emit(() => signer.end(ts));
      finish();
    }

    /** 6.3: the final response when it is still writable, then the end frame. */
    function closeWithCompletion(): void {
      if (ended || cancelled) {
        return;
      }
      if (!finalDelivered && completion !== undefined) {
        let data: string | undefined;
        try {
          data = completion();
        } catch {
          data = undefined;
        }
        const ts = clock();
        // 5.1 covers the completion frame as well: nothing may be signed at the cutoff.
        if (data !== undefined && data !== "" && signable(ts)) {
          if (emit(() => signer.frame(data, ts))) {
            finalDelivered = true;
          }
        }
      }
      endStream();
    }

    /**
     * 3.2: one signal frame, then the end frame; the signal is the last message
     * of its stream. 5.1 outranks it: nothing is signed at or after the cutoff.
     */
    function signalOversize(): void {
      const ts = clock();
      if (!signable(ts)) {
        endStream();
        return;
      }
      if (emit(() => signer.signal("stream_frame_too_large", frameMaxBytes, ts))) {
        endStream();
      }
    }

    /** Handles one completed event; false once forwarding must stop. */
    function forward(lines: readonly StreamLine[]): boolean {
      const parsed = parseHandlerEvent(lines);
      if ("close" in parsed) {
        // An event that cannot be signed closes with the 6.3 shape.
        closeWithCompletion();
        return false;
      }
      if ("drop" in parsed) {
        // 2.16: the pump owns the end frame, so a handler end is dropped.
        return true;
      }
      const ts = clock();
      if (!signable(ts)) {
        // 5.1: stop forwarding and end below the cutoff; no frame is signed here.
        endStream();
        return false;
      }
      if (ENCODER.encode(parsed.data).length > frameMaxBytes) {
        // 2.17/3.2: the cap bounds the data value, not the event bytes; equality is legal.
        signalOversize();
        return false;
      }
      if (!emit(() => signer.frame(parsed.data, ts))) {
        return false;
      }
      if (requestId !== undefined && streamFinalResponseFor(parsed.data, requestId)) {
        finalDelivered = true;
      }
      return true;
    }

    // 3.4: the budget runs from this call, whichever way the body behaves.
    durationHandle = schedule(() => {
      closeWithCompletion();
    }, maxDurationMs);
    // 5.1: a cutoff already known at the open closes a stream that stays quiet.
    armCutoff();

    // The explicit annotation pins the chunk type without relying on inference
    // through the untyped globals of the underlying source.
    const out: ReadableStream<Uint8Array> = new ReadableStream({
      start: (c: unknown): void => {
        controller = c as ByteController;
        try {
          if (body === null) {
            // A null body is an empty stream: end frame only.
            endStream();
            return;
          }
          const reader = body.getReader();
          bodyReader = reader;
          void (async (): Promise<void> => {
            try {
              for (;;) {
                const step = await reader.read();
                if (ended || cancelled) {
                  return;
                }
                if (step.done) {
                  break;
                }
                let completed: StreamLine[][];
                try {
                  completed = events.push(step.value);
                } catch (err) {
                  if (err instanceof StreamEventOverflow) {
                    // Completed events precede the overflowing event in the body.
                    for (const lines of err.completedEvents) {
                      if (!forward(lines)) {
                        return;
                      }
                    }
                    // 2.17/3.2: an event over the cap is signalled, never forwarded.
                    signalOversize();
                    return;
                  }
                  throw err;
                }
                for (const lines of completed) {
                  if (!forward(lines)) {
                    return;
                  }
                }
              }
              // The handler body ended without an end frame: the pump writes it.
              endStream();
            } catch {
              // A read error closes like the duration: completion when valid, then the end frame.
              if (!cancelled) {
                closeWithCompletion();
              }
            }
          })();
        } catch {
          // A body that cannot be read is an empty stream.
          endStream();
        }
      },
      cancel: (): void => {
        // The client is gone: no further byte and no end frame, but the slot is still released.
        cancelled = true;
        finish();
      },
    });
    return out;
  }
}
