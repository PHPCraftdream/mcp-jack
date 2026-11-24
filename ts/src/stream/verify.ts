/**
 * Client verifier of signed streams (spec 05 section 4: 4.1 routing, 4.2 open
 * header, 4.3 each frame, 4.4 truncation, 4.5 idle timeout, 4.6 codes and 4.7
 * verify before parsing) plus the 6.3 close rule. Port of `openHeader` and
 * `verifyStream` in `spec/tools/modern/streams/reference.mjs`: the check order
 * is normative, so this file never reorders a step. Signing strings, grammars,
 * the event reader and the 2.18 signal test come from wire.ts; the key, window,
 * rotation and signature checks are here.
 */
import { decodeBase64URLFixed } from "../core/encoding.js";
import { verify as verifyEd25519 } from "../core/ed25519.js";
import {
  STREAM_DEFAULT_FRAME_MAX_BYTES,
  STREAM_DEFAULT_IDLE_MS,
  STREAM_DEFAULT_WINDOW_SECONDS,
  STREAM_MIN_FRAME_MAX_BYTES,
  StreamVerifyError,
  isStreamResponse,
} from "./codes.js";
import type { StreamClientCode } from "./codes.js";
import {
  StreamEventOverflow,
  StreamEventReader,
  parseStreamFrame,
  parseStreamOpenAuth,
  streamDataHash,
  streamEventMaxBytes,
  streamFinalResponseFor,
  streamFrameSigningString,
  streamOpenSigningString,
  streamSignalCode,
} from "./wire.js";
import type { StreamLine } from "./wire.js";

/** One trusted server key a stream may be signed by (spec 05 sections 4.2 and 5). */
export interface StreamServerKey {
  readonly kid: string;
  readonly publicKey: Uint8Array; // raw 32-byte Ed25519 key
  readonly successorActivation?: number; // A_next in unix seconds (5.1/5.2); absent = no known cutoff
}

/** Everything the verifier needs that is not the response itself. */
export interface StreamVerifyOptions {
  /** Resolves a kid to the trusted key; undefined means an unknown key (4.2 step 4). */
  readonly resolveKey: (kid: string) => StreamServerKey | undefined;
  /** Unix seconds. Called exactly ONCE for the open header (4.2 step 5) and exactly once per frame at step 3 of 4.3. */
  readonly now: () => number;
  /** The `sig` parameter of the v1 request header that opened the stream (2.5, not the whole header). */
  readonly requestSig: string;
  readonly windowSeconds?: number; // default 30, safe integer 1..120
  readonly frameMaxBytes?: number; // default 1048576, safe integer >= 1024
  readonly streamIdleMs?: number; // default 90000, positive safe integer
  readonly consumer?: "mcp" | "stdio"; // default "mcp" (6.1 / 6.2)
  /** Receives each verified data value instead of retaining it, so a long stream keeps no history. */
  readonly onMessage?: (data: string) => void;
}

/** How verification ended: `ok` only after an end frame (or a measured live silence), else the 4.6 code. */
export type StreamTerminal =
  | { readonly state: "ok" }
  | { readonly state: "error"; readonly code: StreamClientCode; readonly framesVerified: number };

/** The messages delivered to the MCP layer plus the terminal state of the stream. */
export interface StreamVerifyResult {
  readonly messages: readonly string[]; // data values delivered to the MCP layer, in order
  readonly terminal: StreamTerminal;
}

/** One body chunk with its arrival time, in milliseconds since the open header was verified. */
export interface StreamVerifyChunk {
  readonly bytes: Uint8Array;
  readonly arrivedAtMs: number; // ms since the open header was verified
}

// Signing strings are signed over their UTF-8 encoding, and 2.17 bounds the
// data value as UTF-8 too, so one shared encoder matches Buffer.byteLength(...,'utf8').
const ENCODER = new TextEncoder();

const JACK_AUTH = "jack-auth";
const MAX_WINDOW_SECONDS = 120;

/** The validated options with every default applied. */
interface ResolvedOptions {
  readonly resolveKey: (kid: string) => StreamServerKey | undefined;
  readonly now: () => number;
  readonly requestSig: string;
  readonly windowSeconds: number;
  readonly frameMaxBytes: number;
  readonly streamIdleMs: number;
  readonly consumer: "mcp" | "stdio";
  readonly onMessage: ((data: string) => void) | undefined;
}

/**
 * Incremental verifier of one `s1` response: `open`, then `push` per chunk,
 * then `end` (or `idle` while the context stands open). A failure latches the
 * terminal, so `terminal` always reports why the stream stopped.
 */
export class StreamVerifier {
  private readonly options: ResolvedOptions;
  private readonly reader: StreamEventReader;
  private readonly delivered: string[] = [];
  private readonly pendingEvents: { readonly lines: readonly StreamLine[]; readonly arrivedAtMs: number }[] = [];
  private deliveredCount = 0; // messages handed out, retained or sunk
  private latched: StreamTerminal | undefined;
  private streamSid = "";
  private streamKey: StreamServerKey | undefined;
  private verifiedCount = 0;
  private expectedSeq = 0;
  private previousTs = -Infinity;
  private prevSig = ""; // 4.3 step 5: the chain starts at the open signature
  private lastVerifiedAtMs = 0; // 0 is the moment the open header was verified (4.5)
  private pendingCrAtMs: number | undefined;
  private pendingOverflow = false;
  private sawEnd = false;

  constructor(options: StreamVerifyOptions) {
    this.options = resolveOptions(options);
    // 2.17: the reader caps an event while its last line is still incomplete,
    // so a peer that never terminates one cannot buffer past the cap.
    this.reader = new StreamEventReader({ maxEventBytes: streamEventMaxBytes(this.options.frameMaxBytes) });
  }

  /** Verifies the open header of the response (4.1/4.2) and returns the sid. */
  open(status: number, headers: readonly (readonly [string, string])[]): string {
    const latched = this.latched;
    if (latched !== undefined) {
      // One open header per stream: a fail is rethrown, an ok stream is already open.
      if (latched.state === "error") {
        throw new StreamVerifyError(latched.code, latched.framesVerified);
      }
      return this.streamSid;
    }
    if (!isStreamResponse(status, headers)) {
      // 4.1 and 1.4: a caller that routes a non-s1 response here has a bug,
      // and 4.6 has no code for it.
      throw new Error("jack client: response is not an s1 response; verify it with the v1 response path");
    }
    let authValue: string | undefined;
    let authCount = 0;
    for (const [name, value] of headers) {
      if (headerNameIs(name, JACK_AUTH)) {
        authCount += 1;
        if (authCount === 1) {
          authValue = value;
        }
      }
    }
    if (authCount === 0) {
      this.fail("stream_missing_auth");
    }
    if (authCount > 1) {
      this.fail("stream_malformed_auth"); // 4.2 step 2: the header is single-valued
    }
    const parsed = parseStreamOpenAuth(authValue ?? "");
    if (!parsed.ok) {
      this.fail(parsed.code);
    }
    const open = parsed.value;
    const key = this.options.resolveKey(open.kid);
    if (key === undefined || key.kid !== open.kid) {
      this.fail("stream_unknown_server_key"); // 4.2 step 4
    }
    // 4.2 step 5: the single clock sample of this open header.
    const now = this.options.now();
    if (Math.abs(now - open.ts) > this.options.windowSeconds) {
      this.fail("stream_out_of_window"); // strict `>`: equal is still in window
    }
    const activation = key.successorActivation;
    if (activation !== undefined && open.ts >= activation) {
      this.fail("stream_after_cutoff"); // 4.2 step 6
    }
    const signingString = streamOpenSigningString({
      status,
      requestSig: this.options.requestSig,
      kid: open.kid,
      ts: open.ts,
      sid: open.sid,
    });
    if (!verifySignature(key.publicKey, signingString, open.sig)) {
      this.fail("stream_bad_signature"); // 4.2 step 7
    }
    this.streamSid = open.sid;
    this.streamKey = key;
    this.prevSig = open.sig;
    return open.sid;
  }

  /** The sid of the verified open header, or "" before a successful open. */
  get sid(): string {
    return this.streamSid;
  }

  /** Frames that verified so far, the 2.18 signal frame included. */
  get framesVerified(): number {
    return this.verifiedCount;
  }

  /** Data values retained so far, in order; empty when an `onMessage` sink was used. */
  get messages(): readonly string[] {
    return this.delivered;
  }

  /** The latched terminal once the stream failed or ended, else undefined. */
  get terminal(): StreamTerminal | undefined {
    return this.latched;
  }

  /** Feeds one body chunk; an optional gate lets streaming callers stop between frames. */
  push(chunk: Uint8Array, arrivedAtMs: number, canVerify: () => boolean = () => true): readonly string[] {
    const latched = this.latched;
    if (latched !== undefined) {
      if (latched.state === "error") {
        throw new StreamVerifyError(latched.code, latched.framesVerified);
      }
      return [];
    }
    if (this.streamKey === undefined) {
      // Pushing before a verified open header is a caller bug, not a stream code.
      throw new Error("jack client: stream verifier is not open; call open() first");
    }
    const heldCrAt = this.pendingCrAtMs;
    const heldCrTerminatesEvent = this.reader.pendingCrTerminatesEvent;
    const continuesCrLf = chunk.length > 0 && chunk[0] === 0x0a;
    const heldCrEventAtMs = heldCrAt !== undefined && heldCrTerminatesEvent && chunk.length > 0 && !continuesCrLf
      ? heldCrAt
      : arrivedAtMs;
    try {
      const split = this.reader.push(chunk);
      if (chunk.length > 0) this.pendingCrAtMs = this.reader.hasPendingCr ? arrivedAtMs : undefined;
      for (let i = 0; i < split.length; i++) {
        this.pendingEvents.push({ lines: split[i]!, arrivedAtMs: i === 0 ? heldCrEventAtMs : arrivedAtMs });
      }
      return this.drainEvents(canVerify);
    } catch (err) {
      if (chunk.length > 0) this.pendingCrAtMs = this.reader.hasPendingCr ? arrivedAtMs : undefined;
      if (err instanceof StreamEventOverflow) {
        this.pendingEvents.push(...err.completedEvents.map((lines, i) => ({ lines, arrivedAtMs: i === 0 ? heldCrEventAtMs : arrivedAtMs })));
        this.pendingOverflow = true;
        return this.drainEvents(canVerify);
      }
      throw err;
    }
  }


  get hasPendingEvents(): boolean {
    return this.pendingEvents.length > 0;
  }

  private drainEvents(canVerify: () => boolean): string[] {
    const delivered: string[] = [];
    while (this.pendingEvents.length > 0 && canVerify()) {
      const event = this.pendingEvents.shift()!;
      delivered.push(...this.verifyEvents([event.lines], event.arrivedAtMs));
    }
    if (this.pendingEvents.length === 0 && this.pendingOverflow) {
      this.pendingOverflow = false;
      this.fail("stream_frame_too_large");
    }
    return delivered;
  }

  /** The per-event checks of 4.3, shared by `push` and the events `end` flushes (2.14). */
  private verifyEvents(events: readonly (readonly StreamLine[])[], arrivedAtMs: number): string[] {
    const key = this.streamKey;
    if (key === undefined) {
      throw new Error("jack client: stream verifier is not open; call open() first");
    }
    const delivered: string[] = [];
    for (const lines of events) {
      // 4.5 first: a frame whose completing byte arrived after the deadline is not verified.
      if (arrivedAtMs - this.lastVerifiedAtMs > this.options.streamIdleMs) {
        this.fail("stream_idle");
      }
      if (this.sawEnd) {
        this.fail("stream_out_of_order"); // 2.16: nothing may follow the end frame
      }
      const parsed = parseStreamFrame(lines);
      if (!parsed.ok) {
        this.fail("stream_bad_frame"); // 4.3 step 1
      }
      const frame = parsed.value;
      // 2.17: the cap bounds the data value as UTF-8, not the bytes of the event.
      if (ENCODER.encode(frame.data).length > this.options.frameMaxBytes) {
        this.fail("stream_frame_too_large");
      }
      if (frame.seq !== this.expectedSeq) {
        this.fail("stream_out_of_order"); // 4.3 step 2
      }
      // 4.3 step 3: the single clock sample of this frame.
      const now = this.options.now();
      if (Math.abs(now - frame.ts) > this.options.windowSeconds || frame.ts < this.previousTs) {
        this.fail("stream_stale_frame");
      }
      const activation = key.successorActivation;
      if (activation !== undefined && frame.ts >= activation) {
        this.fail("stream_after_cutoff"); // 4.3 step 4
      }
      const signingString = streamFrameSigningString({
        sid: this.streamSid,
        seq: frame.seq,
        ts: frame.ts,
        prev: this.prevSig,
        dataHash: streamDataHash(frame.data),
      });
      if (!verifySignature(key.publicKey, signingString, frame.sig)) {
        this.fail("stream_bad_signature"); // 4.3 step 5
      }
      // Only a fully verified frame commits state; the chain advances over its sig.
      this.verifiedCount += 1;
      this.lastVerifiedAtMs = arrivedAtMs;
      this.expectedSeq += 1;
      this.previousTs = frame.ts;
      this.prevSig = frame.sig;
      // 4.3 step 6: a 2.18 signal counts as verified, is never delivered, and no
      // later frame is verified, so the stream is not `stream_truncated`.
      if (frame.kind === "message") {
        const signal = streamSignalCode(frame.data);
        if (signal !== null) {
          this.fail(signal);
        }
      }
      if (frame.kind === "jack-end") {
        this.sawEnd = true; // 2.16: delivered nothing, the stream is now complete
        continue;
      }
      // 6.2: a stdio consumer writes one line per data value, so a raw CR or LF aborts.
      if (this.options.consumer === "stdio" && (frame.data.includes("\n") || frame.data.includes("\r"))) {
        this.fail("stream_bad_frame");
      }
      // 4.7: only a verified message frame reaches the MCP layer. A sink takes
      // it straight through, so the verifier keeps no copy of the history.
      this.deliveredCount += 1;
      const sink = this.options.onMessage;
      if (sink === undefined) {
        this.delivered.push(frame.data);
      } else {
        sink(frame.data);
      }
      delivered.push(frame.data);
    }
    return delivered;
  }

  /** 4.5 for a context that keeps standing open; throws when the deadline passed. */
  idle(arrivedAtMs: number): void {
    if (this.latched !== undefined || this.sawEnd) {
      return;
    }
    if (arrivedAtMs - this.lastVerifiedAtMs > this.options.streamIdleMs) {
      this.fail("stream_idle");
    }
  }

  /** Ends the body (4.4/4.5) and latches the terminal; never throws. */
  end(arrivedAtMs: number, silentAfterMs?: number): StreamVerifyResult {
    const latched = this.latched;
    if (latched !== undefined) {
      return { messages: this.delivered, terminal: latched };
    }
    // 2.14: a final lone CR still closes the event the reader is holding, so it
    // is verified exactly like a pushed one. A failure latches and is returned.
    try {
      const heldCrTerminatesEvent = this.reader.pendingCrTerminatesEvent;
      const trailing = this.reader.finish();
      const arrivedAt = heldCrTerminatesEvent ? this.pendingCrAtMs ?? arrivedAtMs : arrivedAtMs;
      this.pendingCrAtMs = undefined;
      this.pendingEvents.push(...trailing.map((lines) => ({ lines, arrivedAtMs: arrivedAt })));
      this.drainEvents(() => true);
    } catch (err) {
      if (err instanceof StreamEventOverflow) {
        try {
          this.verifyEvents(err.completedEvents, arrivedAtMs);
        } catch (eventErr) {
          const failedEvent = this.latched;
          if (failedEvent !== undefined) {
            return { messages: this.delivered, terminal: failedEvent };
          }
          throw eventErr;
        }
        const overflow = this.latched;
        if (overflow === undefined) {
          try {
            this.fail("stream_frame_too_large");
          } catch {
            // `end()` reports its terminal instead of throwing.
          }
        }
      }
      const failed = this.latched;
      if (failed !== undefined) {
        return { messages: this.delivered, terminal: failed };
      }
      throw err;
    }
    let terminal: StreamTerminal;
    if (this.sawEnd) {
      terminal = { state: "ok" };
    } else if (arrivedAtMs - this.lastVerifiedAtMs + (silentAfterMs ?? 0) > this.options.streamIdleMs) {
      // 4.5: the deadline runs to the last byte received plus any measured trailing silence.
      terminal = { state: "error", code: "stream_idle", framesVerified: this.verifiedCount };
    } else if (silentAfterMs !== undefined) {
      // A measured live silence means the harness stopped reading an open body.
      terminal = { state: "ok" };
    } else {
      terminal = { state: "error", code: "stream_truncated", framesVerified: this.verifiedCount };
    }
    this.latched = terminal;
    return { messages: this.delivered, terminal };
  }

  /** Latches the 4.6 error terminal and throws it; the caller stops reading. */
  private fail(code: StreamClientCode): never {
    this.latched = { state: "error", code, framesVerified: this.verifiedCount };
    throw new StreamVerifyError(code, this.verifiedCount);
  }
}

/** Verifies a whole `s1` response body from its status, headers and chunks. */
export function verifySignedStream(input: {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly chunks: readonly StreamVerifyChunk[];
  readonly silentAfterMs?: number; // 4.5: the context stayed open and silent this long after the last byte
  readonly requestId?: unknown; // the JSON-RPC id of the opening request (6.3)
} & StreamVerifyOptions): StreamVerifyResult & { readonly mcpComplete?: boolean } {
  if (!isStreamResponse(input.status, input.headers)) {
    // Same router as StreamVerifier.open: a caller bug, not a 4.6 code.
    throw new Error("jack client: response is not an s1 response; verify it with the v1 response path");
  }
  const verifier = new StreamVerifier(input);
  let result: StreamVerifyResult;
  try {
    result = drive(verifier, input.status, input.headers, input.chunks, input.silentAfterMs);
  } catch (err) {
    if (!(err instanceof StreamVerifyError)) {
      throw err;
    }
    // 4.4: messages delivered before the failing frame stay valid.
    const terminal: StreamTerminal = verifier.terminal ?? { state: "error", code: err.code, framesVerified: err.framesVerified };
    result = { messages: verifier.messages, terminal };
  }
  if (input.requestId === undefined) {
    return result;
  }
  // 6.3: the terminal decides completion; a live observation never completes.
  return {
    ...result,
    mcpComplete: streamCompletesRequest(result.messages, input.requestId, result.terminal, input.silentAfterMs !== undefined),
  };
}

/**
 * Whether a stream completed its MCP request (6.3): never live, never after a
 * failure, and only when the last message is this request's final response.
 */
export function streamCompletesRequest(
  messages: readonly string[],
  requestId: unknown,
  terminal: StreamTerminal,
  live: boolean,
): boolean {
  if (live || terminal.state !== "ok") {
    return false; // 4.4/6.3: a body without a verified jack-end is never complete
  }
  const last = messages[messages.length - 1];
  return last !== undefined && streamFinalResponseFor(last, requestId);
}

/** Opens, pushes every chunk in order and ends the body; stops at the first failure. */
function drive(
  verifier: StreamVerifier,
  status: number,
  headers: readonly (readonly [string, string])[],
  chunks: readonly StreamVerifyChunk[],
  silentAfterMs: number | undefined,
): StreamVerifyResult {
  verifier.open(status, headers);
  for (const chunk of chunks) {
    verifier.push(chunk.bytes, chunk.arrivedAtMs);
  }
  const last = chunks[chunks.length - 1];
  return verifier.end(last === undefined ? 0 : last.arrivedAtMs, silentAfterMs);
}

/** 4.2 step 7 and 4.3 step 5: a decode or crypto failure is a failed signature, never a throw. */
function verifySignature(publicKey: Uint8Array, signingString: string, signature: string): boolean {
  try {
    return verifyEd25519(publicKey, ENCODER.encode(signingString), decodeBase64URLFixed(signature, 64));
  } catch {
    return false;
  }
}

/** Header names compare ASCII case-insensitively (1.4); no locale lowering, ASCII only. */
function headerNameIs(name: string, expected: string): boolean {
  if (name.length !== expected.length) {
    return false;
  }
  for (let i = 0; i < name.length; i++) {
    const a = name.charCodeAt(i);
    const b = expected.charCodeAt(i);
    const lowerA = a >= 65 && a <= 90 ? a + 32 : a;
    const lowerB = b >= 65 && b <= 90 ? b + 32 : b;
    if (lowerA !== lowerB) {
      return false;
    }
  }
  return true;
}

/** Validates the options and applies the defaults; any problem is a plain client error. */
function resolveOptions(options: StreamVerifyOptions | undefined): ResolvedOptions {
  if (options === undefined || options === null) {
    throw new Error("jack client: stream verifier options are required");
  }
  if (typeof options.resolveKey !== "function") {
    throw new Error("jack client: stream verifier resolveKey must be a function");
  }
  if (typeof options.now !== "function") {
    throw new Error("jack client: stream verifier now must be a function");
  }
  if (typeof options.requestSig !== "string") {
    throw new Error("jack client: stream verifier requestSig must be a string");
  }
  const windowSeconds = options.windowSeconds ?? STREAM_DEFAULT_WINDOW_SECONDS;
  if (typeof windowSeconds !== "number" || !Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > MAX_WINDOW_SECONDS) {
    throw new Error(`jack client: stream verifier windowSeconds must be an integer between 1 and ${MAX_WINDOW_SECONDS}`);
  }
  const frameMaxBytes = options.frameMaxBytes ?? STREAM_DEFAULT_FRAME_MAX_BYTES;
  if (typeof frameMaxBytes !== "number" || !Number.isSafeInteger(frameMaxBytes) || frameMaxBytes < STREAM_MIN_FRAME_MAX_BYTES) {
    throw new Error(`jack client: stream verifier frameMaxBytes must be an integer of at least ${STREAM_MIN_FRAME_MAX_BYTES}`);
  }
  const streamIdleMs = options.streamIdleMs ?? STREAM_DEFAULT_IDLE_MS;
  if (typeof streamIdleMs !== "number" || !Number.isSafeInteger(streamIdleMs) || streamIdleMs <= 0) {
    throw new Error("jack client: stream verifier streamIdleMs must be a positive integer");
  }
  const consumer = options.consumer ?? "mcp";
  if (consumer !== "mcp" && consumer !== "stdio") {
    throw new Error('jack client: stream verifier consumer must be "mcp" or "stdio"');
  }
  return {
    resolveKey: options.resolveKey,
    now: options.now,
    requestSig: options.requestSig,
    windowSeconds,
    frameMaxBytes,
    streamIdleMs,
    consumer,
    onMessage: options.onMessage,
  };
}
