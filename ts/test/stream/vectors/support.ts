/**
 * Shared decoders and the chunking driver for the two signed-stream corpora of
 * spec 05 section 9: `spec/fixtures/modern/stream-vectors.json` (client
 * verification, section 9 "Fields of the client verification file") and
 * `spec/fixtures/modern/stream-build-vectors.json` (server signing, section 9
 * "Fields of the build file").
 *
 * Every field the runners consume is decoded here into a typed record, so a
 * missing or mistyped field throws with a message naming the case id. The
 * optional `data_fill` marker chunk and the optional `expect.messages` marker
 * object expand to `count` copies of their ASCII byte. `expandStreamBody`
 * keeps the arrival time of every body byte (the arrival of the ORIGINAL
 * `response.stream_b64u` chunk that carried it), so the three chunkings of
 * `streamChunkings` can re-cut the same body without moving any arrival time.
 */
import { decodeBase64URL } from "../../../src/core/encoding.js";
import type { StreamTerminal, StreamVerifyChunk, StreamVerifyResult } from "../../../src/stream/verify.js";
import { StreamEventReader } from "../../../src/stream/wire.js";
import type { JsonValue } from "../../support/fixtures/index.js";
import { fixture } from "../../support/fixtures/index.js";
export { fixture };

/** Section 9 `data_fill`: the literal chunk value that expands to `count` copies of `byte`. */
export const DATA_FILL_MARKER = "@data_fill@";

// ---------------------------------------------------------------------------
// JSON shape helpers: every failure names the case and the field.
// ---------------------------------------------------------------------------

/** A JSON object view; throws with the label when the value is not an object. */
function asObject(value: JsonValue | undefined, what: string): { readonly [key: string]: JsonValue } {
  if (value === undefined || value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(what + ": expected a JSON object");
  }
  return value;
}

/** A required member; the caller applies the type check for a labelled message. */
function required(obj: { readonly [key: string]: JsonValue }, key: string, what: string): JsonValue {
  const value = obj[key];
  if (value === undefined) {
    throw new Error(what + "." + key + ": missing");
  }
  return value;
}

/** A JSON array. */
function asArray(value: JsonValue | undefined, what: string): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new Error(what + ": expected a JSON array");
  }
  return value;
}

/** A string member value. */
function asString(value: JsonValue | undefined, what: string): string {
  if (typeof value !== "string") {
    throw new Error(what + ": expected a string");
  }
  return value;
}

/** A safe-integer member value. */
function asInteger(value: JsonValue | undefined, what: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(what + ": expected a safe integer");
  }
  return value;
}

/** An optional safe-integer member; absent means undefined, any other type throws. */
function optionalInteger(
  obj: { readonly [key: string]: JsonValue },
  key: string,
  what: string,
): number | undefined {
  const value = obj[key];
  if (value === undefined) {
    return undefined;
  }
  return asInteger(value, what + "." + key);
}

/** An optional boolean member; absent means undefined, any other type throws. */
function optionalBoolean(
  obj: { readonly [key: string]: JsonValue },
  key: string,
  what: string,
): boolean | undefined {
  const value = obj[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new Error(what + "." + key + ": expected a boolean");
  }
  return value;
}

/** The error text of an unknown throw, for a labelled fixture error. */
function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Client verification corpus (spec 05 section 9, first field table).
// ---------------------------------------------------------------------------

/** Section 9 `data_fill`: the ASCII byte and how often it repeats. */
export interface StreamDataFill {
  readonly byte: string;
  readonly count: number;
}

/** One `expect.messages` entry that stands for `count` copies of one ASCII byte. */
export interface StreamMessageMarker {
  readonly data_fill: StreamDataFill;
}

/** One `expect.messages` entry: the delivered string or a repeated-byte marker. */
export type StreamExpectedMessage = string | StreamMessageMarker;

/** The fixture shape of `expect.terminal` (section 9); `frames_verified` counts the end frame too. */
export type StreamVectorTerminal =
  | { readonly state: "ok" }
  | { readonly state: "error"; readonly code: string; readonly frames_verified: number };

/** The decoded `state` object of one client case. */
export interface StreamVectorState {
  readonly now: number;
  readonly windowSeconds: number;
  readonly pinnedServerKid: string;
  readonly pinnedServerPublicKey: string;
  readonly requestSig: string;
  readonly requestId: JsonValue;
  readonly successorActivation: number | null;
  readonly frameMaxBytes: number;
  /** Section 9 `frame_nows`: the clock sample of frame i; the last value repeats. */
  readonly frameNowSamples: readonly number[];
  readonly streamIdleMs: number | undefined;
}

/** The decoded `response` object of one client case. */
export interface StreamVectorResponse {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly streamB64u: readonly string[];
}

/** The decoded `expect` object of one client case. */
export interface StreamVectorExpect {
  readonly messages: readonly StreamExpectedMessage[];
  readonly terminal: StreamVectorTerminal;
  readonly mcpComplete: boolean | undefined;
}

/** One decoded client case of `stream-vectors.json`. */
export interface StreamVectorCase {
  readonly id: string;
  readonly description: string;
  readonly state: StreamVectorState;
  readonly response: StreamVectorResponse;
  readonly silentAfterMs: number | undefined;
  readonly arrivalMs: readonly number[] | undefined;
  readonly consumer: "mcp" | "stdio" | undefined;
  readonly dataFill: StreamDataFill | undefined;
  readonly expect: StreamVectorExpect;
}

/** Decodes `data_fill` / an `expect.messages` marker: one ASCII byte repeated `count` times. */
function decodeDataFill(value: JsonValue | undefined, what: string): StreamDataFill {
  const obj = asObject(value, what);
  const byte = asString(required(obj, "byte", what), what + ".byte");
  if (byte.length !== 1 || byte.charCodeAt(0) > 0x7f) {
    throw new Error(what + ".byte: expected one ASCII byte");
  }
  const count = asInteger(required(obj, "count", what), what + ".count");
  if (count < 0) {
    throw new Error(what + ".count: expected a non-negative count");
  }
  return { byte, count };
}

/** Decodes one `expect.messages` entry: a string or `{"data_fill":{byte,count}}`. */
function decodeExpectedMessage(value: JsonValue | undefined, what: string): StreamExpectedMessage {
  if (typeof value === "string") {
    return value;
  }
  const obj = asObject(value, what);
  return { data_fill: decodeDataFill(required(obj, "data_fill", what), what + ".data_fill") };
}

/** Decodes `expect.terminal` (section 9): ok, or a 4.6 code plus the verified-frame count. */
function decodeTerminal(value: JsonValue | undefined, what: string): StreamVectorTerminal {
  const obj = asObject(value, what);
  const state = asString(required(obj, "state", what), what + ".state");
  if (state === "ok") {
    return { state };
  }
  if (state !== "error") {
    throw new Error(what + ".state: expected \"ok\" or \"error\", got " + state);
  }
  const code = asString(required(obj, "code", what), what + ".code");
  const framesVerified = asInteger(required(obj, "frames_verified", what), what + ".frames_verified");
  if (framesVerified < 0) {
    throw new Error(what + ".frames_verified: expected a non-negative count");
  }
  return { state: "error", code, frames_verified: framesVerified };
}

/** Decodes the ordered `[[name, value], ...]` header list of a case response. */
function decodeHeaders(value: JsonValue | undefined, what: string): readonly (readonly [string, string])[] {
  const entries = asArray(value, what);
  const pairs: (readonly [string, string])[] = [];
  entries.forEach((entry, index) => {
    const where = what + "[" + index + "]";
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(where + ": expected a [name, value] pair");
    }
    pairs.push([asString(entry[0], where + "[0]"), asString(entry[1], where + "[1]")] as const);
  });
  return pairs;
}

/** Decodes the `stream_b64u` chunk list: marker chunks are kept as the literal text here. */
function decodeChunkList(value: JsonValue | undefined, what: string): readonly string[] {
  return asArray(value, what).map((entry, index) => asString(entry, what + "[" + index + "]"));
}

/** Decodes `state` (section 9 first field table); `successor_activation` is number or null. */
function decodeState(value: JsonValue | undefined, what: string): StreamVectorState {
  const obj = asObject(value, what);
  const activation = required(obj, "successor_activation", what);
  let successorActivation: number | null;
  if (activation === null) {
    successorActivation = null;
  } else {
    successorActivation = asInteger(activation, what + ".successor_activation");
  }
  const samples = obj["frame_nows"];
  const frameNowSamples = samples === undefined
    ? []
    : asArray(samples, what + ".frame_nows").map((sample, index) => asInteger(sample, what + ".frame_nows[" + index + "]"));
  return {
    now: asInteger(required(obj, "now", what), what + ".now"),
    windowSeconds: asInteger(required(obj, "window_seconds", what), what + ".window_seconds"),
    pinnedServerKid: asString(required(obj, "pinned_server_kid", what), what + ".pinned_server_kid"),
    pinnedServerPublicKey: asString(
      required(obj, "pinned_server_public_key", what),
      what + ".pinned_server_public_key",
    ),
    requestSig: asString(required(obj, "request_sig", what), what + ".request_sig"),
    requestId: required(obj, "request_id", what),
    successorActivation,
    frameMaxBytes: asInteger(required(obj, "frame_max_bytes", what), what + ".frame_max_bytes"),
    frameNowSamples,
    streamIdleMs: optionalInteger(obj, "stream_idle_ms", what),
  };
}

/** Decodes `response`: status, headers and the ordered base64url chunks. */
function decodeResponse(value: JsonValue | undefined, what: string): StreamVectorResponse {
  const obj = asObject(value, what);
  return {
    status: asInteger(required(obj, "status", what), what + ".status"),
    headers: decodeHeaders(required(obj, "headers", what), what + ".headers"),
    streamB64u: decodeChunkList(required(obj, "stream_b64u", what), what + ".stream_b64u"),
  };
}

/** Decodes one client case; every later error message carries the decoded id. */
export function decodeStreamVectorCase(raw: JsonValue): StreamVectorCase {
  const obj = asObject(raw, "stream-vectors case");
  const id = asString(required(obj, "id", "stream-vectors case"), "stream-vectors case.id");
  const what = "stream-vectors case " + id;
  const consumerText = obj["consumer"];
  let consumer: "mcp" | "stdio" | undefined;
  if (consumerText !== undefined) {
    const value = asString(consumerText, what + ".consumer");
    if (value !== "mcp" && value !== "stdio") {
      throw new Error(what + ".consumer: expected \"mcp\" or \"stdio\", got " + value);
    }
    consumer = value;
  }
  const dataFillRaw = obj["data_fill"];
  const expectObj = asObject(required(obj, "expect", what), what + ".expect");
  return {
    id,
    description: asString(required(obj, "description", what), what + ".description"),
    state: decodeState(required(obj, "state", what), what + ".state"),
    response: decodeResponse(required(obj, "response", what), what + ".response"),
    silentAfterMs: optionalInteger(obj, "silent_after_ms", what),
    arrivalMs: obj["arrival_ms"] === undefined
      ? undefined
      : asArray(obj["arrival_ms"], what + ".arrival_ms").map((entry, index) =>
        asInteger(entry, what + ".arrival_ms[" + index + "]")),
    consumer,
    dataFill: dataFillRaw === undefined ? undefined : decodeDataFill(dataFillRaw, what + ".data_fill"),
    expect: {
      messages: asArray(required(expectObj, "messages", what + ".expect"), what + ".expect.messages").map(
        (entry, index) => decodeExpectedMessage(entry, what + ".expect.messages[" + index + "]"),
      ),
      terminal: decodeTerminal(required(expectObj, "terminal", what + ".expect"), what + ".expect.terminal"),
      mcpComplete: optionalBoolean(expectObj, "mcp_complete", what + ".expect"),
    },
  };
}

/** Decodes the `cases` array of `stream-vectors.json`. */
export function decodeStreamCorpus(value: JsonValue): readonly StreamVectorCase[] {
  const what = "stream-vectors.json";
  const obj = asObject(value, what);
  return asArray(required(obj, "cases", what), what + ".cases").map((raw) => decodeStreamVectorCase(raw));
}

// ---------------------------------------------------------------------------
// Server-signing corpus (spec 05 section 9, second field table).
// ---------------------------------------------------------------------------

/** One `input.frames` entry: the data value the signer must sign at `ts`. */
export interface StreamBuildInputFrame {
  readonly seq: number;
  readonly ts: number;
  readonly data: string;
}

/** The decoded `input` object of one build case. */
export interface StreamBuildInput {
  readonly requestSig: string;
  readonly kid: string;
  readonly status: number;
  readonly sid: string;
  readonly openTs: number;
  readonly frames: readonly StreamBuildInputFrame[];
}

/** One `expect.frames` entry: every signed value of the frame. */
export interface StreamBuildExpectedFrame {
  readonly seq: number;
  readonly ts: number;
  readonly prev: string;
  readonly dataHash: string;
  readonly signingString: string;
  readonly sig: string;
}

/** The decoded `expect` object of one build case; `stream_b64u` is the whole body. */
export interface StreamBuildExpect {
  readonly jackAuth: string;
  readonly openSigningString: string;
  readonly frames: readonly StreamBuildExpectedFrame[];
  readonly streamB64u: string;
  /** Section 9 `expect.terminal` when the fixture carries one, else undefined. */
  readonly terminal: StreamVectorTerminal | undefined;
}

/** One decoded case of `stream-build-vectors.json`. */
export interface StreamBuildCase {
  readonly id: string;
  readonly description: string;
  readonly input: StreamBuildInput;
  readonly expect: StreamBuildExpect;
}

/** Decodes one `input.frames` entry. */
function decodeBuildInputFrame(value: JsonValue | undefined, what: string): StreamBuildInputFrame {
  const obj = asObject(value, what);
  return {
    seq: asInteger(required(obj, "seq", what), what + ".seq"),
    ts: asInteger(required(obj, "ts", what), what + ".ts"),
    data: asString(required(obj, "data", what), what + ".data"),
  };
}

/** Decodes one `expect.frames` entry. */
function decodeBuildExpectedFrame(value: JsonValue | undefined, what: string): StreamBuildExpectedFrame {
  const obj = asObject(value, what);
  return {
    seq: asInteger(required(obj, "seq", what), what + ".seq"),
    ts: asInteger(required(obj, "ts", what), what + ".ts"),
    prev: asString(required(obj, "prev", what), what + ".prev"),
    dataHash: asString(required(obj, "data_hash", what), what + ".data_hash"),
    signingString: asString(required(obj, "signing_string", what), what + ".signing_string"),
    sig: asString(required(obj, "sig", what), what + ".sig"),
  };
}

/** Decodes one build case; every later error message carries the decoded id. */
export function decodeStreamBuildCase(raw: JsonValue): StreamBuildCase {
  const obj = asObject(raw, "stream-build-vectors case");
  const id = asString(required(obj, "id", "stream-build-vectors case"), "stream-build-vectors case.id");
  const what = "stream-build-vectors case " + id;
  const input = asObject(required(obj, "input", what), what + ".input");
  const expect = asObject(required(obj, "expect", what), what + ".expect");
  return {
    id,
    description: asString(required(obj, "description", what), what + ".description"),
    input: {
      requestSig: asString(required(input, "request_sig", what + ".input"), what + ".input.request_sig"),
      kid: asString(required(input, "kid", what + ".input"), what + ".input.kid"),
      status: asInteger(required(input, "status", what + ".input"), what + ".input.status"),
      sid: asString(required(input, "sid", what + ".input"), what + ".input.sid"),
      openTs: asInteger(required(input, "open_ts", what + ".input"), what + ".input.open_ts"),
      frames: asArray(required(input, "frames", what + ".input"), what + ".input.frames").map(
        (entry, index) => decodeBuildInputFrame(entry, what + ".input.frames[" + index + "]"),
      ),
    },
    expect: {
      jackAuth: asString(required(expect, "jack_auth", what + ".expect"), what + ".expect.jack_auth"),
      openSigningString: asString(
        required(expect, "open_signing_string", what + ".expect"),
        what + ".expect.open_signing_string",
      ),
      frames: asArray(required(expect, "frames", what + ".expect"), what + ".expect.frames").map(
        (entry, index) => decodeBuildExpectedFrame(entry, what + ".expect.frames[" + index + "]"),
      ),
      streamB64u: asString(required(expect, "stream_b64u", what + ".expect"), what + ".expect.stream_b64u"),
      terminal: expect["terminal"] === undefined
        ? undefined
        : decodeTerminal(expect["terminal"], what + ".expect.terminal"),
    },
  };
}

/** Decodes the `cases` array of `stream-build-vectors.json`. */
export function decodeStreamBuildCorpus(value: JsonValue): readonly StreamBuildCase[] {
  const what = "stream-build-vectors.json";
  const obj = asObject(value, what);
  return asArray(required(obj, "cases", what), what + ".cases").map((raw) => decodeStreamBuildCase(raw));
}

// ---------------------------------------------------------------------------
// Section 9 data_fill expansion and the three chunkings.
// ---------------------------------------------------------------------------

/** The whole expanded body plus the arrival time of each of its bytes. */
export interface ExpandedStreamBody {
  readonly bytes: Uint8Array;
  /** `byteArrivalMs[i]` is the `arrival_ms` of the ORIGINAL chunk that carried body byte i (0 when absent). */
  readonly byteArrivalMs: readonly number[];
}

/** Concatenates byte runs in order. */
function concatRuns(runs: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const run of runs) {
    total += run.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const run of runs) {
    out.set(run, offset);
    offset += run.length;
  }
  return out;
}

/**
 * Section 9: decodes every `response.stream_b64u` element, expanding each
 * literal `"@data_fill@"` to `data_fill.count` copies of `data_fill.byte`, and
 * records the arrival time of every byte (the arrival of its original chunk,
 * `arrival_ms` when present, else 0).
 */
export function expandStreamBody(c: StreamVectorCase): ExpandedStreamBody {
  const pieces = c.response.streamB64u;
  const arrival = c.arrivalMs;
  if (arrival !== undefined && arrival.length !== pieces.length) {
    throw new Error(
      "stream-vectors case " + c.id + ": arrival_ms must be parallel to response.stream_b64u ("
        + arrival.length + " vs " + pieces.length + ")",
    );
  }
  const fill = c.dataFill;
  const runs: Uint8Array[] = [];
  const byteArrivalMs: number[] = [];
  pieces.forEach((piece, index) => {
    const arrivedAtMs = arrival?.[index] ?? 0;
    let bytes: Uint8Array;
    if (piece === DATA_FILL_MARKER) {
      if (fill === undefined) {
        throw new Error(
          "stream-vectors case " + c.id + ": response.stream_b64u[" + index + "] is @data_fill@ without data_fill",
        );
      }
      bytes = new Uint8Array(fill.count).fill(fill.byte.charCodeAt(0));
    } else {
      try {
        bytes = decodeBase64URL(piece);
      } catch (err) {
        throw new Error(
          "stream-vectors case " + c.id + ": response.stream_b64u[" + index + "] is not canonical base64url ("
            + errorText(err) + ")",
        );
      }
    }
    runs.push(bytes);
    for (let i = 0; i < bytes.length; i++) {
      byteArrivalMs.push(arrivedAtMs);
    }
  });
  return { bytes: concatRuns(runs), byteArrivalMs };
}

/** The chunking names a failure message reports. */
export type StreamChunkingName = "whole-body" | "byte-by-byte" | "event-boundary";

/** One named chunking of one body. */
export interface StreamChunking {
  readonly name: StreamChunkingName;
  readonly chunks: readonly StreamVerifyChunk[];
}

/** The arrival time of body byte `index`. */
function arrivalAt(body: ExpandedStreamBody, index: number): number {
  return body.byteArrivalMs[index] ?? 0;
}

/**
 * Chunking 1: one chunk per arrival group; an empty body is zero chunks.
 * A verifier chunk carries ONE arrival time, so "one arrival per chunk" holds:
 * adjacent body bytes sharing an arrival are merged and the body is cut at
 * every arrival change. With no `arrival_ms` every byte arrives at 0, so this
 * stays the single whole-body chunk; `stream-idle-timeout` depends on the cut,
 * its 90 s gap must land after the verified frame, not before the first event.
 */
export function wholeBodyChunking(body: ExpandedStreamBody): StreamChunking {
  const chunks: StreamVerifyChunk[] = [];
  let start = 0;
  for (let i = 1; i <= body.bytes.length; i++) {
    if (i < body.bytes.length && arrivalAt(body, i) === arrivalAt(body, i - 1)) {
      continue;
    }
    chunks.push({ bytes: body.bytes.slice(start, i), arrivedAtMs: arrivalAt(body, i - 1) });
    start = i;
  }
  return { name: "whole-body", chunks };
}

/** Chunking 2: one byte per chunk, each arriving at the arrival time of that byte. */
export function byteChunking(body: ExpandedStreamBody): StreamChunking {
  const chunks: StreamVerifyChunk[] = [];
  for (let i = 0; i < body.bytes.length; i++) {
    chunks.push({ bytes: body.bytes.slice(i, i + 1), arrivedAtMs: arrivalAt(body, i) });
  }
  return { name: "byte-by-byte", chunks };
}

/**
 * Chunking 3: split at every SSE event boundary AND at every arrival change
 * (one arrival per chunk). The body is fed byte by byte to the SDK's
 * `StreamEventReader`; a chunk ends right after every byte that completed at
 * least one event and, since no chunk may span two arrival times, right before
 * every byte whose arrival differs from the previous byte's. Any trailing
 * partial bytes form the last chunk. Finding event boundaries with the reader
 * (not with the server's layout) keeps the split honest.
 */
export function eventBoundaryChunking(body: ExpandedStreamBody): StreamChunking {
  const reader = new StreamEventReader();
  const chunks: StreamVerifyChunk[] = [];
  let start = 0;
  for (let i = 0; i < body.bytes.length; i++) {
    if (i > start && arrivalAt(body, i) !== arrivalAt(body, i - 1)) {
      chunks.push({ bytes: body.bytes.slice(start, i), arrivedAtMs: arrivalAt(body, i - 1) });
      start = i;
    }
    const events = reader.push(body.bytes.subarray(i, i + 1));
    if (events.length === 0) {
      continue;
    }
    chunks.push({ bytes: body.bytes.slice(start, i + 1), arrivedAtMs: arrivalAt(body, i) });
    start = i + 1;
  }
  reader.finish();
  if (start < body.bytes.length) {
    chunks.push({ bytes: body.bytes.slice(start), arrivedAtMs: arrivalAt(body, body.bytes.length - 1) });
  }
  return { name: "event-boundary", chunks };
}

/** The three chunkings of one expanded body, in the order a failure message reports them. */
export function streamChunkings(body: ExpandedStreamBody): readonly StreamChunking[] {
  return [wholeBodyChunking(body), byteChunking(body), eventBoundaryChunking(body)];
}

// ---------------------------------------------------------------------------
// Comparison helpers and the summary line.
// ---------------------------------------------------------------------------

/** An SDK result normalised to the fixture's `expect` shape. */
export interface StreamVectorResult {
  readonly messages: readonly string[];
  readonly terminal: StreamVectorTerminal;
}

/** Normalises an SDK result to `{ messages, terminal:{state:"ok"} | {state:"error",code,frames_verified} }`. */
export function normalizeResult(result: StreamVerifyResult): StreamVectorResult {
  const terminal: StreamTerminal = result.terminal;
  const normalized: StreamVectorTerminal = terminal.state === "ok"
    ? { state: "ok" }
    : { state: "error", code: terminal.code, frames_verified: terminal.framesVerified };
  return { messages: result.messages.slice(), terminal: normalized };
}

/** Expands the section 9 `expect.messages` markers to the delivered strings. */
export function expandExpectedMessages(messages: readonly StreamExpectedMessage[]): string[] {
  return messages.map((message) =>
    typeof message === "string" ? message : message.data_fill.byte.repeat(message.data_fill.count));
}

/** Decodes an even-length hex string (`keys.json` seeds) without Buffer. */
export function decodeHexBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error("keys.json: seed_hex must be an even number of hex digits");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** The one summary line per corpus: `VECTOR-SUMMARY corpus=<corpus> sdk=ts pass=<n> excluded=0 deviation=0`. */
export function printSummary(corpus: "stream" | "stream-build", pass: number): void {
  console.log("VECTOR-SUMMARY corpus=" + corpus + " sdk=ts pass=" + pass + " excluded=0 deviation=0");
}
