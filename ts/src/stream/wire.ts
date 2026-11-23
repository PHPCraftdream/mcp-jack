/**
 * Wire grammar of signed streams (spec 05 sections 2.2-2.18): the open value,
 * the SSE event reader, the frame grammar, the signing strings, the 2.18
 * signal template and the 6.3 final-response test. Port of `parseParams`,
 * `parseField`, `parseEvents`, `parseFrame`, `parseSignal`,
 * `openSigningString`, `frameSigningString`, `dataHash` and `serializeFrame`
 * in `spec/tools/modern/streams/reference.mjs`. The size cap (2.17), the
 * signature and the key/window/rotation checks belong to later chunks.
 */
import { BadBase64UrlError, bodyHash, decodeBase64URLFixed } from "../core/encoding.js";
import { STREAM_SCHEME } from "./codes.js";
import type { StreamClientCode } from "./codes.js";
import { STREAM_SIGNAL_CODES } from "./codes.js";

/** Domain separation for the open header signing string (spec 05 section 2.5). */
export const STREAM_OPEN_DOMAIN = "mcp-jack/stream1/open";

/** Domain separation for the frame signing string (spec 05 section 2.15). */
export const STREAM_FRAME_DOMAIN = "mcp-jack/stream1/frame";

/** The JSON-RPC method of a 2.18 transport signal frame. */
export const STREAM_SIGNAL_METHOD = "notifications/jack/stream_error";

/** The parsed `Jack-Auth` open value; every value is the canonical text as sent (spec 05 section 2.1). */
export interface StreamOpenAuth {
  readonly kid: string;
  readonly ts: number;
  readonly sid: string;
  readonly sig: string;
}

/** One verified-shape frame; `data` is the joined data value (spec 05 sections 2.6-2.10). */
export interface StreamFrame {
  readonly kind: "message" | "jack-end";
  readonly data: string;
  readonly seq: number;
  readonly ts: number;
  readonly sig: string;
}

/** One field line of an event: the name is decoded latin1-style and the value is raw bytes (spec 05 sections 2.10-2.13). */
export interface StreamLine {
  readonly name: string;
  readonly value: Uint8Array;
}

/** Outcome of parsing an open header value; section 2.3 decides the code of a bad scheme. */
export type StreamOpenParse =
  | { readonly ok: true; readonly value: StreamOpenAuth }
  | { readonly ok: false; readonly code: StreamClientCode };

/** Outcome of parsing one event; section 2.7-2.13 collapse every violation to `stream_bad_frame`. */
export type StreamFrameParse = { readonly ok: true; readonly value: StreamFrame } | { readonly ok: false; readonly code: "stream_bad_frame" };

const CR = 0x0d;
const LF = 0x0a;
const SP = 0x20;
const COLON = 0x3a;

// Canonical decimal of at most 12 digits (2.2) and 15 digits (2.7).
const TS_RE = /^(?:0|[1-9][0-9]{0,11})$/;
const SEQ_RE = /^(?:0|[1-9][0-9]{0,14})$/;
// `name=value` with no whitespace; names lowercase and case-sensitive (2.2, 2.7).
const PARAM_RE = /^([a-z]+)=([A-Za-z0-9_-]+)$/;
// `s` + digits or `v` + digits, other than `s1` (2.3).
const SCHEME_RE = /^[sv][0-9]+$/;

// 2.16/2.18: the template up to `<n>`, then the canonical limit rule.
const SIGNAL_TEMPLATES: readonly { readonly code: StreamClientCode; readonly prefix: string }[] = STREAM_SIGNAL_CODES.map((code) => ({
  code,
  prefix: '{"jsonrpc":"2.0","method":"' + STREAM_SIGNAL_METHOD + '","params":{"code":"' + code + '","limit":',
}));
const SIGNAL_SUFFIX = "}}";
const LIMIT_RE = /^(?:0|[1-9][0-9]*)$/;
const LIMIT_MAX = 9007199254740991n;

const EMPTY = new Uint8Array(0);
const ENCODER = new TextEncoder();
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const BAD_FRAME: StreamFrameParse = { ok: false, code: "stream_bad_frame" };

/** The open signing string: six LF-joined lines, no trailing LF (spec 05 section 2.5). */
export function streamOpenSigningString(v: {
  readonly status: number;
  readonly requestSig: string;
  readonly kid: string;
  readonly ts: number;
  readonly sid: string;
}): string {
  return [STREAM_OPEN_DOMAIN, String(v.status), v.requestSig, v.kid, String(v.ts), v.sid].join("\n");
}

/** The frame signing string: six LF-joined lines, no trailing LF (spec 05 section 2.15). */
export function streamFrameSigningString(v: {
  readonly sid: string;
  readonly seq: number;
  readonly ts: number;
  readonly prev: string;
  readonly dataHash: string;
}): string {
  return [STREAM_FRAME_DOMAIN, v.sid, String(v.seq), String(v.ts), v.prev, v.dataHash].join("\n");
}

/** `base64url(SHA-256(UTF-8 bytes of the data value))`; the empty value hashes as the empty byte string (spec 05 section 2.15). */
export function streamDataHash(data: string): string {
  return bodyHash(ENCODER.encode(data));
}

/** The exact `Jack-Auth` open value of spec 05 section 2.1. */
export function formatStreamOpenAuth(v: StreamOpenAuth): string {
  return `${STREAM_SCHEME} kid=${v.kid},ts=${v.ts},sid=${v.sid},sig=${v.sig}`;
}

/**
 * Parses a `Jack-Auth` open value under sections 2.2 and 2.3 only: grammar,
 * scheme precedence and canonical encodings. Key, window, rotation and
 * signature checks are steps 4-7 of 4.2 and belong to the verifier.
 */
export function parseStreamOpenAuth(value: string): StreamOpenParse {
  const sp = value.indexOf(" ");
  const scheme = sp < 0 ? value : value.slice(0, sp);
  if (scheme !== STREAM_SCHEME) {
    // 2.3: the scheme is judged before any parameter or encoding check.
    return { ok: false, code: SCHEME_RE.test(scheme) ? "stream_unsupported_version" : "stream_malformed_auth" };
  }
  const params = sp < 0 ? null : parseParams(value.slice(sp + 1), ["kid", "ts", "sid", "sig"]);
  if (params === null) {
    return { ok: false, code: "stream_malformed_auth" };
  }
  const tsText = params.get("ts") ?? "";
  const kid = params.get("kid") ?? "";
  const sid = params.get("sid") ?? "";
  const sig = params.get("sig") ?? "";
  if (!TS_RE.test(tsText) || !isStrictB64u(kid, 32) || !isStrictB64u(sid, 16) || !isStrictB64u(sig, 64)) {
    return { ok: false, code: "stream_malformed_auth" };
  }
  return { ok: true, value: { kid, ts: Number(tsText), sid, sig } };
}

/** Raised when one event outgrows its cap while its last line is still incomplete (2.17). */
export class StreamEventOverflow extends Error {
  readonly completedEvents: readonly (readonly StreamLine[])[];

  constructor(completedEvents: readonly (readonly StreamLine[])[] = []) {
    super("jack stream: event exceeds the frame cap");
    this.name = "StreamEventOverflow";
    this.completedEvents = completedEvents;
  }
}

/**
 * The largest wire size of one event for a given `frameMaxBytes`, a superset of
 * every legal event: the data value of 2.10 is at most `frameMaxBytes` UTF-8
 * bytes, each of its LF-separated pieces costs at most one `data: ` prefix, and
 * the `event:`, `jack:` and blank lines add only a constant.
 */
export function streamEventMaxBytes(frameMaxBytes: number): number {
  return 8 * frameMaxBytes + 4096;
}

/**
 * Incremental SSE event splitter of spec 05 sections 2.6, 2.10 and 2.12-2.14.
 * `push` may receive arbitrary splits; an event is returned only once its
 * terminating blank line arrives, so partial line and event state persists.
 */
export class StreamEventReader {
  // A growable buffer: `len` bytes are live from offset 0, always the start of
  // the unfinished line, and `buf.length` is the capacity.
  private buf: Uint8Array = EMPTY;
  private len = 0;
  private pos = 0; // scan cursor: no byte before it is examined again
  private lineStart = 0; // start of the line being assembled
  private eventBytes = 0; // field lines and terminators of the event so far
  private readonly maxEventBytes: number;
  private lines: StreamLine[] = [];
  private started = false;
  private readonly bomPrefix: number[] = [];
  private finished = false;

  /** An absent `maxEventBytes` keeps the unbounded buffering a test helper relies on. */
  constructor(options?: { readonly maxEventBytes?: number }) {
    this.maxEventBytes = options?.maxEventBytes ?? Infinity;
  }

  /** Feeds the next chunk and returns the events completed by this chunk, in order. */
  push(chunk: Uint8Array): StreamLine[][] {
    if (this.finished || chunk.length === 0) {
      return [];
    }
    let offset = 0;
    let prefix: Uint8Array = EMPTY;
    if (!this.started) {
      while (offset < chunk.length && this.bomPrefix.length < 3) {
        this.bomPrefix.push(chunk[offset++]!);
      }
      if (this.bomPrefix.length < 3) {
        return [];
      }
      this.started = true;
      const isBom = this.bomPrefix[0] === 0xef && this.bomPrefix[1] === 0xbb && this.bomPrefix[2] === 0xbf;
      if (!isBom) {
        prefix = Uint8Array.from(this.bomPrefix);
      }
      this.bomPrefix.length = 0;
    }
    if (this.maxEventBytes === Infinity) {
      this.append(prefix);
      this.append(chunk.subarray(offset));
      return this.scan();
    }
    const events: StreamLine[][] = [];
    let firstSlice = prefix.length > 0;
    while (offset < chunk.length || firstSlice) {
      const sliceSize = firstSlice ? 4096 - prefix.length : 4096;
      const end = Math.min(offset + sliceSize, chunk.length);
      if (firstSlice) {
        this.append(prefix);
        firstSlice = false;
      }
      this.append(chunk.subarray(offset, end));
      try {
        events.push(...this.scan());
      } catch (err) {
        if (err instanceof StreamEventOverflow) {
          throw new StreamEventOverflow([...events, ...err.completedEvents]);
        }
        throw err;
      }
      offset = end;
    }
    return events;
  }

  /** Ends the body and returns the events a final lone CR completed (2.14). */
  finish(): StreamLine[][] {
    if (this.finished) {
      return [];
    }
    this.finished = true;
    const events: StreamLine[][] = [];
    if (!this.started) {
      this.started = true;
      this.append(Uint8Array.from(this.bomPrefix));
      this.bomPrefix.length = 0;
      try {
        events.push(...this.scan());
      } catch (err) {
        if (err instanceof StreamEventOverflow) {
          this.resetAfterFinish();
          throw new StreamEventOverflow([...events, ...err.completedEvents]);
        }
        throw err;
      }
    }
    // A held trailing CR is resolved as a terminator by supplying its LF half.
    if (this.len > 0 && this.pos === this.len - 1 && this.buf[this.pos] === CR) {
      this.append(Uint8Array.of(LF));
      try {
        events.push(...this.scan());
      } catch (err) {
        if (err instanceof StreamEventOverflow) {
          this.resetAfterFinish();
          throw new StreamEventOverflow([...events, ...err.completedEvents]);
        }
        throw err;
      }
    }
    this.resetAfterFinish();
    return events;
  }

  private resetAfterFinish(): void {
    this.buf = EMPTY;
    this.len = 0;
    this.pos = 0;
    this.lineStart = 0;
    this.eventBytes = 0;
    this.lines = [];
  }

  // Growing only on overflow copies the old bytes O(log n) times, so n pushes
  // cost O(n) bytes in total rather than O(n^2).
  private append(chunk: Uint8Array): void {
    const need = this.len + chunk.length;
    if (need > this.buf.length) {
      let capacity = this.buf.length === 0 ? 64 : this.buf.length * 2;
      if (capacity < need) {
        capacity = need;
      }
      const grown = new Uint8Array(capacity);
      grown.set(this.buf.subarray(0, this.len), 0);
      this.buf = grown;
    }
    this.buf.set(chunk, this.len);
    this.len = need;
  }

  private scan(): StreamLine[][] {
    const buf = this.buf;
    const len = this.len;
    const cap = this.maxEventBytes;
    const events: StreamLine[][] = [];
    let start = this.lineStart;
    let i = this.pos;
    while (i < len) {
      // Cap the event while its last line is still incomplete, so a peer that
      // never sends a terminator cannot buffer past the cap (2.17).
      if (this.eventBytes + (i - start) > cap) {
        throw new StreamEventOverflow(events);
      }
      const byte = buf[i];
      if (byte !== CR && byte !== LF) {
        i += 1;
        continue;
      }
      // A trailing CR may be the first half of a CRLF that straddles chunks;
      // it is the one byte a later push examines again.
      if (byte === CR && i + 1 === len) {
        break;
      }
      const contentEnd = i;
      // 2.14: a lone CR and a CRLF are both one terminator.
      const termEnd = byte === CR && buf[i + 1] === LF ? i + 2 : i + 1;
      if (contentEnd === start) {
        // A blank line ends an event only after at least one field line (2.6).
        if (this.lines.length > 0) {
          events.push(this.lines);
          this.lines = [];
          this.eventBytes = 0;
        }
      } else if (buf[start] === COLON) {
        // 2.12: a comment belongs to no event and is dropped unread, so its
        // bytes count towards neither the event nor the cap.
      } else {
        // A copy, not a view: compaction rewrites this buffer in place.
        this.lines.push(splitField(buf.slice(start, contentEnd)));
        this.eventBytes += termEnd - start;
      }
      i = termEnd;
      start = termEnd;
    }
    if (this.eventBytes + (len - start) > cap) {
      throw new StreamEventOverflow(events);
    }
    if (start > 0) {
      // Compact to the unfinished line and shift the cursor with it, so no
      // consumed byte is scanned or copied again.
      buf.copyWithin(0, start, len);
      this.len = len - start;
      this.pos = i - start;
    } else {
      this.pos = i;
    }
    this.lineStart = 0;
    return events;
  }
}

/**
 * Parses one event's field lines under sections 2.6-2.13. The data value is
 * joined with LF; the kind comes from `event` or the SSE default `message`.
 * The 2.17 size cap is the verifier's check.
 */
export function parseStreamFrame(lines: readonly StreamLine[]): StreamFrameParse {
  let kind: "message" | "jack-end" | null = null;
  let jack: string | null = null;
  const data: string[] = [];
  for (const line of lines) {
    const value = decodeUtf8Strict(line.value);
    if (value === null) {
      return BAD_FRAME; // 2.10
    }
    const name = line.name;
    if (name === "event") {
      if (kind !== null || (value !== "message" && value !== "jack-end")) {
        return BAD_FRAME; // 2.8
      }
      kind = value;
    } else if (name === "data") {
      data.push(value);
    } else if (name === "jack") {
      if (jack !== null) {
        return BAD_FRAME; // exactly one jack line (2.7)
      }
      jack = value;
    } else if (name === "id" || name === "retry") {
      return BAD_FRAME; // 2.11
    }
    // 2.13: any other field is ignored.
  }
  if (jack === null) {
    return BAD_FRAME;
  }
  const params = parseParams(jack, ["seq", "ts", "sig"]);
  if (params === null) {
    return BAD_FRAME;
  }
  const seqText = params.get("seq") ?? "";
  const tsText = params.get("ts") ?? "";
  const sig = params.get("sig") ?? "";
  if (!SEQ_RE.test(seqText) || !TS_RE.test(tsText) || !isStrictB64u(sig, 64)) {
    return BAD_FRAME;
  }
  const seq = Number(seqText);
  if (!Number.isSafeInteger(seq)) {
    return BAD_FRAME;
  }
  const dataValue = data.join("\n"); // 2.10
  const frameKind = kind ?? "message"; // SSE default event type (2.6)
  // 2.9: the kind is a function of the signed data, so it cannot be forged.
  if (frameKind === "message" ? dataValue === "" : dataValue !== "") {
    return BAD_FRAME;
  }
  return { ok: true, value: { kind: frameKind, data: dataValue, seq, ts: Number(tsText), sig } };
}

/**
 * The signalled code when `data` is byte-for-byte the 2.18 template with a
 * signalled code and a canonical limit; null for an ordinary message frame.
 */
export function streamSignalCode(data: string): StreamClientCode | null {
  for (const template of SIGNAL_TEMPLATES) {
    if (!data.startsWith(template.prefix) || !data.endsWith(SIGNAL_SUFFIX)) {
      continue;
    }
    const limit = data.slice(template.prefix.length, data.length - SIGNAL_SUFFIX.length);
    if (!LIMIT_RE.test(limit) || BigInt(limit) > LIMIT_MAX) {
      continue;
    }
    return template.code;
  }
  return null;
}

/** The exact bytes of the 2.6 frame shape, including the terminating blank line. */
export function serializeStreamFrame(v: {
  readonly kind: "message" | "jack-end";
  readonly data: string;
  readonly seq: number;
  readonly ts: number;
  readonly sig: string;
}): Uint8Array {
  const lines = [`event: ${v.kind}`];
  for (const piece of v.data.split("\n")) {
    lines.push(piece === "" ? "data:" : `data: ${piece}`);
  }
  lines.push(`jack: seq=${v.seq},ts=${v.ts},sig=${v.sig}`);
  return ENCODER.encode(`${lines.join("\n")}\n\n`);
}

/** Whether a delivered data value is the final JSON-RPC response of this request (spec 05 section 6.3). */
export function streamFinalResponseFor(data: string, requestId: unknown): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return false;
  }
  // JSON.parse only yields objects and arrays here, so this view reads own members safely.
  const obj = parsed as Record<string, unknown>;
  if (obj["jsonrpc"] !== "2.0" || Object.hasOwn(obj, "method")) {
    return false;
  }
  if (JSON.stringify(obj["id"]) !== JSON.stringify(requestId)) {
    return false;
  }
  return Object.hasOwn(obj, "result") !== Object.hasOwn(obj, "error");
}

/**
 * Strict UTF-8 decode (2.10). The round-trip rejects overlong forms, surrogate
 * halves and truncated sequences, matching the reference's buffer re-encode.
 */
export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  let text: string;
  try {
    text = STRICT_UTF8.decode(bytes);
  } catch {
    return null;
  }
  const again = ENCODER.encode(text);
  if (again.length !== bytes.length) {
    return null;
  }
  for (let i = 0; i < again.length; i++) {
    if (again[i] !== bytes[i]) {
      return null;
    }
  }
  return text;
}

/** 2.2 and 2.7: `name=value` pairs joined by single commas; each of `names` exactly once. */
function parseParams(value: string, names: readonly string[]): Map<string, string> | null {
  const out = new Map<string, string>();
  for (const part of value.split(",")) {
    const m = PARAM_RE.exec(part);
    if (m === null) {
      return null;
    }
    const name = m[1] ?? "";
    const v = m[2] ?? "";
    if (!names.includes(name) || out.has(name)) {
      return null;
    }
    out.set(name, v);
  }
  return out.size === names.length ? out : null;
}

/** Strict unpadded base64url of an exact decoded length; the round-trip rejects padding and non-canonical bits. */
function isStrictB64u(value: string, size: number): boolean {
  try {
    decodeBase64URLFixed(value, size);
    return true;
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      return false;
    }
    throw err;
  }
}

/** Splits one line at its first colon; no colon means a bare name with an empty value (2.13), and one leading SP is dropped (2.6). */
function splitField(line: Uint8Array): StreamLine {
  let colon = -1;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === COLON) {
      colon = i;
      break;
    }
  }
  if (colon < 0) {
    return { name: latin1(line), value: EMPTY };
  }
  let value = line.subarray(colon + 1);
  if (value[0] === SP) {
    value = value.subarray(1);
  }
  return { name: latin1(line.subarray(0, colon)), value };
}

/** Field names compare as bytes, so map each byte to one char (latin1), never through UTF-8. */
function latin1(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i] ?? 0);
  }
  return out;
}

/** Concatenates two byte arrays without touching either input. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) {
    return b;
  }
  if (b.length === 0) {
    return a;
  }
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
