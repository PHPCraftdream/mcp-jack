/** Client-side codes, negotiation headers and defaults of signed streams (spec 05 sections 1.1, 1.4, 2.18, 3.2-3.5 and 4.6). */

/** The closed list of client-only rejection codes of spec 05 section 4.6, in spec order. */
export const STREAM_CLIENT_CODES = [
  "stream_missing_auth",
  "stream_malformed_auth",
  "stream_unsupported_version",
  "stream_unknown_server_key",
  "stream_out_of_window",
  "stream_bad_signature",
  "stream_bad_frame",
  "stream_out_of_order",
  "stream_stale_frame",
  "stream_truncated",
  "stream_idle",
  "stream_frame_too_large",
  "stream_after_cutoff",
] as const;

/** One code of the closed list of section 4.6. */
export type StreamClientCode = (typeof STREAM_CLIENT_CODES)[number];

/** The request header that opts a request into a signed stream (spec 05 section 1.1). */
export const STREAM_ACCEPT_HEADER = "Jack-Accept";

/** The only stream scheme this profile defines (spec 05 section 2.2). */
export const STREAM_SCHEME = "s1";

/** Codes a server may signal in a 2.18 transport signal frame; a subset of section 4.6. */
export const STREAM_SIGNAL_CODES: readonly StreamClientCode[] = ["stream_frame_too_large"];

/** Default `frameMaxBytes` (spec 05 section 3.2). */
export const STREAM_DEFAULT_FRAME_MAX_BYTES = 1048576;

/** Smallest legal `frameMaxBytes`, so a 2.18 signal always fits (spec 05 section 3.2). */
export const STREAM_MIN_FRAME_MAX_BYTES = 1024;

/** Default `maxConcurrentStreams` per authenticated identity (spec 05 section 3.3). */
export const STREAM_DEFAULT_MAX_CONCURRENT_STREAMS = 4;

/** Default `maxStreamDurationMs` (spec 05 section 3.4). */
export const STREAM_DEFAULT_MAX_DURATION_MS = 3600000;

/** Default client idle timeout in milliseconds (spec 05 section 4.5). */
export const STREAM_DEFAULT_IDLE_MS = 90000;

/** Default verification window in seconds; heartbeat grants derive from it (spec 05 section 3.5 and spec 01 section 4). */
export const STREAM_DEFAULT_WINDOW_SECONDS = 30;

// OWS is *SP only (HTAB is not admitted), and the token alphabet is section 1.1's.
const ACCEPT_LINE_RE = /^ *[A-Za-z0-9-]+(?: *, *[A-Za-z0-9-]+)*$/;
const SPACE_OWS_RE = /^ +| +$/g;
const SP = 0x20;
const HTAB = 0x09;

/**
 * Whether any `Jack-Accept` line admits the `s1` token (spec 05 section 1.1).
 * A line the grammar rejects contributes no token, so it cannot enable a stream.
 */
export function jackAcceptStreams(headerValues: readonly string[]): boolean {
  for (const line of headerValues) {
    if (!ACCEPT_LINE_RE.test(line)) {
      continue;
    }
    for (const part of line.split(",")) {
      if (part.replace(SPACE_OWS_RE, "") === STREAM_SCHEME) {
        return true;
      }
    }
  }
  return false;
}

/** Whether a response is a signed stream rather than a v1 response (spec 05 section 1.4). */
export function isStreamResponse(status: number, headers: readonly (readonly [string, string])[]): boolean {
  if (status !== 200) {
    return false;
  }
  for (const [name, value] of headers) {
    if (asciiLower(name) !== "content-type") {
      continue;
    }
    const mediaType = trimSpAndHtab((value.split(";")[0] ?? ""));
    if (asciiLower(mediaType) === "text/event-stream") {
      return true;
    }
  }
  return false;
}

/**
 * The heartbeat grant of spec 05 section 3.5: never above `floor(W * 500)`.
 * `W` is the server's own configured window in seconds.
 */
export function grantedHeartbeatMs(requested: number | undefined, windowSeconds: number): number {
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 120) {
    throw new Error("server: windowSeconds must be an integer between 1 and 120 seconds");
  }
  if (requested !== undefined && (!Number.isSafeInteger(requested) || requested <= 0)) {
    throw new Error("server: requested heartbeatMs must be a positive safe integer");
  }
  const cap = Math.floor(windowSeconds * 500);
  return Math.min(requested ?? cap, cap);
}

/** A stream verification terminal error, carrying the code and how many frames had verified before it (spec 05 section 4.6). */
export class StreamVerifyError extends Error {
  readonly code: StreamClientCode;
  readonly framesVerified: number;

  constructor(code: StreamClientCode, framesVerified: number) {
    super(`jack stream: ${code} after ${framesVerified} verified frames`);
    this.name = "StreamVerifyError";
    this.code = code;
    this.framesVerified = framesVerified;
  }
}

/** ASCII-only lowercasing of header names and media types (section 1.4 compares them case-insensitively). */
function asciiLower(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s.charAt(i);
  }
  return out;
}

/** Trim leading and trailing SP and HTAB only, as the media-type rule of section 1.4 requires. */
function trimSpAndHtab(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && (s.charCodeAt(a) === SP || s.charCodeAt(a) === HTAB)) {
    a++;
  }
  while (b > a && (s.charCodeAt(b - 1) === SP || s.charCodeAt(b - 1) === HTAB)) {
    b--;
  }
  return s.slice(a, b);
}
