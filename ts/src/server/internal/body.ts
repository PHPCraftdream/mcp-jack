/**
 * Body classification of spec 02 section 4: strict UTF-8 validation of the
 * exact body bytes, then the JSON-RPC object rules (Go classifyBody). Kept
 * behind the server facade: verify.ts re-exports the public names from here.
 */
import { parseJsonRaw } from "../../core/json-raw.js";
import type { JsonValue, RawJsonNode } from "../../core/json-raw.js";

// One shared strict UTF-8 decoder: a decode failure is exactly "not valid
// UTF-8" (overlong, lone surrogates, truncated sequences all fail) and it
// happens BEFORE any JSON parsing, per spec 02 section 4. ignoreBOM keeps a
// leading BOM in the decoded text (RFC 8259 forbids one before JSON text);
// the tokenizer's whitespace set does not include U+FEFF, so a BOM-prefixed
// body fails parsing and is invalid_request. The reference verifier strips
// the BOM — spec-wins divergence, no fixture covers it.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// ---------------------------------------------------------------------------
// Body classification (spec 02 section 4; Go classifyBody).
// ---------------------------------------------------------------------------

export type RpcKind = "request" | "response";

/** The part of a JSON-RPC object the verifier needs. */
export interface RpcMessage {
  readonly kind: RpcKind;
  /** Raw JSON text of the id member as sent; undefined when absent. */
  readonly id: string | undefined;
  /** Request/notification method; "" for a response. */
  readonly method: string;
  /** True for a tools/call whose params.name is a string. */
  readonly hasTool: boolean;
  /** params.name when hasTool; "" otherwise. */
  readonly tool: string;
  /** Raw JSON text of params.arguments as sent; undefined when absent; tools/call only. */
  readonly arguments: string | undefined;
}

/** True when v is a plain JSON object (not null, not an array). */
function isPlainObject(v: JsonValue): boolean {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// The maximum nesting depth of arrays and objects the body may reach
// (spec 02 section 4 step 2).
const MAX_BODY_DEPTH = 128;

/** Member names of one open object; expectKey is true while the next string is a name. */
interface ObjectScope {
  readonly names: Set<string>;
  expectKey: boolean;
}

/** One-character escapes of JSON strings; anything else maps to itself (the parser rejects it later). */
const SIMPLE_ESCAPES: ReadonlyMap<number, number> = new Map([
  [0x62, 0x08],
  [0x66, 0x0c],
  [0x6e, 0x0a],
  [0x72, 0x0d],
  [0x74, 0x09],
]);

/** UTF-8 bytes of a scalar value as a Latin-1 string, so escaped and raw spellings of a name compare equal. */
function utf8Latin1(cp: number): string {
  if (cp < 0x80) return String.fromCharCode(cp);
  if (cp < 0x800) return String.fromCharCode(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
  if (cp < 0x10000) {
    return String.fromCharCode(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return String.fromCharCode(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
}

/**
 * The body-text rules of spec 02 section 4 step 2, checked on the raw bytes
 * before decoding: a \uXXXX string escape that does not form a Unicode scalar
 * value (a lone or unpaired surrogate), nesting deeper than MAX_BODY_DEPTH
 * levels of arrays and objects, or an object with two members of the same
 * name (compared after unescaping, exact). One byte pass, no recursion, extra
 * space bounded by the depth and the member names of the open objects:
 * JSON.parse-family parsing would keep a lone surrogate and silently keep the
 * last duplicate, and the recursive tokenizer dies on the stack long after
 * the limit.
 */
function unacceptableBody(body: Uint8Array): boolean {
  let inString = false;
  // Set only while inside a member NAME; undefined for every other string.
  let name: string | undefined;
  const scopes: (ObjectScope | null)[] = [];
  let i = 0;
  while (i < body.length) {
    const c = body[i] as number;
    const top = scopes[scopes.length - 1];
    if (!inString) {
      if (c === 0x22) {
        inString = true;
        name = top?.expectKey === true ? "" : undefined;
      } else if (c === 0x7b || c === 0x5b) {
        scopes.push(c === 0x7b ? { names: new Set<string>(), expectKey: true } : null);
        if (scopes.length > MAX_BODY_DEPTH) return true;
      } else if (c === 0x7d || c === 0x5d) {
        scopes.pop();
      } else if (c === 0x3a && top) {
        top.expectKey = false;
      } else if (c === 0x2c && top) {
        top.expectKey = true;
      }
      i += 1;
      continue;
    }
    if (c === 0x22) {
      inString = false;
      if (name !== undefined && top) {
        if (top.names.has(name)) return true;
        top.names.add(name);
      }
      name = undefined;
      i += 1;
      continue;
    }
    if (c !== 0x5c) {
      if (name !== undefined) name += String.fromCharCode(c);
      i += 1;
      continue;
    }
    // Escape handling mirrors the Go/Rust helpers byte for byte.
    if (i + 1 >= body.length) return true;
    if (body[i + 1] !== 0x75) {
      const e = body[i + 1] as number;
      if (name !== undefined) name += String.fromCharCode(SIMPLE_ESCAPES.get(e) ?? e);
      i += 2; // two-byte escape; an escaped backslash keeps the string going
      continue;
    }
    if (i + 6 > body.length) return true;
    const v = hex4(body, i + 2);
    if (v < 0) {
      i += 2; // not a \uXXXX escape: invalid JSON, the parser rejects it
      continue;
    }
    if (v >= 0xdc00 && v <= 0xdfff) return true; // lone low surrogate
    if (v < 0xd800 || v > 0xdbff) {
      if (name !== undefined) name += utf8Latin1(v);
      i += 6; // ordinary \uXXXX escape
      continue;
    }
    // A high surrogate must be followed immediately by \uDC00..\uDFFF.
    const low =
      i + 12 <= body.length && body[i + 6] === 0x5c && body[i + 7] === 0x75
        ? hex4(body, i + 8)
        : -1;
    if (low >= 0xdc00 && low <= 0xdfff) {
      if (name !== undefined) name += utf8Latin1(0x10000 + ((v - 0xd800) << 10) + (low - 0xdc00));
      i += 12; // consume both escapes
      continue;
    }
    return true; // unpaired high surrogate
  }
  return false;
}

/** Parses the four ASCII hex digits at body[at], or -1. */
function hex4(body: Uint8Array, at: number): number {
  let v = 0;
  for (let k = 0; k < 4; k++) {
    const c = body[at + k] as number | undefined;
    if (c === undefined) return -1;
    let d: number;
    if (c >= 0x30 && c <= 0x39) d = c - 0x30;
    else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
    else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
    else return -1;
    v = (v << 4) | d;
  }
  return v;
}

/**
 * The body rules of spec 02 section 4. Order matters: strict UTF-8 validation
 * of the EXACT bytes happens BEFORE any JSON parse (JSON.parse would silently
 * replace invalid bytes). All member lookups go through the members MAP, never
 * `value.__proto__`-style access, so a tool literally named "__proto__"
 * (fixture authz-proto-tool-name) flows through classification like any other name and
 * a "__proto__" member cannot alias another member's path. Returns undefined
 * when the body is not an acceptable JSON-RPC object. An empty POST has no
 * jsonrpc member and is rejected here.
 */
export function classifyBody(body: Uint8Array): RpcMessage | undefined {
  if (unacceptableBody(body)) return undefined;
  let text: string;
  let parsed: { value: JsonValue; source: RawJsonNode };
  try {
    text = UTF8.decode(body);
    parsed = parseJsonRaw(text);
  } catch {
    return undefined; // invalid UTF-8 or invalid JSON
  }
  // (3) root must be a plain JSON object.
  if (!isPlainObject(parsed.value)) return undefined;
  const members = parsed.source.members;
  if (members === undefined) return undefined;

  // (4) jsonrpc must exist and be exactly the string "2.0".
  const version = members.get("jsonrpc");
  if (version === undefined || version.value !== "2.0") return undefined;

  const id = members.get("id")?.text;
  if (!members.has("method")) {
    // (6) A response exists iff id is present AND exactly one of
    // result/error is present (presence via the members map, values
    // irrelevant — an `error: null` still counts, Go parity).
    const hasResult = members.has("result");
    const hasError = members.has("error");
    if (members.has("id") && hasResult !== hasError) {
      return { kind: "response", id, method: "", hasTool: false, tool: "", arguments: undefined };
    }
    return undefined;
  }

  // (5) A request/notification: method must be a string.
  const methodNode = members.get("method");
  if (methodNode === undefined || typeof methodNode.value !== "string") return undefined;
  const method = methodNode.value;

  if (method === "tools/call") {
    // params must exist and be a plain object; name must exist and be a string.
    const params = members.get("params");
    if (params === undefined || !isPlainObject(params.value) || params.members === undefined) return undefined;
    const name = params.members.get("name");
    if (name === undefined || typeof name.value !== "string") return undefined;
    const args = params.members.get("arguments");
    return {
      kind: "request",
      id,
      method,
      hasTool: true,
      tool: name.value,
      arguments: args === undefined ? undefined : args.text,
    };
  }
  return { kind: "request", id, method, hasTool: false, tool: "", arguments: undefined };
}

/** The exact body text when the bytes are valid UTF-8, undefined otherwise. */
export function bodyText(body: Uint8Array): string | undefined {
  try {
    return UTF8.decode(body);
  } catch {
    return undefined;
  }
}
