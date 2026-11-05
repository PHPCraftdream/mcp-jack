/**
 * The request verifier: header grammar, key lookup, time window, signature,
 * nonce and policy, in spec check order (spec 01 section 4, spec 02 section 4).
 *
 * CENTRAL DESIGN DECISION — raw JSON source text.
 * `JSON.parse` loses the raw text of numbers and members, but spec 03 section 3
 * judges native-tool integer arguments on their JSON TEXT (no fraction, no
 * exponent; `-0` is 0), and Go's `json.RawMessage` keeps the raw bytes of `id`
 * and `params.arguments`. This file therefore contains a small strict JSON
 * tokenizer, ported from the reference verifier's `parseJSONRaw`, returning the
 * parsed value PLUS a parallel source tree where every value node carries its
 * exact source text. From that tree the verifier takes the raw text of the
 * top-level `id` (Go Result.RPCID) and the raw text of `params.arguments`
 * (handed to native tools so integer rules can be judged lexically). The
 * tokenizer is exported for reuse by the native-tools task.
 */
import type { RequestAuth } from "../auth-header.js";
import { parseRequestAuth } from "../auth-header.js";
import { BadBase64UrlError, decodeBase64URLFixed, keyId } from "../encoding.js";
import { validatePublicKey, verify as verifyEd25519 } from "../ed25519.js";
import { Code, JackError } from "../errors.js";
import { requestSigningString } from "../signing.js";
import type { AuditEvent, AuditSink } from "./audit.js";
import { AUDIT_FAILURE, AUDIT_SUCCESS } from "./audit.js";
import type { NonceStore } from "./nonce.js";
import type { Policy } from "./policy.js";
import type { RegistryEntry, StateStore } from "./state.js";

// One shared strict UTF-8 decoder: a decode failure is exactly "not valid
// UTF-8" (overlong, lone surrogates, truncated sequences all fail) and it
// happens BEFORE any JSON parsing, per spec 02 section 4. ignoreBOM keeps a
// leading BOM in the decoded text (RFC 8259 forbids one before JSON text);
// the tokenizer's whitespace set does not include U+FEFF, so a BOM-prefixed
// body fails parsing and is invalid_request. The reference verifier strips
// the BOM — spec-wins divergence, no fixture covers it.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// The signing string is signed over its UTF-8 encoding (Go: []byte(signing)).
const ENCODER = new TextEncoder();

// ---------------------------------------------------------------------------
// Strict JSON tokenizer with a parallel source tree (parseJSONRaw, ported).
// ---------------------------------------------------------------------------

/** Any JSON value. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** One node of the parallel source tree: exact text plus parsed value. */
export interface RawJsonNode {
  /** Exact source slice of this value. */
  readonly text: string;
  /** Parsed value (numbers decode like Number(), strings like JSON.parse). */
  readonly value: JsonValue;
  /** Object member nodes, last duplicate wins; undefined for non-objects. */
  readonly members: ReadonlyMap<string, RawJsonNode> | undefined;
  /** Array element nodes; undefined for non-arrays. */
  readonly items: readonly RawJsonNode[] | undefined;
}

/**
 * Strict RFC 8259 parser: throws Error("invalid JSON") on any violation,
 * including trailing content after the root value. Whitespace is exactly
 * " \t\n\r"; raw control chars (< 0x20) in strings violate; escapes are
 * \" \\ \/ \b \f \n \r \t \uXXXX (4 hex digits, any other escape violates).
 * Duplicate object keys keep the LAST (value object and members map alike) —
 * accepted behavior, spec tests README Q11. A member named "__proto__" is
 * defined with Object.defineProperty so it becomes an own property instead of
 * a prototype change (JSON.parse parity; the reference verifier does the
 * same); all other keys by plain assignment. The members Map needs no such
 * care (a Map has no prototype hazard). Each source node is built complete at
 * construction — value, exact text and members/items are all present when the
 * node literal is created; no node is mutated after construction.
 */
export function parseJsonRaw(text: string): { readonly value: JsonValue; readonly source: RawJsonNode } {
  let i = 0;
  const fail = (): never => {
    throw new Error("invalid JSON");
  };
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i] as string)) i++;
  };
  const digit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";
  // An own property even for the key "__proto__", which plain assignment
  // would turn into a prototype change.
  const setMember = (obj: { [key: string]: JsonValue }, key: string, value: JsonValue): void => {
    if (key === "__proto__") {
      Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
    } else {
      obj[key] = value;
    }
  };

  function string(): string {
    i += 1; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail();
      const c = text[i] as string;
      if (c === '"') {
        i += 1;
        return out;
      }
      if (c === "\\") {
        const e = text[i + 1];
        i += 2;
        if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else fail();
      } else {
        if (text.charCodeAt(i) < 0x20) fail(); // raw control char
        out += c;
        i += 1;
      }
    }
  }

  function number(): number {
    const start = i;
    if (text[i] === "-") i += 1;
    // RFC 8259 grammar: no leading zeros; fraction and exponent when present.
    if (text[i] === "0") i += 1;
    else if (digit(text[i])) {
      while (i < text.length && digit(text[i])) i += 1;
    } else fail();
    if (text[i] === ".") {
      i += 1;
      if (!digit(text[i])) fail();
      while (i < text.length && digit(text[i])) i += 1;
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      if (text[i] === "+" || text[i] === "-") i += 1;
      if (!digit(text[i])) fail();
      while (i < text.length && digit(text[i])) i += 1;
    }
    return Number(text.slice(start, i));
  }

  // Parses one value and builds its node in one step: value, exact source text
  // and members/items are all present at construction, so no node can ever be
  // observed with a placeholder value. The source tree is the single source of
  // truth; `parseJsonRaw`'s returned value is `root.value`.
  function valueNode(): RawJsonNode {
    ws();
    const start = i;
    const c = text[i];
    if (c === "{") {
      i += 1;
      ws();
      const obj: { [key: string]: JsonValue } = {};
      const members = new Map<string, RawJsonNode>();
      if (text[i] === "}") {
        i += 1;
        return { text: text.slice(start, i), value: obj, members, items: undefined };
      }
      for (;;) {
        if (text[i] !== '"') fail();
        const key = string();
        ws();
        if (text[i] !== ":") fail();
        i += 1;
        const child = valueNode();
        // Last duplicate wins in the members map and the value object alike.
        members.set(key, child);
        setMember(obj, key, child.value);
        ws();
        if (text[i] === ",") {
          i += 1;
          ws();
          continue;
        }
        if (text[i] === "}") {
          i += 1;
          return { text: text.slice(start, i), value: obj, members, items: undefined };
        }
        fail();
      }
    }
    if (c === "[") {
      i += 1;
      ws();
      const arr: JsonValue[] = [];
      const items: RawJsonNode[] = [];
      if (text[i] === "]") {
        i += 1;
        return { text: text.slice(start, i), value: arr, members: undefined, items };
      }
      for (;;) {
        const child = valueNode();
        items.push(child);
        arr.push(child.value);
        ws();
        if (text[i] === ",") {
          i += 1;
          ws();
          continue;
        }
        if (text[i] === "]") {
          i += 1;
          return { text: text.slice(start, i), value: arr, members: undefined, items };
        }
        fail();
      }
    }
    if (c === '"') {
      const s = string();
      return { text: text.slice(start, i), value: s, members: undefined, items: undefined };
    }
    if (text.startsWith("true", i)) {
      i += 4;
      return { text: text.slice(start, i), value: true, members: undefined, items: undefined };
    }
    if (text.startsWith("false", i)) {
      i += 6;
      return { text: text.slice(start, i), value: false, members: undefined, items: undefined };
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return { text: text.slice(start, i), value: null, members: undefined, items: undefined };
    }
    const n = number();
    return { text: text.slice(start, i), value: n, members: undefined, items: undefined };
  }

  const root = valueNode();
  ws();
  if (i !== text.length) fail(); // trailing content is a violation
  return { value: root.value, source: root };
}

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

/**
 * The body rules of spec 02 section 4. Order matters: strict UTF-8 validation
 * of the EXACT bytes happens BEFORE any JSON parse (JSON.parse would silently
 * replace invalid bytes). All member lookups go through the members MAP, never
 * `value.__proto__`-style access, so a tool literally named "__proto__"
 * (fixture authz-proto-tool-name) flows to the policy like any other name and
 * a "__proto__" member cannot alias another member's path. Returns undefined
 * when the body is not an acceptable JSON-RPC object. An empty POST has no
 * jsonrpc member and is rejected here.
 */
export function classifyBody(body: Uint8Array): RpcMessage | undefined {
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

// ---------------------------------------------------------------------------
// Protocol-native extension point (Go NativeCall/NativeResult/NativeTools);
// the real tools are a LATER task.
// ---------------------------------------------------------------------------

/** Timestamp acceptance window in seconds (spec 01 section 4). */
export const DEFAULT_WINDOW = 30;

/** Names of the protocol-native tools (spec 03); "jack."-prefixed tools never reach the policy. */
export const TOOL_ENROLL = "jack.enroll";
export const TOOL_WHOAMI = "jack.whoami";
export const TOOL_ROTATE_KEY = "jack.key.rotate";
export const TOOL_ADMIN_USER_LIST = "jack.admin.user.list";
export const TOOL_ADMIN_USER_GET = "jack.admin.user.get";
export const TOOL_ADMIN_USER_CREATE = "jack.admin.user.create";
export const TOOL_ADMIN_USER_SET_SCOPES = "jack.admin.user.set_scopes";
export const TOOL_ADMIN_USER_REVOKE = "jack.admin.user.revoke";
export const TOOL_ADMIN_INVITE_CREATE = "jack.admin.invite.create";
export const TOOL_ADMIN_INVITE_LIST = "jack.admin.invite.list";
export const TOOL_ADMIN_INVITE_REVOKE = "jack.admin.invite.revoke";

const NATIVE_TOOLS: ReadonlySet<string> = new Set([
  TOOL_ENROLL,
  TOOL_WHOAMI,
  TOOL_ROTATE_KEY,
  TOOL_ADMIN_USER_LIST,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_CREATE,
  TOOL_ADMIN_USER_SET_SCOPES,
  TOOL_ADMIN_USER_REVOKE,
  TOOL_ADMIN_INVITE_CREATE,
  TOOL_ADMIN_INVITE_LIST,
  TOOL_ADMIN_INVITE_REVOKE,
]);

/** IsNativeTool: membership in the 11 protocol-native tool names. */
export function isNativeTool(name: string): boolean {
  return NATIVE_TOOLS.has(name);
}

/** Spec 03 section 8: calls to these tools are written to the audit sink. */
function auditedTool(name: string): boolean {
  return name === TOOL_ENROLL || name === TOOL_ROTATE_KEY || name.startsWith("jack.admin.");
}

/** What a protocol-native tool handler receives. */
export interface NativeCall {
  readonly tool: string;
  /**
   * params.arguments EXACTLY as sent (raw JSON text); undefined when absent.
   * Native tools judge integer arguments on this text (spec 03 section 3).
   */
  readonly arguments: string | undefined;
  /** Registry entry of the authenticated key; undefined for an enrollment signed by an unregistered key. */
  readonly caller: RegistryEntry | undefined;
  readonly kid: string;
  /** ts parameter of the Jack-Auth header (rotate proofs bind it). */
  readonly ts: number;
  /** Verifier clock, Unix seconds. */
  readonly now: number;
  readonly aud: string;
  readonly state: StateStore;
  /**
   * OUTPUT field (the only mutable one): the handler sets what the audit
   * event names as target (a kid, an invite id or a name), even on failure.
   */
  target: string;
}

/** The successful outcome of a native tool; becomes the CallToolResult structuredContent. */
export interface NativeResult {
  readonly structured: unknown;
}

/**
 * Implements the protocol-native tools of spec 03. call() throws JackError
 * for every protocol rejection; ANY OTHER thrown error is a programming error
 * and PROPAGATES out of Verifier.verify uncaught (Go signals it as a separate
 * error return that the caller treats as a bug — here it is an exception).
 */
export interface NativeTools {
  call(c: NativeCall): NativeResult;
}

// ---------------------------------------------------------------------------
// Verifier.
// ---------------------------------------------------------------------------

/** One HTTP request reduced to what verification needs. */
export interface VerifyRequest {
  readonly method: string;
  /** The origin-form request target exactly as received. */
  readonly target: string;
  /** Every Jack-Auth header value in order. */
  readonly authValues: readonly string[];
  /** Exact body bytes. */
  readonly body: Uint8Array;
}

/** Mirrors Go Result; zero-value style ("" / 0 / undefined) instead of optionals. */
export interface VerifyResult {
  readonly accepted: boolean;
  /** Authenticated kid; "" when authentication failed. */
  readonly kid: string;
  /** 0 when accepted. */
  readonly httpStatus: number;
  /** "" when accepted. */
  readonly code: string;
  readonly message: string;
  /** True once authentication succeeded, including authorization rejections. */
  readonly nonceRecorded: boolean;
  /** "" before auth parsed; the response is bound to it. */
  readonly requestSig: string;
  /** Raw JSON text of the id; undefined for notifications/non-JSON-RPC. */
  readonly rpcId: string | undefined;
  /** "" unless tools/call. */
  readonly tool: string;
  readonly native: boolean;
  /** undefined unless a native tool call succeeded. */
  readonly structured: unknown;
  readonly audit: AuditEvent | undefined;
}

/** Verifier configuration. */
export interface VerifierConfig {
  readonly aud: string;
  readonly state: StateStore;
  readonly nonces: NonceStore;
  readonly policy: Policy;
  /** Optional sink. */
  readonly audit?: AuditSink;
  /** When undefined every jack.* tool is 403 operation_denied. */
  readonly native?: NativeTools;
  /** Seconds; undefined or <= 0 => DEFAULT_WINDOW. */
  readonly window?: number;
  /**
   * REQUIRED injected clock in Unix seconds; the verifier never reads the
   * wall clock (spec tests README "Inject the clock"). Deliberate divergence
   * from Go, whose Config.Now defaults to the wall clock.
   */
  readonly now: () => number;
}

/** Internal mutable accumulator; one VerifyResult literal is built from it. */
interface ResultBuilder {
  accepted: boolean;
  httpStatus: number;
  code: string;
  message: string;
  rpcId: string | undefined;
  tool: string;
  native: boolean;
  structured: unknown;
  audit: AuditEvent | undefined;
}

/** Whether now is inside the entry's validity interval (spec 02 section 1: not_before <= now < not_after). */
function entryActive(e: RegistryEntry, now: number): boolean {
  return (
    (e.notBefore === undefined || e.notBefore === null || e.notBefore <= now) &&
    (e.notAfter === undefined || e.notAfter === null || now < e.notAfter)
  );
}

export class Verifier {
  private readonly aud: string;
  private readonly state: StateStore;
  private readonly nonces: NonceStore;
  private readonly policy: Policy;
  private readonly audit: AuditSink | undefined;
  private readonly native: NativeTools | undefined;
  private readonly window: number;
  private readonly now: () => number;

  /** Throws when aud is "" or state/nonces/policy/now are missing (Go NewVerifier parity). */
  constructor(cfg: VerifierConfig) {
    if (cfg.aud === "") throw new Error("server: VerifierConfig.aud must be non-empty");
    if (cfg.state === undefined) throw new Error("server: VerifierConfig.state must be set");
    if (cfg.nonces === undefined) throw new Error("server: VerifierConfig.nonces must be set");
    if (cfg.policy === undefined) throw new Error("server: VerifierConfig.policy must be set");
    if (cfg.now === undefined) throw new Error("server: VerifierConfig.now must be set");
    this.aud = cfg.aud;
    this.state = cfg.state;
    this.nonces = cfg.nonces;
    this.policy = cfg.policy;
    this.audit = cfg.audit;
    this.native = cfg.native;
    this.window = cfg.window === undefined || cfg.window <= 0 ? DEFAULT_WINDOW : cfg.window;
    this.now = cfg.now;
  }

  /** Runs the pipeline of spec 01 section 4 / spec 02 section 4; stops at the first failing step. */
  verify(req: VerifyRequest): VerifyResult {
    const now = this.now();

    // Step 1: header grammar. JackError carries its own status/code; any
    // other error is a programming error reported as 500 internal_error.
    let auth: RequestAuth;
    try {
      auth = parseRequestAuth(req.authValues);
    } catch (err) {
      if (err instanceof JackError) {
        return rejected(err.httpStatus, err.code, err.message);
      }
      return rejected(500, "internal_error", "internal error");
    }

    // Step 2: key lookup, with the enrollment exception of spec 01 section 4
    // and spec 03 section 3.2.
    const entry = this.state.lookup(auth.kid);
    let key: Uint8Array;
    let caller: RegistryEntry | undefined;
    if (entry !== undefined) {
      if (!entryActive(entry, now)) {
        return rejected(401, Code.KEY_INACTIVE, "key is not active");
      }
      try {
        key = decodeBase64URLFixed(entry.publicKey, 32);
      } catch (err) {
        if (err instanceof BadBase64UrlError) {
          // Unreachable: the registry loader validates keys.
          return rejected(500, "internal_error", "registry holds an invalid public key");
        }
        throw err;
      }
      caller = entry;
    } else {
      const enrolled = this.enrollmentKey(req, auth.kid);
      if ("rejection" in enrolled) {
        return enrolled.rejection;
      }
      key = enrolled.key;
    }

    // Step 3: timestamp window.
    if (Math.abs(now - auth.ts) > this.window) {
      return rejected(401, Code.TIMESTAMP_OUT_OF_WINDOW, "timestamp is outside the acceptance window");
    }

    // Step 4: signature over the signing string, with the SUBMITTED key for
    // an enrollment.
    let sig: Uint8Array;
    try {
      sig = decodeBase64URLFixed(auth.sig, 64);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        // Unreachable: parseRequestAuth pre-validates fixed-length fields.
        return rejected(401, Code.BAD_SIGNATURE, "malformed signature");
      }
      throw err;
    }
    const signing = requestSigningString(req.method, req.target, this.aud, auth.kid, auth.ts, auth.nonce, req.body);
    if (!verifyEd25519(key, ENCODER.encode(signing), sig)) {
      return rejected(401, Code.BAD_SIGNATURE, "signature does not verify");
    }

    // Step 5: nonce, only after the signature verified, so unauthenticated
    // requests cannot fill the cache (spec 01 section 4). True = live replay.
    if (this.nonces.checkAndRecord(auth.kid, auth.nonce, now, auth.ts + this.window)) {
      return rejected(401, Code.REPLAYED_NONCE, "nonce was already used");
    }

    // Step 6 (Go step 9): authorization, on a builder carrying the
    // authentication outcome.
    const b: ResultBuilder = {
      accepted: false,
      httpStatus: 0,
      code: "",
      message: "",
      rpcId: undefined,
      tool: "",
      native: false,
      structured: undefined,
      audit: undefined,
    };
    const done = this.authorize(req, auth, now, caller, b);
    return {
      accepted: done.accepted,
      kid: auth.kid,
      httpStatus: done.httpStatus,
      code: done.code,
      message: done.message,
      nonceRecorded: true,
      requestSig: auth.sig,
      rpcId: done.rpcId,
      tool: done.tool,
      native: done.native,
      structured: done.structured,
      audit: done.audit,
    };
  }

  /**
   * Step 9: body shape, protocol-native tools, policy. `b` already carries
   * kid/nonceRecorded/requestSig at the caller; this sets the rest of it.
   */
  private authorize(
    req: VerifyRequest,
    auth: RequestAuth,
    now: number,
    caller: RegistryEntry | undefined,
    b: ResultBuilder,
  ): ResultBuilder {
    const fail = (status: number, code: string, message: string): ResultBuilder => {
      b.accepted = false;
      b.httpStatus = status;
      b.code = code;
      b.message = message;
      return b;
    };

    // GET is authorized by authentication alone; no JSON-RPC is involved.
    // Any non-GET method is processed like POST here — the 405 for other
    // verbs is the HTTP adapter's job (later task).
    if (req.method === "GET") {
      b.accepted = true;
      return b;
    }

    const msg = classifyBody(req.body);
    if (msg === undefined) {
      // The nonce stays consumed: authentication already succeeded.
      return fail(400, Code.INVALID_REQUEST, "the body is not an acceptable JSON-RPC object");
    }
    b.rpcId = msg.id;
    if (msg.kind === "response") {
      // A client answering a server-initiated request: authorized by
      // authentication alone.
      b.accepted = true;
      return b;
    }
    if (msg.hasTool) {
      b.tool = msg.tool;
    }

    // NATIVE: "jack."-prefixed tools never reach the policy.
    if (msg.hasTool && msg.tool.startsWith("jack.")) {
      b.native = true;
      if (!isNativeTool(msg.tool) || this.native === undefined) {
        // NO audit event: the call never reached a tool (spec 03 section 8).
        return fail(403, Code.OPERATION_DENIED, "operation is not permitted");
      }
      const call: NativeCall = {
        tool: msg.tool,
        arguments: msg.arguments,
        caller,
        kid: auth.kid,
        ts: auth.ts,
        now,
        aud: this.aud,
        state: this.state,
        target: "",
      };
      // Go writes the audit event BEFORE handling the handler error; keep that
      // order on both exits.
      const writeAudit = (failure: JackError | undefined): void => {
        if (!auditedTool(msg.tool)) {
          return;
        }
        // ONE literal with conditional spreads: optional AuditEvent fields are
        // never assigned undefined (exactOptionalPropertyTypes).
        const event: AuditEvent = {
          time: now,
          tool: msg.tool,
          outcome: failure === undefined ? AUDIT_SUCCESS : AUDIT_FAILURE,
          actorKid: auth.kid,
          target: call.target,
          ...(caller !== undefined ? { actorName: caller.name } : {}),
          ...(failure !== undefined ? { code: failure.code } : {}),
        };
        b.audit = event;
        if (this.audit !== undefined) {
          // Go ignores the sink error; so do we.
          try {
            this.audit.record(event);
          } catch {
            /* sink failures never affect the verdict */
          }
        }
      };
      try {
        const out = this.native.call(call);
        writeAudit(undefined);
        b.accepted = true;
        b.structured = out.structured;
        return b;
      } catch (err) {
        // JackError is a protocol rejection; anything else is a programming
        // error and PROPAGATES (documented on NativeTools).
        if (!(err instanceof JackError)) {
          throw err;
        }
        writeAudit(err);
        return fail(err.httpStatus, err.code, err.message);
      }
    }

    // POLICY: everything else.
    if (caller === undefined) {
      // Unreachable: only a jack.enroll request passes step 2 without a
      // registry entry, and it went through the native branch. Kept
      // defensive like Go.
      return fail(401, Code.UNKNOWN_KEY, "unknown key");
    }
    const d = this.policy.evaluate(msg.method, msg.hasTool ? msg.tool : undefined);
    if (!d.allowed) {
      return fail(403, Code.OPERATION_DENIED, "operation is not permitted");
    }
    if (d.scope !== null && !(caller.scopes ?? []).includes(d.scope)) {
      return fail(403, Code.INSUFFICIENT_SCOPE, "the key lacks the required scope");
    }
    b.accepted = true;
    return b;
  }

  /**
   * The one exception to "unknown key is rejected" (spec 01 section 4, spec
   * 03 section 3.2): an unregistered kid is accepted only for a POST
   * tools/call of jack.enroll whose submitted public key is valid and hashes
   * to kid. Returns the SUBMITTED key to verify against, or a rejection
   * Result (never throws JackError).
   */
  private enrollmentKey(req: VerifyRequest, kid: string): { key: Uint8Array } | { rejection: VerifyResult } {
    const unknown = { rejection: rejected(401, Code.UNKNOWN_KEY, "unknown key") };
    if (req.method !== "POST") return unknown;
    const msg = classifyBody(req.body);
    if (msg === undefined || msg.kind !== "request" || msg.method !== "tools/call" || !msg.hasTool || msg.tool !== TOOL_ENROLL) {
      return unknown;
    }
    // arguments must be present and parse to a plain object with a string
    // public_key member.
    if (msg.arguments === undefined) return unknown;
    let argsNode: RawJsonNode;
    try {
      argsNode = parseJsonRaw(msg.arguments).source;
    } catch {
      return unknown;
    }
    if (!isPlainObject(argsNode.value) || argsNode.members === undefined) return unknown;
    const pkNode = argsNode.members.get("public_key");
    if (pkNode === undefined || typeof pkNode.value !== "string") return unknown;
    const submitted = pkNode.value;

    let key: Uint8Array;
    try {
      key = decodeBase64URLFixed(submitted, 32);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        return { rejection: rejected(400, Code.KEY_REJECTED, "public key is not acceptable") };
      }
      throw err;
    }
    if (validatePublicKey(key) !== null) {
      return { rejection: rejected(400, Code.KEY_REJECTED, "public key is not acceptable") };
    }
    if (keyId(key) !== kid) return unknown;
    return { key };
  }
}

/** Builds a rejection result (kid "" because authentication never completed). */
function rejected(httpStatus: number, code: string, message: string): VerifyResult {
  return {
    accepted: false,
    kid: "",
    httpStatus,
    code,
    message,
    nonceRecorded: false,
    requestSig: "",
    rpcId: undefined,
    tool: "",
    native: false,
    structured: undefined,
    audit: undefined,
  };
}
