/**
 * The request verifier: header grammar, key lookup, time window, signature,
 * nonce, in spec check order (spec 01 section 4, spec 02 section 4). On accept
 * it hands the handler a frozen JackIdentity — the verification-time registry
 * snapshot of the caller.
 *
 * CENTRAL DESIGN DECISION — raw JSON source text.
 * `JSON.parse` loses the raw text of numbers and members, but spec 03 section 3
 * judges native-tool integer arguments on their JSON TEXT (no fraction, no
 * exponent; `-0` is 0), and Go's `json.RawMessage` keeps the raw bytes of `id`
 * and `params.arguments`. The shared json-raw module therefore contains a small strict JSON
 * tokenizer, ported from the reference verifier's `parseJSONRaw`, returning the
 * parsed value PLUS a parallel source tree where every value node carries its
 * exact source text. From that tree the verifier takes the raw text of the
 * top-level `id` (Go Result.RPCID) and the raw text of `params.arguments`
 * (handed to native tools so integer rules can be judged lexically). The
 * tokenizer is exported for reuse by the native-tools task.
 */
import type { RequestAuth } from "../core/auth-header.js";
import { parseRequestAuth } from "../core/auth-header.js";
import { BadBase64UrlError, decodeBase64URLFixed, keyId } from "../core/encoding.js";
import { validatePublicKey, verify as verifyEd25519 } from "../core/ed25519.js";
import { Code, JackError } from "../core/errors.js";
import { requestSigningString } from "../core/signing.js";
import type { AuditEvent, AuditSink } from "./audit.js";
import { AUDIT_FAILURE, AUDIT_SUCCESS } from "./audit.js";
import type { NonceStore } from "./registry/nonce.js";
import type { DurableAdmission } from "./durable/admission.js";
import { rememberResultFinish } from "./durable/finish.js";
import type { RegistryEntry, StateStore } from "./registry/state.js";
import { inviteIdOf } from "./registry/state.js";
import { parseJsonRaw } from "../core/json-raw.js";
import type { JsonValue, RawJsonNode } from "../core/json-raw.js";
export { parseJsonRaw } from "../core/json-raw.js";
export type { JsonValue, RawJsonNode } from "../core/json-raw.js";
import { bodyText, classifyBody } from "./internal/body.js";
import { classifyModernRequest, INVALID_TOOL_NAME_MESSAGE, toolsCallNameInvalid } from "../modern/server.js";
import type { ServerProfile } from "../modern/server.js";
export { classifyBody } from "./internal/body.js";
export type { RpcKind, RpcMessage } from "./internal/body.js";

// The signing string is signed over its UTF-8 encoding (Go: []byte(signing)).
const ENCODER = new TextEncoder();

// ---------------------------------------------------------------------------
// Protocol-native extension point (Go NativeCall/NativeResult/NativeTools);
// the real tools are a LATER task.
// ---------------------------------------------------------------------------

/**
 * Verified caller identity: a snapshot of the registry entry taken at
 * verification time. Frozen, so it is immutable to consumers; an in-flight
 * handler keeps the snapshot and registry changes affect only subsequent
 * requests.
 */
export interface JackIdentity {
  readonly kid: string;
  readonly name: string;
  readonly admin: boolean;
}

/** Internal: builds the frozen identity snapshot from the entry authentication used. */
function identitySnapshot(entry: RegistryEntry): JackIdentity {
  return Object.freeze({ kid: entry.kid, name: entry.name, admin: entry.admin === true });
}

/** Timestamp acceptance window in seconds (spec 01 section 4). */
export const DEFAULT_WINDOW = 30;

/**
 * Candidate read-only server-key tool; not one of the 11 current-v1 native
 * tools. Routed ONLY when the verifier is configured with serverKeys
 * (Go ToolServerKey / Config.ServerKeys); otherwise it is denied like today.
 */
export const TOOL_SERVER_KEY = "jack.server.key";

/**
 * Candidate read-only webhook-key tool; not one of the 11 current-v1 native
 * tools. Routed only when the verifier is configured with webhookKey.
 */
export const TOOL_WEBHOOK_KEY = "jack.server.webhook_key";

/** Names of the protocol-native tools (spec 03). */
export const TOOL_ENROLL = "jack.enroll";
export const TOOL_WHOAMI = "jack.whoami";
export const TOOL_ROTATE_KEY = "jack.key.rotate";
export const TOOL_ADMIN_USER_LIST = "jack.admin.user.list";
export const TOOL_ADMIN_USER_GET = "jack.admin.user.get";
export const TOOL_ADMIN_USER_CREATE = "jack.admin.user.create";
export const TOOL_ADMIN_USER_SET_ADMIN = "jack.admin.user.set_admin";
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
  TOOL_ADMIN_USER_SET_ADMIN,
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
  /** Received header instances in received order and casing (spec 04 S9); absent means none. */
  readonly headers?: readonly (readonly [string, string])[];
  /**
   * Deployment profile of spec 04 section 3. undefined or "legacy" runs no
   * section 5 rule, keeping 0.1.x behaviour byte-identical; "modern" and
   * "both" decide the era and refuse or forward before dispatch.
   */
  readonly profile?: ServerProfile;
}

/** A spec 04 section 5 refusal: the signed JSON-RPC error a client verifies like any other response (S10). */
export interface RpcRefusal {
  /** HTTP status of the refusal (400, or 405 for S2). */
  readonly httpStatus: number;
  /** JSON-RPC error code of the section 5.1 table. */
  readonly code: number;
  /** Fixed message of the section 5.1 table; it never echoes a header or body value. */
  readonly message: string;
  /** Raw JSON text of the request id, "null" when the request carries no acceptable id. */
  readonly idText: string;
  /** True only for the 405 refusal, which also carries `Allow: POST`. */
  readonly allowPost: boolean;
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
  /**
   * The caller's identity snapshot, set ONLY when the request is forwarded to
   * the wrapped handler (accepted and not a native tool); undefined for native
   * accepts and every rejection.
   */
  readonly identity: JackIdentity | undefined;
  readonly audit: AuditEvent | undefined;
  /**
   * The era the modern profile decided for this request; absent when no
   * profile decided one and "" is never assigned (additive optional member:
   * an existing caller that builds a VerifyResult still compiles).
   */
  readonly era?: "legacy" | "modern" | "";
  /** The header list the wrapped handler sees in the modern era (S8 removals applied); absent otherwise, and never empty when set. */
  readonly forwardHeaders?: readonly (readonly [string, string])[];
  /** Set when a spec 04 rule refused the request after authentication. */
  readonly rpcRefusal?: RpcRefusal | undefined;
}

/** Verifier configuration. */
export interface VerifierConfig {
  readonly aud: string;
  readonly state: StateStore;
  /** Volatile nonce store; required unless `durable` is set, and never both. */
  readonly nonces?: NonceStore;
  /**
   * Candidate durable admission seam (Go Config.DurableNonces; spec
   * candidate durable-nonces.md sections 1, 2, 5). When set, the nonce is
   * reserved durably AFTER the signature verifies and BEFORE any
   * authorization, state change or dispatch; the volatile `nonces` store is
   * NOT used for that request. Absent => the default path is identical.
   */
  readonly durable?: DurableAdmission;
  /** Optional sink. */
  readonly audit?: AuditSink;
  /** When undefined every jack.* tool is 403 operation_denied. */
  readonly native?: NativeTools;
  /**
   * Routes ONLY the candidate jack.server.key call (Go Config.ServerKeys);
   * undefined denies it exactly like an unknown jack.* tool. The current-v1
   * allowlist checked by isNativeTool is unchanged.
   */
  readonly serverKeys?: NativeTools;
  /**
   * Routes only the candidate jack.server.webhook_key call; undefined denies
   * it like an unknown jack.* tool. The current-v1 allowlist is unchanged.
   */
  readonly webhookKey?: NativeTools;
  /** Seconds; undefined or 0 => DEFAULT_WINDOW; otherwise a safe integer from 1 through 120. */
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
  identity: JackIdentity | undefined;
  audit: AuditEvent | undefined;
  era: "legacy" | "modern" | "";
  forwardHeaders: readonly (readonly [string, string])[];
  rpcRefusal: RpcRefusal | undefined;
}

/** True when v is a plain JSON object (not null, not an array). */
function isPlainObject(v: JsonValue): boolean {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Whether now is inside the entry's validity interval (spec 02 section 1: not_before <= now < not_after). */
function entryActive(e: RegistryEntry, now: number): boolean {
  return (
    (e.notBefore === undefined || e.notBefore === null || e.notBefore <= now) &&
    (e.notAfter === undefined || e.notAfter === null || now < e.notAfter)
  );
}

/**
 * aud rule shared by the verifier and the client constructors: non-empty and
 * free of C0 control characters and DEL (bytes < 0x20 and 0x7f on the wire;
 * UTF-8 multibyte sequences are all >= 0x80, so a code-unit check is exact).
 */
function validAudience(aud: string): boolean {
  if (aud === "") return false;
  for (let i = 0; i < aud.length; i++) {
    const c = aud.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

export class Verifier {
  private readonly aud: string;
  private readonly state: StateStore;
  private readonly nonces: NonceStore | undefined;
  private readonly durable: DurableAdmission | undefined;
  private readonly audit: AuditSink | undefined;
  private readonly native: NativeTools | undefined;
  private readonly serverKeys: NativeTools | undefined;
  private readonly webhookKey: NativeTools | undefined;
  private readonly window: number;
  private readonly now: () => number;
  // Highest valid clock sample seen by this instance (see effectiveNow).
  private highWater = 0;

  /** Throws when aud is "", contains control characters, or state/nonces/now are missing (Go NewVerifier parity). */
  constructor(cfg: VerifierConfig) {
    if (!validAudience(cfg.aud)) throw new Error("server: VerifierConfig.aud must be non-empty and contain no control characters");
    if (cfg.state === undefined) throw new Error("server: VerifierConfig.state must be set");
    if (cfg.nonces === undefined && cfg.durable === undefined) {
      throw new Error("server: VerifierConfig.nonces must be set");
    }
    if (cfg.now === undefined) throw new Error("server: VerifierConfig.now must be set");
    // Go NewVerifier parity: exactly one nonce profile. Both profiles share
    // the bounded integer window; preserve the durable profile's established
    // bound error for safe-integer values outside that range.
    if (cfg.nonces !== undefined && cfg.durable !== undefined) {
      throw new Error("server: VerifierConfig: select exactly one nonce profile");
    }
    const configuredWindow = cfg.window;
    if (configuredWindow !== undefined && configuredWindow !== 0) {
      if (!Number.isSafeInteger(configuredWindow)) {
        throw new Error("server: window must be 0 (default 30) or an integer between 1 and 120 seconds");
      }
      if (cfg.durable !== undefined && (configuredWindow < 0 || configuredWindow > 120)) {
        throw new Error("server: VerifierConfig.durable window must be between 1 and 120 seconds");
      }
      if (configuredWindow < 1 || configuredWindow > 120) {
        throw new Error("server: window must be 0 (default 30) or an integer between 1 and 120 seconds");
      }
    }
    this.aud = cfg.aud;
    this.state = cfg.state;
    this.nonces = cfg.nonces;
    this.durable = cfg.durable;
    this.audit = cfg.audit;
    this.native = cfg.native;
    this.serverKeys = cfg.serverKeys;
    this.webhookKey = cfg.webhookKey;
    // A window is either zero/omitted (the default) or a safe integer in
    // [1, 120]; constructor validation keeps malformed values out of compares.
    this.window = configuredWindow === undefined || configuredWindow === 0 ? DEFAULT_WINDOW : configuredWindow;
    this.now = cfg.now;
  }

  /** The injected clock (Go cfg.Now): adapters sign responses with the same injected clock that verified the request, never the wall clock. */
  get clock(): () => number {
    return this.now;
  }

  /**
   * Request time that never goes backwards within this verifier: max(sample,
   * highest valid sample so far). A wall-clock step back therefore cannot
   * purge a volatile nonce and then accept its replay; a request whose
   * ts + window is below the high-water mark is out of window. Only valid
   * samples reach here, so a broken clock cannot poison the mark.
   */
  private effectiveNow(sample: number): number {
    if (sample > this.highWater) this.highWater = sample;
    return this.highWater;
  }

  /** Whether candidate jack.server.key routing is configured (Go cfg.ServerKeys != nil); the fetch adapter requires a rotation profile when it is. */
  get routesServerKey(): boolean {
    return this.serverKeys !== undefined;
  }

  /** Runs the pipeline of spec 01 section 4 / spec 02 section 4; stops at the first failing step. */
  verify(req: VerifyRequest): VerifyResult {
    const now = this.now();
    // Fail closed on a broken injected clock: NaN/undefined makes every
    // window compare false (fail-open). No nonce is recorded and nothing is
    // dispatched; the clock is a programming error, not a caller fault.
    if (!Number.isSafeInteger(now) || now < 0) {
      return rejected(500, "internal_error", "internal error");
    }
    // Defense in depth: constructor validation requires the shared safe-integer range.
    if (!Number.isSafeInteger(this.window) || this.window < 1 || this.window > 120) {
      return rejected(500, "internal_error", "internal error");
    }
    const effective = this.effectiveNow(now);

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
      if (!entryActive(entry, effective)) {
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
      const enrolled = this.enrollmentKey(req, auth.kid, effective);
      if ("rejection" in enrolled) {
        return enrolled.rejection;
      }
      key = enrolled.key;
    }

    // Step 3: timestamp window.
    if (Math.abs(effective - auth.ts) > this.window) {
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

    // Step 5 (candidate durable profile): reserve durably after the signature
    // verified and BEFORE any authorization, state change or dispatch (spec
    // candidate durable-nonces.md section 2). The volatile store is untouched.
    if (this.durable !== undefined) {
      const outcome = this.durable.reserveForVerify({
        kid: auth.kid,
        nonce: auth.nonce,
        signature: auth.sig,
        signingBytes: signing,
        timestamp: auth.ts,
        window: this.window,
        caller,
      });
      if (!outcome.accepted) {
        const res: VerifyResult = {
          ...rejected(outcome.httpStatus, outcome.code, outcome.message),
          kid: auth.kid,
          nonceRecorded: outcome.nonceRecorded,
          requestSig: auth.sig,
        };
        rememberResultFinish(res, outcome.finish);
        return res;
      }
      const b: ResultBuilder = {
        accepted: false,
        httpStatus: 0,
        code: "",
        message: "",
        rpcId: undefined,
        tool: "",
        native: false,
        structured: undefined,
        identity: undefined,
        audit: undefined,
        era: "",
        forwardHeaders: [],
        rpcRefusal: undefined,
      };
      const done = this.authorize(req, auth, outcome.finalNow, caller, b);
      const res: VerifyResult = {
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
        identity: done.identity,
        audit: done.audit,
        ...(done.era !== undefined && done.era !== "" ? { era: done.era } : {}),
        ...(done.forwardHeaders !== undefined && done.forwardHeaders.length > 0 ? { forwardHeaders: done.forwardHeaders } : {}),
        ...(done.rpcRefusal !== undefined ? { rpcRefusal: done.rpcRefusal } : {}),
      };
      rememberResultFinish(res, outcome.finish);
      return res;
    }

    // Step 5: nonce, only after the signature verified, so
    // requests that fail verification cannot fill the cache (spec 01 section 4). True = live replay.
    if (this.nonces === undefined) {
      // Unreachable: the constructor requires nonces unless the durable seam is set.
      return rejected(500, "internal_error", "internal error");
    }
    if (this.nonces.checkAndRecord(auth.kid, auth.nonce, effective, auth.ts + this.window)) {
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
      identity: undefined,
      audit: undefined,
      era: "",
      forwardHeaders: [],
      rpcRefusal: undefined,
    };
    const done = this.authorize(req, auth, effective, caller, b);
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
      identity: done.identity,
      audit: done.audit,
      ...(done.era !== undefined && done.era !== "" ? { era: done.era } : {}),
      ...(done.forwardHeaders !== undefined && done.forwardHeaders.length > 0 ? { forwardHeaders: done.forwardHeaders } : {}),
      ...(done.rpcRefusal !== undefined ? { rpcRefusal: done.rpcRefusal } : {}),
    };
  }

  /**
   * Step 9: body shape, protocol-native tools, ordinary MCP forwarding. `b`
   * already carries kid/nonceRecorded/requestSig at the caller; this sets the
   * rest of it.
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

    // Spec 04: a configured non-legacy profile runs the era decision and the
    // mirror rules here — after authentication and classification, before any
    // dispatch — so a refused request never reaches a native tool.
    const modernProfile = req.profile !== undefined && req.profile !== "legacy" ? req.profile : undefined;
    const decideEra = (): boolean => {
      if (modernProfile === undefined) return true;
      // Spec 04 section 3: a non-POST request has no body, so the modern rules
      // must never read or parse one (only `H` counts for the era decision).
      const text = req.method === "POST" ? bodyText(req.body) : undefined;
      const decision = classifyModernRequest({
        profile: modernProfile,
        method: req.method,
        target: req.target,
        headers: req.headers ?? [],
        ...(text !== undefined && text !== "" ? { bodyText: text } : {}),
      });
      if (decision.outcome === "refuse") {
        b.accepted = false;
        b.httpStatus = decision.httpStatus;
        b.code = "";
        b.message = decision.message;
        b.rpcRefusal = {
          httpStatus: decision.httpStatus,
          code: decision.code,
          message: decision.message,
          idText: decision.idText,
          allowPost: decision.allowPost,
        };
        return false;
      }
      if (decision.outcome === "refuse_invalid_request") {
        b.accepted = false;
        b.httpStatus = decision.httpStatus;
        b.code = decision.code;
        b.message = decision.message;
        return false;
      }
      b.era = decision.era;
      if (decision.era === "modern") {
        b.forwardHeaders = decision.forward.headers;
      }
      return true;
    };

    // GET is authorized by authentication alone; no JSON-RPC is involved. In
    // the modern profile every other non-POST method is treated the same way,
    // because spec 04 S2 refuses it before the mirror checks: the era decision
    // below turns it into a signed 405, or leaves a legacy-era request as
    // 0.1.x does. Outside a modern profile non-POST methods keep the old
    // POST-like handling; their 405 is the HTTP adapter's job.
    if (req.method === "GET" || (modernProfile !== undefined && req.method !== "POST")) {
      b.accepted = true;
      if (!decideEra()) return b;
      // GET is enrollment-exempt (POST-only), so caller is defined in practice;
      // kept defensive: identity only when a registry entry authenticated.
      if (caller !== undefined) {
        b.identity = identitySnapshot(caller);
      }
      return b;
    }

    const msg = classifyBody(req.body);
    if (msg === undefined) {
      // The nonce stays consumed: authentication already succeeded. In the
      // modern profile the era-neutral refusal of spec 02 section 2 item 4
      // carries the message the vectors fix for byte-identity.
      const text = modernProfile !== undefined ? bodyText(req.body) : undefined;
      const message =
        text !== undefined && toolsCallNameInvalid(text)
          ? INVALID_TOOL_NAME_MESSAGE
          : "the body is not an acceptable JSON-RPC object";
      return fail(400, Code.INVALID_REQUEST, message);
    }
    b.rpcId = msg.id;
    // The era decision and the section 5 rules run before native dispatch.
    if (!decideEra()) return b;
    if (msg.kind === "response") {
      // A client answering a server-initiated request: authorized by
      // authentication alone.
      b.accepted = true;
      if (caller !== undefined) {
        b.identity = identitySnapshot(caller);
      }
      return b;
    }
    if (msg.hasTool) {
      b.tool = msg.tool;
    }

    // NATIVE: "jack."-prefixed tools are handled by the native implementation,
    // which does its own admin gating.
    if (msg.hasTool && msg.tool.startsWith("jack.")) {
      b.native = true;
      // The candidate jack.server.key route is dispatched separately (Go
      // cfg.ServerKeys); the current-v1 allowlist covers every other tool.
      let tools: NativeTools | undefined = this.native;
      if (msg.tool === TOOL_SERVER_KEY) {
        tools = this.serverKeys;
      } else if (msg.tool === TOOL_WEBHOOK_KEY) {
        tools = this.webhookKey;
      } else if (!isNativeTool(msg.tool)) {
        // NO audit event: the call never reached a tool (spec 03 section 8).
        return fail(403, Code.OPERATION_DENIED, "operation is not permitted");
      }
      if (tools === undefined) {
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
        const out = tools.call(call);
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

    // ORDINARY MCP: any authenticated caller is forwarded unchanged; admin
    // gating happens inside the native implementation, never here.
    if (caller === undefined) {
      // Unreachable: only a jack.enroll request passes step 2 without a
      // registry entry, and it went through the native branch. Kept
      // defensive like Go.
      return fail(401, Code.UNKNOWN_KEY, "unknown key");
    }
    b.identity = identitySnapshot(caller);
    b.accepted = true;
    return b;
  }

  /**
   * The one exception to "unknown key is rejected" (spec 01 section 4, spec
   * 03 section 3.2): an unregistered kid is accepted only for a POST
   * tools/call of jack.enroll whose submitted public key is valid and hashes
   * to kid and whose `code` names a live invite (read-only check, before any
   * signature or nonce work). Returns the SUBMITTED key to verify against, or
   * a rejection Result (never throws JackError).
   */
  private enrollmentKey(req: VerifyRequest, kid: string, now: number): { key: Uint8Array } | { rejection: VerifyResult } {
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
    // Gate before any key handling: an unknown kid must not probe key validity without an invite.
    if (!liveInvite(this.state, argsNode.members.get("code")?.value, now)) return unknown;
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

/** Whether `code` is a canonical invite code naming a stored invite that is still valid at now (read-only). */
function liveInvite(state: StateStore, code: unknown, now: number): boolean {
  if (typeof code !== "string") return false;
  let raw: Uint8Array;
  try {
    raw = decodeBase64URLFixed(code, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) return false;
    throw err;
  }
  const invite = state.lookupInvite(inviteIdOf(raw));
  return invite !== undefined && now < invite.expiresAt;
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
    identity: undefined,
    audit: undefined,
  };
}
