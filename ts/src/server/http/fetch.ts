/** Fetch-standard request handler adapter: body buffering, verification, native tools, response signing, signed streams (spec 05), verified-identity hand-off to the wrapped handler. */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { formatResponseAuth } from "../../core/auth-header.js";
import { keyId, encodeBase64URL } from "../../core/encoding.js";
import { validatePublicKey, verify as verifyEd25519 } from "../../core/ed25519.js";
import { ROTATION_MAX_TIMESTAMP } from "../../rotation/wire/record.js";
import type { RotationResponseAuthorization, RotationResponseKeyRequest } from "../../rotation/server/provider.js";
import { responseSigningString } from "../../core/signing.js";
import { STREAM_ACCEPT_HEADER, jackAcceptStreams } from "../../stream/codes.js";
import type { StreamSigningKey } from "../../stream/signer.js";
import { classifyBody } from "../verify.js";
import type { Verifier, VerifyResult } from "../verify.js";
import type { JackIdentity } from "../verify.js";
import { markResponseFinish, takeResultFinish } from "../durable/finish.js";
import { JACK_SERVER_INFO, SERVER_PROFILES, envelopeBodyText, isModernHeaderSignal, refusalBodyText } from "../../modern/server.js";
import type { ServerProfile } from "../../modern/server.js";
import { StreamAdmission, attachJackStream, resolveStreamOptions, startSignedStream, streamLimitBody } from "./stream.js";
import type { StreamServerOptions } from "./stream.js";

// Go NewHandler returns errors; the Fetch-standard API has no error return in
// its factory shape, so configuration problems THROW a plain Error instead.
// This is the one deliberate divergence of the factory.

/**
 * Rotation response-signing profile (Go ResponseKeyProvider): selects the
 * signer under a serving lease and runs the one-shot final gate. Implemented
 * by rotation.RotationServerProvider; the static serverKey profile needs none.
 */
export interface ResponseKeyProvider {
  authorizeResponse(input: RotationResponseKeyRequest): RotationResponseAuthorization;
  /**
   * Spec 05 5.1: the successor activation of `kid`, or undefined when none is
   * known yet. RotationServerProvider implements it; a stream armed with it
   * closes below the cutoff.
   */
  successorActivation?(kid: string): number | undefined;
}

/** Configuration for jackFetchHandler (Go HandlerConfig). */
export interface HandlerConfig {
  /** Authenticates and authorizes every request. */
  verifier: Verifier;
  /**
   * Static profile: 32-byte Ed25519 seed, or an ed25519 private KeyObject.
   * REQUIRED unless rotationKeys is set; the two response-signing profiles
   * are mutually exclusive (Go HandlerConfig.ServerKey / ResponseKeys).
   */
  serverKey?: Uint8Array | KeyObject;
  /**
   * Rotation profile (Go ResponseKeys): the rotating signer source. Exactly
   * one of serverKey / rotationKeys must be supplied — both or neither make
   * jackFetchHandler throw like every other configuration error. When set, a
   * verifier configured to route jack.server.key (VerifierConfig.serverKeys)
   * is REQUIRED: candidate server-key delivery needs ResponseKeys.
   */
  rotationKeys?: ResponseKeyProvider;
  /**
   * Request body cap. undefined, <= 0 or NaN means 1 MiB (Go defaultMaxBodyBytes);
   * +Infinity or a value above Number.MAX_SAFE_INTEGER makes jackFetchHandler throw,
   * because a limit must never silently disable itself.
   */
  maxBodyBytes?: number;
  /**
   * Cap on the upstream response body buffered for signing, independent of
   * maxBodyBytes. undefined or 0 means 1 MiB. Any other value must be a finite
   * integer in (0, Number.MAX_SAFE_INTEGER], otherwise jackFetchHandler throws.
   * A body of exactly this many bytes passes; one more is answered with a signed
   * 502 response_too_large. The cap bounds bytes pulled, not time. On overflow
   * the adapter AWAITS reader.cancel() (in try/catch, so an error cannot mask the
   * 502); an upstream whose cancellation promise never settles is outside the byte
   * cap and can still delay the 502. A stream that only yields empty chunks, or
   * never yields, is not stopped by the cap: empty chunks are not retained, so
   * memory stays bounded, but the read itself continues forever. A deadline on
   * next covers only obtaining the Response, not the later body reads or the
   * cancel; a deadline over the whole call, body consumption included, must wrap
   * the returned handler (e.g. race/abort around handle(req)) and is the caller's
   * responsibility. This SDK has no timeout option. The cap also cannot bound what
   * next buffers internally before returning its Response.
   */
  maxResponseBytes?: number;
  /**
   * Deployment profile of the modern profile (spec 04 section 3). undefined
   * means "legacy", which is byte-identical to 0.1.x: no spec 04 rule runs.
   * "modern" serves every request as modern-era, "both" decides the era per
   * request after authentication (S3).
   */
  profile?: ServerProfile;
  /**
   * Signed streams of spec 05 (scheme s1). undefined means no stream path at
   * all, so every text/event-stream answer keeps the signed 501 of v1. When
   * set, only an opted-in modern 200 text/event-stream of a JSON-RPC request
   * becomes a stream; every other answer stays byte-identical. Invalid limits
   * throw at construction.
   */
  readonly streams?: StreamServerOptions;
}

/** Go defaultMaxBodyBytes. The body must be read in full to be hashed, so the limit is a denial-of-service guard. */
const DEFAULT_MAX_BODY_BYTES = 1 << 20;

/** Default response cap; aligned with the client's response buffer default. */
export const DEFAULT_MAX_RESPONSE_BYTES = 1 << 20;

/** The fixed Ed25519 PKCS#8 DER prefix; appending the 32-byte seed yields a valid private key (client/signer.ts). */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Internal: the exact received origin-form target and the exact Jack-Auth
 * header values, carried on the Request object as symbol-keyed properties,
 * because the Headers object would merge repeated Jack-Auth headers and the
 * URL parser would resolve dot segments. Request constructors drop symbol
 * properties, so the values can never leak to an upstream forwarded through
 * fetch().
 */
export const RAW_TARGET_SYMBOL = Symbol("mcp-jack.raw-target");
export const AUTH_VALUES_SYMBOL = Symbol("mcp-jack.auth-values");
export const RAW_BODY_SYMBOL = Symbol("mcp-jack.raw-body");
export const HEADER_VALUES_SYMBOL = Symbol("mcp-jack.header-values");
export interface JackRequest extends Request {
  [RAW_TARGET_SYMBOL]?: string;
  [AUTH_VALUES_SYMBOL]?: readonly string[];
  /** Exact request body bytes when the Request constructor could not carry them (undici refuses a GET/HEAD body); consumed by jackFetchHandler before reading the stream. */
  [RAW_BODY_SYMBOL]?: Uint8Array;
  /** Every received header instance in received order and casing; a Headers object merges repeats and lowercases names, so the modern-profile rules read the instances here. */
  [HEADER_VALUES_SYMBOL]?: readonly (readonly [string, string])[];
}

/**
 * SDK-PRIVATE request-to-identity storage, keyed by the request object the
 * adapter hands to the wrapped handler. A WeakMap — not an own property — is
 * the association boundary: handler code can neither discover the identity
 * (no own symbol of the request carries it), nor replace it (property
 * assignment cannot touch a map it holds no reference to), nor carry it onto
 * a copied Request (a different object has no entry). The only access path
 * is the jackIdentity() read accessor below; entries die with their request.
 */
const identities = new WeakMap<object, JackIdentity>();

/**
 * Read accessor for the frozen verified-identity snapshot associated by
 * forward() with a forwarded request; undefined when the request carries
 * none. Returns the snapshot itself, never a copy, so snapshot identity is
 * preserved across reads.
 */
export function jackIdentity(req: Request): JackIdentity | undefined {
  return identities.get(req);
}

/**
 * SDK-PRIVATE header-instance storage, keyed like `identities` by the request
 * object the adapter hands to the wrapped handler: the same association
 * boundary, so a copied Request carries no entry and the list cannot be
 * replaced from handler code. The list is the exact forwarded list (modern
 * era: S8 removals applied, received order and casing kept).
 */
const forwardedHeaderLists = new WeakMap<object, readonly (readonly [string, string])[]>();

/** The received header instances of a request the wrapped handler sees, in original order and casing (S9); undefined for any other request. */
export function jackHeaders(req: Request): readonly (readonly [string, string])[] | undefined {
  return forwardedHeaderLists.get(req);
}

/**
 * The header-instance list a legacy-profile request hands to the non-POST
 * pre-check: the legacy profile never reconstructs the received instances,
 * because no section 5 rule reads them.
 */
const EMPTY_HEADER_INSTANCES: readonly (readonly [string, string])[] = [];

/**
 * The received header instances. Without the node adapter's raw list a
 * Headers object has merged repeats with ", " and lowercased names. Header
 * values keep their bytes: a single value is NEVER trimmed. Only a
 * comma-joined value is split — and only for the two single-valued mirrors
 * MCP-Protocol-Version and Mcp-Method, whose valid values never contain a
 * comma — because a Headers object joined the repeats with ", "; the split
 * removes just the one SP/HTAB that separator inserted, so each piece is the
 * received value (S1 header_repeated). Mcp-Name may legitimately contain a
 * comma, so its merged value stays one instance (a genuine repeat then
 * refuses as name_header_mismatch).
 */
function receivedHeaderInstances(req: Request): readonly (readonly [string, string])[] {
  const raw = (req as JackRequest)[HEADER_VALUES_SYMBOL];
  if (raw !== undefined) return raw;
  const out: [string, string][] = [];
  for (const [name, value] of req.headers) {
    // The names of a Headers object are lowercased; only these two are
    // single-valued mirrors whose merged form can be split again.
    const lower = name.toLowerCase();
    if (lower !== "mcp-protocol-version" && lower !== "mcp-method") {
      out.push([name, value]);
      continue;
    }
    const pieces = value.split(",");
    if (pieces.length === 1) {
      // No comma: the merged value IS the received value; never trim it.
      out.push([name, value]);
      continue;
    }
    // A Headers object joined repeats with ", ": remove only the single SP/HTAB
    // that separator inserted, never any other byte of a piece.
    pieces.forEach((piece, index) => out.push([name, index === 0 ? piece : piece.replace(/^[ \t]/, "")]));
  }
  return out;
}

/**
 * Spec 05 section 1.1: the `Jack-Accept` request values in received order.
 * Read from the received instances because a Headers object merges repeats;
 * the name compares ASCII case-insensitively like every header name, and the
 * values are handed to jackAcceptStreams, which combines the lines itself.
 */
function acceptHeaderValues(instances: readonly (readonly [string, string])[]): string[] {
  const values: string[] = [];
  for (const [name, value] of instances) {
    if (name.toLowerCase() === STREAM_ACCEPT_HEADER.toLowerCase()) {
      values.push(value);
    }
  }
  return values;
}

/**
 * Spec 01 section 3.1: the signed target is an origin-form request target:
 * it starts with '/' (so not absolute-, authority- or asterisk-form) and
 * consists only of the bytes 0x21 to 0x7E.
 */
export function isOriginFormTarget(target: string): boolean {
  return target.startsWith("/") && TARGET_BYTES.test(target);
}

/** The first '#' and everything after it is not part of the target (spec 01 section 3.1). */
export function dropFragment(target: string): string {
  const i = target.indexOf("#");
  return i < 0 ? target : target.slice(0, i);
}

/** The bytes 0x21 to 0x7E: anything else must be percent-encoded by the client. */
const TARGET_BYTES = /^[\x21-\x7e]+$/;

/**
 * Fetch's Headers joins repeated Jack-Auth lines with ", ". A valid single
 * value has no whitespace after a comma (spec 01 section 3 grammar), so such a
 * comma proves more than one line; the pieces are handed to the verifier,
 * which answers malformed_auth exactly like for two raw lines.
 */
export function splitRepeatedAuthLines(combined: string): string[] {
  return combined.split(/,[ \t]+/);
}

/**
 * Candidate target from a WHATWG-parsed URL, or undefined when it cannot be
 * proved to be the received target (not stable under re-parsing). The URL
 * parser has already separated a fragment from pathname and search.
 */
function targetFromUrl(requestUrl: string): string | undefined {
  let u: URL;
  try {
    u = new URL(requestUrl);
  } catch {
    return undefined;
  }
  const target = u.pathname + u.search;
  if (!isOriginFormTarget(target)) return undefined;
  const again = new URL(target, "http://localhost");
  return again.pathname + again.search === target ? target : undefined;
}

/**
 * Wraps next, an unmodified MCP server, so that only authenticated and
 * authorized requests reach it and every verified answer is signed (port of
 * Go NewHandler/ServeHTTP). Protocol-native tools are answered here and never
 * reach next. Streaming (text/event-stream) responses cannot be signed in
 * v0.1 (spec README Q1): the answer from next is refused on its header,
 * BEFORE the body is read, with a signed 501. Other answers are buffered up to
 * config.maxResponseBytes (default 1 MiB); a larger body is answered with a
 * signed 502 response_too_large and the upstream stream is cancelled (the
 * adapter awaits reader.cancel() inside try/catch, so a cancellation that never
 * settles can still delay the 502). Invalid limits throw at construction. The
 * cap bounds bytes pulled, not time: a stream that only yields empty chunks or
 * never yields is not stopped by it, and a next that never resolves is not
 * bounded either. A deadline wrapped around next covers only obtaining the
 * Response; to bound body reads and cancel as well, the caller must wrap the
 * returned handler (race/abort around the whole handle(req) call). There is no
 * timeout option.
 *
 * Response signing profile: HandlerConfig takes EITHER the static serverKey
 * OR rotationKeys (Go ResponseKeys), never both and never neither — any other
 * combination throws at construction. On the rotation profile every signed
 * answer first selects the signer from the store (the serving lease is held
 * until the response is built; upstream bodies are fully buffered before
 * signing, so no lease logic blocks on network I/O), computes the signature
 * with the selected key and the fresh ClockGuard sample as the timestamp, and
 * then runs the one-shot final gate: a second fresh sample must still select
 * the same key, otherwise the computed signature is discarded. Every failure
 * of that pipeline — an unavailable, closing or fenced store, a failing
 * signer callback, or a jack.server.key page that does not match the
 * committed ring — is answered with the UNSIGNED 503
 * rotation_state_unavailable "response authorization unavailable" (mirrors
 * Go writeAuthorized). A verifier configured to route jack.server.key
 * without a rotation profile is a construction error.
 *
 * Modern profile (spec 04): config.profile selects the deployment profile.
 * undefined or "legacy" runs no section 5 rule, so 0.1.x behaviour stays
 * byte-identical. "modern" and "both" authenticate and classify the request,
 * then decide the era (S3) and either refuse with a signed JSON-RPC error
 * (S10; the 405 answer also carries Allow: POST) or forward with
 * Mcp-Session-Id and Last-Event-ID removed (S8). The legacy era forwards the
 * original Headers view unchanged, byte-identical to 0.1.x, and only the
 * modern era sets the jackHeaders() entry. Repeated header instances: the
 * node adapter supplies the true received instances; without it a Fetch
 * Request carries only the merged header view, where a Headers object joined
 * repeats with ", " and lowercased the names — for the single-valued mirrors
 * MCP-Protocol-Version and Mcp-Method a comma-joined value is split into one
 * instance per piece (only the separator's single SP/HTAB removed, and a
 * single value never trimmed), while Mcp-Name may legitimately contain a
 * comma and its merged value stays one instance. The wrapped handler reads
 * the exact forwarded list, in received order and casing, with
 * jackHeaders(req). A HEAD refusal is signed over the empty body, because a
 * HEAD response carries no content and the signature therefore covers the
 * (zero) bytes the client receives.
 *
 * Signed streams (spec 05, scheme s1): config.streams enables the stream path
 * of the modern profile only. An opted-in modern 200 text/event-stream of a
 * JSON-RPC request takes a 3.3 slot before any stream byte exists (a full
 * identity gets the signed v1 429), opens with the one-shot response gate
 * (3.1, 5.1) and is pumped into signed frames; its answer carries only
 * content-type, x-accel-buffering and the open Jack-Auth (2.1), and the
 * wrapped handler sees the 3.5 heartbeat grant and the 3.7 cancel signal
 * through jackStream(). Every other text/event-stream answer, including the
 * 501 of a request that did not opt in, keeps its v1 bytes exactly.
 */
export function jackFetchHandler(config: HandlerConfig, next: (req: Request) => Promise<Response>): (req: Request) => Promise<Response> {
  if (config.verifier === undefined) throw new Error("server: HandlerConfig.verifier must be set");
  const rotation = config.rotationKeys;
  if (rotation !== undefined && config.serverKey !== undefined) {
    throw new Error("server: select exactly one response signing profile");
  }
  if (config.verifier.routesServerKey && rotation === undefined) {
    throw new Error("server: candidate server-key delivery requires ResponseKeys");
  }
  let priv: KeyObject | undefined;
  let kid = "";
  // Spec 05 3.1: the stream signer needs the raw 32 public key bytes; kept
  // next to kid so no stream re-exports the SPKI DER to find them again.
  let staticPublicKey: Uint8Array | undefined;
  if (rotation === undefined) {
    if (config.serverKey instanceof Uint8Array) {
      if (config.serverKey.length !== 32) {
        throw new Error("server: HandlerConfig.serverKey must be an Ed25519 private key");
      }
      priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(config.serverKey)]), format: "der", type: "pkcs8" });
    } else if (config.serverKey === undefined) {
      throw new Error("server: HandlerConfig.serverKey must be an Ed25519 private key");
    } else {
      if (config.serverKey.type !== "private" || config.serverKey.asymmetricKeyType !== "ed25519") {
        throw new Error("server: HandlerConfig.serverKey must be an Ed25519 private key");
      }
      priv = config.serverKey;
    }
    // SPKI DER is a fixed 44-byte header followed by the 32-byte raw key (client/signer.ts).
    const der = createPublicKey(priv).export({ type: "spki", format: "der" });
    staticPublicKey = new Uint8Array(der.subarray(der.length - 32));
    kid = keyId(staticPublicKey);
  }
  if (next === undefined) throw new Error("server: next handler must be set");
  const profile = config.profile ?? "legacy";
  if (!SERVER_PROFILES.includes(profile)) {
    throw new Error("server: HandlerConfig.profile must be one of legacy, modern or both");
  }
  const mb = config.maxBodyBytes;
  if (mb !== undefined && (mb === Infinity || mb > Number.MAX_SAFE_INTEGER)) {
    throw new Error("server: HandlerConfig.maxBodyBytes must not be infinite or above Number.MAX_SAFE_INTEGER");
  }
  const limit = mb !== undefined && mb > 0 ? mb : DEFAULT_MAX_BODY_BYTES;
  const mr: unknown = config.maxResponseBytes;
  if (mr !== undefined && mr !== 0 && !(typeof mr === "number" && Number.isSafeInteger(mr) && mr > 0)) {
    throw new Error("server: HandlerConfig.maxResponseBytes must be 0 or a positive safe integer");
  }
  const respLimit = mr === undefined || mr === 0 ? DEFAULT_MAX_RESPONSE_BYTES : (mr as number);
  // Spec 05: resolved once, so a bad stream limit throws here like every other
  // configuration error, and undefined leaves every v1 path untouched.
  const streamOptions = config.streams === undefined ? undefined : resolveStreamOptions(config.streams);
  const admission = streamOptions === undefined ? undefined : new StreamAdmission(streamOptions.maxConcurrentStreams);

  // Renders the rejection body of spec 01 section 4 (field order code,message like Go's structs).
  function errorBody(code: string, message: string): Uint8Array {
    return new TextEncoder().encode(envelopeBodyText(code, message));
  }

  // Writes a Response with exactly the given headers and body. The Response
  // constructor throws for ANY body, even zero-length, on 204/205/304, so
  // those statuses (and empty bodies) get a null bodyInit.
  function writeRaw(status: number, headers: Headers, body: Uint8Array, statusText = ""): Response {
    const out = new Headers(headers);
    out.delete("content-length");
    out.set("content-length", String(body.length));
    const bodyInit = status === 204 || status === 205 || status === 304 || body.length === 0 ? null : body;
    return new Response(bodyInit, { status, statusText, headers: out });
  }

  // Signs the response over its status, the request signature and the exact
  // body bytes that can be transmitted (spec 01 section 5). Fetch forbids
  // response bodies for 204/205/304, so normalize before static signing or
  // rotation authorization can observe the bytes. The static profile uses the
  // INJECTED verifier clock; rotation uses its selected signer, fresh-sample
  // timestamp and final gate otherwise.
  function writeSigned(status: number, headers: Headers, body: Uint8Array, requestSig: string, tool: string, statusText = ""): Response {
    const transmittedBody = status === 204 || status === 205 || status === 304 ? new Uint8Array(0) : body;
    if (rotation !== undefined) {
      return writeAuthorized(rotation, status, headers, transmittedBody, requestSig, tool, statusText);
    }
    if (priv === undefined) {
      // Unreachable: the rotation profile owns every response when configured;
      // kept defensive like the zero-value checks of the Go adapter.
      return writeError(500, "internal_error", "internal error");
    }
    const now = config.verifier.clock();
    const signing = responseSigningString(status, requestSig, kid, now, transmittedBody);
    const sig = sign(null, Buffer.from(signing, "utf-8"), priv);
    headers.set("jack-auth", formatResponseAuth({ kid, ts: now, sig: encodeBase64URL(sig) }));
    return writeRaw(status, headers, transmittedBody, statusText);
  }

  // Rotation profile (Go writeAuthorized): the signer is selected and the
  // serving lease taken BEFORE the signature is computed; the one-shot final
  // gate re-samples the clock and re-selects the signer, and any mismatch
  // discards the computed signature. Every failure — authorization, signer
  // callback, final gate — answers the same UNSIGNED 503: no retry, no other
  // key, no unsigned answer that could pass for a signed success. The lease is
  // held until the response is built (upstream bodies are buffered before
  // signing, so no lock or lease logic ever blocks on network I/O).
  function writeAuthorized(provider: ResponseKeyProvider, status: number, headers: Headers, body: Uint8Array, requestSig: string, tool: string, statusText: string): Response {
    const refuse = (): Response => writeError(503, "rotation_state_unavailable", "response authorization unavailable");
    let authorization: RotationResponseAuthorization;
    try {
      authorization = provider.authorizeResponse({ status, tool, requestSignature: requestSig, body });
    } catch {
      return refuse();
    }
    try {
      const signer = authorization.signer;
      const publicKey = signer.publicKey();
      // Authorization shape and pinned identity are re-checked here exactly
      // like Go authorizeResponse/responsePublicKey; provider details never leak.
      if (!Number.isSafeInteger(authorization.timestamp) || authorization.timestamp < 0 || authorization.timestamp > ROTATION_MAX_TIMESTAMP ||
        publicKey.length !== 32 || validatePublicKey(publicKey) !== null) {
        return refuse();
      }
      const responseKid = keyId(publicKey);
      const message = Buffer.from(responseSigningString(status, requestSig, responseKid, authorization.timestamp, body), "utf-8");
      const supplied = signer.sign(message);
      // Provider callback output is never trusted: length plus an independent
      // verification against the pinned identity (Go responseSignature).
      if (!(supplied instanceof Uint8Array) || supplied.length !== 64 || !verifyEd25519(publicKey, message, supplied)) {
        return refuse();
      }
      authorization.final();
      headers.set("jack-auth", formatResponseAuth({ kid: responseKid, ts: authorization.timestamp, sig: encodeBase64URL(supplied) }));
      return writeRaw(status, headers, body, statusText);
    } catch {
      return refuse();
    } finally {
      authorization.release();
    }
  }

  // Spec 05 3.1: the static profile signs a stream with the static server key
  // and the raw public key bytes kept next to kid. The signer re-verifies every
  // signature against that key, so this callback is never trusted either.
  function staticStreamKey(key: KeyObject, publicKey: Uint8Array): StreamSigningKey {
    return {
      sign: (message: Uint8Array): Uint8Array => new Uint8Array(sign(null, Buffer.from(message), key)),
      publicKey: (): Uint8Array => publicKey,
    };
  }

  // Spec 05 3.1/5.1: the rotation profile opens a stream through the same
  // pipeline and checks as writeAuthorized. The open header is the response
  // gate's only consumer, so final() runs before any stream byte and
  // release() follows immediately in the finally; every failure is the same
  // undefined, which becomes the one unsigned 503.
  function openRotationStream(provider: ResponseKeyProvider, tool: string, requestSig: string): { readonly key: StreamSigningKey; readonly openerTs: number } | undefined {
    let authorization: RotationResponseAuthorization;
    try {
      authorization = provider.authorizeResponse({ status: 200, tool, requestSignature: requestSig, body: new Uint8Array(0) });
    } catch {
      return undefined;
    }
    try {
      const signer = authorization.signer;
      const publicKey = signer.publicKey();
      // Authorization shape and pinned identity are re-checked exactly like
      // writeAuthorized; provider details never leak into a stream.
      if (!Number.isSafeInteger(authorization.timestamp) || authorization.timestamp < 0 || authorization.timestamp > ROTATION_MAX_TIMESTAMP ||
        publicKey.length !== 32 || validatePublicKey(publicKey) !== null) {
        return undefined;
      }
      const key: StreamSigningKey = {
        sign: (message: Uint8Array): Uint8Array => signer.sign(message),
        publicKey: (): Uint8Array => signer.publicKey(),
      };
      authorization.final();
      return { key, openerTs: authorization.timestamp };
    } catch {
      return undefined;
    } finally {
      authorization.release();
    }
  }

  // Writes an unsigned JSON error for requests that never reached authentication.
  function writeError(status: number, code: string, message: string): Response {
    const headers = new Headers();
    headers.set("content-type", "application/json");
    return writeRaw(status, headers, errorBody(code, message));
  }

  // Answers a failed request. Once authentication has succeeded the client
  // holds a request signature to bind to, so the answer is signed; an
  // authentication failure may be unsigned and carries NO Jack-Auth response
  // header (spec 01 section 5). A HEAD response carries no content at all, so
  // EVERY refusal of a HEAD request signs the empty bytes the client actually
  // receives (content-length: 0, no body): that includes a non-rpcRefusal
  // refusal of an authenticated HEAD, such as the body-classification refusal
  // or a post-commit durable-admission refusal, where signing the JSON envelope
  // that is never transmitted could not be verified.
  function reject(res: VerifyResult, method: string): Response {
    const headers = new Headers();
    headers.set("content-type", "application/json");
    // Spec 04 S10: a refusal of the modern profile is a signed JSON-RPC error
    // with Content-Type application/json; the 405 form also carries Allow: POST.
    if (res.rpcRefusal !== undefined) {
      const refusal = res.rpcRefusal;
      if (refusal.allowPost) {
        headers.set("allow", "POST");
      }
      if (method === "HEAD") {
        return writeSigned(refusal.httpStatus, headers, new Uint8Array(0), res.requestSig, res.tool);
      }
      const body = new TextEncoder().encode(refusalBodyText(refusal.idText, refusal.code, refusal.message));
      return writeSigned(refusal.httpStatus, headers, body, res.requestSig, res.tool);
    }
    if (res.httpStatus === 401) {
      headers.set("www-authenticate", "Jack-Auth");
    }
    // The refusal bytes are computed ONCE so a HEAD response never signs or
    // transmits a body it cannot carry; every non-HEAD path keeps its bytes.
    const body = method === "HEAD" ? new Uint8Array(0) : errorBody(res.code, res.message);
    if (res.nonceRecorded) {
      return writeSigned(res.httpStatus, headers, body, res.requestSig, res.tool);
    }
    return writeRaw(res.httpStatus, headers, body, "");
  }

  // Answers a protocol-native tool call as a JSON-RPC response whose result
  // is an MCP CallToolResult carrying the structured payload. The body is
  // built by EXACT string composition so the field order mirrors the Go
  // structs (jsonrpc,id,result{content,structuredContent,isError}) and id is
  // the RAW id text or null (Go json.RawMessage nil marshals as null).
  function native(res: VerifyResult): Response {
    let text: string;
    try {
      text = JSON.stringify(res.structured);
    } catch {
      // BigInt / circular structures: Go's json.Marshal error path.
      const headers = new Headers();
      headers.set("content-type", "application/json");
      return writeSigned(500, headers, errorBody("internal_error", "internal error"), res.requestSig, res.tool);
    }
    const modern = res.era === "modern";
    const body =
      '{"jsonrpc":"2.0","id":' +
      (res.rpcId === undefined ? "null" : res.rpcId) +
      ',"result":{"content":[{"type":"text","text":' +
      JSON.stringify(text) +
      '}],"structuredContent":' +
      text +
      ',"isError":false' +
      (modern
        ? ',"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":' +
          JSON.stringify(JACK_SERVER_INFO.name) +
          ',"version":' +
          JSON.stringify(JACK_SERVER_INFO.version) +
          "}}"
        : "") +
      "}}";
    const headers = new Headers();
    headers.set("content-type", "application/json");
    return writeSigned(200, headers, new TextEncoder().encode(body), res.requestSig, res.tool);
  }

  // Hands an authorized request to the wrapped server and signs what it
  // answers. `acceptStream` is the request's spec 05 opt-in (1.1).
  async function forward(
    req: Request,
    body: Uint8Array,
    res: VerifyResult,
    acceptStream: boolean,
  ): Promise<Response> {
    // Spec 04 S9: the modern era forwards the header instances the era rules
    // returned (S8 removals applied). The legacy era forwards the ORIGINAL
    // Fetch header view — `new Headers(req.headers)` — exactly as 0.1.x does,
    // byte-identical: no split, no trim, no reconstruction from the instance
    // list (`undefined` marks the legacy era here).
    const forwardedList: readonly (readonly [string, string])[] | undefined =
      res.era === "modern" ? res.forwardHeaders ?? [] : undefined;
    const forwardedHeaders = forwardedList !== undefined ? new Headers(forwardedList.map(([name, value]): [string, string] => [name, value])) : new Headers(req.headers);
    // Spec 05 3.8: the body decides whether a stream may exist at all. A
    // JSON-RPC request without an id is a notification; a client-sent response
    // object and an unclassifiable body are neither, so neither may stream.
    const message = classifyBody(body);
    const kind =
      message === undefined
        ? undefined
        : message.kind === "request" && message.id === undefined
          ? "notification"
          : message.kind;
    // Spec 05 1.1/3.7: only a request that may open a stream gets a controller
    // of its own, and only that forwarded Request replaces the received
    // signal. Every other request stays exactly as today: no controller, no
    // stream context, the received signal untouched. A notification carries no
    // rpcId and so never qualifies (3.8).
    // The 2.4 sid is drawn here, once: the handler context needs it while it
    // runs, and the signing key is irrelevant to it.
    const streamPath =
      streamOptions !== undefined && admission !== undefined && acceptStream && res.era === "modern" && kind === "request" && res.rpcId !== undefined
        ? { options: streamOptions, admission, rpcId: res.rpcId, sid: encodeBase64URL(streamOptions.sidSource()), abort: new AbortController() }
        : undefined;
    if (streamPath !== undefined) {
      // A disconnect of the received request cancels the handler as well.
      const outer = req.signal;
      const abort = streamPath.abort;
      if (outer.aborted) {
        abort.abort();
      } else {
        outer.addEventListener("abort", (): void => {
          abort.abort();
        }, { once: true });
      }
    }
    // Restore the EXACT buffered body bytes. undici throws for a GET body,
    // so the body is only attached for methods that can carry one; a
    // conditional spread, never an explicit undefined, keeps
    // exactOptionalPropertyTypes happy.
    const restored = new Request(req.url, {
      method: req.method,
      headers: forwardedHeaders,
      ...(req.method !== "GET" && req.method !== "HEAD" && body.length > 0 ? { body } : {}),
      ...(streamPath === undefined ? {} : { signal: streamPath.abort.signal }),
    });
    // Preserve the node adapter's exact authenticated target for the wrapped
    // handler too; the Request URL itself remains URL-normalized.
    const rawTarget = (req as JackRequest)[RAW_TARGET_SYMBOL];
    if (rawTarget !== undefined) {
      (restored as JackRequest)[RAW_TARGET_SYMBOL] = rawTarget;
    }
    // Associate the verified caller identity with the restored request in
    // SDK-private storage (WeakMap): nothing on the request object to
    // discover or overwrite, and a reconstructed Request carries no
    // association.
    if (res.identity !== undefined) {
      identities.set(restored, res.identity);
    }
    // Hand the wrapped handler the exact forwarded instances (received order
    // and casing, S8 removals applied) through the jackHeaders() accessor:
    // a Headers object can neither keep repeats nor the received casing. The
    // accessor is documented as the modern forwarded list, so only the modern
    // era sets it; in the legacy era it stays unset and handler code falls
    // back to req.headers exactly as before.
    if (forwardedList !== undefined) {
      forwardedHeaderLists.set(restored, forwardedList);
    }
    // 3.5/3.7: the handler reads its stream context, and observes cancellation,
    // while it runs, not after it returned.
    if (streamPath !== undefined) {
      attachJackStream(restored, {
        sid: streamPath.sid,
        heartbeatMs: streamPath.options.heartbeatMs,
        frameMaxBytes: streamPath.options.frameMaxBytes,
        signal: streamPath.abort.signal,
      });
    }

    let resp: Response;
    try {
      resp = await next(restored);
    } catch {
      // DIVERGENCE: Go's net/http recovers a panic in the wrapped handler by
      // closing the connection with NO response at all; a Fetch handler must
      // answer something, and per Go's panic path the answer is never signed.
      const headers = new Headers();
      headers.set("content-type", "application/json");
      return writeRaw(500, headers, errorBody("internal_error", "internal error"), "");
    }

    // Streaming is refused on the HEADER, before the body is read: a live
    // stream can never be buffered, so refusing on the header keeps an endless
    // producer from hanging the adapter (Go buffers the whole body first and
    // would hang). The 501 is built BEFORE cancelling so cancellation can
    // never mask it.
    const ct = resp.headers.get("content-type");
    if (ct !== null && ct.split(";")[0]?.trim().toLowerCase() === "text/event-stream") {
      // Spec 05 3.8: a notification never opens a stream, whatever the handler
      // answered. Its stream body is discarded and the answer is the signed v1
      // 202 with no content (built BEFORE cancelling, so a slow cancel cannot
      // mask it).
      if (kind === "notification") {
        const headers = new Headers();
        headers.set("content-type", "application/json");
        const out = writeSigned(202, headers, new Uint8Array(0), res.requestSig, res.tool);
        try {
          await resp.body?.cancel();
        } catch {
          /* cancellation must not mask the 202 already in hand */
        }
        return out;
      }
      // Spec 05 1.4: an opted-in modern 200 text/event-stream of a JSON-RPC
      // request becomes a signed stream. Every other case falls through to the
      // unchanged v1 501 below: streams not configured, no Jack-Accept s1
      // token, the legacy era, a body that is not a request, or any status but
      // 200.
      if (streamPath !== undefined && resp.status === 200) {
        const rpcId = streamPath.rpcId;
        // 3.1/5.1: one key signs the open header and every frame, and the open
        // timestamp is that key's. The static profile uses the static key and
        // the verifier clock; the rotation profile opens through the one-shot
        // response gate, so a later rotation epoch cannot change this stream.
        return startSignedStream({
          options: streamPath.options,
          admission: streamPath.admission,
          identity: res.identity?.kid ?? res.kid,
          sid: streamPath.sid,
          rpcId,
          abort: streamPath.abort,
          handlerResponse: resp,
          body,
          clock: (): number => config.verifier.clock(),
          requestSig: res.requestSig,
          tool: res.tool,
          openKey: (): { key: StreamSigningKey; openerTs: number } | undefined => {
            if (rotation !== undefined) return openRotationStream(rotation, res.tool, res.requestSig);
            if (priv === undefined || staticPublicKey === undefined) {
              // Unreachable: one response-signing profile is always configured.
              return undefined;
            }
            return { key: staticStreamKey(priv, staticPublicKey), openerTs: config.verifier.clock() };
          },
          // 3.3: the signed v1 429 of an identity at its limit.
          refuseLimit: (): Response => {
            const headers = new Headers();
            headers.set("content-type", "application/json");
            return writeSigned(429, headers, streamLimitBody(rpcId), res.requestSig, res.tool);
          },
          // 5.1: the stream configuration's cutoff first, then the rotation
          // provider's own activation of the opening kid.
          successorActivation: (kid: string): number | undefined => streamPath.options.successorActivation?.(kid) ?? rotation?.successorActivation?.(kid),
          // The unsigned 503 of a key that cannot be opened.
          refuseRotation: (): Response => writeError(503, "rotation_state_unavailable", "response authorization unavailable"),
        });
      }
      const headers = new Headers();
      headers.set("content-type", "application/json");
      const out = writeSigned(501, headers, errorBody("streaming_unsupported", "streaming responses cannot be signed in v0.1"), res.requestSig, res.tool);
      try {
        await resp.body?.cancel();
      } catch {
        /* cancellation must not mask the 501 already in hand */
      }
      return out;
    }

    // Only reachable for non-stream answers. The size is checked BEFORE a chunk
    // is retained, so a hostile upstream body cannot exhaust memory (same cap
    // and 502 answer as the Go and Rust adapters). A read error
    // propagates as a rejection, exactly like arrayBuffer() did.
    let respBody: Uint8Array;
    if (resp.body === null) {
      respBody = new Uint8Array(0);
    } else {
      const reader = resp.body.getReader();
      try {
        let chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk: unknown = value;
          if (!(chunk instanceof Uint8Array)) {
            try {
              await reader.cancel();
            } catch {
              /* the TypeError below is the real failure */
            }
            throw new TypeError("upstream response body chunk is not a Uint8Array");
          }
          // Empty chunks add no bytes; retaining them would grow `chunks` without bound
          // while `total` (and so the cap) never moves. Retained entries are therefore
          // non-empty, at most respLimit of them.
          if (chunk.length === 0) continue;
          if (total + chunk.length > respLimit) {
            chunks = [];
            // Fresh headers only: nothing from the upstream answer survives.
            const headers = new Headers();
            headers.set("content-type", "application/json");
            const out = writeSigned(
              502,
              headers,
              errorBody("response_too_large", "upstream response exceeds the configured limit"),
              res.requestSig,
              res.tool,
            );
            try {
              await reader.cancel();
            } catch {
              /* cancellation must not mask the 502 already in hand */
            }
            return out;
          }
          total += chunk.length;
          chunks.push(chunk);
        }
        respBody = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          respBody.set(c, offset);
          offset += c.length;
        }
      } finally {
        reader.releaseLock();
      }
    }

    const headers = new Headers(resp.headers);
    headers.delete("content-length");
    return writeSigned(resp.status, headers, respBody, res.requestSig, res.tool, resp.statusText);
  }

  return async (req: Request): Promise<Response> => {
    const method = req.method;
    // The received header instances (received order and casing) for the
    // modern-profile rules; a Fetch Request alone carries only the merged view,
    // which receivedHeaderInstances() splits back for the single-valued
    // mirrors. The legacy profile never reconstructs them: it runs no section
    // 5 rule, so the list has no reader and the empty list is never passed to
    // isModernHeaderSignal (the "both" branch below short-circuits it).
    const headerInstances =
      profile === "legacy" ? EMPTY_HEADER_INSTANCES : receivedHeaderInstances(req);
    // Spec 05 1.1: the opt-in is request-side and unsigned. Without config
    // streams this is false and no stream code below runs; the s1 token in a
    // line the 1.1 grammar rejects enables nothing.
    const acceptStream =
      streamOptions !== undefined && jackAcceptStreams(acceptHeaderValues(receivedHeaderInstances(req)));
    if (method !== "GET" && method !== "POST") {
      // A modern-era non-POST request is authenticated first and refused by S2
      // with a signed 405; anything else keeps the 0.1.x unsigned answer.
      const modernEra = profile === "modern" || (profile === "both" && isModernHeaderSignal(headerInstances));
      if (!modernEra) {
        return writeError(405, "method_not_allowed", "only GET and POST are defined");
      }
    }

    // The body must be read IN FULL to be hashed whole. The reader lock is
    // released on every exit path; best-effort cancel on the over-limit path.
    // A GET body cannot travel in the Request (undici refuses one), so the
    // node adapter hands the exact bytes over on the symbol (spec 01
    // section 3.1: the hash covers the bytes exactly as sent, every method).
    const rawBody = (req as JackRequest)[RAW_BODY_SYMBOL];
    let body: Uint8Array;
    if (rawBody !== undefined) {
      body = rawBody;
    } else if (req.body === null) {
      body = new Uint8Array(0);
    } else {
      const reader = req.body.getReader();
      try {
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }
          if (value !== undefined) {
            total += value.length;
            if (total > limit) {
              try {
                await reader.cancel();
              } catch {
                // Cancellation must not mask the cap answer.
              }
              return writeError(413, "invalid_request", "request body is too large");
            }
            chunks.push(value);
          }
        }
        body = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          body.set(chunk, offset);
          offset += chunk.length;
        }
      } catch {
        return writeError(400, "invalid_request", "request body could not be read");
      } finally {
        reader.releaseLock();
      }
    }

    // The received origin-form request target exactly as sent. The node
    // adapter carries it on the symbol; otherwise req.url is assumed to be
    // that target resolved against an origin, and pathname+search is
    // byte-faithful for percent escapes but the URL parser RESOLVES
    // `..`/`.` dot segments — exactly what the symbol exists to preserve.
    let target: string;
    const rawTarget = (req as JackRequest)[RAW_TARGET_SYMBOL];
    if (rawTarget !== undefined) {
      if (!isOriginFormTarget(rawTarget)) return writeError(400, "invalid_request", "malformed request target");
      target = rawTarget;
    } else {
      // LIMIT: the WHATWG parser has already resolved dot segments and
      // escaped spaces/non-ASCII before this adapter sees the URL, so those
      // cannot be detected here; only the node adapter (raw target on the
      // symbol) can refuse them. A fragment is dropped by URL parsing.
      const fromUrl = targetFromUrl(req.url);
      if (fromUrl === undefined) return writeError(400, "invalid_request", "malformed request target");
      target = fromUrl;
    }

    // The exact Jack-Auth header values in order. Without raw headers a
    // repeated Jack-Auth header is recovered from the ", " that Headers
    // inserts; the node adapter supplies the exact values via the symbol.
    const rawAuth = (req as JackRequest)[AUTH_VALUES_SYMBOL];
    const combined = req.headers.get("jack-auth");
    const authValues =
      rawAuth !== undefined ? rawAuth : combined === null ? [] : splitRepeatedAuthLines(combined);

    const res = config.verifier.verify({
      method,
      target,
      authValues,
      body,
      ...(profile !== "legacy" ? { profile, headers: headerInstances } : {}),
    });
    // Durable admission finishes AFTER the response is produced (Go Result.Done
    // in the middleware): the release is idempotent and runs even when the
    // response construction fails. Without the durable option there is no
    // finish handle and nothing changes. The handle also travels on the
    // Response so the node adapter can finish it again after the write.
    const finish = takeResultFinish(res);
    let out!: Response;
    try {
      out = !res.accepted ? reject(res, method) : res.native ? native(res) : await forward(req, body, res, acceptStream);
    } catch (error) {
      // Release even on response failure; idempotent with the node adapter.
      finish?.();
      throw error;
    }
    // The handle travels on the Response for the node adapter, then runs here,
    // before the response is returned (Go Result.Done after the middleware
    // produced the answer).
    markResponseFinish(out, finish);
    finish?.();
    return out;
  };
}
