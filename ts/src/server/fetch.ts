/** Fetch-standard request handler adapter: body buffering, verification, native tools, response signing, verified-identity hand-off to the wrapped handler. */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { formatResponseAuth } from "../auth-header.js";
import { keyId, encodeBase64URL } from "../encoding.js";
import { validatePublicKey, verify as verifyEd25519 } from "../ed25519.js";
import { ROTATION_MAX_TIMESTAMP } from "../rotation-record.js";
import type { RotationResponseAuthorization, RotationResponseKeyRequest } from "../rotation-server-provider.js";
import { responseSigningString } from "../signing.js";
import type { Verifier, VerifyResult } from "./verify.js";
import type { JackIdentity } from "./verify.js";
import { markResponseFinish, takeResultFinish } from "./durable-admission.js";

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
export interface JackRequest extends Request {
  [RAW_TARGET_SYMBOL]?: string;
  [AUTH_VALUES_SYMBOL]?: readonly string[];
  /** Exact request body bytes when the Request constructor could not carry them (undici refuses a GET/HEAD body); consumed by jackFetchHandler before reading the stream. */
  [RAW_BODY_SYMBOL]?: Uint8Array;
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
    kid = keyId(new Uint8Array(der.subarray(der.length - 32)));
  }
  if (next === undefined) throw new Error("server: next handler must be set");
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

  // Renders the rejection body of spec 01 section 4 (field order code,message like Go's structs).
  function errorBody(code: string, message: string): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ error: { code, message } }));
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
  // body bytes (spec 01 section 5) — with the INJECTED verifier clock on the
  // static profile, with the rotation profile's selected signer, fresh-sample
  // timestamp and final gate otherwise — and writes it.
  function writeSigned(status: number, headers: Headers, body: Uint8Array, requestSig: string, tool: string, statusText = ""): Response {
    if (rotation !== undefined) {
      return writeAuthorized(rotation, status, headers, body, requestSig, tool, statusText);
    }
    if (priv === undefined) {
      // Unreachable: the rotation profile owns every response when configured;
      // kept defensive like the zero-value checks of the Go adapter.
      return writeError(500, "internal_error", "internal error");
    }
    const now = config.verifier.clock();
    const signing = responseSigningString(status, requestSig, kid, now, body);
    const sig = sign(null, Buffer.from(signing, "utf-8"), priv);
    headers.set("jack-auth", formatResponseAuth({ kid, ts: now, sig: encodeBase64URL(sig) }));
    return writeRaw(status, headers, body, statusText);
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

  // Writes an unsigned JSON error for requests that never reached authentication.
  function writeError(status: number, code: string, message: string): Response {
    const headers = new Headers();
    headers.set("content-type", "application/json");
    return writeRaw(status, headers, errorBody(code, message));
  }

  // Answers a failed request. Once authentication has succeeded the client
  // holds a request signature to bind to, so the answer is signed; an
  // authentication failure may be unsigned and carries NO Jack-Auth response
  // header (spec 01 section 5).
  function reject(res: VerifyResult): Response {
    const headers = new Headers();
    headers.set("content-type", "application/json");
    if (res.httpStatus === 401) {
      headers.set("www-authenticate", "Jack-Auth");
    }
    const body = errorBody(res.code, res.message);
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
    const body =
      '{"jsonrpc":"2.0","id":' +
      (res.rpcId === undefined ? "null" : res.rpcId) +
      ',"result":{"content":[{"type":"text","text":' +
      JSON.stringify(text) +
      '}],"structuredContent":' +
      text +
      ',"isError":false}}';
    const headers = new Headers();
    headers.set("content-type", "application/json");
    return writeSigned(200, headers, new TextEncoder().encode(body), res.requestSig, res.tool);
  }

  // Hands an authorized request to the wrapped server and signs what it answers.
  async function forward(req: Request, body: Uint8Array, res: VerifyResult): Promise<Response> {
    // Restore the EXACT buffered body bytes. undici throws for a GET body,
    // so the body is only attached for methods that can carry one; a
    // conditional spread, never an explicit undefined, keeps
    // exactOptionalPropertyTypes happy.
    const restored = new Request(req.url, {
      method: req.method,
      headers: new Headers(req.headers),
      ...(req.method !== "GET" && req.method !== "HEAD" && body.length > 0 ? { body } : {}),
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
    if (method !== "GET" && method !== "POST") {
      return writeError(405, "method_not_allowed", "only GET and POST are defined");
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

    const res = config.verifier.verify({ method, target, authValues, body });
    // Durable admission finishes AFTER the response is produced (Go Result.Done
    // in the middleware): the release is idempotent and runs even when the
    // response construction fails. Without the durable option there is no
    // finish handle and nothing changes. The handle also travels on the
    // Response so the node adapter can finish it again after the write.
    const finish = takeResultFinish(res);
    let out!: Response;
    try {
      out = !res.accepted ? reject(res) : res.native ? native(res) : await forward(req, body, res);
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
