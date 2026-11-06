/** Fetch-standard request handler adapter: body buffering, verification, native tools, response signing. */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { formatResponseAuth } from "../auth-header.js";
import { keyId, encodeBase64URL } from "../encoding.js";
import { responseSigningString } from "../signing.js";
import type { Verifier, VerifyResult } from "./verify.js";

// Go NewHandler returns errors; the Fetch-standard API has no error return in
// its factory shape, so configuration problems THROW a plain Error instead.
// This is the one deliberate divergence of the factory.

/** Configuration for jackFetchHandler (Go HandlerConfig). */
export interface HandlerConfig {
  /** Authenticates and authorizes every request. */
  verifier: Verifier;
  /** 32-byte Ed25519 seed, or an ed25519 private KeyObject. */
  serverKey: Uint8Array | KeyObject;
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
export interface JackRequest extends Request {
  [RAW_TARGET_SYMBOL]?: string;
  [AUTH_VALUES_SYMBOL]?: readonly string[];
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
 */
export function jackFetchHandler(config: HandlerConfig, next: (req: Request) => Promise<Response>): (req: Request) => Promise<Response> {
  if (config.verifier === undefined) throw new Error("server: HandlerConfig.verifier must be set");
  let priv: KeyObject;
  if (config.serverKey instanceof Uint8Array) {
    if (config.serverKey.length !== 32) {
      throw new Error("server: HandlerConfig.serverKey must be an Ed25519 private key");
    }
    priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(config.serverKey)]), format: "der", type: "pkcs8" });
  } else {
    if (config.serverKey.type !== "private" || config.serverKey.asymmetricKeyType !== "ed25519") {
      throw new Error("server: HandlerConfig.serverKey must be an Ed25519 private key");
    }
    priv = config.serverKey;
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
  // SPKI DER is a fixed 44-byte header followed by the 32-byte raw key (client/signer.ts).
  const der = createPublicKey(priv).export({ type: "spki", format: "der" });
  const pub = new Uint8Array(der.subarray(der.length - 32));
  const kid = keyId(pub);

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
  // body bytes (spec 01 section 5) with the INJECTED verifier clock, never
  // Date.now, and writes it.
  function writeSigned(status: number, headers: Headers, body: Uint8Array, requestSig: string, statusText = ""): Response {
    const now = config.verifier.clock();
    const signing = responseSigningString(status, requestSig, kid, now, body);
    const sig = sign(null, Buffer.from(signing, "utf-8"), priv);
    headers.set("jack-auth", formatResponseAuth({ kid, ts: now, sig: encodeBase64URL(sig) }));
    return writeRaw(status, headers, body, statusText);
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
      return writeSigned(res.httpStatus, headers, body, res.requestSig);
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
      return writeSigned(500, headers, errorBody("internal_error", "internal error"), res.requestSig);
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
    return writeSigned(200, headers, new TextEncoder().encode(body), res.requestSig);
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
      const out = writeSigned(501, headers, errorBody("streaming_unsupported", "streaming responses cannot be signed in v0.1"), res.requestSig);
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
    return writeSigned(resp.status, headers, respBody, res.requestSig, resp.statusText);
  }

  return async (req: Request): Promise<Response> => {
    const method = req.method;
    if (method !== "GET" && method !== "POST") {
      return writeError(405, "method_not_allowed", "only GET and POST are defined");
    }

    // The body must be read IN FULL to be hashed whole. The reader lock is
    // released on every exit path; best-effort cancel on the over-limit path.
    let body: Uint8Array;
    if (req.body === null) {
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
      target = rawTarget;
    } else {
      let u: URL;
      try {
        u = new URL(req.url);
      } catch {
        return writeError(400, "invalid_request", "malformed request target");
      }
      target = u.pathname + u.search;
    }

    // The exact Jack-Auth header values in order. Without raw headers a
    // repeated Jack-Auth header cannot be detected (undici's Headers merges
    // duplicates with ", "); the node adapter supplies the exact values via
    // the symbol.
    const rawAuth = (req as JackRequest)[AUTH_VALUES_SYMBOL];
    const authValues =
      rawAuth !== undefined
        ? rawAuth
        : req.headers.get("jack-auth") === null
          ? []
          : [req.headers.get("jack-auth") as string];

    const res = config.verifier.verify({ method, target, authValues, body });
    if (!res.accepted) {
      return reject(res);
    }
    if (res.native) {
      return native(res);
    }
    return forward(req, body, res);
  };
}
