/** node:http adapter serving a Fetch-standard handler. */
import type { IncomingMessage, ServerResponse } from "node:http";
import { AUTH_VALUES_SYMBOL, HEADER_VALUES_SYMBOL, RAW_BODY_SYMBOL, RAW_TARGET_SYMBOL, dropFragment, isOriginFormTarget } from "./fetch.js";
import type { JackRequest } from "./fetch.js";
import { finishResponseAdmission } from "../durable/finish.js";

/** Go defaultMaxBodyBytes (mirrors fetch.ts). */
const DEFAULT_MAX_BODY_BYTES = 1 << 20;

const noop = (): void => {};

type ReadResult =
  | { kind: "body"; body: Buffer }
  | { kind: "too-large" }
  | { kind: "error" }
  | { kind: "aborted" };

/**
 * Adapts a node:http (IncomingMessage, ServerResponse) pair to a
 * Fetch-standard Request, hands it to handler and writes the Response back.
 * Synchronous, fire-and-forget and never throws: aborted connections emit
 * 'error'/'aborted' events that must not crash the process, and an
 * unexpected throw must never become an unhandled rejection or a hung socket.
 */
export function serveNode(
  handler: (req: Request) => Promise<Response>,
  options?: { maxBodyBytes?: number },
): (req: IncomingMessage, res: ServerResponse) => void {
  const limit =
    options?.maxBodyBytes !== undefined && options.maxBodyBytes > 0 ? options.maxBodyBytes : DEFAULT_MAX_BODY_BYTES;

  return (req, res) => {
    // Aborted connections emit 'error'/'aborted'; without listeners the
    // process crashes (unhandled 'error' event).
    req.on("error", noop);
    res.on("error", noop);
    serve(req, res).catch(() => {
      // Last resort: swallow anything and free the socket.
      if (!res.writableEnded && !res.destroyed) res.destroy();
    });
  };

  // Writes an unsigned JSON error (mirrors Go writeError): these requests
  // never reached authentication, or the answer is the adapter's own — never
  // signed.
  function writeError(res: ServerResponse, statusCode: number, code: string, message: string): void {
    if (res.writableEnded || res.destroyed) return;
    try {
      const body = Buffer.from(JSON.stringify({ error: { code, message } }), "utf-8");
      res.statusCode = statusCode;
      res.setHeader("content-type", "application/json");
      res.setHeader("content-length", String(body.length));
      res.end(body);
    } catch {
      // The socket may have died between the guard and the write; the res
      // 'error' listener must not fire into the void.
    }
  }

  // Reads the request body fully under the cap.
  function readBody(req: IncomingMessage): Promise<ReadResult> {
    return new Promise<ReadResult>((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let over = false;
      let settled = false;
      const finish = (result: ReadResult): void => {
        // Late events after settlement must be no-ops.
        if (settled) return;
        settled = true;
        resolve(result);
      };
      req.on("data", (chunk: Buffer) => {
        if (over) return;
        total += chunk.length;
        if (total > limit) {
          // Stay in flowing mode and discard the rest so the client can finish
          // writing while the answer goes out.
          over = true;
          finish({ kind: "too-large" });
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        finish({ kind: "body", body: Buffer.concat(chunks) });
      });
      req.on("error", () => finish({ kind: "error" }));
      req.on("aborted", () => finish({ kind: "aborted" }));
    });
  }

  /**
   * 05 2.1/3.7: an event stream is written frame by frame, status and headers
   * first, and the body is pumped instead of buffered. Returns once the stream
   * ended, failed or the socket died; never throws.
   */
  async function writeEventStream(res: ServerResponse, resp: Response, controller: AbortController): Promise<void> {
    const reader = resp.body?.getReader();
    const stop = (): void => {
      // 3.7: the client is gone; cancel the signed pump and the handler with it.
      controller.abort();
      if (reader !== undefined) void reader.cancel().catch(() => {});
    };
    // 3.7: a socket that dies while the loop waits in read() must cancel that read too,
    // which cancels the signed pump and the handler body behind it.
    controller.signal.addEventListener("abort", () => {
      if (reader !== undefined) void reader.cancel().catch(() => {});
    }, { once: true });
    try {
      for (const [name, value] of resp.headers) {
        if (name.toLowerCase() === "set-cookie") continue;
        // A stream has no length: it is written until it ends.
        if (name.toLowerCase() === "content-length") continue;
        res.setHeader(name, value);
      }
      const cookies = resp.headers.getSetCookie();
      if (cookies.length > 0) res.setHeader("set-cookie", cookies);
      res.statusCode = resp.status;
      if (resp.statusText !== "") res.statusMessage = resp.statusText;
      // The headers go on the wire now, not with the first chunk and never at
      // the end of the stream.
      res.flushHeaders();
    } catch {
      stop();
      return;
    }
    if (reader === undefined) {
      try {
        res.end();
      } catch {
        // The socket may have died between the guard and the write.
      }
      return;
    }
    try {
      for (;;) {
        // Never write a byte after the socket died.
        if (res.destroyed || res.writableEnded) {
          stop();
          return;
        }
        const next = await reader.read();
        if (next.done) break;
        if (res.destroyed || res.writableEnded) {
          stop();
          return;
        }
        res.write(next.value);
      }
    } catch {
      // A read error or a write into a dead socket: same disconnect path.
      stop();
      return;
    }
    try {
      if (!res.destroyed && !res.writableEnded) res.end();
    } catch {
      // The socket may have died between the guard and the write.
    }
  }

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // 3.7: one controller per request, aborted when the socket dies, so the
    // Fetch handler observes the disconnect through its request signal and
    // jackStream(req).signal.
    const controller = new AbortController();
    const onSocketGone = (): void => {
      // A response that already ended normally is not a disconnect.
      if (!res.writableEnded) controller.abort();
    };
    req.on("aborted", onSocketGone);
    req.on("close", () => {
      // req 'close' also fires once a fully received body is done; only an
      // incomplete message means the socket died mid-request.
      if (!req.complete) onSocketGone();
    });
    res.on("close", onSocketGone);

    // Early check BEFORE reading anything so oversized requests are answered
    // without buffering the whole body.
    const cl = req.headers["content-length"];
    if (typeof cl === "string") {
      const n = Number(cl);
      if (cl !== "" && Number.isFinite(n) && Number.isInteger(n) && n > limit) {
        writeError(res, 413, "invalid_request", "request body is too large");
        return;
      }
    }

    const read = await readBody(req);
    if (read.kind === "too-large") {
      // The data listener keeps draining, so the client can finish writing.
      writeError(res, 413, "invalid_request", "request body is too large");
      return;
    }
    if (read.kind === "error") {
      writeError(res, 400, "invalid_request", "request body could not be read");
      return;
    }
    if (read.kind === "aborted") {
      // The connection is gone; Go answers 400 into a dead socket, which is
      // indistinguishable from destroying it — no response can be delivered.
      res.destroy();
      return;
    }
    const body = read.body;

    const wireUrl = typeof req.url === "string" && req.url !== "" ? req.url : "/";
    // Spec 01 section 3.1: only an origin-form target of the bytes 0x21 to 0x7E
    // is signed; refuse the rest (absolute-, authority-, asterisk-form, raw
    // non-ASCII bytes) before verification. node:http's own parser already
    // answers a bare 400 to some of them. A fragment is dropped.
    if (!isOriginFormTarget(wireUrl)) {
      writeError(res, 400, "invalid_request", "malformed request target");
      return;
    }
    const rawTarget = dropFragment(wireUrl);
    // The URL object only satisfies the Request constructor; the RAW target
    // travels to the fetch handler on RAW_TARGET_SYMBOL because `new URL`
    // RESOLVES `..`/`.` dot segments and would otherwise change the bytes
    // that were signed (e.g. `/mcp/../mcp?dot=1` must verify against the raw
    // string). The aud check uses the verifier's configured aud — the Host
    // header is never consulted.
    let url: URL;
    try {
      url = new URL("http://localhost" + rawTarget);
    } catch {
      // Go's net/http rejects malformed targets before any handler.
      writeError(res, 400, "invalid_request", "malformed request target");
      return;
    }

    // Rebuild headers from rawHeaders to preserve multiplicity. Host is
    // appended but the Request constructor silently drops it (a fetch
    // forbidden header) — exactly right, since nothing may trust the Host.
    const headers = new Headers();
    const jackAuthValues: string[] = [];
    const headerInstances: [string, string][] = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const value = req.rawHeaders[i + 1];
      if (name === undefined || value === undefined) continue;
      headers.append(name, value);
      headerInstances.push([name, value]);
      if (name.toLowerCase() === "jack-auth") {
        // Exact order; a repeated Jack-Auth header must reach the verifier,
        // which rejects it as malformed_auth.
        jackAuthValues.push(value);
      }
    }

    const method = req.method ?? "GET";
    const fetchReq = new Request(url, {
      method,
      headers,
      // The per-request signal of 3.7, so a disconnect reaches the handler.
      signal: controller.signal,
      // A conditional spread, never an explicit undefined, keeps
      // exactOptionalPropertyTypes happy; undici throws for a GET body.
      ...(method !== "GET" && method !== "HEAD" && body.length > 0 ? { body } : {}),
    });
    (fetchReq as JackRequest)[RAW_TARGET_SYMBOL] = rawTarget;
    (fetchReq as JackRequest)[AUTH_VALUES_SYMBOL] = jackAuthValues;
    // Repeated header instances with their received casing, for the
    // modern-profile rules (spec 04 S1/S9); the Headers object above has
    // already merged repeats and lowercased names.
    (fetchReq as JackRequest)[HEADER_VALUES_SYMBOL] = headerInstances;
    // undici refuses a GET/HEAD body, but the signature covers the bytes
    // exactly as sent (spec 01 section 3.1): the raw bytes travel to the
    // handler on the symbol, like the raw target and the Jack-Auth values.
    if ((method === "GET" || method === "HEAD") && body.length > 0) {
      (fetchReq as JackRequest)[RAW_BODY_SYMBOL] = body;
    }

    let resp: Response;
    try {
      resp = await handler(fetchReq);
    } catch {
      // jackFetchHandler already maps wrapped-handler failures; this is the
      // last-resort guard for a rejecting/throwing handler, where Go would
      // drop the connection (documented divergence).
      writeError(res, 500, "internal_error", "internal error");
      return;
    }

    if (res.writableEnded || res.destroyed) return;
    // 05 2.1/1.4: only `text/event-stream` is streamed; every other answer is
    // buffered byte for byte as before.
    const contentType = resp.headers.get("content-type");
    const mediaType = contentType === null ? "" : (contentType.split(";")[0]?.trim().toLowerCase() ?? "");
    if (mediaType === "text/event-stream") {
      await writeEventStream(res, resp, controller);
      // Durable admission finishes AFTER the response is written (Go defer
      // res.Done()); it is idempotent.
      finishResponseAdmission(resp);
      return;
    }
    const out = Buffer.from(await resp.arrayBuffer());
    try {
      for (const [name, value] of resp.headers) {
        if (name.toLowerCase() === "set-cookie") continue;
        res.setHeader(name, value);
      }
      // getSetCookie keeps every Set-Cookie line; an array value makes
      // node:http emit one header line per cookie.
      const cookies = resp.headers.getSetCookie();
      if (cookies.length > 0) res.setHeader("set-cookie", cookies);
      res.setHeader("content-length", String(out.length));
      res.statusCode = resp.status;
      if (resp.statusText !== "") res.statusMessage = resp.statusText;
      if (out.length > 0) res.end(out);
      else res.end();
    } catch {
      // The socket may have died between the guard and the write.
    }
    // Durable admission finishes AFTER the response is written (Go defer
    // res.Done() in the middleware). Idempotent: the fetch handler that
    // produced this Response already released the lease; a Response without a
    // durable association (default path) is a no-op.
    finishResponseAdmission(resp);
  }
}
