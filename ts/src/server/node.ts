/** node:http adapter serving a Fetch-standard handler. */
import type { IncomingMessage, ServerResponse } from "node:http";
import { AUTH_VALUES_SYMBOL, RAW_TARGET_SYMBOL } from "./fetch.js";
import type { JackRequest } from "./fetch.js";

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
          over = true;
          req.pause();
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

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
      // Drain so the client can finish writing and read the answer.
      req.resume();
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

    const rawTarget = typeof req.url === "string" && req.url !== "" ? req.url : "/";
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
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const value = req.rawHeaders[i + 1];
      if (name === undefined || value === undefined) continue;
      headers.append(name, value);
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
      // A conditional spread, never an explicit undefined, keeps
      // exactOptionalPropertyTypes happy; undici throws for a GET body.
      ...(method !== "GET" && method !== "HEAD" && body.length > 0 ? { body } : {}),
    });
    (fetchReq as JackRequest)[RAW_TARGET_SYMBOL] = rawTarget;
    (fetchReq as JackRequest)[AUTH_VALUES_SYMBOL] = jackAuthValues;

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
  }
}
