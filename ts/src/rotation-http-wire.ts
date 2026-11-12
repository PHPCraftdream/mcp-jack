import { Agent as HTTPAgent, request as requestHTTP } from "node:http";
import type { ClientRequest, IncomingMessage, RequestOptions } from "node:http";
import { Agent as HTTPSAgent, request as requestHTTPS } from "node:https";
import { performance } from "node:perf_hooks";
import { JackError } from "./errors.js";
import type { RotationResponse } from "./rotation-controller.js";

const addAbortListener = EventTarget.prototype.addEventListener;
const removeAbortListener = EventTarget.prototype.removeEventListener;
const abortedGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;

export function requestError(code = "rotation_request_unavailable"): JackError {
  return new JackError(0, code, "rotation request refused");
}

/** Общий monotonic deadline включает signer/controller work, не только socket idle. */
export class RotationDeadline {
  readonly controller = new AbortController();
  private readonly due: number;
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly abort = (): void => { this.controller.abort(); };

  constructor(timeoutMs: number, private readonly caller?: AbortSignal) {
    let aborted = false;
    if (caller !== undefined) {
      try {
        if (!(caller instanceof AbortSignal) || abortedGetter === undefined) throw requestError();
        aborted = abortedGetter.call(caller) === true;
        if (!aborted) addAbortListener.call(caller, "abort", this.abort, { once: true });
      } catch { throw requestError(); }
    }
    this.due = performance.now() + timeoutMs;
    this.timer = setTimeout(this.abort, timeoutMs);
    this.timer.unref();
    if (aborted) this.abort();
  }

  check(): void {
    if (performance.now() >= this.due) this.abort();
    if (this.controller.signal.aborted) throw requestError();
  }

  close(): void {
    clearTimeout(this.timer);
    if (this.caller !== undefined) removeAbortListener.call(this.caller, "abort", this.abort);
  }
}

/** Один physical POST, fresh connection; без proxy, redirect, compression или retry. */
export function exchange(
  endpoint: URL, target: string, header: string, signature: string,
  body: Uint8Array, limit: number, deadline: RotationDeadline,
): Promise<RotationResponse> {
  deadline.check();
  return new Promise((resolve, reject) => {
    let request: ClientRequest | undefined;
    let incoming: IncomingMessage | undefined;
    let agent: HTTPAgent | undefined;
    let done = false;
    const fail = (code?: string): void => {
      if (done) return;
      done = true;
      incoming?.destroy();
      request?.destroy();
      agent?.destroy();
      reject(requestError(code));
    };
    const receive = (response: IncomingMessage): void => {
      incoming = response;
      response.on("error", () => fail());
      response.on("aborted", () => fail());
      if (done) { response.destroy(); return; }
      const status = response.statusCode ?? 0;
      if (status >= 300 && status <= 399) { fail("rotation_redirect_refused"); return; }
      const auth: string[] = [];
      for (let index = 0; index < response.rawHeaders.length; index += 2) {
        const name = response.rawHeaders[index];
        const value = response.rawHeaders[index + 1];
        if (name === undefined || value === undefined) { fail("rotation_result_invalid"); return; }
        const lower = name.toLowerCase();
        if (lower === "content-encoding" || (lower === "content-type" && value.split(";", 1)[0]?.trim().toLowerCase() === "text/event-stream")) {
          fail("rotation_result_invalid"); return;
        }
        if (lower === "jack-auth") auth.push(value);
      }
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        if (done) return;
        if (chunk.length > limit - size) { fail("rotation_result_invalid"); return; }
        size += chunk.length;
        chunks.push(Buffer.from(chunk));
      });
      response.on("end", () => {
        if (done) return;
        if (!response.complete) { fail(); return; }
        try {
          deadline.check();
          const bytes = Buffer.concat(chunks, size);
          done = true;
          request?.destroy();
          agent?.destroy();
          resolve({ status, headers: auth, requestSignature: signature, body: bytes });
        } catch { fail(); }
      });
    };
    const options: RequestOptions = {
      method: "POST", path: target, maxHeaderSize: 16384,
      signal: deadline.controller.signal,
      headers: {
        "Jack-Auth": header, "Content-Type": "application/json",
        "Content-Length": body.length, "Accept": "application/json, text/event-stream",
        "Accept-Encoding": "identity", "Connection": "close", "MCP-Protocol-Version": "2025-11-25",
      },
    };
    try {
      agent = endpoint.protocol === "https:" ? new HTTPSAgent({ keepAlive: false, maxSockets: 1 }) : new HTTPAgent({ keepAlive: false, maxSockets: 1 });
      options.agent = agent;
      request = endpoint.protocol === "https:"
        ? requestHTTPS(endpoint, { ...options, minVersion: "TLSv1.2", rejectUnauthorized: true }, receive)
        : requestHTTP(endpoint, options, receive);
      request.on("error", () => fail());
      request.end(body);
    } catch { fail(); }
  });
}
