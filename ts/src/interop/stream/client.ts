import { request as httpRequest } from "node:http";
import type { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { readFileSync } from "node:fs";
import { InMemorySigner } from "../../client/signing/signer.js";
import { createSigningFetch } from "../../client/transport/transport.js";
import { openSignedStream } from "../../client/stream/session.js";
import { parseRequestAuth, parseResponseAuth } from "../../core/auth-header.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../../core/encoding.js";
import type { StreamServerKey } from "../../stream/verify.js";
import { parseStreamFrame, parseStreamOpenAuth, StreamEventReader, streamSignalCode } from "../../stream/wire.js";
import { clockFile, diagnostic, integer, jsonl, need, parseFlagsFull, scenario } from "./common.js";

type Pair = readonly [string, string];
type MutablePair = [string, string];

const fixtures = JSON.parse(
  readFileSync(new URL("../../../../spec/fixtures/keys.json", import.meta.url), "utf8"),
).keys;

function rows(headers: Headers): Pair[] {
  const result: Pair[] = [];
  headers.forEach((value, name) => result.push([name, value]));
  return result;
}

function outgoing(headers: readonly Pair[]): OutgoingHttpHeaders {
  const result: OutgoingHttpHeaders = {};
  for (const [name, value] of headers) {
    const existing = result[name];
    if (existing === undefined) result[name] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else result[name] = [String(existing), value];
  }
  return result;
}

function makeFetch(save: (value: any) => void, mirrors: readonly Pair[]): typeof fetch {
  return async (input, init) => new Promise<Response>((resolve, reject) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";
    const body = init?.body instanceof Uint8Array
      ? init.body
      : typeof init?.body === "string"
        ? Buffer.from(init.body)
        : Buffer.alloc(0);
    const outgoingRows = init?.headers instanceof Headers
      ? rows(init.headers)
      : rows(new Headers(init?.headers));
    const mirrorNames = new Set(mirrors.map(([name]) => name.toLowerCase()));
    const nonMirrors = outgoingRows.filter(([name]) => !mirrorNames.has(name.toLowerCase()));
    const authIndex = nonMirrors.findIndex(([name]) => name.toLowerCase() === "jack-auth");
    nonMirrors.splice(authIndex < 0 ? nonMirrors.length : authIndex + 1, 0, ...mirrors.map(([name, value]) => [name, value] as Pair));
    outgoingRows.splice(0, outgoingRows.length, ...nonMirrors);
    if (!outgoingRows.some(([name]) => name.toLowerCase() === "content-length")) {
      outgoingRows.push(["content-length", String(body.length)]);
    }
    const requestAbort = new AbortController();
    const timer = setTimeout(() => requestAbort.abort(new Error("request timeout")), 120_000);
    timer.unref();
    const callerSignal = init?.signal;
    const onCallerAbort = () => requestAbort.abort(callerSignal?.reason);
    if (callerSignal?.aborted) onCallerAbort();
    else callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      clearTimeout(timer);
      callerSignal?.removeEventListener("abort", onCallerAbort);
    };
    const request = httpRequest({
      hostname: url.hostname,
      port: Number(url.port),
      path: url.pathname + url.search,
      method,
      headers: outgoing(outgoingRows),
      agent: false,
      signal: requestAbort.signal,
    }, (response: IncomingMessage) => {
      const responseHeaders = new Headers();
      for (let index = 0; index + 1 < response.rawHeaders.length; index += 2) {
        responseHeaders.append(response.rawHeaders[index]!, response.rawHeaders[index + 1]!);
      }
      const chunks: Uint8Array[] = [];
      const wireFrames: any[] = [];
      const waiters: (() => void)[] = [];
      const parser = new StreamEventReader();
      let captureRecord: any;
      let settled = false;
      let ended = false;
      const wireController: { current?: ReadableStreamDefaultController<Uint8Array> } = {};
      const finish = () => {
        if (settled) return;
        settled = true;
        if (ended) {
          for (const lines of parser.finish()) {
            const parsed = parseStreamFrame(lines);
            if (parsed.ok) wireFrames.push(parsed.value);
          }
          captureRecord.evidenceTaskSettled = true;
          for (const wake of waiters.splice(0)) wake();
          wireController.current?.close();
        }
      };
      const onEnd = () => {
        ended = true;
        onReadable();
        cleanup();
        response.removeListener("readable", onReadable);
        response.removeListener("close", onClose);
        response.removeListener("error", onError);
      };
      const onReadable = () => { if (wireController.current) pull(wireController.current); };
      const onClose = () => {
        response.removeListener("readable", onReadable);
        response.removeListener("end", onEnd);
        response.removeListener("error", onError);
        if (!ended) { cleanup(); settled = true; captureRecord.evidenceTaskSettled = true; for (const wake of waiters.splice(0)) wake(); wireController.current?.error(new Error("aborted")); }
      };
      const onError = (error: Error) => {
        response.removeListener("readable", onReadable);
        response.removeListener("end", onEnd);
        response.removeListener("close", onClose);
        cleanup(); settled = true; captureRecord.evidenceTaskSettled = true; for (const wake of waiters.splice(0)) wake(); wireController.current?.error(error);
      };
      const wire = new ReadableStream<Uint8Array>({
        start(controller) {
          wireController.current = controller;
          response.on("readable", onReadable);
          response.once("end", onEnd);
          response.once("close", onClose);
          response.once("error", onError);
        },
        pull(controller) { pull(controller); },
        cancel() {
          cleanup();
          response.removeListener("readable", onReadable);
          response.removeListener("end", onEnd);
          response.removeListener("close", onClose);
          response.removeListener("error", onError);
          settled = true;
          captureRecord.evidenceTaskSettled = true;
          for (const wake of waiters.splice(0)) wake();
          request.destroy();
        },
      });
      function pull(controller: ReadableStreamDefaultController<Uint8Array>): void {
        if (settled) return;
        let chunk: Buffer | null;
        let drained = false;
        while (true) {
          chunk = response.read();
          if (chunk === null) { drained = true; break; }
          const bytes = new Uint8Array(chunk);
          chunks.push(bytes);
          for (const lines of parser.push(bytes)) {
            const parsed = parseStreamFrame(lines);
            if (parsed.ok) {
              wireFrames.push(parsed.value);
              for (const wake of waiters.splice(0)) wake();
            }
          }
          controller.enqueue(bytes);
          if ((controller.desiredSize ?? 0) <= 0) break;
        }
        if (ended && drained && !settled) finish();
      }
      captureRecord = {
        method,
        target: url.pathname + url.search,
        outgoingRows,
        body: Buffer.from(body),
        status: response.statusCode ?? 0,
        responseHeaders,
        rawResponseHeaders: rawHeaderRows(response),
        chunks,
        wireFrames,
        waiters,
        claimedFrames: new Set(),
        evidenceTaskSettled: false,
      };
      save(captureRecord);
      resolve(new Response(wire, { status: response.statusCode ?? 500, headers: responseHeaders }));
    });
    request.on("error", (error) => { cleanup(); reject(error); });
    if (init?.signal?.aborted) request.destroy(new Error("aborted"));
    request.end(body.length ? Buffer.from(body) : undefined);
  });
}

let terminalWritten = false;
let currentScenario: string | null = null;
let currentRequestId: unknown = null;
function terminalJsonl(value: Record<string, unknown>): void {
  if (terminalWritten) return;
  terminalWritten = true;
  jsonl(value);
}

async function main(): Promise<void> {
  const parsed = parseFlagsFull(process.argv.slice(2));
  const flags = parsed.flags;
  const repeated = parsed.repeated;
  const id = need(flags, "scenario");
  currentScenario = id;
  const meta = scenario(id);
  const matrix = need(flags, "matrix");
  if (need(flags, "profile") !== "modern" || !matrix) {
    throw new Error("expected modern profile and matrix");
  }
  const origin = new URL(need(flags, "url"));
  const url = new URL("/mcp", origin.origin);
  const aud = need(flags, "aud");
  const now = clockFile(need(flags, "clock-file"));
  const seed = Buffer.from(need(flags, "seed-hex"), "hex");
  const signer = new InMemorySigner(seed);
  const serverKey = decodeBase64URLFixed(need(flags, "server-public-key"), 32);
  const knownKeys: { kid: string; publicKey: Uint8Array; activation: number }[] = [];
  for (const value of repeated["known-server-key"] ?? []) {
    const fields: Record<string, string> = {};
    for (const segment of value.split(",")) {
      const eq = segment.indexOf("=");
      if (eq <= 0) throw new Error("invalid --known-server-key");
      const name = segment.slice(0, eq);
      if (!(["kid", "public", "activation"] as const).includes(name as "kid" | "public" | "activation") || Object.hasOwn(fields, name)) {
        throw new Error("invalid --known-server-key");
      }
      fields[name] = segment.slice(eq + 1);
    }
    if (fields.kid === undefined || fields.kid === "" || fields.public === undefined || fields.activation === undefined ||
      !/^(0|[1-9][0-9]*)$/.test(fields.activation)) throw new Error("invalid --known-server-key");
    const activation = Number(fields.activation);
    if (!Number.isSafeInteger(activation)) throw new Error("invalid --known-server-key");
    let publicKey: Uint8Array;
    try { publicKey = decodeBase64URLFixed(fields.public, 32); } catch { throw new Error("invalid --known-server-key"); }
    knownKeys.push({ kid: fields.kid, publicKey, activation });
  }
  const pinnedKid = keyId(serverKey);
  const successorActivation = flags["successor-activation"] === undefined ? undefined : integer(flags, "successor-activation");
  const resolveKey = (kid: string): StreamServerKey | undefined => {
    const entry = knownKeys.find((candidate) => candidate.kid === kid);
    if (entry !== undefined) {
      if (now() < entry.activation) return undefined;
      return { kid: entry.kid, publicKey: entry.publicKey };
    }
    if (kid === pinnedKid) {
      return successorActivation === undefined ? { kid, publicKey: serverKey } : { kid, publicKey: serverKey, successorActivation };
    }
    return undefined;
  };
  const body = Buffer.from(need(flags, "request-body-json"));
  const requestData = JSON.parse(body.toString("utf8"));
  currentRequestId = requestData.id;
  let mirrors: Pair[];
  try {
    mirrors = JSON.parse(need(flags, "mirror-headers-json"));
  } catch {
    throw new Error("invalid mirrors");
  }
  if (!Array.isArray(mirrors) || mirrors.some((row) => !Array.isArray(row) || row.length !== 2)) {
    throw new Error("invalid mirrors");
  }

  const nonce = decodeBase64URLFixed(need(flags, "nonce"), 16);
  const config = {
    aud,
    signer,
    serverKey,
    resolveKey,
    clock: now,
    nonceSource: () => nonce,
    windowSeconds: 30,
    requestId: requestData.id,
    ...(meta.stream_options?.frameMaxBytes === undefined ? {} : { frameMaxBytes: meta.stream_options.frameMaxBytes }),
    ...(flags["frame-max-bytes"] === undefined ? {} : { frameMaxBytes: integer(flags, "frame-max-bytes") }),
    ...(meta.stream_options?.idleTimeoutMs === undefined ? {} : { streamIdleMs: meta.stream_options.idleTimeoutMs }),
    ...(flags["idle-timeout-ms"] === undefined ? {} : { streamIdleMs: integer(flags, "idle-timeout-ms") }),
  };
  let capture: any;
  const fetch = makeFetch((value) => { capture = value; }, mirrors);
  const accept = flags["jack-accept"] ?? "";
  const inputHeaders: Pair[] = [
    ["content-type", "application/json"],
    ...mirrors,
    ...(accept ? [["Jack-Accept", accept] as Pair] : []),
  ];
  const init = { method: "POST", body, headers: inputHeaders.map(([name, value]): MutablePair => [name, value]) };

  if (id === "opt-in-required") {
    const response = await createSigningFetch(config, fetch)(url.href, init);
    const raw = new Uint8Array(await response.arrayBuffer());
    const requestHeaders = evidenceHeaders(capture, body, mirrors, accept);
    const requestAuth = parseRequestAuth(authValues(requestHeaders));
    const responseAuth = parseResponseAuth(capture.rawResponseHeaders
      .filter(([name]: Pair) => name.toLowerCase() === "jack-auth")
      .map(([, value]: Pair) => value));
    let refusal: unknown;
    try { refusal = JSON.parse(new TextDecoder().decode(raw)); } catch { refusal = null; }
    const refusalRecord = typeof refusal === "object" && refusal !== null && !Array.isArray(refusal)
      ? refusal as Record<string, unknown>
      : undefined;
    const error = typeof refusalRecord?.error === "object" && refusalRecord.error !== null && !Array.isArray(refusalRecord.error)
      ? refusalRecord.error as Record<string, unknown>
      : undefined;
    const refusalCode = typeof error?.code === "string" ? error.code : "unknown_error";
    const evidence = {
      status: capture.status,
      ts: responseAuth.ts,
      kid: responseAuth.kid,
      request_sig: requestAuth.sig,
      body_b64u: encodeBase64URL(raw),
      sig: responseAuth.sig,
    };
    terminalJsonl({
      type: "terminal", scenario: id, outcome: "refused", code: refusalCode,
      http_status: capture.status, http_code: refusalCode, frames_verified: 0,
      request_id: requestData.id, mcp_complete: false, terminal_frame: null,
      request_sig: requestAuth.sig, v1_evidence: evidence, open: null, frames: [],
      failure_frame: null, successor_activation: null,
    });
    return;
  }

  let session;
  try {
    session = await openSignedStream(config, url.href, init, fetch);
  } catch (error) {
    if (capture?.status === 429) {
      const raw = Buffer.concat(capture.chunks.map((chunk: Uint8Array) => Buffer.from(chunk)));
      let refusal: unknown;
      try { refusal = JSON.parse(raw.toString("utf8")); } catch { refusal = null; }
      const record = typeof refusal === "object" && refusal !== null && !Array.isArray(refusal) ? refusal as Record<string, unknown> : undefined;
      const errorRecord = typeof record?.error === "object" && record.error !== null && !Array.isArray(record.error) ? record.error as Record<string, unknown> : undefined;
      if (typeof errorRecord?.message !== "string") throw error;
      const refusalCode = errorRecord.message;
      const requestHeaders = evidenceHeaders(capture, body, mirrors, accept);
      const requestAuth = parseRequestAuth(authValues(requestHeaders));
      const responseAuth = parseResponseAuth(capture.rawResponseHeaders
        .filter(([name]: Pair) => name.toLowerCase() === "jack-auth")
        .map(([, value]: Pair) => value));
      const evidence = {
        status: capture.status,
        ts: responseAuth.ts,
        kid: responseAuth.kid,
        request_sig: requestAuth.sig,
        body_b64u: encodeBase64URL(raw),
        sig: responseAuth.sig,
      };
      terminalJsonl({
        type: "terminal", scenario: id, outcome: "refused", code: refusalCode,
        http_status: capture.status, http_code: refusalCode, frames_verified: 0,
        request_id: requestData.id, mcp_complete: false, terminal_frame: null,
        request_sig: requestAuth.sig, v1_evidence: evidence, open: null, frames: [],
        failure_frame: null, successor_activation: null,
      });
      return;
    }
    if (capture?.status === 401) {
      const raw = Buffer.concat(capture.chunks.map((chunk: Uint8Array) => Buffer.from(chunk)));
      let refusal: unknown;
      try { refusal = JSON.parse(raw.toString("utf8")); } catch { refusal = null; }
      const record = typeof refusal === "object" && refusal !== null && !Array.isArray(refusal) ? refusal as Record<string, unknown> : undefined;
      const errorRecord = typeof record?.error === "object" && record.error !== null && !Array.isArray(record.error) ? record.error as Record<string, unknown> : undefined;
      if (errorRecord?.code === "replayed_nonce") {
        const requestHeaders = evidenceHeaders(capture, body, mirrors, accept);
        const requestAuth = parseRequestAuth(authValues(requestHeaders));
        terminalJsonl({
          type: "terminal", scenario: id, outcome: "refused", code: "replayed_nonce",
          http_status: 401, http_code: "replayed_nonce", frames_verified: 0,
          request_id: requestData.id, mcp_complete: false, terminal_frame: null,
          request_sig: requestAuth.sig, v1_evidence: null, open: null, frames: [],
          failure_frame: null, successor_activation: null,
        });
        return;
      }
    }
    throw error;
  }
  const responseAuth = capture.rawResponseHeaders.find(([name]: Pair) => name.toLowerCase() === "jack-auth")?.[1] ?? "";
  const parsedOpen = parseStreamOpenAuth(responseAuth);
  if (!parsedOpen.ok) throw new Error("open auth parse failure");
  const open = parsedOpen.value;
  const requestHeaders = evidenceHeaders(capture, body, mirrors, accept);
  const requestAuth = parseRequestAuth(authValues(requestHeaders));
  const rawFrames: any[] = [];
  const frames: any[] = [];
  let delivered = 0;
  let outcome = "complete";
  let code: string | null = null;

  try {
    for await (const data of session.messages()) {
      const frame = await frameForData(capture, data);
      if (frame) {
        rawFrames.push(frame);
        frames.push(frameRecord(frame, open));
      }
      let message: unknown;
      try { message = JSON.parse(data); } catch { message = null; }
      jsonl({
        type: "message", scenario: id, stream_index: 0,
        request_method: capture.method, request_target: capture.target,
        request_body_b64u: encodeBase64URL(body), request_headers: requestHeaders,
        request_sig: requestAuth.sig, request_ts: requestAuth.ts,
        nonce: requestAuth.nonce,
        open: { sid: open.sid, kid: open.kid, ts: open.ts, sig: open.sig },
        frames: frames.slice(), data, message,
      });
      delivered++;
      if ((id === "cancel" || flags.action === "cancel") && delivered === 1) {
        outcome = "cancelled";
        await session.cancel();
        await waitForHandlerCancelled(need(flags, "request-log"), requestAuth.sig);
        break;
      }
    }
  } catch (error) {
    outcome = "error";
    code = error instanceof Error && "code" in error
      ? String((error as { code: unknown }).code)
      : "stream_truncated";
  }

  const done = await session.done;
  if (done.terminal.state === "error" && outcome !== "cancelled") {
    outcome = "error";
    code = done.terminal.code;
  }
  if (outcome === "complete") {
    for (const frame of capture.wireFrames) {
      if (frame.kind === "jack-end" && !rawFrames.some((verified) => verified.seq === frame.seq)) {
        rawFrames.push(frame);
        frames.push(frameRecord(frame, open));
      }
    }
  }

  const terminalCode = done.terminal.state === "error" ? done.terminal.code : null;
  const failedIndex = done.terminal.state === "error"
    ? (terminalCode === "stream_frame_too_large" ? done.terminal.framesVerified - 1 : done.terminal.framesVerified)
    : -1;
  const failed = done.terminal.state === "error" ? capture.wireFrames[failedIndex] : undefined;
  const failureFrame = failed ? {
    kind: streamSignalCode(failed.data) !== null ? "signal" : "message",
    sid: open.sid,
    kid: open.kid,
    seq: failed.seq,
    ts: failed.ts,
    data: failed.data,
    sig: failed.sig,
  } : null;
  const verifiedCount = done.terminal.state === "error" ? done.terminal.framesVerified : frames.length;
  const lastMessage = [...frames].reverse().find((frame) => frame.kind === "message");
  const complete = outcome === "complete"
    && frames.at(-1)?.kind === "end"
    && final(lastMessage?.data, requestData.id);
  terminalJsonl({
    type: "terminal", scenario: id, outcome, code, http_status: null, http_code: null,
    frames_verified: verifiedCount, request_id: requestData.id, mcp_complete: !!complete,
    terminal_frame: frames.at(-1)?.kind === "end" ? { kind: "end", sig: frames.at(-1).sig } : null,
    request_sig: requestAuth.sig, v1_evidence: null,
    open: { sid: open.sid, kid: open.kid, ts: open.ts, sig: open.sig },
    frames, failure_frame: failureFrame, successor_activation: successorActivation ?? knownKeys[0]?.activation ?? null,
  });
}

async function waitForHandlerCancelled(path: string, requestSig: string): Promise<void> {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    try {
      const contents = readFileSync(path, "utf8");
      if (contents.split("\n").some((line) => line.includes('"event":"handler_cancelled"') && line.includes(`"request_sig":"${requestSig}"`))) return;
    } catch { /* file may not exist yet */ }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 50);
    });
  }
}
function evidenceHeaders(capture: any, body: Buffer, mirrors: Pair[], accept: string): Pair[] {
  const auth = capture.outgoingRows.find(([name]: Pair) => name.toLowerCase() === "jack-auth")?.[1];
  if (!auth) throw new Error("SDK request omitted Jack-Auth");
  const actualAccept = capture.outgoingRows.find(([name]: Pair) => name.toLowerCase() === "jack-accept")?.[1] ?? "";
  return [
    ["content-type", "application/json"],
    ["content-length", String(body.length)],
    ["Jack-Auth", auth],
    ...mirrors,
    ...(actualAccept ? [["Jack-Accept", actualAccept] as Pair] : []),
  ];
}

function rawHeaderRows(response: IncomingMessage): Pair[] {
  const result: Pair[] = [];
  for (let index = 0; index + 1 < response.rawHeaders.length; index += 2) {
    result.push([response.rawHeaders[index]!, response.rawHeaders[index + 1]!]);
  }
  return result;
}

function authValues(headers: Pair[]): string[] {
  return headers.filter(([name]) => name.toLowerCase() === "jack-auth").map(([, value]) => value);
}

async function frameForData(capture: any, data: string): Promise<any | undefined> {
  for (;;) {
    const frame = capture.wireFrames.find((candidate: any) =>
      !capture.claimedFrames.has(candidate) && candidate.kind === "message",
    );
    if (frame) {
      capture.claimedFrames.add(frame);
      if (frame.data !== data) throw new Error("verified data does not match captured wire frame");
      return frame;
    }
    if (capture.evidenceTaskSettled) return undefined;
    await new Promise<void>((resolve) => capture.waiters.push(resolve));
  }
}

function frameRecord(frame: any, open: any): any {
  return frame.kind === "jack-end"
    ? { kind: "end", sid: open.sid, kid: open.kid, seq: frame.seq, ts: frame.ts, data: "", sig: frame.sig }
    : { kind: "message", sid: open.sid, kid: open.kid, seq: frame.seq, ts: frame.ts, data: frame.data, sig: frame.sig };
}

function final(data: string | undefined, requestId: unknown): boolean {
  try {
    const message = JSON.parse(data ?? "null");
    return message.jsonrpc === "2.0"
      && message.id === requestId
      && (Object.hasOwn(message, "result") !== Object.hasOwn(message, "error"))
      && !Object.hasOwn(message, "method");
  } catch {
    return false;
  }
}

main().catch((error) => {
  diagnostic(error);
  if (!terminalWritten) {
    terminalJsonl({
      type: "terminal", scenario: currentScenario,
      outcome: "error", code: error instanceof Error && "code" in error ? String((error as { code: unknown }).code) : "client_error",
      http_status: null, http_code: null, frames_verified: 0, request_id: currentRequestId, mcp_complete: false,
      terminal_frame: null, request_sig: null, v1_evidence: null, open: null, frames: [],
      failure_frame: null, successor_activation: null,
    });
  }
  process.exitCode = 1;
});
