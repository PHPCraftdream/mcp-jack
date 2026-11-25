import { createServer } from "node:http";
import { readFileSync, appendFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { InMemorySigner } from "../../client/signing/signer.js";
import { encodeBase64URL } from "../../core/encoding.js";
import { RotationServerProvider } from "../../rotation/server/provider.js";
import type { RotationServerKey } from "../../rotation/server/provider.js";
import { RotationServerStore } from "../../rotation/server/store.js";
import { ServerKeyTool } from "../../server/server-key-tool.js";
import { DurableNonceStore } from "../../server/durable/store.js";
import { DurableNonceAdmission } from "../../server/durable/admission.js";
import { parseRequestAuth } from "../../core/auth-header.js";
import {
  jackFetchHandler,
  jackIdentity,
  jackHeaders,
  RAW_BODY_SYMBOL,
  RAW_TARGET_SYMBOL,
} from "../../server/http/fetch.js";
import type { JackRequest } from "../../server/http/fetch.js";
import { serveNode } from "../../server/http/node.js";
import { Native } from "../../server/native.js";
import { NonceStore } from "../../server/registry/nonce.js";
import { openFileState } from "../../server/registry/state-file.js";
import { Verifier } from "../../server/verify.js";
import { jackStream } from "../../server/http/stream.js";
import { clockFile, diagnostic, integer, jsonl, need, parseFlags, scenario } from "./common.js";

const keys = JSON.parse(
  readFileSync(new URL("../../../../spec/fixtures/keys.json", import.meta.url), "utf8"),
).keys;

function main(): void {
  const flags = parseFlags(process.argv.slice(2));
  if (flags["durable-init"] !== undefined) {
    const dir = need(flags, "durable-dir");
    const now = clockFile(need(flags, "clock-file"));
    const storePath = join(dir, "durable-nonces.bin");
    if (!existsSync(storePath)) DurableNonceStore.initializeUnused(storePath, { deploymentId: "mcp-jack-stream-interop", window: 30, now });
    process.stdout.write('{"durable_initialized":true}\n');
    process.exit(0);
  }
  const id = need(flags, "scenario");
  const meta = scenario(id);
  const matrix = need(flags, "matrix");
  const now = clockFile(need(flags, "clock-file"));
  if (need(flags, "profile") !== "modern" || !["stream", "rotation-stream", "durable-stream"].includes(matrix)) {
    throw new Error("expected modern stream matrix");
  }

  const aud = need(flags, "aud");
  const state = openFileState(need(flags, "state"));
  const seed = Buffer.from(need(flags, "server-seed-hex"), "hex");
  if (seed.length !== 32) throw new Error("invalid server seed");
  const signer = new InMemorySigner(seed);
  const serviceKey = keys.find((key: any) => key.name === "svc");
  if (signer.kid() !== serviceKey.kid) throw new Error("server seed does not identify fixture svc");

  let rotationStore: RotationServerStore | undefined;
  let rotationProvider: RotationServerProvider | undefined;
  let closeRotationStore: () => void = () => undefined;
  if (flags["rotation-store"] !== undefined) {
    const rotationPath = need(flags, "rotation-store");
    const kid0 = signer.kid();
    const rotationOptions = {
      binding: { endpoint: "http://127.0.0.1", aud }, window: 30,
      checkpoint: { ordinal: 0, hash: "-", kid: kid0, publicKeyB64u: encodeBase64URL(signer.publicKey()), publishedAt: 0 },
      now, anchorReference: "ring-0",
    };
    if (!existsSync(rotationPath)) RotationServerStore.initializeUnused(rotationPath, rotationOptions);
    rotationStore = RotationServerStore.open(rotationPath, rotationOptions);
    closeRotationStore = () => rotationStore?.close();
    const rotationKeys: RotationServerKey[] = [{ reference: "ring-0", signer }];
    const ringSeed = flags["ring-seed"];
    if (ringSeed !== undefined) {
      const eq = ringSeed.indexOf("=");
      if (eq <= 0) throw new Error("invalid --ring-seed");
      const reference = ringSeed.slice(0, eq);
      const seedHex = ringSeed.slice(eq + 1);
      if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) throw new Error("invalid --ring-seed");
      const seedBytes = Buffer.from(seedHex, "hex");
      if (seedBytes.length !== 32) throw new Error("invalid --ring-seed");
      rotationKeys.push({ reference, signer: new InMemorySigner(seedBytes) });
    }
    rotationProvider = new RotationServerProvider(rotationStore, rotationKeys);
  }
  let durableStore: DurableNonceStore | undefined;
  let closeDurableStore: () => void = () => undefined;
  if (flags["durable-dir"] !== undefined) {
    durableStore = DurableNonceStore.open(join(need(flags, "durable-dir"), "durable-nonces.bin"), {
      deploymentId: "mcp-jack-stream-interop", window: 30, now,
    });
    closeDurableStore = () => durableStore?.close();
  }

  const options = {
    ...(meta.stream_options ?? {}),
    ...(flags["frame-max-bytes"] === undefined ? {} : { frameMaxBytes: integer(flags, "frame-max-bytes") }),
    ...(flags["max-concurrent-streams"] === undefined ? {} : { maxConcurrentStreams: integer(flags, "max-concurrent-streams") }),
    ...(flags["max-stream-duration-ms"] === undefined ? {} : { maxStreamDurationMs: integer(flags, "max-stream-duration-ms") }),
    ...(flags["heartbeat-ms"] === undefined ? {} : { heartbeatMs: integer(flags, "heartbeat-ms") }),
  };
  const requestLog = need(flags, "request-log");
  let clockControlAcknowledged = false;
  let heldRelease: (() => void) | undefined;
  let heldSid: string | undefined;
  const durationRequests = new Map<string, { start: number; cancelled: boolean; elapsed: boolean }>();
  const verifier = durableStore !== undefined
    ? new Verifier({ aud, state, native: new Native(), now, durable: new DurableNonceAdmission({ store: durableStore, now }) })
    : new Verifier({ aud, state, nonces: new NonceStore(), native: new Native(), now,
      ...(rotationStore === undefined || rotationProvider === undefined ? {} : { serverKeys: new ServerKeyTool(rotationStore, rotationProvider) }) });
  const sdkHandler = jackFetchHandler(
    {
      verifier,
      ...(rotationProvider === undefined ? { serverKey: seed } : { rotationKeys: rotationProvider }),
      profile: "modern",
      streams: {
        ...(options.heartbeatMs === undefined ? {} : { heartbeatMs: options.heartbeatMs }),
        ...(options.maxConcurrentStreams === undefined ? {} : { maxConcurrentStreams: options.maxConcurrentStreams }),
        ...(options.maxStreamDurationMs === undefined ? {} : { maxStreamDurationMs: options.maxStreamDurationMs }),
        ...(options.frameMaxBytes === undefined ? {} : { frameMaxBytes: options.frameMaxBytes }),
      },
    },
    async (req) => {
      const raw = req as JackRequest;
      const body = raw[RAW_BODY_SYMBOL] ?? new Uint8Array(await req.clone().arrayBuffer());
      const text = new TextDecoder().decode(body);
      const parsed = JSON.parse(text);
      const method = parsed.method;
      const params = parsed.params || {};
      const requestAuth = parseRequestAuth([String(req.headers.get("jack-auth") || "")]);
      const requestSig = requestAuth.sig;
      const nonce = requestAuth.nonce;
      const headers = jackHeaders(req) ?? [...req.headers];
      const mirrors = headers.filter(([name]) => /^(mcp-protocol-version|mcp-method|mcp-name|mcp-param-)/i.test(name));
      const mirrorParams = Object.fromEntries(
        mirrors
          .filter(([name]) => /^mcp-param-/i.test(name))
          .map(([name, value]) => [name.slice("mcp-param-".length).toLowerCase(), value]),
      );
      const target = raw[RAW_TARGET_SYMBOL] ?? "/mcp";

      log({
        method: req.method,
        target,
        body: text,
        nonce,
        request_sig: requestSig,
        request_verified: true,
        request_mcp_method: method,
        request_params: params,
        protocol_version: params?._meta?.["io.modelcontextprotocol/protocolVersion"] ?? null,
        mirror_protocol_version: mirrors.find(([name]) => name.toLowerCase() === "mcp-protocol-version")?.[1] ?? null,
        mirror_method: mirrors.find(([name]) => name.toLowerCase() === "mcp-method")?.[1] ?? null,
        mirror_name: mirrors.find(([name]) => name.toLowerCase() === "mcp-name")?.[1] ?? null,
        ...Object.fromEntries(Object.entries(mirrorParams).map(([name, value]) => [`mirror_param_${name}`, value])),
        mirror_headers: mirrors,
        request_method: req.method,
        request_target: target,
        request_body_b64u: encodeBase64URL(body),
        request_headers: headers,
        nonce_committed_before_first_byte: false,
      });
      log({ event: "nonce_committed", nonce, request_sig: requestSig, nonce_committed_before_first_byte: true });

      const context = jackStream(req);
      if (id !== "opt-in-required" && !context) throw new Error("SDK did not attach stream context");
      if (!context) {
        if (id === "opt-in-required") {
          log({ nonce_committed_before_first_byte: true });
          return make([]);
        }
        throw new Error("missing stream context");
      }
      const identity = jackIdentity(req);
      log({
        event: "stream_open",
        nonce_committed_before_first_byte: true,
        sid: context.sid,
        request_sig: requestSig,
        identity: identity?.kid ?? null,
        server_kid: signer.kid(),
      });

      if (id === "cancel") {
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(eventBytes({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } }));
              context.signal.addEventListener("abort", () => {
                log({ event: "handler_cancelled", sid: context.sid, request_sig: requestSig });
              }, { once: true });
            },
          }),
          streamHeaders(),
        );
      }

      if (id === "concurrency-limit") {
        const sid = context.sid;
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(eventBytes({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } }));
              if (heldRelease === undefined) {
                heldSid = sid;
                heldRelease = () => {
                  try {
                    controller.enqueue(eventBytes({ jsonrpc: "2.0", id: parsed.id, result: {} }));
                    controller.close();
                  } catch {
                    // the stream may already be closed; nothing is left to write
                  }
                };
              }
            },
            cancel() {
              if (heldSid === sid) {
                heldRelease = undefined;
                heldSid = undefined;
              }
            },
          }),
          streamHeaders(),
        );
      }

      if (id === "rotation-cutoff-reopen") {
        const activation = integer(flags, "successor-activation");
        const progress = { jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } };
        const final = { jsonrpc: "2.0", id: parsed.id, result: {} };
        if (now() < activation && heldRelease === undefined) {
          const sid = context.sid;
          return new Response(new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(eventBytes(progress));
              controller.enqueue(eventBytes(final));
              heldSid = sid;
              heldRelease = () => { try { controller.close(); } catch { /* already closed */ } };
            },
            cancel() {
              if (heldSid === sid) { heldRelease = undefined; heldSid = undefined; }
            },
          }), streamHeaders());
        }
        return make([progress, final]);
      }

      if (id === "durable-live-replay") {
        const progress = { jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1, message: "stream:first" } };
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(eventBytes(progress));
            const sid = context.sid;
            heldSid = sid;
            heldRelease = () => {
              try { controller.enqueue(eventBytes({ jsonrpc: "2.0", id: parsed.id, result: {} })); controller.close(); }
              catch { /* already closed */ }
            };
          },
          cancel() {
            if (heldSid === context.sid) { heldRelease = undefined; heldSid = undefined; }
          },
        }), streamHeaders());
      }

      if (id === "durable-restart-replay") {
        const progress = { jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1, message: "stream:first" } };
        return make([progress, { jsonrpc: "2.0", id: parsed.id, result: {} }]);
      }

      if (id === "oversize") {
        const limit = options.frameMaxBytes;
        if (limit === undefined) throw new Error("oversize scenario requires --frame-max-bytes");
        const value = JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: { payload: "x".repeat(limit + 32) } });
        const dataBytes = Buffer.byteLength(value, "utf8");
        if (dataBytes <= limit) throw new Error("oversize producer value does not exceed the configured frame limit");
        log({ event: "frame_suppressed", data_bytes: dataBytes, frame_max_bytes: limit });
        return make([value]);
      }

      if (id === "idle") {
        return new Response(new ReadableStream<Uint8Array>({ start() { /* silent past the client idle deadline */ } }), streamHeaders());
      }

      if (method === "events/stream" && id === "max-duration") {
        const start = now();
        const duration = options.maxStreamDurationMs;
        if (duration === undefined) throw new Error("missing max stream duration");
        const tracked = { start, cancelled: false, elapsed: false };
        durationRequests.set(requestSig, tracked);
        const maybeLogElapsed = () => {
          if (tracked.cancelled && clockControlAcknowledged && !tracked.elapsed) {
            tracked.elapsed = true;
            log({ event: "duration_elapsed", start, duration_ms: duration, clock: now() });
          }
        };
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(eventBytes({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } }));
              context.signal.addEventListener("abort", () => {
                tracked.cancelled = true;
                log({ event: "handler_cancelled", sid: context.sid, request_sig: requestSig });
                maybeLogElapsed();
              }, { once: true });
            },
          }),
          streamHeaders(),
        );
      }

      if (id === "max-duration") {
        throw new Error("max-duration scenario requires events/stream");
      }

      if (id === "events-stream") {
        const granted = context.heartbeatMs;
        log({ event: "heartbeat_granted", heartbeat_granted_ms: granted });
        log({ event: "heartbeat_frame", heartbeat_granted_ms: granted, ts: now() });
        return make([
          { jsonrpc: "2.0", method: "notifications/events/active", params: { state: "active" } },
          { jsonrpc: "2.0", method: "notifications/events/event", params: { event: "event" } },
          { jsonrpc: "2.0", method: "notifications/events/heartbeat", params: { event: "heartbeat", heartbeatMs: granted } },
          { jsonrpc: "2.0", method: "notifications/events/terminated", params: { state: "terminated" } },
        ]);
      }
      if (id === "list-changed") {
        return make([
          { jsonrpc: "2.0", method: "notifications/subscriptions/acknowledged", params: { subscriptionId: parsed.id } },
          ...(Array.isArray(params.notifications) && params.notifications.includes("notifications/events/list_changed")
            ? [{ jsonrpc: "2.0", method: "notifications/events/list_changed", params: {} }]
            : []),
          { jsonrpc: "2.0", id: parsed.id, result: {} },
        ]);
      }
      if (id === "opt-in-required") return make([]);
      return make([
        { jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } },
        { jsonrpc: "2.0", id: parsed.id, result: {} },
      ]);
    },
  );

  const handler = async (req: Request): Promise<Response> => {
    const response = await sdkHandler(req);
    if (response.status >= 400) {
      const rawBody = await response.clone().text();
      let envelope: unknown;
      try { envelope = JSON.parse(rawBody); } catch { envelope = null; }
      const error = typeof envelope === "object" && envelope !== null && !Array.isArray(envelope)
        ? (envelope as Record<string, unknown>).error
        : undefined;
      const errorRecord = typeof error === "object" && error !== null && !Array.isArray(error)
        ? error as Record<string, unknown>
        : undefined;
      if (errorRecord?.code === "replayed_nonce") {
        const requestAuth = parseRequestAuth([req.headers.get("jack-auth") ?? ""]);
        log({ event: "replayed_nonce", nonce: requestAuth.nonce, request_sig: requestAuth.sig });
      }
    }
    return response;
  };

  function eventBytes(value: unknown): Uint8Array {
    return new TextEncoder().encode(`data: ${JSON.stringify(value)}\n\n`);
  }
  function streamHeaders(): { status: number; headers: { "content-type": string } } {
    return { status: 200, headers: { "content-type": "text/event-stream" } };
  }
  function make(values: unknown[]): Response {
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (const value of values) controller.enqueue(eventBytes(value));
          controller.close();
        },
      }),
      streamHeaders(),
    );
  }
  function log(row: Record<string, unknown>): void {
    appendFileSync(requestLog, `${JSON.stringify({ scenario: id, matrix, ...row })}\n`);
  }

  const server = createServer(serveNode(handler));
  server.on("error", diagnostic);
  server.listen(integer(flags, "port"), "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("listen failed");
    jsonl({ ready: true, port: address.port, server_public_key: encodeBase64URL(signer.publicKey()), server_kid: signer.kid() });
  });

  let pending = "";
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    try { closeRotationStore(); } catch (error) { process.stderr.write(`rotation store close: ${error instanceof Error ? error.message : String(error)}\n`); }
    try { closeDurableStore(); } catch (error) { process.stderr.write(`durable store close: ${error instanceof Error ? error.message : String(error)}\n`); }
    server.closeAllConnections();
    server.close(() => process.exit(0));
  };
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    pending += chunk;
    let at: number;
    while ((at = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, at).replace(/\r$/, "");
      pending = pending.slice(at + 1);
      try {
        const command = JSON.parse(line);
        if (command.op === "announce") {
          if (rotationProvider === undefined) {
            process.stderr.write("announce requires rotation mode\n");
            continue;
          }
          if (typeof command.reference !== "string" || typeof command.kid !== "string") {
            process.stderr.write("announce requires string reference and kid\n");
            continue;
          }
          try {
            const r = rotationProvider.announce(command.reference, command.kid);
            log({ event: "rotation_announced", reference: command.reference, kid: command.kid,
              published_at: r.record.publishedAt, activates_at: r.record.activatesAt, head_hash: r.record.hash });
            jsonl({ announced: true, ordinal: r.record.ordinal, head_ordinal: r.record.ordinal,
              published_at: r.record.publishedAt, activates_at: r.record.activatesAt, head_hash: r.record.hash });
          } catch (error) {
            process.stderr.write(`announce failed: ${error instanceof Error ? error.message : String(error)}\n`);
          }
        } else if (command.action === "clock_advanced" && id === "max-duration") {
          const clock = now();
          if (command.clock === clock) {
            log({ event: "clock_changed", clock, start: command.start, duration_ms: command.duration_ms });
            clockControlAcknowledged = true;
            for (const [requestSig, tracked] of durationRequests) {
              if (tracked.cancelled && !tracked.elapsed) {
                const duration = options.maxStreamDurationMs;
                if (duration !== undefined) {
                  tracked.elapsed = true;
                  log({ event: "duration_elapsed", start: tracked.start, duration_ms: duration, clock, request_sig: requestSig });
                }
              }
            }
            jsonl({ control: "clock_advanced", clock });
          }
        } else if (command.action === "release") {
          const release = heldRelease;
          const sid = heldSid;
          heldRelease = undefined;
          heldSid = undefined;
          if (release !== undefined) {
            release();
            jsonl({ control: "released", ...(sid === undefined ? {} : { sid }) });
          }
        }
      } catch {
        // Ignore malformed control lines, matching the fake server.
      }
    }
  });
  process.stdin.on("end", stop);
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

try {
  main();
} catch (error) {
  diagnostic(error);
  process.exitCode = 1;
}
