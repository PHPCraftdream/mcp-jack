// Command rotation-server: the rotation server executable of the rotation
// interop matrix harness (interop rotation contract). Serves signed HTTP on
// 127.0.0.1, publishes rotation records from a ring inventory on stdin
// control lines. stdout carries only the ready line and announce lines; every
// diagnostic goes to stderr, and startup failures exit 1 before any stdout.
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { encodeBase64URL } from "../core/encoding.js";
import { InMemorySigner } from "../client/signing/signer.js";
import { RotationServerProvider } from "../rotation/server/provider.js";
import type { RotationServerKey } from "../rotation/server/provider.js";
import { RotationServerStore } from "../rotation/server/store.js";
import { jackFetchHandler } from "../server/http/fetch.js";
import { Native } from "../server/native.js";
import { NonceStore } from "../server/registry/nonce.js";
import { serveNode } from "../server/http/node.js";
import { openFileState } from "../server/registry/state-file.js";
import type { FileState } from "../server/registry/state-file.js";
import { ServerKeyTool } from "../server/server-key-tool.js";
import { Verifier } from "../server/verify.js";

function fail(msg: string): never {
  process.stderr.write(`rotation-server: ${msg}\n`);
  process.exit(1);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

interface Flags {
  aud: string;
  url: string;
  statePath: string;
  serverSeedHex: string;
  rotationStore: string;
  clockFile: string;
  port: number;
  ringSeeds: ReadonlyArray<{ reference: string; seedHex: string }>;
}

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = {
    aud: "",
    url: "",
    statePath: "",
    serverSeedHex: "",
    rotationStore: "",
    clockFile: "",
    port: 0,
    ringSeeds: [],
  };
  const ringSeeds: { reference: string; seedHex: string }[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name === null) fail(`unexpected argument '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined) fail(`--${name} requires a value`);
    i += 1;
    switch (name) {
      case "aud":
        flags.aud = value;
        break;
      case "url":
        flags.url = value;
        break;
      case "state":
        flags.statePath = value;
        break;
      case "server-seed-hex":
        flags.serverSeedHex = value;
        break;
      case "rotation-store":
        flags.rotationStore = value;
        break;
      case "clock-file":
        flags.clockFile = value;
        break;
      case "port": {
        if (!/^\d+$/.test(value)) fail("--port must be a non-negative integer");
        const port = Number(value);
        if (!Number.isSafeInteger(port) || port > 65535) fail("--port out of range");
        flags.port = port;
        break;
      }
      case "ring-seed": {
        // Value is <ref>=<hex>; split at the FIRST '=' only.
        const eq = value.indexOf("=");
        if (eq <= 0) fail("--ring-seed must be <reference>=<64-hex-seed>");
        ringSeeds.push({ reference: value.slice(0, eq), seedHex: value.slice(eq + 1) });
        break;
      }
      default:
        fail(`unknown flag --${name}`);
    }
  }
  flags.ringSeeds = ringSeeds;
  return flags;
}

function requireFlags(flags: Flags): void {
  const missing = (
    [
      ["--aud", flags.aud],
      ["--url", flags.url],
      ["--state", flags.statePath],
      ["--server-seed-hex", flags.serverSeedHex],
      ["--rotation-store", flags.rotationStore],
      ["--clock-file", flags.clockFile],
    ] as const
  ).filter(([_, value]) => value === "");
  if (missing.length > 0) fail(`required flags: ${missing.map(([name]) => name).join(", ")}`);
}

function decodeSeed(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    fail("seed must be 64 hex chars (32 bytes)");
  }
  return Buffer.from(hex.toLowerCase(), "hex");
}

// ---------------------------------------------------------------------------
// Injected clock.
// ---------------------------------------------------------------------------

// Samples --clock-file on EVERY call (the harness rewrites it to advance the
// clock); keeps the last good value so a transient bad file holds the clock,
// and throws before any good sample so the stores fence fail-closed with
// rotation_clock_unavailable.
function makeNow(clockFile: string): () => number {
  let last = -1;
  return (): number => {
    try {
      const text = readFileSync(clockFile, "utf8").trim();
      if (!/^\d+$/.test(text)) throw new Error("not a decimal integer");
      const value = Number(text);
      if (!Number.isSafeInteger(value)) throw new Error("not a safe integer");
      last = value;
    } catch (err) {
      if (last < 0) {
        process.stderr.write(`rotation-server: clock sample failed: ${message(err)}\n`);
        throw new Error(`clock file '${clockFile}' unavailable`);
      }
    }
    return last;
  };
}

// ---------------------------------------------------------------------------
// Store, provider, verifier.
// ---------------------------------------------------------------------------

interface ServerContext {
  store: RotationServerStore;
  provider: RotationServerProvider;
  signer0: InMemorySigner;
  now: () => number;
}

function openContext(flags: Flags): ServerContext {
  const seed = decodeSeed(flags.serverSeedHex);
  const signer0 = new InMemorySigner(seed);
  const kid0 = signer0.kid();
  const pub0b64 = encodeBase64URL(signer0.publicKey());
  const now = makeNow(flags.clockFile);
  const options = {
    binding: { endpoint: flags.url, aud: flags.aud },
    window: 30,
    checkpoint: { ordinal: 0, hash: "-", kid: kid0, publicKeyB64u: pub0b64, publishedAt: 0 },
    now,
    anchorReference: "ring-0",
  };
  if (!existsSync(flags.rotationStore)) {
    try {
      RotationServerStore.initializeUnused(flags.rotationStore, options);
    } catch (err) {
      fail(`initializing rotation store: ${message(err)}`);
    }
  }
  let store: RotationServerStore;
  try {
    store = RotationServerStore.open(flags.rotationStore, options);
  } catch (err) {
    fail(`opening rotation store: ${message(err)}`);
  }
  const keys: RotationServerKey[] = [{ reference: "ring-0", signer: signer0 }];
  for (const entry of flags.ringSeeds) {
    keys.push({ reference: entry.reference, signer: new InMemorySigner(decodeSeed(entry.seedHex)) });
  }
  let provider: RotationServerProvider;
  try {
    provider = new RotationServerProvider(store, keys);
  } catch (err) {
    fail(`building rotation provider: ${message(err)}`);
  }
  return { store, provider, signer0, now };
}

function openVerifierState(path: string): FileState {
  try {
    return openFileState(path);
  } catch (err) {
    return fail(`state file: ${message(err)}`);
  }
}

// ---------------------------------------------------------------------------
// The trivial MCP handler behind the signed wrapper (ping and errors only).
// ---------------------------------------------------------------------------

// Envelopes are composed by string so the id member keeps its raw JSON text.
function envelopeResult(idText: string, resultJson: string): string {
  return `{"jsonrpc":"2.0","id":${idText},"result":${resultJson}}`;
}

function envelopeError(idText: string): string {
  return `{"jsonrpc":"2.0","id":${idText},"error":{"code":-32601,"message":"method not found"}}`;
}

function jsonBody(text: string): Response {
  return new Response(text, { headers: { "content-type": "application/json" } });
}

// Absent id answers as null; a parsed id is re-encoded verbatim.
function idTextOf(body: Uint8Array): string {
  try {
    const req: unknown = JSON.parse(new TextDecoder().decode(body));
    if (typeof req === "object" && req !== null && "id" in req) {
      const id = (req as { id: unknown }).id;
      return id === undefined ? "null" : JSON.stringify(id);
    }
  } catch {
    // best-effort parse: fall through to null id
  }
  return "null";
}

function methodOf(body: Uint8Array): string | undefined {
  try {
    const req: unknown = JSON.parse(new TextDecoder().decode(body));
    if (typeof req === "object" && req !== null && "method" in req) {
      const method = (req as { method: unknown }).method;
      if (typeof method === "string") return method;
    }
  } catch {
    // best-effort parse
  }
  return undefined;
}

async function mcpHandler(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonBody(envelopeResult("null", "{}"));
  }
  const body = new Uint8Array(await req.arrayBuffer());
  return methodOf(body) === "ping" ? jsonBody(envelopeResult(idTextOf(body), "{}")) : jsonBody(envelopeError(idTextOf(body)));
}

// ---------------------------------------------------------------------------
// Serve mode.
// ---------------------------------------------------------------------------

interface AnnounceLine {
  announced: true;
  ordinal: number;
  head_ordinal: number;
  head_hash: string;
  published_at: number;
  activates_at: number;
  revision: number;
}

interface AnnounceFailure {
  announced: false;
  reason: string;
}

function emitLine(line: AnnounceLine | AnnounceFailure): void {
  process.stdout.write(JSON.stringify(line) + "\n");
}

// Stdin control: one JSON object per line, op "announce" publishes one record.
function runControl(provider: RotationServerProvider): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    let doc: unknown;
    try {
      doc = JSON.parse(line);
    } catch (err) {
      process.stderr.write(`rotation-server: control line: ${message(err)}\n`);
      return;
    }
    if (typeof doc !== "object" || doc === null) {
      process.stderr.write("rotation-server: control line: not a JSON object\n");
      return;
    }
    const rec = doc as { op?: unknown; reference?: unknown; kid?: unknown };
    if (rec.op !== "announce") {
      process.stderr.write("rotation-server: unknown control op\n");
      return;
    }
    if (typeof rec.reference !== "string" || typeof rec.kid !== "string") {
      process.stderr.write("rotation-server: announce needs string reference and kid\n");
      return;
    }
    try {
      const r = provider.announce(rec.reference, rec.kid);
      emitLine({
        announced: true,
        ordinal: r.record.ordinal,
        head_ordinal: r.record.ordinal,
        head_hash: r.record.hash,
        published_at: r.record.publishedAt,
        activates_at: r.record.activatesAt,
        revision: r.revision,
      });
    } catch (err) {
      process.stderr.write(`rotation-server: announce failed: ${message(err)}\n`);
      emitLine({ announced: false, reason: "rotation_state_unavailable" });
    }
  });
  rl.on("close", () => {
    stop();
  });
}

function serve(flags: Flags): void {
  const ctx = openContext(flags);
  closeStore = (): void => {
    ctx.store.close();
  };
  const state = openVerifierState(flags.statePath);
  // The native allowlist is unchanged; serverKeys routes ONLY jack.server.key.
  const verifier = new Verifier({
    aud: flags.aud,
    state,
    nonces: new NonceStore(),
    native: new Native(),
    now: ctx.now,
    serverKeys: new ServerKeyTool(ctx.store, ctx.provider),
  });
  const handler = jackFetchHandler({ verifier, rotationKeys: ctx.provider }, mcpHandler);
  const server = createServer(serveNode(handler));
  server.on("error", (err: Error) => fail(`listen: ${err.message}`));
  server.listen(flags.port, "127.0.0.1", () => {
    const addr = server.address();
    const port = addr !== null && typeof addr === "object" ? addr.port : 0;
    if (port <= 0) fail("listen: cannot determine the bound port");
    // The ready line is the first and only stdout output until announce lines.
    process.stdout.write(
      JSON.stringify({
        ready: true,
        port,
        server_public_key: encodeBase64URL(ctx.signer0.publicKey()),
        server_kid: ctx.signer0.kid(),
      }) + "\n",
    );
  });
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  runControl(ctx.provider);
}

function stop(): void {
  // Never fails the process on teardown; diagnostics go to stderr only.
  try {
    closeStore();
  } catch (err) {
    process.stderr.write(`rotation-server: store close: ${message(err)}\n`);
  }
  process.exit(0);
}

// Set once serve() has opened the store; stop() closes it before exit.
let closeStore = (): void => undefined;

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

function main(): void {
  const flags = parseFlags(process.argv.slice(2));
  requireFlags(flags);
  serve(flags);
}

main();
