// Command modern-server: the modern_server executable of the modern interop
// matrix (interop/modern/contract.md section 3), built on the TypeScript
// server SDK. stdout carries only the ready line; every diagnostic goes to
// stderr, and startup failures exit 1 before any stdout.
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { InMemorySigner } from "../client/signing/signer.js";
import { encodeBase64URL } from "../core/encoding.js";
import { SERVER_PROFILES } from "../modern/server.js";
import type { ServerProfile } from "../modern/server.js";
import { jackFetchHandler } from "../server/http/fetch.js";
import { serveNode } from "../server/http/node.js";
import { Native } from "../server/native.js";
import { NonceStore } from "../server/registry/nonce.js";
import { openFileState } from "../server/registry/state-file.js";
import type { FileState } from "../server/registry/state-file.js";
import { Verifier } from "../server/verify.js";
import { clockSource, message, readClock } from "./modern/common.js";
import { createHandler } from "./modern/handler.js";
import type { DiscoverVersionMode } from "./modern/handler.js";

function fail(msg: string): never {
  process.stderr.write(`modern-server: ${msg}\n`);
  process.exit(1);
  // Kept for the type only: the layout check compiles without @types/node, where
  // `process.exit` is untyped and cannot end the control flow by itself.
  throw new Error(msg);
}

/** Contract 3.1: the default `--supported-versions` list. */
const DEFAULT_SUPPORTED_VERSIONS = "2026-07-28,2025-11-25";

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

interface Flags {
  profile: string;
  aud: string;
  statePath: string;
  serverSeedHex: string;
  clockFile: string;
  /** The port, or -1 while `--port` has not been given (0 is a valid port). */
  port: number;
  requestLog: string;
  supportedVersions: string;
  discoverVersionMode: string;
}

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = {
    profile: "",
    aud: "",
    statePath: "",
    serverSeedHex: "",
    clockFile: "",
    port: -1,
    requestLog: "",
    supportedVersions: DEFAULT_SUPPORTED_VERSIONS,
    discoverVersionMode: "supported",
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name === null) fail(`unexpected argument '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined) fail(`--${name} requires a value`);
    i += 1;
    switch (name) {
      case "profile":
        flags.profile = value;
        break;
      case "aud":
        flags.aud = value;
        break;
      case "state":
        flags.statePath = value;
        break;
      case "server-seed-hex":
        flags.serverSeedHex = value;
        break;
      case "clock-file":
        flags.clockFile = value;
        break;
      case "request-log":
        flags.requestLog = value;
        break;
      case "supported-versions":
        flags.supportedVersions = value;
        break;
      case "discover-version-mode":
        flags.discoverVersionMode = value;
        break;
      case "port": {
        if (!/^\d+$/.test(value)) fail("--port must be a decimal integer");
        const port = Number(value);
        if (!Number.isSafeInteger(port) || port > 65535) fail("--port out of range");
        flags.port = port;
        break;
      }
      default:
        fail(`unknown flag --${name}`);
    }
  }
  return flags;
}

function requireFlags(flags: Flags): void {
  const missing = (
    [
      ["--profile", flags.profile === ""],
      ["--aud", flags.aud === ""],
      ["--state", flags.statePath === ""],
      ["--server-seed-hex", flags.serverSeedHex === ""],
      ["--clock-file", flags.clockFile === ""],
      ["--port", flags.port < 0],
    ] as const
  ).filter(([, isMissing]) => isMissing);
  if (missing.length > 0) fail(`required flags: ${missing.map(([name]) => name).join(", ")}`);
}

function parseProfile(text: string): ServerProfile {
  const profile = SERVER_PROFILES.find((candidate) => candidate === text);
  if (profile === undefined) fail(`--profile must be one of ${SERVER_PROFILES.join(", ")}`);
  return profile;
}

function parseDiscoverVersionMode(text: string): DiscoverVersionMode {
  if (text === "supported" || text === "refuse-first" || text === "refuse-always") return text;
  return fail("--discover-version-mode must be supported, refuse-first or refuse-always");
}

/** Contract 3.1: comma-separated, trimmed, empty pieces dropped. */
function parseVersions(text: string): readonly string[] {
  return text.split(",").map((piece) => piece.trim()).filter((piece) => piece !== "");
}

function decodeSeed(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    fail("--server-seed-hex must be 64 hex chars (32 bytes)");
  }
  return Buffer.from(hex.toLowerCase(), "hex");
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

function main(): void {
  const flags = parseFlags(process.argv.slice(2));
  requireFlags(flags);
  const profile = parseProfile(flags.profile);
  const supportedVersions = parseVersions(flags.supportedVersions);
  const discoverVersionMode = parseDiscoverVersionMode(flags.discoverVersionMode);
  const seed = decodeSeed(flags.serverSeedHex);
  // Contract 3.2: an unreadable clock file exits 1 with nothing on stdout.
  try {
    readClock(flags.clockFile);
  } catch (err) {
    fail(message(err));
  }
  // Sampled on every use, so the harness advances the clock by rewriting the file.
  const now = clockSource(flags.clockFile, "modern-server");
  // Contract 3.2: an unreadable state file is a startup error. openFileState
  // itself treats a MISSING file as an empty registry (Go parity), so the
  // presence check has to happen here, before it is opened.
  if (!existsSync(flags.statePath)) fail(`--state ${flags.statePath}: no such file`);
  let state: FileState;
  try {
    state = openFileState(flags.statePath);
  } catch (err) {
    fail(`state file: ${message(err)}`);
  }
  const signer = new InMemorySigner(seed); // ready-line identity from the seed
  const verifier = new Verifier({ aud: flags.aud, state, nonces: new NonceStore(), native: new Native(), now });
  const handler = jackFetchHandler({ verifier, serverKey: seed, profile }, createHandler({
    profile,
    supportedVersions,
    discoverVersionMode,
    requestLog: flags.requestLog === "" ? null : flags.requestLog,
  }));
  const server = createServer(serveNode(handler));
  server.on("error", (err: Error) => fail(`listen: ${err.message}`));
  server.listen(flags.port, "127.0.0.1", () => {
    const addr = server.address();
    const port = addr !== null && typeof addr === "object" ? addr.port : 0;
    if (port <= 0) fail("listen: cannot determine the bound port");
    // The ready line is the first and only stdout output of the process.
    process.stdout.write(
      JSON.stringify({
        ready: true,
        port,
        server_public_key: encodeBase64URL(signer.publicKey()),
        server_kid: signer.kid(),
        profile,
      }) + "\n",
    );
  });
  // Exit 0 on SIGTERM/SIGINT or stdin EOF (the harness closes stdin to stop).
  const stop = (): void => {
    server.close();
    process.exit(0);
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  process.stdin.resume();
  process.stdin.on("end", stop);
  process.stdin.on("close", stop);
}

main();
