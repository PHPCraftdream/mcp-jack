// Command modern-client: one modern interop matrix scenario per invocation
// (interop/modern/contract.md section 4), run on the TypeScript client SDK.
// Exactly one JSON result line on stdout (exit 0 for a completed scenario,
// whatever its outcome); harness-level failures go to stderr with exit 1 and no
// stdout.
import { InMemorySigner } from "../client/signing/signer.js";
import { BadBase64UrlError, decodeBase64URLFixed } from "../core/encoding.js";
import { clockSource, message, nonceFor, readClock } from "./modern/common.js";
import { ClientRun, runScenario } from "./modern/scenarios.js";
import { TransportFailure, createSender } from "./modern/steps.js";
import { createTransport } from "./modern/wire.js";

function fail(msg: string): never {
  process.stderr.write(`modern-client: ${msg}\n`);
  process.exit(1);
  // Kept for the type only: the layout check compiles without @types/node, where
  // `process.exit` is untyped and cannot end the control flow by itself.
  throw new Error(msg);
}

/** The era a run speaks (contract 4.1): fixed, or settled by the C9 probe. */
type Era = "legacy" | "modern" | "auto";

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

interface Flags {
  url: string;
  aud: string;
  seedHex: string;
  anchor: string;
  scenario: string;
  era: string;
  clockFile: string;
  probeVersion: string;
  jsonId: string;
}

/** Contract 4.1: `--probe-version` and `--json-id` are the only flags with a default. */
function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = {
    url: "",
    aud: "",
    seedHex: "",
    anchor: "",
    scenario: "",
    era: "",
    clockFile: "",
    probeVersion: "2026-07-28",
    jsonId: "1",
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name === null) fail(`unexpected argument '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined) fail(`--${name} requires a value`);
    i += 1;
    switch (name) {
      case "url":
        flags.url = value;
        break;
      case "aud":
        flags.aud = value;
        break;
      case "seed-hex":
        flags.seedHex = value;
        break;
      case "anchor":
        flags.anchor = value;
        break;
      case "scenario":
        flags.scenario = value;
        break;
      case "era":
        flags.era = value;
        break;
      case "clock-file":
        flags.clockFile = value;
        break;
      case "probe-version":
        flags.probeVersion = value;
        break;
      case "json-id":
        // Inserted verbatim as the JSON-RPC id, so any JSON text is legal here.
        flags.jsonId = value;
        break;
      default:
        fail(`unknown flag --${name}`);
    }
  }
  return flags;
}

function requireFlags(flags: Flags): void {
  const missing = (
    [
      ["--url", flags.url === ""],
      ["--aud", flags.aud === ""],
      ["--seed-hex", flags.seedHex === ""],
      ["--anchor", flags.anchor === ""],
      ["--scenario", flags.scenario === ""],
      ["--era", flags.era === ""],
      ["--clock-file", flags.clockFile === ""],
    ] as const
  ).filter(([, isMissing]) => isMissing);
  if (missing.length > 0) fail(`required flags: ${missing.map(([name]) => name).join(", ")}`);
}

function parseEra(text: string): Era {
  if (text === "legacy" || text === "modern" || text === "auto") return text;
  return fail("--era must be legacy, modern or auto");
}

function decodeSeed(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    fail("--seed-hex must be 64 hex chars (32 bytes)");
  }
  return new Uint8Array(Buffer.from(hex.toLowerCase(), "hex"));
}

/** The pinned 32-byte server key; anything that does not decode to exactly 32 bytes is a flag error. */
function decodeAnchor(text: string): Uint8Array {
  try {
    return decodeBase64URLFixed(text, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) fail("--anchor must decode to 32 bytes");
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const flags = parseFlags(process.argv.slice(2));
  requireFlags(flags);
  const era = parseEra(flags.era);
  // Contract 4.2: an unreadable clock file exits 1 before any request is made.
  try {
    readClock(flags.clockFile);
  } catch (err) {
    fail(message(err));
  }
  // Sampled on every use, so the harness advances the clock by rewriting the file.
  const clock = clockSource(flags.clockFile, "modern-client");
  const signer = new InMemorySigner(decodeSeed(flags.seedHex));
  const anchor = decodeAnchor(flags.anchor);
  // `--url` is only the origin: the sender appends the contract's /mcp target.
  const origin = flags.url.replace(/\/+$/, "");
  const transport = createTransport();
  // One nonce per NEW request; the replay bypasses the signing fetch, so a
  // replayed request never consumes an index (contract section 2).
  let index = 0;
  const nonce = (): Uint8Array => nonceFor(flags.scenario, index++);
  const sender = createSender({ origin, aud: flags.aud, signer, anchor, clock, nonce, transport });
  const run = new ClientRun(flags.scenario, era, flags.probeVersion, flags.jsonId, sender);
  try {
    await runScenario(run);
  } catch (err) {
    // A request that never got an answer is a process failure before the first
    // answer (contract 4.2, exit 1); after one it is a reported client_error step,
    // so an earlier 2xx (a handshake 202, say) is never the final verdict.
    if (err instanceof TransportFailure && run.steps.length > 0) {
      run.recordTransportFailure(err.spec);
    } else {
      fail(message(err));
    }
  }
  // Flush before exiting: stdout to a pipe is asynchronous in Node, and a bare
  // process.exit could truncate the only line the harness reads.
  process.stdout.write(JSON.stringify(run.result()) + "\n", () => {
    process.exit(0);
  });
}

void main().catch((err: unknown) => fail(message(err)));
