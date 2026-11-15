// Command rotation-client: one rotation interop matrix step per invocation
// (call | refresh | wire | state) on the TypeScript client SDK. Exactly one
// JSON result line on stdout (exit 0 for a completed step, whatever its
// outcome); harness-level failures go to stderr with exit 1 and no stdout.
import { existsSync, readFileSync } from "node:fs";
import { BadBase64UrlError, decodeBase64URLFixed, encodeBase64URL, keyId } from "../encoding.js";
import { JackError } from "../errors.js";
import { parseRequestAuth, parseResponseAuth } from "../auth-header.js";
import { randomNonce, signRequest } from "../client/auth.js";
import { InMemorySigner } from "../client/signer.js";
import { RotationController } from "../rotation-controller.js";
import { RotationHTTPClient } from "../rotation-http.js";
import { RotationError } from "../rotation-record.js";
import { RotationTrustStore } from "../rotation-store.js";
import type { RotationStoreOptions } from "../rotation-store.js";

function fail(msg: string): never {
  process.stderr.write(`rotation-client: ${msg}\n`);
  process.exit(1);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------

interface StepResult {
  outcome: "ok" | "rejected" | "client_error";
  status: number | null; // null unless a wire response was received
  code: string | null; // wire code (rejected) or client-side code (client_error)
  data: unknown; // null unless the step produced reportable data
}

// Prints the one stdout result line and exits 0; the caller must close any
// open store BEFORE calling emit, because emit never returns.
function emit(step: string, r: StepResult): void {
  const out = { scenario: step, outcome: r.outcome, http_status: r.status, code: r.code, data: r.data };
  // Flush before exiting: stdout to a pipe is asynchronous in Node, and a
  // bare process.exit could truncate the only line the harness reads.
  process.stdout.write(JSON.stringify(out) + "\n", () => {
    process.exit(0);
  });
}

function clientError(code: string): StepResult {
  return { outcome: "client_error", status: null, code, data: null };
}

// RotationError/JackError carry the wire or rotation code; anything else is
// reported with the fallback so unexpected throw shapes stay visible.
function errorCode(err: unknown, fallback: string): string {
  return err instanceof JackError || err instanceof RotationError ? err.code : fallback;
}

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

interface Flags {
  step: string;
  url: string;
  aud: string;
  seedHex: string;
  anchor: string;
  store: string;
  clockFile: string;
  cursor: string;
  tool: string;
  window: number;
  timeoutMs: number;
}

const STEPS: ReadonlySet<string> = new Set(["call", "refresh", "wire", "state"]);

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = {
    step: "",
    url: "",
    aud: "",
    seedHex: "",
    anchor: "",
    store: "",
    clockFile: "",
    cursor: "",
    tool: "jack.server.key",
    window: 30,
    timeoutMs: 10000,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : null;
    if (name === null) fail(`unexpected argument '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined) fail(`--${name} requires a value`);
    i += 1;
    switch (name) {
      case "step":
        flags.step = value;
        break;
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
      case "store":
        flags.store = value;
        break;
      case "clock-file":
        flags.clockFile = value;
        break;
      case "cursor":
        flags.cursor = value;
        break;
      case "tool":
        flags.tool = value;
        break;
      case "window": {
        if (!/^\d+$/.test(value)) fail("--window must be a non-negative integer");
        flags.window = Number(value);
        break;
      }
      case "timeout-ms": {
        if (!/^\d+$/.test(value)) fail("--timeout-ms must be a non-negative integer");
        const timeout = Number(value);
        if (!Number.isSafeInteger(timeout)) fail("--timeout-ms out of range");
        flags.timeoutMs = Math.min(30000, Math.max(1, timeout));
        break;
      }
      default:
        fail(`unknown flag --${name}`);
    }
  }
  if (!STEPS.has(flags.step)) fail("--step must be call|refresh|wire|state");
  const required: [string, string][] = [
    ["--url", flags.url],
    ["--aud", flags.aud],
    ["--seed-hex", flags.seedHex],
    ["--clock-file", flags.clockFile],
  ];
  if (flags.step !== "wire") required.push(["--anchor", flags.anchor], ["--store", flags.store]);
  const missing = required.filter(([, value]) => value === "").map(([name]) => name);
  if (missing.length > 0) fail(`required flags: ${missing.join(", ")}`);
  return flags;
}

function decodeSeed(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    fail("--seed-hex must be 64 hex chars (32 bytes)");
  }
  return Buffer.from(hex.toLowerCase(), "hex");
}

// ---------------------------------------------------------------------------
// Store lifecycle.
// ---------------------------------------------------------------------------

function storeOptions(anchorPub: Uint8Array, flags: Flags): RotationStoreOptions {
  return {
    binding: { endpoint: flags.url, aud: flags.aud },
    window: flags.window,
    checkpoint: {
      ordinal: 0,
      hash: "-",
      kid: keyId(anchorPub),
      publicKeyB64u: encodeBase64URL(anchorPub),
      publishedAt: 0,
    },
    now: makeNow(flags.clockFile),
  };
}

// Samples --clock-file on EVERY call (the harness rewrites it to advance the
// clock); keeps the last good value, throws before any good sample.
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
      if (last < 0) throw new Error(`clock file '${clockFile}' unavailable: ${message(err)}`);
    }
    return last;
  };
}

function readClock(clockFile: string): number {
  try {
    const text = readFileSync(clockFile, "utf8").trim();
    if (!/^\d+$/.test(text)) fail(`clock file '${clockFile}': not a decimal integer`);
    const value = Number(text);
    if (!Number.isSafeInteger(value)) fail(`clock file '${clockFile}': not a safe integer`);
    return value;
  } catch (err) {
    return fail(`clock file '${clockFile}': ${message(err)}`);
  }
}

function openStore(path: string, options: RotationStoreOptions): RotationTrustStore {
  if (!existsSync(path)) {
    try {
      RotationTrustStore.initializeUnused(path, options);
    } catch (err) {
      fail(`initializing trust store: ${message(err)}`);
    }
  }
  try {
    return RotationTrustStore.open(path, options);
  } catch (err) {
    fail(`opening trust store: ${message(err)}`);
  }
}

// Closes the store before the result line; a close failure only notes stderr
// (the driver compares results, not store teardown).
function closeQuietly(store: RotationTrustStore, r: StepResult, step: string): void {
  try {
    store.close();
  } catch (err) {
    process.stderr.write(`rotation-client: store close: ${message(err)}\n`);
  }
  emit(step, r);
}

// ---------------------------------------------------------------------------
// Shared wire helpers.
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 1024 * 1024;

// Parses {"error":{"code":...}} best-effort; missing code reports null.
function wireCode(body: Uint8Array): string | null {
  try {
    const doc: unknown = JSON.parse(new TextDecoder().decode(body));
    if (typeof doc === "object" && doc !== null && "error" in doc) {
      const error = (doc as { error: unknown }).error;
      if (typeof error === "object" && error !== null && "code" in error) {
        const code = (error as { code: unknown }).code;
        if (typeof code === "string") return code;
      }
    }
  } catch {
    // best-effort parse
  }
  return null;
}

// Sends one signed POST and classifies transport failures; the caller owns
// the remaining status checks (redirect, encoding, size).
async function signedPost(url: string, header: string, body: Uint8Array): Promise<Response> {
  try {
    return await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "jack-auth": header },
      body: Buffer.from(body),
    });
  } catch {
    throw new JackError(0, "rotation_request_unavailable", "transport failure");
  }
}

function decodeAnchor(anchor: string): Uint8Array {
  try {
    return decodeBase64URLFixed(anchor, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) fail("--anchor must decode to 32 bytes");
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Step: call.
// ---------------------------------------------------------------------------

async function stepCall(signer: InMemorySigner, flags: Flags): Promise<StepResult> {
  const options = storeOptions(decodeAnchor(flags.anchor), flags);
  const store = openStore(flags.store, options);
  let controller: RotationController;
  try {
    controller = new RotationController(store);
  } catch (err) {
    closeQuietly(store, clientError(errorCode(err, "rotation_state_unknown")), flags.step);
    return clientError(errorCode(err, "rotation_state_unknown")); // unreachable: closeQuietly exits
  }
  try {
    const body = Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping"}', "utf8");
    const { snapshot } = store.snapshot();
    const clock = store.checkSnapshotClock(snapshot);
    const header = signRequest(signer, flags.aud, "POST", "/", body, randomNonce(), clock.highWater);
    const requestSig = parseRequestAuth([header]).sig;
    const res = await signedPost(flags.url, header, body);
    if (res.status >= 300 && res.status < 400) {
      closeQuietly(store, clientError("rotation_redirect_refused"), flags.step);
      return clientError("rotation_redirect_refused");
    }
    if (res.headers.get("content-encoding") !== null) {
      closeQuietly(store, clientError("rotation_result_invalid"), flags.step);
      return clientError("rotation_result_invalid");
    }
    const resBody = new Uint8Array(await res.arrayBuffer());
    if (resBody.length > MAX_BODY_BYTES) {
      closeQuietly(store, clientError("rotation_result_invalid"), flags.step);
      return clientError("rotation_result_invalid");
    }
    const authHeader = res.headers.get("jack-auth");
    const verified = controller.verifyResponse({
      status: res.status,
      headers: authHeader === null ? [] : [authHeader],
      requestSignature: requestSig,
      body: resBody,
    });
    if (res.status !== 200) {
      closeQuietly(store, { outcome: "rejected", status: res.status, code: wireCode(resBody), data: null }, flags.step);
      return { outcome: "rejected", status: res.status, code: wireCode(resBody), data: null };
    }
    const signedBy = authHeader === null ? "unknown" : (parseResponseAuth([authHeader])?.kid ?? "unknown");
    closeQuietly(store, { outcome: "ok", status: 200, code: null, data: { signed_by: signedBy } }, flags.step);
    return { outcome: "ok", status: 200, code: null, data: { signed_by: signedBy } };
  } catch (err) {
    const result = clientError(errorCode(err, "rotation_state_unknown"));
    closeQuietly(store, result, flags.step);
    return result;
  }
}

// ---------------------------------------------------------------------------
// Step: refresh (SDK explicit single-page HTTP refresh).
// ---------------------------------------------------------------------------

async function stepRefresh(signer: InMemorySigner, flags: Flags): Promise<StepResult> {
  const options = storeOptions(decodeAnchor(flags.anchor), flags);
  const store = openStore(flags.store, options);
  try {
    const http = new RotationHTTPClient(store, signer, flags.timeoutMs);
    const result = await http.refresh();
    closeQuietly(
      store,
      {
        outcome: "ok",
        status: 200,
        code: null,
        data: {
          committed: result.committed,
          head_ordinal: result.head.ordinal,
          head_hash: result.head.hash,
          terminal_ordinal: result.terminal.ordinal,
          complete: result.complete,
          revision: result.revision,
        },
      },
      flags.step,
    );
    return { outcome: "ok", status: 200, code: null, data: null }; // unreachable: closeQuietly exits
  } catch (err) {
    closeQuietly(store, clientError(errorCode(err, "rotation_state_unknown")), flags.step);
    return clientError(errorCode(err, "rotation_state_unknown"));
  }
}

// ---------------------------------------------------------------------------
// Step: wire (no store, no controller, no verification).
// ---------------------------------------------------------------------------

// --cursor is "o:h": split at the FIRST ':'; ordinal must be a decimal
// non-negative integer string.
function parseCursor(cursor: string): { ordinal: number; hash: string } {
  const colon = cursor.indexOf(":");
  if (colon <= 0) fail("--cursor must be <ordinal>:<hash>");
  const ordText = cursor.slice(0, colon);
  if (!/^\d+$/.test(ordText)) fail("--cursor ordinal must be a non-negative integer");
  const ordinal = Number(ordText);
  if (!Number.isSafeInteger(ordinal)) fail("--cursor ordinal out of range");
  return { ordinal, hash: cursor.slice(colon + 1) };
}

function wireBody(tool: string, cursor: string): Uint8Array {
  if (tool === "jack.server.key") {
    const { ordinal, hash } = parseCursor(cursor);
    return Buffer.from(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "jack.server.key", arguments: { after_ordinal: ordinal, after_hash: hash } },
      }),
      "utf8",
    );
  }
  if (tool === "ping") {
    return Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping"}', "utf8");
  }
  return fail(`unknown --tool '${tool}'`);
}

async function stepWire(signer: InMemorySigner, flags: Flags): Promise<StepResult> {
  const ts = readClock(flags.clockFile);
  const body = wireBody(flags.tool, flags.cursor);
  const header = signRequest(signer, flags.aud, "POST", "/", body, randomNonce(), ts);
  let res: Response;
  try {
    res = await fetch(flags.url, {
      method: "POST",
      headers: { "content-type": "application/json", "jack-auth": header },
      body: Buffer.from(body),
    });
  } catch {
    return clientError("rotation_request_unavailable");
  }
  if (res.status >= 200 && res.status < 300) {
    return { outcome: "ok", status: res.status, code: null, data: null };
  }
  const resBody = new Uint8Array(await res.arrayBuffer());
  return { outcome: "rejected", status: res.status, code: wireCode(resBody), data: null };
}

// ---------------------------------------------------------------------------
// Step: state (store snapshot only).
// ---------------------------------------------------------------------------

function stepState(signer: InMemorySigner, flags: Flags): StepResult {
  const options = storeOptions(decodeAnchor(flags.anchor), flags);
  const store = openStore(flags.store, options);
  try {
    const { snapshot } = store.snapshot();
    return {
      outcome: "ok",
      status: null,
      code: null,
      data: { head_ordinal: snapshot.head.ordinal, head_hash: snapshot.head.hash, revision: snapshot.revision },
    };
  } finally {
    try {
      store.close();
    } catch (err) {
      process.stderr.write(`rotation-client: store close: ${message(err)}\n`);
    }
  }
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const flags = parseFlags(process.argv.slice(2));
  const signer = new InMemorySigner(decodeSeed(flags.seedHex));
  try {
    switch (flags.step) {
      case "call":
        return void (await stepCall(signer, flags));
      case "refresh":
        return void (await stepRefresh(signer, flags));
      case "wire":
        return void emit(flags.step, await stepWire(signer, flags));
      default:
        return void emit(flags.step, stepState(signer, flags));
    }
  } catch (err) {
    fail(`unexpected error: ${message(err)}`);
  }
}

void main();
