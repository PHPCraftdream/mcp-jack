// Command interop-server: the interop-server contract of interop/README.md
// section 4, built on the TypeScript server SDK. Exactly one stdout line is
// ever written: the ready line in serve mode or the --verify-only verdict;
// every diagnostic goes to stderr.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { BadBase64UrlError, decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../encoding.js";
import { verify as verifyEd25519 } from "../ed25519.js";
import { Code, JackError } from "../errors.js";
import { requestSigningString } from "../signing.js";
import { parseRequestAuth } from "../auth-header.js";
import type { RequestAuth } from "../auth-header.js";
import { InMemorySigner } from "../client/signer.js";
import { jackFetchHandler } from "../server/fetch.js";
import { bootstrapAdmin, Native } from "../server/native.js";
import { NonceStore } from "../server/nonce.js";
import { parsePolicy } from "../server/policy.js";
import type { Policy } from "../server/policy.js";
import { openFileState } from "../server/state-file.js";
import type { FileState } from "../server/state-file.js";
import { parseJsonRaw, Verifier } from "../server/verify.js";
import type { RawJsonNode } from "../server/verify.js";
import { serveNode } from "../server/node.js";

function fail(msg: string): never {
  process.stderr.write(`interop-server: ${msg}\n`);
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
  policyPath: string;
  statePath: string;
  serverSeedHex: string;
  bootstrapTtl: string;
  verifyOnly: boolean;
}

const VALUE_FLAGS: ReadonlySet<string> = new Set(["aud", "policy", "state", "server-seed-hex", "bootstrap-ttl"]);

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = { aud: "", policyPath: "", statePath: "", serverSeedHex: "", bootstrapTtl: "", verifyOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : arg.length > 1 && arg.startsWith("-") ? arg.slice(1) : null;
    if (name === null) fail(`unexpected argument '${arg}'`);
    if (name === "verify-only") {
      flags.verifyOnly = true;
      continue;
    }
    if (!VALUE_FLAGS.has(name)) fail(`unknown flag --${name}`);
    const value = argv[i + 1];
    if (value === undefined) fail(`--${name} requires a value`);
    i += 1;
    if (name === "aud") flags.aud = value;
    else if (name === "policy") flags.policyPath = value;
    else if (name === "state") flags.statePath = value;
    else if (name === "server-seed-hex") flags.serverSeedHex = value;
    else flags.bootstrapTtl = value;
  }
  return flags;
}

function decodeSeed(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    fail("--server-seed-hex must be 64 hex chars (32 bytes)");
  }
  return Buffer.from(hex.toLowerCase(), "hex");
}

// ---------------------------------------------------------------------------
// Startup inputs.
// ---------------------------------------------------------------------------

function loadState(path: string): FileState {
  try {
    return openFileState(path);
  } catch (err) {
    return fail(`state file: ${message(err)}`);
  }
}

function loadPolicy(path: string): Policy {
  let data: Buffer;
  try {
    data = readFileSync(path);
  } catch (err) {
    return fail(`policy file: ${message(err)}`);
  }
  try {
    return parsePolicy(data);
  } catch (err) {
    return fail(`policy file: ${message(err)}`);
  }
}

// ---------------------------------------------------------------------------
// --verify-only.
// ---------------------------------------------------------------------------

interface VerifyInput {
  method: string;
  target: string;
  jackAuth: string;
  bodyB64U: string;
}

// Reads all of stdin; the harness writes exactly one JSON object.
async function readVerifyInput(): Promise<VerifyInput> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : (chunk as Buffer));
  }
  let doc: unknown;
  try {
    doc = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (err) {
    return fail(`stdin: ${message(err)}`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    return fail("stdin: not a JSON object");
  }
  const rec = doc as { readonly [key: string]: unknown };
  const str = (key: string): string => {
    const v = rec[key];
    return typeof v === "string" ? v : "";
  };
  return {
    method: str("method"),
    target: str("target"),
    jackAuth: str("jack_auth"),
    bodyB64U: str("body_b64u"),
  };
}

function decodeBody(b64: string): Uint8Array {
  try {
    return decodeBase64URL(b64);
  } catch (err) {
    if (err instanceof BadBase64UrlError) return fail("body_b64u: invalid base64url");
    throw err;
  }
}

type Verdict = { verify: "accept"; kid: string } | { verify: "reject"; code: string };

// Writes the single verdict line and exits 0 (either verdict, Go parity).
function printVerdict(v: Verdict): void {
  process.stdout.write(JSON.stringify(v) + "\n", () => {
    process.exit(0);
  });
}

// --verify-only: request-auth steps 1-4 and 7 of spec 01 section 4; steps
// 5/6/8 (validity, window, nonce) are skipped because the sign cases pin ts
// values 0 and 999999999999.
async function runVerifyOnly(aud: string, state: FileState): Promise<void> {
  const input = await readVerifyInput();
  const body = decodeBody(input.bodyB64U);

  // Steps 1-3 of spec 01 section 4: header grammar and version.
  let auth: RequestAuth;
  try {
    auth = parseRequestAuth([input.jackAuth]);
  } catch (err) {
    if (err instanceof JackError) {
      printVerdict({ verify: "reject", code: err.code });
      return;
    }
    throw err;
  }
  // Step 4: kid lookup in the state file.
  const entry = state.lookup(auth.kid);
  if (entry === undefined) {
    printVerdict({ verify: "reject", code: Code.UNKNOWN_KEY });
    return;
  }
  let pub: Uint8Array;
  try {
    pub = decodeBase64URLFixed(entry.publicKey, 32);
  } catch (err) {
    // Unreachable: the state loader validated every entry's public key.
    if (err instanceof BadBase64UrlError) return fail("registry public key: invalid base64url");
    throw err;
  }
  let sig: Uint8Array;
  try {
    sig = decodeBase64URLFixed(auth.sig, 64);
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      printVerdict({ verify: "reject", code: Code.BAD_SIGNATURE });
      return;
    }
    throw err;
  }
  // Step 7: strict Ed25519 over the canonical signing string.
  const signing = requestSigningString(input.method, input.target, aud, auth.kid, auth.ts, auth.nonce, body);
  const accepted = verifyEd25519(pub, new TextEncoder().encode(signing), sig);
  printVerdict(accepted ? { verify: "accept", kid: auth.kid } : { verify: "reject", code: Code.BAD_SIGNATURE });
}

// ---------------------------------------------------------------------------
// The fixed trivial MCP handler (interop README section 4). It only ever sees
// authorized requests; the wrapper signs every answer.
// ---------------------------------------------------------------------------

async function mcpHandler(req: Request): Promise<Response> {
  if (req.method === "GET") {
    if (new URL(req.url).pathname === "/sse") {
      // Finite SSE answer; the wrapper refuses the event-stream answer on
      // its header and replies with the signed 501 streaming_unsupported.
      return new Response("data: hello\n\n", { headers: { "content-type": "text/event-stream" } });
    }
    // Any other signed GET: answered, then signed by the wrapper.
    return jsonBody('{"jsonrpc":"2.0","id":null,"result":{}}');
  }
  const body = new Uint8Array(await req.arrayBuffer());
  return answerRpc(body);
}

function answerRpc(body: Uint8Array): Response {
  let parsed: ReturnType<typeof parseJsonRaw>;
  try {
    parsed = parseJsonRaw(new TextDecoder().decode(body));
  } catch {
    return jsonBody(envelopeError("null")); // unreachable: the verifier rejected unparseable bodies
  }
  const members = parsed.source.members;
  if (members === undefined) return jsonBody(envelopeError("null"));
  const idNode = members.get("id");
  // Absent id answers as null (Go json.RawMessage nil marshals as null).
  const idText = idNode === undefined ? "null" : idNode.text;
  const methodNode = members.get("method");
  if (methodNode === undefined || typeof methodNode.value !== "string") {
    return jsonBody(envelopeError(idText));
  }
  switch (methodNode.value) {
    case "ping":
      return jsonBody(envelopeResult(idText, "{}"));
    case "tools/list":
      return jsonBody(envelopeResult(idText, '{"tools":[{"name":"echo"}]}'));
    case "tools/call":
      return answerToolCall(members, idText);
    default:
      return jsonBody(envelopeError(idText));
  }
}

function answerToolCall(members: ReadonlyMap<string, RawJsonNode>, idText: string): Response {
  const paramsMembers = members.get("params")?.members;
  const nameNode = paramsMembers?.get("name");
  if (nameNode === undefined || typeof nameNode.value !== "string") {
    return jsonBody(envelopeError(idText));
  }
  switch (nameNode.value) {
    case "echo": {
      const textNode = paramsMembers?.get("arguments")?.members?.get("text");
      if (textNode === undefined || typeof textNode.value !== "string") {
        return jsonBody(envelopeError(idText));
      }
      return jsonBody(envelopeResult(idText, `{"content":[{"type":"text","text":${JSON.stringify(textNode.value)}}]}`));
    }
    case "logs.tail":
    case "config.set":
      // Unmapped by the harness policy, so both answer 403 before reaching
      // here; kept per contract.
      return jsonBody(envelopeResult(idText, '{"content":[{"type":"text","text":"ok"}]}'));
    default:
      return jsonBody(envelopeError(idText));
  }
}

// Envelopes are composed by string so the field order and the RAW id text
// mirror Go's json.RawMessage marshaling exactly.
function envelopeResult(idText: string, resultJson: string): string {
  return `{"jsonrpc":"2.0","id":${idText},"result":${resultJson}}`;
}

function envelopeError(idText: string): string {
  return `{"jsonrpc":"2.0","id":${idText},"error":{"code":-32601,"message":"method not found"}}`;
}

function jsonBody(text: string): Response {
  return new Response(text, { headers: { "content-type": "application/json" } });
}

// ---------------------------------------------------------------------------
// Serve mode.
// ---------------------------------------------------------------------------

function createBootstrapInvite(state: FileState, ttlText: string): string {
  if (!/^\d+$/.test(ttlText)) {
    fail("--bootstrap-ttl must be an integer number of seconds");
  }
  try {
    return bootstrapAdmin(state, Math.floor(Date.now() / 1000), Number(ttlText));
  } catch (err) {
    return fail(`--bootstrap-ttl: ${message(err)}`);
  }
}

function serve(flags: Flags, seed: Uint8Array, state: FileState, policy: Policy, signer: InMemorySigner): void {
  const nowSec = (): number => Math.floor(Date.now() / 1000);
  if (flags.bootstrapTtl !== "") {
    // Printed on stderr; the harness never uses the bootstrap invite.
    process.stderr.write(JSON.stringify({ bootstrap_invite: createBootstrapInvite(state, flags.bootstrapTtl) }) + "\n");
  }
  // No window override: the contract pins the spec default (30 s).
  const verifier = new Verifier({
    aud: flags.aud,
    state,
    nonces: new NonceStore(),
    policy,
    native: new Native(),
    now: nowSec,
  });
  const handler = jackFetchHandler({ verifier, serverKey: seed }, mcpHandler);
  const server = createServer(serveNode(handler));
  server.on("error", (err: Error) => fail(`listen: ${err.message}`));
  server.listen(0, "127.0.0.1", () => {
    const addr = server.address();
    const port = addr !== null && typeof addr === "object" ? addr.port : 0;
    if (port <= 0) fail("listen: cannot determine the bound port");
    // The ready line is the first and only stdout output of serve mode.
    process.stdout.write(
      JSON.stringify({ ready: true, port, server_public_key: encodeBase64URL(signer.publicKey()), server_kid: signer.kid() }) + "\n",
    );
  });
  // Exit 0 on SIGTERM/SIGINT or stdin EOF (the harness closes stdin to stop
  // the server; the fake reference server does the same).
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

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

function main(): void {
  const flags = parseFlags(process.argv.slice(2));
  if (flags.aud === "" || flags.policyPath === "" || flags.statePath === "" || flags.serverSeedHex === "") {
    fail("--aud, --policy, --state and --server-seed-hex are required");
  }
  const seed = decodeSeed(flags.serverSeedHex);
  const signer = new InMemorySigner(seed); // deterministic server key from the seed
  const state = loadState(flags.statePath);
  const policy = loadPolicy(flags.policyPath);
  if (flags.verifyOnly) {
    void runVerifyOnly(flags.aud, state).catch((err) => fail(`unexpected error: ${message(err)}`));
    return;
  }
  serve(flags, seed, state, policy, signer);
}

main();
