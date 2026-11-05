// Command interop-client: every scenario of interop/scenarios.json plus
// sign-only, per interop/README.md sections 5-7, on the TypeScript client
// SDK. Exactly one JSON result line on stdout (exit 0 for a completed
// scenario, whatever its outcome); harness-level failures go to stderr with
// exit 1.
import { readFileSync } from "node:fs";
import { BadBase64UrlError, decodeBase64URL, decodeBase64URLFixed, encodeBase64URL } from "../encoding.js";
import { Code, JackError } from "../errors.js";
import { requestSigningString } from "../signing.js";
import { parseRequestAuth } from "../auth-header.js";
import { HTTPError, parseErrorBody, RPCError } from "../client/errors.js";
import { createSigningFetch, UnauthenticatedResponseError } from "../client/transport.js";
import type { SigningFetch } from "../client/transport.js";
import { randomNonce, signRequest, verifyResponse } from "../client/auth.js";
import { InMemorySigner } from "../client/signer.js";
import { Client } from "../client/rpc.js";
import { TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_SET_SCOPES, TOOL_ENROLL, TOOL_WHOAMI } from "../client/tools.js";
import { parseJsonRaw } from "../server/verify.js";

function fatal(msg: string): never {
  process.stderr.write(`interop-client: ${msg}\n`);
  process.exit(1);
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// Shared types.
// ---------------------------------------------------------------------------

// One scenario step (or the whole single-step scenario); mirrors the Go
// stepResult of interop/go/client/scenarios.go.
interface StepResult {
  kind: "ok" | "rejected" | "client_error";
  status: number; // wire status, meaningful only when hasStatus
  hasStatus: boolean; // true only when a wire response was received
  code: string; // wire code (rejected) or client-side code (client_error); "" -> null
  data?: unknown; // set only for ok and the {step} failure wrapper
}

// authFailureCodes: the only responses that may be unsigned (spec 01
// section 5): 401 answers to requests that failed authentication.
const AUTH_FAILURE_CODES: ReadonlySet<string> = new Set([
  Code.MISSING_AUTH,
  Code.MALFORMED_AUTH,
  Code.UNSUPPORTED_VERSION,
  Code.UNKNOWN_KEY,
  Code.KEY_INACTIVE,
  Code.TIMESTAMP_OUT_OF_WINDOW,
  Code.BAD_SIGNATURE,
  Code.REPLAYED_NONCE,
]);

// One identity from the seeds file (spec/fixtures/keys.json); unknown members
// of the file are ignored by design.
interface SeedEntry {
  seedHex: string;
  kid: string;
}

interface Env {
  baseURL: string;
  aud: string;
  serverKey: Uint8Array;
  args: Map<string, string>;
  seeds: Map<string, SeedEntry>;
  primary: InMemorySigner;
  primaryName: string;
  typedFetch: SigningFetch;
  clients: Map<string, Client>;
  signers: Map<string, InMemorySigner>;
}

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------

// Prints the one stdout result line and exits 0 (interop README section 5):
// http_status is null unless a wire response was received; code "" and
// absent data report as null.
function emit(scenario: string, r: StepResult): void {
  const out: { scenario: string; outcome: string; http_status: number | null; code: string | null; data: unknown } = {
    scenario,
    outcome: r.kind,
    http_status: null,
    code: null,
    data: r.data === undefined ? null : r.data,
  };
  if (r.hasStatus) out.http_status = r.status;
  if (r.code !== "") out.code = r.code;
  // Flush before exiting: stdout to a pipe is asynchronous in Node, and a
  // bare process.exit could truncate the only line the harness reads.
  process.stdout.write(JSON.stringify(out) + "\n", () => {
    process.exit(0);
  });
}

// ---------------------------------------------------------------------------
// Flags.
// ---------------------------------------------------------------------------

// ts records whether --ts was given: ts=0 is a valid sign-case value.
interface TsFlag {
  value: number;
  set: boolean;
}

interface Flags {
  url: string;
  seedHex: string;
  serverPublicKey: string;
  aud: string;
  scenario: string;
  seedsPath: string;
  ts: TsFlag;
  nonce: string;
  args: Map<string, string>;
}

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = {
    url: "",
    seedHex: "",
    serverPublicKey: "",
    aud: "",
    scenario: "",
    seedsPath: "",
    ts: { value: 0, set: false },
    nonce: "",
    args: new Map<string, string>(),
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? arg.slice(2) : arg.length > 1 && arg.startsWith("-") ? arg.slice(1) : null;
    if (name === null) fatal(`unexpected argument '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined) fatal(`--${name} requires a value`);
    i += 1;
    switch (name) {
      case "url":
        flags.url = value;
        break;
      case "seed-hex":
        flags.seedHex = value;
        break;
      case "server-public-key":
        flags.serverPublicKey = value;
        break;
      case "aud":
        flags.aud = value;
        break;
      case "scenario":
        flags.scenario = value;
        break;
      case "seeds":
        flags.seedsPath = value;
        break;
      case "ts":
        if (!/^-?\d+$/.test(value)) fatal("--ts must be an integer");
        flags.ts = { value: Number(value), set: true };
        break;
      case "nonce":
        flags.nonce = value;
        break;
      case "arg": {
        // Value may contain '='; split at the FIRST '=' only.
        const eq = value.indexOf("=");
        flags.args.set(eq < 0 ? value : value.slice(0, eq), eq < 0 ? "" : value.slice(eq + 1));
        break;
      }
      default:
        fatal(`unknown flag --${name}`);
    }
  }
  return flags;
}

// ---------------------------------------------------------------------------
// Inputs.
// ---------------------------------------------------------------------------

function decodeSeed(hex: string, what: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) fatal(`${what}: seed must be 64 hex chars decoding to 32 bytes`);
  return Buffer.from(hex.toLowerCase(), "hex");
}

function decodeServerKey(pubB64: string): Uint8Array {
  try {
    return decodeBase64URLFixed(pubB64, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) fatal("--server-public-key must decode to 32 bytes");
    throw err;
  }
}

function loadSeeds(path: string): Map<string, SeedEntry> {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    return fatal(`reading --seeds: ${message(err)}`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    return fatal(`parsing --seeds: ${message(err)}`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    fatal("parsing --seeds: not a JSON object");
  }
  const keys = (doc as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) fatal("parsing --seeds: keys must be an array");
  const out = new Map<string, SeedEntry>();
  for (const k of keys) {
    if (typeof k !== "object" || k === null) fatal("parsing --seeds: key entries must be objects");
    const rec = k as { name?: unknown; seed_hex?: unknown; kid?: unknown };
    if (typeof rec.name !== "string" || typeof rec.seed_hex !== "string" || typeof rec.kid !== "string") {
      fatal("parsing --seeds: key entries need string name, seed_hex and kid");
    }
    out.set(rec.name, { seedHex: rec.seed_hex, kid: rec.kid });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Identities and transports.
// ---------------------------------------------------------------------------

// Signer for a fixture identity name; the primary identity reuses e.primary.
function signerFor(e: Env, name: string): InMemorySigner {
  if (name === e.primaryName) return e.primary;
  const memo = e.signers.get(name);
  if (memo !== undefined) return memo;
  const entry = e.seeds.get(name);
  if (entry === undefined) fatal(`unknown identity '${name}'`);
  const signer = new InMemorySigner(decodeSeed(entry.seedHex, `identity '${name}'`));
  e.signers.set(name, signer);
  return signer;
}

// Kid of a fixture identity (revoke-key's admin step targets bob by kid).
function kidOf(e: Env, name: string): string {
  const entry = e.seeds.get(name);
  if (entry === undefined) fatal(`unknown identity '${name}'`);
  return entry.kid;
}

// Body of the latest 401 wire response. The SDK reports an unsigned 401 by
// status only, but the harness must still report the wire code (README
// section 5); the value is used for reporting, never for trust decisions.
let lastWireBody: Uint8Array = new Uint8Array(0);

const stashingFetch: typeof fetch = async (input, init) => {
  const resp = await globalThis.fetch(input, init);
  if (resp.status === 401) lastWireBody = new Uint8Array(await resp.clone().arrayBuffer());
  return resp;
};

// Memoized SDK client per identity; typed calls use these.
function typedClient(e: Env, name: string): Client {
  const memo = e.clients.get(name);
  if (memo !== undefined) return memo;
  const client = new Client({ baseUrl: e.baseURL + "/mcp", aud: e.aud, signer: signerFor(e, name), serverKey: e.serverKey, fetchImpl: stashingFetch });
  e.clients.set(name, client);
  return client;
}

// ---------------------------------------------------------------------------
// JSON-RPC bodies.
// ---------------------------------------------------------------------------

// Body builder; params carries only name when args are absent, and the ping
// body has no params member at all (Go rpcCall omitempty).
function rpcBody(tool: string, args?: Record<string, unknown>): Uint8Array {
  const text =
    tool === ""
      ? '{"jsonrpc":"2.0","id":1,"method":"ping"}'
      : `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":${
          args === undefined ? JSON.stringify({ name: tool }) : JSON.stringify({ name: tool, arguments: args })
        }}`;
  return new TextEncoder().encode(text);
}

// ---------------------------------------------------------------------------
// Raw signed path (interop README: low-level signing for replay,
// tampered-body, clock-skew, ping, echo, stream and the raw rejections).
// ---------------------------------------------------------------------------

// rawCall signs one request with a random nonce and timestamp (ts pinned for
// clock-skew), then sends it.
async function rawCall(e: Env, signer: InMemorySigner, method: string, target: string, body: Uint8Array, tsOverride?: number): Promise<StepResult> {
  const nonce = randomNonce();
  const header = signRequest(signer, e.aud, method, target, body, nonce, tsOverride ?? nowSec());
  // The request signature binds the response signing string (spec 01 section 5).
  const requestSig = parseRequestAuth([header]).sig;
  return sendWithHeader(e, header, requestSig, method, target, body);
}

// sendWithHeader sends exact pre-signed bytes and classifies the response.
async function sendWithHeader(e: Env, header: string, requestSig: string, method: string, target: string, body: Uint8Array): Promise<StepResult> {
  const headers = new Headers();
  headers.set("jack-auth", header);
  if (method === "POST") headers.set("content-type", "application/json");
  let resp: Response;
  try {
    resp = await fetch(e.baseURL + target, { method, headers, ...(method === "POST" ? { body } : {}) });
  } catch (err) {
    return fatal(`cannot connect: ${message(err)}`);
  }
  let respBody: Uint8Array;
  try {
    respBody = new Uint8Array(await resp.arrayBuffer());
  } catch (err) {
    return fatal(`reading response body: ${message(err)}`);
  }
  const status = resp.status;
  const authHeader = resp.headers.get("jack-auth");
  const authValues = authHeader === null ? [] : [authHeader];
  const wireCode = parseErrorBody(respBody).code;

  // Returns client_error when a required response signature fails.
  const verified = (): StepResult | undefined => {
    try {
      verifyResponse(e.serverKey, status, authValues, requestSig, respBody, nowSec(), 0);
      return undefined;
    } catch (err) {
      if (err instanceof JackError) return { kind: "client_error", status: 0, hasStatus: false, code: err.code };
      throw err;
    }
  };

  // 401 answers to failed authentication may be unsigned; if a header IS
  // present we still verify it and fail the client on a bad signature.
  if (status === 401 && AUTH_FAILURE_CODES.has(wireCode)) {
    if (authValues.length > 0) {
      const bad = verified();
      if (bad !== undefined) return bad;
    }
    return { kind: "rejected", status, hasStatus: true, code: wireCode };
  }
  // Everything else must carry a valid signature (spec 01 section 5).
  const bad = verified();
  if (bad !== undefined) return bad;
  if (status >= 200 && status < 300) return resultFrom2xx(respBody);
  return { kind: "rejected", status, hasStatus: true, code: wireCode };
}

// Classifies a signature-verified 2xx JSON-RPC envelope; the result member is
// kept verbatim for reported data (interop README section 5).
function resultFrom2xx(body: Uint8Array): StepResult {
  let parsed: ReturnType<typeof parseJsonRaw>;
  try {
    parsed = parseJsonRaw(new TextDecoder().decode(body));
  } catch {
    fatal("malformed json-rpc envelope: invalid JSON");
  }
  const members = parsed.source.members;
  if (members === undefined) fatal("malformed json-rpc envelope: not an object");
  const errorNode = members.get("error");
  // error: null counts as absent (Go decodes null into a nil pointer); a
  // non-object error fails the whole decode like Go's typed unmarshal.
  if (errorNode !== undefined && errorNode.text !== "null") {
    if (errorNode.members === undefined) fatal("malformed json-rpc envelope: error member is not an object");
    // The Go reference reports the RAW text of error.code with quotes
    // trimmed (bytes.Trim); a missing code member reports "".
    const errorCodeNode = errorNode.members.get("code");
    return { kind: "rejected", status: 200, hasStatus: true, code: rawCodeString(errorCodeNode === undefined ? "" : errorCodeNode.text) };
  }
  const resultNode = members.get("result");
  if (resultNode === undefined || resultNode.text === "null") {
    fatal("malformed json-rpc envelope: no result member");
  }
  return { kind: "ok", status: 200, hasStatus: true, code: "", data: resultNode.value };
}

// Go keeps the RAW text of error.code and trims quote characters.
function rawCodeString(raw: string): string {
  return raw.replace(/^"+/, "").replace(/"+$/, "");
}

// ---------------------------------------------------------------------------
// Typed path: raw envelope over the SDK's signed transport, plus SDK typed
// calls for the multi-step scenarios (Go typedRawCall / sdkStep).
// ---------------------------------------------------------------------------

// Sends one tools/call through the shared signed transport (per-identity
// signer via jackSigner) and classifies the answer, keeping the JSON-RPC
// result member verbatim for reported data. A returned response is already
// signature-verified by the transport.
async function typedRawCall(e: Env, signer: InMemorySigner, tool: string, args?: Record<string, unknown>): Promise<StepResult> {
  let resp: Response;
  try {
    resp = await e.typedFetch(e.baseURL + "/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: rpcBody(tool, args),
      jackSigner: signer,
    });
  } catch (err) {
    return classifyTransportError(err);
  }
  let respBody: Uint8Array;
  try {
    respBody = new Uint8Array(await resp.arrayBuffer());
  } catch (err) {
    return fatal(`reading response body: ${message(err)}`);
  }
  if (resp.status >= 200 && resp.status < 300) return resultFrom2xx(respBody);
  return { kind: "rejected", status: resp.status, hasStatus: true, code: parseErrorBody(respBody).code };
}

// Maps an error thrown by the signed transport: an unsigned 401 whose body
// code is one of the auth-failure codes is a wire rejection; any other
// unsigned 401 must not be acted on beyond its status (spec 01 section 5:
// absent header is missing_auth), and any other verification failure is
// client_error. Everything else is a harness-level failure.
function classifyTransportError(err: unknown): StepResult {
  if (err instanceof UnauthenticatedResponseError) {
    const code = parseErrorBody(lastWireBody).code;
    if (AUTH_FAILURE_CODES.has(code)) {
      return { kind: "rejected", status: err.status, hasStatus: true, code };
    }
    return { kind: "client_error", status: 0, hasStatus: false, code: Code.MISSING_AUTH };
  }
  if (err instanceof JackError) return { kind: "client_error", status: 0, hasStatus: false, code: err.code };
  throw err;
}

// sdkStep classifies one SDK typed call; ok keeps the typed result so
// intermediate steps can carry it (invite codes).
async function sdkStep<T>(p: Promise<T>): Promise<{ step: StepResult; value?: T }> {
  try {
    const value = await p;
    return { step: { kind: "ok", status: 200, hasStatus: true, code: "", data: value }, value };
  } catch (err) {
    return { step: classifySdkError(err) };
  }
}

function classifySdkError(err: unknown): StepResult {
  if (err instanceof HTTPError) return { kind: "rejected", status: err.status, hasStatus: true, code: err.code };
  // The SDK transport maps only an unsigned (missing_auth) 401 to
  // UnauthenticatedResponseError (status only); the code comes from the
  // harness wire stash, UNTRUSTED and used for reporting only: a 401
  // with an auth-failure code is a wire rejection; any other unsigned 401 is
  // a client-side anomaly (spec 01 section 5).
  if (err instanceof UnauthenticatedResponseError) {
    const code = parseErrorBody(lastWireBody).code;
    if (AUTH_FAILURE_CODES.has(code)) return { kind: "rejected", status: err.status, hasStatus: true, code };
    return { kind: "client_error", status: 0, hasStatus: false, code: Code.MISSING_AUTH };
  }
  if (err instanceof RPCError) return { kind: "rejected", status: 200, hasStatus: true, code: String(err.code) };
  if (err instanceof JackError) return { kind: "client_error", status: 0, hasStatus: false, code: err.code };
  throw err;
}

// Checks a step's documented expectation; undefined = continue, else the
// caller must emit the failure wrapper (Go requireIntermediate).
function requireIntermediate(idx: number, wantRejected: boolean, wantStatus: number, wantCode: string, got: StepResult): StepResult | undefined {
  const matched = wantRejected
    ? got.kind === "rejected" && got.status === wantStatus && got.code === wantCode
    : got.kind === "ok";
  if (matched) return undefined;
  const out: StepResult = { kind: "client_error", status: 0, hasStatus: false, code: "", data: { step: idx } };
  if (got.kind === "client_error") {
    out.code = got.code;
  } else {
    // A failed intermediate carries its step's wire status (README section 5).
    out.status = got.status;
    out.hasStatus = true;
    out.code = got.code;
  }
  return out;
}

// ---------------------------------------------------------------------------
// sign-only.
// ---------------------------------------------------------------------------

// Reproduces the sign-cases oracle bytes without any network I/O; ignores
// --url / --server-public-key (interop README section 5).
function runSignOnly(scenario: string, primary: InMemorySigner, aud: string, args: Map<string, string>, ts: TsFlag, nonceB64: string): void {
  const method = args.get("method") ?? "";
  const target = args.get("target") ?? "";
  if (method === "" || target === "") fatal("sign-only requires --arg method=... and --arg target=...");
  if (!ts.set) fatal("sign-only requires --ts");
  if (nonceB64 === "") fatal("sign-only requires --nonce");
  let nonce: Uint8Array;
  try {
    nonce = decodeBase64URLFixed(nonceB64, 16);
  } catch (err) {
    if (err instanceof BadBase64UrlError) fatal("--nonce must decode to 16 bytes");
    throw err;
  }
  // Empty body-b64u is valid and means an empty body.
  let body: Uint8Array;
  try {
    body = decodeBase64URL(args.get("body-b64u") ?? "");
  } catch (err) {
    if (err instanceof BadBase64UrlError) fatal("body-b64u: invalid base64url");
    throw err;
  }
  const header = signRequest(primary, aud, method, target, body, nonce, ts.value);
  emit(scenario, {
    kind: "ok",
    status: 0,
    hasStatus: false,
    code: "",
    data: {
      signing_string: requestSigningString(method, target, aud, primary.kid(), ts.value, encodeBase64URL(nonce), body),
      jack_auth: header,
      kid: primary.kid(),
    },
  });
}

// ---------------------------------------------------------------------------
// Scenarios (interop/scenarios.json; mapping mirrors
// interop/go/client/scenarios.go).
// ---------------------------------------------------------------------------

const SCENARIOS: Readonly<Record<string, (e: Env) => Promise<StepResult>>> = {
  ping: (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("")),
  echo: async (e) => {
    const text = e.args.get("text");
    if (text === undefined) fatal("echo requires --arg text=...");
    return rawCall(e, e.primary, "POST", "/mcp", rpcBody("echo", { text }));
  },
  whoami: (e) => typedRawCall(e, signerFor(e, e.primaryName), TOOL_WHOAMI),
  "denied-tool": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("svc.config.set")),
  "unmapped-tool": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("other.tool")),
  "unknown-key": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("svc.status")),
  replay: async (e) => {
    // Build the exact bytes and header ONCE; both sends reuse them. ping is
    // answered by the fixed handler (scenarios.json replay step 0); svc.status
    // would get a signed -32601 instead.
    const body = rpcBody("");
    const header = signRequest(e.primary, e.aud, "POST", "/mcp", body, randomNonce(), nowSec());
    const requestSig = parseRequestAuth([header]).sig;
    const first = await sendWithHeader(e, header, requestSig, "POST", "/mcp", body);
    const bad = requireIntermediate(0, false, 0, "", first);
    if (bad !== undefined) return bad;
    return sendWithHeader(e, header, requestSig, "POST", "/mcp", body);
  },
  "clock-skew": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("svc.status"), nowSec() - 120),
  "tampered-body": async (e) => {
    const body = rpcBody("svc.restart");
    const header = signRequest(e.primary, e.aud, "POST", "/mcp", body, randomNonce(), nowSec());
    const requestSig = parseRequestAuth([header]).sig;
    // Mutate AFTER signing: final '}' (0x7D) becomes '|' (0x7C).
    const mutated = body.slice();
    mutated[mutated.length - 1] = 0x7c;
    return sendWithHeader(e, header, requestSig, "POST", "/mcp", mutated);
  },
  // The harness pins the WRONG key (mallory) for this scenario; the signed
  // 200 answer then fails client verification.
  "bad-server-key": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("")),
  "expired-key": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("svc.status")),
  "key-not-yet-valid": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("svc.status")),
  stream: (e) => rawCall(e, e.primary, "GET", "/sse", new Uint8Array(0)),
  "agent-admin": (e) => typedRawCall(e, signerFor(e, e.primaryName), TOOL_ADMIN_USER_LIST),
  "invalid-request": (e) => rawCall(e, e.primary, "POST", "/mcp", new TextEncoder().encode("this is not JSON")),
  "unknown-native-tool": (e) => rawCall(e, e.primary, "POST", "/mcp", rpcBody("jack.admin.nuke")),
  enroll: async (e) => {
    const inv0 = await sdkStep(typedClient(e, "root").adminInviteCreate({ scopes: ["read"] }));
    const bad0 = requireIntermediate(0, false, 0, "", inv0.step);
    if (bad0 !== undefined) return bad0;
    const inv = inv0.value;
    if (inv === undefined) fatal("unreachable: a matched ok step carries its value");
    const enr1 = await sdkStep(typedClient(e, e.primaryName).enroll(inv.code, "newbie", signerFor(e, e.primaryName)));
    const bad1 = requireIntermediate(1, false, 0, "", enr1.step);
    if (bad1 !== undefined) return bad1;
    return typedRawCall(e, signerFor(e, e.primaryName), TOOL_WHOAMI);
  },
  "enroll-used-invite": async (e) => {
    const inv0 = await sdkStep(typedClient(e, "root").adminInviteCreate({ scopes: ["read"] }));
    const bad0 = requireIntermediate(0, false, 0, "", inv0.step);
    if (bad0 !== undefined) return bad0;
    const inv = inv0.value;
    if (inv === undefined) fatal("unreachable: a matched ok step carries its value");
    const enr1 = await sdkStep(typedClient(e, "newbie").enroll(inv.code, "newbie", signerFor(e, "newbie")));
    const bad1 = requireIntermediate(1, false, 0, "", enr1.step);
    if (bad1 !== undefined) return bad1;
    // Same code, signed by the primary identity (newbie2): single-use invite.
    return typedRawCall(e, signerFor(e, e.primaryName), TOOL_ENROLL, {
      code: inv.code,
      name: "newbie2",
      public_key: encodeBase64URL(signerFor(e, e.primaryName).publicKey()),
    });
  },
  rotate: async (e) => {
    const rot0 = await sdkStep(typedClient(e, e.primaryName).rotateKey(signerFor(e, "newbie")));
    const bad0 = requireIntermediate(0, false, 0, "", rot0.step);
    if (bad0 !== undefined) return bad0;
    // The old alice key must now be dead (unsigned 401 unknown_key).
    const who1 = await sdkStep(typedClient(e, e.primaryName).whoAmI());
    const bad1 = requireIntermediate(1, true, 401, Code.UNKNOWN_KEY, who1.step);
    if (bad1 !== undefined) return bad1;
    return typedRawCall(e, signerFor(e, "newbie"), TOOL_WHOAMI);
  },
  "admin-create": async (e) => {
    const inv0 = await sdkStep(typedClient(e, "root").adminInviteCreate({ scopes: ["read"] }));
    const bad0 = requireIntermediate(0, false, 0, "", inv0.step);
    if (bad0 !== undefined) return bad0;
    const inv = inv0.value;
    if (inv === undefined) fatal("unreachable: a matched ok step carries its value");
    const created1 = await sdkStep(
      typedClient(e, "root").adminUserCreate({
        name: "dave",
        publicKey: encodeBase64URL(signerFor(e, e.primaryName).publicKey()),
        scopes: ["read"],
      }),
    );
    const bad1 = requireIntermediate(1, false, 0, "", created1.step);
    if (bad1 !== undefined) return bad1;
    const enr2 = await sdkStep(typedClient(e, "newbie").enroll(inv.code, "newbie", signerFor(e, "newbie")));
    const bad2 = requireIntermediate(2, false, 0, "", enr2.step);
    if (bad2 !== undefined) return bad2;
    return typedRawCall(e, signerFor(e, e.primaryName), TOOL_WHOAMI);
  },
  "revoke-key": async (e) => {
    const rev0 = await sdkStep(typedClient(e, "root").adminUserRevoke(kidOf(e, "bob")));
    const bad0 = requireIntermediate(0, false, 0, "", rev0.step);
    if (bad0 !== undefined) return bad0;
    return typedRawCall(e, signerFor(e, e.primaryName), TOOL_WHOAMI);
  },
  "last-admin": (e) =>
    typedRawCall(e, signerFor(e, e.primaryName), TOOL_ADMIN_USER_SET_SCOPES, {
      kid: e.primary.kid(),
      scopes: ["read"],
    }),
};

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

function main(): void {
  const flags = parseFlags(process.argv.slice(2));
  if (flags.scenario === "") fatal("--scenario is required");
  if (flags.seedHex === "") fatal("--seed-hex is required");
  const primary = new InMemorySigner(decodeSeed(flags.seedHex, "--seed-hex"));
  // sign-only never touches the network and ignores --url/--server-public-key.
  if (flags.scenario === "sign-only") {
    runSignOnly(flags.scenario, primary, flags.aud, flags.args, flags.ts, flags.nonce);
    return;
  }
  if (flags.url === "") fatal("--url is required");
  if (flags.serverPublicKey === "") fatal("--server-public-key is required");
  if (flags.aud === "") fatal("--aud is required");
  if (flags.seedsPath === "") fatal("--seeds is required");
  const serverKey = decodeServerKey(flags.serverPublicKey);
  const seeds = loadSeeds(flags.seedsPath);
  let primaryName = "";
  for (const [name, entry] of seeds) {
    if (entry.seedHex.toLowerCase() === flags.seedHex.toLowerCase()) primaryName = name;
  }
  const env: Env = {
    baseURL: flags.url,
    aud: flags.aud,
    serverKey,
    args: flags.args,
    seeds,
    primary,
    primaryName,
    // One shared signed transport; per-request signer overrides (jackSigner)
    // apply on top of the default primary.
    typedFetch: createSigningFetch({ aud: flags.aud, signer: primary, serverKey }, stashingFetch),
    clients: new Map<string, Client>(),
    signers: new Map<string, InMemorySigner>(),
  };
  const run = SCENARIOS[flags.scenario];
  if (run === undefined) fatal(`unknown scenario '${flags.scenario}'`);
  run(env).then(
    (r) => emit(flags.scenario, r),
    (err) => fatal(`unexpected error: ${message(err)}`),
  );
}

main();
