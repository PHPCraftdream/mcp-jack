// The thirteen request sequences of contract 4.4, one per scenario id, in the order and with the step names the driver matches positionally. Every request goes through `Sender`; mirrors, projection and era decisions come from the SDK's modern helpers (`buildRequestMirrors`, `filterToolDefinitions`, `projectArguments`, `detectEra`), never from a local re-implementation.
import { detectEra } from "../../modern/era.js";
import type { EraDetection } from "../../modern/era.js";
import { filterToolDefinitions, projectArguments } from "../../modern/annotations.js";
import type { JsonValue } from "../../core/json-raw.js";
import {
  CLIENT_INFO,
  IMPLEMENTED_VERSIONS,
  LEGACY_VERSION,
  MODERN_VERSION,
  REGION_ECHO_SCHEMA,
  TARGET_PATH,
  b64u,
  jsonText,
  ownMember,
} from "./common.js";
import { modernMirrors, requestBody } from "./steps.js";
import type { SendSpec, Sender, SendResult } from "./steps.js";
import type { HeaderPair, Reply, Step } from "./wire.js";
import { buildResult, wireCode } from "./result.js";
import type { ResultLine, VerdictOverride } from "./result.js";

/** The definition a `Mcp-Param-*` projection may read. */
type SchemaLookup =
  | { readonly kind: "schema"; readonly schema: JsonValue }
  | { readonly kind: "none" }
  | { readonly kind: "missing" };

/** One scenario run: the requests it sent, the era of the last one and the verdict it settled on. */
export class ClientRun {
  readonly scenario: string;
  readonly configuredEra: "legacy" | "modern" | "auto";
  readonly probeVersion: string;
  readonly jsonId: string;
  readonly sender: Sender;
  readonly steps: Step[] = [];
  lastEra: "modern" | "legacy";
  lastReply: Reply | null = null;
  override: VerdictOverride | null = null;
  /** The C5-filtered `tools/list` catalog, empty until a scenario reads it. */
  tools: readonly JsonValue[] = [];
  /** True once a `tools/list` answer was read: from then on the projection uses ONLY that catalog. */
  toolsRead = false;

  constructor(
    scenario: string,
    configuredEra: "legacy" | "modern" | "auto",
    probeVersion: string,
    jsonId: string,
    sender: Sender,
  ) {
    this.scenario = scenario;
    this.configuredEra = configuredEra;
    this.probeVersion = probeVersion;
    this.jsonId = jsonId;
    this.sender = sender;
    // A legacy-only client is legacy before its first answer; anything else has to earn the switch.
    this.lastEra = configuredEra === "legacy" ? "legacy" : "modern";
  }

  /**
   * The definition a projection reads (C5/C6). Once a catalog was read only it
   * counts: a tool it does not serve is `missing`, never masked by the fixture
   * definition. Before that, the contract's fixed `region.echo` definition is
   * the only source (3.4 (d)) and any other tool has no definition to read.
   */
  schemaFor(tool: string): SchemaLookup {
    if (!this.toolsRead) {
      return tool === "region.echo" ? { kind: "schema", schema: REGION_ECHO_SCHEMA } : { kind: "none" };
    }
    const entry = this.tools.find((candidate) => ownMember(candidate, "name") === tool);
    if (entry === undefined) return { kind: "missing" };
    const schema = ownMember(entry, "inputSchema");
    return schema === undefined ? { kind: "missing" } : { kind: "schema", schema };
  }

  /** Records one finished request: its step, its reply and its era become the run's last state. */
  record(result: SendResult): void {
    this.steps.push(result.step);
    this.lastReply = result.reply;
    this.lastEra = result.era;
  }

  /**
   * Records a request that produced no HTTP answer: the step reports null
   * response members (contract 4.2) and the run stops with `client_error`, so an
   * earlier 2xx (a handshake 202, say) is never reported as the final verdict.
   */
  recordTransportFailure(spec: SendSpec): void {
    const body = new TextEncoder().encode(spec.body);
    this.steps.push({
      name: spec.name,
      http_method: spec.httpMethod,
      http_target: TARGET_PATH,
      jsonrpc_method: spec.jsonrpcMethod,
      http_status: null,
      id: null,
      request_headers: spec.headers,
      request_body_b64u: b64u(body),
      request_sig: null,
      response_auth: null,
      response_content_type: null,
      response_allow: null,
      response_session_id: null,
      response_body_b64u: "",
    });
    this.override = { outcome: "client_error", code: TRANSPORT_FAILURE };
  }

  /** The result line of this run (contract 4.2). */
  result(): ResultLine {
    return buildResult({
      scenario: this.scenario,
      era: this.lastEra,
      steps: this.steps,
      last: this.lastReply,
      override: this.override,
    });
  }
}

/** A client-side verdict that replaces the wire verdict of the last response: no implementation overlap. */
const NO_OVERLAP: VerdictOverride = { outcome: "rejected", code: "unsupported_version_no_overlap" };

/** A client-side verdict that replaces the wire verdict of the last response: no era could be settled. */
const NO_ERA: VerdictOverride = { outcome: "client_error", code: "unsupported_version" };

/** The client-side verdict of a projection the read catalog cannot describe: the request is not sent (contract 4.2). */
const CATALOG_MISSING: VerdictOverride = { outcome: "client_error", code: "projection_catalog_missing" };

/** The client-side code of a request that never got an answer after an earlier response (contract 4.2, `client_error`). */
const TRANSPORT_FAILURE = "transport_failure";

/** True for a verified 2xx reply: the only answer this matrix treats as usable (contract 4.2). */
function isOk(reply: Reply): boolean {
  return reply.trust === "verified" && reply.status !== null && reply.status >= 200 && reply.status <= 299;
}

/** Contract 4.4 `server/discover`: the mirrors of the asked-for version and a `_meta`-only params object. */
async function discoverStep(run: ClientRun, step: string, version: string): Promise<SendResult> {
  const mirrors = modernMirrors("server/discover", version);
  const body = requestBody(run.jsonId, "server/discover", jsonText({ _meta: mirrors.meta }));
  const result = await run.sender.send({
    name: step,
    jsonrpcMethod: "server/discover",
    httpMethod: "POST",
    body,
    headers: mirrors.headers,
    era: "modern",
  });
  run.record(result);
  return result;
}

/** Contract 4.4 `tools/list`: step `list`, whose answer becomes the catalog later calls project from. */
async function toolsListStep(run: ClientRun): Promise<SendResult> {
  const mirrors = modernMirrors("tools/list", MODERN_VERSION);
  const body = requestBody(run.jsonId, "tools/list", jsonText({ _meta: mirrors.meta }));
  const result = await run.sender.send({
    name: "list",
    jsonrpcMethod: "tools/list",
    httpMethod: "POST",
    body,
    headers: mirrors.headers,
    era: "modern",
  });
  run.record(result);
  if (isOk(result.reply)) {
    // C5: only the definitions that keep a valid annotation set may be called,
    // and from this answer on they are the only source the projection reads.
    run.toolsRead = true;
    const tools = ownMember(ownMember(result.reply.json, "result"), "tools");
    run.tools = Array.isArray(tools) ? filterToolDefinitions(tools) : [];
  }
  return result;
}

/** One modern `tools/call` the scenarios ask for. */
interface ModernCallSpec {
  readonly step: string;
  readonly tool: string;
  readonly args: JsonValue;
  readonly version: string;
  readonly idText: string;
  readonly withName: boolean;
}

/** Contract 4.4 modern `tools/call`: C2 mirrors, `Mcp-Name` only when the call needs it, then the C6 projection. */
async function modernCallStep(run: ClientRun, spec: ModernCallSpec): Promise<SendResult | null> {
  const params: JsonValue = { name: spec.tool, arguments: spec.args };
  const mirrors = modernMirrors("tools/call", spec.version, params);
  // S6 refuses a call whose `Mcp-Name` is missing, so the refusal scenarios drop it explicitly.
  const mirrorHeaders = spec.withName
    ? mirrors.headers
    : mirrors.headers.filter(([name]) => name.toLowerCase() !== "mcp-name");
  // C6: the projection reads the discovered definition, never a fixture one,
  // once this run has read the catalog.
  const lookup = run.schemaFor(spec.tool);
  if (lookup.kind === "missing") {
    // Nothing to project from: the request is not sent and the run stops.
    run.override = CATALOG_MISSING;
    return null;
  }
  const projected = lookup.kind === "schema" ? projectArguments(lookup.schema, spec.args) : undefined;
  if (projected !== undefined && projected.outcome === "refuse") {
    // C6: a value that does not fit its annotated type means the request is never sent.
    throw new Error("modern: " + projected.reason);
  }
  const headers: readonly HeaderPair[] = [...mirrorHeaders, ...(projected !== undefined ? projected.headers : [])];
  const body = requestBody(
    spec.idText,
    "tools/call",
    jsonText({ name: spec.tool, arguments: spec.args, _meta: mirrors.meta }),
  );
  const result = await run.sender.send({
    name: spec.step,
    jsonrpcMethod: "tools/call",
    httpMethod: "POST",
    body,
    headers,
    era: "modern",
  });
  run.record(result);
  return result;
}

/** One legacy `tools/call` the scenarios ask for. */
interface LegacyCallSpec {
  readonly step: string;
  readonly tool: string;
  readonly args: JsonValue;
  readonly idText: string;
  readonly headers: readonly HeaderPair[];
}

/** Contract 5 legacy `tools/call`: no `_meta`, no mirrors beyond the handshake headers the caller passes. */
async function legacyCallStep(run: ClientRun, spec: LegacyCallSpec): Promise<SendResult> {
  const body = requestBody(spec.idText, "tools/call", jsonText({ name: spec.tool, arguments: spec.args }));
  const result = await run.sender.send({
    name: spec.step,
    jsonrpcMethod: "tools/call",
    httpMethod: "POST",
    body,
    headers: spec.headers,
    era: "legacy",
  });
  run.record(result);
  return result;
}

/** The first non-empty value of the header `lowerName`, else null; a header name is case-insensitive. */
function headerValue(headers: readonly HeaderPair[], lowerName: string): string | null {
  for (const [name, value] of headers) {
    if (name.toLowerCase() === lowerName && value !== "") return value;
  }
  return null;
}

/** Contract 4.3 legacy handshake, step 1: `initialize` at `version` and no mirror header at all. */
async function initializeStep(run: ClientRun, version: string): Promise<SendResult> {
  const params = jsonText({
    protocolVersion: version,
    capabilities: {},
    clientInfo: { name: CLIENT_INFO.name, version: CLIENT_INFO.version },
  });
  const result = await run.sender.send({
    name: "initialize",
    jsonrpcMethod: "initialize",
    httpMethod: "POST",
    body: requestBody(run.jsonId, "initialize", params),
    headers: [],
    era: "legacy",
  });
  run.record(result);
  return result;
}

/** Contract 4.3 legacy handshake, step 2: the notification carries the negotiated version and the assigned session. */
async function initializedStep(run: ClientRun, version: string, sessionId: string | null): Promise<SendResult> {
  const headers: HeaderPair[] = [["MCP-Protocol-Version", version]];
  if (sessionId !== null) headers.push(["Mcp-Session-Id", sessionId]);
  const result = await run.sender.send({
    name: "initialized",
    jsonrpcMethod: "notifications/initialized",
    httpMethod: "POST",
    body: '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
    headers,
    era: "legacy",
  });
  run.record(result);
  return result;
}

/** Contract 4.3: initialize then initialized; null when either answer is not a verified 2xx. */
async function handshake(run: ClientRun, version: string): Promise<readonly HeaderPair[] | null> {
  const init = await initializeStep(run, version);
  if (!isOk(init.reply)) return null;
  // The server may answer with the version it settled on: every later header uses that one.
  const negotiatedVersion = ownMember(ownMember(init.reply.json, "result"), "protocolVersion");
  const negotiated = typeof negotiatedVersion === "string" ? negotiatedVersion : version;
  const sessionId = headerValue(init.reply.headers, "mcp-session-id");
  if (!isOk((await initializedStep(run, negotiated, sessionId)).reply)) return null;
  const headers: HeaderPair[] = [["MCP-Protocol-Version", negotiated]];
  if (sessionId !== null) headers.push(["Mcp-Session-Id", sessionId]);
  return headers;
}

/** Contract 4.4: the `region.echo` operation in the era the run settled on. */
async function settledOperation(run: ClientRun, era: "legacy" | "modern", version: string): Promise<void> {
  if (era === "modern") {
    await modernCallStep(run, {
      step: "call",
      tool: "region.echo",
      args: { region: "us-west1" },
      version,
      idText: run.jsonId,
      withName: true,
    });
    return;
  }
  const headers = await handshake(run, version);
  // A refused handshake stops the run: the operation is never sent without its headers.
  if (headers === null) return;
  await legacyCallStep(run, {
    step: "call",
    tool: "region.echo",
    args: { region: "us-west1" },
    idText: run.jsonId,
    headers,
  });
}

/** C9 era detection over one recorded reply: an untrusted or answerless reply carries no era signal. */
function detectionOf(reply: Reply): EraDetection {
  const status = reply.status;
  if (reply.trust === "verified" && status !== null) {
    return detectEra(
      { verified: true, status, ...(reply.text !== "" ? { bodyText: reply.text } : {}) },
      IMPLEMENTED_VERSIONS,
    );
  }
  return detectEra({ verified: false, status: 0 }, IMPLEMENTED_VERSIONS);
}

/** The era a C9 probe settled, or the verdict the run must stop on (contract 4.3). */
interface Negotiation {
  readonly era: "legacy" | "modern" | null;
  readonly version: string;
  readonly override: VerdictOverride | null;
}

/** The client code of a probe the client could not trust: the signed-reply failure or the unsigned-401 family code. */
function untrustedCode(reply: Reply): string {
  if (reply.clientCode !== null) return reply.clientCode;
  const code = wireCode(reply.json);
  return typeof code === "string" ? code : "missing_auth";
}

/**
 * Contract 4.3 over the low-level probe and its single retry. A reply the client
 * could not trust selects no era at all (the operation is never sent), and
 * `unsupported_version_no_overlap` is reserved for a VERIFIED `-32022` with no
 * usable overlap or for a retry answered `-32022` again.
 */
async function negotiate(run: ClientRun): Promise<Negotiation> {
  const probe = await discoverStep(run, "probe", run.probeVersion);
  // Unverified, unsigned (outside the allowed 401 family), malformed or
  // network-failed: no era, and the operation is not sent.
  if (probe.reply.trust !== "verified") {
    return { era: null, version: "", override: { outcome: "client_error", code: untrustedCode(probe.reply) } };
  }
  const first = detectionOf(probe.reply);
  if (first.action === "retry_with_supported") {
    // Contract 4.3: the first implemented version other than the one just attempted.
    const picked = first.supported?.find((version) => version !== run.probeVersion) ?? null;
    if (picked === null) return { era: null, version: "", override: NO_OVERLAP };
    if (picked < MODERN_VERSION) return { era: "legacy", version: picked, override: null };
    const retry = await discoverStep(run, "probe-retry", picked);
    if (retry.reply.trust !== "verified") {
      return { era: null, version: "", override: { outcome: "client_error", code: untrustedCode(retry.reply) } };
    }
    const second = detectionOf(retry.reply);
    // The one allowed retry was answered -32022 again: there is never a second retry.
    if (second.action === "retry_with_supported") return { era: null, version: "", override: NO_OVERLAP };
    // A verified reply with no era signal fails the operation (contract 4.3 table).
    if (second.era === "none") return { era: null, version: "", override: NO_ERA };
    // The only remaining abort is a verified -32022 with no usable overlap.
    if (second.action === "abort") return { era: null, version: "", override: NO_OVERLAP };
    return { era: second.era, version: picked, override: null };
  }
  if (first.era === "none" || first.action === "abort") {
    return {
      era: null,
      version: "",
      override: first.reason === "unsupported_version_no_overlap" ? NO_OVERLAP : NO_ERA,
    };
  }
  return { era: first.era, version: first.era === "modern" ? run.probeVersion : LEGACY_VERSION, override: null };
}

/** Runs the fixed request sequence of `run.scenario` (contract 4.4). */
export async function runScenario(run: ClientRun): Promise<void> {
  switch (run.scenario) {
    case "modern-discover": {
      await discoverStep(run, "discover", MODERN_VERSION);
      return;
    }
    case "modern-call-projection": {
      const list = await toolsListStep(run);
      // A refused catalog leaves nothing the projection could read.
      if (!isOk(list.reply)) return;
      await modernCallStep(run, {
        step: "call",
        tool: "region.echo",
        args: { region: "us-west1" },
        version: MODERN_VERSION,
        idText: run.jsonId,
        withName: true,
      });
      return;
    }
    case "modern-mismatch-name": {
      const call = await modernCallStep(run, {
        step: "call",
        tool: "region.echo",
        args: { region: "us-west1" },
        version: MODERN_VERSION,
        idText: run.jsonId,
        withName: true,
      });
      if (call === null) return;
      // Contract 2: the replay resends the very bytes the first step signed, so the nonce is spent twice.
      const replay = await run.sender.replay(
        { name: "replay", jsonrpcMethod: "tools/call", httpMethod: "POST", body: "", headers: [], era: "modern" },
        call.capture.request,
        call.step.request_sig,
      );
      run.record(replay);
      return;
    }
    case "modern-repeated-version":
    case "modern-session-stripped": {
      // Both rows are the single plain call; the proxy is what differs between them.
      await modernCallStep(run, {
        step: "call",
        tool: "region.echo",
        args: { region: "us-west1" },
        version: MODERN_VERSION,
        idText: run.jsonId,
        withName: true,
      });
      return;
    }
    case "modern-get-405":
    case "modern-head-405": {
      // S2: a body-less GET or HEAD is signed over the empty bytes and only carries the version mirror.
      const httpMethod = run.scenario === "modern-get-405" ? "GET" : "HEAD";
      const result = await run.sender.send({
        name: run.scenario === "modern-get-405" ? "get" : "head",
        jsonrpcMethod: null,
        httpMethod,
        body: "",
        headers: [["MCP-Protocol-Version", MODERN_VERSION]],
        era: "modern",
      });
      run.record(result);
      return;
    }
    case "era-auto-modern":
    case "era-auto-legacy":
    case "era-retry-version": {
      // Every C9 row drives the same low-level flow: one probe at --probe-version,
      // at most one retry, then the operation in the era that was settled
      // (contract 4.3). Only the server's answers differ between the rows.
      const negotiation = await negotiate(run);
      if (negotiation.override !== null) {
        run.override = negotiation.override;
        return;
      }
      if (negotiation.era === null) return;
      await settledOperation(run, negotiation.era, negotiation.version);
      return;
    }
    case "legacy-both-parity": {
      await legacyCallStep(run, {
        step: "call",
        tool: "region.echo",
        args: { region: "us-west1" },
        idText: run.jsonId,
        headers: [],
      });
      return;
    }
    case "native-era-shape": {
      // The era flag decides the shape; only `legacy` is byte-identical to 0.1.x.
      const era = run.configuredEra === "legacy" ? "legacy" : "modern";
      if (era === "modern") {
        await modernCallStep(run, {
          step: "whoami",
          tool: "jack.whoami",
          args: {},
          version: MODERN_VERSION,
          idText: run.jsonId,
          withName: true,
        });
        return;
      }
      await legacyCallStep(run, { step: "whoami", tool: "jack.whoami", args: {}, idText: run.jsonId, headers: [] });
      return;
    }
    case "refusal-id-forms": {
      // The four id texts go in verbatim, and every request omits `Mcp-Name`, which is what S6 refuses.
      const forms: readonly (readonly [string, string])[] = [
        ["id-string", '"abc"'],
        ["id-integer", "7"],
        ["id-null", "null"],
        ["id-fractional", "1.5"],
      ];
      for (const [step, idText] of forms) {
        await modernCallStep(run, {
          step,
          tool: "region.echo",
          args: { region: "us-west1" },
          version: MODERN_VERSION,
          idText,
          withName: false,
        });
      }
      return;
    }
    default:
      throw new Error("modern: unsupported scenario " + JSON.stringify(run.scenario));
  }
}
