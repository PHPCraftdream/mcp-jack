// Self-test only. Stand-in for an SDK modern_client: signs the contract's request sequences, verifies every response against the pinned key, and prints one result line. NOT a reference implementation and NOT SDK evidence.
//
// Usage:
//   node fake-modern-client.mjs --url <base-url> --aud <aud> --seed-hex <64 hex> --anchor <b64u>
//     --scenario <id> --era <legacy|modern|auto> --clock-file <file> [--probe-version <v>] [--json-id <text>]
//
// Implements interop/modern/contract.md sections 2, 4 and 5 only: the fixed
// clock, the derived nonces, the exact header order and request bytes, and one
// result line on stdout.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { b64u, deriveKeys, nonceFor, signRequest, verifyResponseHeader } from './jack-sign.mjs';

// The one endpoint the contract defines; --url is only where it lives.
const TARGET = '/mcp';
const MODERN_VERSION = '2026-07-28';
const LEGACY_VERSION = '2025-11-25';
// The protocol versions this stand-in implements, in the order the retry rule
// of contract 4.3 falls back through. ISO dates compare correctly as strings.
const IMPLEMENTED_VERSIONS = [MODERN_VERSION, LEGACY_VERSION, '2025-06-18'];
const CLIENT_INFO = { name: 'mcp-jack-interop-modern-client', version: '1.0.0' };
const EMPTY_BODY = Buffer.alloc(0);
// The only response family that may lack Jack-Auth: spec 01 section 5, 401 only,
// carrying one of these Jack envelope codes.
const UNSIGNED_401_CODES = new Set([
  'missing_auth',
  'malformed_auth',
  'unsupported_version',
  'unknown_key',
  'key_inactive',
  'timestamp_out_of_window',
  'bad_signature',
  'replayed_nonce',
]);
const REQUIRED_FLAGS = ['url', 'aud', 'seed-hex', 'anchor', 'scenario', 'era', 'clock-file'];
const OPTIONAL_FLAGS = ['probe-version', 'json-id'];
const KNOWN_FLAGS = new Set([...REQUIRED_FLAGS, ...OPTIONAL_FLAGS]);
const ERAS = new Set(['legacy', 'modern', 'auto']);

// Local step failure: the scenario cannot go on, but the last response is
// still the verdict. `client_error` additionally means no answer was trusted.
class ClientFailure extends Error {
  constructor(code, outcome = 'client_error') {
    super(code);
    this.code = code;
    this.outcome = outcome;
  }
}

// The request sequence cannot continue (an intermediate answer was not what
// the sequence needs); the last step decides the result line.
class StopScenario extends Error {}

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// Contract section 2: a startup failure is one stderr line and exit 1, with
// nothing on stdout.
function fail(message) {
  process.stderr.write(`fake-modern-client: ${message}\n`);
  process.exit(1);
}

// `--flag value` pairs only; unknown flags are usage errors rather than typos
// that silently change the run.
function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`);
    const name = arg.slice(2);
    if (!KNOWN_FLAGS.has(name)) fail(`unknown flag '${arg}'`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) fail(`flag '${arg}' needs a value`);
    flags[name] = value;
    i += 1;
  }
  for (const name of REQUIRED_FLAGS) {
    if (flags[name] === undefined) fail(`missing required flag --${name}`);
  }
  if (!ERAS.has(flags.era)) fail(`--era must be legacy, modern or auto, not '${flags.era}'`);
  return {
    url: flags.url,
    aud: flags.aud,
    seedHex: flags['seed-hex'],
    anchor: flags.anchor,
    scenario: flags.scenario,
    era: flags.era,
    clockFile: flags['clock-file'],
    probeVersion: flags['probe-version'] ?? MODERN_VERSION,
    jsonId: flags['json-id'] ?? '1',
  };
}

// Contract section 2: "now" always comes from the clock file, never the wall
// clock. Read it on every request so a stale read can never leak in.
function readClock(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    fail(`cannot read clock file: ${file}`);
  }
  const trimmed = text.trim();
  if (!/^-?\d+$/.test(trimmed)) fail(`clock file does not hold a decimal integer: ${file}`);
  return Number(trimmed);
}

function parseJson(bytes) {
  try {
    return JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    return null;
  }
}

function headerValue(headers, name) {
  const value = headers[name];
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.length === 1 ? value[0] : value.join(', ');
  return value;
}

// The parsed JSON-RPC id of a response body, null when absent or unparsable.
function responseId(json) {
  if (!isObject(json)) return null;
  return json.id === undefined ? null : json.id;
}

// Contract 4.2: an integer code only from a JSON-RPC 2.0 error object, then a
// string Jack envelope code, else null.
function wireCode(json) {
  if (!isObject(json) || !isObject(json.error)) return null;
  if (json.jsonrpc === '2.0' && Number.isInteger(json.error.code)) return json.error.code;
  if (typeof json.error.code === 'string') return json.error.code;
  return null;
}

// A recognized JSON-RPC error (contract 4.3): jsonrpc exactly "2.0", an id
// member present (null allowed) and an integer code with a string message.
function recognizedJsonRpcError(json) {
  return isObject(json)
    && json.jsonrpc === '2.0'
    && Object.prototype.hasOwnProperty.call(json, 'id')
    && isObject(json.error)
    && Number.isInteger(json.error.code)
    && typeof json.error.message === 'string';
}

// The unsigned-allowed family: a Jack envelope carrying a spec 01 code.
function unsignedAllowed(json) {
  return isObject(json)
    && isObject(json.error)
    && typeof json.error.code === 'string'
    && UNSIGNED_401_CODES.has(json.error.code);
}

// One HTTP exchange; resolves with the received status, the lowercased header
// map and the exact body bytes.
function exchange(endpoint, request) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: endpoint.host,
      port: endpoint.port,
      method: request.method,
      path: TARGET,
      // No connection reuse: one socket per request keeps the tamper proxy's
      // one-head-per-connection relay happy and the wire bytes predictable.
      agent: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    // Headers are set one at a time, in contract order (Jack-Auth first, then
    // Content-Type, then the mirrors), so neither order nor casing can drift.
    for (const [name, value] of request.headers) req.setHeader(name, value);
    if (request.body.length > 0) req.end(request.body);
    else req.end();
  });
}

// Verify one response; returns null when trusted, else the client error code.
// An absent Jack-Auth is missing_auth unless it is the unsigned 401 family.
function checkSignature(ctx, step, requestSig, body, json) {
  if (step.response_auth === null) {
    if (step.http_status === 401 && unsignedAllowed(json)) return null;
    return 'missing_auth';
  }
  return verifyResponseHeader(ctx.anchor, step.response_auth, step.http_status, requestSig, body);
}

// Send one already-signed request, record its step, verify the response and
// return what the scenario needs to continue.
async function perform(ctx, { name, jsonrpcMethod, request }) {
  const response = await exchange(ctx.endpoint, request);
  const json = parseJson(response.body);
  const step = {
    name,
    http_method: request.method,
    http_target: TARGET,
    jsonrpc_method: jsonrpcMethod,
    http_status: response.status,
    id: responseId(json),
    request_headers: request.headers.map(([headerName, value]) => [headerName, value]),
    request_body_b64u: b64u(request.body),
    request_sig: request.sig,
    response_auth: headerValue(response.headers, 'jack-auth'),
    response_content_type: headerValue(response.headers, 'content-type'),
    response_allow: headerValue(response.headers, 'allow'),
    response_session_id: headerValue(response.headers, 'mcp-session-id'),
    response_body_b64u: b64u(response.body),
  };
  // The step is recorded before verification, so a client_error still reports
  // every request that actually went out.
  ctx.steps.push(step);
  const problem = checkSignature(ctx, step, request.sig, response.body, json);
  if (problem !== null) throw new ClientFailure(problem);
  return { step, json, request, status: response.status };
}

// Sign and send a new request. The nonce index advances once per new request;
// a replay never comes through here (contract section 2).
async function send(ctx, spec) {
  const method = spec.method ?? 'POST';
  const body = spec.body ?? EMPTY_BODY;
  const timestamp = readClock(ctx.clockFile);
  const nonce = b64u(nonceFor(ctx.scenario, ctx.nonceIndex));
  ctx.nonceIndex += 1;
  const signed = signRequest(ctx.keys.priv, {
    aud: ctx.aud,
    kid: ctx.keys.kid,
    method,
    target: TARGET,
    ts: timestamp,
    nonce,
    body,
  });
  const headers = [['Jack-Auth', signed.header]];
  if (method === 'POST') headers.push(['Content-Type', 'application/json']);
  headers.push(...(spec.mirrors ?? []));
  ctx.lastEra = spec.era;
  return perform(ctx, {
    name: spec.name,
    jsonrpcMethod: spec.jsonrpcMethod ?? null,
    request: { method, headers, body, sig: signed.sig },
  });
}

// Stop the sequence when an intermediate answer is not a success; the last
// step then classifies the result line.
function requireOk(result) {
  if (!(result.status >= 200 && result.status < 300)) throw new StopScenario();
}

function metaFor(version) {
  return {
    'io.modelcontextprotocol/protocolVersion': version,
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': CLIENT_INFO,
  };
}

// The JSON-RPC id is inserted verbatim from --json-id, so bodies are rendered
// as text instead of going through JSON.stringify.
function requestBody(idText, method, params) {
  const head = `{"jsonrpc":"2.0","id":${idText},"method":${JSON.stringify(method)}`;
  if (params === undefined) return Buffer.from(`${head}}`, 'utf8');
  return Buffer.from(`${head},"params":${JSON.stringify(params)}}`, 'utf8');
}

// Mirror headers in the contract's order; a method without a source field
// carries no Mcp-Name, and only a projected argument carries Mcp-Param-*.
function modernMirrors(version, method, name, projectedRegion) {
  const mirrors = [['MCP-Protocol-Version', version], ['Mcp-Method', method]];
  if (name !== undefined) mirrors.push(['Mcp-Name', name]);
  if (projectedRegion !== undefined) mirrors.push(['Mcp-Param-Region', projectedRegion]);
  return mirrors;
}

function sendDiscover(ctx, { name, version }) {
  return send(ctx, {
    name,
    jsonrpcMethod: 'server/discover',
    era: 'modern',
    body: requestBody(ctx.jsonId, 'server/discover', { _meta: metaFor(version) }),
    mirrors: modernMirrors(version, 'server/discover'),
  });
}

function modernToolCall(ctx, { name, tool, args, version = MODERN_VERSION, idText = ctx.jsonId, mirrors }) {
  const params = { name: tool, arguments: args, _meta: metaFor(version) };
  return send(ctx, {
    name,
    jsonrpcMethod: 'tools/call',
    era: 'modern',
    body: requestBody(idText, 'tools/call', params),
    mirrors: mirrors ?? modernMirrors(version, 'tools/call', tool, args.region),
  });
}

function legacyToolCall(ctx, { name, tool, args, sessionHeaders = [] }) {
  const params = { name: tool, arguments: args };
  return send(ctx, {
    name,
    jsonrpcMethod: 'tools/call',
    era: 'legacy',
    body: requestBody(ctx.jsonId, 'tools/call', params),
    mirrors: sessionHeaders,
  });
}

// Contract 4.3 legacy fallback: initialize without any mirror header, then
// notifications/initialized carrying the negotiated version and the session.
// Returns the two session headers for the operation that follows.
async function legacyHandshake(ctx, version) {
  const initialized = await send(ctx, {
    name: 'initialize',
    jsonrpcMethod: 'initialize',
    era: 'legacy',
    body: requestBody(ctx.jsonId, 'initialize', {
      protocolVersion: version,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    }),
    mirrors: [],
  });
  requireOk(initialized);
  const negotiated = typeof initialized.json?.result?.protocolVersion === 'string'
    ? initialized.json.result.protocolVersion
    : version;
  const sessionHeaders = [['MCP-Protocol-Version', negotiated]];
  if (typeof initialized.step.response_session_id === 'string') {
    sessionHeaders.push(['Mcp-Session-Id', initialized.step.response_session_id]);
  }
  const ready = await send(ctx, {
    name: 'initialized',
    jsonrpcMethod: 'notifications/initialized',
    era: 'legacy',
    body: Buffer.from('{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}', 'utf8'),
    mirrors: sessionHeaders,
  });
  requireOk(ready);
  return sessionHeaders;
}

// Contract 4.3 era decision over the verified probe answer only.
function decideEra(result) {
  const status = result.status;
  const json = result.json;
  if (status >= 200 && status < 300) return { era: 'modern' };
  if (recognizedJsonRpcError(json)) {
    const code = json.error.code;
    if (status === 400 && (code === -32020 || code === -32021 || code === -32022)) {
      const supported = code === -32022 && isObject(json.error.data) ? json.error.data.supported : undefined;
      return { era: 'modern', refused: code, supported };
    }
    if (status === 404 && code === -32601) return { era: 'modern' };
  }
  if (status === 400 || status === 404 || status === 405) return { era: 'legacy' };
  return { era: null };
}

// Contract 4.3: the first element of data.supported that this client
// implements and that differs from the version just attempted.
function pickVersion(supported, attempted) {
  if (!Array.isArray(supported)) return null;
  if (!supported.every((value) => typeof value === 'string')) return null;
  for (const value of supported) {
    if (IMPLEMENTED_VERSIONS.includes(value) && value !== attempted) return value;
  }
  return null;
}

const isModernVersion = (version) => version >= MODERN_VERSION;

// Run the modern operation the auto scenarios settle on.
async function settledOperation(ctx, era, version, sessionHeaders) {
  if (era === 'modern') {
    await modernToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' }, version });
    return;
  }
  const headers = sessionHeaders ?? await legacyHandshake(ctx, version);
  await legacyToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' }, sessionHeaders: headers });
}

// Exactly the sequences of contract 4.4, with the step names of that table.
async function runScenario(ctx) {
  switch (ctx.scenario) {
    case 'modern-discover':
      await sendDiscover(ctx, { name: 'discover', version: MODERN_VERSION });
      return;

    case 'modern-call-projection': {
      const list = await send(ctx, {
        name: 'list',
        jsonrpcMethod: 'tools/list',
        era: 'modern',
        body: requestBody(ctx.jsonId, 'tools/list', { _meta: metaFor(MODERN_VERSION) }),
        mirrors: modernMirrors(MODERN_VERSION, 'tools/list'),
      });
      requireOk(list);
      await modernToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' } });
      return;
    }

    case 'modern-mismatch-name': {
      const first = await modernToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' } });
      // A replay is not a new request: the stored bytes, signature and headers
      // go out again unchanged (contract section 2).
      await perform(ctx, { name: 'replay', jsonrpcMethod: 'tools/call', request: first.request });
      return;
    }

    case 'modern-repeated-version':
    case 'modern-session-stripped':
      await modernToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' } });
      return;

    case 'modern-get-405':
    case 'modern-head-405': {
      const upper = ctx.scenario === 'modern-head-405';
      await send(ctx, {
        name: upper ? 'head' : 'get',
        method: upper ? 'HEAD' : 'GET',
        jsonrpcMethod: null,
        era: 'modern',
        body: EMPTY_BODY,
        mirrors: [['MCP-Protocol-Version', MODERN_VERSION]],
      });
      return;
    }

    // C9: exactly one probe decides the era, then the operation runs in it.
    case 'era-auto-modern':
    case 'era-auto-legacy': {
      const probe = await sendDiscover(ctx, { name: 'probe', version: ctx.probeVersion });
      const decision = decideEra(probe);
      if (decision.era === null) throw new ClientFailure('unsupported_version');
      await settledOperation(ctx, decision.era, decision.era === 'modern' ? MODERN_VERSION : LEGACY_VERSION);
      return;
    }

    case 'era-retry-version': {
      const probe = await sendDiscover(ctx, { name: 'probe', version: ctx.probeVersion });
      const decision = decideEra(probe);
      if (decision.refused !== -32022) {
        if (decision.era === null) throw new ClientFailure('unsupported_version');
        await settledOperation(ctx, decision.era, decision.era === 'modern' ? MODERN_VERSION : LEGACY_VERSION);
        return;
      }
      // -32022: at most one retry, with a mutually implemented version.
      const picked = pickVersion(decision.supported, ctx.probeVersion);
      if (picked === null) throw new ClientFailure('unsupported_version_no_overlap', 'rejected');
      if (!isModernVersion(picked)) {
        // A legacy pick runs the handshake at that version, then the operation.
        await settledOperation(ctx, 'legacy', picked);
        return;
      }
      const retry = await sendDiscover(ctx, { name: 'probe-retry', version: picked });
      const again = decideEra(retry);
      if (again.refused === -32022) throw new ClientFailure('unsupported_version_no_overlap', 'rejected');
      if (again.era === null) throw new ClientFailure('unsupported_version');
      await settledOperation(ctx, again.era, picked);
      return;
    }

    case 'legacy-both-parity':
      await legacyToolCall(ctx, { name: 'call', tool: 'region.echo', args: { region: 'us-west1' } });
      return;

    case 'native-era-shape': {
      // The driver passes the era the native call must be shaped for; auto is
      // not a meaningful shape here, so it is read as the modern era.
      const era = ctx.era === 'legacy' ? 'legacy' : 'modern';
      if (era === 'modern') {
        await modernToolCall(ctx, { name: 'whoami', tool: 'jack.whoami', args: {} });
      } else {
        await legacyToolCall(ctx, { name: 'whoami', tool: 'jack.whoami', args: {} });
      }
      return;
    }

    case 'refusal-id-forms': {
      const forms = [
        ['id-string', '"abc"'],
        ['id-integer', '7'],
        ['id-null', 'null'],
        ['id-fractional', '1.5'],
      ];
      for (const [name, idText] of forms) {
        // Modern mirrors minus Mcp-Name: S6 refuses every one of these.
        await modernToolCall(ctx, {
          name,
          tool: 'region.echo',
          args: { region: 'us-west1' },
          idText,
          mirrors: modernMirrors(MODERN_VERSION, 'tools/call'),
        });
      }
      return;
    }

    default:
      fail(`unsupported scenario '${ctx.scenario}'`);
  }
}

// Contract 4.2: outcome and code describe the last response, unless a local
// failure decided the run.
function buildResult(ctx, failure) {
  const last = ctx.steps.length > 0 ? ctx.steps[ctx.steps.length - 1] : null;
  let outcome;
  let httpStatus;
  let code;
  if (failure instanceof ClientFailure) {
    outcome = failure.outcome;
    code = failure.code;
    httpStatus = outcome === 'client_error' || last === null ? null : last.http_status;
  } else if (last === null) {
    outcome = 'client_error';
    httpStatus = null;
    code = null;
  } else {
    httpStatus = last.http_status;
    outcome = httpStatus >= 200 && httpStatus < 300 ? 'ok' : 'rejected';
    code = wireCode(parseJson(Buffer.from(last.response_body_b64u, 'base64url')));
  }
  return {
    scenario: ctx.scenario,
    outcome,
    http_status: httpStatus,
    code,
    data: { era: ctx.lastEra, steps: ctx.steps },
  };
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  // Read the clock once up front so an unreadable file fails before any
  // request; each request reads it again for "now".
  readClock(flags.clockFile);
  let keys;
  try {
    keys = deriveKeys(flags.seedHex);
  } catch {
    fail('--seed-hex is not a 64-character hex seed');
  }
  let endpoint;
  try {
    const parsed = new URL(flags.url);
    if (parsed.protocol !== 'http:') fail(`--url must be an http:// URL: ${flags.url}`);
    endpoint = { host: parsed.hostname, port: parsed.port === '' ? 80 : Number(parsed.port) };
  } catch {
    fail(`--url is not a valid URL: ${flags.url}`);
  }

  const ctx = {
    endpoint,
    aud: flags.aud,
    anchor: flags.anchor,
    clockFile: flags.clockFile,
    scenario: flags.scenario,
    era: flags.era,
    probeVersion: flags.probeVersion,
    jsonId: flags.jsonId,
    keys,
    nonceIndex: 0,
    lastEra: flags.era === 'legacy' ? 'legacy' : 'modern',
    steps: [],
  };

  let failure = null;
  try {
    await runScenario(ctx);
  } catch (error) {
    if (error instanceof StopScenario) {
      failure = null;
    } else if (error instanceof ClientFailure) {
      failure = error;
    } else {
      // A connection failure means the scenario could not be run at all.
      fail(error && error.message ? error.message : String(error));
    }
  }

  const result = buildResult(ctx, failure);
  // Self-test-only deviation control: when JACK_MODERN_DEVIATE names this
  // scenario, the printed result is deliberately wrong (outcome, status and
  // code) while `data` stays real, so the driver's negative control must fail
  // the run. Nothing else in the matrix is affected.
  if (process.env.JACK_MODERN_DEVIATE === ctx.scenario) {
    result.outcome = 'ok';
    result.http_status = 500;
    result.code = null;
  }
  process.stdout.write(JSON.stringify(result) + '\n', () => process.exit(0));
}

main().catch((error) => fail(error && error.message ? error.message : String(error)));
