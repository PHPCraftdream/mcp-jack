// Self-test only. Stand-in for an SDK modern_server: authenticates v1 requests, applies the modern-era rules of spec 04 while the profile says so, answers the contract handler, signs every response. NOT a reference implementation.
//
// Usage:
//   node fake-modern-server.mjs --profile <legacy|modern|both> --aud <aud> --state <file>
//     --server-seed-hex <64 hex> --clock-file <file> --port <n> [--request-log <file>]
//     [--supported-versions <v1,v2,...>] [--discover-version-mode <supported|refuse-first|refuse-always>]
//
// stdout carries exactly one ready line and nothing else; diagnostics go to
// stderr; the fixed clock file is the only source of "now".
import http from 'node:http';
import { appendFileSync, readFileSync } from 'node:fs';
import {
  deriveKeys,
  isFieldValue,
  parseRequestAuth,
  sentinelDecode,
  signResponseHeader,
  verifyRequest,
  wellFormedVersion,
} from './jack-sign.mjs';

// interop/modern/contract.md 4.2: request bodies are bounded before hashing.
const MAX_BODY_BYTES = 1024 * 1024;
// spec 01 section 4 step 6: the default freshness window is 30 seconds.
const FRESHNESS_WINDOW_SECONDS = 30;
// spec 04 section 2: the first modern-era version.
const MODERN_MIN = '2026-07-28';
// spec 04 section 1: the two _meta member names the server validates.
const PROTOCOL_VERSION_META = 'io.modelcontextprotocol/protocolVersion';
const SERVER_INFO_META = 'io.modelcontextprotocol/serverInfo';
const SERVER_NAME = 'mcp-jack-interop-modern';
const SERVER_VERSION = '1.0.0';
const NATIVE_SERVER_INFO = { name: 'mcp-jack', version: '0.2.0' };
// spec 04 section 5 S1: the three mirror headers with at most one instance.
const SINGLE_INSTANCE_HEADERS = ['mcp-protocol-version', 'mcp-method', 'mcp-name'];
const MCP_PARAM_PREFIX = 'mcp-param-';
// spec 04 section 5 S8: session headers removed in the modern era.
const SESSION_HEADERS = ['mcp-session-id', 'last-event-id'];
// spec 04 section 5 S6: the source field per method, exactly as tabulated.
const NAME_SOURCES = new Map([
  ['tools/call', 'name'],
  ['prompts/get', 'name'],
  ['events/poll', 'name'],
  ['events/stream', 'name'],
  ['events/subscribe', 'name'],
  ['events/unsubscribe', 'name'],
  ['resources/read', 'uri'],
]);

// spec 04 section 5.1: the closed reason table. Messages are verbatim.
const REASONS = {
  method_not_allowed: { status: 405, code: -32600, message: 'HTTP method not allowed', id: null },
  header_value_invalid: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax',
  },
  header_repeated: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: a request metadata header appears more than once',
  },
  version_header_missing: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version is missing',
  },
  version_header_malformed: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version is malformed',
  },
  version_meta_missing: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: params._meta protocolVersion is missing',
  },
  version_mismatch: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion',
  },
  method_header_missing: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Method is missing',
  },
  method_header_mismatch: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Method does not match the body method',
  },
  name_header_not_applicable: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Name is not defined for this method',
  },
  name_source_missing: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: the body has no string value for the Mcp-Name source field',
  },
  name_header_missing: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Name is missing',
  },
  name_header_bad_encoding: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Name is not a valid base64 sentinel encoding',
  },
  name_header_mismatch: {
    status: 400,
    code: -32020,
    message: 'Header mismatch: Mcp-Name does not match the body value',
  },
};

// interop/tools/fakes/fake-server.mjs style: every `--flag value` pair becomes
// a member; a flag without a value becomes `true`.
function parseArgs(argv) {
  const out = {};
  const hasValue = (i) => i < argv.length && !argv[i].startsWith('--');
  for (let i = 0; i < argv.length; i += 1) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    if (hasValue(i + 1)) {
      out[key] = argv[i + 1];
      i += 1;
    } else {
      out[key] = true;
    }
  }
  return out;
}

const lower = (name) => name.toLowerCase();

// The received header list as [name, value] pairs, preserving wire order,
// repetition and casing (spec 04 section 5 S9).
function receivedHeaders(rawHeaders) {
  const pairs = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) pairs.push([rawHeaders[i], rawHeaders[i + 1]]);
  return pairs;
}

function instances(headers, lname) {
  return headers.filter(([name]) => lower(name) === lname).map(([, value]) => value);
}

function firstValue(headers, lname) {
  const values = instances(headers, lname);
  return values.length === 0 ? null : values[0];
}

const json = (value) => Buffer.from(JSON.stringify(value), 'utf8');

// spec 04 section 5 S10: a refusal echoes a string or integer id and is null
// for a null, fractional, missing or unusable id.
function refusalId(rpc) {
  if (rpc === null || typeof rpc !== 'object' || Array.isArray(rpc)) return null;
  if (!Object.prototype.hasOwnProperty.call(rpc, 'id')) return null;
  const id = rpc.id;
  if (typeof id === 'string') return id;
  if (typeof id === 'number' && Number.isInteger(id)) return id;
  return null;
}

// interop/modern/contract.md 3.4: the handler answers with the request's id
// echo, null when the body carried none.
function idEcho(rpc) {
  return rpc !== null && typeof rpc === 'object' && !Array.isArray(rpc) ? rpc.id ?? null : null;
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// spec 04 section 5 S3: under profile `both` any modern protocol-version
// signal selects the modern era, from the header instances or the signed body.
function decideEra(profile, rpc, headers) {
  if (profile === 'legacy') return 'legacy';
  if (profile === 'modern') return 'modern';
  const headerVersions = instances(headers, 'mcp-protocol-version');
  if (headerVersions.some((value) => wellFormedVersion(value) && value >= MODERN_MIN)) return 'modern';
  if (typeof rpc?.method === 'string') {
    const meta = isObject(rpc.params) ? rpc.params._meta : null;
    const metaVersion = isObject(meta) ? meta[PROTOCOL_VERSION_META] : null;
    if (wellFormedVersion(metaVersion) && metaVersion >= MODERN_MIN) return 'modern';
  }
  return 'legacy';
}

// spec 04 section 5 S1: the three mirrors and every recognised Mcp-Param-*
// name (the bare prefix is not a parameter header).
function isRequestMetadataHeader(lname) {
  if (SINGLE_INSTANCE_HEADERS.includes(lname)) return true;
  return lname.startsWith(MCP_PARAM_PREFIX) && lname.length > MCP_PARAM_PREFIX.length;
}

// spec 04 section 5 S1, S2, S4, S5 and S6, in that order. Returns a reason
// descriptor or null when the request may be forwarded.
function modernRefusal(req, rpc, headers, skipS1Repeat) {
  if (!skipS1Repeat) {
    for (const lname of SINGLE_INSTANCE_HEADERS) {
      if (instances(headers, lname).length > 1) return REASONS.header_repeated;
    }
  }
  for (const [name, value] of headers) {
    if (isRequestMetadataHeader(lower(name)) && !isFieldValue(value)) return REASONS.header_value_invalid;
  }
  // spec 04 section 5 S2: anything but POST is a signed 405 with Allow: POST.
  if (req.method !== 'POST') return REASONS.method_not_allowed;
  // spec 04 section 5 S12: a client-sent response object has no method, so it
  // has no mirror obligation; it is forwarded after S1 and S8.
  if (typeof rpc.method !== 'string') return null;
  const versionValues = instances(headers, 'mcp-protocol-version');
  const isNotification = !Object.prototype.hasOwnProperty.call(rpc, 'id');
  // spec 04 section 5 S4 (S11 for notifications: no requirement unless the
  // header is present, and then the _meta version is required and equal).
  if (!isNotification || versionValues.length > 0) {
    if (versionValues.length === 0) return REASONS.version_header_missing;
    if (!wellFormedVersion(versionValues[0])) return REASONS.version_header_malformed;
    const meta = isObject(rpc.params) ? rpc.params._meta : null;
    const metaVersion = isObject(meta) ? meta[PROTOCOL_VERSION_META] : null;
    if (typeof metaVersion !== 'string') return REASONS.version_meta_missing;
    if (metaVersion !== versionValues[0]) return REASONS.version_mismatch;
  }
  // spec 04 section 5 S5.
  const methodHeader = firstValue(headers, 'mcp-method');
  if (methodHeader === null) return REASONS.method_header_missing;
  if (methodHeader !== rpc.method) return REASONS.method_header_mismatch;
  // spec 04 section 5 S6, rows 1-5 in order.
  const nameHeader = firstValue(headers, 'mcp-name');
  const source = NAME_SOURCES.get(rpc.method) ?? null;
  if (source === null) {
    if (nameHeader !== null) return REASONS.name_header_not_applicable;
    return null;
  }
  const params = isObject(rpc.params) ? rpc.params : null;
  const sourceValue = params === null ? undefined : params[source];
  if (typeof sourceValue !== 'string') return REASONS.name_source_missing;
  if (nameHeader === null) return REASONS.name_header_missing;
  const decoded = sentinelDecode(nameHeader);
  if (decoded === null) return REASONS.name_header_bad_encoding;
  if (decoded !== sourceValue) return REASONS.name_header_mismatch;
  return null;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const fail = (message) => {
    process.stderr.write(message + '\n');
    process.exit(1);
  };

  for (const flag of ['profile', 'aud', 'state', 'server-seed-hex', 'clock-file', 'port']) {
    if (!args[flag] || args[flag] === true) fail(`missing required --${flag}`);
  }
  const profile = args.profile;
  if (!['legacy', 'modern', 'both'].includes(profile)) fail(`unknown --profile ${profile}`);
  const discoverVersionMode = args['discover-version-mode'] ?? 'supported';
  if (!['supported', 'refuse-first', 'refuse-always'].includes(discoverVersionMode)) {
    fail(`unknown --discover-version-mode ${discoverVersionMode}`);
  }
  const seedHex = args['server-seed-hex'];
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) fail('--server-seed-hex must be 64 hex characters');
  const aud = args.aud;
  const clockFile = args['clock-file'];
  const requestLog = typeof args['request-log'] === 'string' && args['request-log'].length > 0
    ? args['request-log']
    : null;
  const supportedVersions = (typeof args['supported-versions'] === 'string'
    ? args['supported-versions']
    : '2026-07-28,2025-11-25')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const port = Number.parseInt(args.port, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`invalid --port ${args.port}`);

  // interop/modern/contract.md 3.2: an unreadable clock or state file exits 1
  // with nothing on stdout.
  let initialClock;
  try {
    initialClock = readClockStrict(clockFile);
  } catch (err) {
    fail(`unreadable --clock-file ${clockFile}: ${err.message}`);
  }
  let keys;
  try {
    const state = JSON.parse(readFileSync(args.state, 'utf8'));
    if (!isObject(state) || !Array.isArray(state.keys)) throw new Error('state file has no keys array');
    keys = state.keys;
  } catch (err) {
    fail(`unreadable --state ${args.state}: ${err.message}`);
  }

  const { priv, publicKeyB64u, kid } = deriveKeys(seedHex);

  // Self-test controls (interop/modern/contract.md section 8): let the driver
  // prove it detects a wrong server.
  const deviations = new Set(
    (process.env.JACK_MODERN_SERVER_DEVIATE ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  );
  const skipS1Repeat = deviations.has('s1');
  const skipS8 = deviations.has('s8');

  // contract section 2: the clock file is read every time "now" is needed.
  const nowSeconds = () => {
    try {
      return readClockStrict(clockFile);
    } catch {
      return initialClock;
    }
  };

  // spec 01 section 4 step 8: live (kid, nonce) pairs, per process.
  const seenNonces = new Set();
  // contract 3.5: the refuse-first mode counts the discovers of the process.
  let discoverCount = 0;

  function writeResponse(req, res, status, body, options) {
    // requirement and spec 04 S10: a HEAD response carries no content, so the
    // signature covers the empty bytes the client actually receives.
    const wireBody = req.method === 'HEAD' ? Buffer.alloc(0) : body;
    const headers = { 'Content-Type': 'application/json' };
    // spec 04 section 5 S2: a 405 also carries Allow: POST.
    if (status === 405) headers.Allow = 'POST';
    for (const [name, value] of options.extraHeaders ?? []) headers[name] = value;
    if (options.signed) {
      headers['Jack-Auth'] = signResponseHeader(priv, kid, status, options.requestSig, nowSeconds(), wireBody);
    } else if (status === 401) {
      // spec 01 sections 4-5: an authentication failure may be unsigned and
      // carries no response Jack-Auth; WWW-Authenticate is a SHOULD.
      headers['WWW-Authenticate'] = 'Jack-Auth';
    }
    headers['Content-Length'] = String(wireBody.length);
    res.writeHead(status, headers);
    res.end(wireBody);
  }

  // spec 01 section 4: the pre-authentication envelope, never signed.
  const unsignedFailure = (req, res, code, message) => writeResponse(
    req,
    res,
    401,
    json({ error: { code, message } }),
    { signed: false },
  );

  // spec 04 section 5.2: an authenticated body-classification refusal keeps the
  // spec 01 section 4 envelope and is signed like every other response.
  const signedEnvelope = (req, res, status, code, message, requestSig) => writeResponse(
    req,
    res,
    status,
    json({ error: { code, message } }),
    { signed: true, requestSig },
  );

  // spec 04 section 5 S10: every era-rule refusal is a signed JSON-RPC error.
  const signedRefusal = (req, res, refusal, rpc, requestSig) => writeResponse(
    req,
    res,
    refusal.status,
    json({
      jsonrpc: '2.0',
      id: Object.prototype.hasOwnProperty.call(refusal, 'id') ? refusal.id : refusalId(rpc),
      error: { code: refusal.code, message: refusal.message },
    }),
    { signed: true, requestSig },
  );

  // interop/modern/contract.md 3.4: the wrapped handler.
  function handlerAnswer(method, rpc, headers) {
    const id = idEcho(rpc);
    if (method === 'server/discover') {
      // contract 3.4 (b): the legacy profile answers the 0.1.x envelope.
      if (profile === 'legacy') {
        return {
          status: 405,
          body: json({
            error: { code: 'method_not_allowed', message: 'server/discover is not available in the legacy profile' },
          }),
        };
      }
      // contract 3.5 and 3.4 (a) (c).
      const params = isObject(rpc?.params) ? rpc.params : null;
      const meta = params !== null && isObject(params._meta) ? params._meta : null;
      const requested = meta !== null ? meta[PROTOCOL_VERSION_META] : null;
      const requestedText = typeof requested === 'string' ? requested : null;
      let refused;
      if (discoverVersionMode === 'refuse-always') {
        refused = true;
      } else if (discoverVersionMode === 'refuse-first' && discoverCount === 0) {
        refused = true;
      } else {
        refused = requestedText === null || !supportedVersions.includes(requestedText);
      }
      discoverCount += 1;
      if (refused) {
        return {
          status: 400,
          body: json({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32022,
              message: 'Unsupported protocol version',
              data: { supported: supportedVersions, requested: requestedText },
            },
          }),
        };
      }
      return {
        status: 200,
        body: json({
          jsonrpc: '2.0',
          id,
          result: {
            resultType: 'complete',
            supportedVersions,
            capabilities: {},
            serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          },
        }),
      };
    }
    if (method === 'tools/list') {
      // contract 3.4 (d): the single annotated tool.
      return {
        status: 200,
        body: json({
          jsonrpc: '2.0',
          id,
          result: {
            tools: [
              {
                name: 'region.echo',
                inputSchema: {
                  type: 'object',
                  properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
                  required: ['region'],
                },
              },
            ],
          },
        }),
      };
    }
    if (method === 'tools/call' && rpc?.params?.name === 'region.echo') {
      // contract 3.4 (e): one `name: value` line per header instance the
      // handler received, in order, LF-joined, no trailing LF.
      const echo = headers.map(([name, value]) => `${name}: ${value}`).join('\n');
      return {
        status: 200,
        body: json({
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: echo }] },
        }),
      };
    }
    if (method === 'initialize') {
      // contract 3.4 (f): echo the requested version when it is supported and
      // carry the single session id.
      const requested = rpc?.params?.protocolVersion;
      const negotiated = typeof requested === 'string' && supportedVersions.includes(requested)
        ? requested
        : '2025-11-25';
      return {
        status: 200,
        body: json({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: negotiated,
            capabilities: {},
            serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          },
        }),
        extraHeaders: [['Mcp-Session-Id', 'sess-1']],
      };
    }
    if (method === 'notifications/initialized') {
      // contract 3.4 (g): 202 with an empty body.
      return { status: 202, body: Buffer.alloc(0) };
    }
    // contract 3.4 (h): any other method, and tools/call of any other tool.
    return { status: 200, body: json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found' } }) };
  }

  // spec 04 C7: a protocol-native jack.* tool is answered by the wrapper
  // before dispatch, so it never reaches the handler and is never logged.
  function nativeAnswer(name, rpc, entry, era) {
    const id = idEcho(rpc);
    if (name !== 'jack.whoami') {
      return json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found' } });
    }
    const structured = {
      kid: entry.kid,
      name: entry.name,
      admin: entry.admin === true,
      not_before: entry.not_before ?? null,
      not_after: entry.not_after ?? null,
    };
    const result = { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured, isError: false };
    // spec 04 C7: the modern era adds resultType and Jack's serverInfo; the
    // legacy era stays byte-identical to 0.1.x.
    if (era === 'modern') {
      result.resultType = 'complete';
      result._meta = { [SERVER_INFO_META]: NATIVE_SERVER_INFO };
    }
    return json({ jsonrpc: '2.0', id, result });
  }

  function dispatch(req, res, handlerHeaders, rpc, era, auth, entry) {
    const method = typeof rpc?.method === 'string' ? rpc.method : null;
    const toolName = method === 'tools/call' && typeof rpc?.params?.name === 'string' ? rpc.params.name : null;
    if (toolName !== null && toolName.startsWith('jack.')) {
      return writeResponse(req, res, 200, nativeAnswer(toolName, rpc, entry, era), {
        signed: true,
        requestSig: auth.sig,
      });
    }
    const answer = handlerAnswer(method, rpc, handlerHeaders);
    // contract 3.3: one line per handler-dispatched request, flushed before
    // the response is written.
    if (requestLog !== null) {
      appendFileSync(requestLog, JSON.stringify({ method, http_status: answer.status }) + '\n');
    }
    return writeResponse(req, res, answer.status, answer.body, {
      signed: true,
      requestSig: auth.sig,
      extraHeaders: answer.extraHeaders,
    });
  }

  function processRequest(req, res, headers, body) {
    // spec 01 section 4 steps 1-2: exactly one Jack-Auth value.
    const rawAuth = firstValue(headers, 'jack-auth');
    if (rawAuth === null) return unsignedFailure(req, res, 'missing_auth', 'Jack-Auth is missing');
    const auth = parseRequestAuth(rawAuth);
    if (auth === null) return unsignedFailure(req, res, 'malformed_auth', 'Jack-Auth is malformed');
    // step 4: the kid must be registered.
    const entry = keys.find((key) => key && key.kid === auth.kid);
    if (entry === undefined) return unsignedFailure(req, res, 'unknown_key', 'unknown key');
    // step 6: fixed-clock freshness.
    if (Math.abs(auth.ts - nowSeconds()) > FRESHNESS_WINDOW_SECONDS) {
      return unsignedFailure(req, res, 'timestamp_out_of_window', 'request timestamp is outside the window');
    }
    // step 7: the signature over the exact method, target and body bytes.
    const verified = verifyRequest(entry.public_key, {
      aud,
      method: req.method,
      target: req.url,
      auth,
      body,
    });
    if (!verified) return unsignedFailure(req, res, 'bad_signature', 'request signature does not verify');
    // step 8: the nonce is recorded only after the signature verified, so a
    // refusal of any later rule still consumes it (spec 04 S10).
    const nonceKey = `${auth.kid}\n${auth.nonce}`;
    if (seenNonces.has(nonceKey)) return unsignedFailure(req, res, 'replayed_nonce', 'request nonce has already been used');
    seenNonces.add(nonceKey);

    // spec 02 section 2: body classification runs before the era decision.
    let rpc = null;
    if (req.method === 'POST') {
      try {
        rpc = JSON.parse(body.toString('utf8'));
      } catch {
        rpc = null;
      }
      if (!isObject(rpc) || rpc.jsonrpc !== '2.0') {
        return signedEnvelope(req, res, 400, 'invalid_request', 'body is not a JSON-RPC 2.0 object', auth.sig);
      }
      if (rpc.method === 'tools/call' && typeof rpc.params?.name !== 'string') {
        return signedEnvelope(req, res, 400, 'invalid_request', 'tools/call requires a string params.name', auth.sig);
      }
    }

    // spec 04 section 5 S3: the era decision runs before every other rule.
    const era = decideEra(profile, rpc, headers);
    if (era === 'legacy') {
      // spec 04 section 3: no rule of section 5 runs, and the header list is
      // forwarded exactly as received (S8 included).
      return dispatch(req, res, headers, rpc, era, auth, entry);
    }

    // spec 04 section 5 and 5.1: S1, S2, S4, S5, S6, first failure decides.
    const refusal = modernRefusal(req, rpc, headers, skipS1Repeat);
    if (refusal !== null) return signedRefusal(req, res, refusal, rpc, auth.sig);

    // spec 04 section 5 S8: strip every session header before the handler; S9
    // forwards the remaining instances in their received order.
    const forwarded = skipS8
      ? headers
      : headers.filter(([name]) => !SESSION_HEADERS.includes(lower(name)));
    return dispatch(req, res, forwarded, rpc, era, auth, entry);
  }

  function handleRequest(req, res) {
    const headers = receivedHeaders(req.rawHeaders);
    // spec 01 section 4 step 2: a repeated Jack-Auth is malformed_auth. The
    // request body is drained so the refusal is not lost to a socket reset.
    if (instances(headers, 'jack-auth').length > 1) {
      req.resume();
      return unsignedFailure(req, res, 'malformed_auth', 'Jack-Auth must appear exactly once');
    }
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) {
        return writeResponse(req, res, 400, json({ error: { code: 'invalid_request', message: 'request body too large' } }), {
          signed: false,
        });
      }
      processRequest(req, res, headers, Buffer.concat(chunks));
    });
    req.on('error', () => res.destroy());
  }

  // interop/modern/contract.md 3.1: bind loopback, then print one ready line.
  const server = http.createServer(handleRequest);
  server.on('error', (err) => {
    process.stderr.write(`listen failed: ${err.message}\n`);
    process.exit(1);
  });
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(JSON.stringify({
      ready: true,
      port: server.address().port,
      server_public_key: publicKeyB64u,
      server_kid: kid,
      profile,
    }) + '\n');
  });
  const stop = () => process.exit(0);
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  process.stdin.on('end', stop);
  process.stdin.on('close', stop);
  process.stdin.resume();
}

// contract section 2: the clock file holds one decimal integer.
function readClockStrict(file) {
  const text = readFileSync(file, 'utf8').trim();
  if (!/^-?\d+$/.test(text)) throw new Error('clock file does not hold a decimal integer');
  return Number.parseInt(text, 10);
}

main();
