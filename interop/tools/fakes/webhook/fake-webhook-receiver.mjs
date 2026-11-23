// Self-test only. Stand-in for an SDK webhook_receiver: it serves TLS on
// 127.0.0.1, applies the eighteen verification steps of spec 06 section 3 with
// node:crypto and prints the contract's stdout lines. NOT a reference implementation.
import { createHmac, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import {
  b64u,
  publicKeyFromB64u,
  sha256,
  secretBytes,
  w1SigningString,
} from './webhook-sign.mjs';

const MAX_BODY_BYTES = 262144;
const WINDOW_SECONDS = 300;
const JACK_WINDOW_SECONDS = 30;
const ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const TIMESTAMP_RE = /^(0|[1-9][0-9]{0,11})$/;
const SUBSCRIPTION_RE = /^sub_[0-9a-f]{16}$/;
const RFC3339_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;
const USAGE =
  'usage: node fake-webhook-receiver.mjs --port <n> --tls-cert <pem> --tls-key <pem> --clock-file <file> ' +
  '--secret-seed <text> --subscription-id <sub_...> --callback-url <url> --aud <aud> [--card-file <file>] ' +
  '[--card-mcp-url <url>] [--enforce-server-identity] [--require-jack] [--mcp-server-kid <kid>] [--enqueue-fail <n>]';

function fatal(message, code = 1) {
  process.stderr.write(message + '\n');
  process.exit(code);
}

const SINGLE_FLAGS = new Map([
  ['--port', 'port'],
  ['--tls-cert', 'tlsCert'],
  ['--tls-key', 'tlsKey'],
  ['--clock-file', 'clockFile'],
  ['--secret-seed', 'secretSeed'],
  ['--subscription-id', 'subscriptionId'],
  ['--callback-url', 'callbackUrl'],
  ['--aud', 'aud'],
  ['--card-file', 'cardFile'],
  ['--card-mcp-url', 'cardMcpUrl'],
  ['--mcp-server-kid', 'mcpServerKid'],
  ['--enqueue-fail', 'enqueueFail'],
]);

function parseArgs(argv) {
  const out = { enforce: false, requireJack: false, enqueueFail: 0, pending: false };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === '--enforce-server-identity') {
      out.enforce = true;
      continue;
    }
    if (flag === '--require-jack') {
      out.requireJack = true;
      continue;
    }
    if (flag === '--pending-secret') {
      out.pending = true;
      continue;
    }
    const key = SINGLE_FLAGS.get(flag);
    if (key === undefined) fatal(`unknown flag: ${flag}\n${USAGE}`, 2);
    out[key] = argv[(i += 1)];
  }
  for (const key of ['port', 'tlsCert', 'tlsKey', 'clockFile', 'secretSeed', 'subscriptionId', 'callbackUrl', 'aud']) {
    if (out[key] === undefined || out[key] === '') fatal(`missing --${key}\n${USAGE}`, 2);
  }
  out.port = Number(out.port);
  if (!Number.isInteger(out.port) || out.port < 0 || out.port > 65535) fatal('--port must be an integer in 0..65535', 2);
  out.enqueueFail = Number(out.enqueueFail ?? 0);
  if (!Number.isInteger(out.enqueueFail) || out.enqueueFail < 0) fatal('--enqueue-fail must be a non-negative integer', 2);
  return out;
}

const flags = parseArgs(process.argv.slice(2));
const secret = secretBytes(flags.secretSeed);
const pendingSecret = flags.pending === true;
const callbackPath = new URL(flags.callbackUrl).pathname;
const routed = new Set(pendingSecret ? [] : [flags.subscriptionId]);
const terminated = new Set();
const accepted = new Set();
let enqueueFailures = flags.enqueueFail;
let seq = 0;
let enqueuedCount = 0;

function cardKeys() {
  if (typeof flags.cardFile !== 'string') return [];
  let doc;
  try {
    doc = JSON.parse(readFileSync(flags.cardFile, 'utf8'));
  } catch {
    return [];
  }
  const remotes = Array.isArray(doc?.remotes) ? doc.remotes : [];
  let info = null;
  for (const remote of remotes) {
    const candidate = remote?.extensionsInfo?.['io.modelcontextprotocol/events']?.webhooks;
    if (candidate === undefined) continue;
    if (info === null) info = candidate;
    if (typeof flags.cardMcpUrl === 'string' && remote.url === flags.cardMcpUrl) {
      info = candidate;
      break;
    }
  }
  const entries = info?.signingKeys?.keys;
  if (!Array.isArray(entries)) return [];
  const counts = new Map();
  for (const entry of entries) if (typeof entry?.kid === 'string') counts.set(entry.kid, (counts.get(entry.kid) ?? 0) + 1);
  const keys = [];
  for (const entry of entries) {
    if (entry?.kty !== 'OKP' || entry?.crv !== 'Ed25519') continue;
    const raw = Buffer.from(String(entry.x ?? ''), 'base64url');
    if (raw.length !== 32) continue;
    const kid = typeof entry.kid === 'string' ? entry.kid : '';
    if (kid !== b64u(sha256(raw))) continue;
    if (entry.use !== undefined && entry.use !== 'sig') continue;
    if (entry.alg !== undefined && entry.alg !== 'EdDSA') continue;
    if ((counts.get(kid) ?? 0) > 1) continue;
    if (typeof flags.mcpServerKid === 'string' && kid === flags.mcpServerKid) continue;
    keys.push({ kid, publicKey: publicKeyFromB64u(entry.x) });
  }
  return keys;
}

const keys = cardKeys();

function readClock() {
  const text = readFileSync(flags.clockFile, 'utf8').trim();
  if (!/^-?[0-9]+$/.test(text)) fatal('the clock file does not hold a decimal integer');
  return Number.parseInt(text, 10);
}

function headerValues(headers, name) {
  const out = [];
  for (const pair of headers) if (pair[0].toLowerCase() === name) out.push(pair[1]);
  return out;
}

function parseSignature(value) {
  const entries = [];
  for (const part of String(value).split(' ')) {
    const comma = part.indexOf(',');
    if (comma < 1 || comma === part.length - 1) return null;
    entries.push({ scheme: part.slice(0, comma), value: part.slice(comma + 1) });
  }
  return entries.length === 0 ? null : entries;
}

function parseW1(value) {
  const text = String(value).trim();
  if (!text.startsWith('w1 ')) return null;
  const params = new Map();
  for (const part of text.slice(3).split(',')) {
    const eq = part.indexOf('=');
    if (eq < 1) return null;
    params.set(part.slice(0, eq), part.slice(eq + 1));
  }
  if (params.size !== 2) return null;
  if (!/^[A-Za-z0-9_-]{43}$/.test(params.get('kid') ?? '')) return null;
  if (!/^[A-Za-z0-9_-]{86}$/.test(params.get('sig') ?? '')) return null;
  return { kid: params.get('kid'), sig: params.get('sig') };
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonEmpty = (value) => typeof value === 'string' && value.length > 0;

// Canonical JSON text (members sorted, no insignificant whitespace) of a value.
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const members = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(',')}}`;
  }
  return JSON.stringify(value);
}

function bodyKind(bodyJson) {
  if (!isObject(bodyJson)) return { status: 400, code: 'malformed_body' };
  if (bodyJson.type !== undefined) {
    if (!['gap', 'terminated', 'verification'].includes(bodyJson.type)) return { status: 400, code: 'unknown_envelope_type' };
    return { kind: bodyJson.type };
  }
  if (!nonEmpty(bodyJson.eventId) || !nonEmpty(bodyJson.name)) return { status: 400, code: 'malformed_body' };
  if (typeof bodyJson.timestamp !== 'string' || !RFC3339_RE.test(bodyJson.timestamp)) return { status: 400, code: 'malformed_body' };
  if (!isObject(bodyJson.data)) return { status: 400, code: 'malformed_body' };
  if (bodyJson.cursor !== undefined && bodyJson.cursor !== null && typeof bodyJson.cursor !== 'string') {
    return { status: 400, code: 'malformed_body' };
  }
  return { kind: 'event' };
}

function judge(headers, body, now) {
  const required = ['webhook-id', 'webhook-timestamp', 'webhook-signature', 'x-mcp-subscription-id'];
  for (const name of required) if (headerValues(headers, name).length === 0) return { status: 400, code: 'missing_webhook_header' };
  for (const name of required) if (headerValues(headers, name).length > 1) return { status: 400, code: 'duplicate_webhook_header' };
  const webhookId = headerValues(headers, 'webhook-id')[0];
  const timestamp = headerValues(headers, 'webhook-timestamp')[0];
  const signature = headerValues(headers, 'webhook-signature')[0];
  const subscriptionId = headerValues(headers, 'x-mcp-subscription-id')[0];
  if (!ID_RE.test(webhookId)) return { status: 400, code: 'malformed_webhook_id' };
  if (!TIMESTAMP_RE.test(timestamp)) return { status: 400, code: 'malformed_webhook_timestamp' };
  if (!SUBSCRIPTION_RE.test(subscriptionId)) return { status: 400, code: 'malformed_subscription_id' };
  // Step 7 (R3.7, R5.6): a registered secret for this id, or the pending entry
  // whose callback url this endpoint serves.
  if (!pendingSecret && subscriptionId !== flags.subscriptionId) return { status: 401, code: 'unknown_subscription' };
  // Step 8 (R3.8): routing. A verification body is answered in place, and on the
  // pending path routing is decided after the body is parsed (R5.6).
  if (!pendingSecret && !routed.has(subscriptionId)) return { status: 503, code: 'subscription_not_routed' };
  const entries = parseSignature(signature);
  if (entries === null) return { status: 400, code: 'malformed_signature_header' };
  for (const entry of entries) if (!['v1', 'v1a', 'v2a'].includes(entry.scheme)) return { status: 400, code: 'unsupported_signature_scheme' };
  for (const entry of entries) {
    const length = Buffer.from(entry.value, 'base64').length;
    if (length !== (entry.scheme === 'v1' ? 32 : 64)) return { status: 400, code: 'malformed_signature' };
  }
  const content = Buffer.concat([Buffer.from(`${webhookId}.${timestamp}.`, 'utf8'), body]);
  const expected = createHmac('sha256', secret).update(content).digest();
  const v1 = entries.some((entry) => entry.scheme === 'v1' && Buffer.from(entry.value, 'base64').equals(expected));
  if (!v1) return { status: 401, code: 'bad_signature' };
  const instant = Number.parseInt(timestamp, 10);
  if (now - instant > WINDOW_SECONDS) return { status: 401, code: 'stale_timestamp' };
  if (instant - now > WINDOW_SECONDS) return { status: 401, code: 'future_timestamp' };
  if (flags.enforce) {
    if (keys.length === 0) return { status: 503, code: 'no_server_keys' };
    const endpointContent = Buffer.concat([Buffer.from(`${subscriptionId}.${webhookId}.${timestamp}.`, 'utf8'), body]);
    let asymmetric = false;
    for (const entry of entries) {
      if (entry.scheme !== 'v1a' && entry.scheme !== 'v2a') continue;
      const signed = entry.scheme === 'v1a' ? content : sha256(endpointContent);
      const signatureBytes = Buffer.from(entry.value, 'base64');
      if (keys.some((key) => verify(null, signed, key.publicKey, signatureBytes))) {
        asymmetric = true;
        break;
      }
    }
    if (!asymmetric) return { status: 401, code: 'bad_server_signature' };
  }
  if (flags.requireJack) {
    const values = headerValues(headers, 'jack-webhook-auth');
    if (values.length === 0) return { status: 401, code: 'missing_jack_auth' };
    const parsed = parseW1(values[0]);
    if (values.length > 1 || parsed === null) return { status: 400, code: 'malformed_jack_auth' };
    if (typeof flags.mcpServerKid === 'string' && parsed.kid === flags.mcpServerKid) {
      return { status: 401, code: 'webhook_key_is_server_key' };
    }
    const key = keys.find((entry) => entry.kid === parsed.kid);
    if (key === undefined) return { status: 401, code: 'unknown_webhook_key' };
    if (Math.abs(now - instant) > JACK_WINDOW_SECONDS) return { status: 401, code: 'jack_timestamp_out_of_window' };
    const signed = Buffer.from(
      w1SigningString({ aud: flags.aud, subscriptionId, webhookId, timestamp, callbackUrl: flags.callbackUrl, body }),
      'utf8',
    );
    if (!verify(null, signed, key.publicKey, Buffer.from(parsed.sig, 'base64url'))) {
      return { status: 401, code: 'bad_jack_signature' };
    }
  }
  if (accepted.has(webhookId)) return { status: 200, statusBody: 'duplicate', kind: null };
  let bodyJson = null;
  try {
    bodyJson = JSON.parse(body.toString('utf8'));
  } catch {
    bodyJson = null;
  }
  const parsed = bodyKind(bodyJson);
  if (parsed.code !== undefined) return { status: parsed.status, code: parsed.code };
  const kind = parsed.kind;
  if (pendingSecret && !routed.has(subscriptionId) && kind !== 'verification') {
    return { status: 503, code: 'subscription_not_routed', kind };
  }
  if (terminated.has(subscriptionId)) return { status: 410, code: 'subscription_terminated', kind };
  if (enqueueFailures > 0) {
    enqueueFailures -= 1;
    return { status: 503, code: 'enqueue_failed', kind };
  }
  if (kind === 'verification') {
    const nonce = typeof bodyJson.challenge === 'string' ? bodyJson.challenge : '';
    // R5.6: a verified challenge binds the id and routes it.
    if (pendingSecret) routed.add(subscriptionId);
    accepted.add(webhookId);
    return { status: 200, statusBody: 'challenge', kind, challenge: nonce };
  }
  enqueuedCount += 1;
  accepted.add(webhookId);
  if (kind === 'terminated') terminated.add(subscriptionId);
  return { status: 200, statusBody: 'accepted', kind, forwarded: [Buffer.from(canonicalJson(bodyJson), 'utf8')] };
}

function respond(res, status, payload) {
  const text = Buffer.from(JSON.stringify(payload), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': String(text.length), connection: 'close' };
  if (status === 401) headers['www-authenticate'] = 'Webhook-Signature';
  res.writeHead(status, headers);
  res.end(text);
}

function writeLine(value) {
  process.stdout.write(JSON.stringify(value) + '\n');
}

function handle(req, res) {
  const path = new URL(req.url, 'https://placeholder.invalid').pathname;
  if (req.method !== 'POST' || path !== callbackPath) {
    respond(res, 404, { error: { code: 'no_route', message: 'not a delivery endpoint' } });
    return;
  }
  const headers = [];
  for (const [name, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) for (const item of value) headers.push([name, String(item)]);
    else if (value !== undefined) headers.push([name, String(value)]);
  }
  const now = readClock();
  const declared = Number(req.headers['content-length']);
  const record = (outcome, body) => {
    writeLine({
      event: 'delivery',
      seq: (seq += 1) - 1,
      status: outcome.status,
      code: outcome.code ?? null,
      body_status: outcome.statusBody ?? null,
      kind: outcome.kind ?? null,
      webhook_id: headerValues(headers, 'webhook-id')[0] ?? '',
      subscription_id: headerValues(headers, 'x-mcp-subscription-id')[0] ?? '',
      webhook_timestamp: headerValues(headers, 'webhook-timestamp')[0] ?? '',
      challenge: outcome.challenge ?? null,
      enqueued: enqueuedCount,
      forwarded: (outcome.forwarded ?? []).map((value) => Buffer.from(value).toString('base64url')),
      headers,
      body_b64u: body.toString('base64url'),
    });
  };
  if (!Number.isInteger(declared) || declared > MAX_BODY_BYTES) {
    record({ status: 413, code: 'body_too_large' }, Buffer.alloc(0));
    respond(res, 413, { error: { code: 'body_too_large', message: 'body or declared length above the limit' } });
    req.resume();
    return;
  }
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('error', () => res.destroy());
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const outcome = judge(headers, body, now);
    record(outcome, body);
    if (outcome.statusBody === 'accepted') respond(res, 200, { status: 'accepted' });
    else if (outcome.statusBody === 'duplicate') respond(res, 200, { status: 'duplicate' });
    else if (outcome.statusBody === 'challenge') respond(res, 200, { challenge: outcome.challenge });
    else respond(res, outcome.status, { error: { code: outcome.code, message: outcome.code } });
  });
}

const server = https.createServer(
  { cert: readFileSync(flags.tlsCert), key: readFileSync(flags.tlsKey) },
  handle,
);
server.on('error', (error) => fatal(`listen failed: ${error.message}`));
server.listen(flags.port, '127.0.0.1', () => {
  writeLine({ ready: true, role: 'receiver', port: server.address().port, subscription_id: flags.subscriptionId, subscription_known: routed.has(flags.subscriptionId) });
});
const stop = () => process.exit(0);
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.stdin.on('end', stop);
process.stdin.on('close', stop);
process.stdin.resume();
