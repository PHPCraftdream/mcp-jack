// Self-test only. Stand-in for an SDK webhook_sender: it signs with node:crypto,
// resolves through the injected resolver, walks the R1.8 schedule on the virtual
// clock file and prints the contract's stdout lines. NOT a reference implementation.
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import {
  BODIES,
  classifyAddress,
  deriveKeys,
  emissionHeader,
  randomWebhookId,
  secretBytes,
  subscriptionIdFor,
  webhookIdFor,
  w1Header,
} from './webhook-sign.mjs';

const RETRY_OFFSETS = [0, 30, 270, 870];
const RETRY_CAP_SECONDS = 900;
const MAX_ATTEMPTS = 4;
const USAGE =
  'usage: node fake-webhook-sender.mjs --scenario <id> --url <url> --aud <aud> --clock-file <file> ' +
  '--secret-seed <text> --messages <csv> [--subscription-id <id>] [--signing-seed-hex <hex>] ' +
  '[--jack-seed-hex <hex>] [--allowlist <prefix>]... [--allowed-range <cidr>]... ' +
  '[--resolver-file <file>] [--rebind-address <ip>] [--body-file <file>] [--tls-ca <pem>]';

function fatal(message, code = 1) {
  process.stderr.write(message + '\n');
  process.exit(code);
}

const SINGLE_FLAGS = new Map([
  ['--scenario', 'scenario'],
  ['--url', 'url'],
  ['--aud', 'aud'],
  ['--clock-file', 'clockFile'],
  ['--secret-seed', 'secretSeed'],
  ['--subscription-id', 'subscriptionId'],
  ['--signing-seed-hex', 'signingSeedHex'],
  ['--jack-seed-hex', 'jackSeedHex'],
  ['--resolver-file', 'resolverFile'],
  ['--rebind-address', 'rebindAddress'],
  ['--body-file', 'bodyFile'],
  ['--tls-ca', 'tlsCa'],
  ['--tls-ca-der', 'tlsCaDer'],
]);

function parseArgs(argv) {
  const out = { messages: ['event'], allowlist: [], allowedRanges: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === '--allowlist') {
      out.allowlist.push(String(argv[(i += 1)] ?? ''));
      continue;
    }
    if (flag === '--allowed-range') {
      out.allowedRanges.push(String(argv[(i += 1)] ?? ''));
      continue;
    }
    if (flag === '--messages') {
      out.messages = String(argv[(i += 1)] ?? '')
        .split(',')
        .map((part) => part.trim())
        .filter(Boolean);
      continue;
    }
    const key = SINGLE_FLAGS.get(flag);
    if (key === undefined) fatal(`unknown flag: ${flag}\n${USAGE}`, 2);
    out[key] = argv[(i += 1)];
  }
  for (const key of ['scenario', 'url', 'aud', 'clockFile', 'secretSeed']) {
    if (typeof out[key] !== 'string' || out[key] === '') fatal(`missing --${key}\n${USAGE}`, 2);
  }
  if (out.messages.length === 0) fatal(`missing --messages\n${USAGE}`, 2);
  if (out.messages.includes('raw') && typeof out.bodyFile !== 'string') {
    fatal('the raw message kind needs --body-file', 2);
  }
  return out;
}

const flags = parseArgs(process.argv.slice(2));
const target = new URL(flags.url);
const HOST = target.hostname;
const PORT = target.port === '' ? 443 : Number(target.port);

function readClock() {
  const text = readFileSync(flags.clockFile, 'utf8').trim();
  if (!/^-?[0-9]+$/.test(text)) fatal('the clock file does not hold a decimal integer');
  return Number.parseInt(text, 10);
}

function setClock(value) {
  writeFileSync(flags.clockFile, String(value) + '\n');
}

let resolver = null;

function resolveHost(host) {
  if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host)) return [host];
  if (typeof flags.resolverFile !== 'string') return null;
  if (resolver === null) {
    try {
      resolver = JSON.parse(readFileSync(flags.resolverFile, 'utf8'));
    } catch {
      return null;
    }
  }
  const answers = resolver[host];
  if (!Array.isArray(answers) || answers.length === 0) return null;
  return answers.map(String);
}

function postOnce(headers, body, address) {
  return new Promise((resolve) => {
    const options = {
      host: HOST,
      port: PORT,
      method: 'POST',
      path: target.pathname + target.search,
      headers: { ...headers, 'content-length': String(body.length) },
      servername: HOST,
      lookup: (hostname, lookupOptions, callback) => {
        if (lookupOptions !== null && typeof lookupOptions === 'object' && lookupOptions.all === true) {
          callback(null, [{ address, family: 4 }]);
          return;
        }
        callback(null, address, 4);
      },
    };
    if (typeof flags.tlsCa === 'string') options.ca = readFileSync(flags.tlsCa);
    const request = https.request(options, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode ?? null, body: Buffer.concat(chunks) }));
      response.on('error', () => resolve({ status: response.statusCode ?? null, body: Buffer.alloc(0) }));
    });
    request.on('error', () => resolve({ status: null, body: Buffer.alloc(0) }));
    request.end(body);
  });
}

const deviating = process.env.JACK_WEBHOOK_DEVIATE === flags.scenario;
const secret = secretBytes(deviating ? 'deviation' : flags.secretSeed);
const derived = subscriptionIdFor(flags.url);
const effectiveId = typeof flags.subscriptionId === 'string' && flags.subscriptionId !== '' ? flags.subscriptionId : derived;
const signing = typeof flags.signingSeedHex === 'string' ? deriveKeys(flags.signingSeedHex) : null;
const jack = typeof flags.jackSeedHex === 'string' ? deriveKeys(flags.jackSeedHex) : null;
const signingKeys = signing === null ? [] : [{ priv: signing.priv }];

function headersFor(webhookId, timestamp, body) {
  const headers = {
    'content-type': 'application/json',
    'webhook-id': webhookId,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': emissionHeader({
      secret,
      keys: signingKeys,
      webhookId,
      timestamp,
      body,
      endpointId: effectiveId,
    }),
    'X-MCP-Subscription-Id': effectiveId,
  };
  if (jack !== null) {
    headers['Jack-Webhook-Auth'] = w1Header({
      priv: jack.priv,
      kid: jack.kid,
      aud: flags.aud,
      subscriptionId: effectiveId,
      webhookId,
      timestamp,
      callbackUrl: flags.url,
      body,
    });
  }
  return headers;
}

function allowlistMatches() {
  for (const entry of flags.allowlist) {
    if (entry === '') continue;
    if (flags.url === entry) return true;
    const prefix = entry.endsWith('/') ? entry : entry + '/';
    if (flags.url.startsWith(prefix)) return true;
  }
  return false;
}

// The validated address, or the refusal category of contract section 4.4.
function resolveTarget() {
  const answers = resolveHost(HOST);
  if (answers === null) return { refusal: 'connection_refused' };
  for (const answer of answers) {
    if (!classifyAddress(answer, flags.allowedRanges).allow) return { refusal: 'ssrf_blocked_address' };
  }
  return { address: answers[0] };
}

async function ensureVerified() {
  if (allowlistMatches()) return true;
  const target = resolveTarget();
  if (target.address === undefined) return false;
  const nonce = randomBytes(16).toString('base64url');
  const body = Buffer.from(`{"type":"verification","challenge":"${nonce}"}`, 'utf8');
  const response = await postOnce(headersFor(randomWebhookId('verification'), readClock(), body), body, target.address);
  if (response.status === null || response.status < 200 || response.status > 299) return false;
  try {
    const parsed = JSON.parse(response.body.toString('utf8'));
    return parsed !== null && typeof parsed === 'object' && parsed.challenge === nonce;
  } catch {
    return false;
  }
}

function categoryOf(status) {
  if (status >= 200 && status <= 299) return null;
  return status >= 500 ? 'http_5xx' : 'http_4xx';
}

function retryable(status, category) {
  if (category === 'connection_refused' || category === 'timeout' || category === 'tls_error') return true;
  if (category === 'http_5xx') return true;
  return status === 425 || status === 429;
}

function writeLine(value) {
  process.stdout.write(JSON.stringify(value) + '\n');
}

async function sendMessage(index) {
  const kind = flags.messages[index];
  const body = kind === 'raw' ? readFileSync(flags.bodyFile) : BODIES[kind];
  if (body === undefined) fatal(`unknown message kind '${kind}'`);
  const webhookId = webhookIdFor(flags.scenario, index, kind);
  const entry = {
    message: index,
    kind,
    webhook_id: webhookId,
    attempts: 0,
    accepted: false,
    http_status: null,
    last_error: null,
  };
  const t0 = readClock();
  let nextAt = t0;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    if (attempt > 1) setClock(nextAt);
    const now = readClock();
    const target = resolveTarget();
    if (target.address === undefined) {
      entry.last_error = target.refusal;
      return entry;
    }
    if (typeof flags.rebindAddress === 'string' && flags.rebindAddress !== target.address) {
      entry.last_error = 'ssrf_rebinding_blocked';
      return entry;
    }
    entry.attempts += 1;
    const response = await postOnce(headersFor(webhookId, now, body), body, target.address);
    const status = response.status;
    const category = status === null ? 'connection_refused' : categoryOf(status);
    entry.http_status = status;
    entry.last_error = category;
    if (category === null) {
      entry.accepted = true;
      return entry;
    }
    if (!retryable(status, category) || attempt === MAX_ATTEMPTS) return entry;
    nextAt = t0 + RETRY_OFFSETS[attempt];
    if (nextAt <= now || nextAt > t0 + RETRY_CAP_SECONDS) return entry;
  }
  return entry;
}

async function main() {
  writeLine({ ready: true, role: 'sender', callback_url: flags.url, derived_subscription_id: derived });
  const results = [];
  if (await ensureVerified()) {
    for (let index = 0; index < flags.messages.length; index += 1) results.push(await sendMessage(index));
  } else {
    for (let index = 0; index < flags.messages.length; index += 1) {
      const kind = flags.messages[index];
      results.push({
        message: index,
        kind,
        webhook_id: webhookIdFor(flags.scenario, index, kind),
        attempts: 0,
        accepted: false,
        http_status: null,
        last_error: 'challenge_failed',
      });
    }
  }
  writeLine({
    event: 'result',
    scenario: flags.scenario,
    role: 'sender',
    callback_url: flags.url,
    derived_subscription_id: derived,
    results,
  });
}

main().catch((error) => fatal(`fake sender failed: ${error.message}`));
