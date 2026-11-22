// Reference receiver of spec/06-webhooks.md sections 1, 3, 4 and 5 and rule R7.6; pure and deterministic, `now` is an argument, no clock, no randomness, no I/O.
import { crossCheckWebhookKey } from './card.mjs';
import { b64u, b64uDecodeStrict, parseWhsec, sha256 } from './primitives.mjs';
import { asymVerify, checkSchemes, decodeEntries, parseSignatureHeader, v1Verify, w1Verify } from './signatures.mjs';
import { nonceOk } from './verification.mjs';

const H_ID = 'webhook-id';
const H_TS = 'webhook-timestamp';
const H_SIG = 'webhook-signature';
const H_SUB = 'x-mcp-subscription-id';
const H_JACK = 'jack-webhook-auth';
const H_LEN = 'content-length';
const REQUIRED = [H_ID, H_TS, H_SIG, H_SUB];
const ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const TS_RE = /^(0|[1-9][0-9]{0,11})$/;
const SUB_RE = /^sub_[0-9a-f]{16}$/;
const LEN_RE = /^[0-9]+$/;
const TYPES = new Set(['gap', 'terminated', 'verification']);
const DEFAULT_WINDOW = 300;
const DEFAULT_MAX_BODY = 262144;
const DEFAULT_DEDUP = 1200;
const DEFAULT_JACK_WINDOW = 30;
const MAX_ATTEMPTS = 4;
const RETRY_CAP = 900;
const REQUIRE_CHECK = 'require';
const done = (status, body, recorded) => ({ status, body, delivered: [], code: null, recorded });

// R3.1-R3.18, R4.5, R4.6, R7.6: the closed code, status and fixed message table of the receiver.
const ERRORS = {
  missing_webhook_header: [400, 'a required header is absent'],
  duplicate_webhook_header: [400, 'a required header is repeated'],
  malformed_webhook_id: [400, 'webhook-id grammar'],
  malformed_webhook_timestamp: [400, 'webhook-timestamp grammar'],
  malformed_subscription_id: [400, 'subscription id grammar'],
  body_too_large: [413, 'body or declared length above the limit'],
  unknown_subscription: [401, 'no secret applies to the subscription'],
  subscription_not_routed: [503, 'the subscription is not routed'],
  subscription_terminated: [410, 'the subscription is terminated'],
  stale_timestamp: [401, 'timestamp too old'],
  future_timestamp: [401, 'timestamp too far ahead'],
  malformed_signature_header: [400, 'signature header grammar'],
  unsupported_signature_scheme: [400, 'unsupported signature scheme'],
  malformed_signature: [400, 'signature value length'],
  bad_signature: [401, 'signature does not verify'],
  bad_server_signature: [401, 'server signature does not verify'],
  no_server_keys: [503, 'no accepted server key'],
  missing_jack_auth: [401, 'jack header absent'],
  malformed_jack_auth: [400, 'jack header grammar'],
  webhook_key_is_server_key: [401, 'the webhook key is the mcp server key'],
  unknown_webhook_key: [401, 'unknown webhook key'],
  jack_timestamp_out_of_window: [401, 'jack timestamp outside the window'],
  bad_jack_signature: [401, 'jack signature does not verify'],
  webhook_key_mismatch: [401, 'the webhook key sources disagree'],
  webhook_key_missing: [401, 'the webhook key source is missing'],
  enqueue_failed: [503, 'durable enqueue failed'],
  malformed_body: [400, 'body is not a json object'],
  unknown_envelope_type: [400, 'unknown envelope type'],
};

const reject = (code) => {
  const [status, message] = ERRORS[code];
  return { status, body: { error: { code, message } }, delivered: [], code, recorded: false };
};

const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const nonEmpty = (value) => typeof value === 'string' && value.length > 0;

const num = (value, fallback) => (typeof value === 'number' ? value : fallback);

// R3.6, R3.12, R3.13: the raw body bytes, converted from a string once.
function bodyBytes(body) {
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (Buffer.isBuffer(body)) return body;
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  return Buffer.alloc(0);
}

// R3.1, R3.2: values grouped by lowercase name; a pair without a value is a present header with an empty value list.
function collectHeaders(headers) {
  const map = new Map();
  for (const pair of Array.isArray(headers) ? headers : []) {
    if (!Array.isArray(pair) || typeof pair[0] !== 'string') continue;
    const name = pair[0].toLowerCase();
    const values = map.get(name) ?? [];
    const value = pair[1];
    if (typeof value === 'string') values.push(value);
    else if (Array.isArray(value)) for (const item of value) if (typeof item === 'string') values.push(item);
    map.set(name, values);
  }
  return map;
}

// R2.1, R3.7: a secret entry's key bytes; a bad entry is a programmer error, not a request error.
function secretKey(entry) {
  const value = entry && typeof entry === 'object' ? entry.secret : undefined;
  if (Buffer.isBuffer(value)) return value;
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  const parsed = parseWhsec(value);
  if (!parsed.ok) throw new Error(`receiver secret must be a Buffer or a whsec_ value: ${parsed.reason}`);
  return parsed.key;
}

// R3.7, R5.6: pending secrets keep a null subscription id and their callback url until a verification binds them.
function secretEntries(secrets) {
  const list = Array.isArray(secrets) ? secrets : [];
  return list.map((entry) => ({
    key: secretKey(entry),
    subscription_id: entry && typeof entry.subscription_id === 'string' ? entry.subscription_id : null,
    callback_url: entry && typeof entry.callback_url === 'string' ? entry.callback_url : undefined,
  }));
}

// R3.18: a parsed JSON object, or null for anything else.
function parseObject(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
  if (!isObject(parsed)) return null;
  return parsed;
}

// R4.5, R7.3: the raw 32-byte public key of a configured key, whatever member carries it.
function keyBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === 'string') return b64uDecodeStrict(value) ?? Buffer.alloc(0);
  return Buffer.alloc(0);
}

// R4.5: `kid = base64url(SHA-256(raw 32-byte public key))`, so a raw configured server key names its own kid.
function serverKidOf(publicKey) {
  if (publicKey === null) return null;
  const raw = b64uDecodeStrict(publicKey);
  return raw === null ? null : b64u(sha256(raw));
}

// R4.5, R7.3: accepted keys, with every key equal to the configured MCP server key dropped by kid or by raw key.
function acceptedKeys(list, serverKid, serverPublicKey) {
  const out = [];
  for (const key of Array.isArray(list) ? list : []) {
    if (!isObject(key)) continue;
    const pub = keyBytes(key.pub ?? key.x ?? key.public_key);
    const publicKey = typeof key.public_key === 'string' ? key.public_key : b64u(pub);
    if (serverKid !== null && key.kid === serverKid) continue;
    if (serverPublicKey !== null && publicKey === serverPublicKey) continue;
    const x = typeof key.x === 'string' ? key.x : publicKey;
    out.push({
      kid: key.kid,
      public_key: publicKey,
      pub,
      kty: typeof key.kty === 'string' ? key.kty : 'OKP',
      crv: typeof key.crv === 'string' ? key.crv : 'Ed25519',
      x,
    });
  }
  return out;
}

// R1.3, R5.6, R8.8, R3.18: the field set of one parsed envelope or event occurrence.
function fieldsOk(type, message) {
  if (type === 'verification') return nonceOk(message.challenge);
  if (type === 'gap') {
    return hasOwn(message, 'cursor') && (typeof message.cursor === 'string' || message.cursor === null);
  }
  if (type === 'terminated') {
    if (!isObject(message.error)) return false;
    if (!Number.isInteger(message.error.code) || typeof message.error.message !== 'string') return false;
    return !hasOwn(message.error, 'data') || isObject(message.error.data);
  }
  if (!hasOwn(message, 'data')) return false;
  if (hasOwn(message, 'cursor') && !(typeof message.cursor === 'string' || message.cursor === null)) return false;
  return nonEmpty(message.eventId) && nonEmpty(message.name) && nonEmpty(message.timestamp);
}

// R3.1-R3.18, R4.5, R4.6, R7.6: build a receiver from its configuration.
export function createReceiver(config = {}) {
  const window = num(config.window, DEFAULT_WINDOW);
  const maxBody = num(config.max_body, DEFAULT_MAX_BODY);
  const retention = num(config.dedup_retention, DEFAULT_DEDUP);
  const enforce = config.enforce_server_identity === true;
  const serverKid = typeof config.mcp_server_kid === 'string' ? config.mcp_server_kid : null;
  const serverPublicKey = typeof config.mcp_server_public_key === 'string' ? config.mcp_server_public_key : null;
  // R4.5: the raw server key alone still names the kid a jack header must not carry.
  const serverKeyId = serverKid ?? serverKidOf(serverPublicKey);
  const keys = acceptedKeys(config.keys, serverKid, serverPublicKey);
  const requireKeyCheck = config.webhook_key_check === REQUIRE_CHECK;
  const webhookKeyTool = config.webhook_key_tool ?? null;
  const jack = config.jack ?? null;
  const jackWindow = jack === null ? DEFAULT_JACK_WINDOW : num(jack.window, DEFAULT_JACK_WINDOW);
  const entries = secretEntries(config.secrets);
  const routed = new Set(Array.isArray(config.routed) ? config.routed : []);
  const terminated = new Set();
  const accepted = new Map();

  // R3.1-R3.18: one delivery, stopping at the first failing step.
  function handle({ now, headers, body, enqueue = 'ok' } = {}) {
    const raw = bodyBytes(body);
    const all = collectHeaders(headers);
    // R3.1: absence and an empty value list are the same refusal.
    for (const name of REQUIRED) {
      const values = all.get(name);
      if (!values || values.length === 0) return reject('missing_webhook_header');
    }
    // R3.2: a repeated header is refused before any value is read.
    for (const name of REQUIRED) if (all.get(name).length > 1) return reject('duplicate_webhook_header');
    const webhookId = all.get(H_ID)[0];
    const timestamp = all.get(H_TS)[0];
    const subscriptionId = all.get(H_SUB)[0];
    if (!ID_RE.test(webhookId)) return reject('malformed_webhook_id'); // R3.3
    if (!TS_RE.test(timestamp)) return reject('malformed_webhook_timestamp'); // R3.4
    if (!SUB_RE.test(subscriptionId)) return reject('malformed_subscription_id'); // R3.5
    // R3.6: raw length, then the declared length.
    if (raw.length > maxBody) return reject('body_too_large');
    const declared = all.get(H_LEN);
    if (declared && declared.length > 0 && (!LEN_RE.test(declared[0]) || Number(declared[0]) > maxBody)) {
      return reject('body_too_large');
    }
    // R3.7: the one registered secret for the id, else every pending secret of section 5.
    const registered = entries.find((entry) => entry.subscription_id === subscriptionId);
    const candidates = registered ? [registered] : entries.filter((entry) => entry.subscription_id === null);
    const deferred = !registered;
    if (!registered && candidates.length === 0) return reject('unknown_subscription');
    // R3.8: a routed or terminated subscription passes; the deferred path re-checks routing after verification.
    // R3.17: a terminated id is answered only after dedup, so a retry of an accepted message stays a duplicate.
    if (!deferred && !routed.has(subscriptionId) && !terminated.has(subscriptionId)) return reject('subscription_not_routed');
    const parsedHeader = parseSignatureHeader(all.get(H_SIG)[0]); // R3.10
    if (!parsedHeader.ok) return reject(parsedHeader.code);
    const schemes = checkSchemes(parsedHeader.entries); // R3.11
    if (!schemes.ok) return reject(schemes.code);
    const decoded = decodeEntries(parsedHeader.entries); // R3.12
    if (!decoded.ok) return reject(decoded.code);
    const parts = { webhookId, timestamp, body: raw };
    let matched = -1;
    for (let index = 0; index < candidates.length; index += 1) {
      if (v1Verify(decoded.entries, candidates[index].key, parts).ok) {
        matched = index;
        break;
      }
    }
    if (matched === -1) return reject('bad_signature'); // R3.13
    // R3.9: freshness is evaluated only after the HMAC verified.
    const seconds = Number(timestamp);
    if (now - seconds > window) return reject('stale_timestamp');
    if (seconds - now > window) return reject('future_timestamp');
    if (enforce) {
      // R3.14: the asymmetric check runs only when server identity is enforced.
      if (keys.length === 0) return reject('no_server_keys');
      if (!asymVerify(decoded.entries, keys, { ...parts, endpointId: subscriptionId }).ok) {
        return reject('bad_server_signature');
      }
    }
    if (jack) {
      // R3.15: the Jack header is required whenever w1 is configured.
      const values = all.get(H_JACK);
      if (!values || values.length === 0) return reject('missing_jack_auth');
      const callbackUrl = deferred ? candidates[matched].callback_url : jack.callback_urls?.[subscriptionId];
      const options = { keys, now, window: jackWindow, mcpServerKid: serverKeyId };
      const checked = w1Verify(
        values[0],
        { aud: jack.aud, subscriptionId, webhookId, timestamp, callbackUrl, body: raw },
        options,
      );
      if (!checked.ok) return reject(checked.code);
      // R5.6: an entry without a callback url leaves the signature unverifiable.
      if (callbackUrl === undefined) return reject('bad_jack_signature');
    }
    // R7.6: the optional cross-check of the card keys against the native tool result.
    if (requireKeyCheck) {
      const crossed = crossCheckWebhookKey({ keys, toolResult: webhookKeyTool, require: true });
      if (!crossed.ok) return reject(crossed.code);
    }
    // R3.16: an id already answered with a 2xx stays answered while retention holds.
    const seenAt = accepted.get(webhookId);
    if (seenAt !== undefined && now - seenAt <= retention) return done(200, { status: 'duplicate' }, false);
    // R3.18: parse and validate only after every verification step passed.
    const message = parseObject(raw);
    if (message === null) return reject('malformed_body');
    const typed = hasOwn(message, 'type');
    if (typed && !TYPES.has(message.type)) return reject('unknown_envelope_type');
    const type = typed ? message.type : undefined;
    if (!fieldsOk(type, message)) return reject('malformed_body');
    // R3.17: the terminated answer comes after parse, validation and dedup.
    if (terminated.has(subscriptionId)) return reject('subscription_terminated');
    if (enqueue === 'fail') return reject('enqueue_failed');
    // R5.6: only a verification envelope survives the deferred routing check.
    if (deferred && type !== 'verification') return reject('subscription_not_routed');
    accepted.set(webhookId, now);
    if (type === 'verification') {
      // R5.6: the echoed nonce is consumed locally and the pending entry keeps its callback url.
      if (deferred) {
        candidates[matched].subscription_id = subscriptionId;
        routed.add(subscriptionId);
      }
      return done(200, { challenge: message.challenge }, true);
    }
    // R3.17, R8.8: a verified terminated envelope is forwarded and then stops routing.
    if (type === 'terminated') {
      terminated.add(subscriptionId);
      routed.delete(subscriptionId);
    }
    return { status: 200, body: { status: 'accepted' }, delivered: [message], code: null, recorded: true };
  }

  // R3.8: the id is routed on the same receiver, so state recorded by earlier steps stays observable.
  function route(ids) {
    for (const id of Array.isArray(ids) ? ids : []) routed.add(id);
  }

  // R3.1-R3.18: the observable routing, termination, secret and dedup state.
  function snapshot() {
    return {
      routed: [...routed].sort(),
      terminated: [...terminated].sort(),
      secrets: entries.map((entry) => ({
        subscription_id: entry.subscription_id,
        callback_url: entry.callback_url ?? null,
      })),
      accepted: [...accepted.keys()].sort(),
    };
  }

  return { handle, route, snapshot };
}

// R1.8: the four attempt offsets in seconds since t0.
export const RETRY_TIMES = [0, 30, 270, 870];

// R1.7: the classification category of one HTTP status, or null for 2xx.
export function lastErrorOf(status) {
  if (!Number.isInteger(status)) return null;
  if (status >= 200 && status <= 299) return null;
  if (status >= 500 && status <= 599) return 'http_5xx';
  if (status >= 300 && status <= 499) return 'http_4xx';
  return null;
}

// R1.7-R1.9: accept, retry or abandon one attempt; 410 and 413 are final for that delivery only.
export function senderDecision(input = {}) {
  const { status, retryAfter, attempt, t0, responseTime } = input;
  const transport = typeof input.transport === 'string' ? input.transport : null;
  const lastError = transport ?? lastErrorOf(status) ?? 'http_4xx';
  const final = () => ({ action: 'final', lastError });
  if (transport === null) {
    if (Number.isInteger(status) && status >= 200 && status <= 299) return { action: 'accept' };
    if (status === 410 || status === 413) return final();
  }
  const retryable =
    transport !== null ||
    status === 425 ||
    status === 429 ||
    (Number.isInteger(status) && status >= 500 && status <= 599);
  if (!retryable) return final();
  // The fourth attempt is always the last one.
  if (!Number.isInteger(attempt) || attempt >= MAX_ATTEMPTS) return final();
  let nextAt = t0 + RETRY_TIMES[attempt];
  if (Number.isInteger(retryAfter) && retryAfter > 0 && Number.isFinite(responseTime)) {
    const postponed = responseTime + retryAfter;
    if (postponed > nextAt) nextAt = postponed;
  }
  const cap = t0 + RETRY_CAP;
  if (nextAt > cap) nextAt = cap;
  // A capped slot that is already past cannot be retried.
  if (nextAt <= responseTime) return final();
  return { action: 'retry', nextAt, lastError };
}

// R1.8: the four absolute attempt times from t0.
export const retrySchedule = (t0) => RETRY_TIMES.map((delay) => t0 + delay);
