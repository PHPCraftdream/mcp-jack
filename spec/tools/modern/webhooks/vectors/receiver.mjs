// Vectors for spec/06-webhooks.md sections 1, 3, 4 and 5 and rule R7.6
// (R1.1-R1.10, R3.1-R3.18, R4.3, R4.5, R5.6, R7.6).
import {
  b64u,
  createReceiver,
  jwkOf,
  lastErrorOf,
  parseWhsec,
  retrySchedule,
  senderDecision,
  sha256,
  v1Sign,
  v1aSign,
  v2aSign,
  w1Sign,
} from '../reference.mjs';
import { AUD, K, NOW } from '../../../gen/core.mjs';

export const file = 'webhook-receiver-vectors.json';

const SEC_A = `whsec_${sha256('mcp-jack webhook secret: a').subarray(0, 32).toString('base64')}`;
const SEC_B = `whsec_${sha256('mcp-jack webhook secret: b').subarray(0, 32).toString('base64')}`;
const SUB_ID = 'sub_a3f1c8e2b0d49f7e';
const SUB_ID_2 = 'sub_0123456789abcdef';
const ID_EVENT = 'msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const ID_EVENT_2 = 'msg_8Rk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const ID_VERIFY = 'msg_verification_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const ID_TERM = 'msg_terminated_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const HOOK = 'https://hooks.example.test/hooks/alice';
const HOOK_OTHER = 'https://hooks.example.test/hooks/bob';
const STAMP = '2026-01-01T00:00:00Z';
const EVENT = `{"eventId":"evt_1","name":"incident.created","data":{"severity":"P1"}}`;
const EVENT_OTHER = '{"eventId":"evt_2","name":"incident.created","data":{}}';
const GAP = '{"type":"gap","cursor":"cursor_7f3a"}';
const TERM = '{"type":"terminated","error":{"code":-32024,"message":"Forbidden"}}';
const CHALLENGE = b64u(sha256('challenge:1').subarray(0, 16));
const VERIFICATION = `{"type":"verification","challenge":"${CHALLENGE}"}`;
const PAGING = '{"type":"paging"}';
const ARRAY_BODY = '[1]';
const BIG = 'a'.repeat(262145);
const JACK_WINDOW = 30;

const EVENT_MSG = { eventId: 'evt_1', name: 'incident.created', data: { severity: 'P1' } };
const GAP_MSG = { type: 'gap', cursor: 'cursor_7f3a' };
const TERM_MSG = { type: 'terminated', error: { code: -32024, message: 'Forbidden' } };

const JACK = { aud: AUD, window: JACK_WINDOW, callback_urls: { [SUB_ID]: HOOK } };
const JACK_OTHER = { aud: AUD, window: JACK_WINDOW, callback_urls: { [SUB_ID]: HOOK_OTHER } };
// R5.6: a pending entry carries its own callback url, so the URL table may stay empty.
const JACK_EMPTY = { aud: AUD, window: JACK_WINDOW, callback_urls: {} };
const BASE = { secrets: [{ secret: SEC_A, subscription_id: SUB_ID }], routed: [SUB_ID] };
const NOT_ROUTED = { secrets: [{ secret: SEC_A, subscription_id: SUB_ID }], routed: [] };
const PENDING = { secrets: [{ secret: SEC_A, subscription_id: null }], routed: [] };
const PENDING_JACK = {
  secrets: [{ secret: SEC_A, subscription_id: null, callback_url: HOOK }],
  routed: [],
  keys: ['newbie'],
  jack: JACK,
};
const PENDING_JACK_EMPTY = { ...PENDING_JACK, jack: JACK_EMPTY };
const SERVER_KEY = { ...BASE, keys: ['newbie'], jack: JACK, mcp_server_kid: K.svc.kid };
// R7.6: the shape of the `jack.server.webhook_key` tool result.
const webhookKeyTool = (keys) => ({
  webhook_key: { signing_keys: { keys }, egress_ip_ranges: [] },
});

// R1.2, R3.1-R3.18, R4.5, R4.6, R7.6: the closed code, status and message table, restated independently of the reference.
const REJECTIONS = {
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

const rejected = (code) => ({
  status: REJECTIONS[code][0],
  body: { error: { code, message: REJECTIONS[code][1] } },
  delivered: [],
  code,
  recorded: false,
});

const acceptedStep = (delivered) => ({ status: 200, body: { status: 'accepted' }, delivered, code: null, recorded: true });
const duplicateStep = () => ({ status: 200, body: { status: 'duplicate' }, delivered: [], code: null, recorded: false });
const challengeStep = () => ({ status: 200, body: { challenge: CHALLENGE }, delivered: [], code: null, recorded: true });

// R5.6: the snapshot reports one `(subscription id, callback url)` pair per secret entry.
const boundSecret = (entry) => {
  if (typeof entry === 'string') return { subscription_id: entry, callback_url: null };
  if (entry !== null && typeof entry === 'object') {
    return { subscription_id: entry.subscription_id ?? null, callback_url: entry.callback_url ?? null };
  }
  return { subscription_id: null, callback_url: null };
};
const boundSecrets = (...entries) => entries.map(boundSecret);
const finalState = (routed, secrets, accepted, terminated = []) => ({ routed, terminated, secrets, accepted });

const keyBytes = (secret) => {
  const parsed = parseWhsec(secret);
  if (!parsed.ok) throw new Error(`fixture secret rejected (${parsed.reason})`);
  return parsed.key;
};

const signingParts = ({ body, id, ts, subscriptionId }) => ({
  webhookId: id,
  timestamp: String(ts),
  body: Buffer.from(body, 'utf8'),
  endpointId: subscriptionId,
});

// R1.1, R2.8, R3.15: the header array of a correctly signed delivery. `callbackUrl` and
// `jackSubscriptionId` override the `w1` bindings, `jackKey` names the key that signs it.
const delivery = ({
  body,
  id = ID_EVENT,
  ts = NOW,
  secret = SEC_A,
  subscriptionId = SUB_ID,
  jack = null,
  jackKey = null,
  jackSubscriptionId = null,
  callbackUrl = null,
  keys = null,
  signWith = null,
}) => {
  const parts = signingParts({ body, id, ts, subscriptionId });
  let signature = v1Sign(keyBytes(signWith ?? secret), parts);
  if (keys) signature = `${signature} ${v1aSign(K[keys[0]], parts)} ${v2aSign(K[keys[0]], parts)}`;
  const headers = [
    ['webhook-id', id],
    ['webhook-timestamp', String(ts)],
    ['webhook-signature', signature],
    ['X-MCP-Subscription-Id', subscriptionId],
  ];
  if (jack) {
    const keyName = jackKey ?? (keys ? keys[0] : null);
    if (!keyName) throw new Error('a jack header needs a fixture key');
    headers.push([
      'Jack-Webhook-Auth',
      w1Sign(K[keyName], {
        aud: jack.aud,
        subscriptionId: jackSubscriptionId ?? subscriptionId,
        webhookId: id,
        timestamp: String(ts),
        callbackUrl: callbackUrl ?? jack.callback_urls[subscriptionId],
        body: parts.body,
      }),
    ]);
  }
  return headers;
};

const headerValue = (headers, name) => {
  const found = headers.find(([key]) => key.toLowerCase() === name.toLowerCase());
  return found ? found[1] : null;
};

const without = (headers, name) => headers.filter(([key]) => key.toLowerCase() !== name.toLowerCase());
const replacing = (headers, name, value) =>
  headers.map(([key, old]) => [key, key.toLowerCase() === name.toLowerCase() ? value : old]);

const stepOf = (opts, now = NOW) => ({
  now,
  headers: delivery(opts),
  body_text: opts.body,
  ...(opts.enqueue === undefined ? {} : { enqueue: opts.enqueue }),
});
const stepWith = (headers, body, now = NOW) => ({ now, headers, body_text: body });
const stepRepeat = (opts) => ({ now: NOW, headers: delivery(opts), body_repeat: { char: 'a', count: opts.body.length } });
// R3.8: a step that restates the configuration is the same receiver told to route the id since the last attempt.
const afterRouting = (config, step) => ({ ...step, config });

const sequenceCase = (id, rule, description, config, steps, expect) => ({
  id,
  rule,
  description,
  kind: 'sequence',
  input: { config, steps },
  expect,
});

const V1_SIGNATURE = headerValue(delivery({ body: EVENT }), 'webhook-signature');
const V1_B64 = V1_SIGNATURE.slice('v1,'.length);
const V1_TRUNCATED = Buffer.from(V1_B64, 'base64').subarray(0, 16).toString('base64');
const JACK_VALUE = headerValue(delivery({ body: EVENT, keys: ['newbie'], jack: JACK }), 'Jack-Webhook-Auth');

// R1.7: one row per status of the classification table; only 410 and 413 are final by status.
const STATUS_ROWS = [
  [200, { action: 'accept' }],
  [204, { action: 'accept' }],
  [301, { action: 'final', lastError: 'http_4xx' }],
  [404, { action: 'final', lastError: 'http_4xx' }],
  [410, { action: 'final', lastError: 'http_4xx' }],
  [413, { action: 'final', lastError: 'http_4xx' }],
  [425, { action: 'retry', nextAt: NOW + 30, lastError: 'http_4xx' }],
  [429, { action: 'retry', nextAt: NOW + 30, lastError: 'http_4xx' }],
  [500, { action: 'retry', nextAt: NOW + 30, lastError: 'http_5xx' }],
  [502, { action: 'retry', nextAt: NOW + 30, lastError: 'http_5xx' }],
  [503, { action: 'retry', nextAt: NOW + 30, lastError: 'http_5xx' }],
  [504, { action: 'retry', nextAt: NOW + 30, lastError: 'http_5xx' }],
];

// R1.9: the category of a status outside the acceptance range.
const LAST_ERROR_ROWS = [
  [301, 'http_4xx'],
  [410, 'http_4xx'],
  [413, 'http_4xx'],
  [425, 'http_4xx'],
  [500, 'http_5xx'],
];

// R3.18: one otherwise valid, correctly signed body per violated field, each 400 malformed_body.
const FIELD_ROWS = [
  ['rcv-r318-occurrence-missing-event-id', 'an occurrence without eventId fails field validation', `{"name":"incident.created","timestamp":"${STAMP}","data":{}}`],
  ['rcv-r318-occurrence-event-id-not-string', 'an occurrence with a numeric eventId fails field validation', `{"eventId":42,"name":"incident.created","timestamp":"${STAMP}","data":{}}`],
  ['rcv-r318-occurrence-missing-name', 'an occurrence without name fails field validation', `{"eventId":"evt_1","timestamp":"${STAMP}","data":{}}`],
  ['rcv-r318-occurrence-missing-timestamp', 'an occurrence without its timestamp member fails field validation', `{"eventId":"evt_1","name":"incident.created","data":{}}`],
  ['rcv-r318-occurrence-missing-data', 'an occurrence without data fails field validation', `{"eventId":"evt_1","name":"incident.created","timestamp":"${STAMP}"}`],
  ['rcv-r318-occurrence-cursor-bad-type', 'an occurrence whose cursor is a number fails field validation', `{"eventId":"evt_1","name":"incident.created","timestamp":"${STAMP}","data":{},"cursor":5}`],
  ['rcv-r318-gap-missing-cursor', 'a gap envelope without cursor fails field validation', '{"type":"gap"}'],
  ['rcv-r318-terminated-missing-error', 'a terminated envelope without error fails field validation', '{"type":"terminated"}'],
  ['rcv-r318-terminated-code-not-integer', 'a terminated envelope whose error code is the string minus 32024 fails field validation', '{"type":"terminated","error":{"code":"-32024","message":"Forbidden"}}'],
  ['rcv-r318-terminated-data-not-object', 'a terminated envelope whose data is a string fails field validation', '{"type":"terminated","error":{"code":-32024,"message":"Forbidden"},"data":"x"}'],
];

export const cases = [
  sequenceCase('rcv-r11-valid-delivery', 'R1.1', 'a full delivery with jack and a card key is accepted', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepOf({ body: EVENT, keys: ['newbie'], jack: JACK }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r11-minimal-delivery', 'R1.1', 'the four required headers alone carry an accepted delivery', BASE, [
    stepOf({ body: EVENT }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),

  sequenceCase('rcv-r12-raw-body', 'R1.2', 'a raw body of 262145 bytes is refused', BASE, [
    stepRepeat({ body: BIG }),
  ], {
    steps: [rejected('body_too_large')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r12-declared-length', 'R1.2', 'a declared content-length of 262145 is refused before the body is read', BASE, [
    stepWith([...delivery({ body: EVENT }), ['content-length', '262145']], EVENT),
  ], {
    steps: [rejected('body_too_large')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r13-gap', 'R1.3', 'a gap envelope is accepted and forwarded', BASE, [stepOf({ body: GAP })], {
    steps: [acceptedStep([GAP_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r13-terminated', 'R1.3', 'a terminated envelope is accepted, forwarded and stops routing', BASE, [stepOf({ body: TERM })], {
    steps: [acceptedStep([TERM_MSG])],
    final_state: finalState([], boundSecrets(SUB_ID), [ID_EVENT], [SUB_ID]),
  }),
  sequenceCase('rcv-r13-unknown-envelope', 'R1.3', 'a top-level type outside the closed set is refused', BASE, [stepOf({ body: PAGING })], {
    steps: [rejected('unknown_envelope_type')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r13-malformed-body', 'R1.3', 'a body that is not a JSON object is refused', BASE, [stepOf({ body: ARRAY_BODY })], {
    steps: [rejected('malformed_body')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r14-id-too-short', 'R1.4', 'a webhook id of 7 characters violates the grammar', BASE, [
    stepOf({ body: EVENT, id: 'msg_abc' }),
  ], {
    steps: [rejected('malformed_webhook_id')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r14-id-with-dot', 'R1.4', 'a webhook id containing a dot violates the grammar', BASE, [
    stepOf({ body: EVENT, id: 'msg.7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f' }),
  ], {
    steps: [rejected('malformed_webhook_id')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r14-id-too-long', 'R1.4', 'a webhook id of 129 characters violates the grammar', BASE, [
    stepOf({ body: EVENT, id: 'm'.repeat(129) }),
  ], {
    steps: [rejected('malformed_webhook_id')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r33-id-illegal-character', 'R3.3', 'a character outside the id alphabet violates the grammar', BASE, [
    stepOf({ body: EVENT, id: 'msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2!' }),
  ], {
    steps: [rejected('malformed_webhook_id')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r15-ts-leading-zero', 'R1.5', 'a timestamp with a leading zero violates the grammar', BASE, [
    stepOf({ body: EVENT, ts: '0123' }),
  ], {
    steps: [rejected('malformed_webhook_timestamp')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r15-ts-thirteen-digits', 'R1.5', 'a timestamp of 13 digits violates the grammar', BASE, [
    stepOf({ body: EVENT, ts: '1234567890123' }),
  ], {
    steps: [rejected('malformed_webhook_timestamp')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r34-ts-negative', 'R3.4', 'a negative timestamp violates the grammar', BASE, [
    stepOf({ body: EVENT, ts: '-1' }),
  ], {
    steps: [rejected('malformed_webhook_timestamp')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  {
    id: 'rcv-r16-timeout',
    rule: 'R1.6',
    description: 'a response timeout is a retryable timeout category',
    kind: 'sender',
    input: { transport: 'timeout', attempt: 1, t0: NOW, responseTime: NOW },
    expect: { action: 'retry', nextAt: NOW + 30, lastError: 'timeout' },
  },

  ...STATUS_ROWS.map(([status, expect]) => ({
    id: `rcv-r17-status-${status}`,
    rule: 'R1.7',
    description: `a ${status} answer is classified to one sender outcome`,
    kind: 'sender',
    input: { status, attempt: 1, t0: NOW, responseTime: NOW },
    expect,
  })),

  {
    id: 'rcv-r18-schedule',
    rule: 'R1.8',
    description: 'the four attempt times are 0, 30, 270 and 870 seconds after t0',
    kind: 'schedule',
    input: { t0: NOW },
    expect: { times: [NOW, NOW + 30, NOW + 270, NOW + 870] },
  },
  {
    id: 'rcv-r18-retry-after',
    rule: 'R1.8',
    description: 'a retry-after of 120 postpones the second attempt to t0 plus 120',
    kind: 'sender',
    input: { status: 503, retryAfter: 120, attempt: 1, t0: NOW, responseTime: NOW },
    expect: { action: 'retry', nextAt: NOW + 120, lastError: 'http_5xx' },
  },
  {
    id: 'rcv-r18-retry-after-cap',
    rule: 'R1.8',
    description: 'a retry-after of 1000 is capped at t0 plus 900',
    kind: 'sender',
    input: { status: 503, retryAfter: 1000, attempt: 1, t0: NOW, responseTime: NOW },
    expect: { action: 'retry', nextAt: NOW + 900, lastError: 'http_5xx' },
  },
  {
    id: 'rcv-r18-fourth-attempt',
    rule: 'R1.8',
    description: 'the fourth attempt is the last one and abandons the message',
    kind: 'sender',
    input: { status: 500, attempt: 4, t0: NOW, responseTime: NOW + 870 },
    expect: { action: 'final', lastError: 'http_5xx' },
  },

  ...LAST_ERROR_ROWS.map(([status, lastError]) => ({
    id: `rcv-r19-last-error-${status}`,
    rule: 'R1.9',
    description: `a ${status} answer records the ${lastError} category`,
    kind: 'last-error',
    input: { status },
    expect: { lastError },
  })),
  {
    id: 'rcv-r19-connection-refused',
    rule: 'R1.9',
    description: 'a refused connection is retryable under its own category',
    kind: 'sender',
    input: { transport: 'connection_refused', attempt: 1, t0: NOW, responseTime: NOW },
    expect: { action: 'retry', nextAt: NOW + 30, lastError: 'connection_refused' },
  },

  sequenceCase('rcv-r110-ack-after-enqueue', 'R1.10', 'the 2xx follows an enqueue, so the first accepted delivery already carries the message', BASE, [
    stepOf({ body: EVENT }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r110-enqueue-fail', 'R1.10', 'a failed durable enqueue is a retryable 503 that records nothing, and the redelivery is accepted once', BASE, [
    stepOf({ body: EVENT, enqueue: 'fail' }),
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('enqueue_failed'), acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),

  sequenceCase('rcv-r31-missing-signature', 'R3.1', 'an absent signature header is refused before any value is read', BASE, [
    stepWith(without(delivery({ body: EVENT }), 'webhook-signature'), EVENT),
  ], {
    steps: [rejected('missing_webhook_header')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r32-duplicate-id', 'R3.2', 'a repeated webhook id is refused', BASE, [
    stepWith([...delivery({ body: EVENT }), ['webhook-id', ID_EVENT]], EVENT),
  ], {
    steps: [rejected('duplicate_webhook_header')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r35-subscription-id-uppercase', 'R3.5', 'an uppercase hex subscription id violates the grammar', BASE, [
    stepOf({ body: EVENT, subscriptionId: 'sub_0123456789ABCDEF' }),
  ], {
    steps: [rejected('malformed_subscription_id')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r36-declared-length', 'R3.6', 'a declared content-length of one mebibyte is refused', BASE, [
    stepWith([...delivery({ body: EVENT }), ['content-length', '1048576']], EVENT),
  ], {
    steps: [rejected('body_too_large')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r37-unknown-subscription', 'R3.7', 'a registered secret for another subscription id leaves no candidate', { secrets: [{ secret: SEC_A, subscription_id: SUB_ID_2 }], routed: [] }, [
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('unknown_subscription')],
    final_state: finalState([], boundSecrets(SUB_ID_2), []),
  }),
  sequenceCase('rcv-r38-not-routed', 'R3.8', 'a registered subscription that is not routed is retryable', NOT_ROUTED, [
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('subscription_not_routed')],
    final_state: finalState([], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r38-not-routed-then-retry', 'R3.8', 'a 503 for an unrouted id records nothing, so the retried copy is accepted once routing is on', NOT_ROUTED, [
    stepOf({ body: EVENT }),
    afterRouting(BASE, stepOf({ body: EVENT, ts: NOW + 1 }, NOW + 1)),
  ], {
    steps: [rejected('subscription_not_routed'), acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),

  sequenceCase('rcv-r39-stale-timestamp', 'R3.9', 'a timestamp 301 seconds old is stale', BASE, [
    stepOf({ body: EVENT, ts: NOW - 301 }),
  ], {
    steps: [rejected('stale_timestamp')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r39-future-timestamp', 'R3.9', 'a timestamp 301 seconds ahead is in the future', BASE, [
    stepOf({ body: EVENT, ts: NOW + 301 }),
  ], {
    steps: [rejected('future_timestamp')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r39-freshness-boundary', 'R3.9', 'a timestamp exactly 300 seconds old is inside the window', BASE, [
    stepOf({ body: EVENT, ts: NOW - 300 }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r39-stale-and-bad-signature', 'R3.9', 'the HMAC runs before freshness, so stale and badly signed answers bad_signature', BASE, [
    stepOf({ body: EVENT, ts: NOW - 301, signWith: SEC_B }),
  ], {
    steps: [rejected('bad_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r310-trailing-space', 'R3.10', 'a trailing space on the signature header is malformed', BASE, [
    stepWith(replacing(delivery({ body: EVENT }), 'webhook-signature', `${V1_SIGNATURE} `), EVENT),
  ], {
    steps: [rejected('malformed_signature_header')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r311-scheme-v9', 'R3.11', 'an unknown signature scheme is unsupported', BASE, [
    stepWith(replacing(delivery({ body: EVENT }), 'webhook-signature', `v9,${V1_B64}`), EVENT),
  ], {
    steps: [rejected('unsupported_signature_scheme')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r312-truncated-value', 'R3.12', 'a v1 value cut to 16 bytes does not decode to 32 bytes', BASE, [
    stepWith(replacing(delivery({ body: EVENT }), 'webhook-signature', `v1,${V1_TRUNCATED}`), EVENT),
  ], {
    steps: [rejected('malformed_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r313-wrong-secret', 'R3.13', 'a signature over a secret that is not the registered one fails', BASE, [
    stepOf({ body: EVENT, signWith: SEC_B }),
  ], {
    steps: [rejected('bad_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r314-wrong-server-key', 'R3.14', 'an asymmetric pair from an unpublished key fails enforcement', { ...BASE, enforce_server_identity: true, keys: ['newbie3'] }, [
    stepOf({ body: EVENT, keys: ['newbie'] }),
  ], {
    steps: [rejected('bad_server_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r314-no-server-keys', 'R3.14', 'enforcement with an empty accepted key set is no_server_keys', { ...BASE, enforce_server_identity: true, keys: [] }, [
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('no_server_keys')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r315-missing-jack', 'R3.15', 'a configured jack header that is absent is refused', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepOf({ body: EVENT, keys: ['newbie'] }),
  ], {
    steps: [rejected('missing_jack_auth')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-malformed-jack', 'R3.15', 'a jack header with scheme w2 is malformed', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepWith(replacing(delivery({ body: EVENT, keys: ['newbie'], jack: JACK }), 'Jack-Webhook-Auth', JACK_VALUE.replace(/^w1 /, 'w2 ')), EVENT),
  ], {
    steps: [rejected('malformed_jack_auth')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-unknown-key', 'R3.15', 'a jack kid outside the accepted card keys is unknown', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepOf({ body: EVENT, keys: ['newbie3'], jack: JACK }),
  ], {
    steps: [rejected('unknown_webhook_key')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-jack-window', 'R3.15', 'a jack timestamp 31 seconds old is outside the 30 second window', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepOf({ body: EVENT, ts: NOW - 31, keys: ['newbie'], jack: JACK }),
  ], {
    steps: [rejected('jack_timestamp_out_of_window')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-other-callback', 'R3.15', 'a jack signature over another callback url does not verify', { ...BASE, keys: ['newbie'], jack: JACK }, [
    stepOf({ body: EVENT, keys: ['newbie'], jack: JACK_OTHER }),
  ], {
    steps: [rejected('bad_jack_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-server-key-kid', 'R4.5', 'a jack header naming the configured MCP server key is refused before the key lookup', SERVER_KEY, [
    stepOf({ body: EVENT, keys: ['newbie'], jack: JACK, jackKey: 'svc' }),
  ], {
    steps: [rejected('webhook_key_is_server_key')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r315-dedicated-key-accepted', 'R4.5', 'the dedicated webhook key is accepted while the server key id is configured as forbidden', SERVER_KEY, [
    stepOf({ body: EVENT, keys: ['newbie'], jack: JACK }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r315-pending-jack-other-url', 'R3.15', 'on the pending path w1 binds the entry callback url, so another url does not verify', PENDING_JACK_EMPTY, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY, keys: ['newbie'], jack: JACK_EMPTY, callbackUrl: HOOK_OTHER, subscriptionId: SUB_ID }),
  ], {
    steps: [rejected('bad_jack_signature')],
    final_state: finalState([], boundSecrets({ subscription_id: null, callback_url: HOOK }), []),
  }),
  sequenceCase('rcv-r315-pending-jack-other-subscription', 'R3.15', 'on the pending path w1 binds the header subscription id, so a signature over another id does not verify', PENDING_JACK_EMPTY, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY, keys: ['newbie'], jack: JACK_EMPTY, jackSubscriptionId: SUB_ID_2, callbackUrl: HOOK }),
  ], {
    steps: [rejected('bad_jack_signature')],
    final_state: finalState([], boundSecrets({ subscription_id: null, callback_url: HOOK }), []),
  }),
  sequenceCase('rcv-r315-pending-jack-missing', 'R3.15', 'a configured key makes an absent jack header missing_jack_auth even on the pending path', PENDING_JACK_EMPTY, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY, keys: ['newbie'] }),
  ], {
    steps: [rejected('missing_jack_auth')],
    final_state: finalState([], boundSecrets({ subscription_id: null, callback_url: HOOK }), []),
  }),

  sequenceCase('rcv-r316-duplicate-answer', 'R3.16', 'an id already answered with a 2xx is answered duplicate with no forwarding', BASE, [
    stepOf({ body: EVENT }),
    stepOf({ body: EVENT }),
  ], {
    steps: [acceptedStep([EVENT_MSG]), duplicateStep()],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r316-duplicate-retry', 'R3.16', 'a redelivery under the same webhook-id with a fresh timestamp is duplicate', BASE, [
    stepOf({ body: EVENT }),
    stepOf({ body: EVENT, ts: NOW + 1 }, NOW + 1),
  ], {
    steps: [acceptedStep([EVENT_MSG]), duplicateStep()],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r316-duplicate-different-body', 'R3.16', 'dedup is by webhook-id only, so another body under the same id is still duplicate', BASE, [
    stepOf({ body: EVENT }),
    stepOf({ body: EVENT_OTHER, ts: NOW + 2 }, NOW + 2),
  ], {
    steps: [acceptedStep([EVENT_MSG]), duplicateStep()],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),

  sequenceCase('rcv-r317-challenge-echo', 'R3.17', 'a verification envelope is answered with exactly its challenge', BASE, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY }),
  ], {
    steps: [challengeStep()],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_VERIFY]),
  }),
  sequenceCase('rcv-r317-error-body', 'R3.17', 'a failure is answered with exactly the code and message pair', BASE, [
    stepOf({ body: EVENT, signWith: SEC_B }),
  ], {
    steps: [rejected('bad_signature')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),

  sequenceCase('rcv-r318-gap-forward', 'R3.18', 'a gap envelope body is forwarded unchanged', BASE, [stepOf({ body: GAP })], {
    steps: [acceptedStep([GAP_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r318-terminated-forward', 'R3.18', 'a terminated envelope body is forwarded unchanged', BASE, [stepOf({ body: TERM })], {
    steps: [acceptedStep([TERM_MSG])],
    final_state: finalState([], boundSecrets(SUB_ID), [ID_EVENT], [SUB_ID]),
  }),
  sequenceCase('rcv-r318-malformed-body', 'R3.18', 'a body that is not a JSON object is refused after verification', BASE, [stepOf({ body: ARRAY_BODY })], {
    steps: [rejected('malformed_body')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r318-terminated-stops-routing', 'R3.17', 'a terminated envelope with an integer code is forwarded once, then every later delivery for the id is 410', BASE, [
    stepOf({ body: EVENT }),
    stepOf({ body: TERM, id: ID_TERM, ts: NOW + 1 }, NOW + 1),
    stepOf({ body: EVENT, id: ID_EVENT_2, ts: NOW + 2 }, NOW + 2),
  ], {
    steps: [acceptedStep([EVENT_MSG]), acceptedStep([TERM_MSG]), rejected('subscription_terminated')],
    final_state: finalState([], boundSecrets(SUB_ID), [ID_EVENT, ID_TERM], [SUB_ID]),
  }),

  ...FIELD_ROWS.map(([id, description, body]) => sequenceCase(id, 'R3.18', description, BASE, [stepOf({ body })], {
    steps: [rejected('malformed_body')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  })),

  sequenceCase('rcv-r56-pending-secret-binds', 'R5.6', 'a pending secret answers the verification and is bound to the header id', PENDING, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY }),
    stepOf({ body: EVENT }),
  ], {
    steps: [challengeStep(), acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT, ID_VERIFY]),
  }),
  sequenceCase('rcv-r56-pending-wrong-secret', 'R5.6', 'a pending secret that does not verify is bad_signature, never unknown_subscription', PENDING, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY, signWith: SEC_B }),
  ], {
    steps: [rejected('bad_signature')],
    final_state: finalState([], boundSecrets(null), []),
  }),
  sequenceCase('rcv-r56-pending-challenge-json-config', 'R5.6', 'the same pending handshake survives a configuration that was copied through JSON', JSON.parse(JSON.stringify(PENDING)), [
    stepOf({ body: VERIFICATION, id: ID_VERIFY }),
    stepOf({ body: EVENT }),
  ], {
    steps: [challengeStep(), acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT, ID_VERIFY]),
  }),
  sequenceCase('rcv-r56-pending-challenge-with-jack', 'R5.6', 'the challenge and the occurrence are signed with w1 over the pending entry callback url and the header id', PENDING_JACK, [
    stepOf({ body: VERIFICATION, id: ID_VERIFY, keys: ['newbie'], jack: JACK }),
    stepOf({ body: EVENT, keys: ['newbie'], jack: JACK }),
  ], {
    steps: [challengeStep(), acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets({ subscription_id: SUB_ID, callback_url: HOOK }), [ID_EVENT, ID_VERIFY]),
  }),

  sequenceCase('rcv-r76-agree', 'R7.6', 'a required webhook key cross-check passes when the tool result carries the card key', { ...BASE, keys: ['newbie'], webhook_key_check: 'require', webhook_key_tool: webhookKeyTool([jwkOf(K.newbie)]) }, [
    stepOf({ body: EVENT }),
  ], {
    steps: [acceptedStep([EVENT_MSG])],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), [ID_EVENT]),
  }),
  sequenceCase('rcv-r76-mismatch', 'R7.6', 'a tool result carrying another key disagrees with the card', { ...BASE, keys: ['newbie'], webhook_key_check: 'require', webhook_key_tool: webhookKeyTool([jwkOf(K.newbie2)]) }, [
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('webhook_key_mismatch')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
  sequenceCase('rcv-r76-missing', 'R7.6', 'a required cross-check with no tool result is webhook_key_missing', { ...BASE, keys: ['newbie'], webhook_key_check: 'require', webhook_key_tool: null }, [
    stepOf({ body: EVENT }),
  ], {
    steps: [rejected('webhook_key_missing')],
    final_state: finalState([SUB_ID], boundSecrets(SUB_ID), []),
  }),
];

// The receiver configuration of one sequence, with fixture key names resolved to the card key pair.
const configOf = (config = {}) => ({
  ...config,
  keys: Array.isArray(config.keys) ? config.keys.map((name) => ({ kid: K[name].kid, pub: K[name].pub })) : [],
});

const bodyOf = (step) => {
  if (typeof step.body_text === 'string') return step.body_text;
  if (typeof step.body_b64u === 'string') return Buffer.from(step.body_b64u, 'base64url');
  const repeat = step.body_repeat;
  if (repeat && typeof repeat.char === 'string' && Number.isInteger(repeat.count)) return repeat.char.repeat(repeat.count);
  return '';
};

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'sequence': {
      let receiver = createReceiver(configOf(input.config));
      const steps = input.steps.map((step) => {
        // R3.8: a step that restates the configuration is the receiver told to route the id since the last attempt.
        if (step.config !== undefined) receiver = createReceiver(configOf(step.config));
        const out = receiver.handle({
          now: step.now,
          headers: step.headers,
          body: bodyOf(step),
          enqueue: step.enqueue ?? 'ok',
        });
        return {
          status: out.status,
          body: out.body,
          delivered: out.delivered,
          code: out.code,
          recorded: out.recorded,
        };
      });
      return { steps, final_state: receiver.snapshot() };
    }
    case 'sender':
      return senderDecision(input);
    case 'last-error':
      return { lastError: lastErrorOf(input.status) };
    case 'schedule':
      return { times: retrySchedule(input.t0) };
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}
