// Vectors for spec/06-webhooks.md section 4 (R4.1-R4.6).
import { createHash, createPublicKey, sign } from 'node:crypto';
import { b64u, parseW1Header, w1Sign, w1SigningString, w1Verify } from '../reference.mjs';
import { AUD, K, NOW } from '../../../gen/core.mjs';

// Independent expectation: the same w1 bytes rebuilt straight from node:crypto,
// so the KAT does not take its header from the implementation it checks.
const B = (s) => Buffer.from(s, 'utf8');
const b64uLocal = (buf) => Buffer.from(buf).toString('base64url');
const publicBytes = (priv) => createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
const signingString = ({ aud, subscriptionId, webhookId, timestamp, callbackUrl, body }) =>
  ['mcp-jack/webhook1/delivery', aud, subscriptionId, webhookId, String(timestamp), callbackUrl,
   b64uLocal(createHash('sha256').update(body).digest())].join('\n');
const w1Direct = (priv, parts) =>
  `w1 kid=${b64uLocal(createHash('sha256').update(publicBytes(priv)).digest())},sig=${b64uLocal(sign(null, B(signingString(parts)), priv))}`;

export const file = 'webhook-w1-vectors.json';

const ID_EVENT = 'msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const SUB_ID = 'sub_a3f1c8e2b0d49f7e';
const SUB_ID_2 = 'sub_0123456789abcdef';
const HOOK = 'https://hooks.example.test/hooks/alice';
const HOOK_2 = 'https://hooks.example.test:8443/hooks/alice?tenant=1';
const BODY_ASCII = '{"eventId":"evt_1","name":"incident.created","data":{"severity":"P1"}}';
const BODY_UNICODE = '{"name":"café — 世界","data":{"note":"line\\n"}}\n';
const WINDOW = 30;
const KID_LEN = 43;

const claim = (over = {}) => ({
  aud: AUD,
  subscription_id: SUB_ID,
  webhook_id: ID_EVENT,
  webhook_timestamp: NOW,
  callback_url: HOOK,
  bodyText: BODY_ASCII,
  ...over,
});

const partsOf = (claimOf) => ({
  aud: claimOf.aud,
  subscriptionId: claimOf.subscription_id,
  webhookId: claimOf.webhook_id,
  timestamp: claimOf.webhook_timestamp,
  callbackUrl: claimOf.callback_url,
  body: Buffer.from(claimOf.bodyText, 'utf8'),
});

const wireOf = (claimOf) => ({
  aud: claimOf.aud,
  subscription_id: claimOf.subscription_id,
  webhook_id: claimOf.webhook_id,
  webhook_timestamp: claimOf.webhook_timestamp,
  callback_url: claimOf.callback_url,
  body_b64u: b64u(Buffer.from(claimOf.bodyText, 'utf8')),
});

const headerFor = (claimOf, key = 'newbie') => w1Sign(K[key], partsOf(claimOf));

const serverKidInput = (serverKid) => (serverKid === undefined ? {} : { mcp_server_kid: serverKid });

const katCase = (id, rule, description, claimOf) => {
  const parts = partsOf(claimOf);
  return {
    id,
    rule,
    description,
    kind: 'kat-w1',
    input: { key: 'newbie', ...wireOf(claimOf) },
    expect: { result: 'accept', header: w1Direct(K.newbie, parts), signing_string_b64u: b64uLocal(B(signingString(parts))) },
  };
};

const verifyCase = (id, rule, description, { header, sent, keys, now = NOW, serverKid }) => ({
  id,
  rule,
  description,
  kind: 'verify-w1',
  input: { now, window: WINDOW, keys, header, parts: wireOf(sent), ...serverKidInput(serverKid) },
  expect: { result: 'accept' },
});

const rejectCase = (id, rule, description, { header, sent, keys, code, now = NOW, serverKid }) => ({
  id,
  rule,
  description,
  kind: 'verify-w1',
  input: { now, window: WINDOW, keys, header, parts: wireOf(sent), ...serverKidInput(serverKid) },
  expect: { result: 'reject', code },
});

const honest = claim();
const HONEST_HEADER = headerFor(honest);

const kidOf = (header) => {
  const parsed = parseW1Header(header);
  if (!parsed.ok) throw new Error('the base w1 header must parse');
  return parsed.kid;
};
const sigOf = (header) => header.slice(header.indexOf('sig=') + 'sig='.length);
const KID = kidOf(HONEST_HEADER);

export const cases = [
  katCase('w1-kat-basic', 'R4.2', 'the seven-line signing string and its Ed25519 signature over an ASCII body', claim()),
  katCase('w1-kat-unicode-body', 'R4.2', 'the body hash covers the raw UTF-8 bytes including a trailing LF', claim({ bodyText: BODY_UNICODE })),

  verifyCase('w1-accept', 'R4.3', 'a delivery signed for the configured audience, subscription and url verifies', { header: HONEST_HEADER, sent: honest, keys: ['newbie'] }),

  rejectCase('w1-neg-aud', 'R4.3', 'a delivery replayed at another audience does not verify', { header: HONEST_HEADER, sent: claim({ aud: 'https://other.example.test' }), keys: ['newbie'], code: 'bad_jack_signature' }),
  rejectCase('w1-neg-subscription', 'R4.3', 'a delivery replayed at another subscription id does not verify', { header: HONEST_HEADER, sent: claim({ subscription_id: SUB_ID_2 }), keys: ['newbie'], code: 'bad_jack_signature' }),
  rejectCase('w1-neg-webhook-id', 'R4.3', 'a changed webhook-id does not verify', { header: HONEST_HEADER, sent: claim({ webhook_id: 'msg_0Rk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f' }), keys: ['newbie'], code: 'bad_jack_signature' }),
  rejectCase('w1-neg-timestamp', 'R4.3', 'a changed webhook-timestamp inside the window still does not verify', { header: HONEST_HEADER, sent: claim({ webhook_timestamp: NOW - 1 }), keys: ['newbie'], code: 'bad_jack_signature' }),
  rejectCase('w1-neg-callback-url', 'R4.3', 'a callback url differing in port and query does not verify', { header: HONEST_HEADER, sent: claim({ callback_url: HOOK_2 }), keys: ['newbie'], code: 'bad_jack_signature' }),
  rejectCase('w1-neg-body', 'R4.2', 'a body with one added trailing space changes the body hash', { header: HONEST_HEADER, sent: claim({ bodyText: `${BODY_ASCII} ` }), keys: ['newbie'], code: 'bad_jack_signature' }),

  rejectCase('w1-neg-kid', 'R4.5', 'a kid outside the accepted key set is unknown', { header: headerFor(honest, 'newbie3'), sent: honest, keys: ['newbie'], code: 'unknown_webhook_key' }),
  rejectCase('w1-neg-server-key', 'R4.5', 'the MCP server response key id is never an accepted webhook key', { header: headerFor(honest, 'svc'), sent: honest, keys: ['newbie'], code: 'unknown_webhook_key' }),
  rejectCase('w1-server-key-kid', 'R4.5', 'the configured MCP server key id is refused as a webhook key', { header: headerFor(honest, 'svc'), sent: honest, keys: ['newbie'], code: 'webhook_key_is_server_key', serverKid: K.svc.kid }),
  verifyCase('w1-dedicated-key-accepted', 'R4.5', 'the dedicated webhook key is accepted while the server key id is configured as forbidden', { header: HONEST_HEADER, sent: honest, keys: ['newbie'], serverKid: K.svc.kid }),

  rejectCase('w1-neg-window-past', 'R4.4', 'a timestamp 31 seconds old is outside the Jack window', { header: headerFor(claim({ webhook_timestamp: NOW - 31 })), sent: claim({ webhook_timestamp: NOW - 31 }), keys: ['newbie'], code: 'jack_timestamp_out_of_window' }),
  rejectCase('w1-neg-window-future', 'R4.4', 'a timestamp 31 seconds ahead is outside the Jack window', { header: headerFor(claim({ webhook_timestamp: NOW + 31 })), sent: claim({ webhook_timestamp: NOW + 31 }), keys: ['newbie'], code: 'jack_timestamp_out_of_window' }),
  verifyCase('w1-window-boundary', 'R4.4', 'a timestamp exactly 30 seconds old is accepted', { header: headerFor(claim({ webhook_timestamp: NOW - 30 })), sent: claim({ webhook_timestamp: NOW - 30 }), keys: ['newbie'] }),

  rejectCase('w1-neg-rotation-old-key', 'R4.5', 'a header from the rotation predecessor is unknown while only the current key is accepted', { header: headerFor(honest, 'newbie2'), sent: honest, keys: ['newbie'], code: 'unknown_webhook_key' }),

  rejectCase('w1-malformed-scheme', 'R4.1', 'a scheme other than w1 is malformed', { header: `w2 ${HONEST_HEADER.slice(3)}`, sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),
  rejectCase('w1-malformed-no-space', 'R4.1', 'the scheme must be followed by exactly one space', { header: `w1${HONEST_HEADER.slice(3)}`, sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),
  rejectCase('w1-malformed-param-set', 'R4.1', 'a parameter outside kid and sig is malformed', { header: `${HONEST_HEADER},ts=1`, sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),
  rejectCase('w1-malformed-duplicate-param', 'R4.1', 'a repeated parameter is malformed', { header: `${HONEST_HEADER},kid=${KID}`, sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),
  rejectCase('w1-malformed-short-kid', 'R4.1', 'a kid of 42 characters is malformed', { header: HONEST_HEADER.replace(KID, KID.slice(0, KID_LEN - 1)), sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),
  rejectCase('w1-malformed-sig-chars', 'R4.1', 'a signature with a character outside base64url is malformed', { header: `w1 kid=${KID},sig=+${sigOf(HONEST_HEADER).slice(1)}`, sent: honest, keys: ['newbie'], code: 'malformed_jack_auth' }),

  rejectCase('w1-missing', 'R4.6', 'a configured key makes an absent header missing_jack_auth', { header: null, sent: honest, keys: ['newbie'], code: 'missing_jack_auth' }),
  verifyCase('w1-rotation-accept', 'R4.6', 'the rotation predecessor still verifies while both keys are published', { header: headerFor(honest, 'newbie2'), sent: honest, keys: ['newbie', 'newbie2'] }),
];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'kat-w1': {
      const parts = {
        aud: input.aud,
        subscriptionId: input.subscription_id,
        webhookId: input.webhook_id,
        timestamp: input.webhook_timestamp,
        callbackUrl: input.callback_url,
        body: Buffer.from(input.body_b64u, 'base64url'),
      };
      return {
        result: 'accept',
        header: w1Sign(K[input.key], parts),
        signing_string_b64u: b64u(w1SigningString(parts)),
      };
    }
    case 'verify-w1': {
      if (input.header === null || input.header === undefined) return { result: 'reject', code: 'missing_jack_auth' };
      const wire = input.parts;
      const parts = {
        aud: wire.aud,
        subscriptionId: wire.subscription_id,
        webhookId: wire.webhook_id,
        timestamp: wire.webhook_timestamp,
        callbackUrl: wire.callback_url,
        body: Buffer.from(wire.body_b64u, 'base64url'),
      };
      const decided = w1Verify(input.header, parts, {
        keys: input.keys.map((name) => K[name]),
        now: input.now,
        window: input.window,
        mcpServerKid: input.mcp_server_kid ?? null,
      });
      return decided.ok ? { result: 'accept' } : { result: 'reject', code: decided.code };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}
