// Vectors for spec/06-webhooks.md section 2 (R2.1-R2.8) with the section 3 steps R3.9 and R3.11-R3.14.
import { createHash, createHmac, sign } from 'node:crypto';
import {
  asymVerify,
  b64StdEncode,
  b64u,
  checkSchemes,
  decodeEntries,
  ed25519KeyFromSeed,
  emissionHeader,
  parseSignatureHeader,
  parseWhsec,
  v1Content,
  v1Sign,
  v1Verify,
  v1aContent,
  v1aSign,
  v2aContent,
  v2aSign,
} from '../reference.mjs';
import { K, NOW } from '../../../gen/core.mjs';

export const file = 'webhook-signature-vectors.json';

const SW_SOURCE = 'https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md';
const ID_EVENT = 'msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f';
const SUB_ID = 'sub_a3f1c8e2b0d49f7e';
const BODY_ASCII = '{"eventId":"evt_1","name":"incident.created","data":{"severity":"P1"}}';
const BODY_ASCII_LF = `${BODY_ASCII}\n`;
const BODY_ASCII_SPACED = '{"eventId":"evt_1", "name":"incident.created","data":{"severity":"P1"}}';
const BODY_UNICODE = '{"name":"café — 世界","data":{"note":"line\\n"}}\n';
const WINDOW = 300;
const PREFIX_LEN = 'whsec_'.length;
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// Fixture secrets are hash expansions, so a byte count above the 32 bytes of one digest is not silently capped.
const expand = (label, bytes) => {
  const blocks = [];
  for (let counter = 0; Buffer.concat(blocks).length < bytes; counter += 1) {
    blocks.push(createHash('sha256').update(`mcp-jack webhook secret: ${label}:${counter}`, 'utf8').digest());
  }
  return Buffer.concat(blocks).subarray(0, bytes);
};
const secretOf = (label, bytes) => `whsec_${expand(label, bytes).toString('base64')}`;
const SEC_A = secretOf('a', 32);
const SEC_B = secretOf('b', 32);
const SEC_23 = secretOf('s23', 23);
const SEC_24 = secretOf('s24', 24);
const SEC_64 = secretOf('s64', 64);
const SEC_65 = secretOf('s65', 65);

// The expectations below are built with node:crypto directly, never with the reference under test.
const B = (s) => Buffer.from(s, 'utf8');
const b64Std = (buf) => Buffer.from(buf).toString('base64');
const b64uLocal = (buf) => Buffer.from(buf).toString('base64url');
const hmacV1 = (secretValue, id, ts, body) =>
  `v1,${b64Std(createHmac('sha256', Buffer.from(secretValue.slice('whsec_'.length), 'base64')).update(B(`${id}.${ts}.`)).update(body).digest())}`;
const v1aEntry = (priv, id, ts, body) => `v1a,${b64Std(sign(null, Buffer.concat([B(`${id}.${ts}.`), body]), priv))}`;
const v2aEntry = (priv, endpointId, id, ts, body) =>
  `v2a,${b64Std(sign(null, createHash('sha256').update(B(`${endpointId}.${id}.${ts}.`)).update(body).digest(), priv))}`;
const v1ContentBytes = (id, ts, body) => Buffer.concat([B(`${id}.${ts}.`), body]);
const v2aDigest = (endpointId, id, ts, body) =>
  createHash('sha256').update(B(`${endpointId}.${id}.${ts}.`)).update(body).digest();

const bytesOf = (whsec) => {
  const parsed = parseWhsec(whsec);
  if (!parsed.ok) throw new Error(`secret fixture rejected (${parsed.reason})`);
  return parsed.key;
};
const keyB64u = (whsec) => b64u(bytesOf(whsec));
const bodyBytes = (text) => Buffer.from(text, 'utf8');
const katInput = (bodyText) => ({ webhook_id: ID_EVENT, webhook_timestamp: NOW, body_b64u: b64u(bodyBytes(bodyText)) });

const partsOf = ({ webhook_id, webhook_timestamp, body_b64u, endpoint_id }) => ({
  webhookId: webhook_id,
  timestamp: String(webhook_timestamp),
  body: Buffer.from(body_b64u, 'base64url'),
  endpointId: endpoint_id,
});

const claimParts = ({ bodyText = BODY_ASCII, timestamp = NOW, webhookId = ID_EVENT } = {}) => ({
  webhookId,
  timestamp: String(timestamp),
  body: bodyBytes(bodyText),
  endpointId: SUB_ID,
});

const v1Header = (secret, over) => v1Sign(bytesOf(secret), claimParts(over));
const asymHeader = (name, over) => {
  const parts = claimParts(over);
  return `${v1aSign(K[name], parts)} ${v2aSign(K[name], parts)}`;
};

const envelopeOf = ({ signature_header, bodyText = BODY_ASCII, timestamp = NOW }) => ({
  webhook_id: ID_EVENT,
  webhook_timestamp: timestamp,
  signature_header,
  body_b64u: b64u(bodyBytes(bodyText)),
  endpoint_id: SUB_ID,
});

const verifyInput = ({
  signature_header,
  bodyText = BODY_ASCII,
  timestamp = NOW,
  secrets = [SEC_A],
  keys = [],
  enforce = 'none',
}) => ({
  now: NOW,
  window: WINDOW,
  enforce,
  keys,
  secrets,
  envelope: envelopeOf({ signature_header, bodyText, timestamp }),
});

const emissionHeaderOf = (input) =>
  emissionHeader({
    ...partsOf(input),
    secrets: input.secrets.map((entry) => ({ secret: bytesOf(entry.secret), current: entry.current })),
    keys: input.keys.map((entry) => ({ key: K[entry.key], current: entry.current })),
  });

const schemesOf = (header) => {
  const parsed = parseSignatureHeader(header);
  if (!parsed.ok) throw new Error('an emitted header must parse as a signature header');
  return parsed.entries.map((entry) => entry.scheme);
};

const emissionInput = (secrets, keys) => ({
  secrets,
  keys,
  webhook_id: ID_EVENT,
  webhook_timestamp: NOW,
  body_b64u: b64u(bodyBytes(BODY_ASCII)),
  endpoint_id: SUB_ID,
});

// R2.8 order: current v1, previous v1, current v1a then v2a, previous v1a then v2a.
const emissionExpectation = (input) => {
  const body = Buffer.from(input.body_b64u, 'base64url');
  const id = input.webhook_id;
  const endpointId = input.endpoint_id;
  const ts = String(input.webhook_timestamp);
  const currentSecret = input.secrets.find((entry) => entry.current === true);
  const previousSecret = input.secrets.find((entry) => entry.current !== true);
  const currentKey = input.keys.find((entry) => entry.current === true);
  const previousKey = input.keys.find((entry) => entry.current !== true);
  const pairOf = (entry) => [v1aEntry(K[entry.key].priv, id, ts, body), v2aEntry(K[entry.key].priv, endpointId, id, ts, body)];
  const entries = [];
  if (currentSecret) entries.push(hmacV1(currentSecret.secret, id, ts, body));
  if (previousSecret) entries.push(hmacV1(previousSecret.secret, id, ts, body));
  if (currentKey) entries.push(...pairOf(currentKey));
  if (previousKey) entries.push(...pairOf(previousKey));
  const header = entries.join(' ');
  return { result: 'accept', header, schemes: header.split(' ').map((token) => token.split(',')[0]) };
};

const emissionCase = (id, description, input) => ({
  id,
  rule: 'R2.8',
  description,
  kind: 'emission',
  input,
  expect: emissionExpectation(input),
});

const v1ExpectOf = (input) => {
  const { webhookId, timestamp, body } = partsOf(input);
  return {
    signature: hmacV1(input.secret, webhookId, timestamp, body),
    content_b64u: b64uLocal(v1ContentBytes(webhookId, timestamp, body)),
  };
};

const signatureCase = (id, rule, description, input) => ({
  id,
  rule,
  description,
  kind: 'kat-v1',
  input,
  expect: { result: 'accept', ...v1ExpectOf(input) },
});

const gatedSignatureCase = (id, rule, description, kind, input) => {
  const { webhookId, timestamp, body, endpointId } = partsOf(input);
  const priv = K[input.key].priv;
  const content = kind === 'kat-v1a' ? v1ContentBytes(webhookId, timestamp, body) : v2aDigest(endpointId, webhookId, timestamp, body);
  const signature = kind === 'kat-v1a' ? v1aEntry(priv, webhookId, timestamp, body) : v2aEntry(priv, endpointId, webhookId, timestamp, body);
  return { id, rule, description, kind, input, expect: { result: 'accept', signature, content_b64u: b64uLocal(content) } };
};

const body32 = (value) => value.slice(PREFIX_LEN);
const secABody = body32(SEC_A);
const body24 = body32(SEC_24);
const body64 = body32(SEC_64);

// A 25-byte secret ends in "==", so the last data character carries two used bits and four unused ones.
const nonCanonicalBits = () => {
  const body25 = body32(secretOf('s25', 25));
  const index = body25.indexOf('=') - 1;
  const value = B64_ALPHABET.indexOf(body25[index]);
  const other = B64_ALPHABET[(value & 0x30) | ((value + 1) & 0x0f)];
  return `whsec_${body25.slice(0, index)}${other}${body25.slice(index + 1)}`;
};

const v1A = v1Header(SEC_A);
const v1Standard = v1A.slice('v1,'.length);
const unsafeValue = `-${v1Standard.slice(0, -1).slice(1)}_`;
const truncatedValue = b64StdEncode(Buffer.from(v1Standard, 'base64').subarray(0, 16));

const asciiInput = { secret: SEC_A, ...katInput(BODY_ASCII) };

// The published Standard Webhooks example: its minified body, ids and whsk_ seed.
const PUBLISHED_BODY = B('{"type":"contact.created","timestamp":"2022-11-03T20:26:10.344522Z","data":{"id":"1f81eb52-5198-4599-803e-771906343485"}}');
const PUBLISHED_ID = 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W';
const PUBLISHED_TIMESTAMP = 1674087231;
const PUBLISHED_ENDPOINT = 'ep_2fVZdC8Kx9TR4ZoCqHWt3NnLgRb';
const PUBLISHED_SECRET_KEY = 'whsk_4uKPjji/dhB8w6GW3YYDnIMYvXcdHrvH6lidTr4Z+EY=';
const PUBLISHED_V1 = 'v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=';
const PUBLISHED_V2A = 'v2a,kG9XaxZjAEpKB8KeQQb5G1Xp73YH5Rf5gxoWe7cg1kYMiyspdtZXe9w+dAwKeOurAwxfqmlOG/QR4m9s37DzAg==';
const PUBLISHED_COMBINED = `${PUBLISHED_V1} ${PUBLISHED_V2A}`;
const publishedKey = () => ed25519KeyFromSeed(Buffer.from(PUBLISHED_SECRET_KEY.slice('whsk_'.length), 'base64'));

export const cases = [
  { id: 'sig-secret-ok-32', rule: 'R2.1', description: 'a 32-byte secret decodes to the HMAC key', kind: 'secret', input: { value: SEC_A }, expect: { result: 'accept', key_b64u: keyB64u(SEC_A) } },
  { id: 'sig-secret-ok-24', rule: 'R2.1', description: 'a 24-byte secret is accepted at the lower bound', kind: 'secret', input: { value: SEC_24 }, expect: { result: 'accept', key_b64u: keyB64u(SEC_24) } },
  { id: 'sig-secret-ok-64', rule: 'R2.1', description: 'a 64-byte secret is accepted at the upper bound', kind: 'secret', input: { value: SEC_64 }, expect: { result: 'accept', key_b64u: keyB64u(SEC_64) } },
  { id: 'sig-secret-23', rule: 'R2.1', description: 'a 23-byte secret is one byte below the range', kind: 'secret', input: { value: SEC_23 }, expect: { result: 'reject', code: 'invalid_secret', reason: 'length' } },
  { id: 'sig-secret-65', rule: 'R2.1', description: 'a 65-byte secret is one byte above the range', kind: 'secret', input: { value: SEC_65 }, expect: { result: 'reject', code: 'invalid_secret', reason: 'length' } },
  { id: 'sig-secret-no-prefix', rule: 'R2.1', description: 'a bare base64 value without the whsec_ prefix is rejected', kind: 'secret', input: { value: body32(SEC_A) }, expect: { result: 'reject', code: 'invalid_secret', reason: 'prefix' } },
  { id: 'sig-secret-uppercase-prefix', rule: 'R2.1', description: 'an uppercase WHSEC_ prefix is rejected', kind: 'secret', input: { value: `WHSEC_${body32(SEC_A)}` }, expect: { result: 'reject', code: 'invalid_secret', reason: 'prefix' } },
  { id: 'sig-secret-base64url-alphabet', rule: 'R2.1', description: 'a base64url character in the value is rejected', kind: 'secret', input: { value: `whsec_${body24.replace(/[A-Za-z0-9]/, '-')}` }, expect: { result: 'reject', code: 'invalid_secret', reason: 'alphabet' } },
  { id: 'sig-secret-missing-padding', rule: 'R2.1', description: 'a stripped padding character is rejected', kind: 'secret', input: { value: `whsec_${body64.slice(0, -1)}` }, expect: { result: 'reject', code: 'invalid_secret', reason: 'padding' } },
  { id: 'sig-secret-extra-padding', rule: 'R2.1', description: 'an extra padding character is rejected', kind: 'secret', input: { value: `whsec_${secABody}=` }, expect: { result: 'reject', code: 'invalid_secret', reason: 'padding' } },
  { id: 'sig-secret-noncanonical-bits', rule: 'R2.1', description: 'non-zero unused trailing bits are rejected', kind: 'secret', input: { value: nonCanonicalBits() }, expect: { result: 'reject', code: 'invalid_secret', reason: 'canonical' } },
  { id: 'sig-secret-whitespace', rule: 'R2.1', description: 'whitespace inside the base64 part is rejected', kind: 'secret', input: { value: `whsec_${body24.slice(0, 2)} ${body24.slice(3)}` }, expect: { result: 'reject', code: 'invalid_secret', reason: 'alphabet' } },

  signatureCase('sig-v1-ascii', 'R2.2', 'v1 over an ASCII body is the HMAC of id, timestamp and raw body', asciiInput),
  signatureCase('sig-v1-unicode', 'R2.3', 'v1 covers the raw UTF-8 body without normalization', { secret: SEC_A, ...katInput(BODY_UNICODE) }),
  signatureCase('sig-v1-trailing-newline', 'R2.3', 'a body ending in LF is signed with the LF included', { secret: SEC_A, ...katInput(BODY_ASCII_LF) }),
  {
    id: 'sig-v1-body-reserialized',
    rule: 'R2.3',
    description: 'a body that differs from the signed bytes by one space fails verification',
    kind: 'verify',
    input: verifyInput({ signature_header: v1A, bodyText: BODY_ASCII_SPACED }),
    expect: { result: 'reject', code: 'bad_signature' },
  },

  gatedSignatureCase('sig-v1a-kat', 'R2.5', 'v1a is an Ed25519 signature over the raw content', 'kat-v1a', { key: 'newbie', ...katInput(BODY_ASCII) }),
  gatedSignatureCase('sig-v2a-kat', 'R2.6', 'v2a signs the SHA-256 of endpoint id, id, timestamp and body', 'kat-v2a', { key: 'newbie', ...katInput(BODY_ASCII), endpoint_id: SUB_ID }),
  {
    id: 'sig-upstream-v2a',
    rule: 'R2.6',
    description: 'the published Standard Webhooks asymmetric example reproduces byte for byte',
    kind: 'upstream-v2a',
    source: SW_SOURCE,
    input: {
      private_key: PUBLISHED_SECRET_KEY,
      endpoint_id: PUBLISHED_ENDPOINT,
      webhook_id: PUBLISHED_ID,
      webhook_timestamp: PUBLISHED_TIMESTAMP,
      body_b64u: b64u(PUBLISHED_BODY),
    },
    upstream: {
      public_key: 'whpk_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w=',
      sha256_base64: 'YXCi5iN+rjB+iEb6bvg1XbWbVBL+r2S+as3k3n1Ih/A=',
      signature: PUBLISHED_V2A,
    },
    expect: { result: 'accept' },
  },
  {
    id: 'sig-upstream-combined-header',
    rule: 'R2.4',
    description: 'the published combined header keeps the v1 literal and reproduces the v2a half',
    kind: 'upstream-combined',
    source: SW_SOURCE,
    input: {
      webhook_id: PUBLISHED_ID,
      webhook_timestamp: PUBLISHED_TIMESTAMP,
      body_b64u: b64u(PUBLISHED_BODY),
      endpoint_id: PUBLISHED_ENDPOINT,
      private_key: PUBLISHED_SECRET_KEY,
    },
    upstream: {
      header: PUBLISHED_COMBINED,
      note: 'the secret behind the v1 entry is not published; only the v2a half is reproducible',
    },
    expect: {
      result: 'accept',
      v1_literal: PUBLISHED_V1,
      v2a: v2aEntry(publishedKey().priv, PUBLISHED_ENDPOINT, PUBLISHED_ID, String(PUBLISHED_TIMESTAMP), PUBLISHED_BODY),
    },
  },

  { id: 'sig-header-empty', rule: 'R2.4', description: 'an empty signature header is malformed', kind: 'verify', input: verifyInput({ signature_header: '' }), expect: { result: 'reject', code: 'malformed_signature_header' } },
  { id: 'sig-header-leading-space', rule: 'R2.4', description: 'a leading space is malformed', kind: 'verify', input: verifyInput({ signature_header: ` ${v1A}` }), expect: { result: 'reject', code: 'malformed_signature_header' } },
  { id: 'sig-header-trailing-space', rule: 'R2.4', description: 'a trailing space is malformed', kind: 'verify', input: verifyInput({ signature_header: `${v1A} ` }), expect: { result: 'reject', code: 'malformed_signature_header' } },
  { id: 'sig-header-double-space', rule: 'R2.4', description: 'two spaces between entries leave an empty entry', kind: 'verify', input: verifyInput({ signature_header: `${v1Header(SEC_B)}  ${v1A}` }), expect: { result: 'reject', code: 'malformed_signature_header' } },
  { id: 'sig-header-no-comma', rule: 'R2.4', description: 'an entry without a scheme separator is malformed', kind: 'verify', input: verifyInput({ signature_header: `v1${v1Standard}` }), expect: { result: 'reject', code: 'malformed_signature_header' } },
  { id: 'sig-header-empty-value', rule: 'R2.4', description: 'an entry with an empty value is malformed', kind: 'verify', input: verifyInput({ signature_header: 'v1,' }), expect: { result: 'reject', code: 'malformed_signature_header' } },

  { id: 'sig-scheme-v9', rule: 'R3.11', description: 'an unknown scheme is unsupported', kind: 'verify', input: verifyInput({ signature_header: `v9,${v1Standard}` }), expect: { result: 'reject', code: 'unsupported_signature_scheme' } },
  { id: 'sig-scheme-uppercase', rule: 'R3.11', description: 'scheme names are case-sensitive', kind: 'verify', input: verifyInput({ signature_header: `V1,${v1Standard}` }), expect: { result: 'reject', code: 'unsupported_signature_scheme' } },

  { id: 'sig-value-truncated', rule: 'R3.12', description: 'a v1 value of 16 bytes is malformed', kind: 'verify', input: verifyInput({ signature_header: `v1,${truncatedValue}` }), expect: { result: 'reject', code: 'malformed_signature' } },
  { id: 'sig-value-bad-base64', rule: 'R3.12', description: 'a value outside the base64 alphabet is malformed', kind: 'verify', input: verifyInput({ signature_header: 'v1,****' }), expect: { result: 'reject', code: 'malformed_signature' } },
  { id: 'sig-value-urlsafe', rule: 'R3.12', description: 'a value using base64url characters is malformed', kind: 'verify', input: verifyInput({ signature_header: `v1,${unsafeValue}` }), expect: { result: 'reject', code: 'malformed_signature' } },

  { id: 'sig-wrong-secret', rule: 'R3.13', description: 'a signature over the registered secret of another subscription is rejected', kind: 'verify', input: verifyInput({ signature_header: v1Header(SEC_B) }), expect: { result: 'reject', code: 'bad_signature' } },
  { id: 'sig-stale-timestamp', rule: 'R3.9', description: 'a timestamp 301 seconds old is stale', kind: 'verify', input: verifyInput({ signature_header: v1Header(SEC_A, { timestamp: NOW - 301 }), timestamp: NOW - 301 }), expect: { result: 'reject', code: 'stale_timestamp' } },
  { id: 'sig-future-timestamp', rule: 'R3.9', description: 'a timestamp 301 seconds ahead is a future timestamp', kind: 'verify', input: verifyInput({ signature_header: v1Header(SEC_A, { timestamp: NOW + 301 }), timestamp: NOW + 301 }), expect: { result: 'reject', code: 'future_timestamp' } },
  { id: 'sig-timestamp-boundary', rule: 'R3.9', description: 'a timestamp exactly 300 seconds old is accepted', kind: 'verify', input: verifyInput({ signature_header: v1Header(SEC_A, { timestamp: NOW - 300 }), timestamp: NOW - 300 }), expect: { result: 'accept' } },

  { id: 'sig-multi-accept-second', rule: 'R2.7', description: 'the second of two v1 entries verifies', kind: 'verify', input: verifyInput({ signature_header: `${v1Header(SEC_B)} ${v1A}` }), expect: { result: 'accept' } },
  { id: 'sig-multi-none', rule: 'R2.7', description: 'no entry of two v1 signatures verifies with the registered secret', kind: 'verify', input: verifyInput({ signature_header: `${v1Header(SEC_B)} ${v1Header(SEC_64)}` }), expect: { result: 'reject', code: 'bad_signature' } },

  emissionCase('sig-emission-hmac-only', 'a subscription with one secret emits one v1 entry', emissionInput([{ secret: SEC_A, current: true }], [])),
  emissionCase('sig-emission-key', 'a subscription with one signing key emits v1 then v1a and v2a', emissionInput([{ secret: SEC_A, current: true }], [{ key: 'newbie', current: true }])),
  emissionCase('sig-emission-rotating', 'a rotating subscription emits current first, then the predecessor pair', emissionInput(
    [{ secret: SEC_A, current: true }, { secret: SEC_B, current: false }],
    [{ key: 'newbie', current: true }, { key: 'newbie2', current: false }],
  )),

  { id: 'sig-asym-wrong-key', rule: 'R3.14', description: 'a v1a and v2a pair from an unpublished key fails enforcement', kind: 'verify', input: verifyInput({ signature_header: `${v1A} ${asymHeader('newbie3')}`, keys: ['newbie'], enforce: 'server' }), expect: { result: 'reject', code: 'bad_server_signature' } },
  { id: 'sig-asym-ignored', rule: 'R2.7', description: 'the same asymmetric entries are ignored when identity is not enforced', kind: 'verify', input: verifyInput({ signature_header: `${v1A} ${asymHeader('newbie3')}`, keys: ['newbie'] }), expect: { result: 'accept' } },
  { id: 'sig-asym-no-keys', rule: 'R3.14', description: 'enforcement with no accepted key is no_server_keys', kind: 'verify', input: verifyInput({ signature_header: v1A, keys: [], enforce: 'server' }), expect: { result: 'reject', code: 'no_server_keys' } },
  { id: 'sig-asym-kat', rule: 'R3.14', description: 'a v1a and v2a pair from the current key verifies against the accepted set', kind: 'verify', input: verifyInput({ signature_header: `${v1A} ${asymHeader('newbie')}`, keys: ['newbie', 'newbie2'], enforce: 'server' }), expect: { result: 'accept' } },
];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'secret': {
      const parsed = parseWhsec(input.value);
      return parsed.ok
        ? { result: 'accept', key_b64u: b64u(parsed.key) }
        : { result: 'reject', code: parsed.code, reason: parsed.reason };
    }
    case 'kat-v1': {
      const parts = partsOf(input);
      return { result: 'accept', signature: v1Sign(bytesOf(input.secret), parts), content_b64u: b64u(v1Content(parts)) };
    }
    case 'kat-v1a': {
      const parts = partsOf(input);
      return { result: 'accept', signature: v1aSign(K[input.key], parts), content_b64u: b64u(v1aContent(parts)) };
    }
    case 'kat-v2a': {
      const parts = partsOf(input);
      return { result: 'accept', signature: v2aSign(K[input.key], parts), content_b64u: b64u(v2aContent(parts)) };
    }
    case 'emission': {
      const header = emissionHeaderOf(input);
      return { result: 'accept', header, schemes: schemesOf(header) };
    }
    case 'verify':
      return pipeline(input);
    case 'upstream-v2a': {
      const derived = ed25519KeyFromSeed(Buffer.from(input.private_key.slice('whsk_'.length), 'base64'));
      const parts = partsOf(input);
      const publishedPublicKey = b64u(Buffer.from(c.upstream.public_key.slice('whpk_'.length), 'base64'));
      const digest = b64StdEncode(v2aContent(parts));
      const signature = v2aSign(derived, parts);
      const wrong = [];
      if (derived.public_key !== publishedPublicKey) wrong.push('public_key');
      if (digest !== c.upstream.sha256_base64) wrong.push('sha256_base64');
      if (signature !== c.upstream.signature) wrong.push('signature');
      if (wrong.length > 0) throw new Error(`${c.id}: the upstream example disagrees on ${wrong.join(', ')}`);
      return { result: 'accept' };
    }
    case 'upstream-combined': {
      const derived = ed25519KeyFromSeed(Buffer.from(input.private_key.slice('whsk_'.length), 'base64'));
      const parts = partsOf(input);
      const v2a = v2aEntry(derived.priv, parts.endpointId, parts.webhookId, parts.timestamp, parts.body);
      const [v1Literal, publishedV2a] = c.upstream.header.split(' ');
      if (v2a !== publishedV2a) throw new Error(`${c.id}: the upstream combined header disagrees on the v2a entry`);
      return { result: 'accept', v1_literal: v1Literal, v2a };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

function pipeline(input) {
  const envelope = input.envelope;
  const timestamp = Number(envelope.webhook_timestamp);
  if (input.now - timestamp > input.window) return { result: 'reject', code: 'stale_timestamp' };
  if (timestamp - input.now > input.window) return { result: 'reject', code: 'future_timestamp' };
  const parsed = parseSignatureHeader(envelope.signature_header);
  if (!parsed.ok) return { result: 'reject', code: parsed.code };
  const schemes = checkSchemes(parsed.entries);
  if (!schemes.ok) return { result: 'reject', code: schemes.code };
  const decoded = decodeEntries(parsed.entries);
  if (!decoded.ok) return { result: 'reject', code: decoded.code };
  const parts = partsOf(envelope);
  let mac = { ok: false };
  for (const secret of input.secrets) {
    mac = v1Verify(decoded.entries, bytesOf(secret), parts);
    if (mac.ok) break;
  }
  if (!mac.ok) return { result: 'reject', code: 'bad_signature' };
  if (input.enforce === 'server') {
    if (input.keys.length === 0) return { result: 'reject', code: 'no_server_keys' };
    const asym = asymVerify(decoded.entries, input.keys.map((name) => K[name]), parts);
    if (!asym.ok) return { result: 'reject', code: asym.code };
  }
  return { result: 'accept' };
}
