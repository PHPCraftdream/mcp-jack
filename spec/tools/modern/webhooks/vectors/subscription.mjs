// Vectors for spec/06-webhooks.md section 8 (R8.1-R8.9).
import {
  activeSecrets,
  cursorOk,
  gapEnvelope,
  parseWhsec,
  sha256,
  subscriptionKey,
  terminatedEnvelope,
  ttlGrant,
} from '../reference.mjs';
import { NOW } from '../../../gen/core.mjs';

export const file = 'webhook-subscription-vectors.json';

const SUB_DOMAIN = 'mcp-jack/webhook1/subscription';
const HOOK = 'https://hooks.example.test/hooks/alice';
const HOOK_2 = 'https://hooks.example.test:8443/hooks/alice?tenant=1';
const NAME = 'incident.created';
const SEC_A = `whsec_${sha256('mcp-jack webhook secret: a').subarray(0, 32).toString('base64')}`;
const SEC_B = `whsec_${sha256('mcp-jack webhook secret: b').subarray(0, 32).toString('base64')}`;
const GRACE_ENDS_AT = NOW + 300;
const GAP_BODY = '{"type":"gap","cursor":"cursor_7f3a"}';
const TERMINATED_BODY = '{"type":"terminated","error":{"code":"-32024","message":"Forbidden"}}';
const TERMINATED_DATA_BODY = '{"type":"terminated","error":{"code":"-32024","message":"Forbidden","data":{"reason":"Access revoked"}}}';
const OMIT = Symbol('omit');

const jcsInputOf = (principal, canonicalUrl, name, argJson) =>
  `["${SUB_DOMAIN}",${JSON.stringify(principal)},${JSON.stringify(canonicalUrl)},${JSON.stringify(name)},${argJson}]`;

const idOf = ({ principal, url, name, argJson }) => {
  const decided = subscriptionKey({ principal, url, name, arguments: JSON.parse(argJson) });
  if (!decided.ok) throw new Error(`subscription vector for ${principal} derived no id (${decided.code})`);
  return decided.id;
};

const idCase = ({ id, rule, description, principal = 'alice', url, name = NAME, arguments_text = null, canonical_url, argJson, same_id_as }) => ({
  id,
  rule,
  description,
  kind: 'sub-id',
  input: { principal, url, name, arguments_text },
  expect: {
    result: 'accept',
    id: idOf({ principal, url, name, argJson }),
    canonical_url,
    canonical_arguments: argJson,
    jcs_input: jcsInputOf(principal, canonical_url, name, argJson),
  },
  ...(same_id_as === undefined ? {} : { same_id_as }),
});

const idReject = (id, rule, description, url, expect) => ({
  id,
  rule,
  description,
  kind: 'sub-id',
  input: { principal: 'alice', url, name: NAME, arguments_text: null },
  expect,
});

const ttlCase = (id, description, ttlMs, expect) => ({
  id,
  rule: 'R8.5',
  description,
  kind: 'ttl',
  input: { now: NOW, ...(ttlMs === OMIT ? {} : { ttlMs }) },
  expect,
});

const secretCase = (id, description, { current = SEC_A, previous = SEC_B, graceEndsAt = GRACE_ENDS_AT, now = GRACE_ENDS_AT - 1 }, order) => ({
  id,
  rule: 'R8.6',
  description,
  kind: 'secrets',
  input: { current, previous, graceEndsAt, now },
  expect: { result: 'accept', order },
});

const cursorCase = (id, description, value, expect) => ({
  id,
  rule: 'R8.9',
  description,
  kind: 'cursor',
  input: { value },
  expect,
});

export const cases = [
  idCase({ id: 'sub-principal-alice', rule: 'R8.1', description: 'the principal is one component of the key', url: HOOK, arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-principal-bob', rule: 'R8.1', description: 'another principal with the same url, name and arguments derives another id', principal: 'bob', url: HOOK, arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),

  idCase({ id: 'sub-url-canonical-uppercase-host', rule: 'R8.2', description: 'the host is lowercased in the canonical form', url: 'https://HOOKS.Example.Test/hooks/alice', arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-url-default-port', rule: 'R8.2', description: 'port 443 is dropped from the canonical form', url: 'https://hooks.example.test:443/hooks/alice', arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-url-trailing-dot', rule: 'R8.2', description: 'one trailing dot is stripped from the host', url: 'https://hooks.example.test./hooks/alice', arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-url-empty-path', rule: 'R8.2', description: 'an empty path becomes a single slash', url: 'https://hooks.example.test', arguments_text: '{"severity":"P1"}', canonical_url: 'https://hooks.example.test/', argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-url-query-kept', rule: 'R8.2', description: 'a non-empty query and a non-default port are kept', url: HOOK_2, name: 'email.received', canonical_url: HOOK_2, argJson: 'null' }),
  idReject('sub-url-http-rejected', 'R8.2', 'a plain http url is not an https callback url', 'http://hooks.example.test/hooks/alice', { result: 'reject', code: 'scheme_not_https' }),
  idReject('sub-url-userinfo-rejected', 'R8.2', 'userinfo in the authority is rejected', 'https://alice@hooks.example.test/hooks/alice', { result: 'reject', code: 'invalid_callback_url', reason: 'userinfo' }),
  idReject('sub-url-dot-segment-rejected', 'R8.2', 'a dot segment in the path is rejected', 'https://hooks.example.test/hooks/../alice', { result: 'reject', code: 'invalid_callback_url', reason: 'dot_segment' }),

  idCase({ id: 'sub-args-absent', rule: 'R8.3', description: 'absent arguments are keyed as null', url: HOOK, canonical_url: HOOK, argJson: 'null', same_id_as: 'sub-args-explicit-null' }),
  idCase({ id: 'sub-args-explicit-null', rule: 'R8.3', description: 'explicit null arguments are the same key as absent arguments', url: HOOK, arguments_text: 'null', canonical_url: HOOK, argJson: 'null', same_id_as: 'sub-args-absent' }),
  idCase({ id: 'sub-args-key-order', rule: 'R8.3', description: 'object members are sorted by UTF-16 code unit order', url: HOOK, arguments_text: '{"b":1,"a":2}', canonical_url: HOOK, argJson: '{"a":2,"b":1}' }),
  idCase({ id: 'sub-args-number-int', rule: 'R8.3', description: 'the integer form of a number is canonical', url: HOOK, arguments_text: '{"a":1}', canonical_url: HOOK, argJson: '{"a":1}' }),
  idCase({ id: 'sub-args-number-float', rule: 'R8.3', description: 'a trailing .0 serializes as the integer form', url: HOOK, arguments_text: '{"a":1.0}', canonical_url: HOOK, argJson: '{"a":1}', same_id_as: 'sub-args-number-int' }),
  idCase({ id: 'sub-args-number-exponent', rule: 'R8.3', description: 'an exponent form serializes as the integer form', url: HOOK, arguments_text: '{"a":1e0}', canonical_url: HOOK, argJson: '{"a":1}', same_id_as: 'sub-args-number-int' }),
  idCase({ id: 'sub-args-negative-zero', rule: 'R8.3', description: 'negative zero serializes as zero', url: HOOK, arguments_text: '{"a":-0}', canonical_url: HOOK, argJson: '{"a":0}', same_id_as: 'sub-args-positive-zero' }),
  idCase({ id: 'sub-args-positive-zero', rule: 'R8.3', description: 'zero is the canonical serialization of negative zero', url: HOOK, arguments_text: '{"a":0}', canonical_url: HOOK, argJson: '{"a":0}', same_id_as: 'sub-args-negative-zero' }),
  idCase({ id: 'sub-args-unicode-nfc', rule: 'R8.3', description: 'a precomposed accented key is kept as it is', url: HOOK, arguments_text: '{"é":1}', canonical_url: HOOK, argJson: '{"é":1}' }),
  idCase({ id: 'sub-args-unicode-nfd', rule: 'R8.3', description: 'a decomposed accented key is not normalized and derives another id', url: HOOK, arguments_text: '{"e\\u0301":1}', canonical_url: HOOK, argJson: '{"e\u0301":1}' }),
  idCase({ id: 'sub-args-large-number', rule: 'R8.3', description: 'a large number keeps the ECMAScript exponent form', url: HOOK, arguments_text: '{"a":1e21}', canonical_url: HOOK, argJson: '{"a":1e+21}' }),
  idCase({ id: 'sub-args-different-args-same-url', rule: 'R8.3', description: 'the same url with other arguments is another subscription', url: HOOK, arguments_text: '{"severity":"P2"}', canonical_url: HOOK, argJson: '{"severity":"P2"}' }),

  idCase({ id: 'sub-id-shape', rule: 'R8.4', description: 'the derived id is 20 characters of the form sub_ plus 16 lowercase hex', url: HOOK, name: 'subscription.shape', canonical_url: HOOK, argJson: 'null' }),
  idCase({ id: 'sub-id-worked-example-1', rule: 'R8.4', description: 'the first worked example of R8.4 derives its pinned id', url: HOOK, arguments_text: '{"severity":"P1"}', canonical_url: HOOK, argJson: '{"severity":"P1"}' }),
  idCase({ id: 'sub-id-worked-example-2', rule: 'R8.4', description: 'the second worked example of R8.4 derives its pinned id', url: HOOK_2, name: 'email.received', canonical_url: HOOK_2, argJson: 'null' }),

  ttlCase('sub-ttl-default', 'an absent ttl takes the one hour server default', OMIT, { result: 'accept', grantMs: 3600000, refreshBefore: '2026-01-01T01:00:00Z' }),
  ttlCase('sub-ttl-clamp-up', 'a ttl below one minute is clamped up', 30000, { result: 'accept', grantMs: 60000, refreshBefore: '2026-01-01T00:01:00Z' }),
  ttlCase('sub-ttl-clamp-down', 'a ttl above one day is clamped down', 172800000, { result: 'accept', grantMs: 86400000, refreshBefore: '2026-01-02T00:00:00Z' }),
  ttlCase('sub-ttl-null', 'a null ttl grants no expiry and no refresh deadline', null, { result: 'accept', grantMs: null, refreshBefore: null }),
  ttlCase('sub-ttl-negative', 'a negative ttl is invalid_arguments', -1, { result: 'reject', code: 'invalid_arguments', reason: 'ttl' }),
  ttlCase('sub-ttl-fractional', 'a fractional ttl is invalid_arguments', 1.5, { result: 'reject', code: 'invalid_arguments', reason: 'ttl' }),
  ttlCase('sub-ttl-refresh-before-format', 'the refresh deadline is an ISO 8601 UTC second precision string', 3600000, { result: 'accept', grantMs: 3600000, refreshBefore: '2026-01-01T01:00:00Z' }),

  secretCase('sub-secrets-grace-open', 'one second before the grace deadline both secrets sign', {}, ['current', 'previous']),
  secretCase('sub-secrets-grace-closed', 'at the grace deadline only the current secret signs', { now: GRACE_ENDS_AT }, ['current']),
  secretCase('sub-secrets-no-previous', 'without a previous secret only the current one signs', { previous: null, now: GRACE_ENDS_AT - 1 }, ['current']),

  { id: 'sub-envelope-gap', rule: 'R8.7', description: 'a gap envelope is exactly the gap body with the fresh cursor', kind: 'envelope', input: { kind: 'gap', cursor: 'cursor_7f3a' }, expect: { result: 'accept', body_text: GAP_BODY } },
  { id: 'sub-envelope-terminated', rule: 'R8.8', description: 'a terminated envelope without data carries only code and message', kind: 'envelope', input: { kind: 'terminated', code: '-32024', message: 'Forbidden' }, expect: { result: 'accept', body_text: TERMINATED_BODY } },
  { id: 'sub-envelope-terminated-data', rule: 'R8.8', description: 'a terminated envelope appends the optional data member last', kind: 'envelope', input: { kind: 'terminated', code: '-32024', message: 'Forbidden', data: { reason: 'Access revoked' } }, expect: { result: 'accept', body_text: TERMINATED_DATA_BODY } },

  cursorCase('sub-cursor-ok', 'a printable 12-character cursor is accepted', 'cursor_7f3a', { result: 'accept' }),
  cursorCase('sub-cursor-null', 'a null cursor is accepted', null, { result: 'accept' }),
  cursorCase('sub-cursor-empty', 'an empty cursor is rejected', '', { result: 'reject' }),
  cursorCase('sub-cursor-space', 'a cursor containing a space is rejected', 'cursor 7f3a', { result: 'reject' }),
  cursorCase('sub-cursor-too-long', 'a cursor of 513 characters is rejected', 'c'.repeat(513), { result: 'reject' }),
];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'sub-id': {
      const args = input.arguments_text === null || input.arguments_text === undefined
        ? null
        : JSON.parse(input.arguments_text);
      const decided = subscriptionKey({ principal: input.principal, url: input.url, name: input.name, arguments: args });
      if (!decided.ok) {
        return decided.reason === undefined
          ? { result: 'reject', code: decided.code }
          : { result: 'reject', code: decided.code, reason: decided.reason };
      }
      return {
        result: 'accept',
        id: decided.id,
        canonical_url: decided.canonical_url,
        canonical_arguments: decided.canonical_arguments,
        jcs_input: decided.jcs_input,
      };
    }
    case 'ttl': {
      const options = { now: input.now };
      if ('ttlMs' in input) options.ttlMs = input.ttlMs;
      const granted = ttlGrant(options);
      return granted.ok
        ? { result: 'accept', grantMs: granted.grantMs, refreshBefore: granted.refreshBefore }
        : { result: 'reject', code: granted.code, reason: granted.reason };
    }
    case 'secrets': {
      const options = { current: parseWhsec(input.current).key, graceEndsAt: input.graceEndsAt, now: input.now };
      if (input.previous !== null && input.previous !== undefined) options.previous = parseWhsec(input.previous).key;
      return { result: 'accept', order: activeSecrets(options).map((entry) => (entry.current === true ? 'current' : 'previous')) };
    }
    case 'envelope': {
      if (input.kind === 'gap') return { result: 'accept', body_text: gapEnvelope(input.cursor) };
      const error = { code: input.code, message: input.message };
      if ('data' in input) error.data = input.data;
      return { result: 'accept', body_text: terminatedEnvelope(error) };
    }
    case 'cursor':
      return cursorOk(input.value) ? { result: 'accept' } : { result: 'reject' };
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}
