// Tests of spec/tools/modern/webhooks/index.mjs: determinism, case index and hand-mutated reference inputs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from './index.mjs';
import { RULES, RULE_IDS } from './rules.mjs';
import { parseWhsec } from './reference.mjs';
import { NOW, stableStringify } from '../../gen/core.mjs';
import * as signatures from './vectors/signatures.mjs';
import * as w1 from './vectors/w1.mjs';
import * as receiver from './vectors/receiver.mjs';
import * as endpoint from './vectors/endpoint.mjs';
import * as ssrf from './vectors/ssrf.mjs';
import * as subscription from './vectors/subscription.mjs';
import * as card from './vectors/card.mjs';

const MODULES = [signatures, w1, receiver, endpoint, ssrf, subscription, card];
const FILES = [
  'webhook-signature-vectors.json',
  'webhook-w1-vectors.json',
  'webhook-receiver-vectors.json',
  'webhook-endpoint-verification-vectors.json',
  'ssrf-vectors.json',
  'webhook-subscription-vectors.json',
  'server-card-keys-vectors.json',
];

const byId = (mod, id) => {
  const found = mod.cases.find((c) => c.id === id);
  assert.ok(found, `case ${id} is missing from ${mod.file}`);
  return found;
};

test('build() is deterministic', () => {
  assert.deepEqual(build(), build());
  assert.equal(stableStringify(build()), stableStringify(build()));
});

test('build() does not mutate a case', () => {
  const before = MODULES.map((mod) => stableStringify(mod.cases));
  build();
  build();
  assert.deepEqual(MODULES.map((mod) => stableStringify(mod.cases)), before);
});

test('case ids are unique', () => {
  const ids = MODULES.flatMap((mod) => mod.cases.map((c) => c.id));
  let total = 0;
  for (const mod of MODULES) {
    const own = mod.cases.map((c) => c.id);
    assert.equal(new Set(own).size, mod.cases.length);
    total += own.length;
  }
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(total > 250);
});

test('every rule has a vector', () => {
  assert.equal(RULES.length, 80);
  const cases = MODULES.flatMap((mod) => mod.cases);
  const known = new Set(cases.map((c) => c.id));
  assert.equal(known.size, cases.length);
  const mapped = new Map(RULES.map((rule) => [rule.id, []]));
  for (const c of cases) {
    assert.ok(RULE_IDS.has(c.rule), `case ${c.id} names unknown rule ${c.rule}`);
    mapped.get(c.rule).push(c.id);
  }
  let ids = 0;
  for (const rule of RULES) {
    const own = mapped.get(rule.id);
    assert.ok(own.length > 0, `rule ${rule.id} has no case`);
    for (const id of own) assert.ok(known.has(id), `rule ${rule.id} maps missing case id ${id}`);
    ids += own.length;
  }
  assert.equal(ids, cases.length);
});

test('build exposes the sentinel surface', () => {
  const out = build();
  assert.deepEqual(Object.keys(out.files), FILES);
  for (const name of FILES) {
    const doc = out.files[name];
    assert.equal(typeof doc.note, 'string');
    assert.equal(doc.clock, NOW);
    assert.ok(Array.isArray(doc.cases) && doc.cases.length > 0);
  }
  assert.ok(out.casesMarkdown.includes('R7.6'));
  assert.ok(out.casesMarkdown.endsWith('rules covered.\n'));
});

test('the reference rejects hand-mutated input', () => {
  const boundary = byId(signatures, 'sig-timestamp-boundary');
  const late = {
    ...boundary.input,
    envelope: { ...boundary.input.envelope, webhook_timestamp: boundary.input.envelope.webhook_timestamp + 1 },
  };
  assert.deepEqual(signatures.run({ ...boundary, input: late }), { result: 'reject', code: 'bad_signature' });

  const accept = byId(w1, 'w1-accept');
  const moved = { ...accept.input, parts: { ...accept.input.parts, callback_url: 'https://hooks.example.test/hooks/bob' } };
  assert.deepEqual(w1.run({ ...accept, input: moved }), { result: 'reject', code: 'bad_jack_signature' });

  assert.deepEqual(ssrf.run({ kind: 'address', input: { address: '127.0.0.1' } }), { result: 'reject', reason: 'loopback', family: 'ipv4' });
  assert.deepEqual(ssrf.run({ kind: 'address', input: { address: '8.8.8.8' } }), { result: 'accept', reason: 'global', family: 'ipv4' });

  const cache = byId(card, 'card-fetch-accept-cache');
  assert.deepEqual(card.run({ ...cache, input: { ...cache.input, cardUrl: 'https://cdn.example.test/card.json' } }), {
    result: 'reject',
    code: 'cross_origin',
  });

  const minimal = byId(receiver, 'rcv-r11-minimal-delivery');
  const input = JSON.parse(JSON.stringify(minimal.input));
  const clean = receiver.run({ ...minimal, input });
  assert.equal(clean.steps.length, 1);
  assert.equal(clean.steps[0].status, 200);
  assert.equal(clean.steps[0].code, null);
  input.steps[0].headers = input.steps[0].headers.map(([name, value]) => [
    name,
    name.toLowerCase() === 'webhook-timestamp' ? String(NOW + 301) : value,
  ]);
  const out = receiver.run({ ...minimal, input });
  assert.equal(out.steps.length, 1);
  assert.equal(out.steps[0].status, 401);
  assert.equal(out.steps[0].code, 'bad_signature');
});

test('secret fixtures have the intended byte lengths', () => {
  const intended = [
    ['sig-secret-23', 23],
    ['sig-secret-ok-24', 24],
    ['sig-secret-ok-64', 64],
    ['sig-secret-65', 65],
  ];
  const values = new Map();
  for (const [id, bytes] of intended) {
    const value = byId(signatures, id).input.value;
    assert.equal(Buffer.from(value.slice('whsec_'.length), 'base64').length, bytes, `case ${id}`);
    values.set(id, value);
  }
  for (const id of ['sig-secret-ok-24', 'sig-secret-ok-64']) assert.equal(parseWhsec(values.get(id)).ok, true, `case ${id}`);
  for (const id of ['sig-secret-23', 'sig-secret-65']) {
    assert.deepEqual(parseWhsec(values.get(id)), { ok: false, code: 'invalid_secret', reason: 'length' }, `case ${id}`);
  }
});

test('same_id_as pairs resolve', () => {
  const ids = new Map(subscription.cases.map((c) => [c.id, c]));
  for (const c of subscription.cases) {
    if (c.same_id_as === undefined) continue;
    const other = ids.get(c.same_id_as);
    assert.ok(other, `case ${c.id} names missing case ${c.same_id_as}`);
    assert.equal(other.expect.id, c.expect.id);
  }
  for (const c of subscription.cases) {
    if (c.kind !== 'sub-id' || c.expect.result !== 'accept') continue;
    assert.match(c.expect.id, /^sub_[0-9a-f]{16}$/);
  }
});
