// Coverage tests: the rule and reason tables of spec-data.mjs, the case counts
// of the generated vectors and the section 8 markdown must agree with the text
// of spec 04. Counts are pinned so a dropped or duplicated case fails loudly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALL_RULES, ANNOTATION_REASONS, EXEMPT_RULES, NON_VECTOR_RULES, PROJECTION_REASON, REASONS, VECTOR_RULES,
} from './spec-data.mjs';
import generator, { assertRulePartition } from './index.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const SPEC = readFileSync(join(ROOT, '04-modern-profile.md'), 'utf8');
const RESPONSE_VECTORS = JSON.parse(readFileSync(join(ROOT, 'fixtures/response-vectors.json'), 'utf8'));
const OUT = generator.build();
const CASES = [
  ...OUT.files['modern-request-vectors.json'].cases,
  ...OUT.files['header-encoding-vectors.json'].cases,
  ...OUT.files['x-mcp-header-vectors.json'].cases,
  ...OUT.files['era-detection-vectors.json'].cases,
];
const BY_REFERENCE = OUT.files['modern-request-vectors.json'].by_reference;
const byRule = (rule) => CASES.filter((c) => c.rule === rule).length;
const reasonOf = (expect) => Object.keys(REASONS).find((key) => REASONS[key].message === expect.error.message);

// A rule prefix alone does not identify a family: projection refusals also carry
// outcome 'refuse', and annotations live under C5, C6 and C11.
const REFUSALS = CASES.filter((c) => c.rule.startsWith('S') && c.expect.outcome === 'refuse');
const ANNOTATIONS = CASES.filter((c) => c.rule === 'C5' || c.rule === 'C6' || c.rule === 'C11');
const ERA_CASES_STORED = CASES.filter((c) => c.rule === 'C9');

const ERAS = ['modern', 'legacy', 'none'];
const ACTIONS = ['stay_modern', 'fallback_initialize', 'retry_with_supported', 'abort'];
const ERA_REASONS = [
  'unverified',
  'no_modern_error',
  'jack_envelope',
  'modern_method_not_found',
  'unsupported_version_no_overlap',
  'no_era_signal',
];

test('every rule id appears in the spec text', () => {
  for (const id of ALL_RULES) assert.ok(SPEC.includes('`' + id + '`'), id);
});

test('every non-exempt rule has at least one case', () => {
  for (const id of VECTOR_RULES) assert.ok(byRule(id) > 0, id);
});

test('exempt rules have no cases and are listed in the spec', () => {
  for (const id of NON_VECTOR_RULES) {
    assert.ok(Object.hasOwn(EXEMPT_RULES, id), id);
    assert.equal(byRule(id), 0, id);
    assert.ok(SPEC.includes('`' + id + '`'), id);
  }
  assert.deepEqual(NON_VECTOR_RULES.sort(), ['C10', 'C12', 'C7', 'C8']);
});

test('the rule partition is exhaustive', () => {
  assert.deepEqual([...VECTOR_RULES, ...NON_VECTOR_RULES].sort(), [...ALL_RULES].sort());
  assert.equal(new Set([...VECTOR_RULES, ...NON_VECTOR_RULES]).size, ALL_RULES.length);
});

test('every reason token and message appears in the spec text', () => {
  for (const key of Object.keys(REASONS)) {
    assert.ok(SPEC.includes('`' + key + '`'), key);
    assert.ok(SPEC.includes(REASONS[key].message), key);
    assert.ok([400, 405].includes(REASONS[key].http_status), key);
  }
});

test('every annotation and projection reason appears in the spec text', () => {
  for (const token of ANNOTATION_REASONS) assert.ok(SPEC.includes('`' + token + '`'), token);
  assert.ok(SPEC.includes('`' + PROJECTION_REASON + '`'), PROJECTION_REASON);
});

test('request refusal messages are the fixed table entries', () => {
  for (const c of REFUSALS) {
    // The stored expectation carries the wire error only, so the reason token is
    // recovered from the fixed 5.1 message and must match code and status.
    const reason = reasonOf(c.expect);
    assert.ok(reason !== undefined, c.id);
    assert.equal(REASONS[reason].jsonrpc_code, c.expect.error.code, c.id);
    assert.equal(REASONS[reason].http_status, c.expect.http_status, c.id);
  }
});

test('case reasons come from the closed lists', () => {
  for (const c of ANNOTATIONS) {
    if (c.expect.valid === false) assert.ok(ANNOTATION_REASONS.includes(c.expect.reason), c.id);
    if (c.expect.outcome === 'refuse') assert.equal(c.expect.reason, PROJECTION_REASON, c.id);
  }
  for (const c of ERA_CASES_STORED) {
    assert.ok(ERAS.includes(c.expect.era), c.id);
    assert.ok(ACTIONS.includes(c.expect.action), c.id);
    assert.ok(c.expect.reason === null || ERA_REASONS.includes(c.expect.reason), c.id);
  }
  for (const c of CASES.filter((c) => c.kind === 'decode')) {
    assert.ok(c.expect.ok === true || c.expect.reason === 'bad_encoding', c.id);
  }
});

test('case counts are pinned per rule', () => {
  assert.deepEqual(Object.fromEntries(ALL_RULES.map((r) => [r, byRule(r)])), {
    S1: 13, S2: 6, S3: 8, S4: 9, S5: 5, S6: 41, S7: 3, S8: 3, S9: 2, S10: 1, S11: 4, S12: 3,
    C1: 1, C2: 8, C3: 24, C4: 18, C5: 55, C6: 22, C7: 0, C8: 0, C9: 38, C10: 0, C11: 7, C12: 0,
  });
});

test('the markdown coverage table matches the counts', () => {
  for (const rule of ALL_RULES) {
    const count = byRule(rule);
    if (count === 0) continue;
    assert.ok(OUT.casesMarkdown.includes('| ' + rule + ' | ' + count + ' |'), rule);
  }
});

test('the by-reference entry points at real response vectors', () => {
  assert.equal(BY_REFERENCE.length, 1);
  const entry = BY_REFERENCE[0];
  assert.equal(entry.rule, 'C8');
  assert.equal(entry.file, 'fixtures/response-vectors.json');
  const ids = new Set(RESPONSE_VECTORS.cases.map((c) => c.id));
  for (const v of entry.vectors) assert.ok(ids.has(v), v);
  assert.deepEqual(entry.vectors, ['res-wrong-request-binding', 'res-accept']);
});

// The section 8 exemption table must name exactly the exempt rules: deleting a
// row while keeping the rule heading has to fail.
function specExemptRows(spec) {
  const lines = spec.split('\n');
  const start = lines.indexOf('| Rule | Why no vector | Carried by |');
  assert.ok(start >= 0, 'exemption table header not found');
  const ids = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.startsWith('|')) break;
    if (/^\|\s*-+/.test(line)) continue;
    const match = line.match(/^\| `([^`]+)` \|/);
    if (match) ids.push(match[1]);
  }
  return ids;
}

test('the spec exemption table names exactly the exempt rules', () => {
  assert.deepEqual(specExemptRows(SPEC).sort(), [...NON_VECTOR_RULES].sort());
});

test('the generated cases satisfy the rule partition', () => {
  assert.doesNotThrow(() => assertRulePartition(CASES));
});

test('the partition checker rejects a corrupted partition', () => {
  // A non-exempt rule that loses all of its vectors.
  assert.throws(() => assertRulePartition(CASES.filter((c) => c.rule !== 'C11')), /C11 has no mapped vector id/);
  // An exempt rule that carries a vector.
  assert.throws(() => assertRulePartition([...CASES, { id: 'unexpected-c7', rule: 'C7' }]), /exempt rule C7 has vectors/);
  // A rule id outside the closed list.
  assert.throws(() => assertRulePartition([...CASES, { id: 'unexpected-s99', rule: 'S99' }]), /unknown rule S99/);
  // A case id mapped twice, which would hide a dropped vector.
  assert.throws(
    () => assertRulePartition([...CASES, { id: CASES[0].id, rule: CASES[0].rule }]),
    /case id is mapped twice/,
  );
});
