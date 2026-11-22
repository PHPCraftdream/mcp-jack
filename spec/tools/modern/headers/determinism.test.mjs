// Determinism and shape tests of the header family generator (spec 04). build()
// must be pure: identical inputs give byte-identical output, the imported case
// arrays are left untouched, and every stored request expectation carries the
// section 8 wire shape (a forward names the era and the forwarded request, a
// refusal carries the full signed JSON-RPC error).
import test from 'node:test';
import assert from 'node:assert/strict';
import generator from './index.mjs';
import { stableStringify } from './reference.mjs';
import { BY_REFERENCE, REQUEST_CASES } from './vectors/requests.mjs';
import { ENCODING_CASES } from './vectors/encoding.mjs';
import { ANNOTATION_CASES } from './vectors/annotations.mjs';
import { ERA_CASES } from './vectors/era.mjs';

const REQUEST_FILE = 'modern-request-vectors.json';
const ENCODING_FILE = 'header-encoding-vectors.json';
const ANNOTATION_FILE = 'x-mcp-header-vectors.json';
const ERA_FILE = 'era-detection-vectors.json';
const FILES = [REQUEST_FILE, ENCODING_FILE, ANNOTATION_FILE, ERA_FILE];

// The wire shape of a resolved expectation, from index.mjs and spec section 8.
const FORWARD_KEYS = ['consumes_nonce', 'era', 'forward', 'outcome'];
const FORWARD_FIELDS = ['headers', 'method', 'target'];
const REFUSAL_KEYS = ['consumes_nonce', 'content_type', 'era', 'error', 'id', 'jsonrpc', 'outcome', 'signed'];

test('family name is headers', () => {
  assert.equal(generator.family, 'headers');
});

test('build returns the four files and a markdown string', () => {
  const out = generator.build();

  assert.deepEqual(Object.keys(out.files), [
    'modern-request-vectors.json',
    'header-encoding-vectors.json',
    'x-mcp-header-vectors.json',
    'era-detection-vectors.json',
  ]);
  assert.equal(out.files[REQUEST_FILE].format, 'mcp-jack-modern-request-vectors-v1');
  assert.equal(out.files[ENCODING_FILE].format, 'mcp-jack-modern-header-encoding-v1');
  assert.equal(out.files[ANNOTATION_FILE].format, 'mcp-jack-modern-x-mcp-header-v1');
  assert.equal(out.files[ERA_FILE].format, 'mcp-jack-modern-era-detection-v1');

  assert.equal(typeof out.files[REQUEST_FILE].clock.now, 'number');
  assert.deepEqual(out.files[REQUEST_FILE].profiles, ['legacy', 'modern', 'both']);
  assert.equal(out.files[ANNOTATION_FILE].reason_codes.length, 8);
  assert.deepEqual(out.files[ERA_FILE].modern_error_codes, [-32020, -32021, -32022]);

  assert.equal(out.files[REQUEST_FILE].cases.length, 96);
  assert.equal(out.files[ENCODING_FILE].cases.length, 51);
  assert.equal(out.files[ANNOTATION_FILE].cases.length, 78);
  assert.equal(out.files[ERA_FILE].cases.length, 36);

  // Exactly one by-reference entry, asserted field by field. Its description is
  // free text, so only its type is pinned.
  const byReference = out.files[REQUEST_FILE].by_reference;
  assert.equal(byReference.length, 1);
  const [entry] = byReference;
  assert.deepEqual(Object.keys(entry).sort(), ['description', 'file', 'id', 'rule', 'vectors']);
  assert.equal(entry.id, 'cache-replay');
  assert.equal(entry.rule, 'C8');
  assert.equal(typeof entry.description, 'string');
  assert.equal(entry.file, 'fixtures/response-vectors.json');
  assert.deepEqual(entry.vectors, ['res-wrong-request-binding', 'res-accept']);

  assert.equal(typeof out.casesMarkdown, 'string');
});

test('build is deterministic', () => {
  const a = generator.build();
  const b = generator.build();
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.equal(stableStringify(a), stableStringify(b));
});

test('build does not mutate the imported case arrays', () => {
  const before = JSON.stringify([REQUEST_CASES, ENCODING_CASES, ANNOTATION_CASES, ERA_CASES]);
  const byReferenceBefore = JSON.stringify(BY_REFERENCE);
  generator.build();
  const after = JSON.stringify([REQUEST_CASES, ENCODING_CASES, ANNOTATION_CASES, ERA_CASES]);
  assert.equal(before, after);
  assert.equal(JSON.stringify(BY_REFERENCE), byReferenceBefore);
});

test('case ids are unique across the family', () => {
  const out = generator.build();
  const ids = FILES.flatMap((name) => out.files[name].cases.map((c) => c.id));
  for (const entry of out.files[REQUEST_FILE].by_reference) ids.push(entry.id);
  assert.equal(new Set(ids).size, ids.length);
  // 261 cases plus the single by-reference entry.
  assert.equal(ids.length, 262);
});

test('stored request expectations carry the full wire shape', () => {
  const out = generator.build();
  for (const c of out.files[REQUEST_FILE].cases) {
    const expect = c.expect;
    assert.ok(expect.outcome === 'forward' || expect.outcome === 'refuse', c.id);
    if (expect.outcome === 'forward') {
      assert.deepEqual(Object.keys(expect).sort(), FORWARD_KEYS, c.id);
      assert.deepEqual(Object.keys(expect.forward).sort(), FORWARD_FIELDS, c.id);
      assert.equal(expect.consumes_nonce, true, c.id);
      assert.ok(expect.era === 'legacy' || expect.era === 'modern', c.id);
      assert.equal(expect.forward.target, '/mcp', c.id);
      assert.ok(Array.isArray(expect.forward.headers), c.id);
    } else {
      assert.deepEqual(Object.keys(expect).sort(), REFUSAL_KEYS, c.id);
      assert.equal(expect.signed, true, c.id);
      assert.equal(expect.content_type, 'application/json', c.id);
      assert.equal(expect.jsonrpc, '2.0', c.id);
      assert.equal(expect.consumes_nonce, true, c.id);
      assert.equal(typeof expect.http_status, 'number', c.id);
      assert.equal(expect.era, 'modern', c.id);
      assert.deepEqual(Object.keys(expect.error).sort(), ['code', 'message'], c.id);
      assert.equal(typeof expect.error.code, 'number', c.id);
      assert.ok(typeof expect.error.message === 'string' && expect.error.message.length > 0, c.id);
      assert.ok(
        expect.id === null || typeof expect.id === 'string' || typeof expect.id === 'number',
        c.id,
      );
    }
  }
});

test('markdown names every file and its count', () => {
  const md = generator.build().casesMarkdown;
  for (const name of FILES) assert.ok(md.includes(name), name);
  assert.ok(md.includes('## Rule coverage'));
  assert.ok(md.includes('## By-reference cases'));
  assert.ok(md.includes('96 cases'));
  assert.ok(md.includes('51 cases'));
  assert.ok(md.includes('78 cases'));
  assert.ok(md.includes('36 cases'));
  assert.ok(md.includes('cache-replay'));
  assert.ok(md.endsWith('\n') && !md.endsWith('\n\n'));
});
