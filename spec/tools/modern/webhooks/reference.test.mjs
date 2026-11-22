// Boundary tests of the reference primitives, urls, addresses, ttl and emission of spec/tools/modern/webhooks/reference.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  acceptJwkSet,
  challengeEcho,
  checkReceiverDocFetch,
  checkUrl,
  classifyAddress,
  crossCheckWebhookKey,
  ed25519KeyFromSeed,
  emissionEntries,
  fetchDecision,
  formatIPv4,
  formatIPv6,
  IPV4_BLOCKS,
  IPV6_BLOCKS,
  jcs,
  jwkOf,
  pairKey,
  parseIPv4,
  parseIPv6,
  parseSignatureHeader,
  parseWhsec,
  subscriptionKey,
  ttlGrant,
} from './reference.mjs';
import { NOW } from '../../gen/core.mjs';

const KEY = { principal: 'alice', url: 'https://hooks.example.test/hooks/alice', name: 'incident.created' };

test('parseWhsec boundaries', () => {
  const ok = parseWhsec(`whsec_${Buffer.alloc(24, 1).toString('base64')}`);
  assert.equal(ok.ok, true);
  assert.equal(ok.key.length, 24);
  assert.deepEqual(parseWhsec(`whsec_${Buffer.alloc(23, 1).toString('base64')}`), { ok: false, code: 'invalid_secret', reason: 'length' });
  assert.equal(parseWhsec(`whsec_${Buffer.alloc(65, 1).toString('base64')}`).reason, 'length');
  assert.deepEqual(parseWhsec(`whsec_${'A'.repeat(31)}-`), { ok: false, code: 'invalid_secret', reason: 'alphabet' });
  const padded = Buffer.alloc(32, 1).toString('base64');
  assert.ok(padded.endsWith('='));
  assert.deepEqual(parseWhsec(`whsec_${padded.slice(0, -1)}`), { ok: false, code: 'invalid_secret', reason: 'padding' });
});

test('jcs', () => {
  assert.equal(jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(jcs([1, 1.0, 1e3, -0]), '[1,1,1000,0]');
  const accented = jcs({ name: 'café' });
  assert.equal(accented, '{"name":"café"}');
  assert.equal(accented.includes('\\u'), false);
});

test('subscriptionKey', () => {
  const first = subscriptionKey({ ...KEY, arguments: { severity: 'P1' } });
  assert.match(first.id, /^sub_[0-9a-f]{16}$/);
  assert.equal(first.id.length, 20);
  assert.deepEqual(subscriptionKey({ ...KEY, arguments: { severity: 'P1' } }), first);
  assert.equal(subscriptionKey(KEY).id, subscriptionKey({ ...KEY, arguments: null }).id);
});

test('ttlGrant', () => {
  const dflt = ttlGrant({ now: NOW });
  assert.equal(dflt.grantMs, 3600000);
  assert.ok(dflt.refreshBefore.endsWith('Z'));
  assert.deepEqual(ttlGrant({ ttlMs: 30000, now: NOW }), { ok: true, grantMs: 60000, refreshBefore: '2026-01-01T00:01:00Z' });
  assert.equal(ttlGrant({ ttlMs: 172800000, now: NOW }).grantMs, 86400000);
  assert.deepEqual(ttlGrant({ ttlMs: null, now: NOW }), { ok: true, grantMs: null, refreshBefore: null });
  assert.equal(ttlGrant({ ttlMs: -1, now: NOW }).code, 'invalid_arguments');
});

test('classifyAddress', () => {
  assert.deepEqual(classifyAddress('127.0.0.1'), { decision: 'reject', reason: 'loopback', family: 'ipv4', address: '127.0.0.1' });
  assert.equal(classifyAddress('8.8.8.8').decision, 'allow');
  assert.equal(classifyAddress('::1').reason, 'loopback');
  assert.equal(classifyAddress('2606:4700:4700::1111').decision, 'allow');
  assert.deepEqual(classifyAddress('::ffff:10.0.0.1'), {
    decision: 'reject',
    reason: 'ipv4_mapped/private_use',
    family: 'ipv6',
    address: '::ffff:10.0.0.1',
  });
});

// Both registry tables must classify the first and last address of their own block exactly as the deepest row says.
const FAMILIES = [
  { family: 'ipv4', rows: IPV4_BLOCKS, parse: parseIPv4, format: formatIPv4, width: 4 },
  { family: 'ipv6', rows: IPV6_BLOCKS, parse: parseIPv6, format: formatIPv6, width: 16 },
];
// The two translation rows hand the decision to the embedded IPv4 address instead of their own reachable column.
const CHAINED_ROWS = new Set(['ipv4_mapped', 'nat64_well_known']);

const decodeRow = (kind, row) => {
  const [literal, prefixText] = row.block.split('/');
  const parsed = kind.parse(literal);
  if (!parsed.ok) throw new Error(`${row.block}: unparsable network literal`);
  return { name: row.name, reachable: row.reachable, bytes: parsed.bytes, prefix: Number(prefixText) };
};

// First address clears every host bit below the prefix, last address sets them all.
const edgeOf = (kind, row, last) => {
  const bytes = Uint8Array.from(row.bytes);
  for (let i = 0; i < kind.width; i++) {
    const kept = Math.min(Math.max(row.prefix - i * 8, 0), 8);
    const networkBits = (0xff << (8 - kept)) & 0xff;
    const hostBits = last ? 0xff >> kept : 0;
    bytes[i] = ((bytes[i] & networkBits) | hostBits) & 0xff;
  }
  return bytes;
};

// Containment arithmetic on byte prefixes, written here rather than taken from the classifier.
const holdsPrefix = (bytes, network, prefix) => {
  const whole = prefix >> 3;
  for (let i = 0; i < whole; i++) if (bytes[i] !== network[i]) return false;
  const rest = prefix & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (bytes[whole] & mask) === (network[whole] & mask);
};

const deepestRow = (rows, bytes) => {
  let best = null;
  for (const row of rows) {
    if (!holdsPrefix(bytes, row.bytes, row.prefix)) continue;
    if (!best || row.prefix > best.prefix) best = row;
  }
  return best;
};

test('registry rows decide both edges of every block', () => {
  for (const kind of FAMILIES) {
    const rows = kind.rows.map((row) => decodeRow(kind, row));
    for (const row of rows) {
      for (const last of [false, true]) {
        const bytes = edgeOf(kind, row, last);
        const address = kind.format(bytes);
        const where = `${row.block} ${row.name} ${last ? 'last' : 'first'} address ${address}`;
        const verdict = classifyAddress(address);
        assert.equal(verdict.family, kind.family, `${where}: classifyAddress said family ${verdict.family}`);
        if (CHAINED_ROWS.has(row.name)) {
          const embedded = formatIPv4(bytes.subarray(12, 16));
          const inner = classifyAddress(embedded);
          const reasons = [row.name, `${row.name}/${inner.reason}`];
          assert.ok(reasons.includes(verdict.reason), `${where}: expected ${reasons.join(' or ')} but got ${verdict.reason}`);
          assert.equal(verdict.decision, inner.decision, `${where}: expected ${inner.decision} from embedded ${embedded} but got ${verdict.decision}`);
          continue;
        }
        const deepest = deepestRow(rows, bytes);
        assert.equal(verdict.reason, deepest.name, `${where}: expected ${deepest.name} but got ${verdict.reason}`);
        const decision = deepest.reachable ? 'allow' : 'reject';
        assert.equal(verdict.decision, decision, `${where}: expected ${decision} for ${deepest.name} but got ${verdict.decision}`);
      }
    }
  }
});

test('checkUrl', () => {
  assert.equal(checkUrl('https://hooks.example.test').canonical, 'https://hooks.example.test/');
  assert.deepEqual(checkUrl('http://x/'), { ok: false, code: 'scheme_not_https' });
  const userinfo = checkUrl('https://a@b.test/x');
  assert.equal(userinfo.code, 'invalid_callback_url');
  assert.equal(userinfo.reason, 'userinfo');
});

test('challengeEcho byte cap', () => {
  const nonce = 'A'.repeat(22);
  const skeleton = `{"challenge":"${nonce}","pad":""}`;
  const bodyOf = (bytes) => `{"challenge":"${nonce}","pad":"${'a'.repeat(bytes - Buffer.byteLength(skeleton))}"}`;
  const full = bodyOf(4096);
  assert.equal(Buffer.byteLength(full), 4096);
  assert.deepEqual(challengeEcho({ status: 200, bodyText: full, nonce }), { ok: true });
  assert.equal(challengeEcho({ status: 200, bodyText: bodyOf(4097), nonce }).reason, 'too_large');
  const wide = `{"challenge":"${nonce}","pad":"${'é'.repeat(2100)}"}`;
  assert.ok(Buffer.byteLength(wide) > 4096);
  assert.ok(wide.length < 4096);
  assert.deepEqual(challengeEcho({ status: 200, bodyText: wide, nonce, maxBody: 4096 }), {
    ok: false,
    code: 'challenge_failed',
    reason: 'too_large',
  });
});

test('pairKey value semantics', () => {
  assert.equal(pairKey(['alice', KEY.url]), JSON.stringify(['alice', KEY.url]));
  assert.equal(pairKey({ principal: 'alice', url: KEY.url }), pairKey(['alice', KEY.url]));
  assert.equal(pairKey(['alice']), null);
  assert.equal(pairKey(null), null);
  assert.equal(pairKey('alice'), null);
  assert.equal(pairKey({ principal: 'alice' }), null);
  assert.equal(pairKey({ principal: 1, url: KEY.url }), null);
});

test('checkReceiverDocFetch', () => {
  const doc = '{"receivers":["/hooks"]}';
  assert.deepEqual(checkReceiverDocFetch({ status: 200, bodyText: doc }), { ok: true, receivers: ['/hooks'] });
  for (const status of [204, 404, 500]) {
    assert.deepEqual(checkReceiverDocFetch({ status, bodyText: doc }), {
      ok: false,
      code: 'document_fetch_failed',
      reason: `status_${status}`,
    });
  }
  const padTo = (bytes) => doc + ' '.repeat(bytes - Buffer.byteLength(doc));
  assert.equal(Buffer.byteLength(padTo(8192)), 8192);
  assert.deepEqual(checkReceiverDocFetch({ status: 200, bodyText: padTo(8192) }), { ok: true, receivers: ['/hooks'] });
  assert.equal(checkReceiverDocFetch({ status: 200, bodyText: padTo(8193) }).reason, 'too_large');
});

test('crossCheckWebhookKey', () => {
  const a = ed25519KeyFromSeed(Buffer.alloc(32, 3));
  const b = ed25519KeyFromSeed(Buffer.alloc(32, 4));
  const tool = (key) => ({ webhook_key: { signing_keys: { keys: [jwkOf(key)], egress_ip_ranges: [] } } });
  assert.deepEqual(crossCheckWebhookKey({ keys: [jwkOf(a)], toolResult: tool(a), require: true }), { ok: true });
  assert.deepEqual(crossCheckWebhookKey({ keys: [jwkOf(a)], toolResult: tool(b), require: true }), {
    ok: false,
    code: 'webhook_key_mismatch',
  });
  assert.deepEqual(crossCheckWebhookKey({ keys: [jwkOf(a)], toolResult: null, require: true }), {
    ok: false,
    code: 'webhook_key_missing',
  });
  assert.deepEqual(crossCheckWebhookKey({ keys: [jwkOf(a)], toolResult: null, require: false }), { ok: true });
});

test('fetchDecision elapsed cap', () => {
  const mcpUrl = 'https://mcp.example.test/mcp';
  const cardUrl = 'https://mcp.example.test/mcp/server-card';
  const events = { 'io.modelcontextprotocol/events': { webhooks: { signingKeys: { keys: [] }, egressIpRanges: [] } } };
  const body_b64u = Buffer.from(JSON.stringify({ remotes: [{ url: mcpUrl, extensionsInfo: events }] })).toString('base64');
  const response = { status: 200, body_b64u };
  const within = fetchDecision({ mcpUrl, cardUrl, response, elapsed_ms: 10000 });
  assert.equal(within.ok, true);
  assert.deepEqual(within.keys, []);
  assert.deepEqual(fetchDecision({ mcpUrl, cardUrl, response, elapsed_ms: 10001 }), {
    ok: false,
    code: 'timeout',
    reason: 'elapsed',
  });
});

test('acceptJwkSet drops the server key', () => {
  const server = ed25519KeyFromSeed(Buffer.alloc(32, 5));
  const other = ed25519KeyFromSeed(Buffer.alloc(32, 6));
  const out = acceptJwkSet({ keys: [jwkOf(server), jwkOf(other)] }, { mcpServerKid: server.kid });
  assert.deepEqual(out.accepted.map((key) => key.kid), [other.kid]);
  assert.deepEqual(out.rejected, [{ kid: server.kid, reason: 'mcp_server_key' }]);
});

test('emissionEntries', () => {
  const secret = { secret: Buffer.alloc(24, 2), current: true };
  const parts = { webhookId: 'msg_test', timestamp: String(NOW), body: Buffer.from('{}'), endpointId: 'sub_0123456789abcdef' };
  const hmacOnly = emissionEntries({ secrets: [secret], keys: [], ...parts });
  assert.equal(hmacOnly.length, 1);
  const parsed = parseSignatureHeader(hmacOnly[0]);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.entries[0].scheme, 'v1');
  const key = ed25519KeyFromSeed(Buffer.alloc(32, 7));
  const withKey = emissionEntries({ secrets: [secret], keys: [{ key, current: true }], ...parts });
  assert.deepEqual(withKey.map((entry) => parseSignatureHeader(entry).entries[0].scheme), ['v1', 'v1a', 'v2a']);
});
