import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyRequest, encodeHeaderValue, decodeHeaderValue, validateAnnotations, projectArguments, detectEra, buildMirrors,
} from './reference.mjs';
import { META_VERSION_KEY, REASONS } from './spec-data.mjs';

const V = '2026-07-28';
const CT = ['Content-Type', 'application/json'];
const meta = { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} };
const bodyOf = (method, params = {}) => JSON.stringify({
  jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: meta },
});
const call = (params = { name: 'get_weather' }) => bodyOf('tools/call', params);
const mirrors = () => [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT];
const run = (request, profile = 'modern') => classifyRequest({
  profile, request: { method: 'POST', target: '/mcp', ...request },
});
const tokenOf = (out) => Object.keys(REASONS).find((key) => REASONS[key].message === out.error.message);
const outcomeOf = (out) => (out.outcome === 'refuse' ? tokenOf(out) : out.outcome);
const set = (name, value) => mirrors().map(([n, v]) => (n === name ? [n, value] : [n, v]));
const drop = (name) => mirrors().filter(([n]) => n !== name);

test('a valid modern request is forwarded unchanged', () => {
  assert.deepEqual(run({ headers: mirrors(), body_text: call() }), {
    outcome: 'forward', era: 'modern',
    forward: { method: 'POST', target: '/mcp', headers: mirrors() },
    consumes_nonce: true,
  });
  const empty = run({ headers: [...mirrors(), ['Mcp-Param-', 'x']], body_text: call() });
  assert.equal(empty.outcome, 'forward');
  assert.deepEqual(empty.forward.headers, [...mirrors(), ['Mcp-Param-', 'x']]);
});

test('each mirror mutation is refused with its own reason', () => {
  const noMeta = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_weather' } });
  const rows = [
    ['version mismatch', { headers: set('MCP-Protocol-Version', '2026-07-29'), body_text: call() }, 'version_mismatch'],
    ['malformed version', { headers: set('MCP-Protocol-Version', '2026-7-28'), body_text: call() }, 'version_header_malformed'],
    ['version header removed', { headers: drop('MCP-Protocol-Version'), body_text: call() }, 'version_header_missing'],
    ['body without _meta', { headers: mirrors(), body_text: noMeta }, 'version_meta_missing'],
    ['method header mismatch', { headers: set('Mcp-Method', 'resources/read'), body_text: call() }, 'method_header_mismatch'],
    ['method header removed', { headers: drop('Mcp-Method'), body_text: call() }, 'method_header_missing'],
    ['name header mismatch', { headers: set('Mcp-Name', 'get_forecast'), body_text: call() }, 'name_header_mismatch'],
    ['name header removed', { headers: drop('Mcp-Name'), body_text: call() }, 'name_header_missing'],
    ['name header bad encoding', { headers: set('Mcp-Name', '=?base64?@@@@?='), body_text: call() }, 'name_header_bad_encoding'],
    ['second Mcp-Name', { headers: [...mirrors(), ['Mcp-Name', 'get_weather']], body_text: call() }, 'header_repeated'],
    ['raw newline in name', { headers: set('Mcp-Name', 'get_\nweather'), body_text: call() }, 'header_value_invalid'],
    ['nul in param value', { headers: [...mirrors(), ['Mcp-Param-X', 'a\u0000b']], body_text: call() }, 'header_value_invalid'],
    ['tools/call without name', { headers: mirrors(), body_text: call({}) }, 'refuse_invalid_request'],
  ];
  for (const [label, request, reason] of rows) assert.equal(outcomeOf(run(request)), reason, label);
});

test('Mcp-Name on a method without a source field is refused', () => {
  const body_text = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: meta } });
  const headers = [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/list'], ['Mcp-Name', 'get_weather'], CT];
  assert.equal(outcomeOf(run({ headers, body_text })), 'name_header_not_applicable');
});

test('a tools/call without params.name is refused by body classification', () => {
  const expected = {
    outcome: 'refuse_invalid_request', era: null, signed: true,
    http_status: 400, content_type: 'application/json',
    error: { code: 'invalid_request', message: 'tools/call requires a string params.name' },
    consumes_nonce: true,
  };
  assert.deepEqual(run({ headers: mirrors(), body_text: call({}) }), expected);
  assert.deepEqual(run({ headers: mirrors(), body_text: call({}) }, 'legacy'), expected);
  assert.deepEqual(run({ headers: mirrors(), body_text: call({ name: 7 }) }, 'both'), expected);
  const notification = JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { _meta: meta } });
  assert.deepEqual(run({ headers: mirrors(), body_text: notification }), expected);
});

test('a method with a name source but no string value is name_source_missing', () => {
  const rows = [
    ['prompts/get', bodyOf('prompts/get')],
    ['events/subscribe', bodyOf('events/subscribe')],
  ];
  for (const [method, body_text] of rows) {
    const headers = [['MCP-Protocol-Version', V], ['Mcp-Method', method], ['Mcp-Name', 'x'], CT];
    assert.equal(outcomeOf(run({ headers, body_text })), 'name_source_missing', method);
  }
});

test('era decision and method rules', () => {
  assert.equal(outcomeOf(run({ method: 'GET', headers: [['MCP-Protocol-Version', V]] })), 'method_not_allowed');
  assert.equal(outcomeOf(run({ method: 'GET', headers: [['MCP-Protocol-Version', V]] }, 'both')), 'method_not_allowed');

  const legacyGet = run({ method: 'GET', headers: [] }, 'both');
  assert.equal(legacyGet.outcome, 'forward');
  assert.equal(legacyGet.era, 'legacy');

  const stripped = run({ headers: [...mirrors(), ['Mcp-Session-Id', 's1']], body_text: call() });
  assert.deepEqual(stripped, {
    outcome: 'forward', era: 'modern',
    forward: { method: 'POST', target: '/mcp', headers: mirrors() },
    consumes_nonce: true,
  });

  const retained = run({ headers: [...mirrors(), ['Mcp-Session-Id', 's1']], body_text: call() }, 'legacy');
  assert.equal(retained.outcome, 'forward');
  assert.equal(retained.era, 'legacy');
  assert.equal(retained.forward.headers.length, 5);
  assert.deepEqual(retained.forward.headers, [
    ['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Session-Id', 's1'],
  ]);

  const noVersion = run({ headers: [['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather']], body_text: call() }, 'both');
  assert.equal(outcomeOf(noVersion), 'version_header_missing');

  const legacyMalformed = run({
    headers: [CT, ['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Name', 'get\nweather']],
    body_text: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_weather' } }),
  }, 'both');
  assert.equal(legacyMalformed.outcome, 'forward');
  assert.equal(legacyMalformed.era, 'legacy');
  assert.deepEqual(legacyMalformed.forward.headers, [CT, ['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Name', 'get\nweather']]);

  const legacyResponse = run({
    headers: [CT, ['Mcp-Session-Id', 's1']],
    body_text: JSON.stringify({ jsonrpc: '2.0', id: 7, error: { code: -32601, message: 'x' } }),
  }, 'both');
  assert.equal(legacyResponse.outcome, 'forward');
  assert.equal(legacyResponse.era, 'legacy');
  assert.deepEqual(legacyResponse.forward.headers, [CT, ['Mcp-Session-Id', 's1']]);
});

test('encoding literals, round trip and refusal', () => {
  const rows = [
    ['', ''],
    ['us-west1', 'us-west1'],
    [' padded ', '=?base64?IHBhZGRlZCA=?='],
    ['line1\nline2', '=?base64?bGluZTEKbGluZTI=?='],
    ['=?base64?literal?=', '=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?='],
    ['Hello, 世界', '=?base64?SGVsbG8sIOS4lueVjA==?='],
    ['a\tb', '=?base64?YQli?='],
    ['a\rb', '=?base64?YQ1i?='],
    ['a\u0000b', '=?base64?YQBi?='],
    ['a\u007fb', '=?base64?YX9i?='],
    [' leading', '=?base64?IGxlYWRpbmc=?='],
    ['trailing ', '=?base64?dHJhaWxpbmcg?='],
  ];
  for (const [text, header] of rows) {
    assert.equal(encodeHeaderValue(text), header, JSON.stringify(text));
    assert.deepEqual(decodeHeaderValue(header), { ok: true, text }, JSON.stringify(text));
  }
  assert.deepEqual(decodeHeaderValue('=?base64? SGVsbG8=?='), { ok: false, reason: 'bad_encoding' });
  assert.deepEqual(decodeHeaderValue('=?BASE64?SGVsbG8=?='), { ok: true, text: '=?BASE64?SGVsbG8=?=' });
});

test('buildMirrors emits C2 order', () => {
  assert.deepEqual(buildMirrors({ version: V, method: 'tools/call', params: { name: 'get_weather' } }), {
    meta,
    headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather']],
  });
  assert.deepEqual(buildMirrors({ version: V, method: 'server/discover', params: {} }), {
    meta,
    headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'server/discover']],
  });
});

test('annotation validation', () => {
  const valid = { properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } };
  const region = (prop) => ({ properties: { region: prop } });
  assert.deepEqual(validateAnnotations(valid), { valid: true, reason: null });
  assert.deepEqual(validateAnnotations({ properties: { 'x-mcp-header': { type: 'string' } } }), {
    valid: true, reason: null,
  });
  assert.deepEqual(validateAnnotations({ properties: { 'x-mcp-header': { type: 'string', 'x-mcp-header': 'XHeader' } } }), {
    valid: true, reason: null,
  });
  assert.deepEqual(validateAnnotations({ properties: { '': { type: 'string', 'x-mcp-header': 'Empty' } } }), {
    valid: true, reason: null,
  });
  // Validation alone would still pass if the annotation were dropped, so every
  // schema expected to be valid must also project its header (or none at all).
  const reachable = [
    ['property named properties', { properties: { properties: { type: 'string', 'x-mcp-header': 'Props' } } },
      { properties: 'v2' }, [['Mcp-Param-Props', 'v2']]],
    ['nested property named properties', {
      properties: { outer: { type: 'object', properties: { properties: { type: 'string', 'x-mcp-header': 'Inner' } } } },
    }, { outer: { properties: 'p' } }, [['Mcp-Param-Inner', 'p']]],
    ['property named x-mcp-header inside allOf', {
      allOf: [{ properties: { 'x-mcp-header': { type: 'string' } } }],
    }, { 'x-mcp-header': 'v1' }, []],
  ];
  for (const [label, schema, args, headers] of reachable) {
    assert.deepEqual(validateAnnotations(schema), { valid: true, reason: null }, label);
    assert.deepEqual(projectArguments(schema, args), { outcome: 'headers', headers }, label);
  }
  const rows = [
    ['empty', region({ type: 'string', 'x-mcp-header': '' }), 'annotation_name_empty'],
    ['not a token', region({ type: 'string', 'x-mcp-header': 'Re gion' }), 'annotation_name_not_token'],
    ['control', region({ type: 'string', 'x-mcp-header': 'a\rb' }), 'annotation_name_control'],
    ['not a string', region({ type: 'string', 'x-mcp-header': 42 }), 'annotation_name_not_string'],
    ['duplicate', {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        city: { type: 'string', 'x-mcp-header': 'region' },
      },
    }, 'annotation_name_duplicate'],
    ['not primitive', region({ type: 'number', 'x-mcp-header': 'Region' }), 'annotation_type_not_primitive'],
    ['integer range', region({ type: 'integer', maximum: 9007199254740992, 'x-mcp-header': 'Region' }), 'annotation_integer_range_invalid'],
    ['under items', {
      properties: { region: { type: 'array', items: { type: 'string', 'x-mcp-header': 'Region' } } },
    }, 'annotation_not_statically_reachable'],
  ];
  for (const [label, schema, reason] of rows) {
    assert.deepEqual(validateAnnotations(schema), { valid: false, reason }, label);
  }
});

test('projection', () => {
  const valid = { properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } };
  assert.deepEqual(projectArguments(valid, { region: 'eu' }), {
    outcome: 'headers', headers: [['Mcp-Param-Region', 'eu']],
  });
  assert.deepEqual(projectArguments(valid, {}), { outcome: 'headers', headers: [] });
  assert.deepEqual(projectArguments(valid, { region: null }), { outcome: 'headers', headers: [] });
  assert.deepEqual(projectArguments(valid, { region: 42 }), {
    outcome: 'refuse', reason: 'header_projection_invalid_value',
  });
  const named = { properties: { 'x-mcp-header': { type: 'string', 'x-mcp-header': 'XHeader' } } };
  assert.deepEqual(projectArguments(named, { 'x-mcp-header': 'v1' }), {
    outcome: 'headers', headers: [['Mcp-Param-XHeader', 'v1']],
  });
  const empty = { properties: { '': { type: 'string', 'x-mcp-header': 'Empty' } } };
  assert.deepEqual(projectArguments(empty, { '': 'e' }), {
    outcome: 'headers', headers: [['Mcp-Param-Empty', 'e']],
  });
});

test('era detection requires a recognised JSON-RPC error', () => {
  const envelope = (code, extra = '') => '{"jsonrpc":"2.0","id":1,"error":{"code":' + code + ',"message":"x"' + extra + '}}';
  const era = (response, clientVersions = []) => detectEra({ response, clientVersions });
  assert.deepEqual(era({ verified: false, status: 400, body_text: envelope(-32020) }), {
    era: 'none', action: 'abort', reason: 'unverified',
  });
  const rows = [
    ['recognised -32020', { verified: true, status: 400, body_text: envelope(-32020) }, {
      era: 'modern', action: 'stay_modern', reason: null,
    }],
    ['bare error object', { verified: true, status: 400, body_text: '{"error":{"code":-32020}}' }, {
      era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error',
    }],
    ['null id', { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":null,"error":{"code":-32020,"message":"x"}}' }, {
      era: 'modern', action: 'stay_modern', reason: null,
    }],
    ['string code', { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":"-32020","message":"x"}}' }, {
      era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error',
    }],
    ['no id member', { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","error":{"code":-32020,"message":"x"}}' }, {
      era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error',
    }],
    ['jack envelope', { verified: true, status: 400, body_text: '{"error":{"code":"invalid_request"}}' }, {
      era: 'legacy', action: 'fallback_initialize', reason: 'jack_envelope',
    }],
    ['404 unrecognised', { verified: true, status: 404, body_text: '{"error":{"code":-32601}}' }, {
      era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error',
    }],
  ];
  for (const [label, response, expected] of rows) assert.deepEqual(era(response), expected, label);
  const overlap = ',"data":{"supported":["2026-07-28","2099-01-01"]}';
  assert.deepEqual(era({ verified: true, status: 400, body_text: envelope(-32022, overlap) }, ['2026-07-28']), {
    era: 'modern', action: 'retry_with_supported', reason: null, supported: ['2026-07-28'],
  });
  const disjoint = ',"data":{"supported":["2099-01-01"]}';
  assert.deepEqual(era({ verified: true, status: 400, body_text: envelope(-32022, disjoint) }, ['2026-07-28']), {
    era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap',
  });
  const mixed = ',"data":{"supported":["2026-07-28",7]}';
  assert.deepEqual(era({ verified: true, status: 400, body_text: envelope(-32022, mixed) }, ['2026-07-28']), {
    era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap',
  });
  assert.deepEqual(era({ verified: true, status: 400, body_text: '{"jsonrpc":"1.0","id":1,"error":{"code":"invalid_request","message":"x"}}' }), {
    era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error',
  });
  const notFound = '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}';
  assert.deepEqual(era({ verified: true, status: 404, body_text: notFound }), {
    era: 'modern', action: 'stay_modern', reason: 'modern_method_not_found',
  });
});
