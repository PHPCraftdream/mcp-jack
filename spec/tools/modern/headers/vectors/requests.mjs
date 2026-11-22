// Request-level vectors of spec 04 sections 3-6 and 8. Data only: no build,
// no I/O, no clock, no randomness. Every case violates exactly one rule.
import { MODERN_MIN, META_VERSION_KEY } from '../spec-data.mjs';
import { encodeHeaderValue } from '../reference.mjs';

const V = MODERN_MIN;
const CT = ['Content-Type', 'application/json'];
const META_V = META_VERSION_KEY;
const meta = (version = V) => ({ [META_V]: version, 'io.modelcontextprotocol/clientCapabilities': {} });
const callBody = (method, params = {}, version = V) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: meta(version) } });
const callBodyNoMeta = (method, params = {}) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
const notifBody = (method, params = {}, version = V) => JSON.stringify({ jsonrpc: '2.0', method, params: { ...params, _meta: meta(version) } });
const mirrors = (method, name) => [['MCP-Protocol-Version', V], ['Mcp-Method', method], ...(name === undefined ? [] : [['Mcp-Name', name]]), CT];

// The four documented sentinel values of spec 04 section 4. Their base64 is
// transcribed from the source table and asserted against the encoder at load,
// so the constants cannot drift from the reference implementation.
const B64_HELLO_WORLD = '=?base64?SGVsbG8sIOS4lueVjA==?=';
const B64_PADDED = '=?base64?IHBhZGRlZCA=?=';
const B64_LINE = '=?base64?bGluZTEKbGluZTI=?=';
const B64_LITERAL = '=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=';
if (encodeHeaderValue('Hello, 世界') !== B64_HELLO_WORLD) throw new Error('base64 constant mismatch: Hello, 世界');
if (encodeHeaderValue(' padded ') !== B64_PADDED) throw new Error('base64 constant mismatch: padded');
if (encodeHeaderValue('line1\nline2') !== B64_LINE) throw new Error('base64 constant mismatch: line1 LF line2');
if (encodeHeaderValue('=?base64?literal?=') !== B64_LITERAL) throw new Error('base64 constant mismatch: literal sentinel');

// Names that need a sentinel are always encoded here, never typed.
const ENC_TOOL_NAME = encodeHeaderValue('get wéather');
const ENC_RESOURCE_URI = encodeHeaderValue('file:///prøjects/a b.json');
const ENC_PROMPT_NAME = encodeHeaderValue('sum már');
const ENC_EVENT_POLL = encodeHeaderValue('émail.received');
const ENC_EVENT_STREAM = encodeHeaderValue('incidént.created');
const ENC_EVENT_SUBSCRIBE = encodeHeaderValue('incidént.subscribed');
const ENC_EVENT_UNSUBSCRIBE = encodeHeaderValue('incidént.unsubscribed');
const ENC_FORECAST = encodeHeaderValue('get_forecast');

export const REQUEST_CASES = [
  // A. Era decision (S3). A modern signal in either mirror selects the modern
  // era; a legacy-era request is forwarded with its headers untouched.
  {
    id: 'req-legacy-profile-plain-tools-call', rule: 'S3', description: 'legacy profile serves a meta-less call as legacy and keeps the session header',
    profile: 'legacy',
    request: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Session-Id', 'sess-1']], body_text: callBodyNoMeta('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'legacy', forward: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Session-Id', 'sess-1']] } },
  },
  {
    id: 'req-legacy-profile-ignores-modern-mirrors', rule: 'S3', description: 'legacy profile ignores modern mirrors, even a wrong name and a newer body version',
    profile: 'legacy',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'wrong_name'], CT, ['Mcp-Session-Id', 'sess-2']],
      body_text: callBody('tools/call', { name: 'get_weather' }, '2026-07-29') },
    expect: { outcome: 'forward', era: 'legacy',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'wrong_name'], CT, ['Mcp-Session-Id', 'sess-2']] } },
  },
  {
    id: 'req-both-legacy-client-2025-11-25', rule: 'S3', description: 'a 2025-11-25 version header keeps a both-profile request legacy',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Session-Id', 's-9'], CT],
      body_text: callBodyNoMeta('tools/call', { name: 'echo' }) },
    expect: { outcome: 'forward', era: 'legacy',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Session-Id', 's-9'], CT] } },
  },
  {
    id: 'req-both-no-signals', rule: 'S3', description: 'no modern signal means legacy under the both profile',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: [CT], body_text: callBodyNoMeta('tools/list') },
    expect: { outcome: 'forward', era: 'legacy', forward: { method: 'POST', target: '/mcp', headers: [CT] } },
  },
  {
    id: 'req-both-modern-by-header', rule: 'S3', description: 'a modern version header makes the request modern and drops the session header',
    profile: 'both',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Session-Id', 'sess-3']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },
  {
    id: 'req-both-modern-by-meta-only', rule: 'S3', description: 'a modern body version alone makes the request modern, so the missing header is refused',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: [['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_header_missing', id: 1 },
  },
  {
    id: 'req-both-legacy-malformed-name-forwarded', rule: 'S3', description: 'no Section 5 rule may refuse a legacy-era request, not even a malformed name mirror',
    profile: 'both',
    request: { method: 'POST', target: '/mcp',
      headers: [CT, ['MCP-Protocol-Version', '2025-11-25'], ['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Name', 'get\nweather'], ['Mcp-Param-Tenant', 't\u0000x']],
      body_text: callBodyNoMeta('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'legacy',
      forward: { method: 'POST', target: '/mcp',
        headers: [CT, ['MCP-Protocol-Version', '2025-11-25'], ['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Name', 'get\nweather'], ['Mcp-Param-Tenant', 't\u0000x']] } },
  },
  {
    id: 'req-both-legacy-malformed-param-forwarded', rule: 'S3', description: 'a legacy-era request with an empty Mcp-Param name is forwarded untouched',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Param-', 'x']], body_text: callBodyNoMeta('tools/list') },
    expect: { outcome: 'forward', era: 'legacy', forward: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Param-', 'x']] } },
  },

  // B. Header syntax (S1): at most one mirror instance, field-value syntax on
  // each mirror and on every recognised Mcp-Param value.
  {
    id: 'req-version-header-repeated', rule: 'S1', description: 'a repeated MCP-Protocol-Version is refused in the modern era',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['MCP-Protocol-Version', '2026-07-29'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_repeated', id: 1 },
  },
  {
    id: 'req-method-header-repeated', rule: 'S1', description: 'a repeated Mcp-Method is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Method', 'resources/read'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_repeated', id: 1 },
  },
  {
    id: 'req-name-header-repeated', rule: 'S1', description: 'a repeated Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], ['Mcp-Name', ENC_FORECAST], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_repeated', id: 1 },
  },
  {
    id: 'req-name-header-lf', rule: 'S1', description: 'an LF in Mcp-Name violates the field-value syntax even though the body carries the same character',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get\nweather'], CT],
      body_text: callBody('tools/call', { name: 'get\nweather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-name-header-cr', rule: 'S1', description: 'a CR in Mcp-Name violates the field-value syntax even though the body carries the same character',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get\rweather'], CT],
      body_text: callBody('tools/call', { name: 'get\rweather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-name-header-nul', rule: 'S1', description: 'a NUL in Mcp-Name violates the field-value syntax even though the body carries the same character',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get\u0000weather'], CT],
      body_text: callBody('tools/call', { name: 'get\u0000weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-name-header-del', rule: 'S1', description: 'DEL in Mcp-Name violates the field-value syntax even though the body carries the same character',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get\u007fweather'], CT],
      body_text: callBody('tools/call', { name: 'get\u007fweather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-name-header-nonascii', rule: 'S1', description: 'a non-ASCII Mcp-Name violates the field-value syntax before any decoding',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_wéather'], CT],
      body_text: callBody('tools/call', { name: 'get_wéather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-param-value-nul', rule: 'S1', description: 'a NUL in an Mcp-Param value is refused, never forwarded',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-Tenant', 't\u0000x']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-param-value-del', rule: 'S1', description: 'DEL in an Mcp-Param value is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-Tenant', 't\u007fx']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-param-value-nonascii', rule: 'S1', description: 'a non-ASCII Mcp-Param value is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-Tenant', 'ténant']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'header_value_invalid', id: 1 },
  },
  {
    id: 'req-param-value-tab', rule: 'S1', description: 'HTAB is valid field-value syntax, so the param header is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-Tenant', 'a\tb']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-Tenant', 'a\tb']] } },
  },
  {
    id: 'req-param-name-empty-forwarded', rule: 'S1', description: 'Mcp-Param- alone has an empty name, so it is an unknown header and is forwarded',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-', 'x']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Param-', 'x']] } },
  },

  // C. Method (S2): only POST is defined in the modern era.
  {
    id: 'req-modern-get', rule: 'S2', description: 'GET is refused in the modern era with a null id',
    profile: 'modern',
    request: { method: 'GET', target: '/mcp', headers: [['MCP-Protocol-Version', V]] },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_not_allowed', id: null },
  },
  {
    id: 'req-modern-delete', rule: 'S2', description: 'DELETE is refused before the version mirror is checked',
    profile: 'modern',
    request: { method: 'DELETE', target: '/mcp', headers: mirrors('tools/call', 'get_weather'), body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_not_allowed', id: null },
  },
  {
    id: 'req-modern-put', rule: 'S2', description: 'PUT is refused in the modern era',
    profile: 'modern',
    request: { method: 'PUT', target: '/mcp', headers: mirrors('tools/list'), body_text: callBody('tools/list') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_not_allowed', id: null },
  },
  {
    id: 'req-modern-head', rule: 'S2', description: 'HEAD is refused in the modern era',
    profile: 'modern',
    request: { method: 'HEAD', target: '/mcp', headers: [['MCP-Protocol-Version', V]] },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_not_allowed', id: null },
  },
  {
    id: 'req-both-get-modern-header', rule: 'S2', description: 'a modern header makes a both-profile GET modern and refused',
    profile: 'both',
    request: { method: 'GET', target: '/mcp', headers: [['MCP-Protocol-Version', V]] },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_not_allowed', id: null },
  },
  {
    id: 'req-both-get-legacy', rule: 'S2', description: 'a GET without a modern signal stays legacy and is forwarded',
    profile: 'both',
    request: { method: 'GET', target: '/mcp', headers: [CT] },
    expect: { outcome: 'forward', era: 'legacy', forward: { method: 'GET', target: '/mcp', headers: [CT] } },
  },

  // D. Version mirror (S4): header present, well-formed, body version present
  // as a string and byte-equal.
  {
    id: 'req-both-header-modern-meta-below', rule: 'S4', description: 'a modern header with a pre-2026 body version is a mismatch',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'),
      body_text: callBody('tools/call', { name: 'get_weather' }, '2025-11-25') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_mismatch', id: 1 },
  },
  {
    id: 'req-version-header-missing', rule: 'S4', description: 'a modern request without MCP-Protocol-Version is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_header_missing', id: 1 },
  },
  {
    id: 'req-version-header-short-month', rule: 'S4', description: 'a one-digit month is not a version value',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2026-7-28'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }, '2026-7-28') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_header_malformed', id: 1 },
  },
  {
    id: 'req-version-header-suffix', rule: 'S4', description: 'a version with a suffix is malformed',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2026-07-28-draft'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }, '2026-07-28-draft') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_header_malformed', id: 1 },
  },
  {
    id: 'req-version-meta-missing', rule: 'S4', description: 'a request without a body version is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'), body_text: callBodyNoMeta('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_meta_missing', id: 1 },
  },
  {
    id: 'req-version-meta-not-string', rule: 'S4', description: 'a numeric body version counts as missing',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'),
      body_text: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_weather', _meta: { [META_V]: 20260728 } } }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_meta_missing', id: 1 },
  },
  {
    id: 'req-version-mismatch', rule: 'S4', description: 'a body version above the header is a mismatch',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'), body_text: callBody('tools/call', { name: 'get_weather' }, '2026-07-29') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_mismatch', id: 1 },
  },
  {
    id: 'req-version-below-boundary-modern', rule: 'S4', description: 'a well-formed pre-2026 version is forwarded, not refused by Jack',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }, '2025-11-25') },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2025-11-25'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },
  {
    id: 'req-version-above-boundary', rule: 'S4', description: 'a future well-formed version is forwarded',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2027-01-01'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }, '2027-01-01') },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', '2027-01-01'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },

  // E. Mcp-Method (S5): present and byte-equal to the body method.
  {
    id: 'req-method-header-missing', rule: 'S5', description: 'a modern request without Mcp-Method is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_header_missing', id: 1 },
  },
  {
    id: 'req-method-header-mismatch', rule: 'S5', description: 'an Mcp-Method differing from the body method is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_header_mismatch', id: 1 },
  },
  {
    id: 'req-method-header-case', rule: 'S5', description: 'Mcp-Method values are case-sensitive',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'Tools/Call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_header_mismatch', id: 1 },
  },
  {
    id: 'req-method-header-empty', rule: 'S5', description: 'an empty Mcp-Method never matches the method',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', ''], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'method_header_mismatch', id: 1 },
  },
  {
    id: 'req-modern-profile-discover', rule: 'S5', description: 'server/discover carries no Mcp-Name and is forwarded',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'server/discover'], CT],
      body_text: callBody('server/discover', {}) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'server/discover'], CT] } },
  },

  // F. Mcp-Name (S6): the closed source table, one case per method plus the
  // encoding, padding and sentinel edges.
  {
    id: 'req-name-tools-call-missing', rule: 'S6', description: 'tools/call without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], CT],
      body_text: callBody('tools/call', { name: 'get wéather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-tools-call-mismatch', rule: 'S6', description: 'an Mcp-Name naming another tool is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'other_tool'], CT],
      body_text: callBody('tools/call', { name: 'get wéather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-tools-call-encoded', rule: 'S6', description: 'a sentinel-encoded tools/call name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', ENC_TOOL_NAME], CT],
      body_text: callBody('tools/call', { name: 'get wéather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', ENC_TOOL_NAME], CT] } },
  },
  {
    id: 'req-name-resources-read-missing', rule: 'S6', description: 'resources/read without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], CT],
      body_text: callBody('resources/read', { uri: 'file:///prøjects/a b.json' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-resources-read-mismatch', rule: 'S6', description: 'resources/read mirrors params.uri, so another uri is a mismatch',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', 'file:///other.json'], CT],
      body_text: callBody('resources/read', { uri: 'file:///prøjects/a b.json' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-resources-read-encoded', rule: 'S6', description: 'a sentinel-encoded uri is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', ENC_RESOURCE_URI], CT],
      body_text: callBody('resources/read', { uri: 'file:///prøjects/a b.json' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', ENC_RESOURCE_URI], CT] } },
  },
  {
    id: 'req-name-prompts-get-missing', rule: 'S6', description: 'prompts/get without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], CT],
      body_text: callBody('prompts/get', { name: 'sum már' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-prompts-get-mismatch', rule: 'S6', description: 'an Mcp-Name naming another prompt is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], ['Mcp-Name', 'other_prompt'], CT],
      body_text: callBody('prompts/get', { name: 'sum már' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-prompts-get-encoded', rule: 'S6', description: 'a sentinel-encoded prompt name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], ['Mcp-Name', ENC_PROMPT_NAME], CT],
      body_text: callBody('prompts/get', { name: 'sum már' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], ['Mcp-Name', ENC_PROMPT_NAME], CT] } },
  },
  {
    id: 'req-name-events-poll-missing', rule: 'S6', description: 'events/poll without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/poll'], CT],
      body_text: callBody('events/poll', { name: 'émail.received' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-events-poll-mismatch', rule: 'S6', description: 'an Mcp-Name naming another event type is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/poll'], ['Mcp-Name', 'other.event'], CT],
      body_text: callBody('events/poll', { name: 'émail.received' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-events-poll-encoded', rule: 'S6', description: 'a sentinel-encoded events/poll name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/poll'], ['Mcp-Name', ENC_EVENT_POLL], CT],
      body_text: callBody('events/poll', { name: 'émail.received' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/poll'], ['Mcp-Name', ENC_EVENT_POLL], CT] } },
  },
  {
    id: 'req-name-events-stream-missing', rule: 'S6', description: 'events/stream without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/stream'], CT],
      body_text: callBody('events/stream', { name: 'incidént.created' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-events-stream-mismatch', rule: 'S6', description: 'an Mcp-Name naming another event type is refused for events/stream',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/stream'], ['Mcp-Name', 'other.event'], CT],
      body_text: callBody('events/stream', { name: 'incidént.created' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-events-stream-encoded', rule: 'S6', description: 'a sentinel-encoded events/stream name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/stream'], ['Mcp-Name', ENC_EVENT_STREAM], CT],
      body_text: callBody('events/stream', { name: 'incidént.created' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/stream'], ['Mcp-Name', ENC_EVENT_STREAM], CT] } },
  },
  {
    id: 'req-name-events-subscribe-missing', rule: 'S6', description: 'events/subscribe without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], CT],
      body_text: callBody('events/subscribe', { name: 'incidént.subscribed' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-events-subscribe-mismatch', rule: 'S6', description: 'an Mcp-Name naming another event type is refused for events/subscribe',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], ['Mcp-Name', 'other.event'], CT],
      body_text: callBody('events/subscribe', { name: 'incidént.subscribed' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-events-subscribe-encoded', rule: 'S6', description: 'a sentinel-encoded events/subscribe name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], ['Mcp-Name', ENC_EVENT_SUBSCRIBE], CT],
      body_text: callBody('events/subscribe', { name: 'incidént.subscribed' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], ['Mcp-Name', ENC_EVENT_SUBSCRIBE], CT] } },
  },
  {
    id: 'req-name-events-unsubscribe-missing', rule: 'S6', description: 'events/unsubscribe without Mcp-Name is refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/unsubscribe'], CT],
      body_text: callBody('events/unsubscribe', { name: 'incidént.unsubscribed' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_missing', id: 1 },
  },
  {
    id: 'req-name-events-unsubscribe-mismatch', rule: 'S6', description: 'an Mcp-Name naming another event type is refused for events/unsubscribe',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/unsubscribe'], ['Mcp-Name', 'other.event'], CT],
      body_text: callBody('events/unsubscribe', { name: 'incidént.unsubscribed' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-events-unsubscribe-encoded', rule: 'S6', description: 'a sentinel-encoded events/unsubscribe name is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/unsubscribe'], ['Mcp-Name', ENC_EVENT_UNSUBSCRIBE], CT],
      body_text: callBody('events/unsubscribe', { name: 'incidént.unsubscribed' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/unsubscribe'], ['Mcp-Name', ENC_EVENT_UNSUBSCRIBE], CT] } },
  },
  {
    id: 'req-name-source-missing-tools-call', rule: 'S6', description: 'a tools/call without params.name is refused by body classification before any Section 5 rule',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'x'], CT],
      body_text: callBody('tools/call', {}) },
    expect: { outcome: 'refuse_invalid_request' },
  },
  {
    id: 'req-name-source-missing-prompts-get', rule: 'S6', description: 'prompts/get without params.name has no mirror source',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], ['Mcp-Name', 'x'], CT],
      body_text: callBody('prompts/get', {}) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_source_missing', id: 1 },
  },
  {
    id: 'req-name-source-missing-events-subscribe', rule: 'S6', description: 'events/subscribe without params.name has no mirror source',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], ['Mcp-Name', 'x'], CT],
      body_text: callBody('events/subscribe', {}) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_source_missing', id: 1 },
  },
  {
    id: 'req-name-source-not-string', rule: 'S6', description: 'a non-string params.uri cannot be mirrored',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', '7'], CT],
      body_text: callBody('resources/read', { uri: 7 }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_source_missing', id: 1 },
  },
  {
    id: 'req-name-padded-encoded', rule: 'S6', description: 'leading and trailing spaces need a sentinel, which is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_PADDED], CT],
      body_text: callBody('tools/call', { name: ' padded ' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_PADDED], CT] } },
  },
  {
    id: 'req-name-padded-raw', rule: 'S6', description: 'the value after OWS removal drops the padding spaces and no longer matches',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'padded'], CT],
      body_text: callBody('tools/call', { name: ' padded ' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-encoded-mismatch', rule: 'S6', description: 'an encoded name for another tool decodes cleanly and is still refused',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', ENC_FORECAST], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-bad-base64', rule: 'S6', description: 'base64 outside the alphabet is not decodable',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?@@@@?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-missing-padding', rule: 'S6', description: 'base64 without its padding is not decodable',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?SGVsbG8?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-noncanonical-base64', rule: 'S6', description: 'non-zero unused trailing bits make the base64 non-canonical',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?SGVsbG9=?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-invalid-utf8', rule: 'S6', description: 'bytes that are not UTF-8 are not decodable',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?/w==?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-space-in-base64', rule: 'S6', description: 'a space inside the base64 is not decodable',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?SGVs bG8=?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-sentinel-newline', rule: 'S6', description: 'a sentinel carrying an LF decodes to the body name and is forwarded',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_LINE], CT],
      body_text: callBody('tools/call', { name: 'line1\nline2' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_LINE], CT] } },
  },
  {
    id: 'req-name-sentinel-literal-encoded', rule: 'S6', description: 'a value that looks like a sentinel is encoded and decodes back',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_LITERAL], CT],
      body_text: callBody('tools/call', { name: '=?base64?literal?=' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_LITERAL], CT] } },
  },
  {
    id: 'req-name-sentinel-literal-raw', rule: 'S6', description: 'a raw sentinel-shaped value is a sentinel with a bad inner text',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?literal?='], CT],
      body_text: callBody('tools/call', { name: '=?base64?literal?=' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_bad_encoding', id: 1 },
  },
  {
    id: 'req-name-marker-case', rule: 'S6', description: 'the sentinel markers are case-sensitive, so an uppercase marker is plain text',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?BASE64?SGVsbG8=?='], CT],
      body_text: callBody('tools/call', { name: 'Hello' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: 1 },
  },
  {
    id: 'req-name-empty-inner', rule: 'S6', description: 'an empty sentinel inner text decodes to the empty name',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64??='], CT],
      body_text: callBody('tools/call', { name: '' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64??='], CT] } },
  },
  {
    id: 'req-name-events-list', rule: 'S6', description: 'events/list has no source field and refuses Mcp-Name',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('events/list', 'incident.created'), body_text: callBody('events/list') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_not_applicable', id: 1 },
  },
  {
    id: 'req-name-tools-list', rule: 'S6', description: 'tools/list refuses Mcp-Name',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/list', 'get_weather'), body_text: callBody('tools/list') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_not_applicable', id: 1 },
  },
  {
    id: 'req-name-subscriptions-listen', rule: 'S6', description: 'subscriptions/listen refuses Mcp-Name',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('subscriptions/listen', 'toolsListChanged'), body_text: callBody('subscriptions/listen') },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_not_applicable', id: 1 },
  },

  // G. Mcp-Param-* (S7): forwarded unchanged, never decoded, never compared.
  {
    id: 'req-param-forwarded', rule: 'S7', description: 'an Mcp-Param header is forwarded after the mirrors',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Region', 'us-west1']],
      body_text: callBody('tools/call', { name: 'execute_sql', arguments: { region: 'us-west1' } }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Region', 'us-west1']] } },
  },
  {
    id: 'req-param-forwarded-sentinel', rule: 'S7', description: 'an Mcp-Param sentinel value is forwarded without decoding',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Greeting', B64_HELLO_WORLD]],
      body_text: callBody('tools/call', { name: 'execute_sql', arguments: { greeting: 'Hello, 世界' } }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Greeting', B64_HELLO_WORLD]] } },
  },
  {
    id: 'req-param-repeated', rule: 'S7', description: 'repeated Mcp-Param headers keep both values in order',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Tenant', 'acme'], ['Mcp-Param-Tenant', 'beta']],
      body_text: callBody('tools/call', { name: 'execute_sql', arguments: { tenant: 'acme' } }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'execute_sql'], CT, ['Mcp-Param-Tenant', 'acme'], ['Mcp-Param-Tenant', 'beta']] } },
  },

  // H. Session headers (S8): removed in the modern era, case-insensitively.
  {
    id: 'req-session-header-stripped', rule: 'S8', description: 'Mcp-Session-Id is removed in the modern era',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Mcp-Session-Id', 'sess-1']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },
  {
    id: 'req-last-event-id-stripped', rule: 'S8', description: 'Last-Event-ID is removed in the modern era',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['Last-Event-ID', '42']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },
  {
    id: 'req-session-header-lowercase', rule: 'S8', description: 'session header removal is case-insensitive',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT, ['mcp-session-id', 'sess-2']],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },

  // I. Forwarding (S9): original method, target, order and casing.
  {
    id: 'req-forward-preserves-order', rule: 'S9', description: 'forwarding keeps the original header order and casing',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp',
      headers: [['Accept', 'application/json, text/event-stream'], ['MCP-Protocol-Version', V], ['X-Custom', 'a b c'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT],
      body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp',
        headers: [['Accept', 'application/json, text/event-stream'], ['MCP-Protocol-Version', V], ['X-Custom', 'a b c'], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },
  {
    id: 'req-modern-profile-plain-tools-call', rule: 'S9', description: 'modern profile forwards a fully mirrored tools/call unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'), body_text: callBody('tools/call', { name: 'get_weather' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather'], CT] } },
  },

  // J. Refusal shape (S10): the id of the request is echoed, never omitted.
  {
    id: 'req-refusal-id-string', rule: 'S10', description: 'a refusal echoes a string request id',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('tools/call', 'get_weather'),
      body_text: JSON.stringify({ jsonrpc: '2.0', id: 'abc', method: 'tools/call', params: { name: 'get_weather', _meta: meta('2026-07-29') } }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_mismatch', id: 'abc' },
  },

  // K. Notifications (S11): no mirror obligation, present mirrors validated.
  {
    id: 'req-notification-no-mirrors', rule: 'S11', description: 'a notification needs no mirror headers',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [CT], body_text: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/events/list_changed' }) },
    expect: { outcome: 'forward', era: 'modern', forward: { method: 'POST', target: '/mcp', headers: [CT] } },
  },
  {
    id: 'req-notification-mirrors-valid', rule: 'S11', description: 'a notification with valid mirrors is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('events/poll', 'email.received'), body_text: notifBody('events/poll', { name: 'email.received' }) },
    expect: { outcome: 'forward', era: 'modern',
      forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/poll'], ['Mcp-Name', 'email.received'], CT] } },
  },
  {
    id: 'req-notification-version-without-meta', rule: 'S11', description: 'a notification version header requires the body version',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], CT],
      body_text: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/events/list_changed' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'version_meta_missing', id: null },
  },
  {
    id: 'req-notification-name-mismatch', rule: 'S11', description: 'a notification name mismatch is refused with a null id',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: mirrors('events/poll', 'email.sent'), body_text: notifBody('events/poll', { name: 'email.received' }) },
    expect: { outcome: 'refuse', era: 'modern', reason: 'name_header_mismatch', id: null },
  },

  // L. Response objects (S12): no mirror obligation, S1 and S8 still apply.
  {
    id: 'req-response-object-modern', rule: 'S12', description: 'a client response object has no mirror obligation and loses the session header',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], CT, ['Mcp-Session-Id', 'sess-9']],
      body_text: JSON.stringify({ jsonrpc: '2.0', id: 7, result: { resultType: 'complete' } }) },
    expect: { outcome: 'forward', era: 'modern', forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], CT] } },
  },
  {
    id: 'req-response-object-error', rule: 'S12', description: 'a client error response object is forwarded unchanged',
    profile: 'modern',
    request: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], CT],
      body_text: JSON.stringify({ jsonrpc: '2.0', id: 7, error: { code: -32601, message: 'Method not found' } }) },
    expect: { outcome: 'forward', era: 'modern', forward: { method: 'POST', target: '/mcp', headers: [['MCP-Protocol-Version', V], CT] } },
  },
  {
    id: 'req-both-response-object-legacy', rule: 'S12', description: 'a response object without a modern signal stays legacy and keeps its session header',
    profile: 'both',
    request: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Session-Id', 'sess-1']],
      body_text: JSON.stringify({ jsonrpc: '2.0', id: 7, error: { code: -32601, message: 'Method not found' } }) },
    expect: { outcome: 'forward', era: 'legacy',
      forward: { method: 'POST', target: '/mcp', headers: [CT, ['Mcp-Session-Id', 'sess-1']] } },
  },
];

export const BY_REFERENCE = [
  {
    id: 'cache-replay', rule: 'C8',
    description: 'a verified response is bound to the signing request, so a result cached from request A is rejected as the answer to request B',
    file: 'fixtures/response-vectors.json',
    vectors: ['res-wrong-request-binding', 'res-accept'],
  },
];
