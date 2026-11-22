// Era detection vectors of spec 04 section 6 (C9). Data only: no build, no I/O,
// no clock, no randomness. `expect` is the exact detectEra({ response, clientVersions })
// output; the input is `response` plus the versions the client implements.
import { MODERN_ERA_ERROR_CODES } from '../spec-data.mjs';

const RESULT_BODY = '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","protocolVersions":["2026-07-28"],"capabilities":{},"serverInfo":{"name":"srv","version":"1.0.0"}}}';
const HEADER_MISMATCH_BODY = '{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: Mcp-Name is missing"}}';

export const ERA_CASES = [
  // 2xx
  {
    id: 'era-verified-result', rule: 'C9', description: 'a verified 2xx result means the server speaks the modern era',
    response: { verified: true, status: 200, body_text: RESULT_BODY },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: null },
  },
  {
    id: 'era-verified-no-content', rule: 'C9', description: 'a verified 204 with no body is still modern',
    response: { verified: true, status: 204 },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: null },
  },
  {
    id: 'era-unverified-success', rule: 'C9', description: 'verification runs first, so an unverified 2xx aborts with no era',
    response: { verified: false, status: 200, body_text: RESULT_BODY },
    clientVersions: ['2026-07-28'],
    expect: { era: 'none', action: 'abort', reason: 'unverified' },
  },

  // 400 with a recognised modern error
  {
    id: 'era-400-header-mismatch', rule: 'C9', description: '-32020 is a recognised modern error, so a signed 400 is modern',
    response: { verified: true, status: 400, body_text: HEADER_MISMATCH_BODY },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: null },
  },
  {
    id: 'era-400-missing-capability', rule: 'C9', description: '-32021 is a recognised modern error, so a signed 400 is modern',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"Missing required client capability"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: null },
  },
  {
    id: 'era-400-id-null', rule: 'C9', description: 'an id member of null is present, so the error is still recognised',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":null,"error":{"code":-32020,"message":"x"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: null },
  },
  {
    id: 'era-400-unsupported-version', rule: 'C9', description: '-32022 retries with the mutually implemented versions',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25"],"requested":"1900-01-01"}}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'retry_with_supported', reason: null, supported: ['2026-07-28'] },
  },
  {
    id: 'era-400-unsupported-version-multi-overlap', rule: 'C9', description: 'only the overlap is retried and the server order is preserved',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2027-01-01","2025-11-25"],"requested":"1900-01-01"}}}' },
    clientVersions: ['2025-11-25', '2026-07-28'],
    expect: { era: 'modern', action: 'retry_with_supported', reason: null, supported: ['2025-11-25'] },
  },
  {
    id: 'era-400-unsupported-version-no-overlap', rule: 'C9', description: 'no mutually implemented version fails the operation',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2099-01-01"],"requested":"1900-01-01"}}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap' },
  },
  {
    id: 'era-400-unsupported-version-empty', rule: 'C9', description: 'an empty supported list has no overlap and fails the operation',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":[]}}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap' },
  },
  {
    id: 'era-400-unsupported-version-no-data', rule: 'C9', description: '-32022 without a data member has no overlap and fails the operation',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap' },
  },
  {
    id: 'era-400-unsupported-version-not-array', rule: 'C9', description: 'a supported value that is not an array has no overlap',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":"2026-07-28"}}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap' },
  },

  // 400 without a recognised error
  {
    id: 'era-400-bare-error-code', rule: 'C9', description: 'a bare error-code object is not a recognised error and reads legacy',
    response: { verified: true, status: 400, body_text: '{"error":{"code":-32020}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-no-jsonrpc', rule: 'C9', description: 'an object without jsonrpc is not a recognised error and reads legacy',
    response: { verified: true, status: 400, body_text: '{"id":1,"error":{"code":-32020,"message":"x"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-no-id', rule: 'C9', description: 'an error without an id member is not recognised and reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","error":{"code":-32020,"message":"x"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-message-not-string', rule: 'C9', description: 'a non-string error message is not recognised and reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":42}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-code-string', rule: 'C9', description: 'a string error code is not an integer, so a -32020 shape reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":"-32020","message":"x"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-jack-envelope', rule: 'C9', description: 'the Jack string-code envelope is never a modern signal',
    response: { verified: true, status: 400, body_text: '{"error":{"code":"invalid_request","message":"The body is not an acceptable JSON-RPC object"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'jack_envelope' },
  },
  {
    id: 'era-400-jack-streaming-envelope', rule: 'C9', description: 'a streaming_unsupported envelope is also a Jack envelope',
    response: { verified: true, status: 400, body_text: '{"error":{"code":"streaming_unsupported","message":"Streaming is not enabled"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'jack_envelope' },
  },
  {
    id: 'era-400-empty-body', rule: 'C9', description: 'an empty 400 body carries no era signal and reads legacy',
    response: { verified: true, status: 400, body_text: '' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-whitespace-body', rule: 'C9', description: 'a whitespace-only 400 body reads legacy',
    response: { verified: true, status: 400, body_text: '   ' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-not-json', rule: 'C9', description: 'a non-JSON 400 body reads legacy',
    response: { verified: true, status: 400, body_text: '{not json' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-array-body', rule: 'C9', description: 'a JSON array is not a JSON-RPC object and reads legacy',
    response: { verified: true, status: 400, body_text: '[1,2]' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-invalid-params', rule: 'C9', description: '-32602 is not a modern era code, so the 400 reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-method-not-found', rule: 'C9', description: '-32601 on a 400 is not a modern era code',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-legacy-resource-code', rule: 'C9', description: '-32002 is a pre-modern code, so the 400 reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Resource not found"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-application-code', rule: 'C9', description: 'an application error code on a 400 reads legacy',
    response: { verified: true, status: 400, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":42,"message":"Application error"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-400-unverified-modern-body', rule: 'C9', description: 'verification runs before the status rules, so a modern body aborts',
    response: { verified: false, status: 400, body_text: HEADER_MISMATCH_BODY },
    clientVersions: ['2026-07-28'],
    expect: { era: 'none', action: 'abort', reason: 'unverified' },
  },

  // 404
  {
    id: 'era-404-method-not-found', rule: 'C9', description: '-32601 on a 404 proves the modern era without that method',
    response: { verified: true, status: 404, body_text: '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'modern', action: 'stay_modern', reason: 'modern_method_not_found' },
  },
  {
    id: 'era-404-bare-method-not-found', rule: 'C9', description: 'a bare -32601 envelope is not a recognised error and reads legacy',
    response: { verified: true, status: 404, body_text: '{"error":{"code":-32601}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-404-empty-body', rule: 'C9', description: 'a 404 without a recognised error reads legacy',
    response: { verified: true, status: 404, body_text: '' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-404-jack-envelope', rule: 'C9', description: 'a string-code envelope on a 404 reads legacy, not modern',
    response: { verified: true, status: 404, body_text: '{"error":{"code":"not_found","message":"Not found"}}' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },

  // everything else
  {
    id: 'era-405-method-not-allowed', rule: 'C9', description: '405 is always the legacy answer, whatever the body holds',
    response: { verified: true, status: 405 },
    clientVersions: ['2026-07-28'],
    expect: { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' },
  },
  {
    id: 'era-500-server-error', rule: 'C9', description: '500 is a no-signal abort, not a legacy fallback',
    response: { verified: true, status: 500, body_text: 'oops' },
    clientVersions: ['2026-07-28'],
    expect: { era: 'none', action: 'abort', reason: 'no_era_signal' },
  },
  {
    id: 'era-429-rate-limited', rule: 'C9', description: '429 is a no-signal abort',
    response: { verified: true, status: 429 },
    clientVersions: ['2026-07-28'],
    expect: { era: 'none', action: 'abort', reason: 'no_era_signal' },
  },
  {
    id: 'era-401-unsigned', rule: 'C9', description: 'an unsigned 401 aborts before any status rule applies',
    response: { verified: false, status: 401 },
    clientVersions: ['2026-07-28'],
    expect: { era: 'none', action: 'abort', reason: 'unverified' },
  },
];

export const ERA_ERROR_CODES = MODERN_ERA_ERROR_CODES;
