import { verifyRequest } from '../reference-verifier.mjs';
import { NOW, WINDOW, AUD, AUD2, registryJson, nonceOf, call, rpc, buildRequest, cacheOf, materialize, expectOf, agree, requestExpect } from './core.mjs';

export const STATUS = call('status');
export const lastChar = (v) => `${v.slice(0, -1)}B`; // sets unused trailing bits of the 64-byte signature
// A ping request whose string argument carries raw invalid UTF-8 bytes: lossy
// decoding yields valid JSON, so only the UTF-8 check itself can reject it.
export const pingBody = (bad) => Buffer.concat([
  Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"', 'utf8'),
  bad,
  Buffer.from('"}}', 'utf8'),
]);
// Bodies with one duplicated member name: a duplicate makes the body
// unacceptable (02 section 2). The pair sits adjacent so the fixture bytes
// show both occurrences; both orders are kept so no parser can pass by position.
export const dupMethodBody = (first, last) =>
  `{"jsonrpc":"2.0","id":1,"method":"${first}","method":"${last}"}`;
export const dupToolBody = (first, last) =>
  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${first}","name":"${last}"}}`;
// A ping whose params.x nests `levels` arrays: the body reaches
// `levels + 2` container levels (the root object and params), so 126 sits
// exactly at the 128-level maximum and 127 exceeds it (spec 02 section 4).
export const deepBody = (levels) =>
  `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":${'['.repeat(levels)}${']'.repeat(levels)}}}`;
export const REQUEST_CASES = [
  // accept: forwarded ordinary MCP traffic (spec 02 section 2). The old
  // contract denied these at the policy layer; now every authenticated caller
  // is forwarded unchanged, with its verified identity (spec 02 section 3).
  ['accept-ordinary-tool-any-key', 'an ordinary tool is forwarded for a non-admin key (old contract: operation_denied)', { body: call('echo', { text: 'naïve café – 日本語' }) }, [], ['accept']],
  ['accept-unmapped-tool-forwarded', 'a tool with no protocol handling is forwarded (old contract: operation_denied)', { body: call('other.tool') }, [], ['accept']],
  ['accept-unmapped-method-forwarded', 'an ordinary MCP method is forwarded (old contract: operation_denied)', { body: rpc('resources/read') }, [], ['accept']],
  ['accept-proto-tool-name-forwarded', 'a __proto__ tool name is forwarded as an ordinary tool (old contract: operation_denied)', { body: call('__proto__') }, [], ['accept']],
  ['accept-admin-identity', 'a forwarded accept carries the verified identity of an administrator', { key: 'root', body: rpc('tools/list') }, [], ['accept']],
  ['accept-tools-list-any-key', 'tools/list needs authentication only', { key: 'carol', body: rpc('tools/list') }, [], ['accept']],
  ['accept-ping', 'ping needs authentication only', { body: rpc('ping') }, [], ['accept']],
  ['accept-notification', 'notifications/* needs authentication only', { body: rpc('notifications/initialized') }, [], ['accept']],
  ['accept-response-object', 'a JSON-RPC response from the client needs authentication only', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }) }, [], ['accept']],
  ['accept-error-response-object', 'a JSON-RPC error response needs authentication only', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -1, message: 'x' } }) }, [], ['accept']],
  ['accept-query-string', 'query string is part of the signed target', { target: '/mcp?x=1&y=%2F', body: STATUS }, [], ['accept']],
  ['accept-get-empty-body', 'GET carries no JSON-RPC, authentication only', { method: 'GET' }, [], ['accept']],
  ['accept-utf8-body', 'body hash is over exact bytes (non-ASCII)', { body: call('logs.query', { q: 'naïve café – 日本語' }) }, [], ['accept']],
  ['accept-ts-boundary-past', 'ts = now - window is accepted', { ts: NOW - WINDOW, body: STATUS }, [], ['accept']],
  ['accept-ts-boundary-future', 'ts = now + window is accepted', { ts: NOW + WINDOW, body: STATUS }, [], ['accept']],
  ['accept-same-nonce-other-key', 'nonce cache is keyed by (kid, nonce)', { key: 'bob', nonce: nonceOf('shared'), body: STATUS }, [['alice', 'shared', NOW + 10]], ['accept']],
  ['accept-expired-cache-entry', 'cache entry past retain_until no longer blocks', { nonce: nonceOf('old'), body: STATUS }, [['alice', 'old', NOW - 1]], ['accept']],

  // header presence and syntax
  ['malformed-missing-header', 'no Jack-Auth header', { noHeader: true, body: STATUS }, [], ['reject', 401, 'missing_auth']],
  ['malformed-duplicate-header', 'two Jack-Auth headers', { dup: true, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-duplicate-param', 'repeated parameter', { mutate: (v) => `${v},ts=${NOW}`, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-unknown-param', 'unknown parameter', { mutate: (v) => `${v},extra=abc`, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-missing-nonce', 'required parameter absent', { mutate: (v) => v.replace(/,nonce=[^,]+/, ''), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-padded-sig', 'base64url with padding', { mutate: (v) => `${v}=`, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-noncanonical-sig', 'unused trailing bits set in signature', { mutate: lastChar, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-short-nonce', 'nonce is 15 bytes', { mutate: (v) => v.replace(/nonce=([A-Za-z0-9_-]+)/, (_, x) => `nonce=${x.slice(0, 20)}`), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-short-sig', 'signature is 60 bytes', { mutate: (v) => v.replace(/sig=([A-Za-z0-9_-]+)/, (_, x) => `sig=${x.slice(0, 80)}`), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-leading-zero', 'ts with leading zero', { mutate: (v) => v.replace(`ts=${NOW}`, `ts=0${NOW}`), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-negative', 'negative ts', { mutate: (v) => v.replace(`ts=${NOW}`, 'ts=-1'), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-fraction', 'fractional ts', { mutate: (v) => v.replace(`ts=${NOW}`, `ts=${NOW}.5`), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-space-after-comma', 'whitespace between parameters', { mutate: (v) => v.replace(',ts=', ', ts='), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-uppercase-param', 'parameter names are case-sensitive', { mutate: (v) => v.replace('kid=', 'KID='), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-wrong-scheme', 'Bearer scheme', { mutate: () => 'Bearer abcdef', body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-uppercase-scheme', 'scheme is case-sensitive', { mutate: (v) => `V1${v.slice(2)}`, body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-scheme-only', 'version without parameters', { mutate: () => 'v1', body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['unsupported-version', 'version v2', { mutate: (v) => `v2${v.slice(2)}`, body: STATUS }, [], ['reject', 401, 'unsupported_version']],

  // key lookup and validity
  ['unknown-key', 'valid signature from a key not in the registry', { key: 'mallory', body: STATUS }, [], ['reject', 401, 'unknown_key']],
  ['unknown-key-other-tool', 'unregistered key calling anything but jack.enroll', { key: 'newbie', body: call('jack.whoami') }, [], ['reject', 401, 'unknown_key']],
  ['key-not-yet-valid', 'key before not_before', { key: 'erin', body: STATUS }, [], ['reject', 401, 'key_inactive']],
  ['key-expired', 'key at or after not_after', { key: 'frank', body: STATUS }, [], ['reject', 401, 'key_inactive']],

  // timestamp window
  ['ts-too-old', 'ts = now - window - 1', { ts: NOW - WINDOW - 1, body: STATUS }, [], ['reject', 401, 'timestamp_out_of_window']],
  ['ts-too-new', 'ts = now + window + 1', { ts: NOW + WINDOW + 1, body: STATUS }, [], ['reject', 401, 'timestamp_out_of_window']],
  ['ts-checked-before-signature', 'stale ts and bad signature: window error wins', { ts: NOW - 500, flipSig: true, body: STATUS }, [], ['reject', 401, 'timestamp_out_of_window']],

  // signature
  ['sig-tampered-body', 'body changed after signing', { body: STATUS, send: { body: call('restart') } }, [], ['reject', 401, 'bad_signature']],
  ['sig-tampered-target', 'target changed after signing', { body: STATUS, send: { target: '/mcp?admin=1' } }, [], ['reject', 401, 'bad_signature']],
  ['sig-tampered-method', 'method changed after signing', { method: 'POST', body: '', send: { method: 'GET' } }, [], ['reject', 401, 'bad_signature']],
  ['sig-wrong-aud', 'signed for another server', { aud: AUD2, body: STATUS }, [], ['reject', 401, 'bad_signature']],
  ['sig-wrong-key', 'signed by bob, kid of alice', { signKey: 'bob', body: STATUS }, [], ['reject', 401, 'bad_signature']],
  ['sig-flipped-bit', 'one signature bit flipped', { flipSig: true, body: STATUS }, [], ['reject', 401, 'bad_signature']],
  ['sig-noncanonical-s', 'S replaced by S + L satisfies the equation but is non-canonical', { malleate: true, body: STATUS }, [], ['reject', 401, 'bad_signature']],
  ['sig-swapped-nonce', 'nonce in header differs from signed nonce', { hdr: { nonce: nonceOf('another') }, body: STATUS }, [], ['reject', 401, 'bad_signature']],
  ['sig-swapped-ts', 'ts in header differs from signed ts', { hdr: { ts: NOW - 1 }, body: STATUS }, [], ['reject', 401, 'bad_signature']],

  // replay
  ['replay-live-entry', 'same (kid, nonce) within the window', { nonce: nonceOf('seen'), body: STATUS }, [['alice', 'seen', NOW + 10]], ['reject', 401, 'replayed_nonce']],
  ['replay-at-retain-boundary', 'entry with retain_until = now still blocks', { nonce: nonceOf('edge'), body: STATUS }, [['alice', 'edge', NOW]], ['reject', 401, 'replayed_nonce']],
  ['replay-not-recorded-on-bad-sig', 'bad signature does not consume the nonce', { flipSig: true, body: STATUS }, [], ['reject', 401, 'bad_signature']],

  // the admin gate and protocol-native tools (nonce is consumed: authentication already succeeded)
  ['admin-gate-nonadmin', 'a non-admin cannot call an admin tool', { body: call('jack.admin.user.list') }, [], ['reject', 403, 'admin_required']],
  ['admin-gate-admin-accept', 'an administrator lists users', { key: 'root', body: call('jack.admin.user.list') }, [], ['accept']],
  ['whoami-nonadmin', 'jack.whoami returns the non-admin caller', { body: call('jack.whoami') }, [], ['accept']],
  ['whoami-admin', 'jack.whoami returns the administrator caller', { key: 'root', body: call('jack.whoami') }, [], ['accept']],
  ['unknown-native-tool', 'an undefined jack.* tool is denied and not audited', { key: 'root', body: call('jack.admin.user.delete') }, [], ['reject', 403, 'operation_denied']],
  ['admin-tool-auth-failure-no-audit', 'an audited admin tool that fails authentication expects no native audit', { body: call('jack.admin.user.list'), flipSig: true }, [], ['reject', 401, 'bad_signature']],

  // request shape
  ['request-tool-name-missing', 'tools/call without params.name', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-tool-name-not-string', 'params.name is not a string', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 7 } }) }, [], ['reject', 400, 'invalid_request']],
  ['request-method-not-string', 'method is not a string', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 7 }) }, [], ['reject', 400, 'invalid_request']],
  ['request-wrong-jsonrpc-version', 'jsonrpc is not "2.0"', { body: JSON.stringify({ jsonrpc: '1.0', id: 1, method: 'ping' }) }, [], ['reject', 400, 'invalid_request']],
  ['request-response-with-both', 'response object with result and error', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: {}, error: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-response-without-id', 'response object without id', { body: JSON.stringify({ jsonrpc: '2.0', result: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-json', 'signed body is not JSON', { body: '{not json' }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-json-false-suffix', 'false followed by a digit is not a JSON literal', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":false0}}' }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-utf8', 'signed body is not UTF-8', { body: Buffer.from([0xff, 0xfe, 0x7b]) }, [], ['reject', 400, 'invalid_request']],
  // A leading UTF-8 BOM makes the body unacceptable even though the bytes
  // after it are valid JSON (spec 02 section 2). The BOM is part of the
  // signed bytes; the nonce is consumed because rejection is post-auth.
  ['request-bom-prefix', 'a UTF-8 BOM before the JSON body is invalid_request', { body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping"}', 'utf8')]) }, [], ['reject', 400, 'invalid_request']],
  ['request-batch', 'JSON-RPC batch is rejected', { body: `[${STATUS}]` }, [], ['reject', 400, 'invalid_request']],
  ['request-empty-post', 'POST with empty body', { body: '' }, [], ['reject', 400, 'invalid_request']],
  ['request-missing-jsonrpc', 'object without jsonrpc "2.0"', { body: JSON.stringify({ id: 1, method: 'ping' }) }, [], ['reject', 400, 'invalid_request']],

  // cross-language edge cases. Kept at the end so the ids and vector positions
  // of the core cases above stay stable and fixture diffs stay additions-only.
  ['malformed-sig-standard-alphabet', 'signature using + and / instead of - and _', { mutate: (v) => v.replace(/sig=[A-Za-z0-9_-]{2}/, 'sig=+/'), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-space-in-param-value', 'whitespace inside a parameter value', { mutate: (v) => v.replace('kid=', 'kid= '), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-short-kid', 'kid is 31 bytes', { mutate: (v) => v.replace(/kid=([A-Za-z0-9_-]+)/, (_, x) => `kid=${x.slice(0, 42)}`), body: STATUS }, [], ['reject', 401, 'malformed_auth']],
  ['request-utf8-overlong', 'an overlong UTF-8 encoding is rejected although lossy decoding yields valid JSON', { body: pingBody(Buffer.from([0xc0, 0xaf])) }, [], ['reject', 400, 'invalid_request']],
  ['request-utf8-lone-surrogate', 'a UTF-8-encoded surrogate code point is rejected although lossy decoding yields valid JSON', { body: pingBody(Buffer.from([0xed, 0xa0, 0x80])) }, [], ['reject', 400, 'invalid_request']],
  ['request-utf8-truncated', 'a truncated multibyte sequence is rejected although lossy decoding yields valid JSON', { body: pingBody(Buffer.from([0xe2, 0x82])) }, [], ['reject', 400, 'invalid_request']],
  ['dup-method-ping-then-tools-call', 'a duplicated method member makes the body unacceptable: ping then tools/call', { body: dupMethodBody('ping', 'tools/call') }, [], ['reject', 400, 'invalid_request']],
  ['dup-method-tools-call-then-ping', 'the same duplicated pair in the other order is equally unacceptable', { body: dupMethodBody('tools/call', 'ping') }, [], ['reject', 400, 'invalid_request']],
  ['dup-tool-name-whoami-then-admin', 'a duplicated params.name makes the body unacceptable: invalid_request, not a dispatch decision', { body: dupToolBody('jack.whoami', 'jack.admin.user.list') }, [], ['reject', 400, 'invalid_request']],
  ['dup-tool-name-admin-then-whoami', 'the same duplicated params.name in the other order is equally unacceptable', { body: dupToolBody('jack.admin.user.list', 'jack.whoami') }, [], ['reject', 400, 'invalid_request']],
  ['dup-jsonrpc-wrong-then-right', 'a duplicated jsonrpc member makes the body unacceptable even when one occurrence is "2.0"', { body: '{"jsonrpc":"1.0","jsonrpc":"2.0","id":1,"method":"ping"}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-member-escaped-name-method', 'a member whose name unescapes to an earlier name is its duplicate', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","meth\\u006fd":"tools/call"}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-params-object', 'a duplicated params object makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status"},"params":{"other":1}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-params-nested-member', 'a duplicate inside params (a non-tool method) makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1,"x":2}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-arguments-free-form-member', 'a duplicate inside free-form arguments of an ordinary tool makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"a","text":"b"}}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-arguments-deep-member', 'a duplicate several levels below arguments makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"a":{"b":{"c":1,"c":1}}}}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-array-element-object-member', 'a duplicate inside an object that is an array element makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[{"a":1},{"b":1,"b":2}]}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-escaped-name-in-arguments', 'a plain name and its \\u0061 spelling in one arguments object are duplicates', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"a":1,"\\u0061":2}}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-response-object-member', 'a duplicate in a JSON-RPC response object makes the body unacceptable', { body: '{"jsonrpc":"2.0","id":1,"result":{},"result":{}}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-same-name-different-objects-ok', 'the same names in different objects (params, arguments, nested, array elements) are not duplicates', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"name":"x","method":"y","params":{"name":"z","method":"w"},"list":[{"a":1},{"a":2}]}}}' }, [], ['accept']],
  ['dup-name-case-differs-ok', 'member names are compared exactly, without case folding: method and Method are distinct', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","Method":"tools/call"}' }, [], ['accept']],
  ['sig-small-order-r-identity', 'a signature whose R is the identity encoding satisfies the verification equation but is rejected (spec 01 section 2)', { body: STATUS, smallR: true }, [], ['reject', 401, 'bad_signature']],
  ['request-escape-lone-surrogate-method', 'a lone surrogate escape in the method is not acceptable body text (spec 02 section 4)', { body: '{"jsonrpc":"2.0","id":1,"method":"pi\\ud800ng"}' }, [], ['reject', 400, 'invalid_request']],
  ['request-escape-lone-surrogate-member-name', 'a lone surrogate escape in a member name is not acceptable body text', { body: '{"jsonrpc":"2.0","id":1,"m\\ud800":1,"method":"ping"}' }, [], ['reject', 400, 'invalid_request']],
  ['request-escape-lone-surrogate-params-name', 'a lone surrogate escape in params.name is not acceptable body text', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stat\\udc00us"}}' }, [], ['reject', 400, 'invalid_request']],
  ['request-escape-lone-surrogate-after-pair', 'a lone surrogate escape after a valid pair is still not acceptable body text', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\\ud83d\\ude00\\ud800"}}' }, [], ['reject', 400, 'invalid_request']],
  ['request-escape-surrogate-pair-valid', 'a correctly paired surrogate escape is acceptable body text', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\\ud83d\\ude00"}}' }, [], ['accept']],
  ['request-depth-128-ok', 'nesting exactly 128 levels of arrays and objects is accepted', { body: deepBody(126) }, [], ['accept']],
  ['request-depth-129-rejected', 'nesting 129 levels of arrays and objects is invalid_request (spec 02 section 4)', { body: deepBody(127) }, [], ['reject', 400, 'invalid_request']],
];

export const requestVectors = REQUEST_CASES.map(([id, description, opts, cache, tuple]) => {
  const { req, signing } = buildRequest(id, opts);
  const state = materialize({ registry: registryJson.keys, nonce_cache: cacheOf(cache) });
  const got = verifyRequest(req, state);
  const expect = requestExpect(opts, tuple);
  agree(id, expectOf(got, new Set()), expect);
  return {
    id, description,
    state: { now: NOW, window_seconds: WINDOW, aud: AUD, nonce_cache: cacheOf(cache) },
    request: req, expect, debug: { signing_string_lines: signing.split('\n') },
  };
});

// ---- stateful sequences: user management ----