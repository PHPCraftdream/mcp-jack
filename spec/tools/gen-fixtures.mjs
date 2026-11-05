// Deterministic generator for spec/fixtures and spec/tests/CASES.md.
//   node gen-fixtures.mjs          write files
//   node gen-fixtures.mjs --check  verify files on disk are up to date
// Every expected result is cross-checked against reference-verifier.mjs.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  b64u, sha256, kidOf, requestSigningString, responseSigningString, verifyRequest, verifyResponse,
} from './reference-verifier.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const NOW = 1767225600; // 2026-01-01T00:00:00Z
const WINDOW = 30;
const AUD = 'https://svc.example.test';
const AUD2 = 'https://other.example.test';
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// ---- keys (TEST ONLY: seeds are derived from public strings) ----
const KEY_DEFS = {
  alice: { scopes: ['read'] },
  bob: { scopes: ['read', 'lifecycle'] },
  carol: { scopes: ['config:write'] },
  erin: { scopes: ['read'], not_before: NOW + 1000 },
  frank: { scopes: ['read'], not_after: NOW - 1000 },
  mallory: null, // valid key, absent from the registry
  svc: null, // server response-signing key
};
const K = {};
for (const name of Object.keys(KEY_DEFS)) {
  const seed = sha256(`mcp-jack test key: ${name}`);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  K[name] = { name, seed, priv, pub, public_key: b64u(pub), kid: kidOf(pub) };
}

const keysJson = {
  note: 'TEST ONLY. Seeds are sha256("mcp-jack test key: <name>"). Never use these keys outside tests.',
  keys: Object.values(K).map((k) => ({
    name: k.name, seed_hex: k.seed.toString('hex'), public_key: k.public_key, kid: k.kid,
  })),
};

const registry = {
  version: 1,
  aud: AUD,
  keys: Object.entries(KEY_DEFS)
    .filter(([, d]) => d)
    .map(([name, d]) => ({
      kid: K[name].kid, public_key: K[name].public_key, name,
      scopes: d.scopes, not_before: d.not_before ?? null, not_after: d.not_after ?? null,
    })),
};

// ---- builders ----
const nonceOf = (label) => b64u(sha256(`nonce:${label}`).subarray(0, 16));
const sigOf = (name, msg) => b64u(sign(null, Buffer.from(msg, 'utf8'), K[name].priv));
const call = (name, args = {}) => JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
const rpc = (method) => JSON.stringify({ jsonrpc: '2.0', id: 1, method });

// o.sign overrides what is signed, o.send overrides what is sent, o.hdr overrides header values,
// o.mutate rewrites the final header string, o.dup adds a second header, o.noHeader omits it.
function buildRequest(id, o = {}) {
  const {
    key = 'alice', method = 'POST', target = '/mcp', aud = AUD, ts = NOW, body = '',
    nonce = nonceOf(id), signKey = key, flipSig = false,
  } = o;
  const bodyBuf = Buffer.from(body);
  const fields = { method, target, aud, kid: K[key].kid, ts, nonce, body: bodyBuf, ...o.sign };
  const signing = requestSigningString(fields);
  let sig = sigOf(signKey, signing);
  if (flipSig) {
    const raw = Buffer.from(sig, 'base64url');
    raw[0] ^= 1;
    sig = b64u(raw);
  }
  const h = { kid: K[key].kid, ts, nonce, sig, ...o.hdr };
  let header = `v1 kid=${h.kid},ts=${h.ts},nonce=${h.nonce},sig=${h.sig}`;
  if (o.mutate) header = o.mutate(header);

  const sent = Buffer.from(o.send?.body ?? bodyBuf);
  const headers = o.noHeader ? [] : [['Jack-Auth', header]];
  if (o.dup) headers.push(['jack-auth', header]);
  if ((o.send?.method ?? method) === 'POST') headers.push(['Content-Type', 'application/json']);
  return {
    req: {
      method: o.send?.method ?? method,
      target: o.send?.target ?? target,
      headers,
      body_b64u: b64u(sent),
      ...(sent.length && sent.every((c) => c >= 0x20 && c < 0x7f) ? { body_text: sent.toString('utf8') } : {}),
    },
    sig,
    signing,
  };
}

const state = (cache = []) => ({
  now: NOW, window_seconds: WINDOW, aud: AUD,
  nonce_cache: cache.map(([key, label, retain_until]) => ({ kid: K[key].kid, nonce: nonceOf(label), retain_until })),
});

// ---- request cases: [id, description, build options, cache, [result, status, code]] ----
const lastChar = (v) => v.slice(0, -1) + 'B'; // sets unused trailing bits of the 64-byte signature
const REQUEST_CASES = [
  // accept
  ['accept-read-status', 'read key calls a read tool', { body: call('jack.status') }, [], ['accept']],
  ['accept-lifecycle-restart', 'lifecycle key restarts', { key: 'bob', body: call('jack.restart') }, [], ['accept']],
  ['accept-reload', 'lifecycle key reloads', { key: 'bob', body: call('jack.reload') }, [], ['accept']],
  ['accept-config-set', 'config:write key sets config', { key: 'carol', body: call('jack.config.set', { k: 'v' }) }, [], ['accept']],
  ['accept-tools-list-any-key', 'tools/list needs authentication only', { key: 'carol', body: rpc('tools/list') }, [], ['accept']],
  ['accept-ping', 'ping needs authentication only', { body: rpc('ping') }, [], ['accept']],
  ['accept-query-string', 'query string is part of the signed target', { target: '/mcp?x=1&y=%2F', body: call('jack.status') }, [], ['accept']],
  ['accept-get-empty-body', 'GET carries no JSON-RPC, authentication only', { method: 'GET' }, [], ['accept']],
  ['accept-utf8-body', 'body hash is over exact bytes (non-ASCII)', { body: call('jack.logs.query', { q: 'лог ошибок' }) }, [], ['accept']],
  ['accept-ts-boundary-past', 'ts = now - window is accepted', { ts: NOW - WINDOW, body: call('jack.status') }, [], ['accept']],
  ['accept-ts-boundary-future', 'ts = now + window is accepted', { ts: NOW + WINDOW, body: call('jack.status') }, [], ['accept']],
  ['accept-same-nonce-other-key', 'nonce cache is keyed by (kid, nonce)', { key: 'bob', nonce: nonceOf('shared'), body: call('jack.status') }, [['alice', 'shared', NOW + 10]], ['accept']],
  ['accept-expired-cache-entry', 'cache entry past retain_until no longer blocks', { nonce: nonceOf('old'), body: call('jack.status') }, [['alice', 'old', NOW - 1]], ['accept']],

  // header presence and syntax
  ['malformed-missing-header', 'no Jack-Auth header', { noHeader: true, body: call('jack.status') }, [], ['reject', 401, 'missing_auth']],
  ['malformed-duplicate-header', 'two Jack-Auth headers', { dup: true, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-duplicate-param', 'repeated parameter', { mutate: (v) => `${v},ts=${NOW}`, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-unknown-param', 'unknown parameter', { mutate: (v) => `${v},extra=abc`, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-missing-nonce', 'required parameter absent', { mutate: (v) => v.replace(/,nonce=[^,]+/, ''), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-padded-sig', 'base64url with padding', { mutate: (v) => `${v}=`, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-noncanonical-sig', 'unused trailing bits set in signature', { mutate: lastChar, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-short-nonce', 'nonce is 15 bytes', { mutate: (v) => v.replace(/nonce=([A-Za-z0-9_-]+)/, (_, x) => `nonce=${x.slice(0, 20)}`), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-short-sig', 'signature is 60 bytes', { mutate: (v) => v.replace(/sig=([A-Za-z0-9_-]+)/, (_, x) => `sig=${x.slice(0, 80)}`), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-leading-zero', 'ts with leading zero', { mutate: (v) => v.replace(`ts=${NOW}`, `ts=0${NOW}`), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-negative', 'negative ts', { mutate: (v) => v.replace(`ts=${NOW}`, 'ts=-1'), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-ts-fraction', 'fractional ts', { mutate: (v) => v.replace(`ts=${NOW}`, `ts=${NOW}.5`), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-space-after-comma', 'whitespace between parameters', { mutate: (v) => v.replace(',ts=', ', ts='), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-uppercase-param', 'parameter names are case-sensitive', { mutate: (v) => v.replace('kid=', 'KID='), body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-wrong-scheme', 'Bearer scheme', { mutate: () => 'Bearer abcdef', body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-uppercase-scheme', 'scheme is case-sensitive', { mutate: (v) => `V1${v.slice(2)}`, body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['malformed-scheme-only', 'version without parameters', { mutate: () => 'v1', body: call('jack.status') }, [], ['reject', 401, 'malformed_auth']],
  ['unsupported-version', 'version v2', { mutate: (v) => `v2${v.slice(2)}`, body: call('jack.status') }, [], ['reject', 401, 'unsupported_version']],

  // key lookup and validity
  ['unknown-key', 'valid signature from a key not in the registry', { key: 'mallory', body: call('jack.status') }, [], ['reject', 401, 'unknown_key']],
  ['key-not-yet-valid', 'key before not_before', { key: 'erin', body: call('jack.status') }, [], ['reject', 401, 'key_inactive']],
  ['key-expired', 'key at or after not_after', { key: 'frank', body: call('jack.status') }, [], ['reject', 401, 'key_inactive']],

  // timestamp window
  ['ts-too-old', 'ts = now - window - 1', { ts: NOW - WINDOW - 1, body: call('jack.status') }, [], ['reject', 401, 'timestamp_out_of_window']],
  ['ts-too-new', 'ts = now + window + 1', { ts: NOW + WINDOW + 1, body: call('jack.status') }, [], ['reject', 401, 'timestamp_out_of_window']],
  ['ts-checked-before-signature', 'stale ts and bad signature: window error wins', { ts: NOW - 500, flipSig: true, body: call('jack.status') }, [], ['reject', 401, 'timestamp_out_of_window']],

  // signature
  ['sig-tampered-body', 'body changed after signing', { body: call('jack.status'), send: { body: call('jack.restart') } }, [], ['reject', 401, 'bad_signature']],
  ['sig-tampered-target', 'target changed after signing', { body: call('jack.status'), send: { target: '/mcp?admin=1' } }, [], ['reject', 401, 'bad_signature']],
  ['sig-tampered-method', 'method changed after signing', { method: 'POST', body: '', send: { method: 'GET' } }, [], ['reject', 401, 'bad_signature']],
  ['sig-wrong-aud', 'signed for another server', { aud: AUD2, body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],
  ['sig-wrong-key', 'signed by bob, kid of alice', { signKey: 'bob', body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],
  ['sig-flipped-bit', 'one signature bit flipped', { flipSig: true, body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],
  ['sig-swapped-nonce', 'nonce in header differs from signed nonce', { hdr: { nonce: nonceOf('another') }, body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],
  ['sig-swapped-ts', 'ts in header differs from signed ts', { hdr: { ts: NOW - 1 }, body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],

  // replay
  ['replay-live-entry', 'same (kid, nonce) within the window', { nonce: nonceOf('seen'), body: call('jack.status') }, [['alice', 'seen', NOW + 10]], ['reject', 401, 'replayed_nonce']],
  ['replay-at-retain-boundary', 'entry with retain_until = now still blocks', { nonce: nonceOf('edge'), body: call('jack.status') }, [['alice', 'edge', NOW]], ['reject', 401, 'replayed_nonce']],
  ['replay-not-recorded-on-bad-sig', 'bad signature does not consume the nonce', { flipSig: true, body: call('jack.status') }, [], ['reject', 401, 'bad_signature']],

  // authorization (nonce is consumed: authentication already succeeded)
  ['authz-read-key-restart', 'read key may not restart', { body: call('jack.restart') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-read-key-config-set', 'read key may not write config', { body: call('jack.config.set') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-config-write-no-read', 'config:write does not imply read', { key: 'carol', body: call('jack.config.get') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-lifecycle-no-config-write', 'lifecycle does not imply config:write', { key: 'bob', body: call('jack.config.set') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-unmapped-tool', 'unknown tool is denied', { body: call('jack.unknown') }, [], ['reject', 403, 'unmapped_operation']],
  ['authz-proto-tool-name', 'prototype property names are not tools', { body: call('__proto__') }, [], ['reject', 403, 'unmapped_operation']],
  ['authz-unmapped-method', 'unlisted MCP method is denied', { body: rpc('resources/read') }, [], ['reject', 403, 'unmapped_operation']],
  ['request-tool-name-missing', 'tools/call without params.name', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-tool-name-not-string', 'params.name is not a string', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 7 } }) }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-json', 'signed body is not JSON', { body: '{not json' }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-utf8', 'signed body is not UTF-8', { body: Buffer.from([0xff, 0xfe, 0x7b]) }, [], ['reject', 400, 'invalid_request']],
  ['request-batch', 'JSON-RPC batch is rejected', { body: `[${call('jack.status')}]` }, [], ['reject', 400, 'invalid_request']],
  ['request-empty-post', 'POST with empty body', { body: '' }, [], ['reject', 400, 'invalid_request']],
  ['request-missing-jsonrpc', 'object without jsonrpc "2.0"', { body: JSON.stringify({ id: 1, method: 'ping' }) }, [], ['reject', 400, 'invalid_request']],
];

const requestVectors = REQUEST_CASES.map(([id, desc, opts, cache, want]) => {
  const { req, signing } = buildRequest(id, opts);
  const st = state(cache);
  const got = verifyRequest(req, st, registry);
  const [result, http_status, code] = want;
  if (got.result !== result || got.http_status !== http_status || got.code !== code) {
    throw new Error(`${id}: reference verifier disagrees: ${JSON.stringify(got)} vs ${JSON.stringify(want)}`);
  }
  const expect = { result, ...(result === 'accept' ? { kid: got.kid } : { http_status, code }), nonce_recorded: got.nonce_recorded };
  return { id, description: desc, state: st, request: req, expect, debug: { signing_string_lines: signing.split('\n') } };
});

// ---- response cases ----
const base = buildRequest('accept-read-status', { body: call('jack.status') });
const REQ_SIG = base.sig;
const OK_BODY = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

function buildResponse(o = {}) {
  const { status = 200, body = OK_BODY, ts = NOW, signKey = 'svc', kid = K.svc.kid } = o;
  const fields = { status, reqSig: REQ_SIG, kid: K.svc.kid, ts, body: Buffer.from(body), ...o.sign };
  const sig = sigOf(signKey, responseSigningString(fields));
  const h = { kid, ts, sig, ...o.hdr };
  let header = `v1 kid=${h.kid},ts=${h.ts},sig=${h.sig}`;
  if (o.mutate) header = o.mutate(header);
  const sent = Buffer.from(o.send?.body ?? body);
  return {
    status: o.send?.status ?? status,
    headers: o.noHeader ? [] : [['Jack-Auth', header]],
    body_b64u: b64u(sent),
    ...(sent.length ? { body_text: sent.toString('utf8') } : {}),
  };
}

const RESPONSE_CASES = [
  ['res-accept', 'valid response', {}, ['accept']],
  ['res-accept-empty-body', '204 with empty body', { status: 204, body: '' }, ['accept']],
  ['res-accept-ts-boundary-past', 'ts = now - window', { ts: NOW - WINDOW }, ['accept']],
  ['res-accept-ts-boundary-future', 'ts = now + window', { ts: NOW + WINDOW }, ['accept']],
  ['res-missing-header', 'no Jack-Auth header', { noHeader: true }, ['reject', 'missing_auth']],
  ['res-unsupported-version', 'version v2', { mutate: (v) => `v2${v.slice(2)}` }, ['reject', 'unsupported_version']],
  ['res-malformed-nonce-param', 'nonce is not a response parameter', { mutate: (v) => `${v},nonce=${nonceOf('x')}` }, ['reject', 'malformed_auth']],
  ['res-unknown-server-key', 'kid is not the pinned server key', { signKey: 'mallory', hdr: { kid: K.mallory.kid } }, ['reject', 'unknown_server_key']],
  ['res-ts-too-old', 'ts = now - window - 1', { ts: NOW - WINDOW - 1 }, ['reject', 'timestamp_out_of_window']],
  ['res-ts-too-new', 'ts = now + window + 1', { ts: NOW + WINDOW + 1 }, ['reject', 'timestamp_out_of_window']],
  ['res-tampered-body', 'body changed after signing', { send: { body: '{"jsonrpc":"2.0","id":1,"result":{"ok":false}}' } }, ['reject', 'bad_signature']],
  ['res-tampered-status', 'status changed after signing', { send: { status: 500 } }, ['reject', 'bad_signature']],
  ['res-wrong-request-binding', 'signed over a different request signature', { sign: { reqSig: b64u(Buffer.alloc(64, 7)) } }, ['reject', 'bad_signature']],
  ['res-wrong-key-with-pinned-kid', 'pinned kid, signed by another key', { signKey: 'mallory' }, ['reject', 'bad_signature']],
];

const resState = () => ({
  now: NOW, window_seconds: WINDOW, pinned_server_kid: K.svc.kid,
  pinned_server_public_key: K.svc.public_key, request_sig: REQ_SIG,
});

const responseVectors = RESPONSE_CASES.map(([id, desc, opts, want]) => {
  const response = buildResponse(opts);
  const got = verifyResponse(response, resState());
  if (got.result !== want[0] || got.code !== want[1]) {
    throw new Error(`${id}: reference verifier disagrees: ${JSON.stringify(got)} vs ${JSON.stringify(want)}`);
  }
  const expect = want[0] === 'accept' ? { result: 'accept' } : { result: 'reject', code: want[1] };
  return { id, description: desc, state: resState(), response, expect };
});

// ---- output ----
const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const row = (cells) => `| ${cells.join(' | ')} |`;
const casesMd = [
  '# Conformance cases',
  '',
  'Generated by `tools/gen-fixtures.mjs`. Do not edit by hand.',
  '',
  `Fixed clock: now = ${NOW}, window = ${WINDOW} s, aud = \`${AUD}\`.`,
  '',
  '## Request verification (`fixtures/request-vectors.json`)',
  '',
  row(['id', 'description', 'expected']),
  row(['---', '---', '---']),
  ...requestVectors.map((v) => row([
    `\`${v.id}\``, v.description,
    v.expect.result === 'accept' ? 'accept' : `${v.expect.http_status} \`${v.expect.code}\``,
  ])),
  '',
  '## Response verification (`fixtures/response-vectors.json`)',
  '',
  row(['id', 'description', 'expected']),
  row(['---', '---', '---']),
  ...responseVectors.map((v) => row([
    `\`${v.id}\``, v.description, v.expect.result === 'accept' ? 'accept' : `reject \`${v.expect.code}\``,
  ])),
  '',
].join('\n');

const OUT = {
  'fixtures/keys.json': json(keysJson),
  'fixtures/registry.json': json(registry),
  'fixtures/request-vectors.json': json({ registry: 'registry.json', cases: requestVectors }),
  'fixtures/response-vectors.json': json({ cases: responseVectors }),
  'tests/CASES.md': casesMd,
};

if (process.argv.includes('--check')) {
  const stale = Object.entries(OUT).filter(([p, c]) => !existsSync(join(ROOT, p)) || readFileSync(join(ROOT, p), 'utf8') !== c);
  if (stale.length) {
    console.error(`stale: ${stale.map(([p]) => p).join(', ')}`);
    process.exit(1);
  }
  console.log(`ok: ${requestVectors.length} request + ${responseVectors.length} response cases, fixtures up to date`);
} else {
  for (const [p, c] of Object.entries(OUT)) writeFileSync(join(ROOT, p), c);
  console.log(`wrote ${Object.keys(OUT).length} files: ${requestVectors.length} request + ${responseVectors.length} response cases`);
}
