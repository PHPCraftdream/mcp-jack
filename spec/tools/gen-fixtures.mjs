// Deterministic generator for spec/fixtures and spec/tests/CASES.md.
//   node gen-fixtures.mjs          write files
//   node gen-fixtures.mjs --check  verify files on disk are up to date
// Every expected result is cross-checked against reference-verifier.mjs.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  b64u, sha256, kidOf, requestSigningString, responseSigningString, rotateProofString,
  verifyRequest, verifyResponse, validatePublicKey, malleateSignature, defaultHooks,
  validatePolicy, validateRegistry, matchPattern,
  decodePoint, addPoints, encodePoint, BASE_POINT, findOrder8Point, fromBig,
} from './reference-verifier.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const NOW = 1767225600; // 2026-01-01T00:00:00Z
const WINDOW = 30;
const AUD = 'https://svc.example.test';
const AUD2 = 'https://other.example.test';
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const clone = (v) => JSON.parse(JSON.stringify(v));

// ---- keys (TEST ONLY: seeds are derived from public strings) ----
const KEY_DEFS = {
  alice: { scopes: ['read'], std: true },
  bob: { scopes: ['read', 'lifecycle'], std: true },
  carol: { scopes: ['config:write'], std: true },
  erin: { scopes: ['read'], not_before: NOW + 1000, std: true },
  frank: { scopes: ['read'], not_after: NOW - 1000, std: true },
  root: { scopes: ['admin', 'read', 'lifecycle', 'config:write'], std: true },
  agentx: { scopes: ['read'], kind: 'agent', std: true },
  lowadmin: { scopes: ['admin', 'read'] },
  admin2: { scopes: ['admin'] },
  expadmin: { scopes: ['admin'], not_after: NOW - 1000 },
  mallory: null, // valid key, never registered
  svc: null, // server response-signing key
  newbie: null,
  newbie2: null,
  newbie3: null,
};
const K = {};
for (const name of Object.keys(KEY_DEFS)) {
  const seed = sha256(`mcp-jack test key: ${name}`);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  if (validatePublicKey(pub)) throw new Error(`test key ${name} failed validation`);
  K[name] = { name, seed, priv, pub, public_key: b64u(pub), kid: kidOf(pub) };
}

const entryOf = (name, over = {}) => {
  const d = KEY_DEFS[name] ?? {};
  return {
    kid: K[name].kid, public_key: K[name].public_key, name, kind: d.kind ?? 'human',
    scopes: [...(d.scopes ?? [])], not_before: d.not_before ?? null, not_after: d.not_after ?? null, ...over,
  };
};
const STD_NAMES = Object.keys(KEY_DEFS).filter((n) => KEY_DEFS[n]?.std);

const keysJson = {
  note: 'TEST ONLY. Seeds are sha256("mcp-jack test key: <name>"). Never use these keys outside tests.',
  keys: Object.values(K).map((k) => ({
    name: k.name, seed_hex: k.seed.toString('hex'), public_key: k.public_key, kid: k.kid,
  })),
};
const registryJson = { version: 1, aud: AUD, keys: STD_NAMES.map((n) => entryOf(n)) };

const POLICIES = {
  default: {
    version: 1,
    rules: [
      { match: { method: 'ping' }, scope: null },
      { match: { method: 'tools/list' }, scope: null },
      { match: { method: 'notifications/*' }, scope: null },
      { match: { method: 'tools/call', tool: 'svc.danger.*' }, effect: 'deny' },
      { match: { method: 'tools/call', tool: 'svc.config.set' }, scope: 'config:write' },
      { match: { method: 'tools/call', tool: 'svc.reload' }, scope: 'lifecycle' },
      { match: { method: 'tools/call', tool: 'svc.restart' }, scope: 'lifecycle' },
      { match: { method: 'tools/call', tool: 'svc.*' }, scope: 'read' },
    ],
  },
  wildcard: { version: 1, rules: [{ match: { method: 'tools/call' }, scope: null }] },
};

// ---- builders ----
const nonceOf = (label) => b64u(sha256(`nonce:${label}`).subarray(0, 16));
const sigOf = (name, msg) => b64u(sign(null, Buffer.from(msg, 'utf8'), K[name].priv));
const call = (name, args) => JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, ...(args === undefined ? {} : { arguments: args }) } });
const rpc = (method) => JSON.stringify({ jsonrpc: '2.0', id: 1, method });
const codeOf = (label) => b64u(sha256(`seeded invite ${label}`));
const inviteIdOf = (code) => b64u(sha256(Buffer.from(code, 'base64url')));
const rotateProof = (newName, oldName, signer = newName, ts = NOW) =>
  sigOf(signer, rotateProofString({ aud: AUD, oldKid: K[oldName].kid, newKid: K[newName].kid, ts }));

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
  if (o.malleate) sig = b64u(malleateSignature(Buffer.from(sig, 'base64url')));
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

const cacheOf = (items) => items.map(([key, label, retain_until]) => ({ kid: K[key].kid, nonce: nonceOf(label), retain_until }));
const materialize = ({ policy = 'default', registry, invites = [], nonce_cache = [] }) => ({
  now: NOW, window_seconds: WINDOW, aud: AUD, registry: { keys: clone(registry) },
  policy: clone(POLICIES[policy]), invites: clone(invites), nonce_cache: clone(nonce_cache),
});
const byName = (a, b) => (a.name < b.name ? -1 : 1);
const summary = (state) => ({
  users: [...state.registry.keys].sort(byName).map((e) => ({
    name: e.name, kid: e.kid, kind: e.kind ?? 'human', scopes: [...e.scopes].sort(),
    not_before: e.not_before ?? null, not_after: e.not_after ?? null,
  })),
  invites: state.invites.filter((i) => state.now < i.expires_at).length,
});

// Codes created by the server are random in real implementations: expectations use a placeholder.
const PLACEHOLDER = '<b64u43>';
function scrub(value, generated) {
  if (typeof value === 'string') return generated.has(value) ? PLACEHOLDER : value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, generated));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, generated)]));
  return value;
}

function expectOf(got, generated, extra = {}) {
  const e = { result: got.result };
  if (got.result === 'accept') {
    e.kid = got.kid;
    if (got.structured !== undefined) e.structured = scrub(got.structured, generated);
  } else {
    e.http_status = got.http_status;
    e.code = got.code;
  }
  if (got.audit) e.audit = got.audit;
  e.nonce_recorded = got.nonce_recorded;
  return { ...e, ...extra };
}

function agree(id, got, want) {
  const [result, http_status, code] = want;
  if (got.result !== result || got.http_status !== http_status || got.code !== code) {
    throw new Error(`${id}: reference verifier disagrees: ${JSON.stringify(got)} vs ${JSON.stringify(want)}`);
  }
}

// ---- single-request cases: [id, description, build options, nonce cache, expected, policy] ----
const STATUS = call('svc.status');
const lastChar = (v) => `${v.slice(0, -1)}B`; // sets unused trailing bits of the 64-byte signature
const REQUEST_CASES = [
  // accept
  ['accept-read-status', 'read key calls a read tool', { body: STATUS }, [], ['accept']],
  ['accept-lifecycle-restart', 'lifecycle key restarts', { key: 'bob', body: call('svc.restart') }, [], ['accept']],
  ['accept-reload', 'lifecycle key reloads', { key: 'bob', body: call('svc.reload') }, [], ['accept']],
  ['accept-config-set', 'config:write key sets config', { key: 'carol', body: call('svc.config.set', { k: 'v' }) }, [], ['accept']],
  ['accept-tools-list-any-key', 'tools/list needs authentication only', { key: 'carol', body: rpc('tools/list') }, [], ['accept']],
  ['accept-ping', 'ping needs authentication only', { body: rpc('ping') }, [], ['accept']],
  ['accept-notification', 'notifications/* matched by a glob rule with no scope', { body: rpc('notifications/initialized') }, [], ['accept']],
  ['accept-response-object', 'a JSON-RPC response from the client needs authentication only', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }) }, [], ['accept']],
  ['accept-error-response-object', 'a JSON-RPC error response needs authentication only', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -1, message: 'x' } }) }, [], ['accept']],
  ['accept-query-string', 'query string is part of the signed target', { target: '/mcp?x=1&y=%2F', body: STATUS }, [], ['accept']],
  ['accept-get-empty-body', 'GET carries no JSON-RPC, authentication only', { method: 'GET' }, [], ['accept']],
  ['accept-utf8-body', 'body hash is over exact bytes (non-ASCII)', { body: call('svc.logs.query', { q: 'naïve café – 日本語' }) }, [], ['accept']],
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
  ['sig-tampered-body', 'body changed after signing', { body: STATUS, send: { body: call('svc.restart') } }, [], ['reject', 401, 'bad_signature']],
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

  // policy and request shape (nonce is consumed: authentication already succeeded)
  ['authz-read-key-restart', 'read key may not restart', { body: call('svc.restart') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-read-key-config-set', 'read key may not write config (specific rule before svc.*)', { body: call('svc.config.set') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-config-write-no-read', 'config:write does not imply read', { key: 'carol', body: call('svc.config.get') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-lifecycle-no-config-write', 'lifecycle does not imply config:write', { key: 'bob', body: call('svc.config.set') }, [], ['reject', 403, 'insufficient_scope']],
  ['authz-deny-rule', 'an explicit deny rule wins over the later svc.* rule', { key: 'root', body: call('svc.danger.wipe') }, [], ['reject', 403, 'operation_denied']],
  ['authz-unmapped-tool', 'a tool no rule matches is denied', { body: call('other.tool') }, [], ['reject', 403, 'operation_denied']],
  ['authz-proto-tool-name', 'prototype property names are not tools', { body: call('__proto__') }, [], ['reject', 403, 'operation_denied']],
  ['authz-unmapped-method', 'a method no rule matches is denied', { body: rpc('resources/read') }, [], ['reject', 403, 'operation_denied']],
  ['request-tool-name-missing', 'tools/call without params.name', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-tool-name-not-string', 'params.name is not a string', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 7 } }) }, [], ['reject', 400, 'invalid_request']],
  ['request-method-not-string', 'method is not a string', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 7 }) }, [], ['reject', 400, 'invalid_request']],
  ['request-wrong-jsonrpc-version', 'jsonrpc is not "2.0"', { body: JSON.stringify({ jsonrpc: '1.0', id: 1, method: 'ping' }) }, [], ['reject', 400, 'invalid_request']],
  ['request-response-with-both', 'response object with result and error', { body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: {}, error: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-response-without-id', 'response object without id', { body: JSON.stringify({ jsonrpc: '2.0', result: {} }) }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-json', 'signed body is not JSON', { body: '{not json' }, [], ['reject', 400, 'invalid_request']],
  ['request-invalid-utf8', 'signed body is not UTF-8', { body: Buffer.from([0xff, 0xfe, 0x7b]) }, [], ['reject', 400, 'invalid_request']],
  ['request-batch', 'JSON-RPC batch is rejected', { body: `[${STATUS}]` }, [], ['reject', 400, 'invalid_request']],
  ['request-empty-post', 'POST with empty body', { body: '' }, [], ['reject', 400, 'invalid_request']],
  ['request-missing-jsonrpc', 'object without jsonrpc "2.0"', { body: JSON.stringify({ id: 1, method: 'ping' }) }, [], ['reject', 400, 'invalid_request']],

  // protocol-native tools never reach the policy
  ['native-whoami', 'jack.whoami returns the caller (no public key)', { body: call('jack.whoami') }, [], ['accept']],
  ['native-admin-list', 'an admin lists users', { key: 'root', body: call('jack.admin.user.list') }, [], ['accept']],
  ['native-admin-denied-for-read-key', 'admin tools need the admin scope', { body: call('jack.admin.user.list') }, [], ['reject', 403, 'insufficient_scope']],
  ['native-admin-denied-for-agent-key', 'an agent key cannot hold admin', { key: 'agentx', body: call('jack.admin.user.list') }, [], ['reject', 403, 'insufficient_scope']],
  ['native-admin-not-opened-by-policy', 'a wildcard policy does not open jack.admin.*', { body: call('jack.admin.user.list') }, [], ['reject', 403, 'insufficient_scope'], 'wildcard'],
  ['native-unknown-tool-not-opened-by-policy', 'an undefined jack.* tool is denied even under a wildcard policy', { body: call('jack.nope') }, [], ['reject', 403, 'operation_denied'], 'wildcard'],
  ['native-wildcard-policy-other-tool', 'the wildcard policy still allows ordinary tools', { body: call('other.tool') }, [], ['accept'], 'wildcard'],
];

const requestVectors = REQUEST_CASES.map(([id, description, opts, cache, want, policy = 'default']) => {
  const { req, signing } = buildRequest(id, opts);
  const state = materialize({ policy, registry: registryJson.keys, nonce_cache: cacheOf(cache) });
  const got = verifyRequest(req, state);
  agree(id, got, want);
  return {
    id, description,
    state: { now: NOW, window_seconds: WINDOW, aud: AUD, policy, nonce_cache: cacheOf(cache) },
    request: req, expect: expectOf(got, new Set()), debug: { signing_string_lines: signing.split('\n') },
  };
});

// ---- stateful sequences: user management ----
const pk = (name) => K[name].public_key;
const IDENTITY = Buffer.from(`01${'00'.repeat(31)}`, 'hex');
const ORDER2 = fromBig((1n << 255n) - 20n, 32); // (0, -1)
const NONCANONICAL_IDENTITY = fromBig((1n << 255n) - 18n, 32); // y = p + 1
const ORDER8 = findOrder8Point();
const MIXED_ORDER = encodePoint(addPoints(BASE_POINT, ORDER8));
const BAD_KEYS = {
  identity: IDENTITY,
  order2: ORDER2,
  order8: encodePoint(ORDER8),
  noncanonical: NONCANONICAL_IDENTITY,
  mixed: MIXED_ORDER,
};
let offCurve;
for (let y = 2n; !offCurve; y++) if (!decodePoint(fromBig(y, 32))) offCurve = fromBig(y, 32);

const inv = (label, over = {}) => ({
  invite_id: inviteIdOf(codeOf(label)), scopes: ['read'], kind: 'human', created_by: K.root.kid,
  created_at: NOW - 100, expires_at: NOW + 3000, key_ttl_seconds: null, ...over,
});
const enrollArgs = (label, name, publicKey) => ({ code: codeOf(label), name, public_key: publicKey });
const step = (key, tool, args, want, extra = {}) => ({ key, tool, args, want, ...extra });
const A = (...w) => w; // reads better in the tables below

const SEQUENCES = [];
const seq = (id, description, init, steps) => SEQUENCES.push({ id, description, init, steps });
const init = (names, extra = {}) => ({ names, ...extra });

// enrollment
seq('enroll-ok', 'an invite holder enrolls a new key and can use it', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('enroll-key-ttl', 'key_ttl_seconds sets not_after at enrollment time', init(['root'], { invites: [inv('i1', { key_ttl_seconds: 3600 })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-agent-kind', 'the invite decides the kind of the enrolled key', init(['root'], { invites: [inv('i1', { kind: 'agent' })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-invite-last-second', 'an invite is valid until expires_at exclusive', init(['root'], { invites: [inv('i1', { expires_at: NOW + 1 })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-invite-expired', 'an expired invite is invalid', init(['root'], { invites: [inv('i1', { expires_at: NOW })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 403, 'invalid_invite')),
]);
seq('enroll-code-reuse', 'an invite is single-use', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie2', 'jack.enroll', enrollArgs('i1', 'newbie2', pk('newbie2')), A('reject', 403, 'invalid_invite')),
]);
seq('enroll-unknown-code', 'an unknown code is invalid', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('nope', 'newbie', pk('newbie')), A('reject', 403, 'invalid_invite')),
]);
seq('enroll-malformed-code', 'a code that is not canonical base64url is invalid, not a parameter error', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: 'not-a-code!!', name: 'newbie', public_key: pk('newbie') }, A('reject', 403, 'invalid_invite')),
]);
seq('enroll-code-not-string', 'code of the wrong type', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: 7, name: 'newbie', public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
]);
seq('enroll-missing-code', 'code is required', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { name: 'newbie', public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
]);
seq('enroll-invalid-name', 'name must match the allowed character set', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'bad name!', pk('newbie')), A('reject', 400, 'invalid_params')),
]);
seq('enroll-name-taken', 'a taken name fails and does not consume the invite', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'alice', pk('newbie')), A('reject', 409, 'name_taken')),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-registered-key', 'a registered key calling jack.enroll gets key_exists', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('alice', 'jack.enroll', enrollArgs('i1', 'alice2', pk('alice')), A('reject', 409, 'key_exists')),
]);
for (const [label, raw] of Object.entries(BAD_KEYS)) {
  seq(`enroll-key-${label}`, `a ${label} public key is rejected before the signature is checked`, init(['root'], { invites: [inv('i1')] }), [
    step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(raw)), A('reject', 400, 'key_rejected'), { hdr: { kid: kidOf(raw) }, sign: { kid: kidOf(raw) } }),
  ]);
}
seq('enroll-key-wrong-length', 'a 31-byte public key is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(K.newbie.pub.subarray(0, 31))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-padded-encoding', 'a padded base64url public key is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', `${pk('newbie')}=`), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-off-curve', 'a point that is not on the curve is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(offCurve)), A('reject', 400, 'key_rejected')),
]);
seq('enroll-kid-mismatch', 'the header kid must be the hash of the submitted key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie2', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-bad-signature', 'the request must be signed by the submitted key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'bad_signature'), { signKey: 'newbie2' }),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-stale-timestamp', 'the time window applies to enrollment', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'timestamp_out_of_window'), { ts: NOW - WINDOW - 1 }),
]);
seq('enroll-get-with-unknown-kid', 'GET with an unknown kid is unknown_key', init(['root']), [
  { key: 'newbie', method: 'GET', want: A('reject', 401, 'unknown_key') },
]);
seq('enroll-replay', 'a replayed enrollment fails at the nonce check', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  { repeat: 0, want: A('reject', 401, 'replayed_nonce') },
]);

// key rotation
const rotateArgs = (newName, oldName, signer) => ({ public_key: pk(newName), proof: rotateProof(newName, oldName, signer) });
seq('rotate-ok', 'rotation replaces the key; the old key stops working immediately', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', rotateArgs('newbie', 'alice'), A('accept')),
  step('alice', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('rotate-bad-proof', 'the proof must be signed by the new key', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', rotateArgs('newbie', 'alice', 'newbie2'), A('reject', 400, 'invalid_proof')),
]);
seq('rotate-proof-malformed', 'a malformed proof is invalid_proof', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: pk('newbie'), proof: 'abc' }, A('reject', 400, 'invalid_proof')),
]);
seq('rotate-proof-before-existence', 'a bad proof wins over key_exists so existence is not an oracle', init(['root', 'alice', 'bob']), [
  step('alice', 'jack.key.rotate', { public_key: pk('bob'), proof: rotateProof('bob', 'alice', 'newbie') }, A('reject', 400, 'invalid_proof')),
]);
seq('rotate-key-exists', 'rotating to a registered key fails', init(['root', 'alice', 'bob']), [
  step('alice', 'jack.key.rotate', rotateArgs('bob', 'alice'), A('reject', 409, 'key_exists')),
]);
seq('rotate-key-rejected', 'rotating to a small-order key fails', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: b64u(IDENTITY), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-missing-args', 'public_key and proof are required', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
]);

// administration: users
const STD = ['root', 'alice', 'bob', 'agentx'];
seq('admin-user-list', 'an admin lists users sorted by name', init(STD), [
  step('root', 'jack.admin.user.list', {}, A('accept')),
]);
seq('admin-user-list-requires-admin', 'a key without admin is refused and the attempt is audited', init(STD), [
  step('alice', 'jack.admin.user.list', {}, A('reject', 403, 'insufficient_scope')),
]);
seq('admin-user-get', 'get an entry by kid', init(STD), [
  step('root', 'jack.admin.user.get', { kid: K.alice.kid }, A('accept')),
  step('root', 'jack.admin.user.get', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
  step('root', 'jack.admin.user.get', { kid: 7 }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-ok', 'create a user from a public key', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read'] }, A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('admin-create-agent', 'create an agent key', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'bot', public_key: pk('newbie'), scopes: ['read'], kind: 'agent' }, A('accept')),
]);
seq('admin-create-validity', 'create a key with a validity interval', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read'], not_before: NOW - 10, not_after: NOW + 500 }, A('accept')),
]);
seq('admin-create-bad-validity', 'not_before must be below not_after', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read'], not_before: NOW + 500, not_after: NOW }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-name-taken', 'a taken name is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'alice', public_key: pk('newbie'), scopes: ['read'] }, A('reject', 409, 'name_taken')),
]);
seq('admin-create-key-exists', 'a registered key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('alice'), scopes: ['read'] }, A('reject', 409, 'key_exists')),
]);
seq('admin-create-key-rejected', 'a small-order key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(IDENTITY), scopes: ['read'] }, A('reject', 400, 'key_rejected')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(MIXED_ORDER), scopes: ['read'] }, A('reject', 400, 'key_rejected')),
]);
seq('admin-create-invalid-params', 'malformed arguments are invalid_params', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: 'read' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read', 'read'] }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['Bad Scope'] }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read'], kind: 'robot' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'bad name', public_key: pk('newbie'), scopes: ['read'] }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-escalation', 'an admin cannot grant a scope it does not hold', init(['lowadmin', 'alice']), [
  step('lowadmin', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read', 'lifecycle'] }, A('reject', 403, 'scope_escalation')),
]);
seq('admin-create-agent-admin', 'an agent key cannot be given admin', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'bot', public_key: pk('newbie'), scopes: ['admin'], kind: 'agent' }, A('reject', 403, 'agent_admin_forbidden')),
]);
seq('admin-create-escalation-before-agent-rule', 'escalation is checked before the agent rule', init(['lowadmin', 'alice']), [
  step('lowadmin', 'jack.admin.user.create', { name: 'bot', public_key: pk('newbie'), scopes: ['admin', 'lifecycle'], kind: 'agent' }, A('reject', 403, 'scope_escalation')),
]);
seq('admin-set-scopes-ok', 'add a scope the admin holds', init(STD), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.alice.kid, scopes: ['read', 'lifecycle'] }, A('accept')),
]);
seq('admin-set-scopes-remove', 'removing scopes is allowed', init(STD), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.bob.kid, scopes: ['read'] }, A('accept')),
]);
seq('admin-set-scopes-escalation', 'adding a scope the admin lacks is refused', init(['lowadmin', 'alice', 'root']), [
  step('lowadmin', 'jack.admin.user.set_scopes', { kid: K.alice.kid, scopes: ['read', 'lifecycle'] }, A('reject', 403, 'scope_escalation')),
]);
seq('admin-set-scopes-forbidden-target', 'an admin cannot modify a key holding scopes it lacks', init(['lowadmin', 'bob', 'root']), [
  step('lowadmin', 'jack.admin.user.set_scopes', { kid: K.bob.kid, scopes: ['read'] }, A('reject', 403, 'forbidden_admin_target')),
]);
seq('admin-set-scopes-agent-admin', 'admin cannot be added to an agent key', init(STD), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.agentx.kid, scopes: ['read', 'admin'] }, A('reject', 403, 'agent_admin_forbidden')),
]);
seq('admin-set-scopes-unknown-target', 'unknown kid', init(STD), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.mallory.kid, scopes: ['read'] }, A('reject', 404, 'unknown_target')),
]);
seq('admin-set-scopes-invalid', 'scopes must be an array', init(STD), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.alice.kid, scopes: 'read' }, A('reject', 400, 'invalid_params')),
]);
seq('admin-set-scopes-last-admin', 'the last admin cannot demote itself', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.root.kid, scopes: ['read'] }, A('reject', 409, 'last_admin')),
]);
seq('admin-set-scopes-self-demote', 'an admin can demote itself while another admin remains', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.root.kid, scopes: ['read'] }, A('accept')),
]);
seq('admin-last-admin-counts-active-only', 'an expired admin does not count as an administrator', init(['root', 'expadmin']), [
  step('root', 'jack.admin.user.set_scopes', { kid: K.root.kid, scopes: ['read'] }, A('reject', 409, 'last_admin')),
]);
seq('admin-revoke-ok', 'revoke a user', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.alice.kid }, A('accept')),
  step('alice', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);
seq('admin-revoke-unknown', 'unknown kid', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
]);
seq('admin-revoke-forbidden-target', 'an admin cannot revoke a key holding scopes it lacks', init(['lowadmin', 'bob', 'root']), [
  step('lowadmin', 'jack.admin.user.revoke', { kid: K.bob.kid }, A('reject', 403, 'forbidden_admin_target')),
]);
seq('admin-revoke-last-admin', 'the last admin cannot be revoked', init(['root', 'alice']), [
  step('root', 'jack.admin.user.revoke', { kid: K.root.kid }, A('reject', 409, 'last_admin')),
]);
seq('admin-revoke-self-ok', 'an admin can revoke itself while another admin remains', init(['root', 'admin2']), [
  step('root', 'jack.admin.user.revoke', { kid: K.root.kid }, A('accept')),
  step('root', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);

// administration: invites
seq('invite-create-ok', 'create an invite; the code is returned once', init(STD), [
  step('root', 'jack.admin.invite.create', { scopes: ['read'] }, A('accept')),
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-create-options', 'ttl and key_ttl_seconds', init(STD), [
  step('root', 'jack.admin.invite.create', { scopes: ['read', 'lifecycle'], kind: 'agent', ttl_seconds: 604800, key_ttl_seconds: 31536000 }, A('accept')),
]);
seq('invite-create-escalation', 'an invite cannot grant a scope its creator lacks', init(['lowadmin', 'root']), [
  step('lowadmin', 'jack.admin.invite.create', { scopes: ['lifecycle'] }, A('reject', 403, 'scope_escalation')),
]);
seq('invite-create-agent-admin', 'an invite cannot give admin to an agent key', init(STD), [
  step('root', 'jack.admin.invite.create', { scopes: ['admin'], kind: 'agent' }, A('reject', 403, 'agent_admin_forbidden')),
]);
seq('invite-create-invalid-params', 'ttl and kind ranges', init(STD), [
  step('root', 'jack.admin.invite.create', { scopes: ['read'], ttl_seconds: 604801 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { scopes: ['read'], ttl_seconds: 0 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { scopes: ['read'], ttl_seconds: 1.5 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { scopes: ['read'], key_ttl_seconds: 31536001 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { scopes: ['read'], kind: 'robot' }, A('reject', 400, 'invalid_params')),
]);
seq('invite-list-live-only', 'expired invites are not listed', init(STD, { invites: [inv('live'), inv('old', { expires_at: NOW })] }), [
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-revoke-ok', 'a revoked invite can no longer be used', init(STD, { invites: [inv('i1')] }), [
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('i1')) }, A('accept')),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 403, 'invalid_invite')),
]);
seq('invite-revoke-unknown', 'unknown or expired invite ids are unknown_target', init(STD, { invites: [inv('old', { expires_at: NOW })] }), [
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('nope')) }, A('reject', 404, 'unknown_target')),
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('old')) }, A('reject', 404, 'unknown_target')),
]);
seq('admin-unknown-native-tool', 'an undefined jack.* tool is denied and not audited', init(STD), [
  step('root', 'jack.admin.nuke', {}, A('reject', 403, 'operation_denied')),
]);

// Run every sequence against the reference verifier, recording expectations after each step.
const sequenceVectors = SEQUENCES.map(({ id, description, init: ini, steps }) => {
  const registry = ini.names.map((n) => entryOf(n));
  const invites = ini.invites ?? [];
  const policy = ini.policy ?? 'default';
  const state = materialize({ policy, registry, invites });
  const generated = new Set();
  const hooks = {
    newCode(s) {
      const code = defaultHooks.newCode(s);
      generated.add(code);
      generated.add(inviteIdOf(code));
      return code;
    },
  };
  const built = [];
  const out = steps.map((s, i) => {
    let request;
    let signing;
    if (s.repeat !== undefined) {
      ({ request, signing } = built[s.repeat]);
    } else {
      const body = s.method === 'GET' ? '' : call(s.tool, s.args);
      const r = buildRequest(`${id}#${i}`, {
        key: s.key, method: s.method, body, ts: s.ts, signKey: s.signKey, hdr: s.hdr, sign: s.sign,
      });
      request = r.req;
      signing = r.signing;
      built.push({ request, signing });
    }
    if (s.repeat !== undefined) built.push({ request, signing });
    const got = verifyRequest(request, state, hooks);
    agree(`${id}#${i}`, got, s.want);
    return { request, expect: expectOf(got, generated, { after: summary(state) }), debug: { signing_string_lines: signing.split('\n') } };
  });
  return {
    id, description,
    state: { now: NOW, window_seconds: WINDOW, aud: AUD, policy, registry, invites, nonce_cache: [] },
    steps: out,
  };
});

// ---- public-key vectors ----
const keyVectors = [
  ...Object.keys(K).map((name) => ({ id: `valid-${name}`, public_key_hex: K[name].pub.toString('hex'), expect: 'valid' })),
  { id: 'reject-identity', public_key_hex: IDENTITY.toString('hex'), expect: 'rejected', reason: 'identity' },
  { id: 'reject-order-2', public_key_hex: ORDER2.toString('hex'), expect: 'rejected', reason: 'small order' },
  { id: 'reject-order-8', public_key_hex: BAD_KEYS.order8.toString('hex'), expect: 'rejected', reason: 'small order' },
  { id: 'reject-noncanonical-identity', public_key_hex: NONCANONICAL_IDENTITY.toString('hex'), expect: 'rejected', reason: 'y = p + 1' },
  { id: 'reject-y-above-p', public_key_hex: 'ff'.repeat(32), expect: 'rejected', reason: 'y >= p' },
  { id: 'reject-mixed-order', public_key_hex: MIXED_ORDER.toString('hex'), expect: 'rejected', reason: 'base point plus an order-8 point' },
  { id: 'reject-off-curve', public_key_hex: offCurve.toString('hex'), expect: 'rejected', reason: 'not on the curve' },
  { id: 'reject-31-bytes', public_key_hex: K.alice.pub.subarray(0, 31).toString('hex'), expect: 'rejected', reason: 'length' },
  { id: 'reject-33-bytes', public_key_hex: `${K.alice.pub.toString('hex')}00`, expect: 'rejected', reason: 'length' },
].map((v) => {
  const wanted = v.expect === 'valid';
  const got = validatePublicKey(Buffer.from(v.public_key_hex, 'hex')) === null;
  if (got !== wanted) throw new Error(`${v.id}: reference verifier disagrees`);
  return v;
});

// ---- load-time validation vectors (policy and registry documents) ----
const rule = (over = {}) => ({ match: { method: 'ping' }, scope: null, ...over });
const POLICY_CASES = [
  ['valid-default', POLICIES.default, null],
  ['valid-wildcard', POLICIES.wildcard, null],
  ['valid-empty-rules', { version: 1, rules: [] }, null],
  ['valid-deny-rule-without-scope', { version: 1, rules: [{ match: { method: 'tools/call', tool: 'x.*' }, effect: 'deny' }] }, null],
  ['invalid-version', { version: 2, rules: [] }, 'document'],
  ['invalid-unknown-document-field', { version: 1, rules: [], comment: 'x' }, 'document'],
  ['invalid-unknown-rule-field', { version: 1, rules: [rule({ comment: 'x' })] }, 'unknown_field'],
  ['invalid-unknown-match-field', { version: 1, rules: [rule({ match: { method: 'ping', uri: 'x' } })] }, 'unknown_field'],
  ['invalid-missing-method', { version: 1, rules: [rule({ match: {} })] }, 'method'],
  ['invalid-empty-method', { version: 1, rules: [rule({ match: { method: '' } })] }, 'method'],
  ['invalid-tool-without-tools-call', { version: 1, rules: [rule({ match: { method: 'ping', tool: 'x' } })] }, 'tool_without_tools_call'],
  ['invalid-tool-with-glob-method', { version: 1, rules: [rule({ match: { method: 'tools/*', tool: 'x' } })] }, 'tool_without_tools_call'],
  ['invalid-scope-with-deny', { version: 1, rules: [rule({ effect: 'deny', scope: 'read' })] }, 'scope_with_deny'],
  ['invalid-missing-scope', { version: 1, rules: [{ match: { method: 'ping' } }] }, 'missing_scope'],
  ['invalid-malformed-scope', { version: 1, rules: [rule({ scope: 'Read' })] }, 'malformed_scope'],
  ['invalid-reserved-scope', { version: 1, rules: [rule({ scope: 'admin' })] }, 'reserved_scope'],
  ['invalid-effect', { version: 1, rules: [rule({ effect: 'permit' })] }, 'effect'],
].map(([id, document, reason]) => {
  const got = validatePolicy(document);
  if (got !== reason) throw new Error(`policy ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

const regWith = (mutate) => {
  const doc = clone({ version: 1, aud: AUD, keys: [entryOf('alice'), entryOf('bob')] });
  mutate(doc);
  return doc;
};
const REGISTRY_CASES = [
  ['valid-default', registryJson, null],
  ['valid-kind-omitted', regWith((d) => delete d.keys[0].kind), null],
  ['invalid-version', regWith((d) => { d.version = 2; }), 'document'],
  ['invalid-unknown-field', regWith((d) => { d.keys[0].comment = 'x'; }), 'unknown_field'],
  ['invalid-kid-mismatch', regWith((d) => { d.keys[0].kid = K.bob.kid; }), 'kid_mismatch'],
  ['invalid-small-order-key', regWith((d) => { d.keys[0].public_key = b64u(IDENTITY); d.keys[0].kid = kidOf(IDENTITY); }), 'public_key'],
  ['invalid-mixed-order-key', regWith((d) => { d.keys[0].public_key = b64u(MIXED_ORDER); d.keys[0].kid = kidOf(MIXED_ORDER); }), 'public_key'],
  ['invalid-duplicate-name', regWith((d) => { d.keys[1].name = 'alice'; }), 'duplicate_name'],
  ['invalid-duplicate-kid', regWith((d) => { d.keys[1] = { ...d.keys[0], name: 'other' }; }), 'duplicate_kid'],
  ['invalid-name-characters', regWith((d) => { d.keys[0].name = 'bad name'; }), 'name'],
  ['invalid-kind', regWith((d) => { d.keys[0].kind = 'robot'; }), 'kind'],
  ['invalid-agent-with-admin', regWith((d) => { d.keys[0].kind = 'agent'; d.keys[0].scopes = ['admin']; }), 'agent_admin'],
  ['invalid-duplicate-scope', regWith((d) => { d.keys[0].scopes = ['read', 'read']; }), 'scopes'],
  ['invalid-malformed-scope', regWith((d) => { d.keys[0].scopes = ['Bad Scope']; }), 'scopes'],
  ['invalid-validity-order', regWith((d) => { d.keys[0].not_before = NOW + 10; d.keys[0].not_after = NOW; }), 'validity'],
].map(([id, document, reason]) => {
  const got = validateRegistry(document);
  if (got !== reason) throw new Error(`registry ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

// ---- pattern vectors (spec 02 section 3: `*` is the only metacharacter) ----
const PATTERN_CASES = [
  ['svc.*', 'svc.status', true],
  ['svc.*', 'svc.', true],
  ['svc.*', 'svc', false],
  ['*', '', true],
  ['*', 'anything at all', true],
  ['a*b*c', 'aXXbYYc', true],
  ['a*b*c', 'abc', true],
  ['a*b*c', 'acb', false],
  ['svc.status', 'svc.status', true],
  ['svc.status', 'svcXstatus', false],
  ['svc.status', 'SVC.STATUS', false],
  ['tools/*', 'tools/call', true],
  ['a+b', 'a+b', true],
  ['a+b', 'aab', false],
  ['(x)', '(x)', true],
  ['[ab]', 'a', false],
  ['?', 'a', false],
  ['?', '?', true],
  ['*.*', 'jack.nope', true],
  ['a*', 'a\nb', true],
  ['*status', 'svc.status', true],
  ['*status', 'svc.status.extra', false],
].map(([pattern, input, match], i) => {
  if (matchPattern(pattern, input) !== match) throw new Error(`pattern ${pattern} vs ${JSON.stringify(input)} disagrees`);
  return { id: `pattern-${String(i + 1).padStart(2, '0')}`, pattern, input, match };
});

// ---- response cases ----
const base =buildRequest('accept-read-status', { body: STATUS });
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
const ids = [...requestVectors, ...sequenceVectors, ...responseVectors, ...keyVectors].map((v) => v.id);
const dup = ids.find((x, i) => ids.indexOf(x) !== i);
if (dup) throw new Error(`duplicate case id: ${dup}`);

const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const row = (cells) => `| ${cells.join(' | ')} |`;
const outcome = (e) => (e.result === 'accept' ? 'accept' : `${e.http_status} \`${e.code}\``);
const casesMd = [
  '# Conformance cases',
  '',
  'Generated by `tools/gen-fixtures.mjs`. Do not edit by hand.',
  '',
  `Fixed clock: now = ${NOW}, window = ${WINDOW} s, aud = \`${AUD}\`.`,
  '',
  `## Request verification (\`fixtures/request-vectors.json\`, ${requestVectors.length} cases)`,
  '',
  row(['id', 'description', 'expected']),
  row(['---', '---', '---']),
  ...requestVectors.map((v) => row([`\`${v.id}\``, v.description, outcome(v.expect)])),
  '',
  `## User-management sequences (\`fixtures/admin-vectors.json\`, ${sequenceVectors.length} cases)`,
  '',
  row(['id', 'description', 'step outcomes']),
  row(['---', '---', '---']),
  ...sequenceVectors.map((v) => row([`\`${v.id}\``, v.description, v.steps.map((s) => outcome(s.expect)).join(' → ')])),
  '',
  `## Public-key validity (\`fixtures/key-vectors.json\`, ${keyVectors.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...keyVectors.map((v) => row([`\`${v.id}\``, v.expect])),
  '',
  `## Policy documents (\`fixtures/load-vectors.json\`, \`policies\`, ${POLICY_CASES.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...POLICY_CASES.map((v) => row([`\`${v.id}\``, v.reason ? `invalid (${v.reason})` : 'valid'])),
  '',
  `## Registry documents (\`fixtures/load-vectors.json\`, \`registries\`, ${REGISTRY_CASES.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...REGISTRY_CASES.map((v) => row([`\`${v.id}\``, v.reason ? `invalid (${v.reason})` : 'valid'])),
  '',
  `## Pattern matching (\`fixtures/pattern-vectors.json\`, ${PATTERN_CASES.length} cases)`,
  '',
  row(['id', 'pattern', 'input', 'match']),
  row(['---', '---', '---', '---']),
  ...PATTERN_CASES.map((v) => row([`\`${v.id}\``, `\`${v.pattern}\``, `\`${JSON.stringify(v.input)}\``, String(v.match)])),
  '',
  `## Response verification (\`fixtures/response-vectors.json\`, ${responseVectors.length} cases)`,
  '',
  row(['id', 'description', 'expected']),
  row(['---', '---', '---']),
  ...responseVectors.map((v) => row([`\`${v.id}\``, v.description, v.expect.result === 'accept' ? 'accept' : `reject \`${v.expect.code}\``])),
  '',
].join('\n');

const OUT = {
  'fixtures/keys.json': json(keysJson),
  'fixtures/registry.json': json(registryJson),
  'fixtures/policy.json': json(POLICIES.default),
  'fixtures/policy-wildcard.json': json(POLICIES.wildcard),
  'fixtures/request-vectors.json': json({ registry: 'registry.json', policies: { default: 'policy.json', wildcard: 'policy-wildcard.json' }, cases: requestVectors }),
  'fixtures/admin-vectors.json': json({ cases: sequenceVectors }),
  'fixtures/key-vectors.json': json({ cases: keyVectors }),
  'fixtures/load-vectors.json': json({ policies: POLICY_CASES, registries: REGISTRY_CASES }),
  'fixtures/pattern-vectors.json': json({ cases: PATTERN_CASES }),
  'fixtures/response-vectors.json': json({ cases: responseVectors }),
  'tests/CASES.md': casesMd,
};

if (process.argv.includes('--check')) {
  const stale = Object.entries(OUT).filter(([p, c]) => !existsSync(join(ROOT, p)) || readFileSync(join(ROOT, p), 'utf8') !== c);
  if (stale.length) {
    console.error(`stale: ${stale.map(([p]) => p).join(', ')}`);
    process.exit(1);
  }
  console.log(`ok: ${requestVectors.length} request, ${sequenceVectors.length} sequence, ${keyVectors.length} key, ${POLICY_CASES.length} policy, ${REGISTRY_CASES.length} registry, ${PATTERN_CASES.length} pattern, ${responseVectors.length} response cases, fixtures up to date`);
} else {
  for (const [p, c] of Object.entries(OUT)) writeFileSync(join(ROOT, p), c);
  console.log(`wrote ${Object.keys(OUT).length} files: ${requestVectors.length} request, ${sequenceVectors.length} sequence, ${keyVectors.length} key, ${POLICY_CASES.length} policy, ${REGISTRY_CASES.length} registry, ${PATTERN_CASES.length} pattern, ${responseVectors.length} response cases`);
}
