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
  validateRegistry, validateStateFile,
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
// The scope reduction removed scopes and kinds: one strict boolean `admin` per
// entry gates only `jack.admin.*` (spec 02 section 1). Only root is an
// administrator in the std registry; every other entry omits the flag, which
// is the default-false discriminator.
const KEY_DEFS = {
  alice: { std: true },
  bob: { std: true },
  carol: { std: true },
  erin: { not_before: NOW + 1000, std: true },
  frank: { not_after: NOW - 1000, std: true },
  root: { admin: true, std: true },
  agentx: { std: true },
  lowadmin: {}, // an ordinary user despite the historical name
  admin2: { admin: true }, // a second administrator despite the historical name
  expadmin: { admin: true, not_after: NOW - 1000 }, // an expired administrator: admin true, not active
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

// Documents may omit admin (default false), so the entry carries it only when true.
const entryOf = (name, over = {}) => {
  const d = KEY_DEFS[name] ?? {};
  return {
    kid: K[name].kid, public_key: K[name].public_key, name,
    ...(d.admin === true ? { admin: true } : {}),
    ...(d.not_before !== undefined ? { not_before: d.not_before } : {}),
    ...(d.not_after !== undefined ? { not_after: d.not_after } : {}),
    ...over,
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

// ---- builders ----
const nonceOf = (label) => b64u(sha256(`nonce:${label}`).subarray(0, 16));
const sigOf = (name, msg) => b64u(sign(null, Buffer.from(msg, 'utf8'), K[name].priv));
const call = (name, args) => JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, ...(args === undefined ? {} : { arguments: args }) } });
const rpc = (method) => JSON.stringify({ jsonrpc: '2.0', id: 1, method });
// tools/call with raw JSON text for params.arguments, so a case can send
// number literals JSON.stringify cannot express (1.0, 1e3, -0).
const callRaw = (name, argsText) => `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${argsText}}}`;
// arguments with one member replaced by raw JSON text
const rawArg = (args, key, literal) =>
  JSON.stringify({ ...args, [key]: `@@${key}@@` }).replace(JSON.stringify(`@@${key}@@`), literal);
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
const materialize = ({ registry, invites = [], nonce_cache = [] }) => ({
  now: NOW, window_seconds: WINDOW, aud: AUD, registry: { keys: clone(registry) },
  invites: clone(invites), nonce_cache: clone(nonce_cache),
});
const byName = (a, b) => (a.name < b.name ? -1 : 1);

// Codes created by the server are random in real implementations: expectations use a placeholder.
const PLACEHOLDER = '<b64u43>';
function scrub(value, generated) {
  if (typeof value === 'string') return generated.has(value) ? PLACEHOLDER : value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, generated));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, generated)]));
  return value;
}

// Sorting for the full durable-state compare: scrub the id first, then compare
// [scrubbed invite_id, created_at] pairs; JS sort is stable so equal keys keep
// insertion order. Identical implementation on both sides (generator + shadow).
const inviteOrder = (generated) => (a, b) => {
  const ia = generated.has(a.invite_id) ? PLACEHOLDER : a.invite_id;
  const ib = generated.has(b.invite_id) ? PLACEHOLDER : b.invite_id;
  return ia < ib ? -1 : ia > ib ? 1 : a.created_at - b.created_at;
};

function expectOf(got, generated, extra = {}) {
  const e = { result: got.result };
  if (got.result === 'accept') {
    e.kid = got.kid;
    // Forwarded accepts carry the verified caller identity (spec 02 section 3).
    if (got.identity) e.identity = got.identity;
    if (got.structured !== undefined) e.structured = scrub(got.structured, generated);
  } else {
    e.http_status = got.http_status;
    e.code = got.code;
  }
  if (got.audit) e.audit = got.audit;
  e.nonce_recorded = got.nonce_recorded;
  return { ...e, ...extra };
}

// Canonical deep equality: stable stringify with sorted object keys, arrays in order.
const stableStringify = (v) => {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};
const deepEqual = (a, b) => stableStringify(a) === stableStringify(b);

// The verifier must agree with the generator's full independent expectation on
// every field, not just the outcome tuple.
function agree(id, got, want) {
  if (!deepEqual(got, want)) {
    throw new Error(`${id}: reference verifier disagrees:\n  got:  ${stableStringify(got)}\n  want: ${stableStringify(want)}`);
  }
}

// Authentication failures happen before the nonce is recorded; every other
// rejection consumed it.
const AUTH_FAILURES = new Set([
  'missing_auth', 'malformed_auth', 'unsupported_version', 'unknown_key', 'key_inactive',
  'timestamp_out_of_window', 'bad_signature', 'replayed_nonce',
]);
const AUDITED_TOOLS = new Set([
  'jack.enroll', 'jack.key.rotate',
  'jack.admin.user.list', 'jack.admin.user.get', 'jack.admin.user.create', 'jack.admin.user.set_admin',
  'jack.admin.user.revoke', 'jack.admin.invite.create', 'jack.admin.invite.list', 'jack.admin.invite.revoke',
]);
const whoamiView = (e) => ({ kid: e.kid, name: e.name, admin: e.admin === true, not_before: e.not_before ?? null, not_after: e.not_after ?? null });
const userView = (e) => ({ kid: e.kid, public_key: e.public_key, name: e.name, admin: e.admin === true, not_before: e.not_before ?? null, not_after: e.not_after ?? null });
const kidOfB64 = (public_key) => kidOf(Buffer.from(public_key, 'base64url'));

// Full durable state: every registry entry in full, every persisted invite
// record in full (member absent when unset, never null). A rejected step that
// corrupts a public_key or mutates an invite's admin/TTL now fails the compare.

// Independent expectation for a single-request case, built from the registry
// model (02 sections 2-3, 03 section 4).
const JACK_TOOL_RE = /"name":"(jack\.[^"]+)"/g;
function requestExpect(opts, [result, http_status, code]) {
  const caller = registryJson.keys.find((e) => e.name === (opts.key ?? 'alice'));
  const want = { result };
  if (result === 'reject') {
    want.http_status = http_status;
    want.code = code;
  } else {
    want.kid = caller.kid;
  }
  const body = typeof opts.body === 'string' ? opts.body : '';
  const names = [...body.matchAll(JACK_TOOL_RE)].map((m) => m[1]);
  const tool = names[names.length - 1]; // duplicated member names: last wins
  // An enrollment whose submitted key fails validation is rejected inside 01
  // step 4, before the nonce exists: no audit, no nonce (03 sections 3.2 and 8).
  // Admin tools validate keys inside the tool: post-auth, audited, nonce consumed.
  const preAuth = result === 'reject' && (AUTH_FAILURES.has(code) || (code === 'key_rejected' && tool === 'jack.enroll'));
  if (tool === undefined) {
    // Forwarded accepts carry the verified caller identity (spec 02 section 3).
    if (result === 'accept') want.identity = { kid: caller.kid, name: caller.name, admin: caller.admin === true };
  } else if (result === 'accept') {
    if (tool === 'jack.whoami') want.structured = whoamiView(caller);
    if (tool === 'jack.admin.user.list') {
      want.structured = { users: [...registryJson.keys].sort(byName).map(userView) };
      want.audit = { tool, outcome: 'success', code: null, actor_kid: caller.kid };
    }
  } else if (!preAuth && AUDITED_TOOLS.has(tool)) {
    want.audit = { tool, outcome: 'failure', code, actor_kid: caller.kid };
  }
  want.nonce_recorded = !preAuth;
  return want;
}

// ---- shadow model: the generator's own view of sequence state ----
// Each sequence advances this shadow alongside the verifier; the expectation is
// built from the shadow before running the step and must equal the verifier's
// full output, so a verifier that mutates state on rejection fails the compare.
const shadowInit = (ini) => ({
  users: ini.names.map((n) => userView(entryOf(n))),
  invites: (ini.invites ?? []).map((r) => ({
    invite_id: r.invite_id, admin: r.admin === true, created_by: r.created_by,
    created_at: r.created_at, expires_at: r.expires_at,
    ...(r.key_ttl_seconds !== undefined ? { key_ttl_seconds: r.key_ttl_seconds } : {}),
  })),
});
const durableShadow = (shadow, generated) => ({
  users: [...shadow.users].sort(byName).map(userView),
  invites: shadow.invites
    .map((r) => ({
      invite_id: generated.has(r.invite_id) ? PLACEHOLDER : r.invite_id,
      admin: r.admin === true, created_by: r.created_by, created_at: r.created_at, expires_at: r.expires_at,
      ...(r.key_ttl_seconds !== undefined ? { key_ttl_seconds: r.key_ttl_seconds } : {}),
    }))
    .sort(inviteOrder(generated)),
});
const durableState = (state, generated) => ({
  users: [...state.registry.keys].sort(byName).map(userView),
  invites: state.invites
    .map((r) => ({
      invite_id: generated.has(r.invite_id) ? PLACEHOLDER : r.invite_id,
      admin: r.admin === true, created_by: r.created_by, created_at: r.created_at, expires_at: r.expires_at,
      ...(r.key_ttl_seconds !== undefined ? { key_ttl_seconds: r.key_ttl_seconds } : {}),
    }))
    .sort(inviteOrder(generated)),
});
// Raw durable data for the exact rejection check: the JSON round trip keeps
// member presence (absent vs null vs false) instead of normalizing views.
const rawDurable = (state) => JSON.parse(JSON.stringify({ keys: state.registry.keys, invites: state.invites }));
// Raw-JSON bodies (callRaw/rawArg) carry arguments the spread model cannot read.
const shadowArgs = (s) => (typeof s.args === 'string' ? JSON.parse(s.args) : s.model ?? s.args) ?? {};

// Applies an accepted step's effect to the shadow. Rejections never reach this.
function shadowApply(shadow, s, kid) {
  const args = shadowArgs(s);
  const tool = s.tool;
  const caller = shadow.users.find((e) => e.kid === K[s.key].kid);
  if (tool === 'jack.enroll') {
    const invite = shadow.invites.find((r) => r.invite_id === inviteIdOf(args.code) && NOW < r.expires_at);
    shadow.invites.splice(shadow.invites.indexOf(invite), 1);
    shadow.users.push({ kid, public_key: args.public_key, name: args.name, admin: invite.admin, not_before: null, not_after: invite.key_ttl_seconds ? NOW + invite.key_ttl_seconds : null });
  } else if (tool === 'jack.admin.user.create') {
    shadow.users.push({ kid: kidOfB64(args.public_key), public_key: args.public_key, name: args.name, admin: args.admin === true, not_before: args.not_before ?? null, not_after: args.not_after ?? null });
  } else if (tool === 'jack.admin.user.set_admin') {
    shadow.users.find((e) => e.kid === args.kid).admin = args.admin;
  } else if (tool === 'jack.admin.user.revoke') {
    shadow.users.splice(shadow.users.findIndex((e) => e.kid === args.kid), 1);
  } else if (tool === 'jack.key.rotate') {
    caller.kid = kidOfB64(args.public_key);
    caller.public_key = args.public_key;
  } else if (tool === 'jack.admin.invite.create') {
    // Codes created by the server are scrubbed to PLACEHOLDER on the got side,
    // so the shadow can use the same marker as its invite id.
    shadow.invites.push({
      invite_id: PLACEHOLDER, admin: args.admin === true, created_by: caller.kid,
      created_at: NOW, expires_at: NOW + (args.ttl_seconds ?? 3600),
      ...(args.key_ttl_seconds !== undefined ? { key_ttl_seconds: args.key_ttl_seconds } : {}),
    });
  } else if (tool === 'jack.admin.invite.revoke') {
    shadow.invites.splice(shadow.invites.findIndex((r) => r.invite_id === args.invite_id && NOW < r.expires_at), 1);
  }
}

// Builds the full expectation of one sequence step from the shadow, applying
// the step's effect on accept; want.after therefore equals the pre-state for a
// rejection (rejections do not mutate).
function expectStep(shadow, generated, s, key, tuple) {
  const [result, http_status, code] = tuple;
  const accept = result === 'accept';
  const args = shadowArgs(s);
  // The caller is the entry named by the header kid; rotation may have moved it.
  const caller = shadow.users.find((e) => e.kid === K[key].kid);
  const kid = s.tool === 'jack.enroll' ? kidOfB64(args.public_key) : K[key].kid;
  const want = { result };
  if (accept) want.kid = kid;
  else {
    want.http_status = http_status;
    want.code = code;
  }
  // An enrollment whose submitted key fails validation is rejected inside 01
  // step 4, before the nonce exists: no audit, no nonce (03 sections 3.2 and 8).
  // Admin tools validate keys inside the tool: post-auth, audited, nonce consumed.
  const preAuth = result === 'reject' && (AUTH_FAILURES.has(code) || (code === 'key_rejected' && s.tool === 'jack.enroll'));
  const nonceRecorded = !preAuth;
  want.nonce_recorded = nonceRecorded;
  if (s.tool && AUDITED_TOOLS.has(s.tool) && nonceRecorded) {
    want.audit = { tool: s.tool, outcome: accept ? 'success' : 'failure', code: accept ? null : code, actor_kid: kid };
  }
  if (accept && !s.tool) want.identity = { kid, name: caller.name, admin: caller.admin }; // forwarded accept
  if (accept) {
    if (s.tool === 'jack.whoami') want.structured = whoamiView(caller);
    else if (s.tool === 'jack.admin.user.list') want.structured = { users: [...shadow.users].sort(byName).map(userView) };
    else if (s.tool === 'jack.admin.user.get') want.structured = userView(shadow.users.find((e) => e.kid === args.kid));
    else if (s.tool === 'jack.admin.user.create') want.structured = { kid: kidOfB64(args.public_key) };
    else if (s.tool === 'jack.admin.user.revoke') want.structured = { kid: args.kid };
    else if (s.tool === 'jack.key.rotate') want.structured = { kid: kidOfB64(args.public_key) };
    else if (s.tool === 'jack.enroll') {
      const invite = shadow.invites.find((r) => r.invite_id === inviteIdOf(args.code) && NOW < r.expires_at);
      want.structured = { kid, name: args.name, admin: invite.admin };
    } else if (s.tool === 'jack.admin.invite.create') {
      want.structured = { invite_id: PLACEHOLDER, code: PLACEHOLDER, expires_at: NOW + (args.ttl_seconds ?? 3600) };
    } else if (s.tool === 'jack.admin.invite.list') {
      want.structured = {
        invites: shadow.invites.filter((r) => NOW < r.expires_at).map((r) => ({
          invite_id: r.invite_id, admin: r.admin, created_by: r.created_by, created_at: r.created_at, expires_at: r.expires_at,
        })),
      };
    } else if (s.tool === 'jack.admin.invite.revoke') want.structured = { invite_id: args.invite_id };
    shadowApply(shadow, s, kid);
    // set_admin's view is the target after the change.
    if (s.tool === 'jack.admin.user.set_admin') want.structured = userView(shadow.users.find((e) => e.kid === args.kid));
  }
  want.after = durableShadow(shadow, generated);
  return want;
}

// ---- single-request cases: [id, description, build options, nonce cache, expected] ----
const STATUS = call('status');
const lastChar = (v) => `${v.slice(0, -1)}B`; // sets unused trailing bits of the 64-byte signature
// A ping request whose string argument carries raw invalid UTF-8 bytes: lossy
// decoding yields valid JSON, so only the UTF-8 check itself can reject it.
const pingBody = (bad) => Buffer.concat([
  Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"', 'utf8'),
  bad,
  Buffer.from('"}}', 'utf8'),
]);
// Bodies with one duplicated member name for the last-member-wins rule
// (spec README D13, 02 section 2): the duplicate pair sits adjacent so the
// fixture bytes show both occurrences and their order. A first-wins parser
// fails each order-sensitive pair; a merging parser fails the disjoint case.
const dupMethodBody = (first, last) =>
  `{"jsonrpc":"2.0","id":1,"method":"${first}","method":"${last}"}`;
const dupToolBody = (first, last) =>
  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${first}","name":"${last}"}}`;
const REQUEST_CASES = [
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
  ['dup-method-tools-call-last-invalid', 'a duplicated method member keeps the last occurrence: ping then tools/call without params.name', { body: dupMethodBody('ping', 'tools/call') }, [], ['reject', 400, 'invalid_request']],
  ['dup-method-tools-call-first-invalid', 'the same duplicated pair in the other order: tools/call then ping', { body: dupMethodBody('tools/call', 'ping') }, [], ['accept']],
  ['dup-tool-name-first-allow-last-deny', 'a duplicated params.name keeps the last occurrence: jack.whoami then an admin tool called by a non-admin', { body: dupToolBody('jack.whoami', 'jack.admin.user.list') }, [], ['reject', 403, 'admin_required']],
  ['dup-tool-name-first-deny-last-allow', 'the same duplicated params.name in the other order: admin tool then jack.whoami', { body: dupToolBody('jack.admin.user.list', 'jack.whoami') }, [], ['accept']],
  ['dup-jsonrpc-first-wrong-last-right', 'a duplicated jsonrpc member keeps the last occurrence', { body: '{"jsonrpc":"1.0","jsonrpc":"2.0","id":1,"method":"ping"}' }, [], ['accept']],
  ['dup-member-escaped-name-last-wins', 'a member whose name unescapes to an earlier name is its duplicate and keeps the last value', { body: '{"jsonrpc":"2.0","id":1,"method":"ping","meth\\u006fd":"tools/call"}' }, [], ['reject', 400, 'invalid_request']],
  ['dup-params-object-last-without-name', 'a duplicated params object keeps the last one whole: no member union, so the earlier name does not survive', { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status"},"params":{"other":1}}' }, [], ['reject', 400, 'invalid_request']],
];

const requestVectors = REQUEST_CASES.map(([id, description, opts, cache, tuple]) => {
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

// Base record carries no key_ttl_seconds: the member is present only when the
// invite sets a key expiry (spec 03 section 3.3); overrides add real numbers.
const inv = (label, over = {}) => ({
  invite_id: inviteIdOf(codeOf(label)), created_by: K.root.kid,
  created_at: NOW - 100, expires_at: NOW + 3000, ...over,
});
const enrollArgs = (label, name, publicKey) => ({ code: codeOf(label), name, public_key: publicKey });
const step = (key, tool, args, want, extra = {}) => ({ key, tool, args, want, ...extra });
// `model` states the effective arguments when the request body is raw JSON
// text the step's `args` cannot express; expectations are built from it.
const A = (...w) => w; // reads better in the tables below

const SEQUENCES = [];
const seq = (id, description, init, steps) => SEQUENCES.push({ id, description, init, steps });
const init = (names, extra = {}) => ({ names, ...extra });

// enrollment. Enroll steps use enrollArgs against a seeded invite from init;
// codes created by jack.admin.invite.create steps appear in expectations only
// (scrubbed via expectOf), never in emitted request bytes.
seq('enroll-ok', 'an invite holder enrolls a new key and can use it; the enrolled entry is an ordinary user (admin false)', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('enroll-key-ttl', 'key_ttl_seconds sets not_after at enrollment time', init(['root'], { invites: [inv('i1', { key_ttl_seconds: 3600 })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-admin-invite', 'the invite carries admin and the enrolled entry is an administrator', init(['root'], { invites: [inv('i1', { admin: true })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
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
seq('rotate-preserves-admin', 'rotation preserves admin and never trips the last-administrator rule', init(['root']), [
  step('root', 'jack.key.rotate', rotateArgs('newbie', 'root'), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
  step('root', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
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
  step('alice', 'jack.admin.user.list', {}, A('reject', 403, 'admin_required')),
]);
seq('admin-user-get', 'get an entry by kid', init(STD), [
  step('root', 'jack.admin.user.get', { kid: K.alice.kid }, A('accept')),
  step('root', 'jack.admin.user.get', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
  step('root', 'jack.admin.user.get', { kid: 7 }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-ok', 'create a user from a public key', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie') }, A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('admin-create-admin-flag', 'any administrator may create another administrator', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), admin: true }, A('accept')),
]);
seq('admin-create-stale-members-inert', 'unknown argument members are inert: stale scopes and kind cannot escalate (spec 03 section 3)', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read', 'admin'], kind: 'agent' }, A('accept')),
  step('root', 'jack.admin.user.list', {}, A('accept')),
]);
seq('admin-create-admin-mistyped', 'a mistyped admin fails closed', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), admin: 'true' }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-validity', 'create a key with a validity interval', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: NOW - 10, not_after: NOW + 500 }, A('accept')),
]);
seq('admin-create-bad-validity', 'not_before must be below not_after', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: NOW + 500, not_after: NOW }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-name-taken', 'a taken name is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'alice', public_key: pk('newbie') }, A('reject', 409, 'name_taken')),
]);
seq('admin-create-key-exists', 'a registered key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('alice') }, A('reject', 409, 'key_exists')),
]);
seq('admin-create-key-rejected', 'a small-order key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(IDENTITY) }, A('reject', 400, 'key_rejected')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(MIXED_ORDER) }, A('reject', 400, 'key_rejected')),
]);
seq('admin-create-invalid-params', 'malformed arguments are invalid_params', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'bad name', public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: 'x' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_after: 1.5 }, A('reject', 400, 'invalid_params')),
]);
seq('admin-set-admin-grant', 'an administrator can grant admin', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: true }, A('accept')),
]);
seq('admin-set-admin-demote', 'an administrator can demote another administrator', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.admin2.kid, admin: false }, A('accept')),
]);
seq('admin-set-admin-self-demote-ok', 'an administrator can demote itself while another administrator remains', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('accept')),
]);
seq('admin-set-admin-last-admin', 'the last administrator cannot demote itself', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-set-admin-serialized-strip', 'two serialized demotions: the second must be rejected so the invariant holds (spec 03 section 9)', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.admin2.kid, admin: false }, A('accept')),
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-set-admin-invalid-params', 'the admin argument is required and must be a strict boolean', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: null }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: 1 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: 'yes' }, A('reject', 400, 'invalid_params')),
]);
seq('admin-set-admin-unknown-target', 'unknown kid', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.mallory.kid, admin: true }, A('reject', 404, 'unknown_target')),
]);
seq('admin-last-admin-counts-active-only', 'an expired admin does not count as an administrator', init(['root', 'expadmin']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-revoke-ok', 'revoke a user', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.alice.kid }, A('accept')),
  step('alice', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);
seq('admin-revoke-unknown', 'unknown kid', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
]);
seq('admin-revoke-other-admin', 'an administrator can revoke another administrator while one remains', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.revoke', { kid: K.admin2.kid }, A('accept')),
  step('admin2', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
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
  step('root', 'jack.admin.invite.create', {}, A('accept')),
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-create-options', 'ttl and key_ttl_seconds', init(STD), [
  step('root', 'jack.admin.invite.create', { ttl_seconds: 604800, key_ttl_seconds: 31536000 }, A('accept')),
]);
seq('invite-create-admin-invite', 'an admin invite is created and listed with admin true (inheritance on enrollment is covered by enroll-admin-invite)', init(['root']), [
  step('root', 'jack.admin.invite.create', { admin: true }, A('accept')),
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-create-invalid-params', 'ttl ranges and a mistyped admin', init(STD), [
  step('root', 'jack.admin.invite.create', { ttl_seconds: 604801 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { ttl_seconds: 0 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { ttl_seconds: 1.5 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { key_ttl_seconds: 31536001 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { admin: 'yes' }, A('reject', 400, 'invalid_params')),
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

// ---- cross-language edge cases. Kept at the end so the ids and vector
// positions of the core cases above stay stable and fixture diffs stay
// additions-only when new cases are added here. ----
const B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
// A copy of a canonical base64url string that differs only in the two unused
// trailing bits of its last character: a lenient decoder yields the same bytes,
// a strict decoder rejects the encoding. Asserted here so the vector cannot rot.
const withTrailingBits = (canonical) => {
  const idx = B64U_ALPHABET.indexOf(canonical[canonical.length - 1]);
  const variant = canonical.slice(0, -1) + B64U_ALPHABET[(idx + 1) % 64];
  if (!Buffer.from(variant, 'base64url').equals(Buffer.from(canonical, 'base64url'))) {
    throw new Error('trailing-bit variant must decode to the same bytes');
  }
  return variant;
};
const withStandardAlphabet = (canonical) => `+${canonical.slice(1, 42)}/${canonical.slice(43)}`;
const createRaw = (literal) => rawArg({ name: 'dave', public_key: pk('newbie') }, 'not_after', literal);
// A body with a root member whose name embeds the escaped path of the real
// argument; exact-key lookup must ignore it (a joined-path key would alias).
const decoyBody = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":true,"ttl_seconds":60}},"params\\u0000arguments\\u0000ttl_seconds":1.0}';

// enrollment public_key encodings
seq('enroll-key-standard-alphabet', 'a public key using + and / is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', withStandardAlphabet(pk('newbie'))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-trailing-bits', 'a public key differing only in unused trailing bits is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', withTrailingBits(pk('newbie'))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-whitespace', 'a public key with embedded whitespace is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', `${pk('newbie').slice(0, 21)} ${pk('newbie').slice(21)}`), A('reject', 400, 'key_rejected')),
]);

// rotation new-key argument encodings (spec 03 section 3.1)
seq('rotate-key-padded-encoding', 'a padded rotation public_key is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: `${pk('newbie')}=`, proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-standard-alphabet', 'a rotation public_key using + and / is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: withStandardAlphabet(pk('newbie')), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-trailing-bits', 'a rotation public_key with non-zero unused trailing bits is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: withTrailingBits(pk('newbie')), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-whitespace', 'a rotation public_key with embedded whitespace is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: `${pk('newbie').slice(0, 21)} ${pk('newbie').slice(21)}`, proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-wrong-length', 'a 31-byte rotation public_key is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: b64u(K.newbie.pub.subarray(0, 31)), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);

// integer argument classes (spec 03 section 3)
for (const [id, description, literal] of [
  ['admin-create-not-after-fraction', 'a not_after of 1.5 is not an integer', '1.5'],
  ['admin-create-not-after-exponent', 'a not_after of 1e3 is not an integer', '1e3'],
  ['admin-create-not-after-negative', 'a negative not_after is out of range', '-1'],
  ['admin-create-not-after-above-max', 'a not_after above 999999999999 is out of range', '1000000000000'],
  ['admin-create-not-after-huge', 'a not_after beyond float64 precision is out of range', '9007199254740993'],
]) {
  seq(id, description, init(['root']), [
    step('root', 'jack.admin.user.create', createRaw(literal), A('reject', 400, 'invalid_params')),
  ]);
}
seq('admin-create-not-after-negative-zero', 'a not_after of -0 is the integer 0 and accepted', init(['root']), [
  step('root', 'jack.admin.user.create', createRaw('-0'), A('accept')),
]);
for (const [id, description, literal] of [
  ['invite-create-ttl-fraction', 'a ttl_seconds of 1.0 is not an integer', '1.0'],
  ['invite-create-ttl-exponent', 'a ttl_seconds of 1e3 is not an integer', '1e3'],
  ['invite-create-ttl-negative-zero', 'a ttl_seconds of -0 is the integer 0, below the minimum', '-0'],
  ['invite-create-ttl-string', 'a ttl_seconds in a JSON string is not a number', '"60"'],
  ['invite-create-ttl-boolean', 'a boolean ttl_seconds is not a number', 'true'],
  ['invite-create-ttl-huge', 'a ttl_seconds beyond float64 precision is out of range', '9007199254740993'],
]) {
  seq(id, description, init(['root']), [
    step('root', 'jack.admin.invite.create', rawArg({}, 'ttl_seconds', literal), A('reject', 400, 'invalid_params')),
  ]);
}
seq('invite-create-ttl-decoy-member', 'a decoy member cannot override the ttl_seconds number text', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: decoyBody, model: { admin: true, ttl_seconds: 60 } }),
]);
seq('invite-create-ttl-dup-invalid-then-valid', 'a duplicated ttl_seconds member keeps the last occurrence: 1.5 then 60', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":1.5,"ttl_seconds":60}}}', model: { ttl_seconds: 60 } }),
]);
seq('invite-create-ttl-dup-valid-then-invalid', 'the same duplicated pair in the other order: 60 then 1.5', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_params'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":60,"ttl_seconds":1.5}}}' }),
]);
seq('invite-create-arguments-dup-invalid-then-valid', 'a duplicated arguments object keeps the last one: mistyped admin then valid arguments', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":"true"},"arguments":{"admin":true,"ttl_seconds":60}}}', model: { admin: true, ttl_seconds: 60 } }),
]);
seq('invite-create-arguments-dup-valid-then-invalid', 'the same duplicated arguments in the other order: valid then mistyped admin', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_params'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":true,"ttl_seconds":60},"arguments":{"admin":"true"}}}' }),
]);
seq('invite-create-arguments-sibling-members-not-merged', 'duplicate arguments are not merged: the last object alone cannot borrow the earlier admin', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":"true"},"arguments":{"ttl_seconds":60}}}', model: { ttl_seconds: 60 } }),
]);

// Run every sequence against the reference verifier. The expectation is built
// from the shadow model BEFORE the step runs; the verifier decides nothing
// about it and must agree on every field.
const sequenceVectors = SEQUENCES.map(({ id, description, init: ini, steps }) => {
  const registry = ini.names.map((n) => entryOf(n));
  const invites = ini.invites ?? [];
  const state = materialize({ registry, invites });
  const shadow = shadowInit(ini);
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
    const key = s.key ?? steps[s.repeat].key; // a repeated step signs as the original key
    if (s.repeat !== undefined) {
      ({ request, signing } = built[s.repeat]);
    } else {
      const body = s.method === 'GET' ? '' : typeof s.body === 'string' ? s.body : typeof s.args === 'string' ? callRaw(s.tool, s.args) : call(s.tool, s.args);
      const r = buildRequest(`${id}#${i}`, {
        key: s.key, method: s.method, body, ts: s.ts, signKey: s.signKey, hdr: s.hdr, sign: s.sign,
      });
      request = r.req;
      signing = r.signing;
      built.push({ request, signing });
    }
    if (s.repeat !== undefined) built.push({ request, signing });
    const expect = expectStep(shadow, generated, s, key, s.want);
    const rawBefore = rawDurable(state);
    const got = verifyRequest(request, state, hooks);
    agree(`${id}#${i}`, expectOf(got, generated, { after: durableState(state, generated) }), expect);
    // Exact no-mutation for rejections, checked against raw durable data:
    // absent vs null vs false must stay distinct. Nonce-cache movement is
    // intended on post-auth rejections and is deliberately not part of this
    // check. Accepted steps legitimately mutate; they are covered by the
    // durable compare and the post-sequence reader check.
    if (got.result === 'reject' && !deepEqual(rawDurable(state), rawBefore)) {
      throw new Error(`${id}#${i}: a rejected step mutated durable state`);
    }
    return { request, expect, debug: { signing_string_lines: signing.split('\n') } };
  });
  // Producer -> serialization -> reader: the final durable state is written to
  // state-file JSON text and decoded again before the reference reader runs, so
  // a record that only breaks when written and re-read cannot pass as a live
  // object pass-through.
  const serialized = `${JSON.stringify({ version: 1, keys: state.registry.keys, invites: state.invites }, null, 2)}\n`;
  const decoded = JSON.parse(serialized);
  const reader = validateStateFile(decoded);
  if (reader !== null) throw new Error(`${id}: persisted state fails the state-file reader: ${reader}`);
  if (id === 'invite-create-ok') {
    const created = decoded.invites.find((r) => generated.has(r.invite_id));
    if (!created || 'key_ttl_seconds' in created) throw new Error('invite-create-ok: default invite must persist without key_ttl_seconds');
  }
  return {
    id, description,
    state: { now: NOW, window_seconds: WINDOW, aud: AUD, registry, invites, nonce_cache: [] },
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

// ---- load-time validation vectors (registry and state-file documents) ----
const regWith = (mutate) => {
  const doc = clone({ version: 1, aud: AUD, keys: [entryOf('alice'), entryOf('bob')] });
  mutate(doc);
  return doc;
};
const REGISTRY_CASES = [
  ['valid-admin-omitted', registryJson, null],
  ['valid-admin-false', regWith((d) => { d.keys[0].admin = false; }), null],
  ['valid-admin-true', regWith((d) => { d.keys[0].admin = true; }), null],
  ['invalid-admin-number', regWith((d) => { d.keys[0].admin = 1; }), 'admin must be a strict boolean'],
  ['invalid-admin-string', regWith((d) => { d.keys[0].admin = 'true'; }), 'admin must be a strict boolean'],
  ['invalid-admin-null', regWith((d) => { d.keys[0].admin = null; }), 'admin must be a strict boolean'],
  ['invalid-legacy-kind', regWith((d) => { d.keys[0].kind = 'agent'; }), 'legacy field kind'],
  ['invalid-legacy-scopes', regWith((d) => { d.keys[0].scopes = ['read']; }), 'legacy field scopes'],
  ['invalid-unknown-entry-field', regWith((d) => { d.keys[0].comment = 'x'; }), 'unknown field: comment'],
  ['invalid-unknown-document-field', regWith((d) => { d.comment = 'x'; }), 'unknown field: comment'],
  ['invalid-version', regWith((d) => { d.version = 2; }), 'document'],
  ['invalid-duplicate-kid', regWith((d) => { d.keys[1] = { ...d.keys[0], name: 'other' }; }), 'duplicate_kid'],
  ['invalid-duplicate-name', regWith((d) => { d.keys[1].name = 'alice'; }), 'duplicate_name'],
  ['invalid-bad-name', regWith((d) => { d.keys[0].name = 'bad name'; }), 'name'],
  ['invalid-kid-mismatch', regWith((d) => { d.keys[0].kid = K.bob.kid; }), 'kid_mismatch'],
  ['invalid-small-order-key', regWith((d) => { d.keys[0].public_key = b64u(IDENTITY); d.keys[0].kid = kidOf(IDENTITY); }), 'public_key'],
  ['invalid-mixed-order-key', regWith((d) => { d.keys[0].public_key = b64u(MIXED_ORDER); d.keys[0].kid = kidOf(MIXED_ORDER); }), 'public_key'],
  ['invalid-validity-order', regWith((d) => { d.keys[0].not_before = NOW + 10; d.keys[0].not_after = NOW; }), 'validity'],
  ['invalid-negative-not-before', regWith((d) => { d.keys[0].not_before = -1; }), 'validity'],
].map(([id, document, reason]) => {
  const got = validateRegistry(document);
  if (got !== reason) throw new Error(`registry ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

const stateWith = (mutate) => {
  const doc = {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('i')), created_by: K.root.kid, created_at: 100, expires_at: 200 }],
  };
  mutate(doc);
  return doc;
};
const STATE_FILE_CASES = [
  ['statefile-valid-empty', { version: 1, keys: [], invites: [] }, null],
  ['statefile-valid-entry-and-invite', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('i')), admin: false, created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: 3600 }],
  }, null],
  ['statefile-valid-default-invite', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('d')), created_by: K.root.kid, created_at: 100, expires_at: 200 }],
  }, null],
  ['statefile-valid-invite-ttl-min', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('l')), created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: 1 }],
  }, null],
  ['statefile-valid-invite-ttl-max', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('m')), created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: 31536000 }],
  }, null],
  ['statefile-invalid-legacy-kind-entry', stateWith((d) => { d.keys[0].kind = 'human'; }), 'legacy field kind'],
  ['statefile-invalid-legacy-scopes-entry', stateWith((d) => { d.keys[0].scopes = ['read']; }), 'legacy field scopes'],
  ['statefile-invalid-legacy-kind-invite', stateWith((d) => { d.invites[0].kind = 'human'; }), 'legacy field kind'],
  ['statefile-invalid-unknown-document-field', stateWith((d) => { d.comment = 'x'; }), 'unknown field: comment'],
  ['statefile-invalid-unknown-invite-field', stateWith((d) => { d.invites[0].note = 'x'; }), 'unknown field: note'],
  ['statefile-invalid-version', stateWith((d) => { d.version = 2; }), 'document'],
  ['statefile-invalid-duplicate-kid', stateWith((d) => { d.keys.push({ ...d.keys[0], name: 'other' }); }), 'duplicate_kid'],
  ['statefile-invalid-duplicate-invite-id', stateWith((d) => { d.invites.push({ ...d.invites[0], created_at: 150 }); }), 'duplicate_invite_id'],
  ['statefile-invalid-admin-string', stateWith((d) => { d.keys[0].admin = 'true'; }), 'admin must be a strict boolean'],
  ['statefile-invalid-invite-times', stateWith((d) => { d.invites[0].created_at = 300; }), 'expires_at'],
  ['statefile-invalid-invite-ttl-null', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('d')), created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: null }],
  }, 'key_ttl_seconds'],
  ['statefile-invalid-invite-ttl-zero', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('d')), created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: 0 }],
  }, 'key_ttl_seconds'],
  ['statefile-invalid-invite-ttl-above-max', {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('d')), created_by: K.root.kid, created_at: 100, expires_at: 200, key_ttl_seconds: 31536001 }],
  }, 'key_ttl_seconds'],
].map(([id, document, reason]) => {
  const got = validateStateFile(document);
  if (got !== reason) throw new Error(`state file ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

// ---- response cases ----
const base = buildRequest('accept-read-status', { body: STATUS });
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
const ids = [
  ...requestVectors, ...sequenceVectors, ...responseVectors, ...keyVectors,
  ...REGISTRY_CASES, ...STATE_FILE_CASES,
].map((v) => v.id);
const dup = ids.find((x, i) => ids.indexOf(x) !== i);
if (dup) throw new Error(`duplicate case id: ${dup}`);

const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const row = (cells) => `| ${cells.join(' | ')} |`;
const outcome = (e) => (e.result === 'accept' ? 'accept' : `${e.http_status} \`${e.code}\``);
const loadOutcome = (v) => (v.reason ? `invalid (${v.reason})` : 'valid');
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
  `## Response verification (\`fixtures/response-vectors.json\`, ${responseVectors.length} cases)`,
  '',
  row(['id', 'description', 'expected']),
  row(['---', '---', '---']),
  ...responseVectors.map((v) => row([`\`${v.id}\``, v.description, v.expect.result === 'accept' ? 'accept' : `reject \`${v.expect.code}\``])),
  '',
  `## Public-key validity (\`fixtures/key-vectors.json\`, ${keyVectors.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...keyVectors.map((v) => row([`\`${v.id}\``, v.expect])),
  '',
  `## Registry documents (\`fixtures/load-vectors.json\`, ${REGISTRY_CASES.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...REGISTRY_CASES.map((v) => row([`\`${v.id}\``, loadOutcome(v)])),
  '',
  `## State files (\`fixtures/state-file-vectors.json\`, ${STATE_FILE_CASES.length} cases)`,
  '',
  row(['id', 'expected']),
  row(['---', '---']),
  ...STATE_FILE_CASES.map((v) => row([`\`${v.id}\``, loadOutcome(v)])),
  '',
].join('\n');

const OUT = {
  'fixtures/keys.json': json(keysJson),
  'fixtures/registry.json': json(registryJson),
  'fixtures/request-vectors.json': json({ registry: 'registry.json', cases: requestVectors }),
  'fixtures/admin-vectors.json': json({ cases: sequenceVectors }),
  'fixtures/response-vectors.json': json({ cases: responseVectors }),
  'fixtures/key-vectors.json': json({ cases: keyVectors }),
  'fixtures/load-vectors.json': json({ registries: REGISTRY_CASES }),
  'fixtures/state-file-vectors.json': json({ cases: STATE_FILE_CASES }),
  'tests/CASES.md': casesMd,
};

if (process.argv.includes('--check')) {
  const stale = Object.entries(OUT).filter(([p, c]) => !existsSync(join(ROOT, p)) || readFileSync(join(ROOT, p), 'utf8') !== c);
  if (stale.length) {
    console.error(`stale: ${stale.map(([p]) => p).join(', ')}`);
    process.exit(1);
  }
  console.log(`ok: ${requestVectors.length} request, ${sequenceVectors.length} sequence, ${responseVectors.length} response, ${keyVectors.length} key, ${REGISTRY_CASES.length} registry, ${STATE_FILE_CASES.length} state-file cases, fixtures up to date`);
} else {
  for (const [p, c] of Object.entries(OUT)) writeFileSync(join(ROOT, p), c);
  console.log(`wrote ${Object.keys(OUT).length} files: ${requestVectors.length} request, ${sequenceVectors.length} sequence, ${responseVectors.length} response, ${keyVectors.length} key, ${REGISTRY_CASES.length} registry, ${STATE_FILE_CASES.length} state-file cases`);
}
