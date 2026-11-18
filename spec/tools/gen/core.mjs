import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b64u, sha256, kidOf, requestSigningString, rotateProofString, validatePublicKey, malleateSignature, forgeSmallOrderRSig } from '../reference-verifier.mjs';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const NOW = 1767225600; // 2026-01-01T00:00:00Z
export const WINDOW = 30;
export const AUD = 'https://svc.example.test';
export const AUD2 = 'https://other.example.test';
export const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
export const clone = (v) => JSON.parse(JSON.stringify(v));

// ---- keys (TEST ONLY: seeds are derived from public strings) ----
// The scope reduction removed scopes and kinds: one strict boolean `admin` per
// entry gates only `jack.admin.*` (spec 02 section 1). Only root is an
// administrator in the std registry; every other entry omits the flag, which
// is the default-false discriminator.
export const KEY_DEFS = {
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
export const K = {};
for (const name of Object.keys(KEY_DEFS)) {
  const seed = sha256(`mcp-jack test key: ${name}`);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  if (validatePublicKey(pub)) throw new Error(`test key ${name} failed validation`);
  K[name] = { name, seed, priv, pub, public_key: b64u(pub), kid: kidOf(pub) };
}

// Documents may omit admin (default false), so the entry carries it only when true.
export const entryOf = (name, over = {}) => {
  const d = KEY_DEFS[name] ?? {};
  return {
    kid: K[name].kid, public_key: K[name].public_key, name,
    ...(d.admin === true ? { admin: true } : {}),
    ...(d.not_before !== undefined ? { not_before: d.not_before } : {}),
    ...(d.not_after !== undefined ? { not_after: d.not_after } : {}),
    ...over,
  };
};
export const STD_NAMES = Object.keys(KEY_DEFS).filter((n) => KEY_DEFS[n]?.std);

export const keysJson = {
  note: 'TEST ONLY. Seeds are sha256("mcp-jack test key: <name>"). Never use these keys outside tests.',
  keys: Object.values(K).map((k) => ({
    name: k.name, seed_hex: k.seed.toString('hex'), public_key: k.public_key, kid: k.kid,
  })),
};
export const registryJson = { version: 1, aud: AUD, keys: STD_NAMES.map((n) => entryOf(n)) };

// ---- builders ----
export const nonceOf = (label) => b64u(sha256(`nonce:${label}`).subarray(0, 16));
export const sigOf = (name, msg) => b64u(sign(null, Buffer.from(msg, 'utf8'), K[name].priv));
export const call = (name, args) => JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, ...(args === undefined ? {} : { arguments: args }) } });
export const rpc = (method) => JSON.stringify({ jsonrpc: '2.0', id: 1, method });
// tools/call with raw JSON text for params.arguments, so a case can send
// number literals JSON.stringify cannot express (1.0, 1e3, -0).
export const callRaw = (name, argsText) => `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${argsText}}}`;
// arguments with one member replaced by raw JSON text
export const rawArg = (args, key, literal) =>
  JSON.stringify({ ...args, [key]: `@@${key}@@` }).replace(JSON.stringify(`@@${key}@@`), literal);
export const codeOf = (label) => b64u(sha256(`seeded invite ${label}`));
export const inviteIdOf = (code) => b64u(sha256(Buffer.from(code, 'base64url')));
export const rotateProof = (newName, oldName, signer = newName, ts = NOW) =>
  sigOf(signer, rotateProofString({ aud: AUD, oldKid: K[oldName].kid, newKid: K[newName].kid, ts }));

// o.sign overrides what is signed, o.send overrides what is sent, o.hdr overrides header values,
// o.mutate rewrites the final header string, o.dup adds a second header, o.noHeader omits it.
export function buildRequest(id, o = {}) {
  const {
    key = 'alice', method = 'POST', target = '/mcp', aud = AUD, ts = NOW, body = '',
    nonce = nonceOf(id), signKey = key, flipSig = false,
  } = o;
  const bodyBuf = Buffer.from(body);
  const fields = { method, target, aud, kid: K[key].kid, ts, nonce, body: bodyBuf, ...o.sign };
  const signing = requestSigningString(fields);
  let sig = sigOf(signKey, signing);
  if (o.smallR) {
    // A signature forged with R = the identity encoding: it satisfies the
    // verification equation, so only the small-order-R rule can reject it
    // (spec 01 section 2). Signed by the header key itself.
    sig = b64u(forgeSmallOrderRSig(K[key].seed, K[key].pub, Buffer.from(signing, 'utf8')));
  }
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

export const cacheOf = (items) => items.map(([key, label, retain_until]) => ({ kid: K[key].kid, nonce: nonceOf(label), retain_until }));
export const materialize = ({ registry, invites = [], nonce_cache = [] }) => ({
  now: NOW, window_seconds: WINDOW, aud: AUD, registry: { keys: clone(registry) },
  invites: clone(invites), nonce_cache: clone(nonce_cache),
});
export const byName = (a, b) => (a.name < b.name ? -1 : 1);

// Codes created by the server are random in real implementations: expectations use a placeholder.
export const PLACEHOLDER = '<b64u43>';
export function scrub(value, generated) {
  if (typeof value === 'string') return generated.has(value) ? PLACEHOLDER : value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, generated));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, generated)]));
  return value;
}

// Sorting for the full durable-state compare: scrub the id first, then compare
// [scrubbed invite_id, created_at] pairs; JS sort is stable so equal keys keep
// insertion order. Identical implementation on both sides (generator + shadow).
export const inviteOrder = (generated) => (a, b) => {
  const ia = generated.has(a.invite_id) ? PLACEHOLDER : a.invite_id;
  const ib = generated.has(b.invite_id) ? PLACEHOLDER : b.invite_id;
  return ia < ib ? -1 : ia > ib ? 1 : a.created_at - b.created_at;
};

export function expectOf(got, generated, extra = {}) {
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
export const stableStringify = (v) => {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};
export const deepEqual = (a, b) => stableStringify(a) === stableStringify(b);

// The verifier must agree with the generator's full independent expectation on
// every field, not just the outcome tuple.
export function agree(id, got, want) {
  if (!deepEqual(got, want)) {
    throw new Error(`${id}: reference verifier disagrees:\n  got:  ${stableStringify(got)}\n  want: ${stableStringify(want)}`);
  }
}

// Authentication failures happen before the nonce is recorded; every other
// rejection consumed it.
export const AUTH_FAILURES = new Set([
  'missing_auth', 'malformed_auth', 'unsupported_version', 'unknown_key', 'key_inactive',
  'timestamp_out_of_window', 'bad_signature', 'replayed_nonce',
]);
export const AUDITED_TOOLS = new Set([
  'jack.enroll', 'jack.key.rotate',
  'jack.admin.user.list', 'jack.admin.user.get', 'jack.admin.user.create', 'jack.admin.user.set_admin',
  'jack.admin.user.revoke', 'jack.admin.invite.create', 'jack.admin.invite.list', 'jack.admin.invite.revoke',
]);
export const whoamiView = (e) => ({ kid: e.kid, name: e.name, admin: e.admin === true, not_before: e.not_before ?? null, not_after: e.not_after ?? null });
export const userView = (e) => ({ kid: e.kid, public_key: e.public_key, name: e.name, admin: e.admin === true, not_before: e.not_before ?? null, not_after: e.not_after ?? null });
export const kidOfB64 = (public_key) => kidOf(Buffer.from(public_key, 'base64url'));

// Full durable state: every registry entry in full, every persisted invite
// record in full (member absent when unset, never null). A rejected step that
// corrupts a public_key or mutates an invite's admin/TTL now fails the compare.

// Independent expectation for a single-request case, built from the registry
// model (02 sections 2-3, 03 section 4).
export const JACK_TOOL_RE = /"name":"(jack\.[^"]+)"/g;
export function requestExpect(opts, [result, http_status, code]) {
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
  const tool = names[names.length - 1]; // the cases name at most one jack.* tool, or reject before it
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
  } else if (!preAuth && code !== 'invalid_request' && AUDITED_TOOLS.has(tool)) {
    // invalid_request is a body rejection: the call never reaches the tool, so no audit.
    want.audit = { tool, outcome: 'failure', code, actor_kid: caller.kid };
  }
  want.nonce_recorded = !preAuth;
  return want;
}

// ---- shadow model: the generator's own view of sequence state ----
// Each sequence advances this shadow alongside the verifier; the expectation is
// built from the shadow before running the step and must equal the verifier's
// full output, so a verifier that mutates state on rejection fails the compare.
export const shadowInit = (ini) => ({
  users: ini.names.map((n) => userView(entryOf(n))),
  invites: (ini.invites ?? []).map((r) => ({
    invite_id: r.invite_id, admin: r.admin === true, created_by: r.created_by,
    created_at: r.created_at, expires_at: r.expires_at,
    ...(r.key_ttl_seconds !== undefined ? { key_ttl_seconds: r.key_ttl_seconds } : {}),
  })),
});
export const durableShadow = (shadow, generated) => ({
  users: [...shadow.users].sort(byName).map(userView),
  invites: shadow.invites
    .map((r) => ({
      invite_id: generated.has(r.invite_id) ? PLACEHOLDER : r.invite_id,
      admin: r.admin === true, created_by: r.created_by, created_at: r.created_at, expires_at: r.expires_at,
      ...(r.key_ttl_seconds !== undefined ? { key_ttl_seconds: r.key_ttl_seconds } : {}),
    }))
    .sort(inviteOrder(generated)),
});
export const durableState = (state, generated) => ({
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
export const rawDurable = (state) => JSON.parse(JSON.stringify({ keys: state.registry.keys, invites: state.invites }));
// Raw-JSON bodies (callRaw/rawArg) carry arguments the spread model cannot read.
export const shadowArgs = (s) => (typeof s.args === 'string' ? JSON.parse(s.args) : s.model ?? s.args) ?? {};

// Applies an accepted step's effect to the shadow. Rejections never reach this.
export function shadowApply(shadow, s, kid) {
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
export function expectStep(shadow, generated, s, key, tuple) {
  const [result, http_status, code] = tuple;
  const accept = result === 'accept';
  const args = shadowArgs(s);
  // The caller is the entry named by the header kid; rotation may have moved it.
  const caller = shadow.users.find((e) => e.kid === K[key].kid);
  const kid = s.tool === 'jack.enroll' && typeof args.public_key === 'string' ? kidOfB64(args.public_key) : K[key].kid;
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
  // invalid_request is a body rejection: the call never reaches the tool, so no audit.
  if (s.tool && AUDITED_TOOLS.has(s.tool) && nonceRecorded && code !== 'invalid_request') {
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