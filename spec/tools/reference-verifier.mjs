// Reference implementation of the mcp-jack v1 verification algorithm.
// It exists to cross-check the fixtures against the spec text; it is not a product SDK.
import { createHash, createPublicKey, verify } from 'node:crypto';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const sha256 = (buf) => createHash('sha256').update(buf).digest();
export const kidOf = (publicKey) => b64u(sha256(publicKey));

// ---- Ed25519 point arithmetic, only to validate public keys (spec 03 section 2) ----
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;

function pow(base, exp, m = P) {
  let r = 1n;
  let b = mod(base, m);
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}

const inv = (a) => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const D2 = mod(2n * D);
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
const IDENTITY = { X: 0n, Y: 1n, Z: 1n, T: 0n };

const toBig = (buf) => [...buf].reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

export function fromBig(n, len) {
  const out = Buffer.alloc(len);
  for (let i = 0, v = n; i < len; i++, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
}

// Returns an extended-coordinate point, or null for non-canonical or off-curve input.
export function decodePoint(bytes) {
  if (bytes.length !== 32) return null;
  const sign = (bytes[31] >> 7) & 1;
  const y = toBig(bytes) & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const y2 = mod(y * y);
  const x2 = mod(mod(y2 - 1n) * inv(mod(D * y2 + 1n)));
  let x = pow(x2, (P + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * SQRT_M1);
  if (mod(x * x) !== x2) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(P - x);
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
}

export function addPoints(p, q) {
  const A = mod((p.Y - p.X) * (q.Y - q.X));
  const B = mod((p.Y + p.X) * (q.Y + q.X));
  const C = mod(p.T * D2 * q.T);
  const Dd = mod(2n * p.Z * q.Z);
  const E = B - A;
  const F = Dd - C;
  const G = Dd + C;
  const H = B + A;
  return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) };
}

export function mulPoint(point, k) {
  let r = IDENTITY;
  let q = point;
  for (let e = k; e > 0n; e >>= 1n) {
    if (e & 1n) r = addPoints(r, q);
    q = addPoints(q, q);
  }
  return r;
}

const isIdentity = (p) => p.X === 0n && mod(p.Y - p.Z) === 0n;

export function encodePoint(p) {
  const zi = inv(p.Z);
  const x = mod(p.X * zi);
  const out = fromBig(mod(p.Y * zi), 32);
  if (x & 1n) out[31] |= 0x80;
  return out;
}

export const BASE_POINT = decodePoint(Buffer.from('5866666666666666666666666666666666666666666666666666666666666666', 'hex'));

// A point of order 8, found as the torsion component of curve points.
export function findOrder8Point() {
  for (let y = 2n; ; y++) {
    const q = decodePoint(fromBig(y, 32));
    if (!q) continue;
    const t = mulPoint(q, L);
    if (!isIdentity(mulPoint(t, 4n))) return t;
  }
}

// Returns null when the key is acceptable, else a short reason.
export function validatePublicKey(bytes) {
  if (bytes.length !== 32) return 'length';
  const point = decodePoint(bytes);
  if (!point) return 'non_canonical_or_off_curve';
  if (isIdentity(point)) return 'identity';
  if (!isIdentity(mulPoint(point, L))) return 'not_in_prime_order_subgroup';
  return null;
}

// ---- encodings, signing strings ----
export const requestSigningString = ({ method, target, aud, kid, ts, nonce, body }) =>
  ['mcp-jack/v1/request', method, target, aud, kid, String(ts), nonce, b64u(sha256(body))].join('\n');

export const responseSigningString = ({ status, reqSig, kid, ts, body }) =>
  ['mcp-jack/v1/response', String(status), reqSig, kid, String(ts), b64u(sha256(body))].join('\n');

export const rotateProofString = ({ aud, oldKid, newKid, ts }) =>
  ['mcp-jack/v1/rotate', aud, oldKid, newKid, String(ts)].join('\n');

const REQUEST_PARAMS = ['kid', 'ts', 'nonce', 'sig'];
const RESPONSE_PARAMS = ['kid', 'ts', 'sig'];
const RAW_LEN = { kid: 32, nonce: 16, sig: 64 };

// Canonical unpadded base64url of exactly `len` bytes, else null.
export function strictB64u(s, len) {
  if (typeof s !== 'string') return null;
  const buf = Buffer.from(s, 'base64url');
  return buf.length === len && b64u(buf) === s ? buf : null;
}

export function parseAuth(values, allowed) {
  if (values.length === 0) return { code: 'missing_auth' };
  if (values.length > 1) return { code: 'malformed_auth' };
  const value = values[0];
  const sp = value.indexOf(' ');
  const scheme = sp < 0 ? value : value.slice(0, sp);
  if (scheme !== 'v1') return { code: /^v[0-9]+$/.test(scheme) ? 'unsupported_version' : 'malformed_auth' };
  if (sp < 0) return { code: 'malformed_auth' };
  const raw = {};
  for (const part of value.slice(sp + 1).split(',')) {
    const m = /^([a-z]+)=([A-Za-z0-9_-]+)$/.exec(part);
    if (!m || !allowed.includes(m[1]) || m[1] in raw) return { code: 'malformed_auth' };
    raw[m[1]] = m[2];
  }
  if (!allowed.every((k) => k in raw)) return { code: 'malformed_auth' };
  if (!/^(0|[1-9][0-9]{0,11})$/.test(raw.ts)) return { code: 'malformed_auth' };
  for (const k of ['kid', 'nonce', 'sig']) {
    if (k in raw && !strictB64u(raw[k], RAW_LEN[k])) return { code: 'malformed_auth' };
  }
  return { ...raw, ts: Number(raw.ts) };
}

// Strict verification: S must be below L (spec 01 section 2).
export function verifySig(publicKeyB64u, message, sigB64u) {
  const sig = Buffer.from(sigB64u, 'base64url');
  if (sig.length !== 64 || toBig(sig.subarray(32)) >= L) return false;
  const key = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKeyB64u, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  return verify(null, Buffer.from(message, 'utf8'), key, sig);
}

// Same signature with S replaced by S + L: it satisfies the verification equation but is non-canonical.
export const malleateSignature = (sig) =>
  Buffer.concat([sig.subarray(0, 32), fromBig(toBig(sig.subarray(32)) + L, 32)]);

const authHeaders = (headers) => headers.filter(([n]) => n.toLowerCase() === 'jack-auth').map(([, v]) => v);

// ---- policy (spec 02 section 3) ----
const globToRegExp = (pattern) =>
  new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 's');

function evaluatePolicy(policy, method, tool) {
  for (const rule of policy.rules) {
    if (!globToRegExp(rule.match.method).test(method)) continue;
    if (rule.match.tool !== undefined && !(method === 'tools/call' && globToRegExp(rule.match.tool).test(tool ?? ''))) continue;
    if (rule.effect === 'deny') return { effect: 'deny' };
    return { effect: 'allow', scope: rule.scope };
  }
  return { effect: 'deny' };
}

export const matchPattern = (pattern, input) => globToRegExp(pattern).test(input);

const hasOnly = (obj, keys) => Object.keys(obj).every((k) => keys.includes(k));
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Load-time policy validation (spec 02 section 3). Returns null when valid, else a reason.
export function validatePolicy(doc) {
  if (!isObj(doc) || !hasOnly(doc, ['version', 'rules']) || doc.version !== 1 || !Array.isArray(doc.rules)) return 'document';
  for (const rule of doc.rules) {
    if (!isObj(rule) || !hasOnly(rule, ['match', 'scope', 'effect'])) return 'unknown_field';
    if (!isObj(rule.match) || !hasOnly(rule.match, ['method', 'tool'])) return 'unknown_field';
    if (typeof rule.match.method !== 'string' || rule.match.method === '') return 'method';
    if ('tool' in rule.match && (typeof rule.match.tool !== 'string' || rule.match.tool === '')) return 'tool';
    if ('tool' in rule.match && rule.match.method !== 'tools/call') return 'tool_without_tools_call';
    const effect = rule.effect ?? 'allow';
    if (effect !== 'allow' && effect !== 'deny') return 'effect';
    if (effect === 'deny') {
      if ('scope' in rule) return 'scope_with_deny';
    } else {
      if (!('scope' in rule)) return 'missing_scope';
      if (rule.scope !== null && (typeof rule.scope !== 'string' || !SCOPE_RE.test(rule.scope))) return 'malformed_scope';
      if (rule.scope === 'admin') return 'reserved_scope';
    }
  }
  return null;
}

// Load-time registry validation (spec 02 section 1, spec 03 section 2). Returns null or a reason.
export function validateRegistry(doc) {
  if (!isObj(doc) || doc.version !== 1 || typeof doc.aud !== 'string' || !Array.isArray(doc.keys)) return 'document';
  const kids = new Set();
  const names = new Set();
  for (const e of doc.keys) {
    if (!isObj(e) || !hasOnly(e, ['kid', 'public_key', 'name', 'kind', 'scopes', 'not_before', 'not_after'])) return 'unknown_field';
    const raw = strictB64u(e.public_key, 32);
    if (!raw || validatePublicKey(raw)) return 'public_key';
    if (e.kid !== kidOf(raw)) return 'kid_mismatch';
    if (typeof e.name !== 'string' || !NAME_RE.test(e.name)) return 'name';
    if (kids.has(e.kid)) return 'duplicate_kid';
    if (names.has(e.name)) return 'duplicate_name';
    kids.add(e.kid);
    names.add(e.name);
    const kind = e.kind ?? 'human';
    if (kind !== 'human' && kind !== 'agent') return 'kind';
    if (!Array.isArray(e.scopes) || !e.scopes.every((s) => typeof s === 'string' && SCOPE_RE.test(s)) || new Set(e.scopes).size !== e.scopes.length) return 'scopes';
    if (kind === 'agent' && e.scopes.includes('admin')) return 'agent_admin';
    for (const f of ['not_before', 'not_after']) {
      if (e[f] !== undefined && e[f] !== null && (!Number.isInteger(e[f]) || e[f] < 0)) return 'validity';
    }
    if (e.not_before != null && e.not_after != null && e.not_before >= e.not_after) return 'validity';
  }
  return null;
}

// ---- body classification (spec 02 section 4) ----
function classify(body) {
  let msg;
  try {
    msg = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') return null;
  if (typeof msg.method === 'string') return { kind: 'request', msg };
  if (!('method' in msg) && 'id' in msg && ('result' in msg) !== ('error' in msg)) return { kind: 'response', msg };
  return null;
}

// ---- registry helpers ----
const isActive = (entry, now) => (entry.not_before ?? -Infinity) <= now && now < (entry.not_after ?? Infinity);
const kindOf = (entry) => entry.kind ?? 'human';

const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
const SCOPE_RE = /^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$/;

class Rej extends Error {
  constructor(http_status, code) {
    super(code);
    this.http_status = http_status;
    this.code = code;
  }
}
const bad = () => new Rej(400, 'invalid_params');

const view = (e) => ({
  kid: e.kid, public_key: e.public_key, name: e.name, kind: kindOf(e),
  scopes: e.scopes, not_before: e.not_before ?? null, not_after: e.not_after ?? null,
});

function argObject(args) {
  if (args === undefined) return {};
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw bad();
  return args;
}

function argScopes(v) {
  if (!Array.isArray(v) || !v.every((s) => typeof s === 'string' && SCOPE_RE.test(s)) || new Set(v).size !== v.length) throw bad();
  return v;
}

function argKind(v) {
  if (v === undefined) return 'human';
  if (v !== 'human' && v !== 'agent') throw bad();
  return v;
}

function argInt(v, min, max) {
  if (!Number.isInteger(v) || v < min || v > max) throw bad();
  return v;
}

function argTime(v) {
  if (v === undefined || v === null) return null;
  return argInt(v, 0, 999999999999);
}

function argKey(v) {
  if (typeof v !== 'string') throw bad();
  const raw = strictB64u(v, 32);
  if (!raw || validatePublicKey(raw)) throw new Rej(400, 'key_rejected');
  return raw;
}

// ---- protocol-native tools (spec 03) ----
const ADMIN_TOOLS = new Set([
  'jack.admin.user.list', 'jack.admin.user.get', 'jack.admin.user.create', 'jack.admin.user.set_scopes',
  'jack.admin.user.revoke', 'jack.admin.invite.create', 'jack.admin.invite.list', 'jack.admin.invite.revoke',
]);
const NATIVE_TOOLS = new Set(['jack.whoami', 'jack.key.rotate', 'jack.enroll', ...ADMIN_TOOLS]);
const AUDITED = (tool) => tool === 'jack.enroll' || tool === 'jack.key.rotate' || ADMIN_TOOLS.has(tool);

function activeAdmins(entries, now) {
  return entries.filter((e) => e.scopes.includes('admin') && isActive(e, now)).length;
}

function nativeCall(tool, rawArgs, ctx) {
  const { state, caller, kid, ts, hooks } = ctx;
  const entries = state.registry.keys;
  const heldByCaller = (s) => caller.scopes.includes(s);
  const find = (k) => entries.find((e) => e.kid === k);

  if (tool === 'jack.enroll') {
    if (caller) throw new Rej(409, 'key_exists');
    const args = argObject(rawArgs);
    if (typeof args.code !== 'string' || typeof args.name !== 'string' || !NAME_RE.test(args.name)) throw bad();
    const rawCode = strictB64u(args.code, 32);
    const inviteId = rawCode ? b64u(sha256(rawCode)) : null;
    const invite = state.invites.find((i) => i.invite_id === inviteId && state.now < i.expires_at);
    if (!invite) throw new Rej(403, 'invalid_invite');
    if (entries.some((e) => e.name === args.name)) throw new Rej(409, 'name_taken');
    const entry = {
      kid, public_key: args.public_key, name: args.name, kind: invite.kind, scopes: [...invite.scopes],
      not_before: null, not_after: invite.key_ttl_seconds ? state.now + invite.key_ttl_seconds : null,
    };
    entries.push(entry);
    state.invites.splice(state.invites.indexOf(invite), 1);
    return { kid, name: entry.name, kind: entry.kind, scopes: entry.scopes };
  }

  if (tool === 'jack.whoami') {
    argObject(rawArgs);
    const { public_key, ...rest } = view(caller);
    return rest;
  }

  if (tool === 'jack.key.rotate') {
    const args = argObject(rawArgs);
    if (typeof args.public_key !== 'string' || typeof args.proof !== 'string') throw bad();
    const raw = argKey(args.public_key);
    const newKid = kidOf(raw);
    const proofOk = strictB64u(args.proof, 64)
      && verifySig(args.public_key, rotateProofString({ aud: state.aud, oldKid: caller.kid, newKid, ts }), args.proof);
    if (!proofOk) throw new Rej(400, 'invalid_proof');
    if (find(newKid)) throw new Rej(409, 'key_exists');
    caller.kid = newKid;
    caller.public_key = args.public_key;
    return { kid: newKid };
  }

  // administration: scope check, then argument validation (spec 03 section 4)
  if (!heldByCaller('admin')) throw new Rej(403, 'insufficient_scope');
  const args = argObject(rawArgs);

  switch (tool) {
    case 'jack.admin.user.list':
      return { users: [...entries].sort((a, b) => (a.name < b.name ? -1 : 1)).map(view) };

    case 'jack.admin.user.get': {
      if (typeof args.kid !== 'string') throw bad();
      const target = find(args.kid);
      if (!target) throw new Rej(404, 'unknown_target');
      return view(target);
    }

    case 'jack.admin.user.create': {
      if (typeof args.name !== 'string' || !NAME_RE.test(args.name)) throw bad();
      const scopes = argScopes(args.scopes);
      const kind = argKind(args.kind);
      const not_before = argTime(args.not_before);
      const not_after = argTime(args.not_after);
      if (not_before !== null && not_after !== null && not_before >= not_after) throw bad();
      const raw = argKey(args.public_key);
      if (!scopes.every(heldByCaller)) throw new Rej(403, 'scope_escalation');
      if (kind === 'agent' && scopes.includes('admin')) throw new Rej(403, 'agent_admin_forbidden');
      const newKid = kidOf(raw);
      if (entries.some((e) => e.name === args.name)) throw new Rej(409, 'name_taken');
      if (find(newKid)) throw new Rej(409, 'key_exists');
      entries.push({ kid: newKid, public_key: args.public_key, name: args.name, kind, scopes, not_before, not_after });
      return { kid: newKid };
    }

    case 'jack.admin.user.set_scopes': {
      if (typeof args.kid !== 'string') throw bad();
      const scopes = argScopes(args.scopes);
      const target = find(args.kid);
      if (!target) throw new Rej(404, 'unknown_target');
      if (!scopes.filter((s) => !target.scopes.includes(s)).every(heldByCaller)) throw new Rej(403, 'scope_escalation');
      if (kindOf(target) === 'agent' && scopes.includes('admin')) throw new Rej(403, 'agent_admin_forbidden');
      if (!target.scopes.every(heldByCaller)) throw new Rej(403, 'forbidden_admin_target');
      const after = entries.map((e) => (e === target ? { ...e, scopes } : e));
      if (activeAdmins(after, state.now) < 1) throw new Rej(409, 'last_admin');
      target.scopes = scopes;
      return view(target);
    }

    case 'jack.admin.user.revoke': {
      if (typeof args.kid !== 'string') throw bad();
      const target = find(args.kid);
      if (!target) throw new Rej(404, 'unknown_target');
      if (!target.scopes.every(heldByCaller)) throw new Rej(403, 'forbidden_admin_target');
      if (activeAdmins(entries.filter((e) => e !== target), state.now) < 1) throw new Rej(409, 'last_admin');
      entries.splice(entries.indexOf(target), 1);
      return { kid: target.kid };
    }

    case 'jack.admin.invite.create': {
      const scopes = argScopes(args.scopes);
      const kind = argKind(args.kind);
      const ttl = args.ttl_seconds === undefined ? 3600 : argInt(args.ttl_seconds, 1, 604800);
      const keyTtl = args.key_ttl_seconds === undefined ? null : argInt(args.key_ttl_seconds, 1, 31536000);
      if (!scopes.every(heldByCaller)) throw new Rej(403, 'scope_escalation');
      if (kind === 'agent' && scopes.includes('admin')) throw new Rej(403, 'agent_admin_forbidden');
      const code = hooks.newCode(state);
      const invite = {
        invite_id: b64u(sha256(Buffer.from(code, 'base64url'))), scopes, kind, created_by: caller.kid,
        created_at: state.now, expires_at: state.now + ttl, key_ttl_seconds: keyTtl,
      };
      state.invites.push(invite);
      return { invite_id: invite.invite_id, code, expires_at: invite.expires_at };
    }

    case 'jack.admin.invite.list':
      return {
        invites: state.invites.filter((i) => state.now < i.expires_at).map((i) => ({
          invite_id: i.invite_id, scopes: i.scopes, kind: i.kind, created_by: i.created_by,
          created_at: i.created_at, expires_at: i.expires_at,
        })),
      };

    case 'jack.admin.invite.revoke': {
      if (typeof args.invite_id !== 'string') throw bad();
      const invite = state.invites.find((i) => i.invite_id === args.invite_id && state.now < i.expires_at);
      if (!invite) throw new Rej(404, 'unknown_target');
      state.invites.splice(state.invites.indexOf(invite), 1);
      return { invite_id: invite.invite_id };
    }

    default:
      throw new Rej(403, 'operation_denied');
  }
}

// Deterministic invite codes so the generator is reproducible; real servers use a CSPRNG.
export const defaultHooks = {
  newCode(state) {
    state.code_counter = (state.code_counter ?? 0) + 1;
    return b64u(sha256(`reference invite code ${state.code_counter}`));
  },
};

// ---- request verification (spec 01 section 4, spec 02 section 4, spec 03) ----
// req: { method, target, headers: [[name, value]], body_b64u }
// state: { now, window_seconds, aud, registry: {keys}, policy: {rules}, invites, nonce_cache }
// The state is mutated by operations that change it.
export function verifyRequest(req, state, hooks = defaultHooks) {
  const reject = (http_status, code, extra = {}) => ({ result: 'reject', http_status, code, nonce_recorded: false, ...extra });
  const p = parseAuth(authHeaders(req.headers), REQUEST_PARAMS);
  if (p.code) return reject(401, p.code);
  const body = Buffer.from(req.body_b64u, 'base64url');

  let caller = state.registry.keys.find((k) => k.kid === p.kid) ?? null;
  let verifyKey;
  if (caller) {
    if (!isActive(caller, state.now)) return reject(401, 'key_inactive');
    verifyKey = caller.public_key;
  } else {
    // Enrollment exception: the submitted key must hash to kid and be a valid key.
    const parsed = req.method === 'POST' ? classify(body) : null;
    const submitted = parsed?.kind === 'request' && parsed.msg.method === 'tools/call' && parsed.msg.params?.name === 'jack.enroll'
      ? parsed.msg.params.arguments?.public_key
      : undefined;
    if (typeof submitted !== 'string') return reject(401, 'unknown_key');
    const raw = strictB64u(submitted, 32);
    if (!raw || validatePublicKey(raw)) return reject(400, 'key_rejected');
    if (kidOf(raw) !== p.kid) return reject(401, 'unknown_key');
    verifyKey = submitted;
  }

  if (Math.abs(state.now - p.ts) > state.window_seconds) return reject(401, 'timestamp_out_of_window');

  const message = requestSigningString({
    method: req.method, target: req.target, aud: state.aud, kid: p.kid, ts: p.ts, nonce: p.nonce, body,
  });
  if (!verifySig(verifyKey, message, p.sig)) return reject(401, 'bad_signature');

  const replayed = state.nonce_cache.some(
    (e) => e.kid === p.kid && e.nonce === p.nonce && e.retain_until >= state.now,
  );
  if (replayed) return reject(401, 'replayed_nonce');
  state.nonce_cache.push({ kid: p.kid, nonce: p.nonce, retain_until: p.ts + state.window_seconds });

  // Authorization from here on: the nonce is consumed.
  const done = (o) => ({ nonce_recorded: true, ...o });
  const fail = (http_status, code, audit) => done({ result: 'reject', http_status, code, ...(audit ? { audit } : {}) });
  if (req.method === 'GET') return done({ result: 'accept', kid: p.kid });

  const parsed = classify(body);
  if (!parsed) return fail(400, 'invalid_request');
  if (parsed.kind === 'response') return done({ result: 'accept', kid: p.kid });

  const { msg } = parsed;
  let tool;
  if (msg.method === 'tools/call') {
    tool = msg.params?.name;
    if (typeof tool !== 'string') return fail(400, 'invalid_request');
  }

  if (tool !== undefined && tool.startsWith('jack.')) {
    if (!NATIVE_TOOLS.has(tool)) return fail(403, 'operation_denied');
    const audit = (outcome, code) => (AUDITED(tool) ? { tool, outcome, code, actor_kid: p.kid } : undefined);
    try {
      const structured = nativeCall(tool, msg.params.arguments, { state, caller, kid: p.kid, ts: p.ts, hooks });
      return done({ result: 'accept', kid: p.kid, structured, ...(AUDITED(tool) ? { audit: audit('success', null) } : {}) });
    } catch (e) {
      if (!(e instanceof Rej)) throw e;
      return fail(e.http_status, e.code, audit('failure', e.code));
    }
  }

  const decision = evaluatePolicy(state.policy, msg.method, tool);
  if (decision.effect === 'deny') return fail(403, 'operation_denied');
  if (decision.scope !== null && !caller.scopes.includes(decision.scope)) return fail(403, 'insufficient_scope');
  return done({ result: 'accept', kid: p.kid });
}

// res: { status, headers, body_b64u }
// state: { now, window_seconds, pinned_server_kid, pinned_server_public_key, request_sig }
export function verifyResponse(res, state) {
  const reject = (code) => ({ result: 'reject', code });
  const p = parseAuth(authHeaders(res.headers), RESPONSE_PARAMS);
  if (p.code) return reject(p.code);
  if (p.kid !== state.pinned_server_kid) return reject('unknown_server_key');
  if (Math.abs(state.now - p.ts) > state.window_seconds) return reject('timestamp_out_of_window');

  const message = responseSigningString({
    status: res.status, reqSig: state.request_sig, kid: p.kid, ts: p.ts, body: Buffer.from(res.body_b64u, 'base64url'),
  });
  return verifySig(state.pinned_server_public_key, message, p.sig) ? { result: 'accept' } : reject('bad_signature');
}
