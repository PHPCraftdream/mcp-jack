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

// ---- registry and state-file validation (spec 02 section 1, spec 03 sections 1 and 10) ----
const hasOnly = (obj, keys) => Object.keys(obj).every((k) => keys.includes(k));
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const unknownField = (obj, allowed) => `unknown field: ${Object.keys(obj).find((k) => !allowed.includes(k))}`;

// Per-entry validation shared by the registry and the state file. Returns null when valid, else a reason.
const ENTRY_FIELDS = ['kid', 'public_key', 'name', 'admin', 'not_before', 'not_after'];
function validateEntry(e, kids, names) {
  if (!isObj(e)) return 'document';
  // Legacy rejection: scopes, kinds and the policy engine are gone; a legacy file is never migrated (spec 03 section 10).
  if ('kind' in e) return 'legacy field kind';
  if ('scopes' in e) return 'legacy field scopes';
  if (!hasOnly(e, ENTRY_FIELDS)) return unknownField(e, ENTRY_FIELDS);
  // Strict boolean: optional in documents, always present in results (spec 02 section 1).
  if ('admin' in e && e.admin !== true && e.admin !== false) return 'admin must be a strict boolean';
  const raw = strictB64u(e.public_key, 32);
  if (!raw || validatePublicKey(raw)) return 'public_key';
  if (e.kid !== kidOf(raw)) return 'kid_mismatch';
  if (typeof e.name !== 'string' || !NAME_RE.test(e.name)) return 'name';
  if (kids.has(e.kid)) return 'duplicate_kid';
  if (names.has(e.name)) return 'duplicate_name';
  kids.add(e.kid);
  names.add(e.name);
  for (const f of ['not_before', 'not_after']) {
    if (e[f] !== undefined && e[f] !== null && (!Number.isInteger(e[f]) || e[f] < 0)) return 'validity';
  }
  if (e.not_before != null && e.not_after != null && e.not_before >= e.not_after) return 'validity';
  return null;
}

// Load-time registry validation (spec 02 section 1). Returns null when valid, else a reason.
export function validateRegistry(doc) {
  if (!isObj(doc) || doc.version !== 1 || typeof doc.aud !== 'string' || !Array.isArray(doc.keys)) return 'document';
  if (!hasOnly(doc, ['version', 'aud', 'keys'])) return unknownField(doc, ['version', 'aud', 'keys']);
  const kids = new Set();
  const names = new Set();
  for (const e of doc.keys) {
    const reason = validateEntry(e, kids, names);
    if (reason) return reason;
  }
  return null;
}

// Load-time state-file validation (spec 03 section 10). Returns null when valid, else a reason.
const INVITE_FIELDS = ['invite_id', 'admin', 'created_by', 'created_at', 'expires_at', 'key_ttl_seconds'];
export function validateStateFile(doc) {
  if (!isObj(doc) || doc.version !== 1 || !Array.isArray(doc.keys) || !Array.isArray(doc.invites)) return 'document';
  if (!hasOnly(doc, ['version', 'keys', 'invites'])) return unknownField(doc, ['version', 'keys', 'invites']);
  const kids = new Set();
  const names = new Set();
  for (const e of doc.keys) {
    const reason = validateEntry(e, kids, names);
    if (reason) return reason;
  }
  const inviteIds = new Set();
  for (const r of doc.invites) {
    if (!isObj(r)) return 'document';
    if ('kind' in r) return 'legacy field kind';
    if ('scopes' in r) return 'legacy field scopes';
    if (!hasOnly(r, INVITE_FIELDS)) return unknownField(r, INVITE_FIELDS);
    if (typeof r.invite_id !== 'string' || r.invite_id === '') return 'invite_id';
    if (typeof r.created_by !== 'string' || r.created_by === '') return 'created_by';
    if ('admin' in r && r.admin !== true && r.admin !== false) return 'admin must be a strict boolean';
    for (const f of ['created_at', 'expires_at']) {
      if (!Number.isInteger(r[f]) || r[f] < 0) return f;
    }
    if (r.created_at > r.expires_at) return 'expires_at';
    if (r.key_ttl_seconds !== undefined && (!Number.isInteger(r.key_ttl_seconds) || r.key_ttl_seconds < 1 || r.key_ttl_seconds > 31536000)) return 'key_ttl_seconds';
    if (inviteIds.has(r.invite_id)) return 'duplicate_invite_id';
    inviteIds.add(r.invite_id);
  }
  return null;
}

// ---- body classification (spec 02 section 2) ----
// Strict JSON parser that keeps each number literal's source text, because the
// integer rule of spec 03 section 3 reads the JSON text, which JSON.parse
// cannot recover. `sources` mirrors the parsed tree with one node per value; a
// number's node carries its source text in `.text`. Keys are exact member
// names, so no member name can alias another member's path.
function parseJSONRaw(src) {
  let i = 0;
  const fail = () => { throw new Error('invalid JSON'); };
  const ws = () => { while (i < src.length && ' \t\n\r'.includes(src[i])) i++; };
  const digit = (c) => c >= '0' && c <= '9';
  // An own property even for the key "__proto__", which plain assignment would turn into a prototype change.
  const member = (obj, key, value) => {
    if (key === '__proto__') Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
    else obj[key] = value;
  };
  function string() {
    i += 1; // opening quote
    let out = '';
    for (;;) {
      if (i >= src.length) fail();
      const c = src[i];
      if (c === '"') { i += 1; return out; }
      if (c === '\\') {
        const e = src[i + 1];
        i += 2;
        if (e === 'u') {
          const hex = src.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else if (e === '"') out += '"';
        else if (e === '\\') out += '\\';
        else if (e === '/') out += '/';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === 'n') out += '\n';
        else if (e === 'r') out += '\r';
        else if (e === 't') out += '\t';
        else fail();
      } else {
        if (src.charCodeAt(i) < 0x20) fail();
        out += c;
        i += 1;
      }
    }
  }
  function number(node) {
    const start = i;
    if (src[i] === '-') i += 1;
    if (src[i] === '0') i += 1;
    else if (digit(src[i])) { while (i < src.length && digit(src[i])) i += 1; }
    else fail();
    if (src[i] === '.') {
      i += 1;
      if (!digit(src[i])) fail();
      while (i < src.length && digit(src[i])) i += 1;
    }
    if (src[i] === 'e' || src[i] === 'E') {
      i += 1;
      if (src[i] === '+' || src[i] === '-') i += 1;
      if (!digit(src[i])) fail();
      while (i < src.length && digit(src[i])) i += 1;
    }
    node.text = src.slice(start, i);
    return Number(node.text);
  }
  // value(node) parses one value; `node` is its parallel sources node.
  function value(node) {
    ws();
    const c = src[i];
    if (c === '{') {
      i += 1;
      ws();
      const obj = {};
      if (src[i] === '}') { i += 1; return obj; }
      for (;;) {
        if (src[i] !== '"') fail();
        const key = string();
        ws();
        if (src[i] !== ':') fail();
        i += 1;
        const child = {};
        member(node, key, child);
        member(obj, key, value(child));
        ws();
        if (src[i] === ',') { i += 1; ws(); continue; }
        if (src[i] === '}') { i += 1; return obj; }
        fail();
      }
    }
    if (c === '[') {
      i += 1;
      ws();
      const arr = [];
      if (src[i] === ']') { i += 1; return arr; }
      for (;;) {
        const child = {};
        node[arr.length] = child;
        arr.push(value(child));
        ws();
        if (src[i] === ',') { i += 1; ws(); continue; }
        if (src[i] === ']') { i += 1; return arr; }
        fail();
      }
    }
    if (c === '"') return string();
    if (src.startsWith('true', i)) { i += 4; return true; }
    if (src.startsWith('false', i)) { i += 6; return false; }
    if (src.startsWith('null', i)) { i += 4; return null; }
    return number(node);
  }
  const root = {};
  const v = value(root);
  ws();
  if (i !== src.length) fail();
  return { value: v, sources: root };
}

function classify(body) {
  let parsed;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
    parsed = parseJSONRaw(text);
  } catch {
    return null;
  }
  const msg = parsed.value;
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') return null;
  if (typeof msg.method === 'string') return { kind: 'request', msg, sources: parsed.sources };
  if (!('method' in msg) && 'id' in msg && ('result' in msg) !== ('error' in msg)) return { kind: 'response', msg, sources: null };
  return null;
}

const isActive = (entry, now) => (entry.not_before ?? -Infinity) <= now && now < (entry.not_after ?? Infinity);

const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

// The admin flag is always read through isAdmin so a mistyped value can never be confused with false.
const isAdmin = (entry) => entry.admin === true;

class Rej extends Error {
  constructor(http_status, code) {
    super(code);
    this.http_status = http_status;
    this.code = code;
  }
}
const bad = () => new Rej(400, 'invalid_params');

// The view normalizes admin on read: documents may omit it, results never carry it missing.
const view = (e) => ({
  kid: e.kid, public_key: e.public_key, name: e.name, admin: isAdmin(e),
  not_before: e.not_before ?? null, not_after: e.not_after ?? null,
});

// Verified caller identity handed to the wrapped handler (spec 02 section 3).
const identityOf = (e) => ({ kid: e.kid, name: e.name, admin: isAdmin(e) });

function argObject(args) {
  if (args === undefined) return {};
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw bad();
  return args;
}

function argAdmin(v) {
  // Strict boolean: optional, defaults to false; anything else is invalid_params (spec 03 section 3).
  if (v === undefined) return false;
  if (v === true || v === false) return v;
  throw bad();
}

function argAdminRequired(v) {
  if (v === true || v === false) return v;
  throw bad();
}

function argInt(v, min, max, rawText) {
  // An integer only when the JSON text has no fraction and no exponent (spec 03
  // section 3); rawText is null when the value was not a JSON number.
  if (rawText === null || /[.eE]/.test(rawText) || !Number.isInteger(v) || v < min || v > max) throw bad();
  return v;
}

function argTime(v, rawText) {
  if (v === undefined || v === null) return null;
  return argInt(v, 0, 999999999999, rawText);
}

function argKey(v) {
  if (typeof v !== 'string') throw bad();
  const raw = strictB64u(v, 32);
  if (!raw || validatePublicKey(raw)) throw new Rej(400, 'key_rejected');
  return raw;
}

// ---- protocol-native tools (spec 03) ----
const ADMIN_TOOLS = new Set([
  'jack.admin.user.list', 'jack.admin.user.get', 'jack.admin.user.create', 'jack.admin.user.set_admin',
  'jack.admin.user.revoke', 'jack.admin.invite.create', 'jack.admin.invite.list', 'jack.admin.invite.revoke',
]);
const NATIVE_TOOLS = new Set(['jack.whoami', 'jack.key.rotate', 'jack.enroll', ...ADMIN_TOOLS]);
const AUDITED = (tool) => tool === 'jack.enroll' || tool === 'jack.key.rotate' || ADMIN_TOOLS.has(tool);

function activeAdmins(entries, now) {
  return entries.filter((e) => isAdmin(e) && isActive(e, now)).length;
}

// Last administrator (spec 03 section 4): an operation that would leave no active
// entry with admin true is rejected, evaluated against the registry as it would be after the change.
function leavesNoActiveAdmin(entriesAfterChange, now) {
  return activeAdmins(entriesAfterChange, now) === 0;
}

// Unknown argument members are inert: args are read by exact member name only (spec 03 section 3).
function nativeCall(tool, rawArgs, ctx) {
  const { state, caller, kid, ts, hooks, rawNumberText } = ctx;
  const entries = state.registry.keys;
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
      kid, public_key: args.public_key, name: args.name, admin: invite.admin === true,
      not_before: null, not_after: invite.key_ttl_seconds ? state.now + invite.key_ttl_seconds : null,
    };
    entries.push(entry);
    state.invites.splice(state.invites.indexOf(invite), 1);
    return { kid, name: entry.name, admin: entry.admin };
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

  // administration: the admin gate first, then argument validation (spec 03 section 4)
  if (!isAdmin(caller)) throw new Rej(403, 'admin_required');
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
      const admin = argAdmin(args.admin);
      const not_before = argTime(args.not_before, rawNumberText('not_before'));
      const not_after = argTime(args.not_after, rawNumberText('not_after'));
      if (not_before !== null && not_after !== null && not_before >= not_after) throw bad();
      const raw = argKey(args.public_key);
      const newKid = kidOf(raw);
      if (entries.some((e) => e.name === args.name)) throw new Rej(409, 'name_taken');
      if (find(newKid)) throw new Rej(409, 'key_exists');
      entries.push({ kid: newKid, public_key: args.public_key, name: args.name, admin, not_before, not_after });
      return { kid: newKid };
    }

    case 'jack.admin.user.set_admin': {
      if (typeof args.kid !== 'string') throw bad();
      const admin = argAdminRequired(args.admin);
      const target = find(args.kid);
      if (!target) throw new Rej(404, 'unknown_target');
      if (isAdmin(target) && admin === false && isActive(target, state.now)
        && leavesNoActiveAdmin(entries.filter((e) => e !== target), state.now)) throw new Rej(409, 'last_admin');
      target.admin = admin;
      return view(target);
    }

    case 'jack.admin.user.revoke': {
      if (typeof args.kid !== 'string') throw bad();
      const target = find(args.kid);
      if (!target) throw new Rej(404, 'unknown_target');
      if (isAdmin(target) && isActive(target, state.now)
        && leavesNoActiveAdmin(entries.filter((e) => e !== target), state.now)) throw new Rej(409, 'last_admin');
      entries.splice(entries.indexOf(target), 1);
      return { kid: target.kid };
    }

    case 'jack.admin.invite.create': {
      const admin = argAdmin(args.admin);
      const ttl = args.ttl_seconds === undefined ? 3600 : argInt(args.ttl_seconds, 1, 604800, rawNumberText('ttl_seconds'));
      const keyTtl = args.key_ttl_seconds === undefined ? null : argInt(args.key_ttl_seconds, 1, 31536000, rawNumberText('key_ttl_seconds'));
      const code = hooks.newCode(state);
      const invite = {
        invite_id: b64u(sha256(Buffer.from(code, 'base64url'))), admin, created_by: caller.kid,
        created_at: state.now, expires_at: state.now + ttl,
        // Present only when the invite sets a key expiry; null is never stored (spec 03 section 3.3).
        ...(keyTtl !== null ? { key_ttl_seconds: keyTtl } : {}),
      };
      state.invites.push(invite);
      return { invite_id: invite.invite_id, code, expires_at: invite.expires_at };
    }

    case 'jack.admin.invite.list':
      return {
        invites: state.invites.filter((i) => state.now < i.expires_at).map((i) => ({
          invite_id: i.invite_id, admin: i.admin === true, created_by: i.created_by,
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

// ---- request verification (spec 01 section 4, spec 02 section 2, spec 03) ----
// req: { method, target, headers: [[name, value]], body_b64u }
// state: { now, window_seconds, aud, registry: {keys}, invites, nonce_cache }
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
  if (req.method === 'GET') return done({ result: 'accept', kid: p.kid, identity: identityOf(caller) });

  const parsed = classify(body);
  if (!parsed) return fail(400, 'invalid_request');
  if (parsed.kind === 'response') return done({ result: 'accept', kid: p.kid, identity: identityOf(caller) });

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
      const rawNumberText = (key) => {
        const node = parsed.sources?.params?.arguments?.[key];
        return typeof node?.text === 'string' ? node.text : null;
      };
      const structured = nativeCall(tool, msg.params.arguments, { state, caller, kid: p.kid, ts: p.ts, hooks, rawNumberText });
      return done({ result: 'accept', kid: p.kid, structured, ...(AUDITED(tool) ? { audit: audit('success', null) } : {}) });
    } catch (e) {
      if (!(e instanceof Rej)) throw e;
      return fail(e.http_status, e.code, audit('failure', e.code));
    }
  }

  // Ordinary MCP: accepted and forwarded unchanged for any authenticated caller (spec 02 section 2).
  return done({ result: 'accept', kid: p.kid, identity: identityOf(caller) });
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
