// Reference implementation of the mcp-jack v1 verification algorithm.
// It exists to cross-check the fixtures against the spec text; it is not a product SDK.
import { createHash, createPublicKey, verify } from 'node:crypto';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const sha256 = (buf) => createHash('sha256').update(buf).digest();
export const kidOf = (publicKey) => b64u(sha256(publicKey));

// Required scope per MCP tool; tools absent here are denied.
export const TOOL_SCOPES = Object.freeze({
  'jack.status': 'read',
  'jack.logs.query': 'read',
  'jack.metrics.get': 'read',
  'jack.config.get': 'read',
  'jack.config.validate': 'read',
  'jack.config.set': 'config:write',
  'jack.reload': 'lifecycle',
  'jack.restart': 'lifecycle',
});

// MCP methods that need authentication only.
export const UNSCOPED_METHODS = new Set(['tools/list', 'ping']);

const REQUEST_PARAMS = ['kid', 'ts', 'nonce', 'sig'];
const RESPONSE_PARAMS = ['kid', 'ts', 'sig'];
const RAW_LEN = { kid: 32, nonce: 16, sig: 64 };

export const requestSigningString = ({ method, target, aud, kid, ts, nonce, body }) =>
  ['mcp-jack/v1/request', method, target, aud, kid, String(ts), nonce, b64u(sha256(body))].join('\n');

export const responseSigningString = ({ status, reqSig, kid, ts, body }) =>
  ['mcp-jack/v1/response', String(status), reqSig, kid, String(ts), b64u(sha256(body))].join('\n');

// Canonical unpadded base64url of exactly `len` bytes, else null.
function strictB64u(s, len) {
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

function verifySig(publicKeyB64u, message, sigB64u) {
  const key = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKeyB64u, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  return verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(sigB64u, 'base64url'));
}

const authHeaders = (headers) => headers.filter(([n]) => n.toLowerCase() === 'jack-auth').map(([, v]) => v);

function authorize(method, body, key) {
  const accept = { result: 'accept', kid: key.kid, nonce_recorded: true };
  const reject = (http_status, code) => ({ result: 'reject', http_status, code, nonce_recorded: true });
  if (method === 'GET') return accept;

  let msg;
  try {
    msg = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return reject(400, 'invalid_request');
  }
  const isRpc = msg && typeof msg === 'object' && !Array.isArray(msg) && msg.jsonrpc === '2.0' && typeof msg.method === 'string';
  if (!isRpc) return reject(400, 'invalid_request');

  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    if (typeof name !== 'string') return reject(400, 'invalid_request');
    if (!Object.hasOwn(TOOL_SCOPES, name)) return reject(403, 'unmapped_operation');
    return key.scopes.includes(TOOL_SCOPES[name]) ? accept : reject(403, 'insufficient_scope');
  }
  return UNSCOPED_METHODS.has(msg.method) ? accept : reject(403, 'unmapped_operation');
}

// req: { method, target, headers: [[name, value]], body_b64u }
// state: { now, window_seconds, aud, nonce_cache: [{ kid, nonce, retain_until }] }
export function verifyRequest(req, state, registry) {
  const reject = (http_status, code) => ({ result: 'reject', http_status, code, nonce_recorded: false });
  const p = parseAuth(authHeaders(req.headers), REQUEST_PARAMS);
  if (p.code) return reject(401, p.code);

  const key = registry.keys.find((k) => k.kid === p.kid);
  if (!key) return reject(401, 'unknown_key');
  if ((key.not_before ?? -Infinity) > state.now || state.now >= (key.not_after ?? Infinity)) {
    return reject(401, 'key_inactive');
  }
  if (Math.abs(state.now - p.ts) > state.window_seconds) return reject(401, 'timestamp_out_of_window');

  const body = Buffer.from(req.body_b64u, 'base64url');
  const message = requestSigningString({
    method: req.method, target: req.target, aud: state.aud, kid: p.kid, ts: p.ts, nonce: p.nonce, body,
  });
  if (!verifySig(key.public_key, message, p.sig)) return reject(401, 'bad_signature');

  const replayed = state.nonce_cache.some(
    (e) => e.kid === p.kid && e.nonce === p.nonce && e.retain_until >= state.now,
  );
  if (replayed) return reject(401, 'replayed_nonce');

  return authorize(req.method, body, key);
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
