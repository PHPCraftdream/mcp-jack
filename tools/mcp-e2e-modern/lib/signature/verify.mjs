import { createHash, createPublicKey, verify } from 'node:crypto';

const token = /^[A-Za-z0-9_-]+$/;
const decode = (value) => Buffer.from(value, 'base64url');

export function verifyResponseSignature({ jackAuthHeader, status, requestSig, body, serverPublicKeyBase64Url } = {}) {
  if (typeof jackAuthHeader !== 'string') return { ok: false, reason: 'missing_auth' };
  if (typeof jackAuthHeader !== 'string' || !/^v1 /.test(jackAuthHeader)) return { ok: false, reason: 'malformed_auth' };
  const params = jackAuthHeader.slice(3).split(',');
  const values = new Map();
  for (const param of params) {
    const match = /^(kid|ts|sig)=([A-Za-z0-9_-]+)$/.exec(param);
    if (!match || values.has(match[1])) return { ok: false, reason: 'malformed_auth' };
    values.set(match[1], match[2]);
  }
  if (values.size !== 3 || !['kid', 'ts', 'sig'].every((key) => values.has(key))) return { ok: false, reason: 'malformed_auth' };
  if (typeof requestSig !== 'string' || !token.test(requestSig)) return { ok: false, reason: 'missing_request_sig' };
  if (!Number.isInteger(status) || typeof body !== 'string' || typeof serverPublicKeyBase64Url !== 'string' || !token.test(serverPublicKeyBase64Url)) return { ok: false, reason: 'malformed_evidence' };
  try {
    const keyBytes = decode(serverPublicKeyBase64Url);
    if (keyBytes.length !== 32) return { ok: false, reason: 'malformed_public_key' };
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), keyBytes]);
    const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    // Hashes the captured bounded, re-encoded body; timestamp freshness is not checked.
    const bodyHash = createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64url');
    const signingString = ['mcp-jack/v1/response', String(status), requestSig, values.get('kid'), values.get('ts'), bodyHash].join('\n');
    return verify(null, Buffer.from(signingString), publicKey, decode(values.get('sig')))
      ? { ok: true, reason: 'verified' }
      : { ok: false, reason: 'bad_signature' };
  } catch {
    return { ok: false, reason: 'malformed_auth' };
  }
}
