import { base64url, keyId, publicFromSeed, sha256, signSeed, strictBase64url, testSeed, verifyNode } from './crypto.mjs';
import { verifyChain, MAX_ORDINAL } from './rotation-codec.mjs';
import { parseStrictJson, parsedNumberIsIntegerLiteral } from './strict-json.mjs';

const ascii = (text) => Buffer.from(text, 'ascii');
const utf8 = (text) => Buffer.from(text, 'utf8');
const u16 = (number) => Buffer.from([(number >>> 8) & 255, number & 255]);
const requestSigningBytes = (request) => Buffer.from([
  'mcp-jack/v1/request', request.method, request.target, request.aud, request.kid,
  String(request.ts), request.nonce, base64url(sha256(Buffer.from(request.body))),
].join('\n'), 'utf8');
const responseSigningBytes = (response) => Buffer.from([
  'mcp-jack/v1/response', String(response.status), response.requestSig, response.kid,
  String(response.ts), base64url(sha256(Buffer.from(response.body))),
].join('\n'), 'utf8');

export const durableIntentIdentity = ({ deploymentId, kidRaw, nonceRaw, signatureRaw, signingBytes, operationId }) => {
  const deployment = utf8(deploymentId);
  const kid = Buffer.from(kidRaw);
  const nonce = Buffer.from(nonceRaw);
  const signature = Buffer.from(signatureRaw);
  const operation = Buffer.from(operationId);
  if (deployment.length < 1 || deployment.length > 1024 || kid.length !== 32 || nonce.length !== 16 || signature.length !== 64 || operation.length !== 16) throw new TypeError('invalid operation identity fields');
  return base64url(sha256(Buffer.concat([ascii('mcp-jack/durable-nonce/intent/v1\n'), u16(deployment.length), deployment, kid, nonce, signature, sha256(Buffer.from(signingBytes)), operation])));
};

export const verifyRequestSignature = ({ request, publicKey }) => {
  const signature = strictBase64url(request.signature, 64);
  const kidRaw = strictBase64url(request.kid, 32);
  const nonceRaw = strictBase64url(request.nonce, 16);
  if (!signature || !kidRaw || !nonceRaw || keyId(publicKey) !== request.kid) return { ok: false, reason: 'malformed_or_unknown_key' };
  const bytes = requestSigningBytes(request);
  if (!verifyNode(publicKey, bytes, signature)) return { ok: false, reason: 'bad_signature' };
  return { ok: true, signingBytes: bytes, signatureRaw: signature, kidRaw, nonceRaw };
};

export const verifyResponseSignature = ({ response, publicKey }) => {
  const signature = strictBase64url(response.signature, 64);
  if (!signature || !strictBase64url(response.kid, 32) || keyId(publicKey) !== response.kid) return { ok: false, reason: 'unknown_or_malformed_server_key' };
  return verifyNode(publicKey, responseSigningBytes(response), signature) ? { ok: true } : { ok: false, reason: 'bad_signature' };
};

const plain = (node) => {
  if (Array.isArray(node)) return node.map(plain);
  if (node && typeof node === 'object' && Object.hasOwn(node, 'raw') && Object.hasOwn(node, 'value')) return node.value;
  if (node && typeof node === 'object') return Object.fromEntries(Object.entries(node).map(([key, value]) => [key, plain(value)]));
  return node;
};
const fieldsAre = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sameStructure = (a, b) => {
  const normalize = (value) => Array.isArray(value) ? value.map(normalize)
    : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalize(value[key])]))
      : value;
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
};

export const parseRefreshArguments = (raw) => {
  let parsed;
  try { parsed = parseStrictJson(raw).value; } catch { return { ok: false, status: 400, code: 'invalid_params' }; }
  if (!fieldsAre(parsed, ['after_ordinal', 'after_hash']) || !parsedNumberIsIntegerLiteral(parsed.after_ordinal)) return { ok: false, status: 400, code: 'invalid_params' };
  const ordinal = parsed.after_ordinal.value;
  const hash = parsed.after_hash;
  if (ordinal < 0 || ordinal > MAX_ORDINAL || typeof hash !== 'string' || (ordinal === 0 ? hash !== '-' : !strictBase64url(hash, 32))) return { ok: false, status: 400, code: 'invalid_params' };
  return { ok: true, value: { after_ordinal: ordinal, after_hash: hash } };
};

export const parseRefreshEnvelope = (value, text) => {
  let mirror;
  try {
    const parsedMirror = parseStrictJson(text).value;
    const ordinal = value?.head?.ordinal;
    const actualLexeme = Number.isSafeInteger(ordinal) ? String(ordinal)
      : parsedNumberIsIntegerLiteral(ordinal) ? ordinal.raw : null;
    if (actualLexeme === null || !parsedNumberIsIntegerLiteral(parsedMirror?.head?.ordinal)
      || actualLexeme !== parsedMirror.head.ordinal.raw) return { ok: false, error: 'rotation_result_invalid' };
    mirror = plain(parsedMirror);
  } catch { return { ok: false, error: 'rotation_result_invalid' }; }
  const actual = plain(value);
  if (!fieldsAre(actual, ['current', 'records', 'head', 'complete']) || !fieldsAre(mirror, ['current', 'records', 'head', 'complete'])) return { ok: false, error: 'rotation_result_invalid' };
  if (!fieldsAre(actual.current, ['kid', 'public_key']) || typeof actual.current.kid !== 'string' || typeof actual.current.public_key !== 'string') return { ok: false, error: 'rotation_result_invalid' };
  if (!fieldsAre(actual.head, ['ordinal', 'hash']) || !Number.isSafeInteger(actual.head.ordinal) || actual.head.ordinal < 0 || typeof actual.head.hash !== 'string') return { ok: false, error: 'rotation_result_invalid' };
  if (!Array.isArray(actual.records) || actual.records.length > 16 || !actual.records.every((record) => typeof record === 'string') || typeof actual.complete !== 'boolean') return { ok: false, error: 'rotation_result_invalid' };
  if (!sameStructure(actual, mirror)) return { ok: false, error: 'rotation_result_invalid' };
  if (actual.head.ordinal === 0 ? actual.head.hash !== '-' : !strictBase64url(actual.head.hash, 32)) return { ok: false, error: 'rotation_result_invalid' };
  return { ok: true, value: actual };
};

export const parseCandidateResponseBody = (response, expectedId) => {
  let parsed;
  let raw;
  try {
    raw = parseStrictJson(response.body).value;
    parsed = plain(raw);
  } catch { return { ok: false, error: 'rotation_result_invalid' }; }
  if (!fieldsAre(parsed, ['jsonrpc', 'id', 'result']) || parsed.jsonrpc !== '2.0' || parsed.id !== expectedId) return { ok: false, error: 'rotation_result_invalid' };
  if (!fieldsAre(parsed.result, ['content', 'structuredContent', 'isError']) || parsed.result.isError !== false) return { ok: false, error: 'rotation_result_invalid' };
  const content = parsed.result.content;
  if (!Array.isArray(content) || content.length !== 1 || !fieldsAre(content[0], ['type', 'text']) || content[0].type !== 'text' || typeof content[0].text !== 'string') return { ok: false, error: 'rotation_result_invalid' };
  return parseRefreshEnvelope(raw.result.structuredContent, content[0].text);
};

const keyOrdinalFor = (state, kid) => state.ordinalByKid.get(kid);
const intervalAllows = (state, ordinal, ts, finalNow) => {
  const lower = ordinal === 0 ? undefined : state.records[ordinal - 1]?.activatesAt;
  const cutoff = state.records[ordinal]?.activatesAt;
  return (ordinal === 0 || (lower !== undefined && ts >= lower)) && (cutoff === undefined || (ts < cutoff && finalNow < cutoff));
};

const outerTimeValid = (state, response, key, finalNow) => {
  const ordinal = state.ordinalByKid.get(response.kid);
  if (ordinal === undefined) return false;
  const lower = ordinal === 0 ? undefined : state.records[ordinal - 1]?.activatesAt;
  const cutoff = state.records[ordinal]?.activatesAt;
  return Number.isSafeInteger(finalNow)
    && Math.abs(finalNow - response.ts) <= state.window
    && (ordinal === 0 || (lower !== undefined && response.ts >= lower))
    && (cutoff === undefined || (response.ts < cutoff && finalNow < cutoff));
};

export const validateRefreshPreResponse = ({ state, response, expectedId, cursor, textMirror, finalNow = response.now, checkClock }) => {
  const carrierOrdinal = keyOrdinalFor(state, response.kid);
  const publicKey = state.keys.get(response.kid);
  if (!publicKey || keyId(publicKey) !== response.kid) return { ok: false, error: 'unknown_server_key' };
  if (!Number.isSafeInteger(response.now) || !Number.isSafeInteger(response.ts) || Math.abs(response.now - response.ts) > state.window) return { ok: false, error: 'timestamp_out_of_window' };
  if (!verifyResponseSignature({ response, publicKey }).ok) return { ok: false, error: 'bad_signature' };
  if (!outerTimeValid(state, response, publicKey, finalNow)) return { ok: false, error: 'rotation_key_interval' };
  const clockError = checkClock?.(response.now);
  if (clockError) return { ok: false, error: clockError };
  const parsed = parseCandidateResponseBody(response, expectedId);
  if (!parsed.ok) return parsed;
  if (textMirror !== undefined && !parseRefreshEnvelope(parsed.value, textMirror).ok) return { ok: false, error: 'rotation_result_invalid' };
  const envelope = parsed.value;
  if (envelope.current.kid !== response.kid || envelope.current.public_key !== base64url(publicKey)) return { ok: false, error: 'rotation_result_invalid' };
  if (envelope.head.ordinal === 0 ? envelope.head.hash !== '-' : !strictBase64url(envelope.head.hash, 32)) return { ok: false, error: 'rotation_result_invalid' };
  if (envelope.head.ordinal < cursor.ordinal) return { ok: false, error: 'rotation_gap' };
  if (cursor.ordinal !== state.ackOrdinal || cursor.hash !== state.ackHash) return { ok: false, error: 'rotation_gap' };
  const cursorRecord = cursor.ordinal === 0 ? null : state.recordByOrdinal.get(cursor.ordinal);
  if (cursor.ordinal > 0 && !cursorRecord) return { ok: false, error: 'rotation_gap' };

  const recordLines = envelope.records.map((record) => record.split('\n'));
  const firstOrdinal = recordLines.length ? Number(recordLines[0][3]) : null;
  const hasDuplicatePrefix = cursor.ordinal > 0 && firstOrdinal !== null && firstOrdinal <= cursor.ordinal;
  const startAtAnchor = hasDuplicatePrefix;
  const chainKeys = startAtAnchor
    ? new Map([[state.anchorKid, Buffer.from(state.anchorPublicKey)]])
    : new Map(state.keys);
  const parsedChain = verifyChain(envelope.records.map((record) => Buffer.from(record, 'utf8')), {
    endpoint: state.endpoint,
    aud: state.aud,
    anchorKid: state.anchorKid,
    anchorPublicKey: state.anchorPublicKey,
    initialOrdinal: startAtAnchor ? 0 : cursor.ordinal,
    initialHash: startAtAnchor ? '-' : cursor.hash,
    previousKid: startAtAnchor || cursor.ordinal === 0 ? null : cursorRecord.newKid,
    knownKeys: chainKeys,
    priorPublishedAt: startAtAnchor || cursor.ordinal === 0 ? 0 : cursorRecord.publishedAt,
  });
  if (!parsedChain.ok) {
    if (parsedChain.code === 'key_reuse' || parsedChain.code === 'new_key_id' || parsedChain.code === 'new_key' || parsedChain.code === 'activation' || parsedChain.code.endsWith('proof') || parsedChain.code === 'old_authorization') return { ok: false, error: 'rotation_record_invalid' };
    if (parsedChain.code === 'unknown_authorizer' || parsedChain.code === 'adjacency' || parsedChain.code === 'previous_hash' || parsedChain.code === 'ordinal_sequence' || parsedChain.code === 'publication_order') return { ok: false, error: 'rotation_gap' };
    return { ok: false, error: 'rotation_record_invalid' };
  }
  if (parsedChain.records.some((record) => record.publishedAt > response.ts)) return { ok: false, error: 'rotation_record_invalid' };

  const delivered = parsedChain.records;
  let duplicatePrefix = [];
  let extension = delivered;
  if (hasDuplicatePrefix) {
    const cursorIndex = delivered.findIndex((record) => record.ordinal === cursor.ordinal);
    if (cursorIndex < 0) return { ok: false, error: 'rotation_gap' };
    duplicatePrefix = delivered.slice(0, cursorIndex + 1);
    extension = delivered.slice(cursorIndex + 1);
    for (const record of duplicatePrefix) {
      const saved = state.recordByOrdinal.get(record.ordinal);
      if (!saved || saved.hash !== record.hash || saved.wire !== record.wire) return { ok: false, error: 'rotation_conflict' };
    }
  } else {
    let expected = cursor.ordinal + 1;
    for (const record of extension) if (record.ordinal !== expected++) return { ok: false, error: 'rotation_gap' };
  }
  const terminal = delivered.length ? delivered[delivered.length - 1] : { ordinal: cursor.ordinal, hash: cursor.hash };
  if (envelope.complete) {
    if (envelope.head.ordinal !== terminal.ordinal || envelope.head.hash !== terminal.hash) return { ok: false, error: 'rotation_result_invalid' };
  } else if (envelope.head.ordinal <= terminal.ordinal) return { ok: false, error: 'rotation_result_invalid' };
  if (delivered.length === 0 && (!envelope.complete || envelope.head.ordinal !== cursor.ordinal || envelope.head.hash !== cursor.hash)) return { ok: false, error: 'rotation_gap' };
  return { ok: true, records: delivered, duplicates: duplicatePrefix, extension, head: envelope.head, complete: envelope.complete, carrierOrdinal };
};

export const signTestRequest = ({ keyName, method = 'POST', target = '/mcp', aud, kid, ts, nonce, body }) => {
  const seed = testSeed(keyName);
  const message = requestSigningBytes({ method, target, aud, kid, ts, nonce, body: Buffer.from(body) });
  return { message, signature: base64url(signSeed(seed, message)), publicKey: publicFromSeed(seed) };
};
export const signTestResponse = ({ keyName, status = 200, requestSig, kid, ts, body }) => {
  const seed = testSeed(keyName);
  const message = responseSigningBytes({ status, requestSig, kid, ts, body: Buffer.from(body) });
  return { message, signature: base64url(signSeed(seed, message)), publicKey: publicFromSeed(seed) };
};
