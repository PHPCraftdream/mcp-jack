import { base64url, keyId, sha256, strictBase64url, validPublicKey, verifyNode } from './crypto.mjs';

export const DOMAIN = 'mcp-jack/server-key-rotation/min1';
export const GRACE_SECONDS = 172800;
export const MAX_ORDINAL = Number.MAX_SAFE_INTEGER;
export const MAX_TIMESTAMP = 999999999999;
export const MAX_RECORD_BYTES = 8192;
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
const utf8 = (value) => Buffer.from(value, 'utf8');
const decodeUtf8 = (bytes) => strictUtf8.decode(bytes);
const decimal = (text, max) => /^(0|[1-9][0-9]*)$/.test(text) && BigInt(text) <= BigInt(max);
const recordError = (code) => ({ ok: false, code });

const scalarText = (value) => typeof value === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
export const encodeB = ({ endpoint, aud, ordinal, previousHash, oldKid, newKid, newPublicKey, publishedAt, activatesAt, domain = DOMAIN }) => {
  if (!scalarText(endpoint) || !scalarText(aud)) throw new TypeError('endpoint and audience must be Unicode scalar strings');
  const publicText = typeof newPublicKey === 'string' ? newPublicKey : base64url(newPublicKey);
  return Buffer.from([
    domain,
    base64url(utf8(endpoint)),
    base64url(utf8(aud)),
    String(ordinal),
    previousHash,
    oldKid,
    newKid,
    publicText,
    String(publishedAt),
    String(activatesAt),
  ].join('\n'), 'ascii');
};

export const recordHash = (record) => base64url(sha256(Buffer.from(record, 'utf8')));

export const parseRecord = (wire, binding) => {
  const bytes = Buffer.from(wire);
  if (bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) return recordError('record_size');
  if (bytes.some((byte) => byte > 0x7f)) return recordError('non_ascii');
  let text;
  try { text = decodeUtf8(bytes); } catch { return recordError('utf8'); }
  if (!Buffer.from(text, 'utf8').equals(bytes)) return recordError('utf8');
  if (text.endsWith('\n')) return recordError('trailing_lf');
  const lines = text.split('\n');
  if (lines.length !== 12) return recordError('line_count');
  const [domain, endpoint64, aud64, ordinalText, previousHash, oldKid, newKid, public64, publishedText, activationText, newProof64, oldAuth64] = lines;
  if (domain !== DOMAIN) return recordError('domain');
  if (ordinalText.length > 16 || !decimal(ordinalText, MAX_ORDINAL) || ordinalText === '0') return recordError('ordinal');
  if (!decimal(publishedText, MAX_TIMESTAMP) || !decimal(activationText, MAX_TIMESTAMP)) return recordError('timestamp');
  if (!scalarText(binding.endpoint) || !scalarText(binding.aud)) return recordError('utf8');
  const endpointBytes = Buffer.byteLength(binding.endpoint, 'utf8');
  const audBytes = Buffer.byteLength(binding.aud, 'utf8');
  if (endpointBytes < 1 || endpointBytes > 2048 || audBytes < 1 || audBytes > 1024) return recordError('binding_size');
  const endpointRaw = strictBase64url(endpoint64, Buffer.from(endpoint64, 'base64url').length);
  const audRaw = strictBase64url(aud64, Buffer.from(aud64, 'base64url').length);
  if (!endpointRaw || !audRaw || endpointRaw.length < 1 || endpointRaw.length > 2048 || audRaw.length < 1 || audRaw.length > 1024) return recordError('binding_encoding');
  let endpoint;
  let aud;
  try { endpoint = decodeUtf8(endpointRaw); aud = decodeUtf8(audRaw); } catch { return recordError('utf8'); }
  if (endpoint !== binding.endpoint || aud !== binding.aud) return recordError('binding');
  if (base64url(endpointRaw) !== endpoint64 || base64url(audRaw) !== aud64) return recordError('base64url');
  const oldKidRaw = strictBase64url(oldKid, 32);
  const newKidRaw = strictBase64url(newKid, 32);
  if (!oldKidRaw || !newKidRaw) return recordError('key_id');
  if (oldKid !== base64url(oldKidRaw) || newKid !== base64url(newKidRaw)) return recordError('key_id');
  if (Number(ordinalText) > Number.MAX_SAFE_INTEGER) return recordError('ordinal');
  if (!/^[A-Za-z0-9_-]{43}$/.test(public64)) return recordError('base64url');
  const keyRaw = strictBase64url(public64, 32);
  if (!keyRaw || !validPublicKey(keyRaw)) return recordError('new_key');
  if (keyId(keyRaw) !== newKid) return recordError('new_key_id');
  const proofNew = strictBase64url(newProof64, 64);
  const proofOld = strictBase64url(oldAuth64, 64);
  if (!proofNew || !proofOld) return recordError('proof_encoding');
  const publishedAt = Number(publishedText);
  const activatesAt = Number(activationText);
  const expectedActivation = BigInt(publishedText) + BigInt(GRACE_SECONDS);
  if (expectedActivation > BigInt(MAX_TIMESTAMP) || expectedActivation !== BigInt(activationText)) return recordError('activation');
  const b = Buffer.from(lines.slice(0, 10).join('\n'), 'utf8');
  const newMessage = Buffer.concat([Buffer.from(`${DOMAIN}/next-proof\n`, 'ascii'), b]);
  const authMessage = Buffer.concat([Buffer.from(`${DOMAIN}/authorize\n`, 'ascii'), b, Buffer.from(`\n${newProof64}`, 'ascii')]);
  const authorizingPublic = binding.authorizers?.get(oldKid);
  if (!authorizingPublic || keyId(authorizingPublic) !== oldKid) return recordError('unknown_authorizer');
  if (!verifyNode(keyRaw, newMessage, proofNew)) return recordError('new_proof');
  const parsed = {
    domain, endpoint, aud, ordinal: Number(ordinalText), previousHash, oldKid, newKid,
    publicKey: keyRaw, publicKeyB64u: public64, publishedAt, activatesAt,
    proofNew, proofOld, wire: text, b,
  };
  if (!binding.authorizers || !binding.authorizers.has(oldKid)) return recordError('unknown_authorizer');
  if (!verifyNode(binding.authorizers.get(oldKid), authMessage, proofOld)) return recordError('old_authorization');
  parsed.hash = recordHash(text);
  return { ok: true, record: parsed };
};

const DEFAULT_INITIAL = Object.freeze({ ordinal: 0, hash: '-', previousKid: null, publishedAt: 0 });
export const verifyChain = (wires, options) => {
  const { endpoint, aud, anchorKid, anchorPublicKey, initialOrdinal = DEFAULT_INITIAL.ordinal, initialHash = DEFAULT_INITIAL.hash, knownKeys = new Map(), priorPublishedAt = DEFAULT_INITIAL.publishedAt, previousKid: initialPreviousKid = DEFAULT_INITIAL.previousKid, rejectReuse = true } = options;
  if (keyId(anchorPublicKey) !== anchorKid) return recordError('anchor_key_id');
  const keys = new Map(knownKeys);
  keys.set(anchorKid, Buffer.from(anchorPublicKey));
  const previousKidValue = initialPreviousKid;
  const previousHashValue = initialHash;
  let previousKid = previousKidValue;
  let previousHash = previousHashValue;
  let ordinal = initialOrdinal;
  let priorP = priorPublishedAt;
  const accepted = [];
  for (const wire of wires) {
    const authorizers = new Map(keys);
    const parsed = parseRecord(wire, { endpoint, aud, authorizers });
    if (!parsed.ok) return parsed;
    const r = parsed.record;
    if (r.ordinal !== ordinal + 1) return recordError('ordinal_sequence');
    if (r.previousHash !== previousHash || (ordinal === initialOrdinal && previousHash === '-' && r.ordinal !== 1)) return recordError('previous_hash');
    const expectedOld = previousKid ?? anchorKid;
    if (r.oldKid !== expectedOld) return recordError('adjacency');
    if (r.publishedAt < priorP) return recordError('publication_order');
    if (r.publishedAt > MAX_TIMESTAMP || r.activatesAt > MAX_TIMESTAMP) return recordError('timestamp');
    if (rejectReuse && keys.has(r.newKid)) return recordError('key_reuse');
    keys.set(r.newKid, Buffer.from(r.publicKey));
    previousKid = r.newKid;
    previousHash = r.hash;
    ordinal = r.ordinal;
    priorP = r.publishedAt;
    accepted.push(r);
  }
  return { ok: true, records: accepted, head: { ordinal, hash: previousHash }, keys };
};

export const selectedOrdinal = (records, now) => {
  let selected = 0;
  for (const record of records) if (record.activatesAt <= now) selected = record.ordinal;
  return selected;
};

export const assignmentValid = (records, ordinal, ts) => {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0) return false;
  const lower = ordinal === 0 ? 0 : records[ordinal - 1]?.activatesAt;
  const upper = records[ordinal]?.activatesAt;
  return (ordinal === 0 || (lower !== undefined && ts >= lower)) && (upper === undefined || ts < upper);
};
