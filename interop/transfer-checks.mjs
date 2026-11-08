import { createHash } from 'node:crypto';
import { b64u, oracleSign, oracleVerify, publicEnvelope } from './transfer-fixtures.mjs';

const SAFE_LABEL_CHARS = /[^a-zA-Z0-9 _:/=.,-]/gu;
const SIGNER_FIELDS = ['id', 'ok', 'public_key', 'kid', 'public_envelope_b64u', 'signatures_b64u'];
const CONNECTION_FIELDS = ['url', 'aud', 'server_public_key', 'server_kid'];

function safeLabel(value) {
  if (typeof value !== 'string') return 'transfer check';
  return value.slice(0, 120).replace(SAFE_LABEL_CHARS, '-').trim() || 'transfer check';
}

export class TransferCheckFailure extends Error {
  constructor(label = 'transfer check') {
    super(`transfer check failed: ${safeLabel(label)}`);
    this.name = 'TransferCheckFailure';
    this.label = safeLabel(label);
  }
}

function runCheck(label, callback) {
  try {
    return callback();
  } catch (error) {
    if (error instanceof TransferCheckFailure) throw error;
    throw new TransferCheckFailure(label);
  }
}

function requireCheck(condition, label) {
  if (!condition) throw new TransferCheckFailure(label);
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function keysExactly(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function decodeCanonical(text, label) {
  requireCheck(typeof text === 'string' && /^[A-Za-z0-9_-]*$/u.test(text), label);
  const bytes = Buffer.from(text, 'base64url');
  requireCheck(bytes.toString('base64url') === text, label);
  return bytes;
}

function asBytes(value, label) {
  const raw = value && typeof value === 'object' && !Buffer.isBuffer(value) && Object.hasOwn(value, 'bytes')
    ? value.bytes
    : value;
  requireCheck(Buffer.isBuffer(raw) || raw instanceof Uint8Array, label);
  return Buffer.from(raw);
}

function expectedKid(publicBytes) {
  return createHash('sha256').update(publicBytes).digest('base64url');
}

function checkIdentity(result, key, label) {
  const publicBytes = decodeCanonical(result.public_key, label);
  requireCheck(publicBytes.length === 32, label);
  const kid = expectedKid(publicBytes);
  requireCheck(result.kid === kid, label);
  if (key != null) {
    requireCheck(result.public_key === key.public_key && result.kid === key.kid, label);
  }
  return publicBytes;
}

function exactConnection(connection, expected, label) {
  requireCheck(keysExactly(connection, CONNECTION_FIELDS), label);
  for (const field of CONNECTION_FIELDS) requireCheck(connection[field] === expected[field], label);
}

export function checkSignerResult(result, key, messages, label, expected = undefined) {
  return runCheck(label, () => {
    requireCheck(isRecord(result) && result.ok === true, label);
    const fields = expected === undefined ? SIGNER_FIELDS : [...SIGNER_FIELDS, 'connection'];
    requireCheck(keysExactly(result, fields), label);

    const publicBytes = checkIdentity(result, key, label);
    const envelopeBytes = decodeCanonical(result.public_envelope_b64u, label);
    const expectedEnvelope = Buffer.from(publicEnvelope(result.kid, result.public_key), 'utf8');
    requireCheck(envelopeBytes.equals(expectedEnvelope), label);

    requireCheck(Array.isArray(messages) && messages.length === 5, label);
    requireCheck(Array.isArray(result.signatures_b64u) && result.signatures_b64u.length === messages.length, label);
    const signatures = result.signatures_b64u.map((signature) => decodeCanonical(signature, label));
    const messageBytes = messages.map((message) => asBytes(message, label));
    for (let index = 0; index < signatures.length; index += 1) {
      requireCheck(signatures[index].length === 64, label);
      requireCheck(oracleVerify(publicBytes, messageBytes[index], signatures[index]), label);
      if (key != null && key.seed_hex !== undefined) {
        requireCheck(typeof key.seed_hex === 'string' && /^[0-9a-f]{64}$/iu.test(key.seed_hex), label);
        const seed = Buffer.from(key.seed_hex, 'hex');
        requireCheck(oracleSign(seed, messageBytes[index]).equals(signatures[index]), label);
      }
    }

    if (expected === undefined) requireCheck(!Object.hasOwn(result, 'connection'), label);
    else exactConnection(result.connection, expected, label);
    return result;
  });
}

export function checkIssueResult(result, fixture, label) {
  return runCheck(label, () => {
    requireCheck(keysExactly(result, ['id', 'ok', 'credential_b64u', 'public_key', 'kid', 'export_fresh']), label);
    requireCheck(result.ok === true && result.export_fresh === true, label);
    requireCheck(isRecord(fixture) && isRecord(fixture.key) && Buffer.isBuffer(fixture.bytes), label);
    requireCheck(result.public_key === fixture.key.public_key && result.kid === fixture.key.kid, label);
    const credential = decodeCanonical(result.credential_b64u, label);
    requireCheck(credential.equals(fixture.bytes), label);
    return result;
  });
}

export function checkPublicResult(result, key, verdicts, label) {
  return runCheck(label, () => {
    requireCheck(keysExactly(result, ['id', 'ok', 'public_key', 'kid', 'public_only', 'verification_results']), label);
    requireCheck(result.ok === true && result.public_only === true, label);
    requireCheck(isRecord(key), label);
    const publicBytes = decodeCanonical(result.public_key, label);
    requireCheck(publicBytes.length === 32 && result.kid === expectedKid(publicBytes), label);
    requireCheck(result.public_key === key.public_key && result.kid === key.kid, label);
    requireCheck(Array.isArray(verdicts) && Array.isArray(result.verification_results), label);
    requireCheck(result.verification_results.length === verdicts.length, label);
    for (let index = 0; index < verdicts.length; index += 1) {
      requireCheck(typeof verdicts[index] === 'boolean' && result.verification_results[index] === verdicts[index], label);
    }
    return result;
  });
}

export function checkErrorResult(result, expectedClass, label) {
  return runCheck(label, () => {
    requireCheck(keysExactly(result, ['id', 'ok', 'class']), label);
    requireCheck(typeof result.id === 'string' && result.ok === false && result.class === expectedClass, label);
    return result;
  });
}

export function mutationFromBaseline(actual, baseline, negative, label) {
  return runCheck(label, () => {
    requireCheck(Buffer.isBuffer(actual) && Buffer.isBuffer(baseline) && Buffer.isBuffer(negative), label);
    requireCheck(actual.equals(baseline), label);

    let prefix = 0;
    const commonLimit = Math.min(baseline.length, negative.length);
    while (prefix < commonLimit && baseline[prefix] === negative[prefix]) prefix += 1;

    let suffix = 0;
    while (suffix < baseline.length - prefix && suffix < negative.length - prefix &&
        baseline[baseline.length - 1 - suffix] === negative[negative.length - 1 - suffix]) suffix += 1;

    const mutated = Buffer.concat([
      actual.subarray(0, prefix),
      negative.subarray(prefix, negative.length - suffix),
      actual.subarray(actual.length - suffix),
    ]);
    requireCheck(mutated.equals(negative), label);
    return mutated;
  });
}

export function verificationControls(signerResult, messages, wrongSeed) {
  return runCheck('verification controls', () => {
    requireCheck(isRecord(signerResult) && Array.isArray(messages) && messages.length === 5, 'verification controls');
    const publicBytes = decodeCanonical(signerResult.public_key, 'verification controls');
    requireCheck(publicBytes.length === 32 && Array.isArray(signerResult.signatures_b64u) && signerResult.signatures_b64u.length === 5, 'verification controls');
    const messageBytes = messages.map((message) => asBytes(message, 'verification controls'));
    const signatures = signerResult.signatures_b64u.map((signature) => decodeCanonical(signature, 'verification controls'));
    requireCheck(signatures.every((signature) => signature.length === 64), 'verification controls');

    let seed;
    if (Buffer.isBuffer(wrongSeed) || wrongSeed instanceof Uint8Array) seed = Buffer.from(wrongSeed);
    else if (typeof wrongSeed === 'string' && /^[0-9a-f]{64}$/iu.test(wrongSeed)) seed = Buffer.from(wrongSeed, 'hex');
    else if (typeof wrongSeed === 'string') seed = decodeCanonical(wrongSeed, 'verification controls');
    else requireCheck(false, 'verification controls');
    requireCheck(seed.length === 32 && messageBytes[1].length > 0, 'verification controls');

    const verifications = [];
    const verdicts = [];
    const append = (message, signature, expected) => {
      const verified = oracleVerify(publicBytes, message, signature);
      requireCheck(verified === expected, 'verification controls');
      verifications.push({ message_b64u: b64u(message), signature_b64u: b64u(signature) });
      verdicts.push(expected);
    };

    for (let index = 0; index < 5; index += 1) append(messageBytes[index], signatures[index], true);

    const changedMessage = Buffer.from(messageBytes[1]);
    changedMessage[0] ^= 1;
    append(changedMessage, signatures[1], false);

    const changedSignature = Buffer.from(signatures[1]);
    changedSignature[0] ^= 1;
    append(messageBytes[1], changedSignature, false);

    append(messageBytes[1], oracleSign(seed, messageBytes[1]), false);
    append(messageBytes[1], signatures[1].subarray(0, 63), false);
    append(messageBytes[1], Buffer.alloc(0), false);

    requireCheck(verifications.length <= 16 && verdicts.filter(Boolean).length === 5 && verdicts.filter((value) => !value).length === 5, 'verification controls');
    return { verifications, verdicts };
  });
}

export function trustVariants(expected, otherKey) {
  return runCheck('trust variants', () => {
    requireCheck(isRecord(expected) && isRecord(otherKey), 'trust variants');
    for (const field of CONNECTION_FIELDS) requireCheck(Object.hasOwn(expected, field), 'trust variants');
    requireCheck(typeof otherKey.public_key === 'string' && typeof otherKey.kid === 'string', 'trust variants');

    const variants = [];
    const withExpected = (id, overrides = {}) => variants.push({ id, expected: { ...expected, ...overrides } });
    withExpected('wrong-url', { url: 'https://other.example.test' });
    withExpected('wrong-aud', { aud: 'https://other.example.test' });
    withExpected('wrong-server-public-key', { server_public_key: otherKey.public_key });
    withExpected('wrong-server-kid', { server_kid: otherKey.kid });
    withExpected('substituted-pin', { server_public_key: otherKey.public_key, server_kid: otherKey.kid });
    variants.push({ id: 'omitted' });
    variants.push({ id: 'null', expected: null });
    variants.push({ id: 'empty', expected: {} });
    for (const field of CONNECTION_FIELDS) {
      const missing = { ...expected };
      delete missing[field];
      variants.push({ id: `missing-${field.replaceAll('_', '-')}`, expected: missing });
    }

    withExpected('invalid-http-url', { url: 'http://other.example.test' });
    withExpected('empty-aud', { aud: '' });
    withExpected('malformed-public-encoding', { server_public_key: 'not-base64url!' });
    const invalidPublic = Buffer.alloc(32, 0xff);
    withExpected('invalid-strict-public-key', {
      server_public_key: b64u(invalidPublic),
      server_kid: expectedKid(invalidPublic),
    });
    withExpected('malformed-kid', { server_kid: 'not*a-kid' });
    return variants;
  });
}
