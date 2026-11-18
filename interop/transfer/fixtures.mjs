import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const EXPECTED_COUNTS = Object.freeze({ positives: 14, negatives: 51, context: 1, total: 66 });
const EXPECTED_CLASSES = new Set([
  'malformed_json', 'wrong_root_type', 'oversized_envelope', 'unknown_version',
  'unknown_type', 'bad_member_set', 'wrong_field_type', 'bad_encoding', 'bad_url',
  'invalid_public_key', 'seed_pub_mismatch', 'kid_mismatch', 'non_canonical_bytes',
  'wrong_envelope_type', 'private_material_rejected', 'not_private', 'server_identity_mismatch',
]);
const PRIVATE_SINK_IDS = new Set([
  'neg-unknown-version', 'neg-unknown-type', 'neg-bad-kty', 'neg-bad-crv', 'neg-empty-d',
  'neg-seed-pub-mismatch', 'neg-kid-mismatch', 'neg-dup-member',
  'neg-dup-member-last-mismatched', 'neg-dup-member-escaped', 'neg-noncanonical-ws',
  'neg-key-reorder', 'neg-truncated', 'neg-oversized-envelope', 'neg-v-float',
  'neg-size-boundary-4096', 'neg-size-boundary-4097', 'neg-invalid-utf8',
]);
const PUBLIC_SINK_IDS = new Set([
  'neg-unknown-field', 'neg-missing-kid', 'neg-wrong-field-type', 'neg-null-field',
  'neg-b64-padding', 'neg-b64-char', 'neg-escaped-member-name', 'neg-len-short',
  'neg-len-long', 'neg-b64-trailing-bits', 'neg-root-array', 'neg-root-string',
  'neg-empty-input', 'neg-null-input', 'neg-invalid-pub-noncanonical-y',
  'neg-invalid-pub-identity', 'neg-invalid-pub-small-order', 'neg-invalid-pub-off-curve',
]);
const SAFE_ID = /^[a-z0-9-]{1,80}$/u;
const EXPECTED_AUDIENCES = Object.freeze({
  'cred-alice': 'https://svc.example.test',
  'cred-bob': 'https://svc.example.test',
  'cred-aud-html-sensitive': 'a<b>&c',
  'cred-aud-codepoints': 'é😀',
  'cred-aud-control': `a\u0001z`,
  'cred-aud-separators': 'a\u2028b\u2029',
  'cred-aud-replacement-char': 'a\ufffdb',
});

function diagnosticLabel(value) {
  if (typeof value !== 'string') return 'fixture check';
  return value.slice(0, 120).replace(/[^a-zA-Z0-9 _:/=.,-]/gu, '-');
}

/** Boolean assertion; neither an actual value nor an exception detail is reported. */
export function check(condition, label = 'fixture check') {
  if (!condition) throw new Error(`transfer fixture check failed: ${diagnosticLabel(label)}`);
  return true;
}

export function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function decodeB64u(text) {
  check(typeof text === 'string' && /^[A-Za-z0-9_-]*$/u.test(text), 'base64url input');
  const decoded = Buffer.from(text, 'base64url');
  check(b64u(decoded) === text, 'canonical base64url');
  return decoded;
}

function keyId(publicBytes) {
  return b64u(createHash('sha256').update(publicBytes).digest());
}

function seedPublic(seed) {
  check(Buffer.from(seed).length === 32, 'Ed25519 seed length');
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  return Buffer.from(createPublicKey(privateKey).export({ format: 'der', type: 'spki' })).subarray(-32);
}

/** Independent Ed25519 signer from a raw 32-byte seed. */
export function oracleSign(seed, message) {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  return sign(null, Buffer.from(message), privateKey);
}

/** Independent Ed25519 verification against a raw 32-byte public key. */
export function oracleVerify(publicBytes, message, signature) {
  try {
    if (Buffer.from(publicBytes).length !== 32 || Buffer.from(signature).length !== 64) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicBytes)]), format: 'der', type: 'spki' });
    return verify(null, Buffer.from(message), publicKey, Buffer.from(signature));
  } catch {
    return false;
  }
}

export function publicEnvelope(kid, x) {
  return `{"crv":"Ed25519","kid":"${kid}","kty":"OKP","type":"user-key/public","v":1,"x":"${x}"}`;
}

export function privateEnvelope(d, kid, x) {
  return `{"crv":"Ed25519","d":"${d}","kid":"${kid}","kty":"OKP","type":"user-key/private","v":1,"x":"${x}"}`;
}

function validateScalars(value, label) {
  check(typeof value === 'string', label);
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(i + 1);
      check(low >= 0xdc00 && low <= 0xdfff, label);
      i += 1;
    } else {
      check(unit < 0xdc00 || unit > 0xdfff, label);
    }
  }
}

/** Credential template composition; JSON.stringify is used only for fixture string quoting. */
export function credentialEnvelope(aud, clientKey, serverKid, serverPublicKey, url) {
  for (const value of [aud, clientKey, serverKid, serverPublicKey, url]) validateScalars(value, 'credential scalar');
  return `{"aud":${JSON.stringify(aud)},"client_key":${JSON.stringify(clientKey)},"server_kid":${JSON.stringify(serverKid)},"server_public_key":${JSON.stringify(serverPublicKey)},"type":"user-key/credential/client","url":${JSON.stringify(url)},"v":1}`;
}

function safeJson(text, id) {
  try { return JSON.parse(text); } catch { check(false, id); }
}

function ownKeysEqual(actual, expected) {
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
  const a = Object.keys(actual).sort();
  const e = [...expected].sort();
  return a.length === e.length && a.every((key, i) => key === e[i]);
}

function scalarObjectEqual(a, b) {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) || Array.isArray(b)) return false;
  const ak = Object.keys(a).sort();
  const bk = Object.keys(b).sort();
  return ak.length === bk.length && ak.every((key, i) => key === bk[i] && Object.is(a[key], b[key]));
}

function checkUnchangedExcept(actual, baseline, allowed, id) {
  const allow = new Set(allowed);
  const all = new Set([...Object.keys(actual ?? {}), ...Object.keys(baseline ?? {})]);
  for (const key of all) {
    if (!allow.has(key)) check(Object.hasOwn(actual, key) === Object.hasOwn(baseline, key) && Object.is(actual[key], baseline[key]), id);
  }
}

function countLiteral(text, needle) {
  let count = 0;
  let at = 0;
  while ((at = text.indexOf(needle, at)) !== -1) { count += 1; at += needle.length; }
  return count;
}

function findById(groups, id) {
  const found = groups.flat().find((entry) => entry?.id === id);
  check(Boolean(found), id);
  return found;
}

function referenceId(reference, label) {
  check(typeof reference === 'string', label);
  const match = /^the exact ([a-z0-9-]+) envelope string$/u.exec(reference);
  check(match !== null, label);
  return match[1];
}

function exactEnvelopeReference(groups, reference, expectedKind, label) {
  const id = referenceId(reference, label);
  const item = findById(groups, id);
  check(item.kind === expectedKind && typeof item.envelope === 'string', label);
  return item.envelope;
}

function parseHex(text, label, length = undefined) {
  check(typeof text === 'string' && text.length % 2 === 0 && /^[0-9a-f]+$/iu.test(text), label);
  const out = Buffer.from(text, 'hex');
  if (length !== undefined) check(out.length === length, label);
  return out;
}

function loadPinnedKeys(keysJson) {
  const pins = {
    alice: { seed_hex: '15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f', public_key: 'kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE', kid: 'TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs' },
    bob: { seed_hex: '7eb4f89033dfe79db5a8fdaa667361b768722d619b62f531fba0cae9714a351b', public_key: '27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE', kid: 'g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns' },
    carol: { seed_hex: '50d2c03eab0770775c84772e131000ba021d8a1716629b068a85b273cca17fbb', public_key: 'r1DLsXDIaAY-rmPFCzV9dgAxes6dpdXkOrJNHiFkQl4', kid: 'bu9N_ld9z81i0mvxfKO0bgHdiYjZx7jBF8sd8DTo9gc' },
    svc: { seed_hex: 'cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901', public_key: 'wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw', kid: 'wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88' },
  };
  check(Array.isArray(keysJson?.keys), 'keys.json shape');
  const byName = Object.create(null);
  for (const pinName of Object.keys(pins)) {
    const key = keysJson.keys.find((entry) => entry?.name === pinName);
    check(Boolean(key), `keys ${pinName}`);
    const pin = pins[pinName];
    const seed = parseHex(key.seed_hex, `keys ${pinName} seed`, 32);
    const pub = decodeB64u(key.public_key);
    check(pub.length === 32, `keys ${pinName} public length`);
    check(key.seed_hex === pin.seed_hex && key.public_key === pin.public_key && key.kid === pin.kid, `keys ${pinName} independent pin`);
    check(seedPublic(seed).equals(pub), `keys ${pinName} seed public derivation`);
    check(keyId(pub) === pin.kid, `keys ${pinName} kid derivation`);
    byName[pinName] = Object.freeze({ seed_hex: key.seed_hex, public_key: key.public_key, kid: key.kid });
  }
  return Object.freeze(byName);
}

function loadRejectVectors(vectorJson) {
  check(Array.isArray(vectorJson?.cases), 'key-vectors shape');
  const out = Object.create(null);
  for (const id of ['reject-y-above-p', 'reject-identity', 'reject-order-2', 'reject-off-curve']) {
    const vector = vectorJson.cases.find((entry) => entry?.id === id);
    check(Boolean(vector) && vector.expect === 'rejected', `key vector ${id}`);
    out[id] = parseHex(vector.public_key_hex, `key vector ${id} bytes`, 32);
  }
  return out;
}

function checkPinnedKeyEnvelope(item, keys, parsed, label) {
  const keyName = item.id.includes('alice') ? 'alice' : item.id.includes('bob') ? 'bob' : 'carol';
  const pin = keys[keyName];
  const rawPub = decodeB64u(parsed.x);
  check(parsed.x === pin.public_key && parsed.kid === pin.kid, label);
  check(rawPub.equals(decodeB64u(pin.public_key)) && keyId(rawPub) === pin.kid, label);
  if (Object.hasOwn(parsed, 'd')) {
    const seed = decodeB64u(parsed.d);
    check(seed.equals(parseHex(pin.seed_hex, label, 32)), label);
    check(seedPublic(seed).equals(rawPub), label);
  }
}

function materializePositive(item, context, keys, vectorBytes, positivesById) {
  const id = item.id;
  if (item.kind === 'public_envelope' || item.kind === 'private_envelope' || item.kind === 'client_credential') {
    if (typeof item.envelope === 'string') return Buffer.from(item.envelope, 'utf8');
  }
  const recipe = item.compose;
  check(recipe && typeof recipe === 'object', id);
  if (id === 'priv-rfc8032-test1') {
    check(recipe.seed_b64u_of_hex === '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', id);
    check(recipe.public_key_b64u_of_hex === 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', id);
    const seed = parseHex(recipe.seed_b64u_of_hex, id, 32);
    const pub = parseHex(recipe.public_key_b64u_of_hex, id, 32);
    check(b64u(seed) === 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', id);
    check(b64u(pub) === '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', id);
    check(seedPublic(seed).equals(pub), id);
    const kid = keyId(pub);
    const text = privateEnvelope(b64u(seed), kid, b64u(pub));
    check(item.kind === 'private_envelope' && recipe.kid === 'base64url(SHA-256(public key bytes)) computed by the test runner with the SDK key-id function', id);
    return Buffer.from(text, 'utf8');
  }
  if (item.kind === 'client_credential' && recipe.template === 'client_credential') {
    const clientKey = exactEnvelopeReference([context.positives], recipe.client_key, 'private_envelope', id);
    const server = keys.svc;
    check(recipe.server_public_key === server.public_key && recipe.server_kid === server.kid, id);
    check(recipe.url === 'https://svc.example.test', id);
    const aud = Array.isArray(recipe.aud_codepoints) ? audienceFromCodepoints(recipe.aud_codepoints, id) : recipe.aud;
    check(typeof aud === 'string', id);
    const text = credentialEnvelope(aud, clientKey, recipe.server_kid, recipe.server_public_key, recipe.url);
    return Buffer.from(text, 'utf8');
  }
  check(false, id);
}

function audienceFromCodepoints(parts, label) {
  check(Array.isArray(parts), label);
  let result = '';
  for (const part of parts) {
    if (typeof part === 'number') {
      check(Number.isInteger(part) && part >= 0 && part <= 0x10ffff && !(part >= 0xd800 && part <= 0xdfff), label);
      result += String.fromCodePoint(part);
    } else {
      check(typeof part === 'string' && [...part].length === 1, label);
      validateScalars(part, label);
      result += part;
    }
  }
  const expected = {
    'cred-aud-codepoints': 'é😀',
    'cred-aud-control': `a\u0001z`,
    'cred-aud-separators': 'a\u2028b\u2029',
    'cred-aud-replacement-char': 'a\ufffdb',
  }[label];
  check(typeof expected === 'string' && result === expected, label);
  return result;
}

function parseEscapeRecipe(description, id) {
  check(typeof description === 'string', id);
  const count = /\b(six|twelve)-character\b/u.exec(description)?.[1];
  const declared = count === 'six' ? 6 : count === 'twelve' ? 12 : 0;
  const inParens = /\(([^()]*)\)/u.exec(description)?.[1];
  check(declared > 0 && typeof inParens === 'string', id);
  const tokens = inParens.split(', ');
  const groups = [];
  for (let i = 0; i < tokens.length;) {
    check(tokens[i] === 'backslash' && tokens[i + 1] === 'lowercase u', id);
    i += 2;
    const hex = tokens.slice(i, i + 4);
    check(hex.length === 4 && hex.every((ch) => /^[0-9a-f]$/u.test(ch)), id);
    groups.push(hex.join(''));
    i += 4;
  }
  const raw = groups.map((hex) => `\\u${hex}`).join('');
  check(raw.length === declared, id);
  const units = groups.map((hex) => Number.parseInt(hex, 16));
  if (id === 'neg-cred-aud-lone-surrogate-escape') check(units.length === 1 && units[0] >= 0xd800 && units[0] <= 0xdbff, id);
  else if (id === 'neg-cred-aud-lone-low-surrogate-escape') check(units.length === 1 && units[0] >= 0xdc00 && units[0] <= 0xdfff, id);
  else check(units.length === 2 && units[0] >= 0xd800 && units[0] <= 0xdbff && units[1] >= 0xdc00 && units[1] <= 0xdfff, id);
  return raw;
}

function replaceAudRaw(base, replacement, id) {
  const prefix = '{"aud":"';
  check(base.startsWith(prefix), id);
  const end = base.indexOf('"', prefix.length);
  check(end > prefix.length, id);
  return Buffer.from(prefix + replacement + base.slice(end), 'utf8');
}

function materializeNegative(item, positives, vectorBytes, negatives) {
  const id = item.id;
  if (typeof item.envelope === 'string') return Buffer.from(item.envelope, 'utf8');
  const recipe = item.compose;
  check(recipe && typeof recipe === 'object', id);
  if (id === 'neg-size-boundary-4096' || id === 'neg-size-boundary-4097') {
    const total = id.endsWith('4096') ? 4096 : 4097;
    check(recipe.kind === 'priv-alice followed by trailing spaces' && recipe.total_input_bytes === total, id);
    const base = Buffer.from(findById([positives], 'priv-alice').envelope, 'utf8');
    check(base.length < total, id);
    return Buffer.concat([base, Buffer.alloc(total - base.length, 0x20)]);
  }
  if (id === 'neg-invalid-utf8') {
    check(typeof recipe.kind === 'string' && recipe.kind.includes('final byte 0x7D') && recipe.kind.includes('0xFF') && recipe.kind.includes('byte length unchanged'), id);
    const base = Buffer.from(findById([positives], 'priv-alice').envelope, 'utf8');
    check(base.at(-1) === 0x7d, id);
    base[base.length - 1] = 0xff;
    return base;
  }
  if (id.startsWith('neg-cred-aud-') && id !== 'neg-cred-dup-inner-member') {
    check(recipe.base === 'cred-alice', id);
    const rawAud = parseEscapeRecipe(recipe.aud_replacement, id);
    return replaceAudRaw(findById([positives], 'cred-alice').envelope, rawAud, id);
  }
  if (id === 'neg-cred-dup-inner-member') {
    check(recipe.base === 'cred-alice', id);
    const reference = referenceId(recipe.client_key_replacement, id);
    const referenced = findById([negatives], reference);
    check(reference === 'neg-dup-member' && typeof referenced.envelope === 'string', id);
    const inner = referenced.envelope;
    check(inner.startsWith('{"crv":"Ed25519","d":"') && countLiteral(inner, '"kid":"') === 2, id);
    return Buffer.from(credentialEnvelope('https://svc.example.test', inner, 'wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88', 'wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw', 'https://svc.example.test'), 'utf8');
  }
  if (id.startsWith('neg-invalid-pub-') && recipe.template === 'public_envelope') {
    const vectorId = recipe.x_from_key_vector;
    check(typeof vectorId === 'string' && vectorBytes[vectorId], id);
    check(recipe.kid === 'base64url(SHA-256(x bytes)) computed by the test runner', id);
    const x = vectorBytes[vectorId];
    return Buffer.from(publicEnvelope(keyId(x), b64u(x)), 'utf8');
  }
  if (id === 'neg-cred-invalid-server-pub' && recipe.template === 'client_credential') {
    const vectorId = recipe.server_public_key_from_key_vector;
    check(typeof vectorId === 'string' && vectorBytes[vectorId], id);
    const clientKey = exactEnvelopeReference([positives], recipe.client_key, 'private_envelope', id);
    check(clientKey === findById([positives], 'priv-alice').envelope, id);
    check(recipe.aud === 'https://svc.example.test' && recipe.url === 'https://svc.example.test', id);
    check(recipe.server_kid === 'base64url(SHA-256(server_public_key bytes)) computed by the test runner', id);
    const x = vectorBytes[vectorId];
    return Buffer.from(credentialEnvelope(recipe.aud, clientKey, keyId(x), b64u(x), recipe.url), 'utf8');
  }
  check(false, id);
}

function materializeContext(item, positives, keys) {
  check(item.id === 'cred-wrong-server' && item.kind === 'client_credential', 'context case');
  check(item.structural_outcome === 'accepted_by_import_pipeline' && item.trust_outcome === 'server_identity_mismatch', 'context outcomes');
  const r = item.compose;
  check(r?.template === 'client_credential', 'context recipe');
  const clientKey = exactEnvelopeReference([positives], r.client_key, 'private_envelope', item.id);
  check(clientKey === findById([positives], 'priv-alice').envelope, item.id);
  const alice = keys.alice;
  check(r.server_public_key === alice.public_key && r.server_kid === alice.kid, item.id);
  check(r.url === 'https://svc.example.test' && r.aud === 'https://svc.example.test', item.id);
  return Buffer.from(credentialEnvelope(r.aud, clientKey, r.server_kid, r.server_public_key, r.url), 'utf8');
}

function intendedSink(id) {
  if (PRIVATE_SINK_IDS.has(id)) return 'private';
  if (PUBLIC_SINK_IDS.has(id)) return 'public';
  if (id === 'neg-escaped-url-slash' || id.startsWith('neg-cred-')) return 'credential';
  check(false, id);
}

const PRIVATE_BASE_MUTATIONS = Object.freeze({
  'neg-unknown-version': { allow: ['v'], expect: { v: 2 } },
  'neg-unknown-type': { allow: ['type'], expect: { type: 'user-key/secret' } },
  'neg-bad-kty': { allow: ['kty'], expect: { kty: 'EC' } },
  'neg-bad-crv': { allow: ['crv'], expect: { crv: 'Ed448' } },
  'neg-empty-d': { allow: ['d'], expect: { d: '' } },
  'neg-seed-pub-mismatch': { allow: ['x', 'kid'], expect: { x: '27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE', kid: 'g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns' } },
  'neg-kid-mismatch': { allow: ['kid'], expect: { kid: 'g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns' } },
  'neg-dup-member': { allow: [], duplicate: 'same' },
  'neg-dup-member-last-mismatched': { allow: ['kid'], expect: { kid: 'g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns' }, duplicate: 'mismatched' },
  'neg-dup-member-escaped': { allow: [], duplicate: 'escaped' },
  'neg-noncanonical-ws': { allow: [] },
  'neg-key-reorder': { allow: [] },
  'neg-v-float': { allow: ['v'], expect: { v: 1 } },
});
const PUBLIC_BASE_MUTATIONS = Object.freeze({
  'neg-unknown-field': { allow: ['comment'], expect: { comment: 'hi' } },
  'neg-missing-kid': { allow: ['kid'], remove: ['kid'] },
  'neg-wrong-field-type': { allow: ['kid'], expect: { kid: 123 } },
  'neg-null-field': { allow: ['x'], expect: { x: null } },
  'neg-b64-padding': { allow: ['x'], expect: { x: 'kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE=' } },
  'neg-b64-char': { allow: ['kid'], expect: { kid: 'TXF9TkhWm+UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs' } },
  'neg-escaped-member-name': { allow: [] },
  'neg-len-short': { allow: ['x'], expect: { x: 'kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJ' } },
  'neg-len-long': { allow: ['kid'], expect: { kid: 'TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNsA' } },
  'neg-b64-trailing-bits': { allow: ['x'], expect: { x: 'kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJF' } },
});
const CREDENTIAL_BASE_MUTATIONS = Object.freeze({
  'neg-cred-unknown-version': { allow: ['v'], expect: { v: 2 } },
  'neg-cred-unknown-type': { allow: ['type'], expect: { type: 'user-key/credential/server' } },
  'neg-cred-missing-server-kid': { allow: ['server_kid'], remove: ['server_kid'] },
  'neg-cred-extra-server-private-key': { allow: ['server_private_key'], expect: { server_private_key: '27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE' } },
  'neg-cred-server-kid-mismatch': { allow: ['server_kid'], expect: { server_kid: 'TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs' } },
  'neg-cred-bad-url': { allow: ['url'], expect: { url: 'http://svc.example.test' } },
  'neg-cred-empty-aud': { allow: ['aud'], expect: { aud: '' } },
  'neg-escaped-url-slash': { allow: [] },
  'neg-cred-client-key-noncanonical': { allow: ['client_key'], inner: 'noncanonical' },
  'neg-cred-client-key-public': { allow: ['client_key'], inner: 'public' },
});

function validateLiteralNegative(item, bytes, positives, keys, vectorBytes, negatives) {
  const id = item.id;
  check(EXPECTED_CLASSES.has(item.expect_class), id);
  check(typeof item.expect_why === 'string', id);
  const text = item.envelope;
  const pAlice = findById([positives], 'priv-alice').envelope;
  const pubAlice = findById([positives], 'pub-alice').envelope;
  const credAlice = findById([positives], 'cred-alice').envelope;
  if (id === 'neg-truncated') {
    check(text === pAlice.slice(0, 64) && bytes.length === 64, id);
    return;
  }
  if (id === 'neg-oversized-envelope') {
    check(bytes.length > 4096 && text.startsWith(pAlice) && /^ +$/u.test(text.slice(pAlice.length)), id);
    return;
  }
  if (id === 'neg-empty-input' || id === 'neg-null-input' || id === 'neg-root-array' || id === 'neg-root-string') {
    check(text === ({ 'neg-empty-input': '', 'neg-null-input': 'null', 'neg-root-array': '[]', 'neg-root-string': '"user-key/private"' })[id], id);
    return;
  }
  if (id === 'neg-dup-member' || id === 'neg-dup-member-last-mismatched' || id === 'neg-dup-member-escaped') {
    const parsed = safeJson(text, id);
    checkUnchangedExcept(parsed, safeJson(pAlice, id), id === 'neg-dup-member-last-mismatched' ? ['kid'] : [], id);
    const ordinary = `"kid":"${keys.alice.kid}"`;
    if (id === 'neg-dup-member') check(countLiteral(text, ordinary) === 2, id);
    if (id === 'neg-dup-member-last-mismatched') check(text.endsWith(`,"kid":"${keys.bob.kid}"}`) && parsed.kid === keys.bob.kid, id);
    if (id === 'neg-dup-member-escaped') check(text.endsWith(`,"\\u006b\\u0069\\u0064":"${keys.alice.kid}"}`), id);
    return;
  }
  if (id === 'neg-cred-aud-lone-surrogate-escape' || id === 'neg-cred-aud-lone-low-surrogate-escape' || id === 'neg-cred-aud-escaped-surrogate-pair') {
    const raw = parseEscapeRecipe(item.compose.aud_replacement, id);
    const expected = replaceAudRaw(credAlice, raw, id);
    check(bytes.equals(expected), id);
    return;
  }
  if (id === 'neg-cred-dup-inner-member') {
    const outer = safeJson(text, id);
    const base = safeJson(credAlice, id);
    checkUnchangedExcept(outer, base, ['client_key'], id);
    const duplicate = findById([negatives], 'neg-dup-member').envelope;
    check(typeof duplicate === 'string' && outer.client_key === duplicate, id);
    check(countLiteral(outer.client_key, `"kid":"${keys.alice.kid}"`) === 2, id);
    return;
  }
  if (id.startsWith('neg-invalid-pub-')) {
    const vectorId = ({
      'neg-invalid-pub-noncanonical-y': 'reject-y-above-p',
      'neg-invalid-pub-identity': 'reject-identity',
      'neg-invalid-pub-small-order': 'reject-order-2',
      'neg-invalid-pub-off-curve': 'reject-off-curve',
    })[id];
    const x = vectorBytes[vectorId];
    const parsed = safeJson(text, id);
    check(text === publicEnvelope(keyId(x), b64u(x)) && parsed.x === b64u(x) && parsed.kid === keyId(x), id);
    return;
  }
  if (id === 'neg-cred-invalid-server-pub') {
    const server = vectorBytes['reject-y-above-p'];
    const outer = safeJson(text, id);
    check(outer.server_public_key === b64u(server) && outer.server_kid === keyId(server), id);
    return;
  }
  if (id === 'neg-size-boundary-4096' || id === 'neg-size-boundary-4097' || id === 'neg-invalid-utf8') return;
  if (id === 'neg-cred-dup-inner-member') return;

  let baseText;
  let plan;
  if (PRIVATE_BASE_MUTATIONS[id]) { baseText = pAlice; plan = PRIVATE_BASE_MUTATIONS[id]; }
  else if (PUBLIC_BASE_MUTATIONS[id]) { baseText = pubAlice; plan = PUBLIC_BASE_MUTATIONS[id]; }
  else if (CREDENTIAL_BASE_MUTATIONS[id]) { baseText = credAlice; plan = CREDENTIAL_BASE_MUTATIONS[id]; }
  else check(false, id);
  const parsed = safeJson(text, id);
  const baseline = safeJson(baseText, id);
  checkUnchangedExcept(parsed, baseline, plan.allow, id);
  for (const [field, value] of Object.entries(plan.expect ?? {})) check(Object.is(parsed[field], value), id);
  for (const field of plan.remove ?? []) check(!Object.hasOwn(parsed, field), id);
  if (id === 'neg-noncanonical-ws') check(text === pAlice.replace('{', '{ '), id);
  if (id === 'neg-key-reorder') {
    check(text.startsWith('{"type":"user-key/private","v":1,'), id);
    check(ownKeysEqual(parsed, ['crv', 'd', 'kid', 'kty', 'type', 'v', 'x']), id);
  }
  if (id === 'neg-v-float') check(text.includes('"v":1.0'), id);
  if (plan.inner === 'noncanonical') check(parsed.client_key === pAlice.replace('{"crv"', '{ "crv"'), id);
  if (plan.inner === 'public') check(parsed.client_key === pubAlice, id);
  if (id === 'neg-escaped-member-name') check(text.startsWith('{"\\u0063rv":"Ed25519"') && scalarObjectEqual(parsed, baseline), id);
  if (id === 'neg-escaped-url-slash') check(text.includes('"url":"https:\\/\\/svc.example.test"') && scalarObjectEqual(parsed, baseline), id);
  if (id === 'neg-cred-extra-server-private-key') check(ownKeysEqual(parsed, [...Object.keys(baseline), 'server_private_key']), id);
}

function validateComposedNegative(item, bytes, positives, keys, vectorBytes) {
  const id = item.id;
  check(EXPECTED_CLASSES.has(item.expect_class), id);
  if (id === 'neg-size-boundary-4096' || id === 'neg-size-boundary-4097') {
    const base = Buffer.from(findById([positives], 'priv-alice').envelope, 'utf8');
    check(bytes.length === (id.endsWith('4096') ? 4096 : 4097) && bytes.subarray(0, base.length).equals(base), id);
    check(bytes.subarray(base.length).every((byte) => byte === 0x20), id);
  } else if (id === 'neg-invalid-utf8') {
    const base = Buffer.from(findById([positives], 'priv-alice').envelope, 'utf8');
    check(bytes.length === base.length && bytes.subarray(0, -1).equals(base.subarray(0, -1)) && bytes.at(-1) === 0xff, id);
  } else if (id.startsWith('neg-invalid-pub-')) {
    const vectorId = item.compose.x_from_key_vector;
    const x = vectorBytes[vectorId];
    check(bytes.toString('utf8') === publicEnvelope(keyId(x), b64u(x)), id);
  } else if (id === 'neg-cred-invalid-server-pub') {
    const x = vectorBytes[item.compose.server_public_key_from_key_vector];
    const parsed = safeJson(bytes.toString('utf8'), id);
    check(parsed.server_public_key === b64u(x) && parsed.server_kid === keyId(x), id);
  } else if (id.startsWith('neg-cred-aud-')) {
    const parsed = safeJson(bytes.toString('utf8'), id);
    if (id === 'neg-cred-aud-escaped-surrogate-pair') check(parsed.aud === '😀', id);
    else check(parsed.aud === (id.endsWith('low-surrogate-escape') ? '\udc00' : '\ud800'), id);
  } else if (id === 'neg-cred-dup-inner-member') {
    const parsed = safeJson(bytes.toString('utf8'), id);
    check(typeof parsed.client_key === 'string' && countLiteral(parsed.client_key, `"kid":"${keys.alice.kid}"`) === 2, id);
  } else check(false, id);
}

function makeMessages() {
  return Object.freeze([
    Object.freeze({ id: 'empty', bytes: Buffer.alloc(0) }),
    Object.freeze({ id: 'ascii-label', bytes: Buffer.from('mcp-jack transfer fixture ASCII message', 'utf8') }),
    Object.freeze({ id: 'utf8-unicode', bytes: Buffer.from('mcp-jack transfer fixture — café 😀', 'utf8') }),
    Object.freeze({ id: 'binary-nul-lf-ff', bytes: Buffer.from([0x00, 0x0a, 0xff]) }),
    Object.freeze({ id: 'deterministic-4096', bytes: Buffer.alloc(4096, 0x61) }),
  ]);
}

function validatePositive(item, bytes, keys, positivesById) {
  const id = item.id;
  const text = bytes.toString('utf8');
  check(Buffer.from(text, 'utf8').equals(bytes), id);
  const parsed = safeJson(text, id);
  if (item.kind === 'public_envelope') {
    check(ownKeysEqual(parsed, ['crv', 'kid', 'kty', 'type', 'v', 'x']), id);
    check(text === publicEnvelope(parsed.kid, parsed.x), id);
    check(parsed.crv === 'Ed25519' && parsed.kty === 'OKP' && parsed.type === 'user-key/public' && parsed.v === 1, id);
    const named = id.slice('pub-'.length);
    const key = keys[named];
    check(parsed.x === key.public_key && parsed.kid === key.kid, id);
    check(item.expect_x === key.public_key && item.expect_kid === key.kid, id);
  } else if (item.kind === 'private_envelope') {
    check(ownKeysEqual(parsed, ['crv', 'd', 'kid', 'kty', 'type', 'v', 'x']), id);
    check(text === privateEnvelope(parsed.d, parsed.kid, parsed.x), id);
    check(parsed.crv === 'Ed25519' && parsed.kty === 'OKP' && parsed.type === 'user-key/private' && parsed.v === 1, id);
    if (id === 'priv-rfc8032-test1') {
      const seed = decodeB64u(parsed.d);
      const pub = decodeB64u(parsed.x);
      const rfcSignature = Buffer.from('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex');
      check(seed.equals(parseHex(item.compose.seed_b64u_of_hex, id, 32)) && pub.equals(parseHex(item.compose.public_key_b64u_of_hex, id, 32)), id);
      check(b64u(seed) === 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A' && b64u(pub) === '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', id);
      check(keyId(pub) === parsed.kid && seedPublic(seed).equals(pub), id);
      check(oracleSign(seed, Buffer.alloc(0)).equals(rfcSignature) && oracleVerify(pub, Buffer.alloc(0), rfcSignature), id);
    } else checkPinnedKeyEnvelope(item, keys, parsed, id);
  } else if (item.kind === 'client_credential') {
    check(ownKeysEqual(parsed, ['aud', 'client_key', 'server_kid', 'server_public_key', 'type', 'url', 'v']), id);
    check(text === credentialEnvelope(parsed.aud, parsed.client_key, parsed.server_kid, parsed.server_public_key, parsed.url), id);
    check(parsed.type === 'user-key/credential/client' && parsed.v === 1, id);
    check(parsed.server_public_key === keys.svc.public_key && parsed.server_kid === keys.svc.kid && keyId(decodeB64u(parsed.server_public_key)) === keys.svc.kid, id);
    check(parsed.url === 'https://svc.example.test', id);
    const expectedAud = EXPECTED_AUDIENCES[id];
    check(parsed.aud === expectedAud && typeof parsed.aud === 'string' && parsed.aud.length > 0, id);
    const referencedId = id === 'cred-bob' ? 'priv-bob' : 'priv-alice';
    check(parsed.client_key === positivesById[referencedId].envelope, id);
    const inner = safeJson(parsed.client_key, id);
    checkPinnedKeyEnvelope({ id: referencedId }, keys, inner, id);
    check(parsed.server_kid === (item.expect_server_kid ?? keys.svc.kid), id);
    if (item.expect_client_kid !== undefined) check(item.expect_client_kid === inner.kid, id);
    if (item.expect_aud !== undefined) check(item.expect_aud === expectedAud, id);
  } else check(false, id);
}

function validateContext(item, bytes, keys, positivesById) {
  const text = bytes.toString('utf8');
  const parsed = safeJson(text, item.id);
  check(text === credentialEnvelope(parsed.aud, parsed.client_key, parsed.server_kid, parsed.server_public_key, parsed.url), item.id);
  check(ownKeysEqual(parsed, ['aud', 'client_key', 'server_kid', 'server_public_key', 'type', 'url', 'v']), item.id);
  check(parsed.client_key === positivesById['priv-alice'].envelope, item.id);
  check(parsed.aud === 'https://svc.example.test' && parsed.url === 'https://svc.example.test', item.id);
  check(parsed.server_public_key === keys.alice.public_key && parsed.server_kid === keys.alice.kid, item.id);
  check(keyId(decodeB64u(parsed.server_public_key)) === parsed.server_kid, item.id);
}

/** Load, independently pin, materialize and shape-check all 66 shared transfer cases. */
export function loadTransferFixtures(repoRoot) {
  let table;
  let keysJson;
  let vectorJson;
  try {
    table = JSON.parse(readFileSync(join(repoRoot, 'spec/fixtures/user-key-transfer.json'), 'utf8'));
    // Direct paths are intentional: keys.json is the independent seed oracle.
    keysJson = JSON.parse(readFileSync(join(repoRoot, 'spec/fixtures/keys.json'), 'utf8'));
    vectorJson = JSON.parse(readFileSync(join(repoRoot, 'spec/fixtures/key-vectors.json'), 'utf8'));
  } catch {
    check(false, 'fixture files readable');
  }
  check(table.schema === 'user-key-transfer-fixtures/1', 'transfer fixture schema');
  check(Array.isArray(table.positives) && table.positives.length === EXPECTED_COUNTS.positives, 'positive count');
  check(Array.isArray(table.negatives) && table.negatives.length === EXPECTED_COUNTS.negatives, 'negative count');
  check(Array.isArray(table.context_cases) && table.context_cases.length === EXPECTED_COUNTS.context, 'context count');
  check(table.positives.length + table.negatives.length + table.context_cases.length === EXPECTED_COUNTS.total, 'total case count');

  const seen = new Set();
  for (const item of [...table.positives, ...table.negatives, ...table.context_cases]) {
    check(typeof item.id === 'string' && SAFE_ID.test(item.id) && !seen.has(item.id), 'unique case ids');
    seen.add(item.id);
  }
  const keys = loadPinnedKeys(keysJson);
  const svcExpected = Object.freeze({
    url: 'https://svc.example.test',
    aud: 'https://svc.example.test',
    server_public_key: keys.svc.public_key,
    server_kid: keys.svc.kid,
  });
  const vectors = loadRejectVectors(vectorJson);
  const positivesById = Object.fromEntries(table.positives.map((entry) => [entry.id, entry]));
  for (const name of ['alice', 'bob', 'carol']) {
    check(positivesById[`pub-${name}`]?.kind === 'public_envelope' && positivesById[`priv-${name}`]?.kind === 'private_envelope', `positive pair ${name}`);
  }
  const vectorBytes = Object.freeze(vectors);
  const positives = table.positives.map((item) => {
    check(['public_envelope', 'private_envelope', 'client_credential'].includes(item.kind), item.id);
    const bytes = materializePositive(item, table, keys, vectorBytes, positivesById);
    validatePositive(item, bytes, keys, positivesById);
    let key;
    if (item.id === 'priv-rfc8032-test1') {
      const parsed = safeJson(bytes.toString('utf8'), item.id);
      key = Object.freeze({
        seed_hex: item.compose.seed_b64u_of_hex,
        public_key: parsed.x,
        kid: keyId(decodeB64u(parsed.x)),
      });
    } else if (item.kind === 'client_credential') {
      key = keys[item.id === 'cred-bob' ? 'bob' : 'alice'];
    } else {
      const name = item.id.startsWith('pub-') ? item.id.slice(4) : item.id.slice(5);
      key = keys[name];
    }
    const expected = item.kind === 'client_credential'
      ? Object.freeze({
        url: svcExpected.url,
        aud: EXPECTED_AUDIENCES[item.id],
        server_public_key: svcExpected.server_public_key,
        server_kid: svcExpected.server_kid,
      })
      : undefined;
    if (item.kind === 'client_credential') check(typeof expected.aud === 'string', item.id);
    return Object.freeze({ ...item, bytes, key, ...(expected === undefined ? {} : { expected }) });
  });
  const negatives = table.negatives.map((item) => {
    check(typeof item.expect_class === 'string' && EXPECTED_CLASSES.has(item.expect_class), item.id);
    const sink = intendedSink(item.id);
    let bytes;
    if (typeof item.envelope === 'string') bytes = Buffer.from(item.envelope, 'utf8');
    else bytes = materializeNegative(item, positives, vectorBytes, table.negatives);
    if (typeof item.envelope === 'string') validateLiteralNegative(item, bytes, positives, keys, vectorBytes, table.negatives);
    else validateComposedNegative(item, bytes, positives, keys, vectorBytes);
    check(bytes instanceof Buffer, item.id);
    return Object.freeze({ ...item, bytes, sink });
  });
  const context = table.context_cases.map((item) => {
    check(item.kind === 'client_credential', item.id);
    const bytes = materializeContext(item, positives, keys);
    validateContext(item, bytes, keys, positivesById);
    const structuralExpected = Object.freeze({
      url: 'https://svc.example.test',
      aud: 'https://svc.example.test',
      server_public_key: keys.alice.public_key,
      server_kid: keys.alice.kid,
    });
    return Object.freeze({ ...item, bytes, key: keys.alice, expected: svcExpected, structuralExpected });
  });
  const credentialCases = Object.freeze(positives.filter((entry) => entry.kind === 'client_credential'));
  const messages = makeMessages();
  // Verify all message oracles once at load so callers receive a pinned, known-good set.
  for (const name of ['alice', 'bob', 'carol']) {
    const key = keys[name];
    const seed = parseHex(key.seed_hex, `oracle seed ${name}`, 32);
    const pub = decodeB64u(key.public_key);
    for (const message of messages) {
      const signature = oracleSign(seed, message.bytes);
      check(signature.length === 64 && oracleVerify(pub, message.bytes, signature), `oracle signature ${name}`);
    }
  }
  // Keep table and source fixtures untouched; materialized case records carry independent byte copies.
  return Object.freeze({ table, keys, positives: Object.freeze(positives), negatives: Object.freeze(negatives), context: Object.freeze(context), credentialCases, svcExpected, messages });
}
