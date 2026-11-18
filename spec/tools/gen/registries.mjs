import { b64u, kidOf, validatePublicKey, validateRegistry, validateStateFile } from '../reference-verifier.mjs';
import { NOW, AUD, clone, K, entryOf, registryJson, codeOf, inviteIdOf } from './core.mjs';
import { IDENTITY, ORDER2, NONCANONICAL_IDENTITY, MIXED_ORDER, BAD_KEYS, offCurve } from './sequences.mjs';

export const keyVectors = [
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
export const regWith = (mutate) => {
  const doc = clone({ version: 1, aud: AUD, keys: [entryOf('alice'), entryOf('bob')] });
  mutate(doc);
  return doc;
};
export const REGISTRY_CASES = [
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
  ['invalid-not-before-int64-overflow', regWith((d) => { d.keys[0].not_before = 9223372036854775808; }), 'validity'],
].map(([id, document, reason]) => {
  const got = validateRegistry(document);
  if (got !== reason) throw new Error(`registry ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

export const stateWith = (mutate) => {
  const doc = {
    version: 1,
    keys: [entryOf('alice')],
    invites: [{ invite_id: inviteIdOf(codeOf('i')), created_by: K.root.kid, created_at: 100, expires_at: 200 }],
  };
  mutate(doc);
  return doc;
};
export const STATE_FILE_CASES = [
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
  ['statefile-invalid-invite-created-at-int64-overflow', stateWith((d) => { d.invites[0].created_at = 9223372036854775808; }), 'created_at'],
  ['statefile-invalid-invite-ttl-int64-overflow', stateWith((d) => { d.invites[0].key_ttl_seconds = 9223372036854775808; }), 'key_ttl_seconds'],
].map(([id, document, reason]) => {
  const got = validateStateFile(document);
  if (got !== reason) throw new Error(`state file ${id}: reference verifier says ${got}, expected ${reason}`);
  return { id, document, expect: reason === null ? 'valid' : 'invalid', ...(reason ? { reason } : {}) };
});

// ---- response cases ----