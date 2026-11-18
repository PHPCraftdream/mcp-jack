import { sign } from 'node:crypto';
import { b64u, kidOf, verifyRequest, defaultHooks, validateStateFile, decodePoint, addPoints, encodePoint, BASE_POINT, findOrder8Point, fromBig } from '../reference-verifier.mjs';
import { NOW, WINDOW, AUD, K, entryOf, call, callRaw, rawArg, codeOf, inviteIdOf, rotateProof, buildRequest, materialize, expectOf, deepEqual, agree, shadowInit, durableState, rawDurable, expectStep } from './core.mjs';

export const pk = (name) => K[name].public_key;
export const IDENTITY = Buffer.from(`01${'00'.repeat(31)}`, 'hex');
export const ORDER2 = fromBig((1n << 255n) - 20n, 32); // (0, -1)
export const NONCANONICAL_IDENTITY = fromBig((1n << 255n) - 18n, 32); // y = p + 1
export const ORDER8 = findOrder8Point();
export const MIXED_ORDER = encodePoint(addPoints(BASE_POINT, ORDER8));
export const BAD_KEYS = {
  identity: IDENTITY,
  order2: ORDER2,
  order8: encodePoint(ORDER8),
  noncanonical: NONCANONICAL_IDENTITY,
  mixed: MIXED_ORDER,
};
export let offCurve;
for (let y = 2n; !offCurve; y++) if (!decodePoint(fromBig(y, 32))) offCurve = fromBig(y, 32);

// Base record carries no key_ttl_seconds: the member is present only when the
// invite sets a key expiry (spec 03 section 3.3); overrides add real numbers.
export const inv = (label, over = {}) => ({
  invite_id: inviteIdOf(codeOf(label)), created_by: K.root.kid,
  created_at: NOW - 100, expires_at: NOW + 3000, ...over,
});
export const enrollArgs = (label, name, publicKey) => ({ code: codeOf(label), name, public_key: publicKey });
export const step = (key, tool, args, want, extra = {}) => ({ key, tool, args, want, ...extra });
// `model` states the effective arguments when the request body is raw JSON
// text the step's `args` cannot express; expectations are built from it.
export const A = (...w) => w; // reads better in the tables below

export const SEQUENCES = [];
export const seq = (id, description, init, steps) => SEQUENCES.push({ id, description, init, steps });
export const init = (names, extra = {}) => ({ names, ...extra });

// enrollment. Enroll steps use enrollArgs against a seeded invite from init;
// codes created by jack.admin.invite.create steps appear in expectations only
// (scrubbed via expectOf), never in emitted request bytes.
seq('enroll-ok', 'an invite holder enrolls a new key and can use it; the enrolled entry is an ordinary user (admin false)', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('enroll-key-ttl', 'key_ttl_seconds sets not_after at enrollment time', init(['root'], { invites: [inv('i1', { key_ttl_seconds: 3600 })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-admin-invite', 'the invite carries admin and the enrolled entry is an administrator', init(['root'], { invites: [inv('i1', { admin: true })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('enroll-invite-last-second', 'an invite is valid until expires_at exclusive', init(['root'], { invites: [inv('i1', { expires_at: NOW + 1 })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-invite-expired', 'an expired invite (expires_at = now) is not live: ordinary unsigned unknown_key before the signature check, no nonce, no audit', init(['root'], { invites: [inv('i1', { expires_at: NOW })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-code-reuse', 'an invite is single-use: once consumed the code is no longer live, so the second enrollment is unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  step('newbie2', 'jack.enroll', enrollArgs('i1', 'newbie2', pk('newbie2')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-unknown-code', 'a code that names no invite is not live: unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('nope', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-unknown-kid-unread-member', 'with a live invite, an unread arguments member with an out-of-range number is never range-checked: the unknown-kid enrollment succeeds', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', rawArg({ code: codeOf('i1'), name: 'newbie', public_key: pk('newbie') }, 'x', '1e999'), A('accept')),
]);
seq('enroll-malformed-code', 'a code that is not canonical base64url is not live: unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: 'not-a-code!!', name: 'newbie', public_key: pk('newbie') }, A('reject', 401, 'unknown_key')),
]);
seq('enroll-code-not-string', 'a code that is not a JSON string is not live: unknown_key, not invalid_params', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: 7, name: 'newbie', public_key: pk('newbie') }, A('reject', 401, 'unknown_key')),
]);
seq('enroll-missing-code', 'a missing code is not live: unknown_key, not invalid_params', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { name: 'newbie', public_key: pk('newbie') }, A('reject', 401, 'unknown_key')),
]);
seq('enroll-invalid-name', 'name must match the allowed character set', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'bad name!', pk('newbie')), A('reject', 400, 'invalid_params')),
]);
seq('enroll-name-taken', 'a taken name fails and does not consume the invite', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'alice', pk('newbie')), A('reject', 409, 'name_taken')),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-registered-key', 'a registered key calling jack.enroll gets key_exists', init(['root', 'alice'], { invites: [inv('i1')] }), [
  step('alice', 'jack.enroll', enrollArgs('i1', 'alice2', pk('alice')), A('reject', 409, 'key_exists')),
]);
for (const [label, raw] of Object.entries(BAD_KEYS)) {
  seq(`enroll-key-${label}`, `a ${label} public key is rejected before the signature is checked`, init(['root'], { invites: [inv('i1')] }), [
    step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(raw)), A('reject', 400, 'key_rejected'), { hdr: { kid: kidOf(raw) }, sign: { kid: kidOf(raw) } }),
  ]);
}
seq('enroll-key-wrong-length', 'a 31-byte public key is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(K.newbie.pub.subarray(0, 31))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-padded-encoding', 'a padded base64url public key is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', `${pk('newbie')}=`), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-off-curve', 'a point that is not on the curve is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(offCurve)), A('reject', 400, 'key_rejected')),
]);
seq('enroll-kid-mismatch', 'the header kid must be the hash of the submitted key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie2', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-bad-signature', 'the request must be signed by the submitted key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'bad_signature'), { signKey: 'newbie2' }),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-stale-timestamp', 'the time window applies to enrollment', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'timestamp_out_of_window'), { ts: NOW - WINDOW - 1 }),
]);
seq('enroll-get-with-unknown-kid', 'GET with an unknown kid is unknown_key', init(['root']), [
  { key: 'newbie', method: 'GET', want: A('reject', 401, 'unknown_key') },
]);
seq('enroll-replay', 'a replayed enrollment fails at the nonce check', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('accept')),
  { repeat: 0, want: A('reject', 401, 'replayed_nonce') },
]);

// key rotation
export const rotateArgs = (newName, oldName, signer) => ({ public_key: pk(newName), proof: rotateProof(newName, oldName, signer) });
seq('rotate-ok', 'rotation replaces the key; the old key stops working immediately', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', rotateArgs('newbie', 'alice'), A('accept')),
  step('alice', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('rotate-preserves-admin', 'rotation preserves admin and never trips the last-administrator rule', init(['root']), [
  step('root', 'jack.key.rotate', rotateArgs('newbie', 'root'), A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
  step('root', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);
seq('rotate-bad-proof', 'the proof must be signed by the new key', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', rotateArgs('newbie', 'alice', 'newbie2'), A('reject', 400, 'invalid_proof')),
]);
seq('rotate-proof-malformed', 'a malformed proof is invalid_proof', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: pk('newbie'), proof: 'abc' }, A('reject', 400, 'invalid_proof')),
]);
seq('rotate-proof-before-existence', 'a bad proof wins over key_exists so existence is not an oracle', init(['root', 'alice', 'bob']), [
  step('alice', 'jack.key.rotate', { public_key: pk('bob'), proof: rotateProof('bob', 'alice', 'newbie') }, A('reject', 400, 'invalid_proof')),
]);
seq('rotate-key-exists', 'rotating to a registered key fails', init(['root', 'alice', 'bob']), [
  step('alice', 'jack.key.rotate', rotateArgs('bob', 'alice'), A('reject', 409, 'key_exists')),
]);
seq('rotate-key-rejected', 'rotating to a small-order key fails', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: b64u(IDENTITY), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-missing-args', 'public_key and proof are required', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
]);

// administration: users
export const STD = ['root', 'alice', 'bob', 'agentx'];
seq('admin-user-list', 'an admin lists users sorted by name', init(STD), [
  step('root', 'jack.admin.user.list', {}, A('accept')),
]);
seq('admin-user-list-requires-admin', 'a key without admin is refused and the attempt is audited', init(STD), [
  step('alice', 'jack.admin.user.list', {}, A('reject', 403, 'admin_required')),
]);
seq('admin-user-get', 'get an entry by kid', init(STD), [
  step('root', 'jack.admin.user.get', { kid: K.alice.kid }, A('accept')),
  step('root', 'jack.admin.user.get', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
  step('root', 'jack.admin.user.get', { kid: 7 }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-ok', 'create a user from a public key', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie') }, A('accept')),
  step('newbie', 'jack.whoami', {}, A('accept')),
]);
seq('admin-create-admin-flag', 'any administrator may create another administrator', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), admin: true }, A('accept')),
]);
seq('admin-create-stale-members-inert', 'unknown argument members are inert: stale scopes and kind cannot escalate (spec 03 section 3)', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), scopes: ['read', 'admin'], kind: 'agent' }, A('accept')),
  step('root', 'jack.admin.user.list', {}, A('accept')),
]);
seq('admin-create-admin-mistyped', 'a mistyped admin fails closed', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), admin: 'true' }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-validity', 'create a key with a validity interval', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: NOW - 10, not_after: NOW + 500 }, A('accept')),
]);
seq('admin-create-bad-validity', 'not_before must be below not_after', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: NOW + 500, not_after: NOW }, A('reject', 400, 'invalid_params')),
]);
seq('admin-create-name-taken', 'a taken name is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'alice', public_key: pk('newbie') }, A('reject', 409, 'name_taken')),
]);
seq('admin-create-key-exists', 'a registered key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('alice') }, A('reject', 409, 'key_exists')),
]);
seq('admin-create-key-rejected', 'a small-order key is refused', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(IDENTITY) }, A('reject', 400, 'key_rejected')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: b64u(MIXED_ORDER) }, A('reject', 400, 'key_rejected')),
]);
seq('admin-create-invalid-params', 'malformed arguments are invalid_params', init(STD), [
  step('root', 'jack.admin.user.create', { name: 'bad name', public_key: pk('newbie') }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_before: 'x' }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.create', { name: 'dave', public_key: pk('newbie'), not_after: 1.5 }, A('reject', 400, 'invalid_params')),
]);
seq('admin-set-admin-grant', 'an administrator can grant admin', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: true }, A('accept')),
]);
seq('admin-set-admin-demote', 'an administrator can demote another administrator', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.admin2.kid, admin: false }, A('accept')),
]);
seq('admin-set-admin-self-demote-ok', 'an administrator can demote itself while another administrator remains', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('accept')),
]);
seq('admin-set-admin-last-admin', 'the last administrator cannot demote itself', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-set-admin-serialized-strip', 'two serialized demotions: the second must be rejected so the invariant holds (spec 03 section 9)', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.admin2.kid, admin: false }, A('accept')),
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-set-admin-invalid-params', 'the admin argument is required and must be a strict boolean', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: null }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: 1 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.user.set_admin', { kid: K.alice.kid, admin: 'yes' }, A('reject', 400, 'invalid_params')),
]);
seq('admin-set-admin-unknown-target', 'unknown kid', init(['root', 'alice']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.mallory.kid, admin: true }, A('reject', 404, 'unknown_target')),
]);
seq('admin-last-admin-counts-active-only', 'an expired admin does not count as an administrator', init(['root', 'expadmin']), [
  step('root', 'jack.admin.user.set_admin', { kid: K.root.kid, admin: false }, A('reject', 409, 'last_admin')),
]);
seq('admin-revoke-ok', 'revoke a user', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.alice.kid }, A('accept')),
  step('alice', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);
seq('admin-revoke-unknown', 'unknown kid', init(STD), [
  step('root', 'jack.admin.user.revoke', { kid: K.mallory.kid }, A('reject', 404, 'unknown_target')),
]);
seq('admin-revoke-other-admin', 'an administrator can revoke another administrator while one remains', init(['root', 'admin2', 'alice']), [
  step('root', 'jack.admin.user.revoke', { kid: K.admin2.kid }, A('accept')),
  step('admin2', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);
seq('admin-revoke-last-admin', 'the last admin cannot be revoked', init(['root', 'alice']), [
  step('root', 'jack.admin.user.revoke', { kid: K.root.kid }, A('reject', 409, 'last_admin')),
]);
seq('admin-revoke-self-ok', 'an admin can revoke itself while another admin remains', init(['root', 'admin2']), [
  step('root', 'jack.admin.user.revoke', { kid: K.root.kid }, A('accept')),
  step('root', 'jack.whoami', {}, A('reject', 401, 'unknown_key')),
]);

// administration: invites
seq('invite-create-ok', 'create an invite; the code is returned once', init(STD), [
  step('root', 'jack.admin.invite.create', {}, A('accept')),
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-create-options', 'ttl and key_ttl_seconds', init(STD), [
  step('root', 'jack.admin.invite.create', { ttl_seconds: 604800, key_ttl_seconds: 31536000 }, A('accept')),
]);
seq('invite-create-admin-invite', 'an admin invite is created and listed with admin true (inheritance on enrollment is covered by enroll-admin-invite)', init(['root']), [
  step('root', 'jack.admin.invite.create', { admin: true }, A('accept')),
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-create-invalid-params', 'ttl ranges and a mistyped admin', init(STD), [
  step('root', 'jack.admin.invite.create', { ttl_seconds: 604801 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { ttl_seconds: 0 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { ttl_seconds: 1.5 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { key_ttl_seconds: 31536001 }, A('reject', 400, 'invalid_params')),
  step('root', 'jack.admin.invite.create', { admin: 'yes' }, A('reject', 400, 'invalid_params')),
]);
seq('invite-list-live-only', 'expired invites are not listed', init(STD, { invites: [inv('live'), inv('old', { expires_at: NOW })] }), [
  step('root', 'jack.admin.invite.list', {}, A('accept')),
]);
seq('invite-revoke-ok', 'a revoked invite can no longer be used', init(STD, { invites: [inv('i1')] }), [
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('i1')) }, A('accept')),
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('invite-revoke-unknown', 'unknown or expired invite ids are unknown_target', init(STD, { invites: [inv('old', { expires_at: NOW })] }), [
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('nope')) }, A('reject', 404, 'unknown_target')),
  step('root', 'jack.admin.invite.revoke', { invite_id: inviteIdOf(codeOf('old')) }, A('reject', 404, 'unknown_target')),
]);
seq('admin-unknown-native-tool', 'an undefined jack.* tool is denied and not audited', init(STD), [
  step('root', 'jack.admin.nuke', {}, A('reject', 403, 'operation_denied')),
]);

// ---- cross-language edge cases. Kept at the end so the ids and vector
// positions of the core cases above stay stable and fixture diffs stay
// additions-only when new cases are added here. ----
export const B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
// A copy of a canonical base64url string that differs only in the two unused
// trailing bits of its last character: a lenient decoder yields the same bytes,
// a strict decoder rejects the encoding. Asserted here so the vector cannot rot.
export const withTrailingBits = (canonical) => {
  const idx = B64U_ALPHABET.indexOf(canonical[canonical.length - 1]);
  const variant = canonical.slice(0, -1) + B64U_ALPHABET[(idx + 1) % 64];
  if (!Buffer.from(variant, 'base64url').equals(Buffer.from(canonical, 'base64url'))) {
    throw new Error('trailing-bit variant must decode to the same bytes');
  }
  return variant;
};
export const withStandardAlphabet = (canonical) => `+${canonical.slice(1, 42)}/${canonical.slice(43)}`;
export const createRaw = (literal) => rawArg({ name: 'dave', public_key: pk('newbie') }, 'not_after', literal);
// A body with a root member whose name embeds the escaped path of the real
// argument; exact-key lookup must ignore it (a joined-path key would alias).
export const decoyBody = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":true,"ttl_seconds":60}},"params\\u0000arguments\\u0000ttl_seconds":1.0}';

// enrollment public_key encodings
seq('enroll-key-standard-alphabet', 'a public key using + and / is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', withStandardAlphabet(pk('newbie'))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-trailing-bits', 'a public key differing only in unused trailing bits is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', withTrailingBits(pk('newbie'))), A('reject', 400, 'key_rejected')),
]);
seq('enroll-key-whitespace', 'a public key with embedded whitespace is rejected', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', `${pk('newbie').slice(0, 21)} ${pk('newbie').slice(21)}`), A('reject', 400, 'key_rejected')),
]);

// Unknown-kid enrollment needs a live invite for `code` before anything else
// (spec 01 section 4, 03 section 3.2): every miss is the ordinary unknown_key,
// with no nonce recorded and no audit event.
seq('enroll-unknown-kid-no-invite', 'a well-formed self-signed enrollment with no invite in the state is unknown_key', init(['root']), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
]);
seq('enroll-unknown-kid-expired-invite', 'an invite with expires_at = now is not live: unknown_key, and a byte-identical retry is unknown_key again (no nonce was recorded)', init(['root'], { invites: [inv('i1', { expires_at: NOW })] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key')),
  { repeat: 0, want: A('reject', 401, 'unknown_key') },
]);
seq('enroll-unknown-kid-code-padded', 'a code with base64url padding is not canonical: unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key'), { body: call('jack.enroll', { code: `${codeOf('i1')}=`, name: 'newbie', public_key: pk('newbie') }) }),
]);
seq('enroll-unknown-kid-code-trailing-bits', 'a code differing only in unused trailing bits is not canonical: unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key'), { body: call('jack.enroll', { code: withTrailingBits(codeOf('i1')), name: 'newbie', public_key: pk('newbie') }) }),
]);
seq('enroll-unknown-kid-live-invite', 'a live invite lets the unknown kid enroll; only the matching invite is consumed', init(['root'], { invites: [inv('i1'), inv('live', { admin: true })] }), [
  step('newbie', 'jack.enroll', enrollArgs('live', 'newbie', pk('newbie')), A('accept')),
]);
seq('enroll-unknown-kid-bad-key-no-invite', 'an identity public key with no live invite is unknown_key, not key_rejected (the invite check comes first)', init(['root']), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', b64u(IDENTITY)), A('reject', 401, 'unknown_key'), { hdr: { kid: kidOf(IDENTITY) }, sign: { kid: kidOf(IDENTITY) } }),
]);
seq('enroll-unknown-kid-missing-public-key', 'a live invite but no public_key: unknown_key, not invalid_params', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: codeOf('i1'), name: 'newbie' }, A('reject', 401, 'unknown_key')),
]);
seq('enroll-unknown-kid-public-key-not-string', 'a live invite but a non-string public_key: unknown_key', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', { code: codeOf('i1'), name: 'newbie', public_key: 7 }, A('reject', 401, 'unknown_key')),
]);
seq('enroll-unknown-kid-live-invite-duplicate-member', 'a live invite but a duplicate member in the body: the body is not acceptable, so unknown_key (no nonce, no audit)', init(['root'], { invites: [inv('i1')] }), [
  step('newbie', 'jack.enroll', enrollArgs('i1', 'newbie', pk('newbie')), A('reject', 401, 'unknown_key'), { body: callRaw('jack.enroll', rawArg(enrollArgs('i1', 'newbie', pk('newbie')), 'name', '"newbie","name":"newbie"')) }),
]);

// rotation new-key argument encodings (spec 03 section 3.1)
seq('rotate-key-padded-encoding', 'a padded rotation public_key is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: `${pk('newbie')}=`, proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-standard-alphabet', 'a rotation public_key using + and / is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: withStandardAlphabet(pk('newbie')), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-trailing-bits', 'a rotation public_key with non-zero unused trailing bits is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: withTrailingBits(pk('newbie')), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-whitespace', 'a rotation public_key with embedded whitespace is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: `${pk('newbie').slice(0, 21)} ${pk('newbie').slice(21)}`, proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);
seq('rotate-key-wrong-length', 'a 31-byte rotation public_key is rejected', init(['root', 'alice']), [
  step('alice', 'jack.key.rotate', { public_key: b64u(K.newbie.pub.subarray(0, 31)), proof: rotateProof('newbie', 'alice') }, A('reject', 400, 'key_rejected')),
]);

// integer argument classes (spec 03 section 3)
for (const [id, description, literal] of [
  ['admin-create-not-after-fraction', 'a not_after of 1.5 is not an integer', '1.5'],
  ['admin-create-not-after-exponent', 'a not_after of 1e3 is not an integer', '1e3'],
  ['admin-create-not-after-negative', 'a negative not_after is out of range', '-1'],
  ['admin-create-not-after-above-max', 'a not_after above 999999999999 is out of range', '1000000000000'],
  ['admin-create-not-after-huge', 'a not_after beyond float64 precision is out of range', '9007199254740993'],
]) {
  seq(id, description, init(['root']), [
    step('root', 'jack.admin.user.create', createRaw(literal), A('reject', 400, 'invalid_params')),
  ]);
}
seq('admin-create-not-after-negative-zero', 'a not_after of -0 is the integer 0 and accepted', init(['root']), [
  step('root', 'jack.admin.user.create', createRaw('-0'), A('accept')),
]);
for (const [id, description, literal] of [
  ['invite-create-ttl-fraction', 'a ttl_seconds of 1.0 is not an integer', '1.0'],
  ['invite-create-ttl-exponent', 'a ttl_seconds of 1e3 is not an integer', '1e3'],
  ['invite-create-ttl-negative-zero', 'a ttl_seconds of -0 is the integer 0, below the minimum', '-0'],
  ['invite-create-ttl-string', 'a ttl_seconds in a JSON string is not a number', '"60"'],
  ['invite-create-ttl-boolean', 'a boolean ttl_seconds is not a number', 'true'],
  ['invite-create-ttl-huge', 'a ttl_seconds beyond float64 precision is out of range', '9007199254740993'],
]) {
  seq(id, description, init(['root']), [
    step('root', 'jack.admin.invite.create', rawArg({}, 'ttl_seconds', literal), A('reject', 400, 'invalid_params')),
  ]);
}
seq('invite-create-ttl-decoy-member', 'a decoy member cannot override the ttl_seconds number text', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: decoyBody, model: { admin: true, ttl_seconds: 60 } }),
]);
seq('invite-create-ttl-dup-invalid-then-valid', 'a duplicated ttl_seconds member makes the body unacceptable (1.5 then 60): invalid_request after authentication, state unchanged, no tool audit', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":1.5,"ttl_seconds":60}}}' }),
]);
seq('invite-create-ttl-dup-valid-then-invalid', 'the same duplicated pair in the other order (60 then 1.5) is equally unacceptable', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":60,"ttl_seconds":1.5}}}' }),
]);
seq('invite-create-arguments-dup-invalid-then-valid', 'a duplicated arguments object makes the body unacceptable (mistyped admin, then valid arguments)', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":"true"},"arguments":{"admin":true,"ttl_seconds":60}}}' }),
]);
seq('invite-create-arguments-dup-valid-then-invalid', 'the same duplicated arguments in the other order (valid, then mistyped admin) is equally unacceptable', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":true,"ttl_seconds":60},"arguments":{"admin":"true"}}}' }),
]);
seq('invite-create-arguments-dup-disjoint', 'duplicated arguments objects with disjoint members are not merged or resolved: the body is unacceptable', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"admin":"true"},"arguments":{"ttl_seconds":60}}}' }),
]);
seq('invite-create-params-nested-dup', 'a duplicate member in params next to a well-formed arguments object makes the body unacceptable', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":60},"_meta":1,"_meta":2}}' }),
]);
seq('invite-create-ttl-dup-escaped-name', 'ttl_seconds and its \\u005f-escaped spelling in one arguments object are duplicates', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('reject', 400, 'invalid_request'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":60,"ttl\\u005fseconds":61}}}' }),
]);
seq('invite-create-same-name-in-nested-object', 'the same member name in different objects is not a duplicate: the nested ttl_seconds does not touch the real one', init(['root']), [
  step('root', 'jack.admin.invite.create', undefined, A('accept'), { body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"ttl_seconds":60,"meta":{"ttl_seconds":1.5}}}}', model: { ttl_seconds: 60 } }),
]);

// Run every sequence against the reference verifier. The expectation is built
// from the shadow model BEFORE the step runs; the verifier decides nothing
// about it and must agree on every field.
export const sequenceVectors = SEQUENCES.map(({ id, description, init: ini, steps }) => {
  const registry = ini.names.map((n) => entryOf(n));
  const invites = ini.invites ?? [];
  const state = materialize({ registry, invites });
  const shadow = shadowInit(ini);
  const generated = new Set();
  const hooks = {
    newCode(s) {
      const code = defaultHooks.newCode(s);
      generated.add(code);
      generated.add(inviteIdOf(code));
      return code;
    },
  };
  const built = [];
  const out = steps.map((s, i) => {
    let request;
    let signing;
    const key = s.key ?? steps[s.repeat].key; // a repeated step signs as the original key
    if (s.repeat !== undefined) {
      ({ request, signing } = built[s.repeat]);
    } else {
      const body = s.method === 'GET' ? '' : typeof s.body === 'string' ? s.body : typeof s.args === 'string' ? callRaw(s.tool, s.args) : call(s.tool, s.args);
      const r = buildRequest(`${id}#${i}`, {
        key: s.key, method: s.method, body, ts: s.ts, signKey: s.signKey, hdr: s.hdr, sign: s.sign,
      });
      request = r.req;
      signing = r.signing;
      built.push({ request, signing });
    }
    if (s.repeat !== undefined) built.push({ request, signing });
    const expect = expectStep(shadow, generated, s, key, s.want);
    const rawBefore = rawDurable(state);
    const got = verifyRequest(request, state, hooks);
    agree(`${id}#${i}`, expectOf(got, generated, { after: durableState(state, generated) }), expect);
    // Exact no-mutation for rejections, checked against raw durable data:
    // absent vs null vs false must stay distinct. Nonce-cache movement is
    // intended on post-auth rejections and is deliberately not part of this
    // check. Accepted steps legitimately mutate; they are covered by the
    // durable compare and the post-sequence reader check.
    if (got.result === 'reject' && !deepEqual(rawDurable(state), rawBefore)) {
      throw new Error(`${id}#${i}: a rejected step mutated durable state`);
    }
    return { request, expect, debug: { signing_string_lines: signing.split('\n') } };
  });
  // Producer -> serialization -> reader: the final durable state is written to
  // state-file JSON text and decoded again before the reference reader runs, so
  // a record that only breaks when written and re-read cannot pass as a live
  // object pass-through.
  const serialized = `${JSON.stringify({ version: 1, keys: state.registry.keys, invites: state.invites }, null, 2)}\n`;
  const decoded = JSON.parse(serialized);
  const reader = validateStateFile(decoded);
  if (reader !== null) throw new Error(`${id}: persisted state fails the state-file reader: ${reader}`);
  if (id === 'invite-create-ok') {
    const created = decoded.invites.find((r) => generated.has(r.invite_id));
    if (!created || 'key_ttl_seconds' in created) throw new Error('invite-create-ok: default invite must persist without key_ttl_seconds');
  }
  return {
    id, description,
    state: { now: NOW, window_seconds: WINDOW, aud: AUD, registry, invites, nonce_cache: [] },
    steps: out,
  };
});

// ---- public-key vectors ----