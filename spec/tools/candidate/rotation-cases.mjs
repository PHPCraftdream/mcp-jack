import { base64url } from './crypto.mjs';
import { signRecord, keyOfName } from './rotation-encode.mjs';

export const ENDPOINT = 'https://svc.example.test/mcp';
export const AUDIENCE = 'https://svc.example.test';
export const ROTATION_KEYS = Object.freeze({
  anchor: keyOfName('candidate-server-anchor'),
  next1: keyOfName('candidate-server-next1'),
  next2: keyOfName('candidate-server-next2'),
  next3: keyOfName('candidate-server-next3'),
  other: keyOfName('candidate-server-other'),
});
const make = (ordinal, previousHash, oldSigner, newSigner, publishedAt, extra = {}) => signRecord({ endpoint: ENDPOINT, aud: AUDIENCE, ordinal, previousHash, oldSigner, newSigner, publishedAt, ...extra });
const r1 = make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000);
const r2 = make(2, r1.hash, ROTATION_KEYS.next1, ROTATION_KEYS.next2, 4600);
const tieR1 = make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000);
const tieR2 = make(2, tieR1.hash, ROTATION_KEYS.next1, ROTATION_KEYS.next2, 1000);
const wrongP = make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 2000);
const decreasingP = make(2, wrongP.hash, ROTATION_KEYS.next1, ROTATION_KEYS.next2, 1000);
const gapOrdinal = make(2, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next2, 1000);
const wrongHash = make(1, base64url(Buffer.alloc(32, 7)), ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000);
const badAdjacency = make(2, r1.hash, ROTATION_KEYS.anchor, ROTATION_KEYS.next2, 4600);
const reusedAnchor = signRecord({ endpoint: ENDPOINT, aud: AUDIENCE, ordinal: 1, previousHash: '-', oldSigner: ROTATION_KEYS.anchor, newSigner: ROTATION_KEYS.anchor, publishedAt: 1000 });
const wrongKid = signRecord({ endpoint: ENDPOINT, aud: AUDIENCE, ordinal: 1, previousHash: '-', oldSigner: ROTATION_KEYS.anchor, newSigner: ROTATION_KEYS.next1, publishedAt: 1000, overrides: { newKid: ROTATION_KEYS.other.kid } });
const wrongActivation = make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000, { activatesAt: 173801 });
const overflowActivation = make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 999999999999);
const wrongDomainText = r1.wireText.replace('mcp-jack/server-key-rotation/min1', 'mcp-jack/server-key-rotation/min2');
const paddedKeyText = r1.wireText.replace(ROTATION_KEYS.next1.publicKeyB64u, `${ROTATION_KEYS.next1.publicKeyB64u}=`);
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const lastKidIndex = alphabet.indexOf(ROTATION_KEYS.anchor.kid.at(-1));
const noncanonicalKidText = r1.wireText.replace(ROTATION_KEYS.anchor.kid, `${ROTATION_KEYS.anchor.kid.slice(0, -1)}${alphabet[lastKidIndex | 1]}`);
const trailingLF = `${r1.wireText}\n`;
const nonAscii = Buffer.concat([r1.wire, Buffer.from([0xff])]);
const oversized = Buffer.concat([r1.wire, Buffer.alloc(8192, 0x41)]);
const leadingZero = r1.wireText.replace('\n1\n', '\n01\n');
const newProofStart = r1.wireText.lastIndexOf('\n', r1.wireText.lastIndexOf('\n') - 1) + 1;
const newProofEnd = r1.wireText.indexOf('\n', newProofStart);
const newProofRaw = Buffer.from(r1.wireText.slice(newProofStart, newProofEnd), 'base64url');
newProofRaw[0] ^= 1;
const newProofText = base64url(newProofRaw);
const signedNewProofText = r1.wireText.slice(0, newProofStart) + newProofText + r1.wireText.slice(newProofEnd);
const oldProofStart = r1.wireText.lastIndexOf('\n') + 1;
const oldProofRaw = Buffer.from(r1.wireText.slice(oldProofStart), 'base64url');
oldProofRaw[0] ^= 1;
const oldProofText = r1.wireText.slice(0, oldProofStart) + base64url(oldProofRaw);
const signedOldProofText = Buffer.from(oldProofText, 'ascii');
const item = (id, wire, expected, description, binding = { endpoint: ENDPOINT, aud: AUDIENCE }, setup = 'single') => ({
  id, expected, description, binding, setup, wire_b64u: base64url(Buffer.from(wire)), wire_ascii: Buffer.from(wire).toString('ascii'),
});

export const ROTATION_KEYS_PUBLIC = Object.fromEntries(Object.entries(ROTATION_KEYS).map(([name, key]) => [name, { public_key: key.publicKeyB64u, kid: key.kid }]));
export const ROTATION_VALID = Object.freeze({
  overlapping: [r1, r2].map((record) => record.wireText),
  tie: [tieR1, tieR2].map((record) => record.wireText),
});
export const ROTATION_NEGATIVE = Object.freeze([
  item('bad-domain', wrongDomainText, 'domain', 'wrong exact domain'),
  item('binding-endpoint', make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000, { endpoint: `${ENDPOINT}/` }).wire, 'binding', 'endpoint differs by one trailing slash'),
  item('binding-audience', make(1, '-', ROTATION_KEYS.anchor, ROTATION_KEYS.next1, 1000, { aud: `${AUDIENCE}/` }).wire, 'binding', 'audience differs by one trailing slash'),
  item('ordinal-gap', gapOrdinal.wire, 'ordinal_sequence', 'ordinal starts at 2 with valid proof; verify as chain', { endpoint: ENDPOINT, aud: AUDIENCE }, 'chain'),
  item('ordinal-leading-zero', leadingZero, 'ordinal', 'ordinal has a leading zero'),
  item('previous-full-hash', wrongHash.wire, 'previous_hash', 'wrong previous complete record digest; verify as chain', { endpoint: ENDPOINT, aud: AUDIENCE }, 'chain'),
  item('adjacent-authorizer', badAdjacency.wire, 'adjacency', 'R2 is validly signed by known K0 but violates the sequential K0>K1 authorization edge', { endpoint: ENDPOINT, aud: AUDIENCE }, 'after-r1'),
  item('new-key-id', wrongKid.wire, 'new_key_id', 'new kid does not hash the new admitted key'),
  item('activation-arithmetic', wrongActivation.wire, 'activation', 'activation differs from checked P+172800'),
  item('timestamp-overflow', overflowActivation.wire, 'timestamp', 'checked P+172800 exceeds 12-digit domain'),
  item('new-possession-proof', signedNewProofText, 'new_proof', 'new proof signature byte changed while encoding remains canonical'),
  item('old-authorization-proof', signedOldProofText, 'old_authorization', 'old authorization signature byte changed while encoding remains canonical'),
  item('base64url-padding', paddedKeyText, 'base64url', 'public key has padding'),
  item('key-id-unused-bits', noncanonicalKidText, 'key_id', 'kid has nonzero unused base64url bits'),
  item('trailing-lf', trailingLF, 'trailing_lf', 'record has terminal line feed'),
  item('invalid-utf8', nonAscii, 'non_ascii', 'invalid non-ASCII byte'),
  item('record-size-cap', oversized, 'record_size', 'decoded record exceeds 8192 bytes'),
  item('retained-key-reuse', reusedAnchor.wire, 'key_reuse', 'R1 has valid proof and predecessor authorization but repeats K0', { endpoint: ENDPOINT, aud: AUDIENCE }, 'chain'),
  item('decreasing-publication-time', decreasingP.wire, 'publication_order', 'P2<P1 with valid adjacent proofs; verify as chain', { endpoint: ENDPOINT, aud: AUDIENCE }, 'decreasing'),
]);

export const rotationRecordsForVerification = Object.freeze({ r1, r2, tieR1, tieR2, wrongP, decreasingP, gapOrdinal, wrongHash, badAdjacency, reusedAnchor });
