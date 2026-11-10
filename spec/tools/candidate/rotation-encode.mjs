import { base64url, keyId, publicFromSeed, sha256, signSeed, testSeed } from './crypto.mjs';

export const ROTATION_DOMAIN = 'mcp-jack/server-key-rotation/min1';
export const GRACE = 172800;
const ascii = (text) => Buffer.from(text, 'ascii');
const utf8 = (text) => Buffer.from(text, 'utf8');

export const keyOfName = (name) => {
  const seed = testSeed(name);
  const publicKey = publicFromSeed(seed);
  return { name, seed, publicKey, publicKeyB64u: base64url(publicKey), kid: keyId(publicKey) };
};

export const encodeBody = ({ endpoint, aud, ordinal, previousHash, oldKid, newKid, publicKey, publishedAt, activatesAt, domain = ROTATION_DOMAIN }) => Buffer.from([
  domain,
  base64url(utf8(endpoint)),
  base64url(utf8(aud)),
  String(ordinal),
  previousHash,
  oldKid,
  newKid,
  base64url(publicKey),
  String(publishedAt),
  String(activatesAt),
].join('\n'), 'ascii');

export const signRecord = ({ endpoint, aud, ordinal, previousHash, oldSigner, newSigner, publishedAt, activatesAt = publishedAt + GRACE, overrides = {} }) => {
  const values = {
    endpoint, aud, ordinal, previousHash,
    oldKid: oldSigner.kid,
    newKid: newSigner.kid,
    publicKey: newSigner.publicKey,
    publishedAt,
    activatesAt,
    ...overrides,
  };
  const b = encodeBody(values);
  const proofNew = signSeed(newSigner.seed, Buffer.concat([ascii(`${ROTATION_DOMAIN}/next-proof\n`), b]));
  const proofNew64 = base64url(proofNew);
  const oldMessage = Buffer.concat([ascii(`${ROTATION_DOMAIN}/authorize\n`), b, ascii(`\n${proofNew64}`)]);
  const proofOld = signSeed(oldSigner.seed, oldMessage);
  const wire = Buffer.concat([b, ascii(`\n${proofNew64}\n${base64url(proofOld)}`)]);
  return {
    b,
    wire,
    wireText: wire.toString('ascii'),
    hash: base64url(sha256(wire)),
    fields: { ...values, publicKeyB64u: base64url(values.publicKey) },
    proofNew,
    proofOld,
  };
};
