import test from 'node:test';
import assert from 'node:assert/strict';
import { base64url, keyId, publicFromSeed, sha256, signSeed, testSeed, verifyNode, RFC8032_TEST } from '../../tools/candidate/crypto.mjs';
import { pureVerifier, runCryptoKats } from '../../tools/candidate/independent-checks.mjs';
import { ROTATION_KEYS_PUBLIC, ROTATION_NEGATIVE, ROTATION_VALID, rotationRecordsForVerification, ENDPOINT, AUDIENCE } from '../../tools/candidate/rotation-cases.mjs';
import { verifyChain, parseRecord, selectedOrdinal, assignmentValid, encodeB } from '../../tools/candidate/rotation-codec.mjs';
import { parseRefreshArguments, verifyRequestSignature, verifyResponseSignature } from '../../tools/candidate/verification.mjs';

const named = (name) => {
  const seed = testSeed(name);
  const publicKey = publicFromSeed(seed);
  return { seed, publicKey, kid: keyId(publicKey) };
};

test('RFC 8032 known-answer signature agrees with independent pure verifier and Node verifier', () => {
  assert.equal(runCryptoKats().signature, RFC8032_TEST.signature);
  const publicKey = publicFromSeed(Buffer.from(RFC8032_TEST.seed, 'hex'));
  const signature = Buffer.from(RFC8032_TEST.signature, 'hex');
  assert.equal(publicKey.toString('hex'), RFC8032_TEST.publicKey);
  assert.equal(verifyNode(publicKey, Buffer.alloc(0), signature), true);
  assert.equal(pureVerifier(publicKey, Buffer.alloc(0), signature), true);
});

test('candidate codec signs exact ten-line B and twelve-line R without trailing LF', () => {
  const anchor = Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url');
  const chain = verifyChain(ROTATION_VALID.overlapping.map((wire) => Buffer.from(wire, 'ascii')), { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
  assert.equal(chain.ok, true);
  assert.deepEqual(chain.records.map((r) => [r.ordinal, r.publishedAt, r.activatesAt]), [[1, 1000, 173800], [2, 4600, 177400]]);
  const r1 = rotationRecordsForVerification.r1;
  assert.equal(r1.b.toString('ascii').split('\n').length, 10);
  assert.equal(r1.wireText.split('\n').length, 12);
  assert.equal(r1.wireText.endsWith('\n'), false);
  assert.equal(encodeB({ endpoint: ENDPOINT, aud: AUDIENCE, ...r1.fields, newPublicKey: r1.fields.publicKey }).equals(r1.b), true);
  assert.equal(r1.hash, base64url(sha256(r1.wire)));
  const tie = verifyChain(ROTATION_VALID.tie.map((wire) => Buffer.from(wire, 'ascii')), { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
  assert.equal(selectedOrdinal(tie.records, 173800), 2);
  assert.equal(assignmentValid(tie.records, 1, 173800), false);
});

test('negative rotation corpus reaches parser and chain verifier at expected errors', () => {
  const anchor = Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url');
  const keys = new Map(Object.values(ROTATION_KEYS_PUBLIC).map((key) => [key.kid, Buffer.from(key.public_key, 'base64url')]));
  for (const row of ROTATION_NEGATIVE) {
    const wire = Buffer.from(row.wire_b64u, 'base64url');
    const got = row.setup === 'chain'
      ? verifyChain([wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor })
      : row.setup === 'after-r1'
        ? verifyChain([Buffer.from(ROTATION_VALID.overlapping[0], 'ascii'), wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor })
        : row.setup === 'decreasing'
          ? verifyChain([Buffer.from(rotationRecordsForVerification.wrongP.wireText, 'ascii'), wire], { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor })
          : parseRecord(wire, { endpoint: row.binding.endpoint, aud: row.binding.aud, authorizers: keys });
    assert.deepEqual({ ok: got.ok, code: got.code }, { ok: false, code: row.expected }, row.id);
  }
});

test('new signer lower activation is inclusive and earlier timestamps cannot be assigned', () => {
  const anchor = Buffer.from(ROTATION_KEYS_PUBLIC.anchor.public_key, 'base64url');
  const chain = verifyChain(ROTATION_VALID.overlapping.map((wire) => Buffer.from(wire, 'ascii')), { endpoint: ENDPOINT, aud: AUDIENCE, anchorKid: ROTATION_KEYS_PUBLIC.anchor.kid, anchorPublicKey: anchor });
  assert.equal(assignmentValid(chain.records, 1, 173800), true);
  assert.equal(assignmentValid(chain.records, 1, 173799), false);
  assert.equal(assignmentValid(chain.records, 1, 177400), false);
});

test('strict server-key cursor rejects duplicate fields, exponent/fraction integers, and inconsistent anchor cursor', () => {
  assert.deepEqual(parseRefreshArguments('{"after_ordinal":0,"after_hash":"-"}').value, { after_ordinal: 0, after_hash: '-' });
  for (const raw of ['{"after_ordinal":0,"after_hash":"-","after_hash":"-"}', '{"after_ordinal":1e0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":1.0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":0,"after_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}', '{"after_ordinal":0,"after_hash":"-","extra":true}']) assert.equal(parseRefreshArguments(raw).code, 'invalid_params');
});

test('v1 request and response authentication use exact raw bytes and reject tampering', () => {
  const signer = named('candidate-raw-signature');
  const nonce = base64url(Buffer.alloc(16, 6));
  const body = Buffer.from('request bytes');
  const message = Buffer.from(['mcp-jack/v1/request', 'POST', '/mcp?raw=1', AUDIENCE, signer.kid, '1000', nonce, base64url(sha256(body))].join('\n'));
  const signature = base64url(signSeed(signer.seed, message));
  const checked = verifyRequestSignature({ request: { method: 'POST', target: '/mcp?raw=1', aud: AUDIENCE, kid: signer.kid, ts: 1000, nonce, body, signature }, publicKey: signer.publicKey });
  assert.equal(checked.ok, true);
  assert.deepEqual(checked.signingBytes, message);
  assert.equal(pureVerifier(signer.publicKey, message, Buffer.from(signature, 'base64url')), true);
  const tampered = verifyRequestSignature({ request: { method: 'POST', target: '/mcp?raw=1', aud: AUDIENCE, kid: signer.kid, ts: 1000, nonce, body: Buffer.from('changed'), signature }, publicKey: signer.publicKey });
  assert.equal(tampered.reason, 'bad_signature');
  const responseBody = Buffer.from('response bytes');
  const responseMessage = Buffer.from(['mcp-jack/v1/response', '200', signature, signer.kid, '1000', base64url(sha256(responseBody))].join('\n'));
  const responseSignature = base64url(signSeed(signer.seed, responseMessage));
  assert.equal(verifyResponseSignature({ response: { status: 200, requestSig: signature, kid: signer.kid, ts: 1000, body: responseBody, signature: responseSignature }, publicKey: signer.publicKey }).ok, true);
});
