import { sign } from 'node:crypto';
import { b64u, responseSigningString, verifyResponse, forgeSmallOrderRSig } from '../reference-verifier.mjs';
import { NOW, WINDOW, K, nonceOf, sigOf, buildRequest } from './core.mjs';
import { STATUS } from './requests.mjs';
import { A } from './sequences.mjs';

export const base = buildRequest('accept-read-status', { body: STATUS });
export const REQ_SIG = base.sig;
export const OK_BODY = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

export function buildResponse(o = {}) {
  const { status = 200, body = OK_BODY, ts = NOW, signKey = 'svc', kid = K.svc.kid } = o;
  const fields = { status, reqSig: REQ_SIG, kid: K.svc.kid, ts, body: Buffer.from(body), ...o.sign };
  const message = responseSigningString(fields);
  // A signature forged with R = the identity encoding: it satisfies the
  // verification equation, so only the small-order-R rule can reject it
  // (spec 01 section 2). The default 'svc' signer is the pinned key.
  const sig = o.smallR
    ? b64u(forgeSmallOrderRSig(K.svc.seed, K.svc.pub, Buffer.from(message, 'utf8')))
    : sigOf(signKey, message);
  const h = { kid, ts, sig, ...o.hdr };
  let header = `v1 kid=${h.kid},ts=${h.ts},sig=${h.sig}`;
  if (o.mutate) header = o.mutate(header);
  const sent = Buffer.from(o.send?.body ?? body);
  return {
    status: o.send?.status ?? status,
    headers: o.noHeader ? [] : [['Jack-Auth', header]],
    body_b64u: b64u(sent),
    ...(sent.length ? { body_text: sent.toString('utf8') } : {}),
  };
}

export const RESPONSE_CASES = [
  ['res-accept', 'valid response', {}, ['accept']],
  ['res-accept-empty-body', '204 with empty body', { status: 204, body: '' }, ['accept']],
  ['res-accept-ts-boundary-past', 'ts = now - window', { ts: NOW - WINDOW }, ['accept']],
  ['res-accept-ts-boundary-future', 'ts = now + window', { ts: NOW + WINDOW }, ['accept']],
  ['res-missing-header', 'no Jack-Auth header', { noHeader: true }, ['reject', 'missing_auth']],
  ['res-unsupported-version', 'version v2', { mutate: (v) => `v2${v.slice(2)}` }, ['reject', 'unsupported_version']],
  ['res-malformed-nonce-param', 'nonce is not a response parameter', { mutate: (v) => `${v},nonce=${nonceOf('x')}` }, ['reject', 'malformed_auth']],
  ['res-unknown-server-key', 'kid is not the pinned server key', { signKey: 'mallory', hdr: { kid: K.mallory.kid } }, ['reject', 'unknown_server_key']],
  ['res-ts-too-old', 'ts = now - window - 1', { ts: NOW - WINDOW - 1 }, ['reject', 'timestamp_out_of_window']],
  ['res-ts-too-new', 'ts = now + window + 1', { ts: NOW + WINDOW + 1 }, ['reject', 'timestamp_out_of_window']],
  ['res-tampered-body', 'body changed after signing', { send: { body: '{"jsonrpc":"2.0","id":1,"result":{"ok":false}}' } }, ['reject', 'bad_signature']],
  ['res-tampered-status', 'status changed after signing', { send: { status: 500 } }, ['reject', 'bad_signature']],
  ['res-wrong-request-binding', 'signed over a different request signature', { sign: { reqSig: b64u(Buffer.alloc(64, 7)) } }, ['reject', 'bad_signature']],
  ['res-wrong-key-with-pinned-kid', 'pinned kid, signed by another key', { signKey: 'mallory' }, ['reject', 'bad_signature']],
  ['res-small-order-r-identity', 'a response signature whose R is the identity encoding is rejected (spec 01 section 2)', { smallR: true }, ['reject', 'bad_signature']],
];

export const resState = () => ({
  now: NOW, window_seconds: WINDOW, pinned_server_kid: K.svc.kid,
  pinned_server_public_key: K.svc.public_key, request_sig: REQ_SIG,
});

export const responseVectors = RESPONSE_CASES.map(([id, desc, opts, want]) => {
  const response = buildResponse(opts);
  const got = verifyResponse(response, resState());
  if (got.result !== want[0] || got.code !== want[1]) {
    throw new Error(`${id}: reference verifier disagrees: ${JSON.stringify(got)} vs ${JSON.stringify(want)}`);
  }
  const expect = want[0] === 'accept' ? { result: 'accept' } : { result: 'reject', code: want[1] };
  return { id, description: desc, state: resState(), response, expect };
});

// ---- output ----