// Shared constants and builders for the s1 stream vectors (spec 05).
import { NOW, WINDOW, K, buildRequest } from '../../gen/core.mjs';
import {
  b64u,
  sha256,
  buildStream,
  dataHash,
  frameSigningString,
  serializeFrame,
  signMessage,
} from './reference.mjs';

export const SVC = K.svc; // pinned server stream key
export const ALT = K.mallory; // valid key, never pinned

// 2.4: sid is 16 random bytes, base64url encoded.
export const sidOf = (label) => b64u(sha256(`stream sid: ${label}`).subarray(0, 16));
export const SID = sidOf('primary');
export const SID2 = sidOf('other');

// 9: the JSON-RPC id of the request that opened the stream (6.3).
export const REQUEST_ID = 1;
export const REQUEST_ID2 = 2;

export const OPEN_BODY = '{"jsonrpc":"2.0","id":' + REQUEST_ID + ',"method":"events/stream","params":{"name":"email.received","arguments":{}}}';
export const OPEN2_BODY = '{"jsonrpc":"2.0","id":' + REQUEST_ID2 + ',"method":"events/stream","params":{"name":"email.received","arguments":{}}}';

// 2.5: the open header binds to the v1 request sig of the opening request.
export const REQ_SIG = buildRequest('accept-stream-open', { body: OPEN_BODY }).sig;
export const REQ_SIG2 = buildRequest('accept-stream-open-2', { body: OPEN2_BODY }).sig;

export const prog = (n) => `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":${n}}}`;
export const MSG = prog(1);
export const MSG2 = prog(2);
export const MSG3 = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

export const MAX_FRAME = 1048576; // 3.2 default frameMaxBytes

// One signed stream: the open header value plus every frame signature.
export const signChain = ({
  sid = SID,
  kid = SVC.kid,
  privKey = SVC.priv,
  requestSig = REQ_SIG,
  status = 200,
  openTs = NOW,
  frames,
}) => buildStream({ privKey, kid, sid, status, requestSig, openTs, frames });

// An opener with no frames; its open sig is the chain root of a hand-built body.
export const openOnly = (over = {}) => signChain({ frames: [], ...over });

// Frames of 2.15 chained from `prev` and signed by the pinned key. A `prev` or
// `sid` that disagrees with the open header keeps every frame self-consistent
// but breaks the stream at 4.3 step 5.
export const chainFrom = ({ prev, sid = SID, frames }) => {
  let last = prev;
  const signed = [];
  const body = [];
  for (const { seq, ts, data } of frames) {
    const kind = data === '' ? 'jack-end' : 'message';
    const data_hash = dataHash(data);
    const signing_string = frameSigningString({ sid, seq, ts, prev: last, hash: data_hash });
    const sig = signMessage(SVC.priv, signing_string);
    signed.push({ seq, ts, prev: last, data_hash, signing_string, sig });
    body.push(serializeFrame({ kind, data, seq, ts, sig }));
    last = sig;
  }
  return { body: body.join(''), frames: signed };
};

export const authHeaders = (jackAuth, extra = []) => [
  ['Content-Type', 'text/event-stream'],
  ['X-Accel-Buffering', 'no'],
  ['Jack-Auth', jackAuth],
  ...extra,
];

export const baseState = (over = {}) => ({
  now: NOW,
  window_seconds: WINDOW,
  pinned_server_kid: SVC.kid,
  pinned_server_public_key: SVC.public_key,
  request_sig: REQ_SIG,
  request_id: REQUEST_ID,
  successor_activation: null,
  frame_max_bytes: MAX_FRAME,
  ...over,
});

// chunks holds base64url body pieces; `expect` is supplied by the caller and
// is never derived from the reference implementation.
export const clientVector = (
  id,
  description,
  { state, status = 200, headers, chunks, expect, silent_after_ms, consumer, data_fill },
) => ({
  id,
  description,
  state,
  response: { status, headers, stream_b64u: chunks },
  expect,
  ...(silent_after_ms !== undefined ? { silent_after_ms } : {}),
  ...(consumer !== undefined ? { consumer } : {}),
  ...(data_fill !== undefined ? { data_fill } : {}),
});

// One frame's exact bytes, for hand-assembled bodies.
export const frameOf = (signed, kind, data) =>
  serializeFrame({ kind, data, seq: signed.seq, ts: signed.ts, sig: signed.sig });

export const bytes = (str) => Buffer.from(str, 'utf8');
export const chunk = (buf) => b64u(buf);

// Character 40 of an 86-char sig: the length and the canonical trailing bits
// survive, the signature does not (4.2 step 7).
export const flipMid = (sig) => `${sig.slice(0, 40)}${sig[40] === 'A' ? 'B' : 'A'}${sig.slice(41)}`;

// Frame size of 2.17 for one signed frame written with `data`.
export const frameSizeOf = (signed, kind, data) =>
  serializeFrame({ kind, data, seq: signed.seq, ts: signed.ts, sig: signed.sig }).length;

// Section 9 data_fill: one long repeated-byte data value is replaced by the
// marker, so the vector file stays small.
export const MARKER = '@data_fill@';
export const dataFill = (count, byte = 'x') => ({ byte, count });
// 9 expect.messages marker form of one delivered message.
export const fillMessage = (count, byte = 'x') => ({ data_fill: { byte, count } });
export const markerChunks = (body, fill) => {
  const at = body.indexOf(fill);
  if (at < 0) throw new Error(`markerChunks: no ${fill}`);
  return [b64u(bytes(body.slice(0, at))), MARKER, b64u(bytes(body.slice(at + fill.length)))];
};

// 2.18 transport signal, 3.5 heartbeat and the 6.3 final response.
export const SIGNAL_AT = (code, limitText) => '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"' + code + '","limit":' + limitText + '}}';
export const SIGNAL = (limit) => SIGNAL_AT('stream_frame_too_large', limit);
export const HEARTBEAT = '{"jsonrpc":"2.0","method":"notifications/events/heartbeat","params":{"cursor":null,"_meta":{"io.modelcontextprotocol/subscriptionId":1}}}';
export const EVENTS_RESULT = (id) => '{"jsonrpc":"2.0","id":' + id + ',"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":' + id + '}}}';
// 6.3 lookalikes: each one leaves the MCP request incomplete.
export const RESULT_WRONG_ID = EVENTS_RESULT(REQUEST_ID2);
export const RESULT_NO_JSONRPC = '{"id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}';
export const RESULT_BOTH = '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"x"}}';
export const RESULT_BAD_ID_TYPE = '{"jsonrpc":"2.0","id":"1","result":{}}';
