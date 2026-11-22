// Client vectors for the open-header checks of spec 05 sections 4.2 and 4.5.
// Every opener here fails a step of 4.2, so no frame is read and nothing is
// delivered. Each body is nonetheless a complete stream chained from that same
// opener's sig, so a verifier that wrongly accepts the opener would deliver a
// message instead of ending in truncation.
import { NOW, WINDOW } from '../../../gen/core.mjs';
import { b64u, sha256 } from '../reference.mjs';
import {
  ALT,
  MSG,
  REQ_SIG,
  REQ_SIG2,
  SID,
  SVC,
  authHeaders,
  baseState,
  bytes,
  chainFrom,
  chunk,
  clientVector,
  flipMid,
  openOnly,
} from '../fixtures.mjs';

const NONCE_EXTRA = b64u(sha256('stream nonce: extra').subarray(0, 16));
const BAD_SID = b64u(sha256('stream sid: bad').subarray(0, 15));

// One message frame then the end frame, for every vector.
const FRAMES = [{ seq: 0, ts: NOW, data: MSG }, { seq: 1, ts: NOW, data: '' }];

// The chain root is the sig in the header (2.15). Signing is deterministic, so
// the same arguments name the same opener for the header and for the body.
const stream = (over = {}) => chainFrom({ prev: openOnly(over).open_sig, sid: over.sid ?? SID, frames: FRAMES });
const auth = (over = {}) => authHeaders(openOnly(over).jack_auth);
const one = (body) => [chunk(bytes(body))];

// 2.3: only the leading scheme changes, the parameters stay valid.
const withScheme = (jack, scheme) => scheme + jack.slice(2);

// Replace the trailing sig value of an open header, keeping the rest.
const withSig = (jack, sig) => `${jack.slice(0, jack.lastIndexOf('=') + 1)}${sig}`;

const err = (code) => ({ messages: [], terminal: { state: 'error', code, frames_verified: 0 } });

const GOOD = openOnly();
const FLIPPED = flipMid(GOOD.open_sig);

export const openVectors = [
  clientVector('stream-open-missing-auth', 'no Jack-Auth header at all', {
    state: baseState(),
    headers: [['Content-Type', 'text/event-stream'], ['X-Accel-Buffering', 'no']],
    chunks: one(stream().body),
    expect: err('stream_missing_auth'),
  }),
  clientVector('stream-open-duplicate-auth', 'two Jack-Auth lines, each a valid open value', {
    state: baseState(),
    headers: authHeaders(GOOD.jack_auth, [['jack-auth', GOOD.jack_auth]]),
    chunks: one(stream().body),
    expect: err('stream_malformed_auth'),
  }),
  clientVector('stream-open-extra-param', 'a fifth parameter appended to a valid open value', {
    state: baseState(),
    headers: authHeaders(`${GOOD.jack_auth},nonce=${NONCE_EXTRA}`),
    chunks: one(stream().body),
    expect: err('stream_malformed_auth'),
  }),
  clientVector('stream-open-bad-sid', 'sid is 15 bytes instead of 16', {
    state: baseState(),
    headers: auth({ sid: BAD_SID }),
    chunks: one(stream({ sid: BAD_SID }).body),
    expect: err('stream_malformed_auth'),
  }),
  clientVector('stream-open-scheme-s2', 'scheme s2', {
    state: baseState(),
    headers: authHeaders(withScheme(GOOD.jack_auth, 's2')),
    chunks: one(stream().body),
    expect: err('stream_unsupported_version'),
  }),
  clientVector('stream-open-scheme-v1', 'scheme v1', {
    state: baseState(),
    headers: authHeaders(withScheme(GOOD.jack_auth, 'v1')),
    chunks: one(stream().body),
    expect: err('stream_unsupported_version'),
  }),
  // Signed by the pinned key under a kid that is not pinned, so only step 4 fails.
  clientVector('stream-open-unknown-kid', 'kid of a valid key that is not pinned', {
    state: baseState(),
    headers: auth({ kid: ALT.kid, privKey: SVC.priv }),
    chunks: one(stream({ kid: ALT.kid, privKey: SVC.priv }).body),
    expect: err('stream_unknown_server_key'),
  }),
  clientVector('stream-open-wrong-key', 'pinned kid signed by another key', {
    state: baseState(),
    headers: auth({ kid: SVC.kid, privKey: ALT.priv }),
    chunks: one(stream({ kid: SVC.kid, privKey: ALT.priv }).body),
    expect: err('stream_bad_signature'),
  }),
  clientVector('stream-open-ts-old', 'open ts one second past the window', {
    state: baseState({ now: NOW }),
    headers: auth({ openTs: NOW - WINDOW - 1 }),
    chunks: one(stream({ openTs: NOW - WINDOW - 1 }).body),
    expect: err('stream_out_of_window'),
  }),
  clientVector('stream-open-ts-future', 'open ts one second ahead of the window', {
    state: baseState({ now: NOW }),
    headers: auth({ openTs: NOW + WINDOW + 1 }),
    chunks: one(stream({ openTs: NOW + WINDOW + 1 }).body),
    expect: err('stream_out_of_window'),
  }),
  clientVector('stream-open-cutoff', 'open ts at the successor activation', {
    state: baseState({ successor_activation: NOW + 10 }),
    headers: auth({ openTs: NOW + 10 }),
    chunks: one(stream({ openTs: NOW + 10 }).body),
    expect: err('stream_after_cutoff'),
  }),
  // One mid-sig character changed; the body chains from the flipped sig.
  clientVector('stream-open-bad-signature', 'one mid-sig character changed', {
    state: baseState(),
    headers: authHeaders(withSig(GOOD.jack_auth, FLIPPED)),
    chunks: one(chainFrom({ prev: FLIPPED, frames: FRAMES }).body),
    expect: err('stream_bad_signature'),
  }),
  clientVector('stream-open-splice', 'open signed over another request sig', {
    state: baseState({ request_sig: REQ_SIG2 }),
    headers: auth({ requestSig: REQ_SIG }),
    chunks: one(stream({ requestSig: REQ_SIG }).body),
    expect: err('stream_bad_signature'),
  }),
];
