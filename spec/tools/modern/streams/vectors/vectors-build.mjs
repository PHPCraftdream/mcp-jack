// spec/tools/modern/streams/vectors/vectors-build.mjs
// Server-signing known-answer vectors (spec 05 section 9, build file): each
// case is the reference buildStream output over one fixed input.
import { NOW, WINDOW } from '../../../gen/core.mjs';
import {
  MSG,
  MSG2,
  MSG3,
  REQ_SIG,
  SID,
  SVC,
  baseState,
  bytes,
  chunk,
  prog,
} from '../fixtures.mjs';
import { buildStream, parseSignal } from '../reference.mjs';

// Same shape as the multiline client vector: one JSON-RPC message with LFs.
const PRETTY = '{\n  "jsonrpc": "2.0",\n  "method": "notifications/message",\n  "params": {"data": "multi"}\n}';
const UNI = '{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"café 漢字"}}';
// 3.2: the exact transport notification an oversize handler message becomes.
const SMALL_CAP = 1024;
const OVERSIZE = `{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":${SMALL_CAP}}}`;

const INPUT = { request_sig: REQ_SIG, kid: SVC.kid, status: 200, sid: SID, open_ts: NOW };

const DEFS = [
  ['build-open', 'open header of a stream with no frames', []],
  ['build-only-end', 'the end frame alone at seq 0', [
    { seq: 0, ts: NOW + 1, data: '' },
  ]],
  ['build-single-frame', 'one message frame then the end frame', [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW + 1, data: '' },
  ]],
  ['build-three-frames', 'three message frames then the end frame', [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW + 1, data: MSG2 },
    { seq: 2, ts: NOW + 2, data: MSG3 },
    { seq: 3, ts: NOW + 3, data: '' },
  ]],
  ['build-multiline', 'one message holding LFs, one data line per piece', [
    { seq: 0, ts: NOW, data: PRETTY },
    { seq: 1, ts: NOW + 1, data: '' },
  ]],
  ['build-unicode', 'raw non-ASCII UTF-8 in the data value', [
    { seq: 0, ts: NOW, data: UNI },
    { seq: 1, ts: NOW + 1, data: '' },
  ]],
  ['build-oversize-error-frame', 'a 1025-byte handler message against a 1024-byte cap: the signal then the end frame', [
    { seq: 0, ts: NOW, data: OVERSIZE },
    { seq: 1, ts: NOW + 1, data: '' },
  ]],
  ['build-long-ts', 'three frames 100 s apart, end frame repeats the last ts', [
    { seq: 0, ts: NOW, data: prog(1) },
    { seq: 1, ts: NOW + 100, data: prog(2) },
    { seq: 2, ts: NOW + 200, data: prog(3) },
    { seq: 3, ts: NOW + 200, data: '' },
  ]],
];

const sign = (input) => buildStream({
  privKey: SVC.priv,
  kid: input.kid,
  sid: input.sid,
  status: input.status,
  requestSig: input.request_sig,
  openTs: input.open_ts,
  frames: input.frames,
});

// expect is buildStream's own output under the section 9 names; stream_b64u is
// one base64url string of the whole body.
const expectOf = (out) => ({
  jack_auth: out.jack_auth,
  open_signing_string: out.open_signing_string,
  frames: out.frames.map(({ seq, ts, prev, data_hash, signing_string, sig }) => ({
    seq,
    ts,
    prev,
    data_hash,
    signing_string,
    sig,
  })),
  stream_b64u: chunk(bytes(out.body)),
});

export const buildVectors = DEFS.map(([id, description, frames]) => {
  const input = { ...INPUT, frames };
  return { id, description, input, expect: expectOf(sign(input)) };
});

// 4.3 step 6: a verified 2.18 signal ends the stream undelivered, so it is the
// terminal state before any end frame; 4.4 is the body that ends unterminated.
const terminalOf = (frames) => {
  for (let i = 0; i < frames.length; i += 1) {
    const signal = parseSignal(frames[i].data);
    if (signal !== null) return { state: 'error', code: signal.code, frames_verified: i + 1 };
  }
  if (frames.some((f) => f.data === '')) return { state: 'ok' };
  return { state: 'error', code: 'stream_truncated', frames_verified: 0 };
};

// Positive control per case: the client state that must verify the stream.
export const buildCaseChecks = buildVectors.map((c) => {
  const tses = c.input.frames.map((f) => f.ts);
  const last = tses.length > 0 ? tses[tses.length - 1] : c.input.open_ts;
  // The open header is checked against state.now too, so a stream longer than
  // one window keeps its open ts as the clock.
  const now = Math.abs(last - c.input.open_ts) <= WINDOW ? last : c.input.open_ts;
  // The oversize case is signed against the 1024-byte cap it reports.
  const cap = c.id === 'build-oversize-error-frame' ? { frame_max_bytes: SMALL_CAP } : {};
  return {
    id: c.id,
    state: baseState({ now, frame_nows: tses, ...cap }),
    expectedMessages: c.input.frames.filter((f) => f.data !== '').map((f) => f.data),
    expectedTerminal: terminalOf(c.input.frames),
  };
});
