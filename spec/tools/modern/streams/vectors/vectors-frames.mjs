// spec/tools/modern/streams/vectors/vectors-frames.mjs
// Client vectors for the frame rules of spec 05 sections 2.6-2.18, 4.3-4.5, 6.2, 6.3.
// Expectations are literal: `messages` lists what reached the MCP layer before
// the terminal state. Nothing here is derived from the reference implementation.
import { Buffer } from 'node:buffer';
import { NOW } from '../../../gen/core.mjs';
import {
  b64u,
  dataHash,
  frameSigningString,
  serializeFrame,
  sha256,
  signMessage,
} from '../reference.mjs';
import {
  EVENTS_RESULT,
  HEARTBEAT,
  MAX_FRAME,
  MSG,
  MSG2,
  MSG3,
  REQUEST_ID,
  RESULT_BAD_ID_TYPE,
  RESULT_BOTH,
  RESULT_NO_JSONRPC,
  RESULT_WRONG_ID,
  SID,
  SID2,
  SIGNAL,
  SIGNAL_AT,
  SVC,
  authHeaders,
  baseState,
  bytes,
  chainFrom,
  chunk,
  clientVector,
  dataFill,
  fillMessage,
  frameOf,
  markerChunks,
  openOnly,
  prog,
  signChain,
} from '../fixtures.mjs';

const ok = (messages) => ({ messages, terminal: { state: 'ok' } });
const bad = (code, frames_verified, messages = []) => ({
  messages,
  terminal: { state: 'error', code, frames_verified },
});
// One chunk holding a whole body (string or Buffer).
const one = (body) => [chunk(bytes(body))];
// One frame's bytes with extra field lines inserted just before its jack line.
const withLines = (signed, kind, data, lines) =>
  frameOf(signed, kind, data).replace(/^jack:/m, `${lines}\njack:`);

// 1, 6-11, 33, 34, 37, 51: MSG at seq 0, then the end frame at seq 1.
const SINGLE = signChain({
  frames: [{ seq: 0, ts: NOW, data: MSG }, { seq: 1, ts: NOW, data: '' }],
});
const SINGLE_BYTES = bytes(SINGLE.body);
const FRAME0 = frameOf(SINGLE.frames[0], 'message', MSG);
const END_FRAME = frameOf(SINGLE.frames[1], 'jack-end', '');
const END_BYTES = bytes(END_FRAME);

// 2: the end frame alone.
const ONLY_END = signChain({ frames: [{ seq: 0, ts: NOW, data: '' }] });

// 24, 32, 36: open header of a stream with no frames.
const OPEN_ONLY = signChain({ frames: [] });

// 3
const MANY = signChain({
  frames: [
    { seq: 0, ts: NOW, data: prog(1) },
    { seq: 1, ts: NOW + 1, data: prog(2) },
    { seq: 2, ts: NOW + 2, data: prog(3) },
    { seq: 3, ts: NOW + 3, data: prog(4) },
    { seq: 4, ts: NOW + 4, data: prog(5) },
    { seq: 5, ts: NOW + 5, data: '' },
  ],
});

// 4: one message whose JSON holds LFs, written as several data lines (2.10).
const PRETTY = '{\n  "jsonrpc": "2.0",\n  "method": "notifications/message",\n  "params": {"data": "multi"}\n}';
const PRETTY_STREAM = signChain({
  frames: [{ seq: 0, ts: NOW, data: PRETTY }, { seq: 1, ts: NOW, data: '' }],
});

// 5: raw non-ASCII UTF-8 inside the data value (2.10).
const UNI = '{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"café 漢字"}}';
const UNI_STREAM = signChain({
  frames: [{ seq: 0, ts: NOW, data: UNI }, { seq: 1, ts: NOW, data: '' }],
});

// 6: every LF became CRLF and one BOM leads the body (2.14).
const CRLF_BODY = Buffer.concat([
  Buffer.from([0xef, 0xbb, 0xbf]),
  bytes(SINGLE.body.replace(/\n/g, '\r\n')),
]);

// 7: comment lines before frame 0, inside frame 0, and before the end (2.12).
const COMMENTS_BODY =
  `: keepalive\nevent: message\ndata: ${MSG}\n: mid\n`
  + `jack: seq=0,ts=${NOW},sig=${SINGLE.frames[0].sig}\n\n:\n`
  + END_FRAME;

// 8: unknown field lines on both frames, unsigned (2.13).
const UNKNOWN_BODY =
  withLines(SINGLE.frames[0], 'message', MSG, 'x-jack-note: 1\nnote')
  + withLines(SINGLE.frames[1], 'jack-end', '', 'x-jack-note: 1\nnote');

// 9: frame 0 without its event line, so the SSE default type applies (2.6).
const NO_EVENT_BODY = FRAME0.replace('event: message\n', '') + END_FRAME;

// 11: one byte per chunk.
const PER_BYTE = [...SINGLE_BYTES].map((b) => chunk(Buffer.from([b])));

// 12: 90 s of stream against per-frame clock samples (4.3 step 3).
const LONG = signChain({
  frames: [
    { seq: 0, ts: NOW, data: prog(1) },
    { seq: 1, ts: NOW + 30, data: prog(2) },
    { seq: 2, ts: NOW + 60, data: prog(3) },
    { seq: 3, ts: NOW + 90, data: prog(4) },
    { seq: 4, ts: NOW + 90, data: '' },
  ],
});

// 13: ts exactly one window behind now.
const WINDOW_EDGE = signChain({
  frames: [
    { seq: 0, ts: NOW - 30, data: MSG },
    { seq: 1, ts: NOW - 30, data: '' },
  ],
});

// 14: everything one second below the successor activation.
const CUTOFF_OK = signChain({
  openTs: NOW + 9,
  frames: [
    { seq: 0, ts: NOW + 9, data: MSG },
    { seq: 1, ts: NOW + 9, data: '' },
  ],
});

// 15-21: seq and timestamp failures. Every chain is honest and complete, its
// last frame a valid end frame chained from the signature actually sent, so only
// the rule under test fails: a verifier that wrongly accepts the failing frame
// still reads the end frame and finishes `ok` (4.3, 4.4).
const chainWith = (frames) => ({
  ...chainFrom({ prev: OPEN_ONLY.open_sig, frames }),
  jack_auth: OPEN_ONLY.jack_auth,
});
const FIRST_ONE = chainWith([
  { seq: 1, ts: NOW, data: MSG },
  { seq: 2, ts: NOW, data: MSG2 },
  { seq: 3, ts: NOW, data: '' },
]);
const GAP = chainWith([
  { seq: 0, ts: NOW, data: MSG },
  { seq: 2, ts: NOW, data: MSG2 },
  { seq: 3, ts: NOW, data: '' },
]);
// The repeat is signed over the chain's real predecessor, so only seq fails.
const REPEAT = chainWith([
  { seq: 0, ts: NOW, data: MSG },
  { seq: 0, ts: NOW, data: MSG2 },
  { seq: 1, ts: NOW, data: '' },
]);
// 17: only the seq numbers are out of order; the chain follows the order sent,
// so a verifier that ignores seq would accept all four frames and end `ok`.
const REORDER = chainWith([
  { seq: 0, ts: NOW, data: MSG },
  { seq: 2, ts: NOW, data: MSG2 },
  { seq: 1, ts: NOW, data: MSG3 },
  { seq: 3, ts: NOW, data: '' },
]);
const REGRESS = chainWith([
  { seq: 0, ts: NOW + 5, data: MSG },
  { seq: 1, ts: NOW + 4, data: MSG2 },
  { seq: 2, ts: NOW + 4, data: '' },
]);
// 20: the open header is ten seconds old, so frame 0 sits exactly one window
// behind its own clock sample and frame 1 one second past it. The end frame
// carries NOW, its own sample, so a verifier that wrongly accepts the stale
// frame 1 still verifies the end frame and finishes `ok`.
const STALE_OPEN = openOnly({ openTs: NOW - 10 });
const STALE = {
  ...chainFrom({
    prev: STALE_OPEN.open_sig,
    frames: [
      { seq: 0, ts: NOW - 40, data: MSG },
      { seq: 1, ts: NOW - 31, data: MSG2 },
      { seq: 2, ts: NOW, data: '' },
    ],
  }),
  jack_auth: STALE_OPEN.jack_auth,
};
// 5.2: a frame at the cutoff has no valid successor frame, so the body simply
// stops after it instead of ending with an end frame of its own.
const CUTOFF = signChain({
  frames: [{ seq: 0, ts: NOW + 10, data: MSG }],
});
// 5.2: the end frame itself can be the frame that crosses the cutoff, after a
// valid message frame below it.
const CUTOFF_END = signChain({
  frames: [{ seq: 0, ts: NOW, data: MSG }, { seq: 1, ts: NOW + 10, data: '' }],
});

// 22, 23: a three-frame chain, then frame 1 broken in two ways.
const CHAIN3 = signChain({
  frames: [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW, data: MSG2 },
    { seq: 2, ts: NOW, data: '' },
  ],
});
const OPEN_PREV_SIG = signMessage(
  SVC.priv,
  frameSigningString({
    sid: SID,
    seq: 1,
    ts: NOW,
    prev: CHAIN3.open_sig,
    hash: dataHash(MSG2),
  }),
);
// The end frame chains from the signature frame 1 actually carries, so a
// verifier that wrongly accepts frame 1 still finishes `ok`.
const OPEN_PREV_END_SIG = signMessage(
  SVC.priv,
  frameSigningString({ sid: SID, seq: 2, ts: NOW, prev: OPEN_PREV_SIG, hash: dataHash('') }),
);
const BAD_SIG_BODY = frameOf(CHAIN3.frames[0], 'message', MSG)
  + serializeFrame({ kind: 'message', data: MSG2, seq: 1, ts: NOW, sig: OPEN_PREV_SIG })
  + serializeFrame({ kind: 'jack-end', data: '', seq: 2, ts: NOW, sig: OPEN_PREV_END_SIG });
const TAMPERED = MSG2.replace('"progress":2', '"progress":9');
const TAMPERED_BODY = frameOf(CHAIN3.frames[0], 'message', MSG)
  + serializeFrame({ kind: 'message', data: TAMPERED, seq: 1, ts: NOW, sig: CHAIN3.frames[1].sig })
  + frameOf(CHAIN3.frames[2], 'jack-end', '');

// 24: frame 0 is signed under another sid than the open header, so only that
// one input of its signing string differs and the chain value is unchanged.
const WS_OPEN = openOnly();
const WS_SIG = signMessage(
  SVC.priv,
  frameSigningString({ sid: SID2, seq: 0, ts: NOW, prev: WS_OPEN.open_sig, hash: dataHash(MSG) }),
);
const WS_END = signMessage(
  SVC.priv,
  frameSigningString({ sid: SID, seq: 1, ts: NOW, prev: WS_SIG, hash: dataHash('') }),
);
const WRONG_SID_BODY = serializeFrame({ kind: 'message', data: MSG, seq: 0, ts: NOW, sig: WS_SIG })
  + serializeFrame({ kind: 'jack-end', data: '', seq: 1, ts: NOW, sig: WS_END });

// 25-28: frame 1 of an honest three-frame chain carries one illegal field. The
// inserted field leaves the data and the signature untouched, so the trailing
// end frame still chains from it and a lenient verifier finishes `ok`.
const CHAIN3_0 = frameOf(CHAIN3.frames[0], 'message', MSG);
const CHAIN3_END = frameOf(CHAIN3.frames[2], 'jack-end', '');
const ID_BODY = CHAIN3_0 + withLines(CHAIN3.frames[1], 'message', MSG2, 'id: 7') + CHAIN3_END;
const RETRY_BODY = CHAIN3_0
  + withLines(CHAIN3.frames[1], 'message', MSG2, 'retry: 1000')
  + CHAIN3_END;
const EXTRA_PARAM_BODY = CHAIN3_0
  + frameOf(CHAIN3.frames[1], 'message', MSG2).replace(/^(jack: .*)$/m, `$1,kid=${SVC.kid}`)
  + CHAIN3_END;
const DOUBLE_JACK_BODY = FRAME0.replace(/^(jack: .*)$/m, '$1\n$1') + END_FRAME;

// 29: an event name outside the closed pair (2.8).
const UNKNOWN_EVENT_BODY = serializeFrame({
  kind: 'answer',
  data: MSG,
  seq: 0,
  ts: NOW,
  sig: SINGLE.frames[0].sig,
}) + END_FRAME;

// 30: an end frame signed over a non-empty value (2.9). A valid empty end frame
// follows, chained from the signature this frame actually carries, so a verifier
// that wrongly accepts it still finds a well-formed end frame and finishes `ok`.
const END_DATA = signChain({
  frames: [{ seq: 0, ts: NOW, data: MSG }, { seq: 1, ts: NOW, data: 'x' }],
});
const END_DATA_END_SIG = signMessage(
  SVC.priv,
  frameSigningString({ sid: SID, seq: 2, ts: NOW, prev: END_DATA.frames[1].sig, hash: dataHash('') }),
);
const END_DATA_BODY = frameOf(END_DATA.frames[0], 'message', MSG)
  + serializeFrame({ kind: 'jack-end', data: 'x', seq: 1, ts: NOW, sig: END_DATA.frames[1].sig })
  + serializeFrame({ kind: 'jack-end', data: '', seq: 2, ts: NOW, sig: END_DATA_END_SIG });

// 31: event message, no data lines, so the empty value (2.9). A verifier that
// wrongly accepts it as an empty message still finds a valid end frame, signed
// over the signature this frame carries.
const EMPTY_VAL = signChain({ frames: [{ seq: 0, ts: NOW, data: '' }] });
const EMPTY_END_SIG = signMessage(
  SVC.priv,
  frameSigningString({
    sid: SID,
    seq: 1,
    ts: NOW,
    prev: EMPTY_VAL.frames[0].sig,
    hash: dataHash(''),
  }),
);
const EMPTY_DATA_BODY = serializeFrame({
  kind: 'message',
  data: '',
  seq: 0,
  ts: NOW,
  sig: EMPTY_VAL.frames[0].sig,
}).replace('data:\n', '')
  + serializeFrame({ kind: 'jack-end', data: '', seq: 1, ts: NOW, sig: EMPTY_END_SIG });

// 32: data bytes 7b 22 c3 28 22 7d are not UTF-8 (2.10).
const RAW = Buffer.from([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]);
const RAW_SIG = signMessage(
  SVC.priv,
  frameSigningString({
    sid: SID,
    seq: 0,
    ts: NOW,
    prev: OPEN_ONLY.open_sig,
    hash: b64u(sha256(RAW)),
  }),
);
const RAW_END_SIG = signMessage(
  SVC.priv,
  frameSigningString({ sid: SID, seq: 1, ts: NOW, prev: RAW_SIG, hash: dataHash('') }),
);
const RAW_BODY = Buffer.concat([
  bytes('event: message\ndata: '),
  RAW,
  bytes(`\njack: seq=0,ts=${NOW},sig=${RAW_SIG}\n\n`),
  bytes(serializeFrame({ kind: 'jack-end', data: '', seq: 1, ts: NOW, sig: RAW_END_SIG })),
]);

// 34: one correct frame after the end frame (2.16), then the end frame of the
// longer chain so a verifier that wrongly accepts the late frame still ends `ok`.
const AFTER_END = signChain({
  frames: [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW, data: '' },
    { seq: 2, ts: NOW, data: MSG3 },
    { seq: 3, ts: NOW, data: '' },
  ],
});

// 35: two verified frames and no end frame (4.4).
const NO_END = signChain({
  frames: [{ seq: 0, ts: NOW, data: MSG }, { seq: 1, ts: NOW, data: MSG2 }],
});

// 37: frame 0 whole, then half of the end frame's bytes (2.14, 4.4).
const CUT_BODY = Buffer.concat([
  bytes(FRAME0),
  END_BYTES.subarray(0, END_BYTES.length >> 1),
]);

// 10, 40: frameMaxBytes bounds the data value of one message frame (2.17), not
// the bytes the event occupies, so CAP data bytes is legal and one more is not.
const CAP = 1048576;
const fillStream = (n) => signChain({
  frames: [{ seq: 0, ts: NOW, data: 'x'.repeat(n) }, { seq: 1, ts: NOW, data: '' }],
});
const AT_CAP = fillStream(CAP);
const OVER_CAP = fillStream(CAP + 1);

// 38, 49: a message, then a signed 2.18 signal whose end frame is never read.
const signalled = (limit) => signChain({
  frames: [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW, data: SIGNAL(limit) },
    { seq: 2, ts: NOW, data: '' },
  ],
});
const SIGNALLED = signalled(MAX_FRAME);
const STDIO_SIGNAL = signalled(1024);
// 2.18: the canonical zero limit is a signal too, and it needs no end frame.
const LIMIT_ZERO = signChain({ frames: [{ seq: 0, ts: NOW, data: SIGNAL(0) }] });

// 39-42: objects that only look like a 2.18 signal are ordinary messages.
const LOOK_METHOD = '{"jsonrpc":"2.0","method":"notifications/jack/stream_errors","params":{"code":"stream_frame_too_large","limit":1048576}}';
const LOOK_EXTRA = '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1048576,"extra":1}}';
const LOOK_CODE = '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_idle","limit":1048576}}';
const LOOK_LIMIT = '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":"1048576"}}';
// 2.18: a limit spelled outside the canonical decimal integer form (1e3,
// 1000.0, 01000) is not a signal, and neither is one extra space or a code
// that is not a string.
const LOOK_LIMIT_EXP = SIGNAL_AT('stream_frame_too_large', '1e3');
const LOOK_LIMIT_DECIMAL = SIGNAL_AT('stream_frame_too_large', '1000.0');
const LOOK_LIMIT_LEADING_ZERO = SIGNAL_AT('stream_frame_too_large', '01000');
const LOOK_SPACE = '{"jsonrpc":"2.0", "method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1000}}';
const LOOK_CODE_TYPE = '{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":5,"limit":1000}}';
const lookStream = (data) => signChain({
  frames: [{ seq: 0, ts: NOW, data }, { seq: 1, ts: NOW, data: '' }],
});

// 43: frame 1's data value is 1025 bytes against a 1024-byte cap (2.17).
const LATE_N = 1025;
const LATE = signChain({
  frames: [
    { seq: 0, ts: NOW, data: MSG },
    { seq: 1, ts: NOW, data: 'x'.repeat(LATE_N) },
    { seq: 2, ts: NOW, data: '' },
  ],
});

// 4.5, 44: idle vectors carry section 9 arrival_ms, so the deadline runs from
// the time each chunk arrived, not from the whole body at once.
const IDLE_OPEN = openOnly();
const TWO_TICKS = {
  ...chainFrom({
    prev: IDLE_OPEN.open_sig,
    frames: [
      { seq: 0, ts: NOW, data: MSG },
      { seq: 1, ts: NOW + 90, data: MSG2 },
      { seq: 2, ts: NOW + 180, data: '' },
    ],
  }),
  jack_auth: IDLE_OPEN.jack_auth,
};
const tickChunks = TWO_TICKS.body.split('\n\n').filter((s) => s !== '').map((s) => chunk(bytes(`${s}\n\n`)));
// 46: heartbeat frames 80 s apart, the last one arriving with the end frame.
const IDLE_BEATS = {
  ...chainFrom({
    prev: IDLE_OPEN.open_sig,
    frames: [
      { seq: 0, ts: NOW, data: HEARTBEAT },
      { seq: 1, ts: NOW + 80, data: HEARTBEAT },
      { seq: 2, ts: NOW + 160, data: HEARTBEAT },
      { seq: 3, ts: NOW + 160, data: '' },
    ],
  }),
  jack_auth: IDLE_OPEN.jack_auth,
};
const beatChunks = IDLE_BEATS.body.split('\n\n').filter((s) => s !== '').map((s) => chunk(bytes(`${s}\n\n`)));
const TICKS = baseState({ now: NOW, frame_nows: [NOW, NOW + 90, NOW + 180], stream_idle_ms: 90000 });
const BEAT_STATE = baseState({ now: NOW, frame_nows: [NOW, NOW + 80, NOW + 160, NOW + 160], stream_idle_ms: 90000 });
const BOM_BYTES = Buffer.from([0xef, 0xbb, 0xbf]);
// 2.14, 4.5: the split sits exactly between frame 0's second-to-last and last
// byte, the newline that completes its terminating blank line. A lookup that
// forgets the BOM's three bytes maps that byte into the first chunk and accepts
// the frame; the correct lookup times it in the late chunk and the stream goes
// idle with nothing verified.
const BOM_SPLIT = FRAME0.length - 1;
const BOM_BODY = Buffer.concat([BOM_BYTES, bytes(SINGLE.body)]);
const BOM_CHUNKS = [
  chunk(BOM_BODY.subarray(0, BOM_BYTES.length + BOM_SPLIT)),
  chunk(BOM_BODY.subarray(BOM_BYTES.length + BOM_SPLIT)),
];
// 2.6, 4.5: the same boundary without a BOM, so the late chunk carries only the
// final newline of the frame's blank line and the frame is still late.
const BLANK_SPLIT = FRAME0.length - 1;
const BLANK_BODY = bytes(SINGLE.body);
const BLANK_CHUNKS = [
  chunk(BLANK_BODY.subarray(0, BLANK_SPLIT)),
  chunk(BLANK_BODY.subarray(BLANK_SPLIT)),
];
// 2.12, 4.5: a comment carries no frame, so it resets nothing.
const COMMENT_CHUNKS = [chunk(bytes(FRAME0)), chunk(bytes(': keepalive\n'))];
// 50, 6.3: a close chain carries one progress frame, then the last message
// frame in whatever shape it has, then the end frame.
const closeChain = (last) => chainWith([
  { seq: 0, ts: NOW, data: prog(1) },
  { seq: 1, ts: NOW, data: last },
  { seq: 2, ts: NOW, data: '' },
]);
const CLOSE_RESULT = closeChain(EVENTS_RESULT(REQUEST_ID));
const CLOSE_NO_RESULT = chainWith([
  { seq: 0, ts: NOW, data: prog(1) },
  { seq: 1, ts: NOW, data: '' },
]);
const CLOSE_WRONG_ID = closeChain(RESULT_WRONG_ID);
const CLOSE_NO_JSONRPC = closeChain(RESULT_NO_JSONRPC);
const CLOSE_BOTH = closeChain(RESULT_BOTH);
const CLOSE_ID_TYPE = closeChain(RESULT_BAD_ID_TYPE);
// 4.4, 6.3: the final response of the opening request, with no verified end
// frame after it, so the body is truncated and the request never completes.
const CLOSE_NO_END = chainWith([
  { seq: 0, ts: NOW, data: prog(1) },
  { seq: 1, ts: NOW, data: EVENTS_RESULT(REQUEST_ID) },
]);

// 2.18: a lookalike is an ordinary message, so it is delivered and the stream
// still ends with its own end frame.
const lookVector = (id, description, data) => clientVector(id, description, {
  state: baseState(),
  headers: authHeaders(lookStream(data).jack_auth),
  chunks: one(lookStream(data).body),
  expect: ok([data]),
});
// 4.5: one arrival time per chunk, and the opener of `chain` is the only
// verified event when a vector carries no frames.
const idleVectorFor = (chain) => (
  id, description, state, chunks, arrival_ms, expect, silent_after_ms,
) => ({
  ...clientVector(id, description, {
    state, headers: authHeaders(chain.jack_auth), chunks, expect, silent_after_ms,
  }),
  ...(arrival_ms === undefined ? {} : { arrival_ms }),
});
const idleVector = idleVectorFor(IDLE_OPEN);
// The same idle form over a body that does carry frames.
const singleIdleVector = idleVectorFor(SINGLE);
// 6.3: every close chain ends `ok`; mcp_complete says whether its last message
// frame is the final JSON-RPC response of the opening request.
const closeVector = (id, description, chain, messages, complete) => clientVector(id, description, {
  state: baseState(),
  headers: authHeaders(chain.jack_auth),
  chunks: one(chain.body),
  expect: { messages, terminal: { state: 'ok' }, mcp_complete: complete },
});

export const frameVectors = [
  clientVector('stream-ok-single', 'one message frame then the end frame (2.6, 2.16)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: [chunk(SINGLE_BYTES)],
    expect: ok([MSG]),
  }),
  clientVector('stream-ok-only-end', 'end frame alone at seq 0, no message (2.16)', {
    state: baseState(),
    headers: authHeaders(ONLY_END.jack_auth),
    chunks: one(ONLY_END.body),
    expect: ok([]),
  }),
  clientVector('stream-ok-many', 'five message frames, seq 0-4, then the end frame', {
    state: baseState(),
    headers: authHeaders(MANY.jack_auth),
    chunks: one(MANY.body),
    expect: ok([prog(1), prog(2), prog(3), prog(4), prog(5)]),
  }),
  clientVector('stream-ok-multiline-data', 'data value holds LFs, one data line per piece (2.10)', {
    state: baseState(),
    headers: authHeaders(PRETTY_STREAM.jack_auth),
    chunks: one(PRETTY_STREAM.body),
    expect: ok([PRETTY]),
  }),
  clientVector('stream-ok-unicode', 'raw non-ASCII UTF-8 in the data value (2.10)', {
    state: baseState(),
    headers: authHeaders(UNI_STREAM.jack_auth),
    chunks: one(UNI_STREAM.body),
    expect: ok([UNI]),
  }),
  clientVector('stream-ok-crlf', 'CRLF terminators and a leading BOM verify as LF (2.14)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: [chunk(CRLF_BODY)],
    expect: ok([MSG]),
  }),
  clientVector('stream-ok-comments', 'comments before, inside and between events (2.12)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: one(COMMENTS_BODY),
    expect: ok([MSG]),
  }),
  clientVector('stream-ok-unknown-field', 'unknown field and bare-name lines are ignored (2.13)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: one(UNKNOWN_BODY),
    expect: ok([MSG]),
  }),
  clientVector('stream-ok-no-event-field', 'frame 0 omits event, defaults to message (2.6)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: one(NO_EVENT_BODY),
    expect: ok([MSG]),
  }),
  clientVector(
    'stream-ok-frame-max-boundary',
    'frame 0 data value is exactly frame_max_bytes long (2.17, 4.3 step 1)',
    {
      state: baseState({ frame_max_bytes: CAP }),
      headers: authHeaders(AT_CAP.jack_auth),
      chunks: markerChunks(AT_CAP.body, 'x'.repeat(CAP)),
      data_fill: dataFill(CAP),
      expect: { messages: [fillMessage(CAP)], terminal: { state: 'ok' } },
    },
  ),
  clientVector(
    'stream-ok-byte-split',
    'stream_b64u pieces of one byte, concatenated before parsing (section 8)',
    {
      state: baseState(),
      headers: authHeaders(SINGLE.jack_auth),
      chunks: PER_BYTE,
      expect: ok([MSG]),
    },
  ),
  clientVector(
    'stream-ok-long-stream',
    '90 s stream, each frame inside the window of its own clock sample (4.3 step 3)',
    {
      state: baseState({
        frame_nows: [NOW, NOW + 30, NOW + 60, NOW + 90, NOW + 90],
      }),
      headers: authHeaders(LONG.jack_auth),
      chunks: one(LONG.body),
      expect: ok([prog(1), prog(2), prog(3), prog(4)]),
    },
  ),
  clientVector('stream-ok-window-boundary', 'frame ts exactly W behind now is inside (4.3 step 3)', {
    state: baseState({ now: NOW }),
    headers: authHeaders(WINDOW_EDGE.jack_auth),
    chunks: one(WINDOW_EDGE.body),
    expect: ok([MSG]),
  }),
  clientVector(
    'stream-ok-cutoff-below',
    'open and frame ts one second below the successor activation (4.3 step 4)',
    {
      state: baseState({ successor_activation: NOW + 10 }),
      headers: authHeaders(CUTOFF_OK.jack_auth),
      chunks: one(CUTOFF_OK.body),
      expect: ok([MSG]),
    },
  ),
  clientVector('stream-frame-seq-first-not-zero', 'frame seq 1 where 0 is expected (4.3 step 2)', {
    state: baseState(),
    headers: authHeaders(FIRST_ONE.jack_auth),
    chunks: one(FIRST_ONE.body),
    expect: bad('stream_out_of_order', 0),
  }),
  clientVector('stream-frame-seq-gap', 'frame seq 2 where 1 is expected (4.3 step 2)', {
    state: baseState(),
    headers: authHeaders(GAP.jack_auth),
    chunks: one(GAP.body),
    expect: bad('stream_out_of_order', 1, [MSG]),
  }),
  clientVector(
    'stream-frame-seq-repeat',
    'frame seq 0 twice, the repeat signed over the chain predecessor (4.3 step 2)',
    {
      state: baseState(),
      headers: authHeaders(REPEAT.jack_auth),
      chunks: one(REPEAT.body),
      expect: bad('stream_out_of_order', 1, [MSG]),
    },
  ),
  clientVector('stream-frame-seq-reorder', 'frames delivered 0, 2, 1 (4.3 step 2)', {
    state: baseState(),
    headers: authHeaders(REORDER.jack_auth),
    chunks: one(REORDER.body),
    expect: bad('stream_out_of_order', 1, [MSG]),
  }),
  clientVector('stream-frame-ts-regress', 'frame 1 ts below frame 0 ts (4.3 step 3)', {
    state: baseState({ now: NOW }),
    headers: authHeaders(REGRESS.jack_auth),
    chunks: one(REGRESS.body),
    expect: bad('stream_stale_frame', 1, [MSG]),
  }),
  clientVector(
    'stream-frame-ts-stale',
    'frame 1 is 31 s behind its clock sample, frame 0 is exactly 30 s (4.3 step 3)',
    {
      state: baseState({ now: NOW, frame_nows: [NOW - 10, NOW, NOW] }),
      headers: authHeaders(STALE.jack_auth),
      chunks: one(STALE.body),
      expect: bad('stream_stale_frame', 1, [MSG]),
    },
  ),
  clientVector(
    'stream-frame-after-cutoff',
    'a frame at the cutoff has no valid successor: no end frame can follow, and stream_after_cutoff takes precedence over stream_truncated (5.2)',
    {
      state: baseState({ successor_activation: NOW + 10 }),
      headers: authHeaders(CUTOFF.jack_auth),
      chunks: one(CUTOFF.body),
      expect: bad('stream_after_cutoff', 0),
    },
  ),
  clientVector(
    'stream-frame-end-after-cutoff',
    'the end frame itself is at the cutoff, after a valid message below it (4.3 step 4, 5.2)',
    {
      state: baseState({ successor_activation: NOW + 10 }),
      headers: authHeaders(CUTOFF_END.jack_auth),
      chunks: one(CUTOFF_END.body),
      expect: bad('stream_after_cutoff', 1, [MSG]),
    },
  ),
  clientVector(
    'stream-frame-bad-signature',
    'frame 1 signed over the open sig instead of frame 0 sig (4.3 step 5)',
    {
      state: baseState(),
      headers: authHeaders(CHAIN3.jack_auth),
      chunks: one(BAD_SIG_BODY),
      expect: bad('stream_bad_signature', 1, [MSG]),
    },
  ),
  clientVector(
    'stream-frame-tampered-data',
    'frame 1 data changed after signing, its signature kept (4.3 step 5)',
    {
      state: baseState(),
      headers: authHeaders(CHAIN3.jack_auth),
      chunks: one(TAMPERED_BODY),
      expect: bad('stream_bad_signature', 1, [MSG]),
    },
  ),
  clientVector(
    'stream-frame-wrong-sid',
    'frame 0 signed with another sid, the chain value unchanged (2.15, 4.3 step 5)',
    {
      state: baseState(),
      headers: authHeaders(WS_OPEN.jack_auth),
      chunks: one(WRONG_SID_BODY),
      expect: bad('stream_bad_signature', 0),
    },
  ),
  clientVector('stream-frame-id-field', 'an id field on frame 1 (2.11, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(CHAIN3.jack_auth),
    chunks: one(ID_BODY),
    expect: bad('stream_bad_frame', 1, [MSG]),
  }),
  clientVector('stream-frame-retry-field', 'a retry field on frame 1 (2.11, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(CHAIN3.jack_auth),
    chunks: one(RETRY_BODY),
    expect: bad('stream_bad_frame', 1, [MSG]),
  }),
  clientVector('stream-frame-extra-jack-param', 'a fourth jack parameter on frame 1 (2.7, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(CHAIN3.jack_auth),
    chunks: one(EXTRA_PARAM_BODY),
    expect: bad('stream_bad_frame', 1, [MSG]),
  }),
  clientVector('stream-frame-double-jack', 'frame 0 carries two jack lines (2.7, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: one(DOUBLE_JACK_BODY),
    expect: bad('stream_bad_frame', 0),
  }),
  clientVector('stream-frame-unknown-event', 'event other than message or jack-end (2.8, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(SINGLE.jack_auth),
    chunks: one(UNKNOWN_EVENT_BODY),
    expect: bad('stream_bad_frame', 0),
  }),
  clientVector('stream-frame-end-with-data', 'jack-end frame with non-empty data (2.9, 4.3 step 1)', {
    state: baseState(),
    headers: authHeaders(END_DATA.jack_auth),
    chunks: one(END_DATA_BODY),
    expect: bad('stream_bad_frame', 1, [MSG]),
  }),
  clientVector(
    'stream-frame-message-empty-data',
    'event message with no data lines, so the empty value (2.9, 4.3 step 1)',
    {
      state: baseState(),
      headers: authHeaders(EMPTY_VAL.jack_auth),
      chunks: one(EMPTY_DATA_BODY),
      expect: bad('stream_bad_frame', 0),
    },
  ),
  clientVector(
    'stream-frame-invalid-utf8',
    'data bytes 7b 22 c3 28 22 7d are not UTF-8 (2.10, 4.3 step 1)',
    {
      state: baseState(),
      headers: authHeaders(OPEN_ONLY.jack_auth),
      chunks: [chunk(RAW_BODY)],
      expect: bad('stream_bad_frame', 0),
    },
  ),
  clientVector(
    'stream-frame-oversize',
    'frame 0 data value is one byte over frame_max_bytes (2.17)',
    {
      state: baseState({ frame_max_bytes: CAP }),
      headers: authHeaders(OVER_CAP.jack_auth),
      chunks: markerChunks(OVER_CAP.body, 'x'.repeat(CAP + 1)),
      data_fill: dataFill(CAP + 1),
      expect: bad('stream_frame_too_large', 0),
    },
  ),
  clientVector(
    'stream-frame-after-end',
    'a correctly chained frame follows the end frame (2.16, 4.3)',
    {
      state: baseState(),
      headers: authHeaders(AFTER_END.jack_auth),
      chunks: one(AFTER_END.body),
      expect: bad('stream_out_of_order', 2, [MSG]),
    },
  ),
  clientVector(
    'stream-truncated-no-end',
    'both frames verify and the body ends without an end frame (4.4)',
    {
      state: baseState(),
      headers: authHeaders(NO_END.jack_auth),
      chunks: one(NO_END.body),
      expect: bad('stream_truncated', 2, [MSG, MSG2]),
    },
  ),
  clientVector('stream-truncated-empty-body', 'valid open header, empty body (4.4)', {
    state: baseState(),
    headers: authHeaders(OPEN_ONLY.jack_auth),
    chunks: [],
    expect: bad('stream_truncated', 0),
  }),
  clientVector(
    'stream-truncated-mid-frame',
    'body ends inside the end frame, its last line unterminated (2.14, 4.4)',
    {
      state: baseState(),
      headers: authHeaders(SINGLE.jack_auth),
      chunks: [chunk(CUT_BODY)],
      expect: bad('stream_truncated', 1, [MSG]),
    },
  ),
  clientVector(
    'stream-signal-too-large',
    'signed transport signal ends the stream, the end frame after it is not read (2.18, 4.3 step 6)',
    {
      state: baseState(),
      headers: authHeaders(SIGNALLED.jack_auth),
      chunks: one(SIGNALLED.body),
      expect: {
        messages: [MSG],
        terminal: { state: 'error', code: 'stream_frame_too_large', frames_verified: 2 },
        mcp_complete: false,
      },
    },
  ),
  clientVector('stream-ok-signal-lookalike-method', 'method stream_errors is an ordinary message (2.18)', {
    state: baseState(),
    headers: authHeaders(lookStream(LOOK_METHOD).jack_auth),
    chunks: one(lookStream(LOOK_METHOD).body),
    expect: ok([LOOK_METHOD]),
  }),
  clientVector('stream-ok-signal-lookalike-extra', 'an extra params member keeps it a message (2.18)', {
    state: baseState(),
    headers: authHeaders(lookStream(LOOK_EXTRA).jack_auth),
    chunks: one(lookStream(LOOK_EXTRA).body),
    expect: ok([LOOK_EXTRA]),
  }),
  clientVector('stream-ok-signal-lookalike-code', 'code stream_idle is outside the signalled set (2.18)', {
    state: baseState(),
    headers: authHeaders(lookStream(LOOK_CODE).jack_auth),
    chunks: one(lookStream(LOOK_CODE).body),
    expect: ok([LOOK_CODE]),
  }),
  clientVector('stream-ok-signal-lookalike-limit', 'a string limit is not a JSON number (2.18)', {
    state: baseState(),
    headers: authHeaders(lookStream(LOOK_LIMIT).jack_auth),
    chunks: one(lookStream(LOOK_LIMIT).body),
    expect: ok([LOOK_LIMIT]),
  }),
  lookVector('stream-ok-signal-lookalike-limit-exp', 'a limit written 1e3 is not canonical (2.18)',
    LOOK_LIMIT_EXP),
  lookVector('stream-ok-signal-lookalike-limit-decimal', 'a limit written 1000.0 is not canonical (2.18)',
    LOOK_LIMIT_DECIMAL),
  lookVector('stream-ok-signal-lookalike-limit-leading-zero', 'a limit written 01000 is not canonical (2.18)',
    LOOK_LIMIT_LEADING_ZERO),
  lookVector('stream-ok-signal-lookalike-whitespace', 'one extra space keeps it a message (2.18)',
    LOOK_SPACE),
  lookVector('stream-ok-signal-lookalike-code-type', 'a numeric code is not a string code (2.18)',
    LOOK_CODE_TYPE),
  clientVector(
    'stream-signal-limit-zero',
    'a canonical zero limit is still a signal, and no end frame follows it (2.18, 4.3 step 6)',
    {
      state: baseState(),
      headers: authHeaders(LIMIT_ZERO.jack_auth),
      chunks: one(LIMIT_ZERO.body),
      expect: { ...bad('stream_frame_too_large', 1), mcp_complete: false },
    },
  ),
  clientVector(
    'stream-frame-oversize-late',
    'frame 1 data value is 1025 bytes against a 1024-byte cap, frame 0 stays valid (2.17, 4.3 step 1)',
    {
      state: baseState({ frame_max_bytes: 1024 }),
      headers: authHeaders(LATE.jack_auth),
      chunks: [
        chunk(bytes(frameOf(LATE.frames[0], 'message', MSG))),
        ...markerChunks(frameOf(LATE.frames[1], 'message', 'x'.repeat(LATE_N)), 'x'.repeat(LATE_N)),
        chunk(bytes(frameOf(LATE.frames[2], 'jack-end', ''))),
      ],
      data_fill: dataFill(LATE_N),
      expect: bad('stream_frame_too_large', 1, [MSG]),
    },
  ),
  // 4.5: 90 s between open and frame 1, and again between frame 1 and the end
  // frame, so every gap is exactly the threshold and the timer resets each time.
  idleVector(
    'stream-idle-boundary-alive', 'a gap of exactly streamIdleMs between verified frames is not idle (4.5)',
    TICKS, tickChunks, [0, 90000, 180000], ok([MSG, MSG2]),
  ),
  idleVector(
    'stream-idle-timeout', 'a gap one millisecond past streamIdleMs is idle (4.5)',
    TICKS, tickChunks, [0, 90001, 180000], bad('stream_idle', 1, [MSG]),
  ),
  idleVector(
    'stream-idle-heartbeat', 'heartbeats reset the timer, so 160 s with no 90 s gap stays alive (3.5, 4.5)',
    BEAT_STATE, beatChunks, [0, 80000, 160000, 160000], ok([HEARTBEAT, HEARTBEAT, HEARTBEAT]),
  ),
  idleVector(
    'stream-idle-open-silence', 'a valid opener followed by more than streamIdleMs of silence (4.5)',
    baseState({ stream_idle_ms: 90000 }), [], undefined, bad('stream_idle', 0, []), 90001,
  ),
  {
    ...clientVector('stream-idle-bom-late-chunk', 'the split is between frame 0\'s last two bytes, so a BOM-unaware lookup accepts the frame and the correct one times it late (2.14, 4.5)', {
      state: baseState({ stream_idle_ms: 90000 }),
      headers: authHeaders(SINGLE.jack_auth),
      chunks: BOM_CHUNKS,
      expect: bad('stream_idle', 0),
    }),
    arrival_ms: [0, 90001],
  },
  {
    ...clientVector('stream-idle-blank-line-late-chunk', 'an event completes only at its terminating blank line, so a late final newline makes the frame late (2.6, 4.5)', {
      state: baseState({ stream_idle_ms: 90000 }),
      headers: authHeaders(SINGLE.jack_auth),
      chunks: BLANK_CHUNKS,
      expect: bad('stream_idle', 0),
    }),
    arrival_ms: [0, 90001],
  },
  {
    ...clientVector('stream-idle-comment-silence', 'a comment at 80000 ms plus 20000 ms of silence is 100000 ms without a verified frame (4.5)', {
      state: baseState({ stream_idle_ms: 90000 }),
      headers: authHeaders(SINGLE.jack_auth),
      chunks: COMMENT_CHUNKS,
      silent_after_ms: 20000,
      expect: bad('stream_idle', 1, [MSG]),
    }),
    arrival_ms: [0, 80000],
  },
  clientVector('stream-stdio-ok', 'stdio consumer writes one line per message frame (6.2)', {
    state: baseState(),
    headers: authHeaders(CHAIN3.jack_auth),
    chunks: one(CHAIN3.body),
    consumer: 'stdio',
    expect: ok([MSG, MSG2]),
  }),
  clientVector('stream-stdio-raw-lf', 'a data value with raw LFs aborts the stdio consumer (6.2)', {
    state: baseState(),
    headers: authHeaders(PRETTY_STREAM.jack_auth),
    chunks: one(PRETTY_STREAM.body),
    consumer: 'stdio',
    expect: bad('stream_bad_frame', 1, []),
  }),
  clientVector(
    'stream-stdio-signal',
    'the stdio consumer stops at a verified signal and writes nothing of it (2.18, 6.2)',
    {
      state: baseState(),
      headers: authHeaders(STDIO_SIGNAL.jack_auth),
      chunks: one(STDIO_SIGNAL.body),
      consumer: 'stdio',
      expect: {
        messages: [MSG],
        terminal: { state: 'error', code: 'stream_frame_too_large', frames_verified: 2 },
        mcp_complete: false,
      },
    },
  ),
  closeVector('stream-close-with-result', 'the final result message precedes the end frame (6.3)',
    CLOSE_RESULT, [prog(1), EVENTS_RESULT(REQUEST_ID)], true),
  closeVector('stream-close-without-result', 'the end frame without a final result message (6.3)',
    CLOSE_NO_RESULT, [prog(1)], false),
  closeVector('stream-close-lookalike-wrong-id', 'a response for another id leaves the request open (6.3)',
    CLOSE_WRONG_ID, [prog(1), RESULT_WRONG_ID], false),
  closeVector('stream-close-lookalike-no-jsonrpc', 'a response without jsonrpc leaves it open (6.3)',
    CLOSE_NO_JSONRPC, [prog(1), RESULT_NO_JSONRPC], false),
  closeVector('stream-close-lookalike-both', 'a response with result and error leaves it open (6.3)',
    CLOSE_BOTH, [prog(1), RESULT_BOTH], false),
  closeVector('stream-close-lookalike-id-type', 'a response whose id is a string leaves it open (6.3)',
    CLOSE_ID_TYPE, [prog(1), RESULT_BAD_ID_TYPE], false),
  clientVector('stream-close-no-end-frame', 'a final response without a verified jack-end is truncated and never MCP-complete (4.4, 6.3)', {
    state: baseState(),
    headers: authHeaders(CLOSE_NO_END.jack_auth),
    chunks: one(CLOSE_NO_END.body),
    expect: {
      messages: [prog(1), EVENTS_RESULT(REQUEST_ID)],
      terminal: { state: 'error', code: 'stream_truncated', frames_verified: 2 },
      mcp_complete: false,
    },
  }),
];
