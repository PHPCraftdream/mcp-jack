// Reference implementation of spec/05-signed-streams.md.
// Cross-check only: the vectors are compared against it; it is not a product SDK.
// `ok` for a `silentAfterMs` vector means no idle timeout fired: the connection
// stayed open (4.5). `stream_idle` is 4.5.

import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { Buffer } from 'node:buffer';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const EMPTY = Buffer.alloc(0);

const CR = 0x0d;
const LF = 0x0a;
const SP = 0x20;
const COLON = 0x3a;

// 01 section 2: L = 2^252 + 27742317777372353535851937790883648493.
const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

// Little-endian bytes to BigInt; `S` and point coordinates use this form.
const leBigInt = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) n = (n << 8n) | BigInt(bytes[i]);
  return n;
};

// The eight small-order point encodings R must not be (01 section 2).
const SMALL_ORDER_R = [
  '01' + '00'.repeat(31),
  '00'.repeat(32),
  '00'.repeat(31) + '80',
  'ec' + 'ff'.repeat(30) + '7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

const TS_RE = /^(?:0|[1-9][0-9]{0,11})$/; // canonical decimal, at most 12 digits (2.2)
const SEQ_RE = /^(?:0|[1-9][0-9]{0,14})$/; // canonical decimal, at most 15 digits (2.7)
const PARAM_RE = /^([a-z]+)=([A-Za-z0-9_-]+)$/;
const SCHEME_RE = /^[sv][0-9]+$/;
const EVENT_NAMES = ['message', 'jack-end'];

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const sha256 = (buf) => createHash('sha256').update(buf).digest();
export const dataHash = (data) => b64u(sha256(Buffer.from(data, 'utf8')));

export const OPEN_DOMAIN = 'mcp-jack/stream1/open';
export const FRAME_DOMAIN = 'mcp-jack/stream1/frame';

export const CLIENT_CODES = [
  'stream_missing_auth',
  'stream_malformed_auth',
  'stream_unsupported_version',
  'stream_unknown_server_key',
  'stream_out_of_window',
  'stream_bad_signature',
  'stream_bad_frame',
  'stream_out_of_order',
  'stream_stale_frame',
  'stream_truncated',
  'stream_idle',
  'stream_frame_too_large',
  'stream_after_cutoff',
];

export const SIGNAL_METHOD = 'notifications/jack/stream_error';
export const SIGNAL_CODES = ['stream_frame_too_large'];

export const openSigningString = ({ status, requestSig, kid, ts, sid }) =>
  [OPEN_DOMAIN, String(status), requestSig, kid, String(ts), sid].join('\n');

export const frameSigningString = ({ sid, seq, ts, prev, hash }) =>
  [FRAME_DOMAIN, sid, String(seq), String(ts), prev, hash].join('\n');

export const signMessage = (privKey, message) => b64u(sign(null, Buffer.from(message, 'utf8'), privKey));

export const publicKeyObject = (publicKeyB64u) =>
  createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKeyB64u, 'base64url')]),
    format: 'der',
    type: 'spki',
  });

export const verifyMessage = (publicKeyB64u, message, sigB64u) => {
  const sig = strictB64u(sigB64u, 64);
  if (sig === null) return false;
  // 01 section 2: `R` must not be a small-order point and `S` must be below L.
  if (SMALL_ORDER_R.includes(sig.subarray(0, 32).toString('hex'))) return false;
  if (leBigInt(sig.subarray(32)) >= GROUP_ORDER) return false;
  try {
    return verify(null, Buffer.from(message, 'utf8'), publicKeyObject(publicKeyB64u), sig);
  } catch {
    // A pinned key that is not a usable Ed25519 point verifies nothing.
    return false;
  }
};

// Strict unpadded base64url of an exact byte length; the round-trip rejects
// padding, foreign characters and non-canonical trailing bits (01 section 2).
function strictB64u(value, len) {
  if (typeof value !== 'string') return null;
  const buf = Buffer.from(value, 'base64url');
  return buf.length === len && b64u(buf) === value ? buf : null;
}

// 2.10: a lossy decode does not round-trip, so this rejects overlong forms and
// surrogate halves as well as truncated sequences.
function utf8(bytes) {
  const text = bytes.toString('utf8');
  return Buffer.from(text, 'utf8').equals(bytes) ? text : null;
}

// 2.2 and 2.7: `name=value` pairs joined by a single comma with no whitespace;
// lowercase case-sensitive names, each of `names` exactly once.
function parseParams(value, names) {
  const out = new Map();
  for (const part of value.split(',')) {
    const m = PARAM_RE.exec(part);
    if (m === null) return null;
    const [, name, v] = m;
    if (!names.includes(name) || out.has(name)) return null;
    out.set(name, v);
  }
  return out.size === names.length ? out : null;
}

const isEventStream = (headers) =>
  headers.some(
    ([name, value]) => name.toLowerCase() === 'content-type'
      && String(value).split(';')[0].trim().toLowerCase() === 'text/event-stream',
  );

function parseBody(chunks) {
  const buf = Buffer.concat((chunks ?? []).map((chunk) => Buffer.from(chunk, 'base64url')));
  // At most one BOM at the very start is ignored and unsigned (2.14).
  return buf.subarray(0, BOM.length).equals(BOM) ? buf.subarray(BOM.length) : buf;
}

function parseField(line) {
  const colon = line.indexOf(COLON);
  if (colon < 0) return { name: line, value: EMPTY }; // bare name is an empty value (2.13)
  const value = line.subarray(colon + 1);
  return { name: line.subarray(0, colon), value: value[0] === SP ? value.subarray(1) : value };
}

// Yields one event per blank line that follows at least one field line. `end` is
// the offset just past the terminating blank line, which 4.5 maps to a time.
function* parseEvents(buf) {
  let start = 0;
  let lines = [];
  for (let i = 0; i < buf.length;) {
    const byte = buf[i];
    if (byte !== CR && byte !== LF) {
      i += 1;
      continue;
    }
    const contentEnd = i;
    // A lone CR and a CRLF are both one terminator.
    const termEnd = byte === CR && buf[i + 1] === LF ? i + 2 : i + 1;
    if (contentEnd === start) {
      if (lines.length > 0) yield { lines, end: termEnd };
      lines = [];
    } else if (buf[start] === COLON) {
      // comment: belongs to no event, unsigned (2.12)
    } else {
      lines.push(parseField(buf.subarray(start, contentEnd)));
    }
    i = termEnd;
    start = termEnd;
  }
  // An unterminated trailing line is discarded (2.14).
}

// Frame grammar, 2.6-2.13. Returns the frame, or null for stream_bad_frame.
function parseFrame(lines) {
  let kind = null;
  let jack = null;
  const data = [];
  for (const line of lines) {
    const value = utf8(line.value);
    if (value === null) return null; // 2.10
    const name = line.name.toString('latin1');
    if (name === 'event') {
      if (kind !== null || !EVENT_NAMES.includes(value)) return null; // 2.8
      kind = value;
    } else if (name === 'data') {
      data.push(value);
    } else if (name === 'jack') {
      if (jack !== null) return null; // exactly one jack line (2.7)
      jack = value;
    } else if (name === 'id' || name === 'retry') {
      return null; // 2.11
    }
    // any other field carries nothing and is ignored (2.13)
  }
  if (jack === null) return null;
  const params = parseParams(jack, ['seq', 'ts', 'sig']);
  if (params === null) return null;
  if (!SEQ_RE.test(params.get('seq')) || !TS_RE.test(params.get('ts'))) return null;
  if (strictB64u(params.get('sig'), 64) === null) return null;
  const value = data.join('\n'); // 2.10
  const frameKind = kind ?? 'message'; // SSE default event type (2.6)
  // 2.9: the kind is a function of the signed data, so it cannot be forged.
  if (frameKind === 'message' ? value === '' : value !== '') return null;
  const seq = Number(params.get('seq'));
  if (!Number.isSafeInteger(seq)) return null;
  return { kind: frameKind, data: value, seq, ts: Number(params.get('ts')), sig: params.get('sig') };
}

// 2.18: the template with `<code>` filled in, up to the start of `<n>`.
const SIGNAL_TEMPLATES = SIGNAL_CODES.map((code) => ({
  code,
  prefix: '{"jsonrpc":"2.0","method":"' + SIGNAL_METHOD + '","params":{"code":"' + code + '","limit":',
}));
const SIGNAL_SUFFIX = '}}';
const LIMIT_RE = /^(?:0|[1-9][0-9]*)$/; // canonical decimal (2.18)
const LIMIT_MAX = 9007199254740991n;

// 2.18 transport signal: returns the signalled code, or null for an ordinary
// message frame. Byte-exact, so extra members, whitespace or a non-canonical
// limit all stay deliverable.
export function parseSignal(data) {
  for (const { code, prefix } of SIGNAL_TEMPLATES) {
    if (!data.startsWith(prefix) || !data.endsWith(SIGNAL_SUFFIX)) continue;
    const limit = data.slice(prefix.length, data.length - SIGNAL_SUFFIX.length);
    if (!LIMIT_RE.test(limit) || BigInt(limit) > LIMIT_MAX) continue;
    return { code };
  }
  return null;
}

// 4.2 open header, in order, with the scheme read first on the raw value (2.3).
function openHeader(response, state) {
  const values = [];
  for (const [name, value] of response.headers) {
    if (name.toLowerCase() === 'jack-auth') values.push(value);
  }
  if (values.length === 0) return { code: 'stream_missing_auth' };
  if (values.length > 1) return { code: 'stream_malformed_auth' };
  const raw = String(values[0]);
  const sp = raw.indexOf(' ');
  const scheme = sp < 0 ? raw : raw.slice(0, sp);
  if (scheme !== 's1') {
    return { code: SCHEME_RE.test(scheme) ? 'stream_unsupported_version' : 'stream_malformed_auth' };
  }
  const params = sp < 0 ? null : parseParams(raw.slice(sp + 1), ['kid', 'ts', 'sid', 'sig']);
  if (params === null || !TS_RE.test(params.get('ts'))) return { code: 'stream_malformed_auth' };
  if (strictB64u(params.get('kid'), 32) === null) return { code: 'stream_malformed_auth' };
  if (strictB64u(params.get('sid'), 16) === null) return { code: 'stream_malformed_auth' };
  if (strictB64u(params.get('sig'), 64) === null) return { code: 'stream_malformed_auth' };
  const kid = params.get('kid');
  const ts = Number(params.get('ts'));
  const sid = params.get('sid');
  const sig = params.get('sig');
  if (kid !== state.pinned_server_kid) return { code: 'stream_unknown_server_key' };
  if (Math.abs(state.now - ts) > state.window_seconds) return { code: 'stream_out_of_window' };
  if (state.successor_activation != null && ts >= state.successor_activation) {
    return { code: 'stream_after_cutoff' };
  }
  const signingString = openSigningString({ status: response.status, requestSig: state.request_sig, kid, ts, sid });
  if (!verifyMessage(state.pinned_server_public_key, signingString, sig)) return { code: 'stream_bad_signature' };
  return { kid, ts, sid, sig };
}

export function verifyStream({ response, state, silentAfterMs, arrivalMs, consumer = 'mcp' }) {
  // 6.1 and 6.2: those are the only two consumers the spec maps.
  if (consumer !== 'mcp' && consumer !== 'stdio') throw new Error(`unknown consumer: ${consumer}`);

  // 1.4: anything else is a v1 response, including the signed refusals.
  if (response.status !== 200 || !isEventStream(response.headers)) {
    throw new Error('response is not an s1 response: verify it with the v1 response path');
  }

  const open = openHeader(response, state);
  if (open.code) {
    return { messages: [], terminal: { state: 'error', code: open.code, frames_verified: 0 } };
  }

  const body = parseBody(response.stream_b64u);
  const nows = state.frame_nows;
  // 4.5: decoded chunk lengths map a body offset back to its arrival time.
  const chunkLens = (response.stream_b64u ?? []).map((c) => Buffer.from(c, 'base64url').length);
  const idleMs = state.stream_idle_ms ?? 90000;
  const timeAt = (offset) => {
    if (arrivalMs == null) return 0;
    let start = 0;
    for (let i = 0; i < chunkLens.length; i += 1) {
      const end = start + chunkLens[i];
      if (offset < end) return arrivalMs[i] ?? 0;
      start = end;
    }
    return 0;
  };
  const messages = [];
  let framesVerified = 0;
  let expectedSeq = 0;
  let expectedPrev = open.sig;
  let previousTs = -Infinity;
  let last = 0; // 4.5: ms since the open header was verified
  let ended = false;

  const fail = (code) => ({ messages, terminal: { state: 'error', code, frames_verified: framesVerified } });

  for (const event of parseEvents(body)) {
    // 4.5 first: a frame that arrives after the deadline is not verified.
    const t = timeAt(event.end - 1);
    if (t - last > idleMs) return fail('stream_idle');
    if (ended) return fail('stream_out_of_order'); // 2.16: nothing may follow the end frame
    const frame = parseFrame(event.lines);
    if (frame === null) return fail('stream_bad_frame');
    // 2.17: the cap bounds the data value, not the bytes of the event.
    if (Buffer.byteLength(frame.data, 'utf8') > state.frame_max_bytes) return fail('stream_frame_too_large');
    if (frame.seq !== expectedSeq) return fail('stream_out_of_order');
    // The client samples its clock per frame; the last sample repeats (4.3).
    const now = nows?.[Math.min(framesVerified, nows.length - 1)] ?? state.now;
    if (Math.abs(now - frame.ts) > state.window_seconds || frame.ts < previousTs) {
      return fail('stream_stale_frame');
    }
    if (state.successor_activation != null && frame.ts >= state.successor_activation) {
      return fail('stream_after_cutoff');
    }
    const signingString = frameSigningString({
      sid: open.sid,
      seq: frame.seq,
      ts: frame.ts,
      prev: expectedPrev,
      hash: dataHash(frame.data),
    });
    if (!verifyMessage(state.pinned_server_public_key, signingString, frame.sig)) {
      return fail('stream_bad_signature');
    }
    framesVerified += 1;
    last = t;
    expectedSeq += 1;
    previousTs = frame.ts;
    expectedPrev = frame.sig;
    // 4.3 step 6: the signal counts as verified, is not delivered, ends the
    // stream; no end frame is read or required after it.
    const signal = frame.kind === 'message' ? parseSignal(frame.data) : null;
    if (signal !== null) {
      return { messages, terminal: { state: 'error', code: signal.code, frames_verified: framesVerified } };
    }
    if (frame.kind === 'jack-end') {
      ended = true;
      continue;
    }
    // 4.3 step 7 / 6.2: one stdout line per data value, so a raw CR or LF aborts.
    if (consumer === 'stdio' && (frame.data.includes('\n') || frame.data.includes('\r'))) {
      return fail('stream_bad_frame');
    }
    // 4.6: only a verified message frame reaches the MCP layer.
    messages.push(frame.data);
  }

  // 4.4 and 4.5: a measured silence means the harness stopped reading a live
  // connection, not that the body ended.
  if (!ended && silentAfterMs !== undefined && silentAfterMs !== null) {
    if (silentAfterMs > idleMs) return fail('stream_idle');
    return { messages, terminal: { state: 'ok' } };
  }

  if (!ended) return fail('stream_truncated');
  return { messages, terminal: { state: 'ok' } };
}

export function serializeFrame({ kind, data, seq, ts, sig }) {
  const lines = [`event: ${kind}`];
  for (const piece of String(data).split('\n')) {
    lines.push(piece === '' ? 'data:' : `data: ${piece}`);
  }
  lines.push(`jack: seq=${seq},ts=${ts},sig=${sig}`);
  return `${lines.join('\n')}\n\n`;
}

export function buildStream({ privKey, kid, sid, status, requestSig, openTs, frames }) {
  const open_signing_string = openSigningString({ status, requestSig, kid, ts: openTs, sid });
  const open_sig = signMessage(privKey, open_signing_string);
  const jack_auth = `s1 kid=${kid},ts=${openTs},sid=${sid},sig=${open_sig}`;
  let prev = open_sig;
  const signed = [];
  const body = [];
  for (const frame of frames) {
    const kind = frame.data === '' ? 'jack-end' : 'message';
    const data_hash = dataHash(frame.data);
    const signing_string = frameSigningString({ sid, seq: frame.seq, ts: frame.ts, prev, hash: data_hash });
    const sig = signMessage(privKey, signing_string);
    signed.push({ seq: frame.seq, ts: frame.ts, prev, data_hash, signing_string, sig });
    body.push(serializeFrame({ kind, data: frame.data, seq: frame.seq, ts: frame.ts, sig }));
    prev = sig;
  }
  return { jack_auth, open_signing_string, open_sig, frames: signed, body: body.join('') };
}
