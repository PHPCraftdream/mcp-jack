// spec/tools/modern/streams/streams.test.mjs
// Checks the s1 generator (spec 05 section 9) against its own vectors and the
// independent reference implementation. Deterministic; no fixtures on disk.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { test, describe } from 'node:test';
import { stableStringify } from '../../gen/core.mjs';
import { CLIENT_CODES, parseSignal, verifyStream } from './reference.mjs';
import { buildVectors, buildCaseChecks } from './vectors/vectors-build.mjs';
import { MARKER } from './fixtures.mjs';
import { default as generator } from './index.mjs';
import { RULES, EXEMPT, REQUIREMENTS, CLIENT_COUNT } from './rules.mjs';

const SPEC = new URL('../../../05-signed-streams.md', import.meta.url);
const CLIENT = 'stream-vectors.json';
const BUILD = 'stream-build-vectors.json';
const BUILD_COUNT = 8;
const STREAM_ID = /^stream-[a-z0-9-]+$/;
const BUILD_ID = /^build-[a-z0-9-]+$/;
// Section 9: the numbered rules of sections 1-6 and the Exemptions table rows.
const HEADING = /^### (\d+\.\d+)/gm;
const EXEMPT_ROW = /^\| `(\d+\.\d+)` \|/gm;
const IN_SIX = /^[1-6]\./;

const casesOf = ({ files }, key) => files[key].cases;
const idsOf = (text, re) => [...text.matchAll(re)].map((m) => m[1]);
const unb64 = (piece) => Buffer.from(piece, 'base64url');
const b64u = (buf) => Buffer.from(buf).toString('base64url');

// Section 9 data_fill: a marker chunk expands to N copies of one ASCII byte
// before the body is parsed. A case without the field keeps its chunks.
const expand = (c) => {
  const fill = c.data_fill;
  const chunks = fill === undefined
    ? c.response.stream_b64u
    : c.response.stream_b64u.map((piece) => (piece === MARKER
      ? b64u(Buffer.from(fill.byte.repeat(fill.count), 'utf8'))
      : piece));
  return { status: c.response.status, headers: c.response.headers, stream_b64u: chunks };
};

// Run the reference over a vector under its own clock, silence and consumer
// (4.5, 6.2), optionally with one response field replaced.
const verify = (c, over = {}) => verifyStream({
  response: { ...expand(c), ...over },
  state: c.state,
  silentAfterMs: c.silent_after_ms,
  consumer: c.consumer,
});

const bodyOf = (c) => Buffer.concat(expand(c).stream_b64u.map(unb64));
const chunksOf = (text) => [b64u(Buffer.from(text, 'latin1'))];

// Flip the character at `at` to another base64url letter.
const flip = (str, at) => `${str.slice(0, at)}${str[at] === 'A' ? 'B' : 'A'}${str.slice(at + 1)}`;

// Index 40 of a sig value: mid-signature, so the length and the canonical
// trailing bits survive and only the signature changes (4.5).
const SIG_MID = 40;

const singleOk = () => casesOf(generator.build(), CLIENT).find((c) => c.id === 'stream-ok-single');

describe('signed streams (s1)', () => {
  test('build() is deterministic', () => {
    const a = generator.build();
    const b = generator.build();
    assert.equal(stableStringify(a), stableStringify(b));
    assert.deepEqual(Object.keys(a.files).sort(), [BUILD, CLIENT].sort());
    assert.equal(a.files[CLIENT].cases.length, CLIENT_COUNT);
    assert.equal(typeof a.casesMarkdown, 'string');
    assert.ok(a.casesMarkdown.length > 0);
    assert.ok(a.casesMarkdown.includes('# Signed stream cases'));
  });

  test('case ids are unique and well formed', () => {
    const built = generator.build();
    const client = casesOf(built, CLIENT);
    const builds = casesOf(built, BUILD);
    assert.equal(client.length, CLIENT_COUNT);
    assert.equal(builds.length, BUILD_COUNT);
    const ids = new Set();
    for (const c of client) {
      assert.match(c.id, STREAM_ID);
      assert.ok(!ids.has(c.id), c.id);
      ids.add(c.id);
    }
    for (const c of builds) {
      assert.match(c.id, BUILD_ID);
      assert.ok(!ids.has(c.id), c.id);
      ids.add(c.id);
    }
  });

  test('every client error code is covered', () => {
    const codes = casesOf(generator.build(), CLIENT)
      .filter((c) => c.expect.terminal.state === 'error')
      .map((c) => c.expect.terminal.code);
    const known = new Set(CLIENT_CODES);
    assert.equal(CLIENT_CODES.length, 13);
    for (const code of codes) assert.ok(known.has(code), code);
    for (const code of CLIENT_CODES) assert.ok(codes.includes(code), code);
  });

  test('every rule has a vector and every vector has a rule', () => {
    const built = generator.build();
    const clientIds = casesOf(built, CLIENT).map((c) => c.id);
    const buildIds = casesOf(built, BUILD).map((c) => c.id);
    const all = new Set([...clientIds, ...buildIds]);
    const text = readFileSync(SPEC, 'utf8');

    // Every numbered heading of sections 1-6 is a rule and vice versa.
    const headings = idsOf(text, HEADING).filter((id) => IN_SIX.test(id));
    assert.deepEqual(new Set(headings), new Set(RULES));

    // The Exemptions table is the same set the generator exports.
    const exempt = new Set(idsOf(text, EXEMPT_ROW));
    assert.deepEqual(exempt, new Set(EXEMPT));

    for (const rule of RULES) {
      const entry = REQUIREMENTS[rule];
      const isMapped = entry !== undefined && entry.vectors.length > 0;
      const isExempt = exempt.has(rule);
      assert.ok(!(isMapped && isExempt), `${rule}: both mapped and exempt`);
      assert.ok(isMapped || isExempt, `${rule}: neither mapped nor exempt`);
    }

    const listed = new Set();
    for (const [rule, { vectors }] of Object.entries(REQUIREMENTS)) {
      assert.ok(RULES.includes(rule), `${rule}: mapped rule has no spec heading`);
      for (const id of vectors) {
        assert.ok(all.has(id), `${rule}: ${id} is not a fixture case`);
        listed.add(id);
      }
    }
    for (const id of all) assert.ok(listed.has(id), `${id}: no rule lists it`);
  });

  test('the spec text names every client code and both domains', () => {
    const text = readFileSync(SPEC, 'utf8');
    for (const code of CLIENT_CODES) assert.ok(text.includes(code), code);
    assert.ok(text.includes('mcp-jack/stream1/open'));
    assert.ok(text.includes('mcp-jack/stream1/frame'));
  });

  test('the reference rejects hand-mutated streams', () => {
    const c = singleOk();
    assert.deepEqual(verify(c), c.expect);

    // a: one mid-sig character changed in the open header value.
    const headers = expand(c).headers.map(([name, value]) => (name.toLowerCase() === 'jack-auth'
      ? [name, flip(value, value.lastIndexOf('sig=') + 'sig='.length + SIG_MID)]
      : [name, value]));
    const open = verify(c, { headers });
    assert.equal(open.terminal.state, 'error');
    assert.equal(open.terminal.code, 'stream_bad_signature');

    // b: one mid-sig character changed in the end frame, after the message.
    const text = bodyOf(c).toString('latin1');
    const sigAt = text.lastIndexOf('sig=') + 'sig='.length + SIG_MID;
    const frame = verify(c, { stream_b64u: chunksOf(flip(text, sigAt)) });
    assert.equal(frame.terminal.state, 'error');
    assert.equal(frame.terminal.code, 'stream_bad_signature');
    assert.deepEqual(frame.messages, c.expect.messages);

    // c: the last three bytes gone, so the end frame never terminates (4.4).
    const body = bodyOf(c);
    const cut = verify(c, { stream_b64u: [b64u(body.subarray(0, body.length - 3))] });
    assert.equal(cut.terminal.state, 'error');
    assert.equal(cut.terminal.code, 'stream_truncated');

    // d: the data of the message changed, so its frame does not verify (4.7).
    const from = text.indexOf('"progress":1');
    assert.ok(from > 0);
    const edited = `${text.slice(0, from)}"progress":7${text.slice(from + '"progress":1'.length)}`;
    const data = verify(c, { stream_b64u: chunksOf(edited) });
    assert.equal(data.terminal.state, 'error');
    assert.deepEqual(data.messages, []);
  });

  test('routing rejects non-s1 responses', () => {
    const state = singleOk().state;
    const response = (status, contentType, stream_b64u = []) => ({
      status,
      headers: [['Content-Type', contentType]],
      stream_b64u,
    });
    // 1.4: a signed refusal, a JSON 200, a 500 and an empty 204 are v1.
    assert.throws(() => verifyStream({ response: response(429, 'application/json'), state }), Error);
    assert.throws(() => verifyStream({ response: response(200, 'application/json'), state }), Error);
    assert.throws(() => verifyStream({ response: response(500, 'text/event-stream'), state }), Error);
    assert.throws(() => verifyStream({ response: response(204, 'text/event-stream'), state }), Error);
  });

  test('every build case is a positive control', () => {
    const checks = new Map(buildCaseChecks.map((c) => [c.id, c]));
    for (const c of buildVectors) {
      const check = checks.get(c.id);
      assert.ok(check !== undefined, c.id);
      const got = verifyStream({
        response: {
          status: 200,
          headers: [['Content-Type', 'text/event-stream'], ['Jack-Auth', c.expect.jack_auth]],
          stream_b64u: [c.expect.stream_b64u],
        },
        state: check.state,
      });
      // 4.3 step 6: a verified 2.18 signal ends the stream undelivered.
      const messages = check.expectedMessages.filter((data) => parseSignal(data) === null);
      assert.deepEqual(got, { messages, terminal: check.expectedTerminal }, c.id);
    }
  });

  test('the stream signal and idle rules are exercised', () => {
    const client = casesOf(generator.build(), CLIENT);
    // 4.5: the gaps between successive chunk arrivals, in ms.
    const gaps = (c) => c.arrival_ms.slice(1).map((t, i) => t - c.arrival_ms[i]);

    // 4.5: one millisecond past the threshold is idle, by arrival time and by
    // silence alike; a BOM or a comment moves no verified frame to a later time.
    const idle = client.filter((c) => c.expect.terminal.code === 'stream_idle');
    assert.equal(idle.length, 5);
    const byId = (id) => {
      const c = idle.find((v) => v.id === id);
      assert.ok(c !== undefined, id);
      return c;
    };
    const timeout = byId('stream-idle-timeout');
    assert.ok(gaps(timeout).includes(timeout.state.stream_idle_ms + 1));
    const silent = byId('stream-idle-open-silence');
    assert.deepEqual(silent.response.stream_b64u, []);
    assert.ok(silent.silent_after_ms > silent.state.stream_idle_ms);
    const bom = byId('stream-idle-bom-late-chunk');
    assert.equal(bom.expect.terminal.frames_verified, 0);
    assert.ok(gaps(bom).some((g) => g > bom.state.stream_idle_ms));
    const mirror = byId('stream-idle-blank-line-late-chunk');
    assert.equal(mirror.expect.terminal.frames_verified, 0);
    const comment = byId('stream-idle-comment-silence');
    assert.equal(comment.expect.terminal.frames_verified, 1);
    assert.ok(comment.arrival_ms.length > 0);
    assert.ok(comment.silent_after_ms > 0);

    // 4.5: heartbeats keep every gap under the threshold and still exceed it in
    // total; a gap of exactly the threshold between verified frames is alive.
    const alive = client.filter((c) => c.arrival_ms !== undefined
      && c.expect.terminal.state === 'ok'
      && gaps(c).every((g) => g < c.state.stream_idle_ms));
    assert.equal(alive.length, 1);
    assert.ok(gaps(alive[0]).reduce((a, b) => a + b, 0) > alive[0].state.stream_idle_ms);
    const boundary = client.find((c) => c.arrival_ms !== undefined
      && c.expect.terminal.state === 'ok'
      && gaps(c).includes(c.state.stream_idle_ms));
    assert.ok(boundary !== undefined);

    // 2.18: the signal is verified but never delivered.
    const signal = client.find((c) => c.id === 'stream-signal-too-large');
    assert.equal(signal.expect.terminal.state, 'error');
    assert.equal(signal.expect.terminal.code, 'stream_frame_too_large');
    assert.equal(signal.expect.terminal.frames_verified, 2);
    assert.equal(signal.expect.messages.length, 1);
    assert.equal(signal.expect.mcp_complete, false);

    // 2.18: a canonical zero limit is still a signal, at the first frame.
    const zero = client.find((c) => c.id === 'stream-signal-limit-zero');
    assert.equal(zero.expect.terminal.code, 'stream_frame_too_large');
    assert.equal(zero.expect.terminal.frames_verified, 1);

    // 5.2: the end frame itself can cross the cutoff; the stream cannot complete.
    const endCut = client.find((c) => c.id === 'stream-frame-end-after-cutoff');
    assert.equal(endCut.expect.terminal.code, 'stream_after_cutoff');
    assert.equal(endCut.expect.terminal.frames_verified, 1);
    const noEndCut = client.find((c) => c.id === 'stream-frame-after-cutoff');
    assert.equal(noEndCut.expect.terminal.code, 'stream_after_cutoff');
    assert.equal(noEndCut.expect.terminal.frames_verified, 0);

    // 6.2: the stdio consumer aborts on a data value holding a raw LF.
    const stdio = client.filter((c) => c.consumer === 'stdio');
    assert.ok(stdio.length > 0);
    assert.ok(stdio.some((c) => c.expect.terminal.code === 'stream_bad_frame'));

    // 6.3: seven close shapes state whether the last message was the response;
    // only the one carrying the opening request's result completes it, and a
    // body without an end frame is truncated instead (4.4).
    const closes = client.filter((c) => c.id.startsWith('stream-close-'));
    assert.equal(closes.length, 7);
    for (const c of closes) assert.equal(typeof c.expect.mcp_complete, 'boolean', c.id);
    assert.equal(closes.filter((c) => c.expect.mcp_complete).length, 1);
    const noEnd = closes.find((c) => c.id === 'stream-close-no-end-frame');
    assert.ok(noEnd !== undefined);
    assert.equal(noEnd.expect.terminal.code, 'stream_truncated');
    assert.equal(noEnd.expect.mcp_complete, false);

    // 2.17, 9: the two cap vectors keep their one huge data value as a marker.
    const atCap = client.find((c) => c.id === 'stream-ok-frame-max-boundary');
    const overCap = client.find((c) => c.id === 'stream-frame-oversize');
    assert.equal(atCap.data_fill.count, 1048576);
    assert.equal(overCap.data_fill.count, 1048577);
    assert.ok(typeof atCap.expect.messages[0] === 'object');
    assert.equal(typeof atCap.expect.messages[0].data_fill.count, 'number');
  });
});
