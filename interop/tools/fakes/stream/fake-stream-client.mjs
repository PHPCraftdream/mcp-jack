#!/usr/bin/env node
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../');
const arg = name => { const i = process.argv.indexOf(name); return i < 0 ? null : process.argv[i + 1]; };
const scenario = arg('--scenario') || '', matrix = arg('--matrix') || 'stream', url = new URL(arg('--url') || 'http://127.0.0.1:1');
const scenarioMeta = JSON.parse(readFileSync(join(root, 'interop/stream-scenarios.json'), 'utf8')).matrices[matrix]?.find(item => item.id === scenario);
const clockFile = arg('--clock-file'), aliceSeed = arg('--seed-hex') || '', pinnedPublic = arg('--server-public-key') || '';
const keys = JSON.parse(readFileSync(join(root, 'spec/fixtures/keys.json'), 'utf8')).keys;
const alice = keys.find(key => key.name === 'alice'), svc = keys.find(key => key.name === 'svc');
const keyFromSeed = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8' });
const publicKey = b64 => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b64, 'base64url')]), format: 'der', type: 'spki' });
const privateKey = keyFromSeed(aliceSeed), pinnedKey = publicKey(pinnedPublic);
const b64 = bytes => Buffer.from(bytes).toString('base64url'), sha = bytes => createHash('sha256').update(bytes).digest('base64url');
const strictB64 = (value, length) => typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').length === length && b64(Buffer.from(value, 'base64url')) === value;
const now = () => { const value = Number(readFileSync(clockFile, 'utf8').trim()); if (!Number.isSafeInteger(value) || value < 0) throw Error('invalid shared clock'); return value; };
const producer = scenarioMeta?.producer || scenario;
const requestIdDefault = scenarioMeta?.request_id ?? 1;
const requestMethod = scenarioMeta?.request_method || ({ 'progress-final': 'tools/call', 'subscriptions-listen': 'subscriptions/listen', 'list-changed': 'subscriptions/listen', 'events-stream': 'events/stream', cancel: 'tools/call', 'max-duration': 'tools/call' })[producer] || 'tools/call';
const requestParams = scenario === 'list-changed' ? { notifications: ['notifications/events/list_changed'] } : (scenarioMeta?.request_params || {});
const requestBody = Buffer.from(arg('--request-body-json') || JSON.stringify({ jsonrpc: '2.0', id: requestIdDefault, method: requestMethod, params: { ...requestParams, _meta: { 'io.modelcontextprotocol/protocolVersion': arg('--modern-version') || '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'mcp-jack-interop-stream-client', version: '1.0.0' } } } }));
let requestObject;
try { requestObject = JSON.parse(requestBody.toString('utf8')); } catch { throw Error('invalid request body JSON'); }
const requestId = Object.hasOwn(requestObject || {}, 'id') ? requestObject.id : null;
const wireMcpMethod = requestObject?.method;
const protocolVersion = requestObject?.params?._meta?.['io.modelcontextprotocol/protocolVersion'] || '2026-07-28';
let mirrorHeaders = [];
try { mirrorHeaders = JSON.parse(arg('--mirror-headers-json') || JSON.stringify([['MCP-Protocol-Version', protocolVersion], ['Mcp-Method', wireMcpMethod]])); } catch { throw Error('invalid mirror headers'); }
const requestTs = now();
const nonce = arg('--nonce') || b64(createHash('sha256').update(`${matrix}\n${scenario}`).digest().subarray(0, 16));
if (!strictB64(nonce, 16)) throw Error('nonce must be canonical 16-byte base64url');
const aud = arg('--aud');
if (typeof aud !== 'string' || aud.length === 0) throw Error('--aud is required');
const requestText = ['mcp-jack/v1/request', 'POST', '/mcp', aud, alice.kid, String(requestTs), nonce, sha(requestBody)].join('\n');
const requestSig = b64(sign(null, Buffer.from(requestText, 'utf8'), privateKey));
const requestHeaders = [['content-type', 'application/json'], ['content-length', String(requestBody.length)], ['Jack-Auth', `v1 kid=${alice.kid},ts=${requestTs},nonce=${nonce},sig=${requestSig}`], ...mirrorHeaders, ...(arg('--jack-accept') ? [['Jack-Accept', arg('--jack-accept')]] : [])];
let emitted = false, badEvidenceEmitted = false;
function terminal(outcome, code, status, evidence, open, frames, verifiedCount = frames?.length || 0, failureFrame = null) {
  if (emitted) return; emitted = true;
  const terminalFrame = frames?.at(-1)?.kind === 'end' ? { kind: 'end', sig: frames.at(-1).sig } : null;
  let lastMessage = null;
  for (const frame of frames || []) {
    if (frame.kind !== 'end' && frame.kind !== 'signal') {
      try { lastMessage = JSON.parse(frame.data); } catch { lastMessage = null; }
    }
  }
  const hasResult = lastMessage && Object.hasOwn(lastMessage, 'result');
  const hasError = lastMessage && Object.hasOwn(lastMessage, 'error');
  const mcpComplete = outcome === 'complete' && !!terminalFrame && scenario !== 'idle' &&
    lastMessage?.jsonrpc === '2.0' && Object.hasOwn(lastMessage, 'id') && lastMessage.id === requestId && hasResult !== hasError &&
    !Object.hasOwn(lastMessage, 'method');
  console.log(JSON.stringify({ type: 'terminal', scenario, outcome, code: code || null, http_status: status ?? null,
    http_code: status === 501 ? 'streaming_unsupported' : status === 429 ? 'stream_limit_exceeded' : null,
    frames_verified: verifiedCount, request_id: requestId, mcp_complete: mcpComplete,
    terminal_frame: terminalFrame, request_sig: requestSig, v1_evidence: evidence || null, open: open ?? null, frames: frames ?? [],
    failure_frame: failureFrame ?? null, successor_activation: arg('--successor-activation') ? Number(arg('--successor-activation')) : null }));
}
function refusal(res, raw) {
  const status = res.statusCode;
  if (status === 401) {
    let replayed = false;
    try { replayed = JSON.parse(raw.toString('utf8'))?.error?.code === 'replayed_nonce'; } catch { replayed = false; }
    terminal(replayed ? 'refused' : 'error', replayed ? 'replayed_nonce' : 'stream_bad_frame', status, null, null, [], 0);
    return;
  }
  const auth = String(res.headers['jack-auth'] || ''), match = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)$/.exec(auth);
  const kid = match?.[1], tsText = match?.[2], sig = match?.[3], ts = Number(tsText);
  const evidence = { status, ts, kid, request_sig: requestSig, body_b64u: b64(raw), sig };
  let valid = status === 429 || status === 501;
  valid &&= kid === svc.kid && /^(0|[1-9][0-9]{0,11})$/.test(tsText || '') && Number.isSafeInteger(ts) && strictB64(sig, 64);
  if (valid) valid = verify(null, Buffer.from(['mcp-jack/v1/response', String(status), requestSig, kid, tsText, sha(raw)].join('\n')), pinnedKey, Buffer.from(sig, 'base64url'));
  if (valid) {
    try {
      const parsed = JSON.parse(raw.toString('utf8'));
      valid = parsed?.jsonrpc === '2.0' && parsed.id === requestObject.id && parsed.error?.code === -32603 && parsed.error?.message === (status === 501 ? 'streaming_unsupported' : 'stream_limit_exceeded');
    } catch { valid = false; }
  }
  terminal(valid ? 'refused' : 'error', valid ? (status === 501 ? 'streaming_unsupported' : 'stream_limit_exceeded') : 'stream_bad_signature', status, valid ? evidence : null, null, [], 0);
}
function parseOpen(value, response, expectedRequestSig) {
  if (response.statusCode !== 200 || !/^text\/event-stream(?:\s*;|\s*$)/i.test(String(response.headers['content-type'] || ''))) throw Error('stream_bad_frame');
  if (Array.isArray(value)) throw Error('stream_malformed_auth');
  const match = /^s1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),sid=([A-Za-z0-9_-]+),sig=([A-Za-z0-9_-]+)$/.exec(String(value || ''));
  if (!match) throw Error(value ? 'stream_malformed_auth' : 'stream_missing_auth');
  const [, kid, tsText, sid, sig] = match, ts = Number(tsText);
  if (!strictB64(kid, 32) || !strictB64(sid, 16) || !strictB64(sig, 64)) throw Error('stream_malformed_auth');
  if (kid !== svc.kid) throw Error('stream_unknown_server_key');
  const openText = ['mcp-jack/stream1/open', '200', expectedRequestSig, kid, tsText, sid].join('\n');
  if (!verify(null, Buffer.from(openText), pinnedKey, Buffer.from(sig, 'base64url'))) throw Error('stream_bad_signature');
  return { sid, kid, ts, sig };
}
function frameFrom(block, open, previous, expectedSeq) {
  const lines = block.split(/\r\n|\n|\r/), events = [], data = [], jacks = [];
  for (const line of lines) {
    if (!line || line.startsWith(':')) continue;
    const at = line.indexOf(':'), name = at < 0 ? line : line.slice(0, at), raw = at < 0 ? '' : line.slice(at + 1), value = raw.startsWith(' ') ? raw.slice(1) : raw;
    if (name === 'event') events.push(value);
    else if (name === 'data') data.push(value);
    else if (name === 'jack') jacks.push(value);
    else if (name === 'id' || name === 'retry') throw Error('stream_bad_frame');
  }
  if (events.length > 1 || jacks.length !== 1) throw Error('stream_bad_frame');
  const event = events[0] || 'message', auth = /^seq=(0|[1-9][0-9]{0,14}),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)$/.exec(jacks[0]);
  if (!auth || !['message', 'jack-end'].includes(event)) throw Error('stream_bad_frame');
  const [, seqText, tsText, sig] = auth, seq = Number(seqText), ts = Number(tsText), dataValue = data.join('\n');
  if (!Number.isSafeInteger(seq) || seq !== expectedSeq) throw Error('stream_out_of_order');
  if (!strictB64(sig, 64) || (event === 'message' ? dataValue === '' : dataValue !== '')) throw Error('stream_bad_frame');
  if (Buffer.from(dataValue, 'utf8').toString('utf8') !== dataValue || dataValue.includes('\r')) throw Error('stream_bad_frame');
  const signing = ['mcp-jack/stream1/frame', open.sid, String(seq), String(ts), previous, sha(Buffer.from(dataValue, 'utf8'))].join('\n');
  if (!verify(null, Buffer.from(signing), pinnedKey, Buffer.from(sig, 'base64url'))) throw Error('stream_bad_signature');
  return { kind: event === 'jack-end' ? 'end' : 'message', sid: open.sid, kid: open.kid, seq, ts, data: dataValue, sig };
}
function isSignal(data) {
  const m = /^\{"jsonrpc":"2\.0","method":"notifications\/jack\/stream_error","params":\{"code":"(stream_frame_too_large)","limit":(0|[1-9][0-9]*)\}\}$/.exec(data);
  return m && BigInt(m[2]) <= 9007199254740991n ? m[1] : null;
}
// Object form lets Node add Host; the flat array form sends none and the server answers 400.
const headerObject = {};
for (const [name, value] of requestHeaders) headerObject[name] = Object.hasOwn(headerObject, name) ? [].concat(headerObject[name], value) : value;
const requestOptions = { hostname: url.hostname, port: url.port, path: '/mcp', method: 'POST', headers: headerObject };
  const request = http.request(requestOptions, response => {
  const status = response.statusCode;
  if (status !== 200 || !/^text\/event-stream(?:\s*;|\s*$)/i.test(String(response.headers['content-type'] || ''))) {
    const chunks = []; response.on('data', chunk => chunks.push(chunk));
    response.on('end', () => refusal(response, Buffer.concat(chunks))); return;
  }
  let open, buffer = '', previous, previousTs = -Infinity, seq = 0, frames = [], ended = false, done = false;
  const idleTimer = scenario === 'idle' ? setTimeout(() => { if (!done) { finish('error', 'stream_idle'); response.destroy(); } }, Number(arg('--idle-timeout-ms') || scenarioMeta?.stream_options?.idleTimeoutMs || 90000)) : null;
  const finish = (outcome, code, failureFrame = null, verifiedCount = frames.length) => { if (done) return; done = true; if (idleTimer) clearTimeout(idleTimer); terminal(outcome, code, status, null, open, frames, verifiedCount, failureFrame); };
  try { open = parseOpen(response.headers['jack-auth'], response, requestSig); previous = open.sig; }
  catch (error) { response.destroy(); finish('error', error.message); return; }
  const onBlock = block => {
    if (done) return;
    try {
      const rawJack = /(?:^|\n)jack: seq=(0|[1-9][0-9]{0,14}),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)/.exec(block);
      if (rawJack) {
        const wireTs = Number(rawJack[2]);
        if (Math.abs(now() - wireTs) > 30 || wireTs < previousTs) throw Error('stream_stale_frame');
      }
      const activation = Number(arg('--successor-activation'));
      if (Number.isSafeInteger(activation) && rawJack && Number(rawJack[2]) >= activation) {
        const rawData = [...block.matchAll(/(?:^|\n)data: ?([^\r\n]*)/g)].map(match => match[1]).join('\n');
        const failureFrame = { kind: 'message', sid: open.sid, kid: open.kid, seq: Number(rawJack[1]), ts: Number(rawJack[2]), data: rawData, sig: rawJack[3] };
        finish('error', 'stream_after_cutoff', failureFrame); response.destroy(); return;
      }
      const frame = frameFrom(block, open, previous, seq);
      const maxBytes = Number(arg('--frame-max-bytes') || scenarioMeta?.stream_options?.frameMaxBytes || 1048576);
      if (Buffer.byteLength(frame.data, 'utf8') > maxBytes) throw Error('stream_frame_too_large');
      if (Math.abs(now() - frame.ts) > 30 || frame.ts < previousTs) throw Error('stream_stale_frame');
      previousTs = frame.ts;
      frames.push(frame); previous = frame.sig; seq++;
      if (frame.kind === 'end') { ended = true; finish('complete', null); response.destroy(); return; }
      const signal = isSignal(frame.data);
      if (signal) { const signalFrame = { ...frame, kind: 'signal' }; frames.pop(); finish('error', signal, signalFrame, frames.length + 1); response.destroy(); return; }
      let message; try { message = JSON.parse(frame.data); } catch { throw Error('stream_bad_frame'); }
      const evidenceRequestSig = process.env.JACK_STREAM_FAKE_BAD_EVIDENCE === '1' && !badEvidenceEmitted ? 'invalid-request-signature' : requestSig;
      if (evidenceRequestSig !== requestSig) badEvidenceEmitted = true;
      console.log(JSON.stringify({ type: 'message', scenario, stream_index: 0, data: frame.data, message, request_sig: evidenceRequestSig, request_ts: requestTs,
        request_method: 'POST', request_target: '/mcp', request_body_b64u: b64(requestBody), request_headers: requestHeaders,
        open, frames: frames.slice() }));
      if (scenario === 'cancel' || arg('--action') === 'cancel') { finish('cancelled', null); response.destroy(); return; }
      if (arg('--action') === 'hold' && (scenario === 'concurrency-limit' || scenario === 'durable-live-replay') && frames.length === 1) return;
    } catch (error) {
      let failureFrame = null;
      const seqMatch = /(?:^|\n)jack: seq=(0|[1-9][0-9]{0,14}),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)/.exec(block);
      if (seqMatch) {
        const dataMatch = [...block.matchAll(/(?:^|\n)data: ?([^\r\n]*)/g)];
        const dataValue = dataMatch.map(match => match[1]).join('\n');
        failureFrame = { kind: 'message', sid: open.sid, kid: open.kid, seq: Number(seqMatch[1]), ts: Number(seqMatch[2]), data: dataValue, sig: seqMatch[3] };
      }
      finish('error', error.message || 'stream_bad_frame', failureFrame); response.destroy();
    }
  };
  response.on('data', chunk => {
    buffer += chunk.toString('utf8');
    let at;
    while (!done && (at = /\r\n\r\n|\n\n|\r\r/.exec(buffer)) !== null) {
      const block = buffer.slice(0, at.index); buffer = buffer.slice(at.index + at[0].length);
      if (block) onBlock(block);
    }
  });
  response.on('end', () => { if (!done) finish(ended ? 'complete' : 'error', ended ? null : 'stream_truncated'); });
  response.on('aborted', () => { if (!done) finish('error', 'stream_truncated'); });
  response.on('error', () => { if (!done) finish('error', 'stream_truncated'); });
});
request.on('error', error => { if (!emitted) { console.error(error.message); terminal('error', 'stream_truncated', null, null, null, []); process.exitCode = 1; } });
request.end(requestBody);
