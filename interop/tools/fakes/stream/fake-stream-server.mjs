#!/usr/bin/env node
import http from 'node:http';
import { readFileSync, appendFileSync, existsSync, mkdirSync, writeFileSync, renameSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify, createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../');
const arg = name => { const i = process.argv.indexOf(name); return i < 0 ? null : process.argv[i + 1]; };
const scenario = arg('--scenario'), matrix = arg('--matrix') || 'stream';
const clockFile = arg('--clock-file'), requestLog = arg('--request-log'), durableDir = arg('--durable-dir');
const fixtures = JSON.parse(readFileSync(join(root, 'spec/fixtures/keys.json'), 'utf8')).keys;
const svc = fixtures.find(k => k.name === 'svc'), alice = fixtures.find(k => k.name === 'alice');
if (arg('--durable-init')) {
  if (!durableDir) throw Error('--durable-init requires --durable-dir');
  mkdirSync(durableDir, { recursive: true });
  try { writeFileSync(join(durableDir, 'committed-nonces.json'), '[]', { flag: 'wx' }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  console.log('{"durable_initialized":true}');
  process.exit(0);
}
const keyFromSeed = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8' });
const publicKey = b64 => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b64, 'base64url')]), format: 'der', type: 'spki' });
const svcKey = keyFromSeed(svc.seed_hex), aliceKey = publicKey(alice.public_key);
const ringSeed = arg('--ring-seed');
const ringEntry = ringSeed?.match(/^ring-1=([0-9a-f]{64})$/i);
const erin = fixtures.find(k => k.name === 'erin');
const erinKey = ringEntry ? keyFromSeed(ringEntry[1]) : null;
const keyAt = () => Number(arg('--successor-activation')) <= now() && erinKey && erin ? { kid: erin.kid, key: erinKey, public_key: erin.public_key } : { kid: svc.kid, key: svcKey, public_key: svc.public_key };
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const hash = bytes => createHash('sha256').update(bytes).digest('base64url');
const now = () => { const v = Number(readFileSync(clockFile, 'utf8').trim()); if (!Number.isSafeInteger(v) || v < 0) throw Error('invalid shared clock'); return v; };
const signText = text => b64(sign(null, Buffer.from(text, 'utf8'), keyAt().key));
const writeLog = row => { if (requestLog) appendFileSync(requestLog, `${JSON.stringify({ scenario, matrix, ...row })}\n`); };
const scenarioMeta = JSON.parse(readFileSync(join(root, 'interop/stream-scenarios.json'), 'utf8')).matrices[matrix]?.find(item => item.id === scenario) || (matrix === 'stream' ? JSON.parse(readFileSync(join(root, 'interop/stream-scenarios.json'), 'utf8')).matrices.staged?.find(item => item.id === scenario) : null);
const metadataProducer = scenarioMeta?.producer || scenario;
const requestId = scenarioMeta?.request_id ?? 1;
const options = scenarioMeta?.stream_options || {};
const payloads = {
  'progress-final': [{ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }, { jsonrpc: '2.0', id: requestId, result: {} }],
  'subscriptions-listen': [{ jsonrpc: '2.0', method: 'notifications/subscriptions/acknowledged', params: { subscriptionId: requestId } }, ...(scenarioMeta?.request_params?.notifications?.includes('notifications/events/list_changed') ? [{ jsonrpc: '2.0', method: 'notifications/events/list_changed', params: {} }] : []), { jsonrpc: '2.0', id: requestId, result: {} }],
  'list-changed': [{ jsonrpc: '2.0', method: 'notifications/subscriptions/acknowledged', params: { subscriptionId: requestId } }, { jsonrpc: '2.0', method: 'notifications/events/list_changed', params: {} }, { jsonrpc: '2.0', id: requestId, result: {} }],
    'events-stream': [
    { jsonrpc: '2.0', method: 'notifications/events/active', params: { state: 'active' } },
    { jsonrpc: '2.0', method: 'notifications/events/event', params: { event: 'event' } },
    { jsonrpc: '2.0', method: 'notifications/events/heartbeat', params: { event: 'heartbeat' } },
    { jsonrpc: '2.0', method: 'notifications/events/terminated', params: { state: 'terminated' } },
  ],
  cancel: [],
  'max-duration': [{ jsonrpc: '2.0', id: requestId, result: {} }],
  'relay-drop': [{ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }, { jsonrpc: '2.0', id: requestId, result: {} }],
  'relay-edit-data': [{ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }, { jsonrpc: '2.0', id: requestId, result: {} }],
  'relay-truncate': [{ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }, { jsonrpc: '2.0', id: requestId, result: {} }],
  'relay-reorder': [{ n: 0 }, { n: 1 }],
  'relay-splice': [{ n: 0 }, { n: 1 }],
  'relay-replay': [{ n: 0 }, { n: 1 }],
};
const nonceSet = new Set();
if (durableDir) {
  mkdirSync(durableDir, { recursive: true });
  const file = join(durableDir, 'committed-nonces.json');
  if (existsSync(file)) for (const nonce of JSON.parse(readFileSync(file, 'utf8'))) nonceSet.add(nonce);
}
const active = new Set();
let stopping = false;
let heldResponse = null;
let heldStream = null;
const streamAdmissions = new Map();
let maxDurationControlAcknowledged = false;
const controlLines = [];
let controlPending = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  controlPending += chunk;
  let at;
  while ((at = controlPending.indexOf('\n')) >= 0) {
    const line = controlPending.slice(0, at).replace(/\r$/, ''); controlPending = controlPending.slice(at + 1);
    try { controlLines.push(JSON.parse(line)); } catch { continue; }
    const command = controlLines.shift();
    if (command?.op === 'announce') {
      const activation = Number(arg('--successor-activation'));
      if (!erinKey || !erin || command.reference !== 'ring-1' || command.kid !== erin.kid || !Number.isSafeInteger(activation)) { console.error('invalid rotation announce command'); continue; }
      const headHash = hash(Buffer.from(`${erin.kid}:${activation}`));
      writeLog({ event: 'rotation_announced', reference: command.reference, kid: erin.kid, published_at: now(), activates_at: activation, head_hash: headHash });
      console.log(JSON.stringify({ announced: true, ordinal: 1, head_ordinal: 1, published_at: now(), activates_at: activation, head_hash: headHash }));
    }
    if (command?.action === 'release' && heldResponse && heldStream) {
      const stream = heldStream;
      if (!stream.released) {
        stream.released = true;
        const { res, frame, sid, seq, prev, cleanup, requestId } = stream;
        const final = frame(sid, seq, JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }), prev);
        const end = frame(sid, seq + 1, '', final.sig);
        res.end(final.wire + end.wire); cleanup(); heldResponse = null; heldStream = null;
      }
      console.log(JSON.stringify({ control: 'released', sid: stream.sid }));
    }
    if (command?.action === 'clock_advanced' && scenario === 'max-duration') {
      const clock = now();
      if (command.clock === clock) {
        writeLog({ event: 'clock_changed', clock, start: command.start, duration_ms: command.duration_ms });
        maxDurationControlAcknowledged = true;
        console.log(JSON.stringify({ control: 'clock_advanced', clock }));
      }
    }
  }
});
function commitNonce(nonce) {
  nonceSet.add(nonce);
  if (durableDir && process.env.JACK_STREAM_FAKE_NO_DURABLE_PERSIST !== '1') {
    const file = join(durableDir, 'committed-nonces.json'), temp = `${file}.${process.pid}.tmp`;
    writeFileSync(temp, JSON.stringify([...nonceSet]));
    renameSync(temp, file);
  }
}
function frame(sid, seq, data, prev) {
  const identity = keyAt(), ts = now(), sig = b64(sign(null, Buffer.from(['mcp-jack/stream1/frame', sid, String(seq), String(ts), prev, hash(Buffer.from(data, 'utf8'))].join('\n')), identity.key));
  const lines = [`event: ${data === '' ? 'jack-end' : 'message'}`];
  for (const part of data.split('\n')) lines.push(part === '' ? 'data:' : `data: ${part}`);
  lines.push(`jack: seq=${seq},ts=${ts},sig=${sig}`);
  return { wire: `${lines.join('\n')}\n\n`, sig, seq, ts, data, kind: data === '' ? 'end' : 'message' };
}
function v1Response(res, status, requestSig, code, id) {
  const body = Buffer.from(status === 501
    ? JSON.stringify({ error: { code: 'streaming_unsupported', message: 'streaming responses cannot be signed in v0.1' } })
    : JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32603, message: 'stream_limit_exceeded' } }));
  const ts = now(), identity = keyAt(), sig = b64(sign(null, Buffer.from(['mcp-jack/v1/response', String(status), requestSig, identity.kid, String(ts), hash(body)].join('\n')), identity.key));
  res.writeHead(status, { 'content-type': 'application/json', 'Jack-Auth': `v1 kid=${identity.kid},ts=${ts},sig=${sig}` });
  res.end(body);
}
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks), auth = String(req.headers['jack-auth'] || '');
    const match = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),nonce=([A-Za-z0-9_-]+),sig=([A-Za-z0-9_-]+)$/.exec(auth);
    const requestSig = match?.[4] || null, nonce = match?.[3];
    let valid = false, parsed;
    if (match && match[1] === alice.kid && Buffer.from(nonce, 'base64url').length === 16 && b64(Buffer.from(nonce, 'base64url')) === nonce && Buffer.from(requestSig, 'base64url').length === 64 && b64(Buffer.from(requestSig, 'base64url')) === requestSig) {
      const text = ['mcp-jack/v1/request', req.method, req.url, arg('--aud'), match[1], match[2], nonce, hash(body)].join('\n');
      valid = req.method === 'POST' && req.url === '/mcp' && typeof arg('--aud') === 'string' && arg('--aud').length > 0 && verify(null, Buffer.from(text, 'utf8'), aliceKey, Buffer.from(requestSig, 'base64url'));
    }
    try { parsed = JSON.parse(body.toString('utf8')); } catch { parsed = null; }
    const requestId = parsed && Object.hasOwn(parsed, 'id') ? parsed.id : null;
    const requestParams = parsed?.params && typeof parsed.params === 'object' ? parsed.params : {};
    const protocolVersion = requestParams?._meta?.['io.modelcontextprotocol/protocolVersion'];
    const method = parsed?.method;
    const nameField = ({ 'tools/call': 'name', 'prompts/get': 'name', 'events/poll': 'name', 'events/stream': 'name', 'events/subscribe': 'name', 'events/unsubscribe': 'name', 'resources/read': 'uri' })[method];
    const expectedName = nameField ? requestParams[nameField] : undefined;
    const requestHeaders = req.rawHeaders.reduce((rows, value, index, all) => { if (index % 2 === 0) rows.push([value, all[index + 1]]); return rows; }, []);
    const hasName = requestHeaders.some(([name]) => name.toLowerCase() === 'mcp-name');
    valid &&= req.method === 'POST' && req.url === '/mcp' && typeof arg('--aud') === 'string' && arg('--aud').length > 0 && parsed?.jsonrpc === '2.0' && typeof parsed?.method === 'string' && parsed.params !== null && typeof parsed.params === 'object' && !Array.isArray(parsed.params) && typeof protocolVersion === 'string' && req.headers['mcp-protocol-version'] === protocolVersion && req.headers['mcp-method'] === method &&
      (!nameField ? !hasName : typeof expectedName === 'string' && req.headers['mcp-name'] === expectedName);
    const expectedMeta = {
      'io.modelcontextprotocol/protocolVersion': protocolVersion,
      'io.modelcontextprotocol/clientCapabilities': {},
      'io.modelcontextprotocol/clientInfo': { name: 'mcp-jack-interop-stream-client', version: '1.0.0' },
    };
    const actualMeta = requestParams?._meta;
    valid &&= actualMeta !== null && typeof actualMeta === 'object' && !Array.isArray(actualMeta) &&
      Object.keys(actualMeta).length === Object.keys(expectedMeta).length &&
      Object.entries(expectedMeta).every(([key, value]) => JSON.stringify(actualMeta[key]) === JSON.stringify(value));
    const expectedMethod = scenarioMeta?.request_method || method;
    const expectedParams = method === 'subscriptions/listen'
      ? { notifications: scenarioMeta?.request_params?.notifications || [] }
      : (scenarioMeta?.request_params || {});
    const actualParams = { ...requestParams };
    delete actualParams._meta;
    const expectedParamKeys = Object.keys(expectedParams);
    valid &&= parsed?.id === (scenarioMeta?.request_id ?? 1) && method === expectedMethod && expectedParamKeys.length === Object.keys(actualParams).length && expectedParamKeys.every(key => JSON.stringify(actualParams[key]) === JSON.stringify(expectedParams[key]));
    const expectedMirrorParams = scenarioMeta?.mirror_params || {};
    const actualMirrorParams = requestHeaders.filter(([name]) => /^mcp-param-/i.test(name));
    const expectedMirrorRows = [
      ['MCP-Protocol-Version', protocolVersion], ['Mcp-Method', method],
      ...(nameField && typeof expectedName === 'string' ? [['Mcp-Name', expectedName]] : []),
      ...Object.entries(expectedMirrorParams).map(([name, value]) => [`Mcp-Param-${name}`, String(value)]),
    ];
    if (scenario === 'list-changed') expectedMirrorRows[1] = ['Mcp-Method', 'subscriptions/listen'];
    const actualMirrorRows = requestHeaders.filter(([name]) => /^(mcp-protocol-version|mcp-method|mcp-name|mcp-param-)/i.test(name));
    const unmatchedMirrors = [...actualMirrorRows];
    valid &&= actualMirrorRows.length === expectedMirrorRows.length && expectedMirrorRows.every(([name, value]) => {
      const index = unmatchedMirrors.findIndex(([actualName, actualValue]) => actualName.toLowerCase() === name.toLowerCase() && actualValue === value);
      if (index < 0) return false;
      unmatchedMirrors.splice(index, 1);
      return true;
    }) && unmatchedMirrors.length === 0;
    writeLog({ method: req.method, target: req.url, body: body.toString('utf8'), nonce: nonce ?? null, request_sig: requestSig, request_verified: valid,
      request_mcp_method: method ?? null, request_params: requestParams, protocol_version: protocolVersion ?? null,
      mirror_protocol_version: req.headers['mcp-protocol-version'] ?? null, mirror_method: req.headers['mcp-method'] ?? null,
      mirror_name: req.headers['mcp-name'] ?? null, mirror_headers: requestHeaders.filter(([name]) => /^(mcp-protocol-version|mcp-method|mcp-name|mcp-param-)/i.test(name)),
      request_method: req.method, request_target: req.url, request_body_b64u: b64(body), request_headers: requestHeaders, nonce_committed_before_first_byte: false });
    if (!valid) { res.writeHead(401); res.end(); return; }
    if (nonceSet.has(nonce)) { writeLog({ event: 'replayed_nonce', nonce, request_sig: requestSig }); res.writeHead(401, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: { code: 'replayed_nonce' } })); return; }
    commitNonce(nonce);
    writeLog({ event: 'nonce_committed', nonce, request_sig: requestSig, nonce_committed_before_first_byte: true });
    const jackAcceptValues = requestHeaders.filter(([name]) => name.toLowerCase() === 'jack-accept').map(([, value]) => value);
    const jackAcceptValid = jackAcceptValues.length > 0 && jackAcceptValues.every(value => /^(?:[A-Za-z0-9-]+(?: *, *[A-Za-z0-9-]+)*)$/.test(value));
    const jackAcceptTokens = jackAcceptValid ? jackAcceptValues.flatMap(value => value.split(',').map(token => token.trim())) : [];
    if (!jackAcceptValid || !jackAcceptTokens.includes('s1')) {
      writeLog({ nonce_committed_before_first_byte: true });
      v1Response(res, 501, requestSig, 'streaming_unsupported', requestId); return;
    }
    const streamAdmissionKey = match?.[1];
    const admissionLimit = Number(options.maxConcurrentStreams ?? arg('--max-concurrent-streams') ?? 4);
    if (process.env.JACK_STREAM_FAKE_IGNORE_LIMIT !== '1' && (streamAdmissions.get(streamAdmissionKey) || 0) >= admissionLimit) {
      writeLog({ nonce_committed_before_first_byte: true });
      v1Response(res, 429, requestSig, 'stream_limit_exceeded', requestId); return;
    }
    const suppliedSid = arg('--sid') || scenarioMeta?.sid;
    const sid = suppliedSid || b64(randomBytes(16)), ts = now();
    if (!/^[A-Za-z0-9_-]+$/.test(sid) || Buffer.from(sid, 'base64url').length !== 16 || b64(Buffer.from(sid, 'base64url')) !== sid) throw Error('sid must be canonical 16-byte base64url');
    const identity = keyAt(), openSig = b64(sign(null, Buffer.from(['mcp-jack/stream1/open', '200', requestSig, identity.kid, String(ts), sid].join('\n')), identity.key));
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache', 'x-accel-buffering': 'no', 'Jack-Auth': `s1 kid=${identity.kid},ts=${ts},sid=${sid},sig=${openSig}` });
      writeLog({ event: 'stream_open', nonce_committed_before_first_byte: true, sid, request_sig: requestSig, identity: alice.kid, server_kid: identity.kid });
    active.add(res);
    if (scenario === 'concurrency-limit' || options.maxConcurrentStreams !== undefined || arg('--action') === 'hold') streamAdmissions.set(streamAdmissionKey, (streamAdmissions.get(streamAdmissionKey) || 0) + 1);
    let prev = openSig, seq = 0, closed = false;
    const onClose = () => {
      if (closed) return;
      closed = true; active.delete(res);
      if (scenario === 'concurrency-limit' || options.maxConcurrentStreams !== undefined || arg('--action') === 'hold') streamAdmissions.set(streamAdmissionKey, Math.max(0, (streamAdmissions.get(streamAdmissionKey) || 0) - 1));
      if (heldResponse === res) { heldResponse = null; heldStream = null; }
      if (!res.writableEnded) writeLog({ event: 'handler_cancelled', sid, request_sig: requestSig });
    };
    res.on('close', onClose);
    const send = data => { if (closed || res.destroyed) return null; const f = frame(sid, seq++, data, prev); prev = f.sig; res.write(f.wire); return f; };
    const oversized = scenario === 'oversize';
    if (oversized) {
      const oversizedValue = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { payload: 'x'.repeat(Number(options.frameMaxBytes) + 32) } });
      const oversizedBytes = Buffer.byteLength(oversizedValue, 'utf8');
      if (!Number.isSafeInteger(options.frameMaxBytes) || options.frameMaxBytes < 1024 || oversizedBytes <= options.frameMaxBytes) throw Error('oversize fake producer did not exceed configured frame limit');
      writeLog({ event: 'frame_suppressed', data_bytes: oversizedBytes, frame_max_bytes: options.frameMaxBytes });
      send(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/jack/stream_error', params: { code: 'stream_frame_too_large', limit: options.frameMaxBytes } }));
      const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res); return;
    }
    if (scenario === 'max-duration') {
      const start = now(), duration = Number(options.maxStreamDurationMs || arg('--max-stream-duration-ms') || 1000);
      send(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }));
      const responseMessage = method === 'events/stream'
        ? { jsonrpc: '2.0', id: requestId, result: { resultType: 'complete', _meta: { 'io.modelcontextprotocol/subscriptionId': requestId } } }
        : { jsonrpc: '2.0', id: requestId, result: {} };
      let elapsedLogged = false;
      const timer = setInterval(() => {
        if (closed || res.destroyed) { clearInterval(timer); return; }
        if (maxDurationControlAcknowledged && !elapsedLogged && now() >= start + Math.ceil(duration / 1000)) {
          elapsedLogged = true; writeLog({ event: 'duration_elapsed', start, duration_ms: duration, clock: now() });
          send(JSON.stringify(responseMessage));
          const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res); clearInterval(timer);
        }
      }, 10);
      timer.unref(); return;
    }
    if (scenario === 'events-stream') {
      const requestedHeartbeat = Number(options.heartbeatMs ?? arg('--heartbeat-ms') ?? 15000);
      const windowSeconds = Number(options.windowSeconds ?? arg('--window-seconds') ?? 30);
      const heartbeatGranted = Math.min(Number.isSafeInteger(requestedHeartbeat) && requestedHeartbeat >= 0 ? requestedHeartbeat : 0, Math.floor(windowSeconds * 500));
      writeLog({ event: 'heartbeat_granted', heartbeat_granted_ms: heartbeatGranted });
    }
    if (scenario === 'events-stream') {
      const requestedHeartbeat = Number(options.heartbeatMs ?? arg('--heartbeat-ms') ?? 15000);
      const windowSeconds = Number(options.windowSeconds ?? arg('--window-seconds') ?? 30);
      const heartbeatGranted = Math.min(Number.isSafeInteger(requestedHeartbeat) && requestedHeartbeat >= 0 ? requestedHeartbeat : 0, Math.floor(windowSeconds * 500));
      writeLog({ event: 'heartbeat_granted', heartbeat_granted_ms: heartbeatGranted });
      const events = payloads['events-stream'];
      for (let index = 0; index < events.length; index++) {
        const msg = events[index];
        if (msg.method === 'notifications/events/heartbeat') {
          msg.params = { event: 'heartbeat', heartbeatMs: heartbeatGranted };
          writeLog({ event: 'heartbeat_frame', heartbeat_granted_ms: heartbeatGranted, ts: now() });
        }
        send(JSON.stringify(msg));
      }
    } else if (!['idle', 'cancel', 'concurrency-limit', 'durable-live-replay', 'durable-restart-replay', 'oversize'].includes(scenario)) for (const item of payloads[metadataProducer] || []) send(JSON.stringify(item));
    if (scenario === 'cancel') { send(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } })); return; }
    if (scenario === 'concurrency-limit' || scenario === 'durable-live-replay') {
      const firstMessage = scenario === 'durable-live-replay'
        ? { jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1, message: 'stream:first' } }
        : { jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } };
      send(JSON.stringify(firstMessage));
      const shouldHold = scenario === 'durable-live-replay' || heldResponse === null;
      if (!shouldHold) { const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res); return; }
      heldResponse = res;
      const heldStreamKey = match?.[1];
      heldStream = { res, frame, sid, seq, prev, requestId, identity: heldStreamKey, released: false, cleanup: () => { if (closed) return; closed = true; active.delete(res); streamAdmissions.set(heldStreamKey, Math.max(0, (streamAdmissions.get(heldStreamKey) || 0) - 1)); } };
      return;
    }
    if (scenario === 'durable-restart-replay') {
      send(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1, message: 'stream:first' } }));
      const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res); return;
    }
    if (scenario === 'idle') { res.flushHeaders(); const timer = setTimeout(() => { if (closed || res.destroyed) return; const message = JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }); send(message); const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res); }, Math.max(1, Number(options.idleTimeoutMs || arg('--idle-timeout-ms') || 1000) + 25)); timer.unref(); return; }
    const end = frame(sid, seq, '', prev); res.end(end.wire); closed = true; active.delete(res);
  });
});
server.listen(Number(arg('--port') || 0), '127.0.0.1', () => console.log(JSON.stringify({ ready: true, port: server.address().port, server_public_key: svc.public_key, server_kid: svc.kid })));
function shutdown() {
  if (stopping) return; stopping = true;
  for (const response of active) response.destroy();
  active.clear(); server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.stdin.on('end', shutdown);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, shutdown);
