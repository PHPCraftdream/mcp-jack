#!/usr/bin/env node
// Signed-stream interoperability runner. Node >=20; cryptographic checks use Node built-ins.
import { readFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { createHash, createPublicKey, verify } from 'node:crypto';
import net from 'node:net';
import { startRelay } from './stream/relay.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const MATRICES = ['stream', 'rotation-stream', 'durable-stream'];
const USAGE = 'usage: node interop/stream.mjs [--matrix stream|rotation-stream|durable-stream] [--targets file] [--servers lang,...] [--clients lang,...] [--scenario id,...] [--list] [--self-test]';
let tempRoot;
const children = new Set();
const relays = new Set();
let cleanupPromise;

function usageError(message) { throw Object.assign(new Error(message), { usage: true }); }
function parseArgs(args) {
  const out = { matrix: 'stream', targets: join(HERE, 'targets.json'), servers: null, clients: null, scenario: null, list: false, selfTest: false };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (['--matrix', '--targets', '--servers', '--clients', '--scenario'].includes(flag)) {
      if (!args[i + 1] || args[i + 1].startsWith('--')) usageError(`missing value for ${flag}`);
      out[flag.slice(2)] = args[++i];
    } else if (flag === '--list') out.list = true;
    else if (flag === '--self-test') out.selfTest = true;
    else usageError(`unknown flag ${flag}`);
  }
  if (!MATRICES.includes(out.matrix)) usageError(`unknown matrix '${out.matrix}'`);
  if (out.list && out.selfTest) usageError('--list and --self-test cannot be combined');
  return out;
}
function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { usageError(`cannot read JSON ${path}: ${error.message}`); }
}
function relayFixtureFrame(transform) {
  const vectors = readJson(join(ROOT, 'spec/fixtures/modern/stream-vectors.json'));
  const id = transform === 'splice' ? 'stream-frame-wrong-sid' : 'stream-frame-end-after-cutoff';
  const vector = vectors.cases?.find(item => item.id === id);
  const encoded = vector?.response?.stream_b64u?.[0];
  if (typeof encoded !== 'string') usageError(`missing pre-signed ${id} relay fixture`);
  const body = Buffer.from(encoded, 'base64url');
  const events = body.toString('latin1').split(/(?<=\n\n)/);
  const event = transform === 'splice' ? events[0] : events.find(value => /^event: jack-end\r?$/m.test(value));
  if (!event || !event.endsWith('\n\n')) usageError(`invalid pre-signed ${id} relay fixture`);
  return Buffer.from(event, 'latin1');
}
function subset(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((v, i) => subset(actual[i], v));
  if (expected && typeof expected === 'object') return !!actual && typeof actual === 'object' && !Array.isArray(actual) && Object.entries(expected).every(([k, v]) => Object.hasOwn(actual, k) && subset(actual[k], v));
  return actual === expected;
}
function b64(value, length, label = 'base64url') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error(`invalid ${label}`);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) throw Error(`invalid ${label}`);
  return bytes;
}
const sha256 = bytes => createHash('sha256').update(bytes).digest('base64url');
function makeVerifier(fixtures) {
  const keys = fixtures?.keys;
  const svc = Array.isArray(keys) && keys.find(key => key.name === 'svc');
  if (!svc || typeof svc.kid !== 'string' || typeof svc.public_key !== 'string') usageError('svc fixture missing or invalid');
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), b64(svc.public_key, 32, 'svc public key')]), format: 'der', type: 'spki' });
  function signed(text, signature) { return verify(null, Buffer.from(text, 'utf8'), publicKey, b64(signature, 64, 'signature')); }
  function verifyOpen(open, requestSig) {
    if (!open || open.kid !== svc.kid || !Number.isSafeInteger(open.ts) || open.ts < 0) throw Error('invalid open fields');
    b64(open.sid, 16, 'stream sid');
    b64(requestSig, 64, 'request signature');
    const text = ['mcp-jack/stream1/open', '200', requestSig, open.kid, String(open.ts), open.sid].join('\n');
    if (!signed(text, open.sig)) throw Error('bad open signature');
  }
  function verifyFrame(frame, open, expectedSeq, previousSig) {
    if (!frame || frame.sid !== open.sid || frame.kid !== open.kid || frame.seq !== expectedSeq || !Number.isSafeInteger(frame.ts) || frame.ts < 0 || typeof frame.data !== 'string') throw Error(`invalid frame fields at ${expectedSeq}`);
    const bytes = Buffer.from(frame.data, 'utf8');
    if (bytes.toString('utf8') !== frame.data) throw Error(`invalid UTF-8 at frame ${expectedSeq}`);
    const text = ['mcp-jack/stream1/frame', open.sid, String(expectedSeq), String(frame.ts), previousSig, sha256(bytes)].join('\n');
    if (!signed(text, frame.sig)) throw Error(`bad frame signature ${expectedSeq}`);
    if (frame.kind === 'end' && frame.data !== '') throw Error('invalid end frame data');
    if (frame.kind !== 'end' && frame.kind !== 'message' && frame.kind !== 'signal') throw Error('unknown frame kind');
    return frame.sig;
  }
  function verifyFrames(open, requestSig, frames, { allowMissing = false } = {}) {
    if (!Array.isArray(frames)) {
      if (allowMissing) return { count: 0, ended: false, messages: [] };
      throw Error('missing frame evidence');
    }
    let previous = open.sig;
    const dataMessages = [];
    let ended = false;
    for (let i = 0; i < frames.length; i++) {
      const frame = frames[i];
      if (ended) throw Error('frame appears after end');
      previous = verifyFrame(frame, open, i, previous);
      if (frame.kind === 'end') ended = true;
      else if (frame.kind === 'message') dataMessages.push(frame.data);
    }
    return { count: frames.length, ended, messages: dataMessages };
  }
  function verifyRefusal(terminal, requestSig) {
    const e = terminal.v1_evidence;
    if (!e || e.status !== terminal.http_status || !Number.isSafeInteger(e.status) || e.kid !== svc.kid || !Number.isSafeInteger(e.ts) || e.request_sig !== requestSig) throw Error('invalid v1 refusal evidence');
    b64(requestSig, 64, 'request signature');
    const body = b64(e.body_b64u, undefined, 'v1 body');
    const text = ['mcp-jack/v1/response', String(e.status), requestSig, e.kid, String(e.ts), sha256(body)].join('\n');
    if (!signed(text, e.sig)) throw Error('bad v1 refusal signature');
    let parsed;
    try { parsed = JSON.parse(body.toString('utf8')); } catch { throw Error('v1 refusal body is not JSON'); }
    const bodyCode = parsed?.error?.message ?? parsed?.error?.code;
    if (terminal.http_code !== undefined && terminal.http_code !== null && bodyCode !== terminal.http_code) throw Error('v1 refusal code differs from signed body');
    if (terminal.code !== undefined && terminal.code !== null && bodyCode !== terminal.code) throw Error('terminal refusal code differs from signed body');
  }
  return (line, expectedRequestId) => {
    if (!line || typeof line !== 'object' || Array.isArray(line)) throw Error('JSONL record must be an object');
    if (line.type === 'message') {
      if (typeof line.request_sig !== 'string') throw Error('message record missing request signature');
      verifyOpen(line.open, line.request_sig);
      const verified = verifyFrames(line.open, line.request_sig, line.frames);
      if (typeof line.data !== 'string' && line.message === undefined) throw Error('message record missing data/message');
      const data = line.data;
      if (data !== undefined && verified.messages.filter(value => value === data).length !== 1) throw Error('message data must match exactly one signed frame');
      if (line.message !== undefined) {
        const candidates = verified.messages.filter(value => data === undefined || value === data);
          const matching = candidates.find(value => { try { return isDeepStrictEqual(JSON.parse(value), line.message); } catch { return false; } });
          if (matching === undefined) throw Error('message object differs from signed frame data');
          if (data === undefined && verified.messages.filter(value => value === matching).length !== 1) throw Error('message must match exactly one signed data frame');
      }
      return { messages: line.message !== undefined ? [line.message] : [JSON.parse(data)], frames: verified.count };
    }
    if (line.type !== 'terminal') throw Error(`unknown JSONL record type '${line.type}'`);
    if (line.outcome === 'refused') {
      if (line.mcp_complete !== false) throw Error('refusal terminal mcp_complete must be false');
      if (line.open !== undefined && line.open !== null) throw Error('refusal terminal must not include stream open evidence');
      if (line.frames !== undefined && (!Array.isArray(line.frames) || line.frames.length !== 0)) throw Error('refusal terminal frames must be omitted or empty');
      for (const key of ['terminal_frame', 'failure_frame', 'successor_activation']) if (line[key] !== undefined && line[key] !== null) throw Error(`refusal terminal ${key} must be null or omitted`);
      if (typeof line.request_sig !== 'string') throw Error('refusal terminal missing request signature');
      b64(line.request_sig, 64, 'request signature');
      if (line.v1_evidence !== undefined && line.v1_evidence !== null) {
        const refusalCode = line.http_code ?? line.code;
        const allowed = (line.http_status === 501 && refusalCode === 'streaming_unsupported') ||
          (line.http_status === 429 && refusalCode === 'stream_limit_exceeded');
        if (!allowed || (line.code !== undefined && line.code !== refusalCode) || (line.http_code !== undefined && line.http_code !== refusalCode)) throw Error('unsupported signed refusal terminal');
        verifyRefusal(line, line.request_sig);
      } else {
        if (line.http_status !== 401 || (line.http_code ?? line.code) !== 'replayed_nonce') throw Error('unsupported unsigned refusal terminal');
        if (line.code !== undefined && line.code !== 'replayed_nonce') throw Error('unsigned refusal code must be replayed_nonce');
        if (line.http_code !== undefined && line.http_code !== 'replayed_nonce') throw Error('unsigned refusal http_code must be replayed_nonce');
        if (line.http_body_b64u !== undefined) {
          const body = b64(line.http_body_b64u, undefined, 'refusal body');
          let parsed;
          try { parsed = JSON.parse(body.toString('utf8')); } catch { throw Error('unsigned refusal body is not JSON'); }
          if ((parsed?.error?.code ?? parsed?.error?.message) !== 'replayed_nonce') throw Error('unsigned refusal body is not replayed_nonce');
        }
      }
      return { terminal: line, evidenceMessages: [], frames: 0 };
    }
    if (line.outcome === 'complete' || line.outcome === 'error') {
      if (!line.open || typeof line.request_sig !== 'string' || !Array.isArray(line.frames)) throw Error('stream terminal requires open, request signature, and frame array');
    }
    if (line.request_sig !== undefined && line.request_sig !== null) b64(line.request_sig, 64, 'request signature');
    let verified = { count: 0, ended: false, messages: [] };
    if (line.open !== undefined || line.frames !== undefined) {
      if (!line.open || typeof line.request_sig !== 'string') throw Error('terminal evidence lacks open or request signature');
      verifyOpen(line.open, line.request_sig);
      verified = verifyFrames(line.open, line.request_sig, line.frames, { allowMissing: true });
    }
    if (line.v1_evidence !== undefined && line.v1_evidence !== null) verifyRefusal(line, line.request_sig);
    if (typeof line.mcp_complete !== 'boolean') throw Error('terminal mcp_complete must be boolean');
    if (line.outcome === 'complete') {
      if (!line.terminal_frame || line.terminal_frame.kind !== 'end') throw Error('complete terminal lacks signed end');
      if (!Number.isSafeInteger(line.frames_verified) || line.frames_verified < 1) throw Error('complete terminal has invalid frames_verified');
      if (!verified.ended || verified.count !== line.frames_verified) throw Error('terminal frame evidence count/end mismatch');
      if (line.terminal_frame.sig === undefined || b64(line.terminal_frame.sig, 64, 'terminal frame signature').toString('base64url') !== line.frames.at(-1)?.sig) throw Error('terminal frame differs from signed evidence');
      if (line.frames.at(-1)?.kind !== 'end') throw Error('signed evidence does not end in terminal frame');
      if (line.mcp_complete) {
        const delivered = verified.messages.at(-1);
        let response;
        try { response = JSON.parse(delivered); } catch { throw Error('mcp_complete terminal lacks final JSON-RPC response'); }
        const requestId = line.request_id ?? expectedRequestId;
        const hasResult = Object.hasOwn(response, 'result'), hasError = Object.hasOwn(response, 'error');
        if (response.jsonrpc !== '2.0' || (requestId !== undefined && (!Object.hasOwn(response, 'id') || !isDeepStrictEqual(response.id, requestId))) || hasResult === hasError || Object.hasOwn(response, 'method')) throw Error('mcp_complete terminal lacks matching JSON-RPC response');
      }
    } else if (line.outcome === 'error') {
      if (line.code === 'stream_frame_too_large') {
        const failure = line.failure_frame;
        const expectedSeq = verified.count;
        if (!failure || failure.kind !== 'signal') throw Error('oversize terminal lacks signal failure_frame evidence');
        const previous = verified.count ? line.frames.at(-1).sig : line.open?.sig;
        if (!line.open || !Array.isArray(line.frames) || !Number.isSafeInteger(line.frames_verified) || line.frames_verified !== verified.count + 1) throw Error('oversize terminal has invalid verified frame count');
        if (failure.kind !== 'signal') throw Error('oversize failure frame is not marked as a transport signal');
        verifyFrame(failure, line.open, expectedSeq, previous);
        const match = /^\{"jsonrpc":"2\.0","method":"notifications\/jack\/stream_error","params":\{"code":"stream_frame_too_large","limit":(0|[1-9][0-9]*)\}\}$/.exec(failure.data);
        if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) > Number.MAX_SAFE_INTEGER) throw Error('failure_frame is not the canonical stream signal');
        if (verified.messages.some(data => data === failure.data)) throw Error('transport signal was surfaced as a message');
      }
      if (line.code === 'stream_after_cutoff') {
        if (!line.failure_frame || !Number.isSafeInteger(line.successor_activation) || !Number.isSafeInteger(line.failure_frame.ts) || line.failure_frame.ts < line.successor_activation) throw Error('after-cutoff failure lacks timestamp-at/after activation evidence');
      }
      if (line.code === 'stream_truncated' && (verified.ended || line.frames_verified !== verified.count)) throw Error('truncated terminal has invalid end/count evidence');
      if (line.failure_frame) {
        const frame = line.failure_frame;
        const expectedSeq = verified.count;
        const previous = verified.count ? line.frames.at(-1).sig : line.open?.sig;
        if (!line.open || !Number.isSafeInteger(frame.ts) || frame.ts < 0 || frame.sid !== line.open.sid || frame.kid !== line.open.kid || typeof frame.data !== 'string' || !['end', 'message', 'signal'].includes(frame.kind)) throw Error('malformed failure frame evidence');
        b64(frame.sig, 64, 'failure frame signature');
        const bytes = Buffer.from(frame.data, 'utf8');
        if (bytes.toString('utf8') !== frame.data) throw Error('invalid failure frame UTF-8');
        if (line.code === 'stream_out_of_order') {
          if (!Number.isSafeInteger(frame.seq) || frame.seq === expectedSeq) throw Error('out-of-order failure frame lacks wrong sequence');
        } else if (line.code === 'stream_bad_signature') {
          if (!Number.isSafeInteger(frame.seq) || frame.seq !== expectedSeq) throw Error('bad-signature failure frame has invalid sequence');
        } else if (line.code !== 'stream_after_cutoff' && frame.seq !== expectedSeq) throw Error('failure frame has unexpected sequence');
        if (line.code === 'stream_bad_signature') {
          const text = ['mcp-jack/stream1/frame', line.open.sid, String(frame.seq), String(frame.ts), previous, sha256(bytes)].join('\n');
          if (signed(text, frame.sig)) throw Error('bad-signature failure frame unexpectedly verifies');
        } else if (line.code !== 'stream_after_cutoff' && line.code !== 'stream_out_of_order') {
          const text = ['mcp-jack/stream1/frame', line.open.sid, String(frame.seq), String(frame.ts), previous, sha256(bytes)].join('\n');
          if (!signed(text, frame.sig)) throw Error('failure frame lacks a valid chained signature');
        }
      }
    } else if (verified.count && line.frames_verified !== undefined && line.frames_verified !== verified.count) throw Error('terminal frames_verified mismatch');
    return { terminal: line, evidenceMessages: verified.messages, frames: verified.count };
  };
}
function deterministicVariant(value, label) { return createHash('sha256').update(`${value}\n${label}`).digest().subarray(0, 16).toString('base64url'); }
function scenarioRequest(scenario) {
  const method = scenario.request_method;
  if (typeof method !== 'string' || !method) throw Error(`scenario ${scenario.id} lacks request_method; refusing to invent a signed method`);
  const params = scenario.request_params ?? {};
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw Error(`scenario ${scenario.id} request_params must be an object`);
  const body = { jsonrpc: '2.0', id: scenario.request_id ?? 1, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'mcp-jack-interop-stream-client', version: '1.0.0' } } } };
  const name = scenario.mirror_name ?? (method === 'tools/call' ? params.name : (method === 'events/stream' ? params.name : params.uri));
  const mirrors = [['MCP-Protocol-Version', '2026-07-28'], ['Mcp-Method', method], ...(typeof name === 'string' ? [['Mcp-Name', name]] : []), ...Object.entries(scenario.mirror_params || {}).map(([name, value]) => [`Mcp-Param-${name}`, String(value)])];
  return { body: JSON.stringify(body), mirrors };
}
function targetCommand(target) {
  if (!Array.isArray(target) || !target.length || target.some(x => typeof x !== 'string')) usageError('invalid target argv');
  const [first, ...rest] = target;
  if (first === 'node') {
    if (!rest.length) usageError('node target requires a script path');
    return [process.execPath, [resolve(ROOT, rest[0]), ...rest.slice(1)]];
  }
  const path = resolve(ROOT, first);
  if (existsSync(path)) return [path, rest];
  if (process.platform === 'win32' && existsSync(`${path}.exe`)) return [`${path}.exe`, rest];
  usageError(`target executable missing ${path}`);
}
function launch(target, args, timeout = 30000) { return launchResolved(targetCommand(target), args, timeout); }
function launchResolved(resolved, args, timeout = 30000) {
  const [command, prefix] = resolved;
  const child = spawn(command, [...prefix, ...args], { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'] });
  children.add(child);
  let stdout = '', stderr = '', pending = '', timedOut = false, killTimer;
  const lineQueue = [], lineWaiters = [];
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    stdout += chunk; pending += chunk;
    let at;
    while ((at = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, at).replace(/\r$/, ''); pending = pending.slice(at + 1);
      const waiter = lineWaiters.shift();
      if (waiter) waiter.resolve(line); else lineQueue.push(line);
    }
  });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8000); });
  const processInfo = { child, get stdout() { return stdout; }, get stderr() { return stderr; },
    write(value) { if (!child.stdin.destroyed) child.stdin.write(value); },
    nextLine(timeoutMs = 10000) {
      if (lineQueue.length) return Promise.resolve(lineQueue.shift());
      return new Promise((resolveLine, rejectLine) => {
        const waiter = { resolve: value => { clearTimeout(timer); resolveLine(value); }, reject: error => { clearTimeout(timer); rejectLine(error); } };
        const timer = setTimeout(() => { const at = lineWaiters.indexOf(waiter); if (at >= 0) lineWaiters.splice(at, 1); rejectLine(Error('stdout line timeout')); }, timeoutMs);
        lineWaiters.push(waiter);
      });
    } };
  processInfo.done = new Promise((resolveDone, rejectDone) => {
    const timer = setTimeout(() => {
      timedOut = true;
      if (!child.kill('SIGTERM') && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      killTimer = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, 1200);
    }, timeout);
    child.once('error', rejectDone);
    child.once('close', (code, signal) => { clearTimeout(timer); clearTimeout(killTimer); for (const waiter of lineWaiters.splice(0)) waiter.reject(Error('child closed')); children.delete(child); resolveDone({ code, signal, stdout, stderr, timedOut }); });
  });
  return processInfo;
}
async function stopServerClean(info) {
  if (!info || info.child.exitCode !== null || info.child.signalCode !== null) return;
  info.child.stdin.end();
  const result = await info.done;
  if (result.code !== 0 || result.signal || result.timedOut) throw Error(`server clean stop failed${result.signal ? ` (${result.signal})` : ''}: ${result.stderr}`);
}
async function stopChild(info) {
  if (!info || info.child.exitCode !== null || info.child.signalCode !== null) return;
  info.child.kill('SIGTERM');
  await Promise.race([info.done.catch(() => {}), new Promise(resolveDone => setTimeout(resolveDone, 1200))]);
  if (info.child.exitCode === null && info.child.signalCode === null) info.child.kill('SIGKILL');
  await info.done.catch(() => {});
}
function readRows(path) {
  const text = existsSync(path) ? readFileSync(path, 'utf8') : '';
  return text.split(/\r?\n/).filter(Boolean).map((line, index) => { try { return JSON.parse(line); } catch { throw Error(`request log line ${index + 1} is invalid JSON`); } });
}
function scenarioSubset(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((value, index) => subset(actual[index], value));
  return subset(actual, expected);
}
function waitReady(info) {
  return info.nextLine(10000).then(row => {
    let ready;
    try { ready = JSON.parse(row); } catch (error) { throw Error(`invalid server readiness line: ${error.message}`); }
    if (ready.ready !== true || !Number.isInteger(ready.port) || ready.port < 1 || ready.port > 65535) throw Error('invalid readiness JSON');
    return ready;
  }, error => { throw Error(`server failed before readiness: ${error.message}: ${info.stderr}`); });
}
function parseJsonLines(output) {
  const lines = output.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (!lines.length || lines.some(line => !line.trim())) throw Error('client output contains empty/non-record JSONL line');
  return lines.map((line, i) => { try { return JSON.parse(line); } catch (error) { throw Error(`invalid JSONL line ${i + 1}: ${error.message}`); } });
}
function verifyRequestEvidence(record, alice, aud) {
  if (!record || record.request_method !== 'POST' || typeof record.request_target !== 'string' || typeof record.request_body_b64u !== 'string' || !Array.isArray(record.request_headers)) throw Error('request evidence is incomplete');
  const body = b64(record.request_body_b64u);
  const authRows = record.request_headers.filter(row => Array.isArray(row) && row.length === 2 && String(row[0]).toLowerCase() === 'jack-auth');
  if (authRows.length !== 1 || typeof authRows[0][1] !== 'string') throw Error('request evidence lacks exactly one Jack-Auth');
  const match = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),nonce=([A-Za-z0-9_-]+),sig=([A-Za-z0-9_-]+)$/.exec(authRows[0][1]);
  if (!match || match[1] !== alice.kid || !Number.isSafeInteger(Number(match[2]))) throw Error('request Jack-Auth is malformed or uses unexpected key');
  b64(match[3], 16, 'request nonce');
  b64(match[4], 64, 'request signature');
  if (record.request_sig !== match[4] || record.nonce !== match[3]) throw Error('request JSONL signature/nonce differs from Jack-Auth');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), b64(alice.public_key, 32, 'Alice public key')]), format: 'der', type: 'spki' });
  const text = ['mcp-jack/v1/request', record.request_method, record.request_target, aud, match[1], match[2], match[3], sha256(body)].join('\n');
  if (!verify(null, Buffer.from(text, 'utf8'), key, b64(match[4], 64, 'request signature'))) throw Error('request signature does not verify against captured raw body');
  if (record.request_target !== '/mcp') throw Error('durable replay target differs from expected endpoint');
}
function decodeHttpResponse(raw) {
  const split = raw.indexOf('\r\n\r\n');
  if (split < 0) throw Error('durable replay returned malformed HTTP response');
  const head = raw.subarray(0, split).toString('latin1');
  const lines = head.split('\r\n');
  const statusLine = /^HTTP\/1\.[01] (\d{3})(?: [\x20-\x7e]*)?$/.exec(lines.shift());
  if (!statusLine) throw Error('durable replay returned malformed HTTP response');
  const headers = new Map();
  for (const line of lines) {
    if (!line || /^[ \t]/.test(line)) throw Error('durable replay returned malformed HTTP headers');
    const match = /^([^: \t]+):[ \t]*(.*)$/.exec(line);
    if (!match || /[\x00-\x08\x0a-\x1f\x7f]/.test(match[2])) throw Error('durable replay returned malformed HTTP headers');
    const name = match[1].toLowerCase();
    const values = headers.get(name) || [];
    values.push(match[2].trim());
    headers.set(name, values);
  }
  const lengths = headers.get('content-length') || [];
  const transferEncodings = headers.get('transfer-encoding') || [];
  if (lengths.length && transferEncodings.length) throw Error('durable replay response has ambiguous framing');
  let body;
  if (lengths.length) {
    if (lengths.length !== 1 || !/^(0|[1-9][0-9]*)$/.test(lengths[0])) throw Error('durable replay response has invalid Content-Length');
    const length = Number(lengths[0]);
    if (!Number.isSafeInteger(length) || raw.length - split - 4 !== length) throw Error('durable replay response Content-Length mismatch');
    body = raw.subarray(split + 4);
  } else if (transferEncodings.length) {
    if (transferEncodings.length !== 1 || transferEncodings[0].toLowerCase() !== 'chunked') throw Error('durable replay response has unsupported or ambiguous Transfer-Encoding');
    const wire = raw.subarray(split + 4);
    const decoded = [];
    let offset = 0, complete = false;
    while (!complete) {
      const lineEnd = wire.indexOf('\r\n', offset);
      if (lineEnd < 0) throw Error('durable replay response has malformed chunk framing');
      const sizeLine = wire.subarray(offset, lineEnd).toString('latin1');
      const sizeMatch = /^([0-9A-Fa-f]+)(?:;[!#$%&'*+.^_`|~0-9A-Za-z=-]+(?:=[!#$%&'*+.^_`|~0-9A-Za-z:-]+)?)*$/.exec(sizeLine);
      if (!sizeMatch) throw Error('durable replay response has malformed chunk size');
      const size = Number.parseInt(sizeMatch[1], 16);
      if (!Number.isSafeInteger(size)) throw Error('durable replay response has invalid chunk size');
      offset = lineEnd + 2;
      if (size === 0) {
        while (true) {
          const trailerEnd = wire.indexOf('\r\n', offset);
          if (trailerEnd < 0) throw Error('durable replay response has malformed chunk trailers');
          if (trailerEnd === offset) { offset += 2; complete = true; break; }
          const trailer = wire.subarray(offset, trailerEnd).toString('latin1');
          if (/^[ \t]/.test(trailer) || !/^([^: \t]+):[ \t]*[^\r\n]*$/.test(trailer)) throw Error('durable replay response has malformed chunk trailers');
          const trailerName = trailer.slice(0, trailer.indexOf(':')).toLowerCase();
          if (['content-length', 'transfer-encoding', 'host'].includes(trailerName)) throw Error('durable replay response has invalid framing trailer');
          offset = trailerEnd + 2;
        }
      } else {
        if (size > wire.length - offset - 2 || wire[offset + size] !== 13 || wire[offset + size + 1] !== 10) throw Error('durable replay response has truncated chunk data');
        decoded.push(wire.subarray(offset, offset + size));
        offset += size + 2;
      }
    }
    if (offset !== wire.length) throw Error('durable replay response has bytes after chunk trailers');
    body = Buffer.concat(decoded);
  } else {
    body = raw.subarray(split + 4);
  }
  return { head, status: Number(statusLine[1]), body };
}
async function replayRawRequest(port, evidence, verifyReplay) {
  if (!evidence || evidence.request_method !== 'POST' || typeof evidence.request_target !== 'string' ||
      typeof evidence.request_body_b64u !== 'string' || !Array.isArray(evidence.request_headers)) {
    throw Error('durable replay cannot proceed: first-message JSONL must include request_method, request_target, request_body_b64u, request_headers');
  }
  const body = b64(evidence.request_body_b64u);
  if (typeof evidence.request_sig !== 'string') throw Error('durable replay evidence lacks request signature');
  b64(evidence.request_sig, 64, 'request signature');
  const target = evidence.request_target;
  if (!target.startsWith('/') || target.startsWith('//') || /[\r\n]/.test(target)) throw Error('durable replay target is not canonical origin-form');
  const headers = evidence.request_headers;
  if (headers.some(row => !Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string' || typeof row[1] !== 'string' || /[\r\n]/.test(row[0]) || /[\r\n]/.test(row[1]))) throw Error('durable replay request headers are malformed');
  const authRows = headers.filter(row => String(row[0]).toLowerCase() === 'jack-auth');
  const lengthRows = headers.filter(row => String(row[0]).toLowerCase() === 'content-length');
  if (lengthRows.length !== 1 || lengthRows[0][1] !== String(body.length)) throw Error('durable replay content length differs from exact captured body');
  const authRowsValid = authRows.length === 1 && new RegExp(`^v1 kid=[A-Za-z0-9_-]+,ts=(0|[1-9][0-9]{0,11}),nonce=[A-Za-z0-9_-]+,sig=${evidence.request_sig}$`).test(authRows[0][1]);
  if (!authRowsValid) throw Error('durable replay Jack-Auth differs from verified request evidence');
  const host = `127.0.0.1:${port}`;
  const rows = headers.filter(row => !['host', 'content-length', 'connection'].includes(String(row[0]).toLowerCase()));
  const wire = Buffer.concat([Buffer.from(`${evidence.request_method} ${evidence.request_target} HTTP/1.1\r\nHost: ${host}\r\n${rows.map(([name, value]) => `${name}: ${value}\r\n`).join('')}Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`, 'latin1'), body]);
  const socket = net.connect(port, '127.0.0.1');
  const chunks = [];
  socket.on('data', chunk => chunks.push(chunk));
  const socketError = new Promise((_, reject) => socket.once('error', reject));
  await Promise.race([new Promise(resolveConnect => socket.once('connect', resolveConnect)), socketError]);
  socket.end(wire);
  await Promise.race([new Promise(resolveClose => socket.once('close', resolveClose)), socketError]);
  const raw = Buffer.concat(chunks), response = decodeHttpResponse(raw);
  const { head, status, body: responseBody } = response;
  if (status !== 401) throw Error(`exact durable replay expected HTTP 401, got ${status || 'invalid status'}`);
  let parsed; try { parsed = JSON.parse(responseBody.toString('utf8')); } catch { throw Error('durable replay refusal body is not JSON'); }
  if ((parsed?.error?.code ?? parsed?.error?.message) !== 'replayed_nonce') throw Error('durable replay refusal body is not replayed_nonce');
  const responseAuth = [...head.matchAll(/^Jack-Auth:\s*(.*)$/gim)];
  if (responseAuth.length > 1) throw Error('durable replay response has duplicate Jack-Auth headers');
  const auth = responseAuth[0]?.[1];
  if (auth !== undefined) verifyReplay(auth, status, responseBody, evidence.request_sig);
  return { status, code: 'replayed_nonce', responseBody, v1_evidence: auth === undefined ? null : { status, kid: /^v1 kid=([A-Za-z0-9_-]+)/.exec(auth)?.[1], ts: Number(/,ts=(0|[1-9][0-9]{0,11}),/.exec(auth)?.[1]), sig: /,sig=([A-Za-z0-9_-]+)$/.exec(auth)?.[1], body_b64u: responseBody.toString('base64url'), request_sig: evidence.request_sig } };
}
function verifyRawV1(auth, status, body, requestSig, pinnedVerifier) {
  const match = /^v1 kid=([A-Za-z0-9_-]+),ts=(0|[1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]+)$/.exec(auth);
  if (!match) throw Error('durable replay response Jack-Auth is malformed');
  pinnedVerifier({ type: 'terminal', outcome: 'refused', http_status: status, request_sig: requestSig, code: 'replayed_nonce', http_code: 'replayed_nonce', mcp_complete: false, v1_evidence: { status, kid: match[1], ts: Number(match[2]), sig: match[3], body_b64u: body.toString('base64url'), request_sig: requestSig } });
}
async function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    await Promise.all([...relays].map(async relay => { try { await relay.close(); } catch {} }));
    relays.clear();
    await Promise.all([...children].map(child => stopChild({ child, done: new Promise(resolveDone => child.once('close', resolveDone)) })));
    if (tempRoot) { try { rmSync(tempRoot, { recursive: true, force: true }); } catch {} tempRoot = undefined; }
  })();
  return cleanupPromise;
}
process.once('SIGINT', () => { cleanup().finally(() => { process.exitCode = 130; }); });
process.once('SIGTERM', () => { cleanup().finally(() => { process.exitCode = 143; }); });
process.once('exit', () => { if (tempRoot) { try { rmSync(tempRoot, { recursive: true, force: true }); } catch {} } });

async function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); }
  catch (error) { console.error(`${error.message}\n${USAGE}`); process.exitCode = 2; return; }
  try {
    // These lifecycle matrices are intentionally deferred; do not resolve targets or
    // look up scenario rows for them until their orchestration is implemented.
    if (args.matrix === 'rotation-stream' || args.matrix === 'durable-stream') {
      console.log(`DEFERRED matrix=${args.matrix}: lifecycle orchestration is not active`);
      process.exitCode = 2;
      return;
    }
    // Resolve --targets from the repository root, never relative to the targets file itself.
    const targetPath = resolve(ROOT, args.targets);
    const targetDoc = readJson(targetPath);
    const scenarioDoc = readJson(join(HERE, 'stream-scenarios.json'));
    const scenarios = scenarioDoc.matrices?.[args.matrix];
    if (!Array.isArray(scenarios)) usageError(`missing matrix ${args.matrix}`);
    if (args.list) { for (const scenario of scenarios) console.log(scenario.id); return; }
    if (args.selfTest) { await (await import('./stream/selftest.mjs')).selfTest(); return; }
    const languages = Object.keys(targetDoc);
    const select = (input, flag) => {
      const result = input === null ? languages : input.split(',').map(value => value.trim());
      if (!result.length || result.some(value => !value)) usageError(`empty language in ${flag}`);
      for (const language of result) if (!Object.hasOwn(targetDoc, language)) usageError(`unknown language '${language}' for ${flag}`);
      return result;
    };
    const servers = select(args.servers, '--servers');
    const clients = select(args.clients, '--clients');
    for (const [language, role] of [...servers.map(x => [x, 'stream_server']), ...clients.map(x => [x, 'stream_client'])]) {
      const target = targetDoc[language]?.[role];
      if (!Array.isArray(target) || !target.length || target.some(value => typeof value !== 'string')) usageError(`invalid target ${language}.${role}`);
    }
    let selected = scenarios;
    if (args.scenario !== null) {
      const ids = args.scenario.split(',').map(value => value.trim());
      if (!ids.length || ids.some(value => !value)) usageError('empty scenario id');
      for (const id of ids) if (!scenarios.some(scenario => scenario.id === id)) usageError(`unknown scenario '${id}'`);
      selected = ids.map(id => scenarios.find(scenario => scenario.id === id));
    }
    const registry = readJson(join(ROOT, 'spec/fixtures/registry.json'));
    if (!registry || registry.version !== 1 || typeof registry.aud !== 'string' || !Array.isArray(registry.keys)) usageError('invalid registry fixture');
    const fixture = readJson(join(ROOT, 'spec/fixtures/keys.json'));
    const verifyRecord = makeVerifier(fixture);
    const svc = fixture.keys.find(key => key.name === 'svc');
    const alice = fixture.keys.find(key => key.name === 'alice');
    if (!alice || typeof alice.seed_hex !== 'string' || typeof svc.seed_hex !== 'string') usageError('alice/svc fixture missing or invalid');
    tempRoot = mkdtempSync(join(tmpdir(), 'jack-stream-'));
    const statePath = join(tempRoot, 'state.json');
    writeFileSync(statePath, `${JSON.stringify({ version: 1, keys: registry.keys, invites: [] })}\n`);
    const resolvedTargets = Object.fromEntries([...servers.map(language => [`${language}:server`, targetCommand(targetDoc[language].stream_server)]), ...clients.map(language => [`${language}:client`, targetCommand(targetDoc[language].stream_client)])]);
    let passed = 0, failed = 0;
    const pairCount = servers.length * clients.length;
    console.log(`matrix=${args.matrix} pairs=${pairCount} checks=${selected.length}`);
    for (const client of clients) for (const serverLanguage of servers) {
      let pairPassed = 0;
      console.log(`== pair client=${client} server=${serverLanguage} matrix=${args.matrix} ==`);
      for (const scenario of selected) {
        let server, clientProcess, relay, secondClientProcess, concurrencyHeld = false, diagLog;
        try {
          const suffix = `${client}-${serverLanguage}-${scenario.id}-${passed + failed}`;
          const requestLog = join(tempRoot, `${suffix}.jsonl`);
          diagLog = requestLog;
          const clockFile = join(tempRoot, `${suffix}.clock`);
          const now = scenario.clock ?? (scenario.rotation ? 1767052810 : 1800000000);
          const activation = scenario.successor_activation ?? (scenario.rotation ? 1767225610 : undefined);
          writeFileSync(clockFile, `${now}\n`);
          const serverArgs = ['--profile', 'modern', '--matrix', args.matrix, '--scenario', scenario.id, '--aud', registry.aud, '--state', statePath, '--server-seed-hex', svc.seed_hex, '--clock-file', clockFile, '--request-log', requestLog, '--port', '0'];
          const rotationSuccessor = scenario.rotation ? fixture.keys.find(key => key.name === 'erin') : null;
          if (scenario.rotation && !rotationSuccessor?.seed_hex) throw Error('rotation scenario contract gap: successor fixture erin is unavailable');
          if (scenario.rotation) serverArgs.push('--ring-seed', `ring-1=${rotationSuccessor.seed_hex}`);
          if (scenario.id === 'rotation-cutoff-reopen') serverArgs.push('--successor-activation', String(activation));
          const options = scenario.stream_options || {};
          for (const [key, flag] of [['frameMaxBytes', '--frame-max-bytes'], ['maxConcurrentStreams', '--max-concurrent-streams'], ['maxStreamDurationMs', '--max-stream-duration-ms'], ['heartbeatMs', '--heartbeat-ms'], ['idleTimeoutMs', '--idle-timeout-ms']]) {
            if (options[key] !== undefined) serverArgs.push(flag, String(options[key]));
          }
          if (scenario.durable) {
            const durableDir = join(tempRoot, `${suffix}-durable`);
            serverArgs.push('--durable-dir', durableDir);
            if (scenario.durable.initialize_before_start) {
              mkdirSync(durableDir, { mode: 0o700 });
              const init = await launchResolved(resolvedTargets[`${serverLanguage}:server`], [...serverArgs, '--durable-init']);
              const initialized = await init.done;
              if (initialized.code !== 0 || initialized.signal || initialized.timedOut || initialized.stdout !== '{"durable_initialized":true}\n') throw Error(`durable store initialization failed or returned unexpected output: ${initialized.stderr}`);
            }
          }
          if (scenario.rotation) serverArgs.push('--rotation-store', join(tempRoot, `${suffix}-rotation`));
          server = launchResolved(resolvedTargets[`${serverLanguage}:server`], serverArgs);
          let ready = await waitReady(server);
          if (ready.server_public_key !== svc.public_key || ready.server_kid !== svc.kid) throw Error('server ready identity differs from pinned svc fixture');
          if (scenario.rotation) {
            server.write(`${JSON.stringify({ op: 'announce', reference: 'ring-1', kid: rotationSuccessor.kid })}\n`);
            let announced;
            try { announced = JSON.parse(await server.nextLine(10000)); } catch { throw Error('rotation server returned invalid announce JSON'); }
            if (announced.announced !== true || announced.ordinal !== 1 || announced.head_ordinal !== 1 || announced.published_at !== now || announced.activates_at !== activation || typeof announced.head_hash !== 'string') throw Error('rotation announce differs from the fixture-bound publish/activation contract');
            const gap = Error('rotation scenario cannot reopen with successor identity: selected client IPC exposes no successor-key resolver/configuration for stream verification; required --known-server-key kid=<kid>,public=<b64>,activation=<A> is unavailable');
            gap.contractGap = true;
            throw gap;
          }
          if (scenario.relay) {
            relay = await startRelay({ upstreamPort: ready.port, transform: scenario.relay, scenario: { ...scenario, relayFrame: relayFixtureFrame(scenario.relay) } });
            relays.add(relay);
            ready = { ...ready, port: relay.port };
          }
          const { body: requestBody, mirrors: mirrorHeaders } = scenarioRequest(scenario);
          const clientArgs = ['--profile', 'modern', '--matrix', args.matrix, '--scenario', scenario.id, '--url', `http://127.0.0.1:${ready.port}`, '--aud', registry.aud, '--clock-file', clockFile, '--server-public-key', svc.public_key, '--seed-hex', alice.seed_hex, '--request-log', requestLog, '--nonce', scenario.nonce, '--sid', scenario.sid, '--request-body-json', requestBody, '--jack-accept', scenario.id === 'opt-in-required' ? '' : 's1', '--modern-version', '2026-07-28', '--mirror-headers-json', JSON.stringify(mirrorHeaders)];
          if (scenario.id === 'cancel') clientArgs.push('--action', 'cancel');
          if (scenario.id === 'concurrency-limit' || scenario.id === 'durable-live-replay' || scenario.id === 'durable-restart-replay') clientArgs.push('--action', 'hold');
          if (activation !== undefined) clientArgs.push('--successor-activation', String(activation));
          if (scenario.durable) clientArgs.push('--durable-dir', join(tempRoot, `${suffix}-durable`));
          for (const [key, flag] of [['frameMaxBytes', '--frame-max-bytes'], ['maxConcurrentStreams', '--max-concurrent-streams'], ['maxStreamDurationMs', '--max-stream-duration-ms'], ['heartbeatMs', '--heartbeat-ms'], ['idleTimeoutMs', '--idle-timeout-ms']]) {
            if (options[key] !== undefined) clientArgs.push(flag, String(options[key]));
          }
          if (scenario.rotation) clientArgs.push('--rotation-store', join(tempRoot, `${suffix}-rotation`));
          clientProcess = launchResolved(resolvedTargets[`${client}:client`], clientArgs);
          if (scenario.id === 'max-duration') {
            const firstLine = await clientProcess.nextLine(10000);
            const firstRecord = JSON.parse(firstLine);
            if (firstRecord?.type !== 'message') throw Error('max-duration client did not emit its first stream message/open evidence');
            verifyRecord(firstRecord, scenario.request_id);
            if (!firstRecord.open || !Array.isArray(firstRecord.frames) || firstRecord.frames.length < 1) throw Error('max-duration client did not provide verified open/initial-frame evidence');
            let initialMessage;
            try { initialMessage = JSON.parse(firstRecord.data); } catch { initialMessage = firstRecord.message; }
            if (initialMessage && initialMessage.jsonrpc === '2.0' && initialMessage.id === scenario.request_id && (Object.hasOwn(initialMessage, 'result') || Object.hasOwn(initialMessage, 'error')) && !Object.hasOwn(initialMessage, 'method')) throw Error('max-duration producer sent its final response before the controlled clock advance');
            const beforeAdvance = await Promise.race([
              clientProcess.nextLine(100).then(line => ({ line }), error => ({ timeout: true, error })),
              new Promise(resolveResult => setTimeout(() => resolveResult({ timeout: true }), 110)),
            ]);
            if (!beforeAdvance.timeout) throw Error(`max-duration stream completed/emitted another record before clock advance: ${beforeAdvance.line}`);
            const duration = options.maxStreamDurationMs;
            if (!Number.isSafeInteger(duration) || duration <= 0) throw Error('max-duration scenario lacks a positive maxStreamDurationMs control value');
            const advanced = now + Math.ceil(duration / 1000);
            writeFileSync(clockFile, `${advanced}\n`);
            server.write(`${JSON.stringify({ action: 'clock_advanced', clock: advanced, start: now, duration_ms: duration })}\n`);
            let control;
            try { control = JSON.parse(await server.nextLine(1000)); } catch { throw Error('max-duration server cannot signal/acknowledge clock control; duration orchestration unsupported'); }
            if (control?.control !== 'clock_advanced' || control.clock !== advanced) throw Error('max-duration server did not acknowledge the requested clock control');
            const durationRows = readRows(requestLog);
            const changedAt = durationRows.findIndex(row => row.event === 'clock_changed' || row.event === 'clock_observed' && row.clock_changed === true);
            if (changedAt < 0) throw Error('max-duration request log lacks an observed clock_changed control record');
          }
          if (scenario.durable?.replay_while_first_stream_open || scenario.durable?.clean_restart) {
            const firstRecord = JSON.parse(await clientProcess.nextLine(10000));
            if (firstRecord?.type !== 'message') throw Error('durable client did not emit its first stream message');
            verifyRequestEvidence(firstRecord, alice, registry.aud);
            verifyRecord(firstRecord, scenario.request_id);
            const authRows = firstRecord.request_headers.filter(row => Array.isArray(row) && String(row[0]).toLowerCase() === 'jack-auth');
            if (authRows.length !== 1 || !authRows[0][1].endsWith(`sig=${firstRecord.request_sig}`)) throw Error('durable replay Jack-Auth differs from verified request signature');
            let replay;
            if (scenario.durable.replay_while_first_stream_open) {
            const endedBeforeReplay = await Promise.race([clientProcess.done.then(() => true), new Promise(resolveResult => setTimeout(() => resolveResult(false), 50))]);
            if (endedBeforeReplay) throw Error('first stream terminated before live replay');
            replay = await replayRawRequest(ready.port, firstRecord, (auth, status, body, sig) => verifyRawV1(auth, status, body, sig, verifyRecord));
            const liveRows = readRows(requestLog);
            const replayAt = liveRows.findIndex(row => row.event === 'replayed_nonce' && row.request_sig === firstRecord.request_sig && row.nonce === firstRecord.nonce);
            const firstRequest = liveRows.find(row => row.request_sig === firstRecord.request_sig && row.request_verified === true);
            const loggedAuth = firstRequest?.request_headers?.filter(row => Array.isArray(row) && String(row[0]).toLowerCase() === 'jack-auth').map(([, value]) => value);
            const capturedAuth = firstRecord.request_headers.filter(row => Array.isArray(row) && String(row[0]).toLowerCase() === 'jack-auth').map(([, value]) => value);
            const committedAt = liveRows.findIndex(row => row.event === 'nonce_committed' && row.request_sig === firstRecord.request_sig && row.nonce === firstRecord.nonce && row.nonce_committed_before_first_byte === true);
            const openedAt = liveRows.findIndex(row => row.event === 'stream_open' && row.request_sig === firstRecord.request_sig);
            if (!firstRequest || firstRequest.nonce !== firstRecord.nonce || firstRequest.request_body_b64u !== firstRecord.request_body_b64u || !isDeepStrictEqual(loggedAuth, capturedAuth) || committedAt < 0 || openedAt < 0 || committedAt >= openedAt || replayAt <= openedAt) throw Error('live replay log does not prove exact authenticated replay after nonce commit and stream_open');
            const stillOpen = await Promise.race([clientProcess.done.then(() => false), new Promise(resolveResult => setTimeout(() => resolveResult(true), 50))]);
              if (!stillOpen) throw Error('first stream ended before live replay response');
              concurrencyHeld = false;
              await stopChild(clientProcess);
              const liveLines = parseJsonLines(clientProcess.stdout);
              for (const record of liveLines) verifyRecord(record, scenario.request_id);
            } else {
              const initialRows = readRows(requestLog);
              const requestAt = initialRows.findIndex(row => row.request_sig === firstRecord.request_sig && row.request_verified === true);
              const committedAt = initialRows.findIndex((row, i) => i >= requestAt && row.event === 'nonce_committed' && row.request_sig === firstRecord.request_sig && row.nonce === firstRecord.nonce && row.nonce_committed_before_first_byte === true);
              const openedAt = initialRows.findIndex((row, i) => i >= requestAt && row.event === 'stream_open' && row.request_sig === firstRecord.request_sig);
              if (requestAt < 0 || committedAt < 0 || openedAt < 0 || committedAt >= openedAt) throw Error('durable log does not prove nonce commit before stream open');
              await stopServerClean(server); server = null;
              server = launchResolved(resolvedTargets[`${serverLanguage}:server`], serverArgs);
              ready = await waitReady(server);
              if (ready.server_public_key !== svc.public_key || ready.server_kid !== svc.kid) throw Error('restarted durable server identity differs from pinned svc fixture');
              replay = await replayRawRequest(ready.port, firstRecord, (auth, status, body, sig) => verifyRawV1(auth, status, body, sig, verifyRecord));
              const rows = readRows(requestLog);
              const restartRequest = rows.find(row => row.request_sig === firstRecord.request_sig && row.request_verified === true);
              const replayRow = rows.findIndex(row => row.event === 'replayed_nonce' && row.request_sig === firstRecord.request_sig && row.nonce === firstRecord.nonce);
              const restartCommittedAt = rows.findIndex(row => row.event === 'nonce_committed' && row.request_sig === firstRecord.request_sig && row.nonce === firstRecord.nonce && row.nonce_committed_before_first_byte === true);
              const restartOpenedAt = rows.findIndex(row => row.event === 'stream_open' && row.request_sig === firstRecord.request_sig);
              if (!restartRequest || restartRequest.nonce !== scenario.nonce || restartRequest.request_body_b64u !== firstRecord.request_body_b64u || restartCommittedAt < 0 || restartOpenedAt < 0 || restartCommittedAt >= restartOpenedAt || replayRow <= restartOpenedAt) throw Error('restart replay log does not match exact captured authenticated request and ordered nonce lifecycle');
              await stopServerClean(server); server = null;
              await stopChild(clientProcess);
            }
            if (replay.code !== 'replayed_nonce') throw Error('durable replay was not refused');
            const durableMessages = scenario.durable.replay_while_first_stream_open ? [firstRecord.message ?? JSON.parse(firstRecord.data)] : [];
            const durableTerminal = { type: 'terminal', outcome: 'refused', http_status: replay.status, http_code: replay.code, request_sig: firstRecord.request_sig, mcp_complete: false, v1_evidence: replay.v1_evidence };
            const durableActual = { messages: durableMessages, terminal: durableTerminal };
            if (!scenarioSubset(durableActual, scenario.expected)) throw Error(`durable lifecycle oracle mismatch: ${JSON.stringify(durableActual)}`);
            if (scenario.durable.clean_restart && (replay.status !== 401 || replay.code !== 'replayed_nonce')) throw Error('durable restart replay response was not refused as replayed_nonce');
            verifyRecord(durableTerminal, scenario.request_id);
            passed++; pairPassed++;
            console.log(`PASS ${scenario.id}`);
            continue;
          }

          let concurrencyAggregate, concurrencyRecords;
          if (scenario.id === 'concurrency-limit') {
            const firstLine = await clientProcess.nextLine(10000);
            const firstRecord = JSON.parse(firstLine);
            if (firstRecord?.type !== 'message') throw Error('hold client did not emit its first message');
            verifyRecord(firstRecord, scenario.request_id);
            concurrencyRecords = [firstRecord];
            concurrencyHeld = true;
            const secondArgs = [...clientArgs];
            const secondNonce = deterministicVariant(scenario.nonce, 'second');
            const secondSid = deterministicVariant(scenario.sid, 'second');
            secondArgs.splice(secondArgs.indexOf('--action') + 1, 1, 'once');
            secondArgs.splice(secondArgs.indexOf('--nonce') + 1, 1, secondNonce);
            secondArgs.splice(secondArgs.indexOf('--sid') + 1, 1, secondSid);
            secondClientProcess = launchResolved(resolvedTargets[`${client}:client`], secondArgs);
            const secondResult = await secondClientProcess.done;
            if (secondResult.code !== 0) throw Error(`second client exit ${secondResult.code}: ${secondResult.stderr}`);
            const secondRecords = parseJsonLines(secondResult.stdout);
            const secondTerminals = secondRecords.filter(record => record?.type === 'terminal');
            if (secondTerminals.length !== 1 || secondRecords.at(-1) !== secondTerminals[0]) throw Error('second client expected one final terminal record');
            verifyRecord(secondTerminals[0], scenario.request_id);
            const secondTerminal = secondTerminals[0];
            if (secondTerminal.http_status !== 429 || secondTerminal.code !== 'stream_limit_exceeded' || !secondTerminal.v1_evidence) throw Error('second client did not receive signed stream-limit refusal');
            if (secondTerminal.request_sig !== undefined) verifyRecord(secondTerminal, scenario.request_id);
            if (typeof secondTerminal.request_sig !== 'string' || !secondTerminal.v1_evidence || secondTerminal.v1_evidence.request_sig !== secondTerminal.request_sig) throw Error('second refusal lacks its actual request signature evidence');
            if (secondTerminal.v1_evidence.status !== 429 || secondTerminal.v1_evidence.request_sig !== secondTerminal.request_sig) throw Error('second 429 evidence is not bound to its actual request');
            const noBytes = (secondTerminal.frames_verified ?? 0) === 0 && (!Array.isArray(secondTerminal.frames) || secondTerminal.frames.length === 0) && !secondTerminal.open;
            if (!noBytes) throw Error('second 429 refusal unexpectedly includes stream bytes');
            const secondLog = readRows(requestLog).find(row => row.request_sig === secondTerminal.request_sig);
            if (!secondLog || secondLog.nonce !== secondNonce || secondLog.request_verified !== true || secondLog.request_sig !== secondTerminal.request_sig) throw Error('second 429 request log does not prove the expected independent signed nonce request');
            server.write(`${JSON.stringify({ action: 'release' })}\n`);
            let releaseAck;
            try { releaseAck = JSON.parse(await server.nextLine(10000)); } catch { throw Error('server did not acknowledge held-stream release'); }
            if (releaseAck?.control !== 'released' || (releaseAck.sid !== undefined && releaseAck.sid !== firstRecord.open?.sid)) throw Error('server released-control acknowledgement does not match held stream');
            concurrencyHeld = false;
            const released = await clientProcess.done;
            if (released.code !== 0) throw Error(`first concurrency client exit ${released.code}: ${released.stderr}`);
            concurrencyRecords = parseJsonLines(released.stdout);
            const firstTerminals = concurrencyRecords.filter(record => record?.type === 'terminal');
            if (firstTerminals.length !== 1 || concurrencyRecords.at(-1) !== firstTerminals[0]) throw Error('released held stream must end with exactly one terminal after all messages');
            for (const record of concurrencyRecords) verifyRecord(record, scenario.request_id);
            if (concurrencyRecords.slice(0, -1).some(record => record?.type !== 'message')) throw Error('released held stream contains a non-message before terminal');
            const firstTerminal = firstTerminals[0];
            if (firstTerminal.outcome !== 'complete') throw Error('released first stream did not complete');
            concurrencyAggregate = { terminal: secondTerminal, firstTerminal, secondRecords, secondRequestSig: secondTerminal.request_sig };
          }
          const result = await clientProcess.done;
          clientProcess.lastResult = result;
          if (result.code !== 0) throw Error(`client exit ${result.code}${result.signal ? ` (${result.signal})` : ''}: ${result.stderr}`);
          const records = concurrencyRecords ?? parseJsonLines(result.stdout);
          const terminalRecords = records.filter(record => record?.type === 'terminal');
          if (scenario.id !== 'concurrency-limit' && (terminalRecords.length !== 1 || records.at(-1) !== terminalRecords[0])) throw Error('expected exactly one final terminal record');
          if (scenario.id === 'concurrency-limit' && (terminalRecords.length !== 1 || records.at(-1) !== terminalRecords[0])) throw Error('held first stream must have exactly one final terminal');
          const messageRecords = records.slice(0, -1);
          if (messageRecords.some(record => record?.type !== 'message')) throw Error('unexpected non-message record before terminal');
          const messages = [];
          for (const record of messageRecords) {
            const checked = verifyRecord(record, scenario.request_id);
            if (typeof record.data === 'string') {
              try { messages.push(JSON.parse(record.data)); } catch { throw Error('verified message data is not JSON'); }
            } else if (record.message !== undefined) messages.push(record.message);
            else throw Error('message line lacks data/message');
            if (record.data === undefined && record.message === undefined) throw Error('message line lacks verified data');
          }
          const terminalCheck = verifyRecord(terminalRecords[0], scenario.request_id);
          const logText = existsSync(requestLog) ? readFileSync(requestLog, 'utf8') : '';
          const logRows = logText.split(/\r?\n/).filter(Boolean).map((line, index) => { try { return JSON.parse(line); } catch { throw Error(`request log line ${index + 1} is invalid JSON`); } });
          if (scenario.id === 'max-duration') {
            const changedAt = logRows.findIndex(row => row.event === 'clock_changed' || row.event === 'clock_observed' && row.clock_changed === true);
            const elapsedAt = logRows.findIndex(row => row.event === 'duration_elapsed' || row.duration_elapsed === true);
            if (changedAt < 0 || elapsedAt <= changedAt) throw Error('max-duration server log must prove ordered clock_changed then duration_elapsed observations');
            if (terminalCheck.terminal.outcome !== 'complete' || terminalCheck.terminal.terminal_frame?.kind !== 'end') throw Error('max-duration stream must finish with complete terminal and signed end');
          }
          const heartbeatPayload = 'notifications/events/heartbeat';
          const heartbeatExpected = scenario.stream_options?.heartbeatMs !== undefined || (scenario.expected?.messages || []).some(message => message?.method === heartbeatPayload);
          if (heartbeatExpected) {
            const grantRows = logRows.filter(row => row.event === 'heartbeat_granted' || row.heartbeat_granted_ms !== undefined || row.granted_heartbeat_ms !== undefined);
            if (!grantRows.length) throw Error('heartbeat contract gap: server request log does not expose its granted heartbeat value');
            const grantRow = grantRows.at(-1);
            const granted = grantRow.heartbeat_granted_ms ?? grantRow.granted_heartbeat_ms ?? grantRow.heartbeat_ms;
            if (!Number.isSafeInteger(granted) || granted < 0) throw Error('heartbeat contract gap: server log grant is not a nonnegative integer');
            const windowSeconds = scenario.windowSeconds ?? scenario.stream_options?.windowSeconds ?? 30;
            if (!Number.isSafeInteger(windowSeconds) || windowSeconds <= 0 || granted > Math.floor(windowSeconds * 500)) throw Error('server heartbeat grant exceeds floor(W * 500)');
            const heartbeatFrames = new Map();
            for (const record of records) for (const frame of record.frames || []) {
              if (frame.kind === 'message') {
                let message; try { message = JSON.parse(frame.data); } catch { continue; }
                if (message?.method === heartbeatPayload) heartbeatFrames.set(frame.seq, frame);
              }
            }
            const expectedHeartbeatCount = (scenario.expected?.messages || []).filter(message => message?.method === heartbeatPayload).length;
            if (!heartbeatFrames.size || heartbeatFrames.size !== expectedHeartbeatCount) throw Error(`heartbeat contract gap: expected ${expectedHeartbeatCount} verified heartbeat frames, observed ${heartbeatFrames.size}`);
            const frames = [...heartbeatFrames.values()].sort((a, b) => a.seq - b.seq);
            for (let i = 0; i < frames.length; i++) {
              if (Math.abs(frames[i].ts - now) > windowSeconds) throw Error('heartbeat frame timestamp is outside W');
              if (i && frames[i].ts - frames[i - 1].ts > Math.ceil(granted / 1000)) throw Error('heartbeat frame interval exceeds logged server grant');
            }
          }
          const observedRequestSigs = new Set(logRows.map(row => row.request_sig).filter(value => typeof value === 'string'));
          for (const record of records) {
            if (typeof record.request_sig === 'string' && observedRequestSigs.size && !observedRequestSigs.has(record.request_sig)) throw Error('client evidence request signature absent from server request log');
          }
          const { body: expectedBody, mirrors: expectedMirrors } = scenarioRequest(scenario);
          const allRecords = concurrencyAggregate ? [...concurrencyRecords, ...concurrencyAggregate.secondRecords] : records;
          const expectedSignatures = new Set(allRecords.map(record => record.request_sig).filter(value => typeof value === 'string'));
          if (expectedSignatures.size === 0) throw Error('client records lack request signatures for authenticated request-log audit');
          const authRows = logRows.filter(row => expectedSignatures.has(row.request_sig) && typeof row.body === 'string');
          if (authRows.length !== expectedSignatures.size) throw Error('server request log is missing an authenticated request record');
          const expectedJson = JSON.parse(expectedBody);
          for (const row of authRows) {
            if (row.request_verified !== true) throw Error('server request log does not prove authentication');
            if (row.body !== expectedBody || row.request_method !== 'POST' || row.request_mcp_method !== scenario.request_method || !isDeepStrictEqual(row.request_params?._meta, expectedJson.params._meta)) throw Error('server log modern request metadata/body differs from scenario request');
            const expectedNonce = scenario.id === 'concurrency-limit' && row.request_sig === concurrencyAggregate?.secondRequestSig ? deterministicVariant(scenario.nonce, 'second') : scenario.nonce;
            if (row.nonce !== expectedNonce) throw Error('server request nonce differs from expected scenario input');
            if (row.mirror_protocol_version !== '2026-07-28' || row.mirror_method !== scenario.request_method) throw Error('server request log modern protocol/method mirrors mismatch');
            const expectedMirrorParams = Object.fromEntries(expectedMirrors.filter(([name]) => name.startsWith('Mcp-Param-')));
            if (Object.entries(expectedMirrorParams).some(([name, value]) => row[`mirror_param_${name.slice('Mcp-Param-'.length).toLowerCase()}`] !== undefined && String(row[`mirror_param_${name.slice('Mcp-Param-'.length).toLowerCase()}`]) !== value)) throw Error('server request log Mcp-Param mirrors mismatch');
            if (expectedMirrors.some(([name]) => name === 'Mcp-Name') && row.mirror_name !== expectedMirrors.find(([name]) => name === 'Mcp-Name')[1]) throw Error('server request log Mcp-Name mirror mismatch');
            if (scenario.id === 'concurrency-limit') {
              const firstRequestRow = logRows.find(row => row.request_sig === concurrencyRecords[0]?.request_sig && row.request_verified === true);
              const firstOpenRow = logRows.find(row => row.event === 'stream_open' && row.request_sig === concurrencyRecords[0]?.request_sig);
              const secondRequestRow = logRows.find(row => row.request_sig === concurrencyAggregate.secondRequestSig && row.request_verified === true);
              if (!firstRequestRow || firstRequestRow.nonce !== scenario.nonce || firstRequestRow.request_method !== 'POST' || firstRequestRow.request_mcp_method !== scenario.request_method || firstRequestRow.body !== expectedBody || !isDeepStrictEqual(firstRequestRow.request_params?._meta, expectedJson.params._meta) || !firstOpenRow || firstOpenRow.sid !== concurrencyRecords[0]?.open?.sid) throw Error('first concurrency success log entry does not match its exact nonce/signature/sid');
              if (!secondRequestRow || secondRequestRow.nonce !== deterministicVariant(scenario.nonce, 'second') || secondRequestRow.request_method !== 'POST' || secondRequestRow.request_mcp_method !== scenario.request_method || secondRequestRow.body !== expectedBody || !isDeepStrictEqual(secondRequestRow.request_params?._meta, expectedJson.params._meta)) throw Error('second concurrency request log does not match its exact nonce and shared request body');
              if (firstRequestRow.nonce === secondRequestRow.nonce) throw Error('concurrency requests must use distinct nonces');
            }
          }
          if (scenario.id === 'cancel' && !logRows.some(row => row.event === 'handler_cancelled' || row.event === 'request_cancelled' || row.handler_cancelled === true)) throw Error('request log lacks observed handler cancellation');
          if (scenario.id === 'cancel' && !terminalRecords[0]?.outcome?.includes('cancel')) throw Error('client did not report cancellation terminal after its first message');
          if (scenario.durable?.commit_before_first_byte) {
            const committed = logRows.findIndex(row => row.nonce_committed_before_first_byte === true || row.event === 'nonce_committed');
            const opened = logRows.findIndex(row => row.event === 'stream_open' || row.event === 'first_byte' || row.first_response_byte === true);
            if (committed < 0 || (opened >= 0 && committed > opened)) throw Error('request log lacks durable nonce commit before first response byte');
          }
          if (scenario.relay && !relay.applied()) throw Error(`relay transform '${scenario.relay}' was not applied`);
          const actualTerminal = scenario.id === 'cancel' ? { ...terminalCheck.terminal, handler_cancelled: logRows.some(row => row.event === 'handler_cancelled' || row.event === 'request_cancelled' || row.handler_cancelled === true) } : terminalCheck.terminal;
          const actual = concurrencyAggregate ? { messages: [], terminal: concurrencyAggregate.terminal } : { messages, terminal: actualTerminal };
          if (!scenarioSubset(actual, scenario.expected)) throw Error(`oracle mismatch expected=${JSON.stringify(scenario.expected)} actual=${JSON.stringify(actual)}`);
          passed++; pairPassed++;
          console.log(`PASS ${scenario.id}`);
          } catch (error) {
          if (error.contractGap) { console.error(`CONTRACT GAP ${scenario.id}: ${error.message}`); process.exitCode = 2; throw error; }
          failed++;
          console.log(`FAIL ${scenario.id}: ${error.message}`);
          const last = clientProcess?.lastResult;
          if (last) console.log(`  client stdout: ${String(last.stdout).slice(0, 3000)}\n  client stderr: ${String(last.stderr).slice(0, 1000)}`);
          if (diagLog && existsSync(diagLog)) console.log(`  request log: ${readFileSync(diagLog, 'utf8').slice(0, 3000)}`);
        } finally {
          if (concurrencyHeld && server) server.write(`${JSON.stringify({ action: 'release' })}\n`);
          if (secondClientProcess) await stopChild(secondClientProcess);
          if (clientProcess) await stopChild(clientProcess);
          if (relay) { await relay.close(); relays.delete(relay); }
          await stopChild(server);
        }
      }
      console.log(`pair client=${client} server=${serverLanguage} passed=${pairPassed} failed=${selected.length - pairPassed}`);
    }
    console.log(`INTEROP-SUMMARY matrix=${args.matrix} pairs=${pairCount} checks=${selected.length} passed=${passed} failed=${failed} result=${failed ? 'fail' : 'pass'}`);
    process.exitCode = failed ? 1 : 0;
  } catch (error) {
    console.error(error.message);
    if (error.usage) { console.error(USAGE); process.exitCode = 2; }
    else process.exitCode = 2;
  } finally { await cleanup(); }
}
main().catch(async error => { console.error(error.stack || error); process.exitCode = 2; await cleanup(); });
