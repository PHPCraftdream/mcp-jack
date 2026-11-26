import { createServer, request as requestHttp } from 'node:http';
import { bound, redactRecord } from '../redact.mjs';
import { CAPTURE_DEFAULTS } from '../config.mjs';

export function startIncrementalProxy({ port = 0, secrets = [], limits = {} } = {}) {
  const upstreamBase = new URL(limits.upstream ?? process.env.MCP_E2E_UPSTREAM ?? 'http://127.0.0.1:0');
  const maxEvents = limits.maxEvents ?? CAPTURE_DEFAULTS.maxEvents;
  const maxBytes = limits.maxBytesPerEvent ?? CAPTURE_DEFAULTS.maxBytesPerEvent;
  const captures = [];
  const requests = new Map();
  // Raw evidence is in-process only, persisted as boolean+fingerprint only.
  const rawSignatures = new Map();
  const waiters = new Set();
  const outbound = new Set();
  let sequence = 0;
  const add = (record) => {
    if (captures.length >= maxEvents) return;
    captures.push(redactRecord({ ...record, body: bound(record.body, maxBytes) }, secrets));
    for (const waiter of [...waiters]) {
      try { if (waiter.predicate(captures.at(-1))) { waiters.delete(waiter); waiter.resolve(captures.at(-1)); } } catch { }
    }
  };
  const server = createServer((down, res) => {
    const id = `hop-${++sequence}`;
    if (requests.size >= maxEvents) requests.delete(requests.keys().next().value);
    const allowed = ['jack-accept', 'accept', 'mcp-protocol-version', 'protocol-version', 'mcp-method', 'mcp-name', ...Object.keys(down.headers).filter((key) => key.startsWith('mcp-param-'))];
    const hop = { id, hop: id, method: down.method ?? null, headers: Object.fromEntries([...allowed, 'jack-auth'].filter((key) => down.headers[key] !== undefined).map((key) => [key, down.headers[key]])), hasAuth: down.headers['jack-auth'] !== undefined || down.headers.authorization !== undefined };
    requests.set(id, hop);
    let reqText = '';
    const appendLimited = (current, addition) => {
      const combined = current + addition;
      return Buffer.byteLength(combined, 'utf8') <= maxBytes + 16 ? combined : bound(combined, maxBytes);
    };
    const target = new URL(down.url ?? '/', upstreamBase);
    const headers = { ...down.headers, host: target.host };
    const upstream = requestHttp(target, { method: down.method, headers });
    outbound.add(upstream); upstream.once('close', () => outbound.delete(upstream));
    let aborted = false;
    const abortUpstream = () => {
      if (aborted || res.writableEnded) return;
      aborted = true;
      upstream.destroy();
      add({ hop: id, direction: 'event', method: down.method ?? null, status: null, media_type: null, headers: {}, body: '[upstream-aborted]' });
    };
    res.on('close', abortUpstream);
    down.on('data', (chunk) => { reqText = appendLimited(reqText, chunk.toString('utf8')); });
    down.on('end', () => add({ hop: id, direction: 'request', method: down.method ?? null, status: null, media_type: down.headers['content-type']?.split(';')[0] ?? null, headers: Object.fromEntries(['jack-auth'].filter((key) => down.headers[key] !== undefined).map((key) => [key, down.headers[key]])), body: reqText }));
    down.on('aborted', abortUpstream);
    down.on('error', abortUpstream);
    upstream.on('error', (error) => {
      if (aborted) return;
      add({ hop: id, direction: 'event', method: down.method ?? null, status: null, media_type: null, headers: {}, body: `[upstream-error] ${error.message}` });
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('upstream request failed');
    });
    upstream.on('response', (up) => {
      const media = String(up.headers['content-type'] ?? '').split(';')[0] || null;
      res.writeHead(up.statusCode ?? 502, up.headers);
      let responseText = '';
      let sseBuffer = '';
      const eventFields = [];
      const recordFrame = (frame) => {
        if (!frame) return;
        add({ hop: id, direction: 'event', method: down.method ?? null, status: up.statusCode ?? null, media_type: media, headers: {}, body: frame });
      };
      up.on('data', (chunk) => {
        if (!res.destroyed && !res.write(chunk)) {
          up.pause();
          res.once('drain', () => up.resume());
        }
        const text = chunk.toString('utf8');
        if (media === 'text/event-stream') {
          sseBuffer += text;
          let match;
          while ((match = /\r?\n\r?\n/.exec(sseBuffer)) !== null) {
            const frame = sseBuffer.slice(0, match.index);
            sseBuffer = sseBuffer.slice(match.index + match[0].length);
            recordFrame(frame);
          }
          if (Buffer.byteLength(sseBuffer, 'utf8') > 64 * maxBytes) {
            const tailBytes = Buffer.from(sseBuffer, 'utf8').subarray(-64 * maxBytes);
            sseBuffer = tailBytes.toString('utf8');
          }
        } else responseText = appendLimited(responseText, text);
      });
      up.on('end', () => {
        if (media === 'text/event-stream') recordFrame(sseBuffer);
        else {
          if (up.headers['jack-auth'] !== undefined) rawSignatures.set(id, { status: up.statusCode ?? null, jackAuth: up.headers['jack-auth'], body: responseText });
          add({ hop: id, direction: 'response', method: down.method ?? null, status: up.statusCode ?? null, media_type: media, headers: Object.fromEntries(['jack-auth'].filter((key) => up.headers[key] !== undefined).map((key) => [key, up.headers[key]])), body: responseText });
        }
        if (!res.destroyed) res.end();
      });
      up.on('error', () => { if (!res.destroyed) res.destroy(); });
    });
    down.pipe(upstream);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      resolve({ url: `http://127.0.0.1:${address.port}`, port: address.port, captures, requests, rawSignatures, metadata: requests, waitFor(predicate) {
        const match = captures.find(predicate); if (match) return Promise.resolve(match);
        return new Promise((done) => waiters.add({ predicate, resolve: done }));
      }, close: () => new Promise((done) => { for (const req of outbound) req.destroy(); server.closeAllConnections?.(); server.close(() => done()); }) });
    });
  });
}
