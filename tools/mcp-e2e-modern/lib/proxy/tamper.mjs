import { createServer, request as requestHttp } from 'node:http';
import { bound, redactRecord } from '../redact.mjs';
import { CAPTURE_DEFAULTS } from '../config.mjs';

export function startTamperProxy({ port = 0, secrets = [], flipByteOffset = 0, upstream, limits = {} } = {}) {
  const base = new URL(upstream ?? limits.upstream ?? process.env.MCP_E2E_UPSTREAM ?? 'http://127.0.0.1:0');
  const captures = [];
  let sequence = 0;
  let flipped = false;
  const save = (entry) => {
    if (captures.length < (limits.maxEvents ?? CAPTURE_DEFAULTS.maxEvents)) captures.push(redactRecord({ ...entry, body: bound(entry.body, limits.maxBytesPerEvent ?? CAPTURE_DEFAULTS.maxBytesPerEvent) }, secrets));
  };
  const server = createServer((down, res) => {
    const hop = `hop-${++sequence}`;
    const chunks = [];
    down.on('data', (chunk) => chunks.push(chunk));
    down.on('end', () => {
      const body = Buffer.concat(chunks);
      save({ hop, direction: 'request', method: down.method ?? null, status: null, media_type: down.headers['content-type']?.split(';')[0] ?? null, body: body.toString('utf8') });
      const target = new URL(down.url ?? '/', base);
      const req = requestHttp(target, { method: down.method, headers: { ...down.headers, host: target.host } }, (up) => {
        const out = [];
        up.on('data', (chunk) => out.push(chunk));
        up.on('end', () => {
          const bytes = Buffer.concat(out);
          save({ hop, direction: 'response', method: down.method ?? null, status: up.statusCode ?? null, media_type: String(up.headers['content-type'] ?? '').split(';')[0] || null, body: bytes.toString('utf8') });
          let send = bytes;
          if (!flipped && bytes.length && Number.isInteger(flipByteOffset) && flipByteOffset >= 0 && flipByteOffset < bytes.length) {
            send = Buffer.from(bytes); send[flipByteOffset] ^= 1; flipped = true;
          }
          const headers = { ...up.headers, 'content-length': send.length };
          delete headers['transfer-encoding'];
          res.writeHead(up.statusCode ?? 502, headers); res.end(send);
        });
        up.on('error', () => res.destroy());
      });
      req.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('upstream request failed'); });
      req.end(body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      resolve({ url: `http://127.0.0.1:${address.port}`, port: address.port, captures, get flipped() { return flipped; }, stop: () => new Promise((done) => { server.closeAllConnections?.(); server.close(done); }) });
    });
  });
}
