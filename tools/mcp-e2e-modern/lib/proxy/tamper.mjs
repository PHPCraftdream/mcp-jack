import { createServer, request as requestHttp } from 'node:http';
import { bound, redactRecord } from '../redact.mjs';
import { CAPTURE_DEFAULTS } from '../config.mjs';

export function startTamperProxy({ port = 0, secrets = [], upstream, limits = {} } = {}) {
  const base = new URL(upstream ?? limits.upstream ?? process.env.MCP_E2E_UPSTREAM ?? 'http://127.0.0.1:0');
  const captures = [];
  const outbound = new Set();
  let sequence = 0;
  let flipped = false;
  let flipInfo = null;
  const save = (entry) => {
    if (captures.length < (limits.maxEvents ?? CAPTURE_DEFAULTS.maxEvents)) captures.push(redactRecord({ ...entry, body: bound(entry.body, limits.maxBytesPerEvent ?? CAPTURE_DEFAULTS.maxBytesPerEvent) }, secrets));
  };
  const server = createServer((down, res) => {
    const hop = `hop-${++sequence}`;
    const chunks = [];
    down.on('data', (chunk) => chunks.push(chunk));
    down.on('end', () => {
      const body = Buffer.concat(chunks);
      save({ hop, direction: 'request', method: down.method ?? null, status: null, media_type: down.headers['content-type']?.split(';')[0] ?? null, headers: Object.fromEntries(['jack-auth'].filter((key) => down.headers[key] !== undefined).map((key) => [key, down.headers[key]])), body: body.toString('utf8') });
      const target = new URL(down.url ?? '/', base);
      const req = requestHttp(target, { method: down.method, headers: { ...down.headers, host: target.host } }, (up) => {
        const out = [];
        up.on('data', (chunk) => out.push(chunk));
        up.on('end', () => {
          const bytes = Buffer.concat(out);
          save({ hop, direction: 'response', method: down.method ?? null, status: up.statusCode ?? null, media_type: String(up.headers['content-type'] ?? '').split(';')[0] || null, headers: Object.fromEntries(['jack-auth'].filter((key) => up.headers[key] !== undefined).map((key) => [key, up.headers[key]])), body: bytes.toString('utf8') });
          let send = bytes;
          if (!flipped && bytes.length) {
            send = Buffer.from(bytes);
            const text = send.toString('latin1');
            const jack = /(?:^|\n)jack: seq=[^\r\n]*?\bts=([0-9]+)/.exec(text);
            let offset;
            let target;
            if (jack) {
              offset = jack.index + jack[0].lastIndexOf(jack[1]) + jack[1].length - 1;
              target = 'frame ts value';
            } else {
              const resultMember = /"result"\s*:/.exec(text);
              let valueOffset = -1;
              if (resultMember) {
                const tail = text.slice(resultMember.index + resultMember[0].length);
                const valuePattern = /"(?:\\.|[^"\\])*"/g;
                let value;
                while ((value = valuePattern.exec(tail))) {
                  const after = tail.slice(value.index + value[0].length);
                  if (/^\s*:/.test(after)) continue;
                  const content = value[0].slice(1, -1);
                  for (let i = 0; i < content.length; i += 1) {
                    if (content[i] === '\\') {
                      i += content[i + 1] === 'u' ? 5 : 1;
                      continue;
                    }
                    if (/[b-z]/.test(content[i])) {
                      valueOffset = resultMember.index + resultMember[0].length + value.index + 1 + i;
                      break;
                    }
                  }
                  if (valueOffset >= 0) break;
                }
              }
              if (valueOffset >= 0) {
                offset = valueOffset;
                target = 'json string value after result member';
              } else {
                offset = 0;
                target = 'body byte 0 (no covered letter found)';
              }
            }
            const before = String.fromCharCode(send[offset]);
            send[offset] ^= 1;
            flipInfo = { offset, before, after: String.fromCharCode(send[offset]), target };
            flipped = true;
          }
          const headers = { ...up.headers, 'content-length': send.length };
          delete headers['transfer-encoding'];
          res.writeHead(up.statusCode ?? 502, headers); res.end(send);
        });
        up.on('error', () => res.destroy());
      });
      outbound.add(req); req.once('close', () => outbound.delete(req));
      req.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('upstream request failed'); });
      req.end(body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      resolve({ url: `http://127.0.0.1:${address.port}`, port: address.port, captures, get flipped() { return flipped; }, get flipInfo() { return flipInfo; }, stop: () => new Promise((done) => { for (const req of outbound) req.destroy(); server.closeAllConnections?.(); server.close(() => done()); }) });
    });
  });
}
