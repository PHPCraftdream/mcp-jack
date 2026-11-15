// Driver-owned fake rotation peer for negative controls in the rotation
// interop matrix. NOT an SDK and NOT a reference implementation: like
// fake-server.mjs it performs NO request verification, it only serves
// canned, correctly signed responses driven by a mode file. Usage:
//   node rotation-fake.mjs --port <n> --clock-file <f> --mode-file <f>
//     --aud <aud> --url <u> --k0-seed-hex <hex> --k1-seed-hex <hex>
//     --k1-kid <kid> --p <publishedAt>
import http from 'node:http';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256b64u = (b) => b64u(createHash('sha256').update(b).digest());

// Derive the Ed25519 keypair from a 32-byte seed exactly like fake-server.mjs.
function deriveKeys(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = spki.subarray(spki.length - 32);
  return { priv, pubB64u: b64u(pub), kid: b64u(createHash('sha256').update(pub).digest()) };
}

function parseArgs(argv) {
  const out = {};
  const hasValue = (j) => j < argv.length && !argv[j].startsWith('--');
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    if (hasValue(i + 1)) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}

// Loose jack_auth grammar check, copied from fake-server.mjs.
function parseAuth(header) {
  if (typeof header !== 'string') return null;
  const m = /^v1\s+kid=([^,]+),ts=([^,]+),nonce=([^,]+),sig=([^,]+)$/.exec(header.trim());
  if (!m || !/^\d+$/.test(m[2])) return null;
  return { kid: m[1], ts: m[2], nonce: m[3], sig: m[4] };
}

// Sign the exact response body bytes with the given key at the injected ts.
function respond(res, status, reqSig, kid, priv, bodyBuf, ts) {
  const signing = ['mcp-jack/v1/response', String(status), reqSig, kid, String(ts), sha256b64u(bodyBuf)].join('\n');
  const sig = b64u(sign(null, Buffer.from(signing, 'utf8'), priv));
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Jack-Auth': `v1 kid=${kid},ts=${ts},sig=${sig}`,
  });
  res.end(bodyBuf);
}

// Canonical min1 record codec: exactly 12 LF-joined ASCII lines with no
// key= prefixes — line 1 is the domain, lines 2-3 are base64url of the raw
// UTF-8 url/aud bytes, 4-5 ordinal/prev, 6-8 kid/key lines, 9-10 plain
// decimal times; then the proof line and the old-key authorization line.
function buildRecord(b) {
  const proof = b64u(sign(null, Buffer.from(b.domain + '/next-proof\n' + b.body, 'utf8'), b.k1.priv));
  const authz = b64u(sign(null, Buffer.from(b.domain + '/authorize\n' + b.body + '\n' + proof, 'utf8'), b.k0.priv));
  return { record: b.body + '\n' + proof + '\n' + authz, proof };
}

// Flip exactly the first character of line 8 (index 7), the raw base64url
// new_public_key line (no prefix), so the codec still parses but the
// proof/kid binding checks fail.
function tamperRecord(r1) {
  const lines = r1.split('\n');
  const rep = lines[7].charAt(0) === 'A' ? 'B' : 'A';
  lines[7] = rep + lines[7].slice(1);
  return lines.join('\n');
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  for (const f of ['port', 'clock-file', 'mode-file', 'aud', 'url', 'k0-seed-hex', 'k1-seed-hex', 'p']) {
    if (!a[f]) {
      process.stderr.write(`missing required --${f}\n`);
      return process.exit(1);
    }
  }
  const k0 = deriveKeys(a['k0-seed-hex']);
  const k1 = deriveKeys(a['k1-seed-hex']);
  const p = parseInt(a.p, 10);
  const DOMAIN = 'mcp-jack/server-key-rotation/min1';
  const body = [
    DOMAIN,
    b64u(Buffer.from(a.url, 'utf8')),
    b64u(Buffer.from(a.aud, 'utf8')),
    '1',
    '-',
    k0.kid,
    a['k1-kid'] ?? k1.kid,
    k1.pubB64u,
    String(p),
    String(p + 172800),
  ].join('\n');
  const built = buildRecord({ body, k0, k1, domain: DOMAIN });
  const r1 = built.record;
  const r1Hash = sha256b64u(Buffer.from(r1, 'utf8'));
  const r1Tampered = tamperRecord(r1);

  const pageFor = (record) => ({
    current: { kid: k0.kid, public_key: k0.pubB64u },
    records: [record],
    head: { ordinal: 1, hash: r1Hash },
    complete: true,
  });

  const readMode = () => (existsSync(a['mode-file']) ? readFileSync(a['mode-file'], 'utf8').trim() : '');
  const readClock = () => {
    try { return parseInt(readFileSync(a['clock-file'], 'utf8').trim(), 10); } catch { return 0; }
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const mode = readMode();
      const ts = readClock();
      let rpc = null;
      try { rpc = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* best effort */ }
      const reqSig = parseAuth(req.headers['jack-auth'])?.sig ?? '';
      if (mode === 'page' || mode === 'page-tamper') {
        const page = pageFor(mode === 'page-tamper' ? r1Tampered : r1);
        const bodyBuf = Buffer.from(JSON.stringify({
          jsonrpc: '2.0', id: rpc?.id ?? null,
          result: { content: [{ type: 'text', text: JSON.stringify(page) }], structuredContent: page, isError: false },
        }), 'utf8');
        return respond(res, 200, reqSig, k0.kid, k0.priv, bodyBuf, ts);
      }
      if (mode === 'old-key') {
        // Signed by the OLD key: after the cutoff A this is an old-key
        // response the client must refuse.
        const payload = rpc?.method === 'ping'
          ? { jsonrpc: '2.0', id: rpc.id ?? null, result: {} }
          : { jsonrpc: '2.0', id: rpc?.id ?? null, error: { code: -32601, message: 'method not found' } };
        return respond(res, 200, reqSig, k0.kid, k0.priv, Buffer.from(JSON.stringify(payload), 'utf8'), ts);
      }
      // Unknown/missing mode: never expected in the matrix.
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end('{"error":"rotation-fake: unknown or missing mode"}');
    });
  });
  server.listen(parseInt(a.port, 10), '127.0.0.1', () => {
    const ready = JSON.stringify({ ready: true, port: server.address().port, server_public_key: k0.pubB64u, server_kid: k0.kid });
    process.stdout.write(ready + '\n');
  });
  const stop = () => process.exit(0);
  process.on('SIGTERM', stop);
  process.stdin.on('end', stop);
  process.stdin.on('close', stop);
  process.stdin.resume();
}

main();
