// Self-test only. Minimal stand-in for an SDK interop-server; exercises the
// harness contract but is NOT a reference implementation and never verifies
// request signatures in normal mode. Usage:
//   node fake-server.mjs --aud <aud> --policy <f> --state <f> --server-seed-hex <hex> [--bootstrap-ttl <s>] [--verify-only]
import http from 'node:http';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256b64u = (b) => b64u(createHash('sha256').update(b).digest());

// Derive the Ed25519 keypair from a 32-byte seed exactly like gen-fixtures.
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
    else out[key] = true; // valueless flags (--verify-only)
  }
  return out;
}

// Loose jack_auth grammar check: scheme v1 with kid/ts/nonce/sig params.
function parseAuth(header) {
  if (typeof header !== 'string') return null;
  const m = /^v1\s+kid=([^,]+),ts=([^,]+),nonce=([^,]+),sig=([^,]+)$/.exec(header.trim());
  if (!m || !/^\d+$/.test(m[2])) return null;
  return { kid: m[1], ts: m[2], nonce: m[3], sig: m[4] };
}

function respond(res, status, reqSig, kid, priv, bodyBuf) {
  const ts = Math.floor(Date.now() / 1000);
  const signing = ['mcp-jack/v1/response', String(status), reqSig, kid, String(ts), sha256b64u(bodyBuf)].join('\n');
  const sig = b64u(sign(null, Buffer.from(signing, 'utf8'), priv));
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Jack-Auth': `v1 kid=${kid},ts=${ts},sig=${sig}`,
  });
  res.end(bodyBuf);
}

function verifyOnly(a) {
  const req = JSON.parse(readFileSync(0, 'utf8').trim());
  const auth = parseAuth(req.jack_auth);
  if (!auth) {
    process.stdout.write(JSON.stringify({ verify: 'reject', code: 'malformed_auth' }) + '\n');
    return process.exit(0);
  }
  const state = JSON.parse(readFileSync(a.state, 'utf8'));
  const key = (state.keys || []).find((k) => k.kid === auth.kid);
  if (!key) {
    process.stdout.write(JSON.stringify({ verify: 'reject', code: 'unknown_key' }) + '\n');
    return process.exit(0);
  }
  const body = Buffer.from(req.body_b64u, 'base64url');
  const signing = ['mcp-jack/v1/request', req.method, req.target, a.aud, auth.kid, auth.ts, auth.nonce, sha256b64u(body)].join('\n');
  const spkiDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key.public_key, 'base64url')]);
  const ok = verify(null, Buffer.from(signing, 'utf8'), { key: createPublicKey({ key: spkiDer, format: 'der', type: 'spki' }) }, Buffer.from(auth.sig, 'base64url'));
  process.stdout.write(JSON.stringify(ok ? { verify: 'accept', kid: auth.kid } : { verify: 'reject', code: 'bad_signature' }) + '\n');
  // Self-test control: a nonzero exit must fail the verify phase even when the
  // verdict line itself is correct.
  if (process.env.JACK_SELFTEST_VERIFY_EXIT2) return process.exit(2);
  process.exit(0);
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  if (a['bootstrap-ttl']) process.stderr.write(JSON.stringify({ bootstrap_invite: 'fake-invite-code' }) + '\n');
  if (a['verify-only']) return verifyOnly(a);
  const { priv, pubB64u, kid } = deriveKeys(a['server-seed-hex']);
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const reqSig = parseAuth(req.headers['jack-auth'])?.sig ?? '';
      if (req.method === 'POST') {
        let rpc;
        try {
          rpc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          rpc = null;
        }
        // svc.config.set is always denied with 403; JACK_UNSIGNED_403 only
        // controls whether the denial is signed, exercising the client rule
        // that only auth-failure answers may go unsigned.
        if (rpc && rpc.method === 'tools/call' && rpc.params?.name === 'svc.config.set') {
          const body = Buffer.from(JSON.stringify({ error: { code: 'insufficient_scope', message: 'policy denies svc.config.set' } }), 'utf8');
          if (process.env.JACK_UNSIGNED_403) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            return res.end(body);
          }
          return respond(res, 403, reqSig, kid, priv, body);
        }
        // jack.whoami: answer from the actual --state file, keyed by the
        // request's Jack-Auth kid, so the client's outcome depends on server state.
        if (rpc && rpc.method === 'tools/call' && rpc.params?.name === 'jack.whoami') {
          const authKid = parseAuth(req.headers['jack-auth'])?.kid ?? null;
          let entry = null;
          try {
            const state = JSON.parse(readFileSync(a.state, 'utf8'));
            entry = (state.keys || []).find((k) => k.kid === authKid) ?? null;
          } catch {
            entry = null;
          }
          const body = Buffer.from(JSON.stringify({
            jsonrpc: '2.0', id: rpc.id ?? null,
            result: { structuredContent: { kid: entry?.kid ?? null, name: entry?.name ?? null, not_before: entry?.not_before ?? null, not_after: entry?.not_after ?? null } },
          }), 'utf8');
          return respond(res, 200, reqSig, kid, priv, body);
        }
        let body;
        if (!rpc) {
          body = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } };
        } else if (rpc.method === 'ping') {
          body = { jsonrpc: '2.0', id: rpc.id ?? null, result: {} };
        } else {
          body = { jsonrpc: '2.0', id: rpc.id ?? null, error: { code: -32601, message: 'method not found' } };
        }
        return respond(res, 200, reqSig, kid, priv, Buffer.from(JSON.stringify(body), 'utf8'));
      }
      if (req.method === 'GET' && req.url === '/sse') {
        return respond(res, 501, reqSig, kid, priv, Buffer.from(JSON.stringify({ error: { code: 'streaming_unsupported', message: 'not supported' } }), 'utf8'));
      }
      return respond(res, 200, reqSig, kid, priv, Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: null, result: {} }), 'utf8'));
    });
  });
  server.listen(0, '127.0.0.1', () => {
    const ready = JSON.stringify({ ready: true, port: server.address().port, server_public_key: pubB64u, server_kid: kid });
    if (process.env.JACK_READY_MODE === 'split') {
      // Write the ready line in two chunks split at the first ',' so the
      // harness parser must buffer until a complete newline-terminated line.
      const i = ready.indexOf(',');
      process.stdout.write(ready.slice(0, i));
      setTimeout(() => process.stdout.write(ready.slice(i) + '\n'), 50);
    } else if (process.env.JACK_READY_MODE === 'blank') {
      process.stdout.write('\n');
      process.stdout.write(ready + '\n');
    } else {
      process.stdout.write(ready + '\n');
    }
  });
  const stop = () => process.exit(0);
  process.on('SIGTERM', stop);
  process.stdin.on('end', stop);
  process.stdin.on('close', stop);
  process.stdin.resume();
}

main();
