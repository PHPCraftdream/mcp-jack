// Self-test only. Minimal stand-in for an SDK interop-client; NOT a reference
// implementation. Usage:
//   node fake-client.mjs --url <u> --seed-hex <hex> --server-public-key <b64u>
//     --aud <aud> --scenario <name> [--seeds <f>] [--ts <n>] [--nonce <b64u>] [--arg k=v]...
import { spawn } from 'node:child_process';
import http from 'node:http';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256b64u = (b) => b64u(createHash('sha256').update(b).digest());

function deriveKeys(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = spki.subarray(spki.length - 32);
  return { priv, kid: b64u(createHash('sha256').update(pub).digest()) };
}

function parseArgs(argv) {
  const out = { args: {} };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    if (f === '--arg') {
      const [k, ...rest] = (argv[++i] ?? '').split('=');
      out.args[k] = rest.join('=');
    } else if (f.startsWith('--')) {
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) out[f.slice(2)] = argv[++i];
      else out[f.slice(2)] = true;
    }
  }
  return out;
}

// spec/01-authentication.md section 3.1 request signing string + header.
function requestAuth(priv, kid, aud, method, target, ts, nonce, body) {
  const signing = ['mcp-jack/v1/request', method, target, aud, kid, String(ts), nonce, sha256b64u(body)].join('\n');
  const sig = b64u(sign(null, Buffer.from(signing, 'utf8'), priv));
  return { signing, header: `v1 kid=${kid},ts=${ts},nonce=${nonce},sig=${sig}`, sig };
}

// spec/01-authentication.md section 5 response verification.
function verifyResponse(serverPubB64u, resAuth, status, reqSig, body) {
  const m = /^v1\s+kid=([^,]+),ts=([^,]+),sig=([^,]+)$/.exec((resAuth || '').trim());
  // Spec 01 section 5, table row 1: an absent response header is missing_auth
  // (malformed_auth is reserved for present-but-invalid headers).
  if (!resAuth) return 'missing_auth';
  if (!m) return 'malformed_auth';
  const [, kid, ts, sig] = m;
  const signing = ['mcp-jack/v1/response', String(status), reqSig, kid, ts, sha256b64u(body)].join('\n');
  const spkiDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(serverPubB64u, 'base64url')]);
  const ok = verify(null, Buffer.from(signing, 'utf8'), { key: createPublicKey({ key: spkiDer, format: 'der', type: 'spki' }) }, Buffer.from(sig, 'base64url'));
  return ok ? null : 'bad_signature';
}

function emit(scenario, outcome, httpStatus, code, data, exitCode = 0) {
  process.stdout.write(JSON.stringify({ scenario, outcome, http_status: httpStatus, code, data }) + '\n');
  process.exit(exitCode);
}

// Generic signed tools/call round trip. Spec 01 section 5: only answers to
// requests that FAILED authentication may go unsigned, so any statusCode other
// than 401 must carry a verifiable Jack-Auth signature.
function signedCall(scenario, a, priv, kid, tool, args, onReply) {
  const payload = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: args ? { name: tool, arguments: args } : { name: tool } };
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const ts = Math.floor(Date.now() / 1000);
  const nonce = b64u(randomBytes(16));
  const { header, sig } = requestAuth(priv, kid, a.aud, 'POST', '/mcp', ts, nonce, body);
  const req = http.request(a.url.replace(/\/$/, '') + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Jack-Auth': header } }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => {
      const raw = Buffer.concat(chunks);
      if (res.statusCode !== 401) {
        const err = verifyResponse(a['server-public-key'], res.headers['jack-auth'], res.statusCode, sig, raw);
        if (err) return emit(scenario, 'client_error', null, err, null);
      }
      let parsed = null;
      try { parsed = JSON.parse(raw.toString('utf8')); } catch { /* tolerate non-JSON bodies */ }
      onReply(res.statusCode, parsed);
    });
  });
  req.on('error', () => { process.stderr.write('fake client: cannot connect\n'); process.exit(1); });
  req.end(body);
}

function ping(a, priv, kid) {
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }), 'utf8');
  const ts = Math.floor(Date.now() / 1000);
  const nonce = b64u(randomBytes(16));
  const { header, sig } = requestAuth(priv, kid, a.aud, 'POST', '/mcp', ts, nonce, body);
  const req = http.request(a.url.replace(/\/$/, '') + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Jack-Auth': header } }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => {
      const err = verifyResponse(a['server-public-key'], res.headers['jack-auth'], res.statusCode, sig, Buffer.concat(chunks));
      if (err) return emit('ping', 'client_error', null, err, null);
      emit('ping', 'ok', res.statusCode, null, {});
    });
  });
  req.on('error', () => { process.stderr.write('fake client: cannot connect\n'); process.exit(1); });
  req.end(body);
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  const { priv, kid } = deriveKeys(a['seed-hex']);
  const s = a.scenario;
  if (process.env.JACK_SELFTEST_DEVIATE === s) {
    // Deliberately wrong result so the harness negative control can detect it.
    emit(s, 'rejected', 403, 'operation_denied', null);
  }
  if (process.env.JACK_SELFTEST_EXIT2 === s) {
    // Result WOULD match the harness expectation, but the exit code is 2; the
    // harness must treat any nonzero client exit as a harness-level failure.
    if (s === 'ping') emit(s, 'ok', 200, null, {}, 2);
    else emit(s, 'rejected', 403, null, null, 2);
  }
  if (process.env.JACK_SELFTEST_PIPE_HOLDER === s) {
    // Exit-before-drain control: hold this process's stdout pipe open from a
    // grandchild, exit without writing anything, and let the grandchild emit
    // the canonical ping result ~300ms after this process is gone. The
    // harness must capture on 'close' (drained pipes), not 'exit'.
    const result = JSON.stringify({ scenario: s, outcome: 'ok', http_status: 200, code: null, data: {} });
    const holder = spawn(process.execPath, ['-e', `setTimeout(() => { process.stdout.write(${JSON.stringify(result)} + '\\n'); }, 300);`], { stdio: ['ignore', 'inherit', 'ignore'] });
    holder.unref();
    process.exit(0);
  }
  if (s === 'sign-only') {
    const body = Buffer.from(a.args['body-b64u'], 'base64url');
    const { signing, header } = requestAuth(priv, kid, a.aud, a.args.method, a.args.target, a.ts, a.nonce, body);
    emit('sign-only', 'ok', null, null, { signing_string: signing, jack_auth: header, kid });
  } else if (s === 'ping') {
    ping(a, priv, kid);
  } else if (s === 'denied-tool') {
    signedCall('denied-tool', a, priv, kid, 'svc.config.set', null, (status, parsed) => {
      if (status >= 200 && status < 300) emit('denied-tool', 'ok', status, null, {});
      else emit('denied-tool', 'rejected', status, parsed?.error?.code ?? null, null);
    });
  } else if (s === 'last-admin') {
    emit('last-admin', 'rejected', 409, 'last_admin', null);
  } else if (s === 'key-not-yet-valid') {
    // Outcome depends on the server's state file: with the not_before override
    // applied the key is genuinely not yet valid; without it the whoami
    // answer proves the key IS valid, so we deliberately report the wrong
    // code and the harness comparison must fail.
    signedCall('key-not-yet-valid', a, priv, kid, 'jack.whoami', null, (status, parsed) => {
      const notBefore = parsed?.result?.structuredContent?.not_before;
      if (typeof notBefore === 'number' && notBefore > Math.floor(Date.now() / 1000) + 300) {
        emit('key-not-yet-valid', 'rejected', 401, 'key_inactive', null);
      } else {
        emit('key-not-yet-valid', 'rejected', 401, 'unknown_key', null);
      }
    });
  } else {
    process.stderr.write(`fake client: unsupported scenario ${s}\n`);
    process.exit(1);
  }
}

main();
