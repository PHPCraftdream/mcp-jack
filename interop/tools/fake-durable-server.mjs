// Harness-only fake: mimics the SDK durable executable contract (--durable-dir,
// --durable-init, --durable-window) in plain node so the durable.mjs self-test
// can run the whole matrix without any SDK. NOT a reference implementation.
// Store file <durable-dir>/nonces: {"committed": {"<ts>:<nonce>": true}, "clean": bool}
// The dirty gate is {clean:false}, written at startup BEFORE the ready line and
// rewritten {clean:true} only on a clean stop (stdin EOF / SIGTERM); SIGKILL
// therefore leaves the store dirty and the next start refuses.
// With JACK_FAKE_DEVIATE=forget the server never records a committed nonce, so a
// byte-identical replay after a restart is accepted (a scenario failure, exit 1).
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import http from 'node:http';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');

// Same derivation as fake-server.mjs, for the ready-line identity fields.
function deriveKeys(seedHex) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = spki.subarray(spki.length - 32);
  return { pubB64u: b64u(pub), kid: b64u(createHash('sha256').update(pub).digest()) };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}

function storePath(a) {
  if (!a['durable-dir']) {
    process.stderr.write('fake-durable-server: --durable-dir is required\n');
    process.exit(1);
  }
  return join(a['durable-dir'], 'nonces');
}

const a = parseArgs(process.argv.slice(2));
const path = storePath(a);
const window = Number.isInteger(parseInt(a['durable-window'], 10)) ? parseInt(a['durable-window'], 10) : 30;

if (a['durable-init']) {
  if (existsSync(path)) {
    process.stderr.write('fake-durable-server: store already initialized\n');
    process.exit(1);
  }
  writeFileSync(path, JSON.stringify({ committed: {}, clean: true }));
  process.stdout.write('{"durable_initialized":true}\n');
  process.exit(0);
}

// Serve mode: the store must exist and be clean, or startup is refused with
// no stdout at all (the dirty-epoch fail-closed gate).
if (!existsSync(path)) {
  process.stderr.write('fake-durable-server: store not initialized\n');
  process.exit(1);
}
let committed;
try {
  committed = JSON.parse(readFileSync(path, 'utf8')).committed ?? {};
} catch {
  process.stderr.write('fake-durable-server: store unreadable\n');
  process.exit(1);
}
if (JSON.parse(readFileSync(path, 'utf8')).clean !== true) {
  process.stderr.write('dirty\n');
  process.exit(1);
}
// Durable H advances at open: entries whose retention (ts+W, inclusive) has
// expired are purged before admission. Parsing ts back out of the key keeps
// the store format trivial.
const nowSec = () => Math.floor(Date.now() / 1000);
const now0 = nowSec();
for (const key of Object.keys(committed)) {
  const ts = parseInt(key.split(':')[0], 10);
  if (Number.isInteger(ts) && now0 > ts + window) delete committed[key];
}
// Mark the serving epoch dirty immediately; a clean close rewrites clean:true.
const persist = (clean) => {
  try { writeFileSync(path, JSON.stringify({ committed, clean })); } catch { /* best effort */ }
};
persist(false);

const { pubB64u, kid } = deriveKeys(a['server-seed-hex'] ?? '');
const server = http.createServer((req, res) => {
  const send = (status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(body);
  };
  const m = /^FAKE (\d+) (\S+)/.exec(String(req.headers['jack-auth'] ?? ''));
  if (!m) return send(401, '{"error":{"code":"missing_auth"}}');
  const ts = parseInt(m[1], 10);
  const key = `${ts}:${m[2]}`;
  const now = nowSec();
  if (committed[key]) return send(401, '{"error":{"code":"replayed_nonce"}}');
  // Expired pair: retention lapsed inclusively, allow and re-commit.
  if (process.env.JACK_FAKE_DEVIATE !== 'forget') committed[key] = true;
  send(200, '{"jsonrpc":"2.0","id":null,"result":{}}');
});
server.listen(0, '127.0.0.1', () => {
  const ready = JSON.stringify({ ready: true, port: server.address().port, server_public_key: pubB64u, server_kid: kid });
  process.stdout.write(ready + '\n');
});
const cleanStop = () => { persist(true); process.exit(0); };
process.stdin.on('end', cleanStop);
process.stdin.on('close', cleanStop);
process.on('SIGTERM', cleanStop);
process.stdin.resume();
