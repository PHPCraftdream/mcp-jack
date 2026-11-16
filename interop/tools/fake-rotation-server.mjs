// Self-test only. Minimal stand-in for an SDK interop rotation server;
// exercises the rotation-server harness contract but is NOT a reference
// implementation. It serves NO HTTP; it only binds the requested port, prints
// the ready line and answers announce control lines from stdin. Usage:
//   node fake-rotation-server.mjs --aud <aud> --url <u> --state <f>
//     --server-seed-hex <hex> --rotation-store <f> --clock-file <f> [--port <n>]
//     [--ring-seed <ref>=<hex>]...   (ring seeds are accepted, never used)
import net from 'node:net';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
// head_hash is opaque to the driver; it only must match the fake client's
// refresh head_hash (interop/tools/fake-rotation-client.mjs).
const HEAD43 = 'a'.repeat(43);

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
    if (key === 'ring-seed') {
      if (hasValue(i + 1)) { (out['ring-seed'] ??= []).push(argv[++i]); }
      continue;
    }
    if (hasValue(i + 1)) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}

function readClockInt(path) {
  const t = parseInt(readFileSync(path, 'utf8').trim(), 10);
  if (!Number.isInteger(t)) throw new Error(`clock file ${path} does not hold an integer`);
  return t;
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  for (const f of ['aud', 'url', 'state', 'server-seed-hex', 'rotation-store', 'clock-file']) {
    if (!a[f]) {
      process.stderr.write(`missing required --${f}\n`);
      return process.exit(1);
    }
  }
  const { pubB64u, kid } = deriveKeys(a['server-seed-hex']);
  // G9 r3 contract: a latched store never becomes ready (fail-closed startup).
  const modeEnv = process.env.JACK_ROTATION_MODE_FILE;
  if (modeEnv && existsSync(modeEnv) && readFileSync(modeEnv, 'utf8').trim() === 'clock-latched') {
    process.stderr.write('rotation store: rotation_clock_unsafe (latched)\n');
    return process.exit(1);
  }
  const server = net.createServer(() => { /* contract fake: no HTTP protocol */ });
  const wantPort = a.port ? parseInt(a.port, 10) : 0;
  server.listen(wantPort, '127.0.0.1', () => {
    const ready = JSON.stringify({ ready: true, port: server.address().port, server_public_key: pubB64u, server_kid: kid });
    process.stdout.write(ready + '\n');
  });
  let buf = '';
  process.stdin.on('data', (d) => {
    buf += d;
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (line.trim() === '') continue;
      let ctl;
      try { ctl = JSON.parse(line); } catch { continue; }
      if (ctl?.op !== 'announce') continue;
      const p = readClockInt(a['clock-file']);
      // Deviation hook for the driver self-test: a wrong activation offset.
      const activatesAt = process.env.JACK_ROTATION_DEVIATE === 'announce' ? p + 100 : p + 172800;
      const headHash = HEAD43;
      process.stdout.write(JSON.stringify({
        announced: true, ordinal: 1, head_ordinal: 1, head_hash: headHash,
        published_at: p, activates_at: activatesAt, revision: 1,
      }) + '\n');
    }
  });
  const stop = () => process.exit(0);
  process.stdin.on('end', stop);
  process.stdin.on('close', stop);
  process.stdin.resume();
}

main();
