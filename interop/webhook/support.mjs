// Shared helpers for the webhook interop matrix driver: fixtures, Server Card
// documents, throw-away TLS files, clock files and the loopback shadow listener.
// The child, port and subset helpers come from the modern matrix unchanged.
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import net from 'node:net';
import {
  REPO_ROOT,
  allocPort,
  fail,
  killTree,
  makeChild,
  readJson,
  resolveTarget,
  splitLangs,
  stopChild,
  subsetMatches,
  waitClose,
} from '../modern/support.mjs';
export {
  REPO_ROOT,
  allocPort,
  fail,
  killTree,
  makeChild,
  readJson,
  resolveTarget,
  splitLangs,
  stopChild,
  subsetMatches,
  waitClose,
};

// Absolute directory of the webhook driver modules (interop/webhook).
export const SCRIPT_DIR = join(REPO_ROOT, 'interop', 'webhook');

// Load the fixture identities the matrix pins. A missing one is fatal.
export function loadFixtures() {
  const doc = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'keys fixture');
  const keys = Array.isArray(doc.keys) ? doc.keys : [];
  const keysByName = Object.fromEntries(keys.map((key) => [key.name, key]));
  for (const name of ['alice', 'newbie', 'mallory', 'svc']) {
    if (keysByName[name] === undefined) fail(`keys fixture is missing the '${name}' identity`);
    const entry = keysByName[name];
    if (typeof entry.seed_hex !== 'string' || typeof entry.public_key !== 'string' || typeof entry.kid !== 'string') {
      fail(`keys fixture entry '${name}' is missing seed_hex, public_key or kid`);
    }
  }
  return { keys, keysByName };
}

// The Server Card document of contract section 3 for the given fixture names.
export function cardDocument(keysByName, names) {
  const jwks = names.map((name) => {
    const entry = keysByName[name];
    return { kty: 'OKP', crv: 'Ed25519', x: entry.public_key, kid: entry.kid, use: 'sig', alg: 'EdDSA' };
  });
  return JSON.stringify({
    remotes: [
      {
        url: 'https://mcp.example.test/mcp',
        extensionsInfo: {
          'io.modelcontextprotocol/events': {
            webhooks: { signingKeys: { keys: jwks }, egressIpRanges: ['198.51.100.0/24'] },
          },
        },
      },
    ],
  }) + '\n';
}

// Write one decimal clock value.
export function writeClock(path, value) {
  writeFileSync(path, String(value) + '\n');
}

// Write any text file (resolver files, bodies, cards) and return the path.
export function writeText(path, text) {
  writeFileSync(path, text);
  return path;
}

function openssl(cwd, args) {
  const result = spawnSync('openssl', args, { cwd, encoding: 'utf8' });
  if (result.error !== undefined && result.error !== null) {
    fail(`openssl is required for the webhook matrix and could not be started: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = String(result.stderr ?? '').trim().split('\n').pop() ?? '';
    fail(`openssl ${args[0]} failed (exit ${result.status}): ${detail}`);
  }
}

const LEAF_EXTENSIONS = [
  'basicConstraints=critical,CA:FALSE',
  'keyUsage=critical,digitalSignature,keyEncipherment',
  'extendedKeyUsage=serverAuth',
  'subjectAltName=DNS:hooks.example.test',
  '',
].join('\n');

// Mint a throw-away CA and a leaf for hooks.example.test; no key is committed.
export function ensureTlsFiles(dir) {
  const caPem = join(dir, 'ca.pem');
  const caKey = join(dir, 'ca-key.pem');
  const caDer = join(dir, 'ca.der');
  const leafKey = join(dir, 'leaf-key.pem');
  const leafCsr = join(dir, 'leaf.csr');
  const leafPem = join(dir, 'leaf.pem');
  const extensions = writeText(join(dir, 'leaf.ext'), LEAF_EXTENSIONS);
  openssl(dir, [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', caKey, '-out', caPem, '-days', '2',
    '-subj', '/CN=mcp-jack interop webhook CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', leafKey, '-out', leafCsr, '-subj', '/CN=hooks.example.test']);
  openssl(dir, [
    'x509', '-req', '-in', leafCsr, '-CA', caPem, '-CAkey', caKey,
    '-CAcreateserial', '-out', leafPem, '-days', '2', '-extfile', extensions,
  ]);
  openssl(dir, ['x509', '-in', caPem, '-outform', 'der', '-out', caDer]);
  return { caPem, caDer, certPem: leafPem, keyPem: leafKey };
}

// Every value of a header name in a received [[name, value], ...] list.
export function headerValues(headers, name) {
  const lower = String(name).toLowerCase();
  const out = [];
  for (const pair of Array.isArray(headers) ? headers : []) {
    if (Array.isArray(pair) && String(pair[0]).toLowerCase() === lower) out.push(String(pair[1]));
  }
  return out;
}

// A TCP listener that accepts and immediately closes: the peer a rebinding
// dialer reaches, so the refusal must come from the policy, not from ECONNREFUSED.
export async function startShadowListener(port) {
  const sockets = new Set();
  let accepted = 0;
  let received = 0;
  const server = net.createServer((socket) => {
    accepted += 1;
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('data', (chunk) => { received += chunk.length; });
    socket.on('close', () => sockets.delete(socket));
    // Hold the socket briefly so a TLS or request byte a dialer writes is counted.
    setTimeout(() => socket.destroy(), 300);
  });
  await new Promise((resolve, reject) => {
    server.once('error', (error) => {
      reject(new Error(`cannot bind the loopback alias 127.0.0.2:${port} (the rebinding scenario needs Linux): ${error.message}`));
    });
    server.listen(port, '127.0.0.2', resolve);
  });
  return {
    connections: () => accepted,
    bytes: () => received,
    close: () => new Promise((resolve) => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      server.close(() => resolve());
    }),
  };
}
