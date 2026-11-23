// Shared helpers for the modern (MCP 2026-07-28) interop matrix driver.
// Dependency-free Node >= 20 tooling: node: builtins only, named exports only.
import { spawn } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

// Absolute directory of this module and the repository root two levels above
// it, so fixtures and target paths resolve the same way from any cwd.
export const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

// Fail the harness loudly: one line on stderr, then exit with the given code.
export function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

// Read and parse a JSON file, failing with the file role and path so a broken
// fixture never looks like a scenario mismatch.
export function readJson(path, what) {
  if (!existsSync(path)) fail(`missing ${what}: ${path}`);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fail(`invalid JSON in ${what} (${path}): ${e.message}`);
  }
}

// Turn a comma-separated language flag into a list: null means "all", and an
// unknown name is a usage error rather than a silently skipped pair.
export function splitLangs(value, all, flag) {
  if (value === null) return [...all];
  const parts = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const p of parts) {
    if (!all.includes(p)) fail(`unknown language '${p}' for ${flag} (known: ${all.join(', ')})`);
  }
  return parts;
}

// Recursive subset match: expected members must occur in actual with matching
// values. Arrays here are compared element-wise by length, unlike the request
// harness where arrays are exact, because the modern expectations pin the
// order and count of steps and tool lists.
export function subsetMatches(expected, actual) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) return false;
    return expected.every((item, i) => subsetMatches(item, actual[i]));
  }
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    return Object.keys(expected).every((k) => k in actual && subsetMatches(expected[k], actual[k]));
  }
  return expected === actual;
}

const KID_PLACEHOLDER = /^\$kid:([A-Za-z0-9_-]+)$/;
const PUBLIC_KEY_PLACEHOLDER = /^\$public_key:([A-Za-z0-9_-]+)$/;

// Resolve `$kid:<name>` and `$public_key:<name>` against the fixture map; an
// unknown name throws so the caller can turn it into an expected-file failure.
function resolveString(value, keysByName) {
  const lookup = (field, name) => {
    const entry = keysByName[name];
    if (!entry) throw new Error(`unknown fixture key '${name}' in placeholder '${value}'`);
    return entry[field];
  };
  const kid = KID_PLACEHOLDER.exec(value);
  if (kid) return lookup('kid', kid[1]);
  const publicKey = PUBLIC_KEY_PLACEHOLDER.exec(value);
  if (publicKey) return lookup('public_key', publicKey[1]);
  return value;
}

// Recursively replace fixture placeholders in an expectation document; returns
// new arrays and objects so the loaded scenario table stays untouched.
export function resolvePlaceholders(value, keysByName) {
  if (typeof value === 'string') return resolveString(value, keysByName);
  if (Array.isArray(value)) return value.map((item) => resolvePlaceholders(item, keysByName));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolvePlaceholders(v, keysByName);
    return out;
  }
  return value;
}

// Load the key and registry fixtures; the harness always needs the client
// identity alice and the server identity svc, so a missing one is fatal.
export function loadFixtures() {
  const keysDoc = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'keys fixture');
  const keys = Array.isArray(keysDoc.keys) ? keysDoc.keys : [];
  const keysByName = Object.fromEntries(keys.map((k) => [k.name, k]));
  for (const name of ['alice', 'svc']) {
    if (!keysByName[name]) fail(`keys fixture is missing the '${name}' identity`);
  }
  const registry = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'registry.json'), 'registry fixture');
  return { keys, keysByName, registry };
}

// Render the strict server state document: the fixture registry without its
// top-level aud member, which is exactly what interop-server reads.
export function registryStateDoc(registry) {
  return JSON.stringify({ version: 1, keys: registry.keys, invites: [] }, null, 2) + '\n';
}

// Canonical unpadded base64url of a byte sequence.
export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

// Unpadded base64url of the SHA-256 digest, the form used in signing strings.
export const sha256b64u = (bytes) => createHash('sha256').update(bytes).digest('base64url');

// Build an Ed25519 public KeyObject from the 32 raw key bytes by prefixing the
// fixed SPKI DER header; node:crypto exposes no raw-bytes constructor.
export function publicKeyFromB64u(b64uText) {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(b64uText, 'base64url')]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

// Independently verify a response Jack-Auth value (spec 01 section 5) so the
// driver never trusts a client's own verdict; `present:false` covers the
// unsigned-allowed 401 family, whose ok stays false.
export function verifyResponse(pinnedPublicKeyB64u, responseAuth, status, requestSig, bodyBytes) {
  const raw = typeof responseAuth === 'string' ? responseAuth.trim() : '';
  if (raw === '') return { present: false, kid: null, ok: false, code: null };
  const m = /^v1\s+kid=([^,]+),ts=([^,]+),sig=([^,]+)$/.exec(raw);
  if (!m) return { present: true, kid: null, ok: false, code: 'malformed_auth' };
  const [, kid, ts, sig] = m;
  const signing = ['mcp-jack/v1/response', String(status), String(requestSig ?? ''), kid, ts, sha256b64u(bodyBytes)].join('\n');
  let ok = false;
  try {
    ok = verify(null, Buffer.from(signing, 'utf8'), publicKeyFromB64u(pinnedPublicKeyB64u), Buffer.from(sig, 'base64url'));
  } catch {
    ok = false;
  }
  return { present: true, kid, ok, code: ok ? null : 'bad_signature' };
}

// Parse a JSON-RPC response body; anything unparsable or non-object yields all
// nulls so the driver can compare the client's view against its own parse.
export function parseJsonBody(bytes) {
  let json;
  try {
    json = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    return { json: null, result: null, error: null, id: null };
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    return { json: null, result: null, error: null, id: null };
  }
  return { json, result: json.result ?? null, error: json.error ?? null, id: json.id ?? null };
}

// Split the tools/call echo text into header instances. A value may itself
// contain ': ', so the split happens at the first one; a malformed non-empty
// line means the echo cannot be trusted and yields null.
export function parseHeaderEcho(text) {
  if (typeof text !== 'string') return null;
  const out = [];
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const m = /^([^:\r\n]+): (.*)$/.exec(line);
    if (!m) return null;
    out.push({ name: m[1], value: m[2] });
  }
  return out;
}

// Evaluate a header_echo expectation over `[[name, value], ...]`; names compare
// case-insensitively, values exactly. Returns null when satisfied, else a short
// reason the driver prints with the failing scenario.
export function headerPredicate(headers, spec) {
  const list = Array.isArray(headers) ? headers : [];
  const lower = (s) => String(s).toLowerCase();
  for (const entry of spec?.contains ?? []) {
    const cut = entry.indexOf(': ');
    if (cut === -1) return `malformed header expectation '${entry}' (expected 'Name: value')`;
    const name = lower(entry.slice(0, cut));
    const value = entry.slice(cut + 2);
    if (!list.some(([n, v]) => lower(n) === name && v === value)) return `missing header '${entry}'`;
  }
  for (const name of spec?.absent ?? []) {
    if (list.some(([n]) => lower(n) === lower(name))) return `unexpected header '${name}'`;
  }
  for (const [name, count] of Object.entries(spec?.counts ?? {})) {
    const actual = list.filter(([n]) => lower(n) === lower(name)).length;
    if (actual !== count) return `header '${name}' occurs ${actual} times, expected ${count}`;
  }
  return null;
}

// ---- child process helpers ---------------------------------------------------

// Spawn a target executable with piped stdio and a rolling stderr tail; the
// stdout line queue lets startup handshakes wait for one ready line at a time.
export function makeChild(cmd, args, env = {}) {
  const child = spawn(cmd, args, {
    cwd: REPO_ROOT,
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let stderr = '';
  let stdout = '';
  let pending = '';
  const lineQueue = [];
  const waiters = [];
  child.stdout.on('data', (d) => {
    stdout += d;
    pending += d;
    let idx;
    while ((idx = pending.indexOf('\n')) !== -1) {
      const line = pending.slice(0, idx);
      pending = pending.slice(idx + 1);
      if (line.trim() === '') continue;
      const w = waiters.shift();
      if (w) w.resolve(line);
      else lineQueue.push(line);
    }
  });
  // Keep only the tail: startup failures are diagnosed from the last lines.
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-4000); });
  child._stderrTail = () => stderr;
  child._stdoutText = () => stdout;
  // Resolve the next complete non-empty stdout line, killing the child on
  // timeout so a hung target cannot stall the matrix.
  child._nextLine = (timeoutMs, label) => new Promise((res, rej) => {
    if (lineQueue.length > 0) return res(lineQueue.shift());
    const w = {
      resolve: (line) => { clearTimeout(timer); res(line); },
      reject: (err) => { clearTimeout(timer); rej(err); },
    };
    const timer = setTimeout(() => {
      const i = waiters.indexOf(w);
      if (i !== -1) waiters.splice(i, 1);
      killTree(child);
      rej(new Error(`${label}: timeout after ${timeoutMs}ms waiting for stdout line\nstderr tail:\n${stderr}`));
    }, timeoutMs);
    waiters.push(w);
  });
  child.on('close', () => {
    while (waiters.length > 0) {
      waiters.shift().reject(new Error(`child closed before producing the expected stdout line\nstderr tail:\n${stderr}`));
    }
  });
  child._closeOutcome = new Promise((r) => child.once('close', (code, signal) => r({ code, signal })));
  return child;
}

// Best-effort termination; an already exited child is left alone.
export function killTree(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.kill(); } catch { /* best effort */ }
}

// Wait for the child to close, killing it and rejecting on timeout so a
// wedged target fails the pair instead of hanging the run.
export function waitClose(child, timeoutMs, label) {
  return new Promise((res, rej) => {
    const timer = setTimeout(() => { killTree(child); rej(new Error(`${label}: timeout after ${timeoutMs}ms`)); }, timeoutMs);
    child.on('close', (code) => { clearTimeout(timer); res(code); });
    child.on('error', (e) => { clearTimeout(timer); rej(e); });
  });
}

// Stop a server politely via stdin EOF, then force it down if it does not exit
// within two seconds.
export async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.stdin.end(); } catch { /* best effort */ }
  const timeout = new Promise((r) => setTimeout(r, 2000));
  await Promise.race([child._closeOutcome, timeout]);
  killTree(child);
}

// Reserve an ephemeral loopback port the target can then bind exactly.
export function allocPort() {
  return new Promise((res, rej) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => res(port));
    });
    srv.on('error', rej);
  });
}

// Resolve a target argv like interop/rotation.mjs: bare commands from PATH,
// relative paths from the repo root, with .exe tolerance on Windows.
export function resolveTarget(argv, role, label) {
  for (const arg of argv.slice(1)) {
    if (!arg.includes('/') && !arg.includes('\\')) continue;
    let p = resolve(REPO_ROOT, arg);
    if (!existsSync(p) && process.platform === 'win32' && existsSync(p + '.exe')) p = p + '.exe';
    if (!existsSync(p)) fail(`target binary not found for ${label} role ${role}: ${p}`);
  }
  const cmd = argv[0];
  if (!cmd.includes('/') && !cmd.includes('\\') && !(process.platform === 'win32' && /^[a-zA-Z]:/.test(cmd))) {
    if (argv.length === 1) {
      const found = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':')
        .map((d) => join(d, cmd)).find((p) => existsSync(p) || (process.platform === 'win32' && existsSync(p + '.exe')));
      if (!found) fail(`target binary not found for ${label} role ${role}: ${cmd}`);
      return { cmd: process.platform === 'win32' && !existsSync(found) ? found + '.exe' : found, args: [], display: cmd };
    }
    return { cmd, args: argv.slice(1), display: cmd };
  }
  const abs = resolve(REPO_ROOT, cmd);
  let exe = abs;
  if (!existsSync(exe) && process.platform === 'win32' && !exe.toLowerCase().endsWith('.exe')) {
    if (existsSync(exe + '.exe')) exe = exe + '.exe';
  }
  if (!existsSync(exe)) fail(`target binary not found for ${label} role ${role}: ${exe}`);
  return { cmd: exe, args: argv.slice(1), display: exe };
}

// Extract the `sig` parameter from a request Jack-Auth value; null when the
// value does not parse. Used only for the driver's own diagnostics.
export function requestSignature(jackAuthHeader) {
  if (typeof jackAuthHeader !== 'string') return null;
  const value = jackAuthHeader.trim();
  const sp = value.indexOf(' ');
  if (sp < 0 || value.slice(0, sp) !== 'v1') return null;
  for (const part of value.slice(sp + 1).split(',')) {
    const m = /^sig=([A-Za-z0-9_-]+)$/.exec(part);
    if (m) return m[1];
  }
  return null;
}
