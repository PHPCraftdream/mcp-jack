// Dependency-free Node durable-restart interop matrix harness for the
// candidate durable-nonce store contract (spec/candidate/durable-nonces.md).
// Node >= 20, node: builtins only.
//   node interop/durable.mjs [--targets <file>] [--servers <l,l,...>]
//        [--clients <l,l,...>] [--list] [--self-test]
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const b64u = (b) => Buffer.from(b).toString('base64url');
const CHECKS = [
  'durable-restart-replay',
  'durable-crash-fail-closed',
  'durable-expiry-reuse',
];
const CHECK_DOCS = {
  'durable-restart-replay': 'clean stop reopens the store; byte-identical resend is 401 replayed_nonce; fresh nonce is 200',
  'durable-crash-fail-closed': 'after SIGKILL the dirty epoch stays; restart on the same store exits nonzero with no ready line',
  'durable-expiry-reuse': 'with W=2 the same (ts,nonce) pair is reusable only after retention expired under an advanced H; immediate resend is 401',
};
const USAGE = `usage: node interop/durable.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>] [--list] [--self-test]`;

function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

// Only the pair's startup prep is retried on an ephemeral-port race; product
// checks are never retried (same policy as rotation.mjs).
class StartupPortRace extends Error {}

function startupFail(message) {
  if (/EADDRINUSE|address already in use/i.test(message)) throw new StartupPortRace(message);
  fail(message);
}

function parseArgs(argv) {
  const out = { targets: join(SCRIPT_DIR, 'targets.json'), servers: null, clients: null, list: false, selfTest: false };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--targets': out.targets = argv[++i]; break;
      case '--servers': out.servers = argv[++i]; break;
      case '--clients': out.clients = argv[++i]; break;
      case '--list': out.list = true; break;
      case '--self-test': out.selfTest = true; break;
      default: fail(`unknown flag: ${f}\n${USAGE}`);
    }
  }
  return out;
}

function readJson(path, what) {
  if (!existsSync(path)) fail(`missing ${what}: ${path}`);
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch (e) { fail(`invalid JSON in ${what} (${path}): ${e.message}`); }
}

function splitLangs(v, all, flag) {
  if (v === null) return [...all];
  const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
  for (const p of parts) if (!all.includes(p)) fail(`unknown language '${p}' for ${flag} (known: ${all.join(', ')})`);
  return parts;
}

// The durable harness uses the SAME server/client roles as run.mjs; every
// selected language must provide both as non-empty argv arrays.
function validateTargets(targets, langs) {
  for (const lang of langs) {
    const t = targets[lang];
    for (const role of ['server', 'client']) {
      if (!t || !Array.isArray(t[role]) || t[role].length === 0) {
        fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
      }
    }
  }
}

// Resolve a target argv like run.mjs/rotation.mjs: bare commands from PATH,
// relative paths from the repo root, .exe tolerance on Windows.
function resolveTarget(argv, role, label) {
  for (const arg of argv.slice(1)) {
    if (!arg.includes('/') && !arg.includes('\\')) continue;
    let p = resolve(REPO_ROOT, arg);
    if (!existsSync(p) && process.platform === 'win32' && existsSync(p + '.exe')) p = p + '.exe';
    if (!existsSync(p)) fail(`target binary not found for ${label} role ${role}: ${p}`);
  }
  let cmd = argv[0];
  if (!cmd.includes('/') && !cmd.includes('\\') && !(process.platform === 'win32' && /^[a-zA-Z]:/.test(cmd))) {
    if (argv.length === 1) {
      const found = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':')
        .map((d) => join(d, cmd)).find((p) => existsSync(p) || (process.platform === 'win32' && existsSync(p + '.exe')));
      if (!found) fail(`target binary not found for ${label} role ${role}: ${cmd}`);
      cmd = process.platform === 'win32' && !existsSync(found) ? found + '.exe' : found;
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

// ---- child process helpers ---------------------------------------------------

function makeChild(cmd, args, env) {
  const child = spawn(cmd, args, { cwd: REPO_ROOT, env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let stderr = '';
  let stdout = '';
  const lineQueue = [];
  const waiters = [];
  child.stdout.on('data', (d) => {
    stdout += d;
    let buf = child._buf === undefined ? '' : child._buf;
    buf += d;
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (line.trim() === '') continue;
      const w = waiters.shift();
      if (w) w.resolve(line);
      else lineQueue.push(line);
    }
    child._buf = buf;
  });
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-4000); });
  child._stderrTail = () => stderr;
  child._stdoutText = () => stdout;
  // Next complete non-empty stdout line with a timeout; the child is killed
  // on timeout and on early close.
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
      const w = waiters.shift();
      w.reject(new Error(`child closed before producing the expected stdout line\nstderr tail:\n${stderr}`));
    }
  });
  child._closeOutcome = new Promise((r) => child.once('close', (code, signal) => r({ code, signal })));
  return child;
}

function killTree(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.kill(); } catch { /* best effort */ }
}

function waitClose(child, timeoutMs, label) {
  return new Promise((res, rej) => {
    const timer = setTimeout(() => { killTree(child); rej(new Error(`${label}: timeout after ${timeoutMs}ms`)); }, timeoutMs);
    child.on('close', (code) => { clearTimeout(timer); res(code); });
    child.on('error', (e) => { clearTimeout(timer); rej(e); });
  });
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.stdin.end(); } catch { /* best effort */ }
  const timeout = new Promise((r) => setTimeout(r, 2000));
  await Promise.race([child._closeOutcome, timeout]);
  killTree(child);
}

// ---- fixtures -----------------------------------------------------------------

function loadFixtures() {
  const keysList = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'keys fixture').keys;
  const keys = Object.fromEntries(keysList.map((k) => [k.name, k]));
  for (const name of ['svc', 'alice']) {
    if (!keys[name]) fail(`keys fixture is missing the '${name}' identity`);
  }
  const registry = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'registry.json'), 'registry fixture');
  return { keys, registry };
}

// ---- wire helpers ----------------------------------------------------------------

// Raw GET /mcp with exactly the harness-built head; returns the full response.
function sendRaw(port, authHeader) {
  return new Promise((res) => {
    const head = Buffer.from(
      `GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nJack-Auth: ${authHeader}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
      'latin1');
    const chunks = [];
    let settled = false;
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      res({ err, text: Buffer.concat(chunks).toString('utf8') });
    };
    const timer = setTimeout(() => finish('timeout'), 10000);
    const sock = connect({ host: '127.0.0.1', port }, () => { sock.write(head); });
    sock.on('data', (d) => chunks.push(d));
    sock.on('end', () => finish(null));
    sock.on('close', () => finish(null));
    sock.on('error', (e) => finish(e.message));
  });
}

function parseResponse(raw) {
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(raw.text);
  if (!m) return { failed: true, reason: `no HTTP response (${raw.err ?? 'empty'})` };
  const status = parseInt(m[1], 10);
  const bodyStart = raw.text.indexOf('\r\n\r\n');
  const c = bodyStart === -1 ? null : /"code"\s*:\s*"([a-z_]+)"/.exec(raw.text.slice(bodyStart));
  return { failed: false, status, code: status === 200 ? null : (c ? c[1] : null) };
}

// ---- core runner -----------------------------------------------------------------

async function runMatrix(opts) {
  const { clientLangs, serverLangs, targets, keys, registry } = opts;
  const failures = [];
  const allChildren = new Set();
  const tmpRoots = [];
  const registerExitHandlers = () => {
    const killAll = () => { for (const c of allChildren) killTree(c); };
    process.on('exit', killAll);
    process.on('SIGINT', () => { killAll(); process.exit(130); });
    process.on('SIGTERM', () => { killAll(); process.exit(143); });
    process.on('exit', () => {
      for (const t of tmpRoots) { try { rmSync(t, { recursive: true, force: true }); } catch { /* best effort */ } }
    });
  };
  registerExitHandlers();

  const baseArgs = (tmp) => (['--aud', registry.aud, '--state', join(tmp, 'state.json'), '--server-seed-hex', keys.svc.seed_hex]);

  // Run the client in sign-only mode and return the Jack-Auth header value.
  async function runSignOnly(lang, port, ts, nonce, pairLabel) {
    const t = resolveTarget(targets[lang].client, 'client', `client=${lang}`);
    const args = [...t.args,
      '--url', `http://127.0.0.1:${port}`,
      '--seed-hex', keys.alice.seed_hex,
      '--server-public-key', keys.svc.public_key,
      '--aud', registry.aud,
      '--scenario', 'sign-only',
      '--ts', String(ts),
      '--nonce', nonce,
      '--arg', 'method=GET', '--arg', 'target=/mcp', '--arg', 'body-b64u=',
    ];
    let child;
    try {
      child = makeChild(t.cmd, args);
    } catch (e) {
      return { failed: true, reason: `cannot spawn client for ${pairLabel}: ${t.display} (${e.message})`, stderr: '' };
    }
    allChildren.add(child);
    let code;
    try {
      code = await waitClose(child, 20000, `client sign-only ${pairLabel}`);
    } catch (e) {
      allChildren.delete(child);
      return { failed: true, reason: e.message, stderr: child._stderrTail() };
    }
    allChildren.delete(child);
    const lines = child._stdoutText().split('\n').filter((l) => l.trim() !== '');
    if (code !== 0) {
      return { failed: true, reason: `client sign-only exited ${code} (expected 0)`, stderr: child._stderrTail() };
    }
    if (lines.length === 0) {
      return { failed: true, reason: 'client sign-only produced no output', stderr: child._stderrTail() };
    }
    let result;
    try { result = JSON.parse(lines[lines.length - 1]); } catch {
      return { failed: true, reason: 'client sign-only last stdout line is not JSON', stderr: child._stderrTail() };
    }
    if (result.outcome !== 'ok' || typeof result.data?.jack_auth !== 'string') {
      return { failed: true, reason: `client sign-only reported ${JSON.stringify(result.outcome)} without jack_auth`, stderr: child._stderrTail() };
    }
    return { failed: false, header: result.data.jack_auth, stderr: child._stderrTail() };
  }

  // Sign at (ts, nonce) and send raw; returns {ok, status, code, header}.
  async function sendSigned(lang, port, ts, nonce, pairLabel) {
    const sign = await runSignOnly(lang, port, ts, nonce, pairLabel);
    if (sign.failed) return { ok: false, reason: sign.reason, stderr: sign.stderr, status: null, code: null };
    const raw = await sendRaw(port, sign.header);
    const r = parseResponse(raw);
    if (r.failed) return { ok: false, reason: r.reason, stderr: '', status: null, code: null, header: sign.header };
    return { ok: true, status: r.status, code: r.code, header: sign.header, stderr: '' };
  }

  // Resend a captured header byte-identically.
  async function resend(port, header) {
    const r = parseResponse(await sendRaw(port, header));
    if (r.failed) return { ok: false, reason: r.reason, status: null, code: null };
    return { ok: true, status: r.status, code: r.code, header };
  }

  // Server spawn with the run.mjs ready-line protocol (10s deadline).
  async function spawnServer(lang, extraArgs, label) {
    const t = resolveTarget(targets[lang].server, 'server', `server=${lang}`);
    let child;
    try {
      child = makeChild(t.cmd, [...t.args, ...extraArgs]);
    } catch (e) {
      fail(`cannot spawn server for ${label}: ${t.display} (${e.message})`);
    }
    allChildren.add(child);
    let line;
    try {
      line = await child._nextLine(10000, `server ${label}`);
    } catch (e) {
      startupFail(`server failed to become ready for ${label}: ${e.message}`);
    }
    let ready;
    try { ready = JSON.parse(line); } catch { fail(`malformed ready line from server (${label}): ${line}`); }
    if (ready.ready !== true || !Number.isInteger(ready.port) || ready.port <= 0 || !ready.server_public_key || !ready.server_kid) {
      fail(`malformed ready line from server (${label}): ${line}`);
    }
    return { child, port: ready.port, ready };
  }

  // Explicit out-of-band initialization: exactly one {"durable_initialized":true}
  // stdout line and exit 0.
  async function durableInit(lang, args, label) {
    const t = resolveTarget(targets[lang].server, 'server', `server=${lang}`);
    let child;
    try {
      child = makeChild(t.cmd, [...t.args, ...args]);
    } catch (e) {
      fail(`cannot spawn server init for ${label}: ${t.display} (${e.message})`);
    }
    allChildren.add(child);
    let line;
    try {
      line = await child._nextLine(10000, `durable init ${label}`);
    } catch (e) {
      fail(`durable init failed for ${label}: ${e.message}`);
    }
    if (line.trim() !== '{"durable_initialized":true}') {
      fail(`durable init printed unexpected line for ${label}: ${line}`);
    }
    const code = await waitClose(child, 10000, `durable init ${label}`);
    allChildren.delete(child);
    if (code !== 0) fail(`durable init exited ${code} for ${label}\nstderr tail:\n${child._stderrTail()}`);
  }

  // Clean stop via stdin EOF; must exit 0 (killTree fallback means failure).
  async function cleanStop(child, label) {
    try { child.stdin.end(); } catch { /* best effort */ }
    let code;
    try {
      code = await waitClose(child, 10000, `clean stop ${label}`);
    } catch (e) {
      allChildren.delete(child);
      return { ok: false, code: null, reason: e.message, stderr: child._stderrTail() };
    }
    allChildren.delete(child);
    return { ok: code === 0, code, reason: code === 0 ? '' : `clean stop exited ${code} (expected 0)`, stderr: child._stderrTail() };
  }

  // Crash: SIGKILL then await close.
  async function crash(child, label) {
    try { child.kill('SIGKILL'); } catch { /* best effort */ }
    let outcome;
    try {
      outcome = await Promise.race([
        child._closeOutcome,
        new Promise((r) => setTimeout(() => { killTree(child); r(null); }, 5000)),
      ]);
    } finally {
      allChildren.delete(child);
    }
    if (!outcome) return { ok: false, reason: `crash ${label}: child did not close after SIGKILL`, stderr: child._stderrTail() };
    return { ok: true, outcome };
  }

  // A Rust/TS killed owner leaves this exact marker. Only remove it after the
  // child has closed; Go's bbolt backend has no marker to remove.
  function removeCrashOwnerMarker(lang, dir, label) {
    if (lang !== 'rust' && lang !== 'typescript') return { ok: true };
    const marker = join(dir, 'nonces.owner');
    if (!existsSync(marker)) return { ok: false, reason: `${label}: expected stale owner marker is absent: ${marker}` };
    try { unlinkSync(marker); } catch (e) { return { ok: false, reason: `${label}: cannot remove stale owner marker: ${e.message}` }; }
    if (existsSync(marker)) return { ok: false, reason: `${label}: stale owner marker remains after removal` };
    return { ok: true };
  }

  // Expect the SDK's exact dirty/recovery startup failure: exit 1, no stdout,
  // and the diagnostic emitted by that interop server's durable-open path.
  const DURABLE_RECOVERY_DIAGNOSTIC = {
    go: 'durable store: durable: explicit recovery required',
    rust: 'durable nonce store: RecoveryRequired',
    typescript: 'durable store: durable: recovery required',
    fake: 'dirty', // the self-test fake server (interop/tools/fake-server.mjs)
  };
  async function expectStartupRefusal(lang, args, label) {
    const t = resolveTarget(targets[lang].server, 'server', `server=${lang}`);
    let child;
    try {
      child = makeChild(t.cmd, [...t.args, ...args]);
    } catch (e) {
      return { refused: false, reason: `spawn error: ${e.message}`, stderr: '' };
    }
    allChildren.add(child);
    const outcome = await Promise.race([
      child._closeOutcome,
      new Promise((r) => setTimeout(() => { killTree(child); r(null); }, 10000)),
    ]);
    allChildren.delete(child);
    if (!outcome) return { refused: false, reason: 'restart child did not exit within 10s', stderr: child._stderrTail(), stdout: child._stdoutText() };
    const stdout = child._stdoutText();
    const stderr = child._stderrTail();
    const expectedDiagnostic = DURABLE_RECOVERY_DIAGNOSTIC[lang];
    if (stdout !== '') return { refused: false, reason: `restart wrote unexpected stdout: ${stdout}`, stderr, stdout };
    if (outcome.code !== 1 || outcome.signal !== null) {
      return { refused: false, reason: `restart closed with code=${outcome.code} signal=${outcome.signal} (expected exit 1)`, stderr, stdout };
    }
    if (!expectedDiagnostic || !stderr.includes(expectedDiagnostic)) {
      return { refused: false, reason: `restart lacks exact recovery diagnostic '${expectedDiagnostic}'`, stderr, stdout };
    }
    return { refused: true, code: outcome.code, stderr, stdout };
  }

  const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

  // Wait until now >= t0 + 3s (retention ts+2 expired inclusively).
  async function waitExpiry(t0) {
    while (Date.now() / 1000 < t0 + 3) await sleepMs(100);
  }

  function recordFailure(id, pairLabel, expected, run) {
    failures.push({ check: id, pair: pairLabel });
    process.stdout.write(`FAIL ${id}\n`);
    process.stdout.write(`  check: ${id}\n  pair: ${pairLabel}\n`);
    process.stdout.write(`  expected: ${JSON.stringify(expected)}\n`);
    process.stdout.write(`  actual: ${JSON.stringify(run.actual ?? null)}\n`);
    if (run.reason) process.stdout.write(`  reason: ${run.reason}\n`);
    if (run.stderr) process.stdout.write(`  stderr tail:\n${run.stderr.split('\n').map((l) => '    ' + l).join('\n')}\n`);
  }

  // ---- Check A: clean stop, restart, byte-identical replay is refused ----
  async function checkA(ctx, pairLabel) {
    const id = 'durable-restart-replay';
    const base = baseArgs(ctx.tmp);
    const dir = join(ctx.tmp, 'durable-a');
    mkdirSync(dir, { mode: 0o700 }); // the stores require an existing private directory
    const failR = (expected, run) => { recordFailure(id, pairLabel, expected, run); return false; };
    await durableInit(ctx.server, [...base, '--durable-dir', dir, '--durable-init'], `${pairLabel} ${id}`);
    let srv;
    try {
      srv = await spawnServer(ctx.server, [...base, '--durable-dir', dir], `${pairLabel} ${id} start`);
      const t0 = Math.floor(Date.now() / 1000);
      const n1 = b64u(randomBytes(16));
      const r1 = await sendSigned(ctx.client, srv.port, t0, n1, pairLabel);
      if (!r1.ok || r1.status !== 200) return failR({ http_status: 200 }, { actual: { status: r1.status, code: r1.code }, reason: r1.reason, stderr: r1.stderr });
      const stop1 = await cleanStop(srv.child, `${pairLabel} ${id}`);
      if (!stop1.ok) return failR({ exit: 0 }, { actual: { exit: stop1.code }, reason: stop1.reason, stderr: stop1.stderr });
      srv = await spawnServer(ctx.server, [...base, '--durable-dir', dir], `${pairLabel} ${id} restart`);
      const r2 = await resend(srv.port, r1.header);
      if (!r2.ok || r2.status !== 401 || r2.code !== 'replayed_nonce') {
        return failR({ http_status: 401, code: 'replayed_nonce' }, { actual: { status: r2.status, code: r2.code }, reason: r2.reason ?? 'byte-identical resend accepted' });
      }
      const t2 = Math.floor(Date.now() / 1000);
      const n2 = b64u(randomBytes(16));
      const r3 = await sendSigned(ctx.client, srv.port, t2, n2, pairLabel);
      if (!r3.ok || r3.status !== 200) return failR({ http_status: 200 }, { actual: { status: r3.status, code: r3.code }, reason: r3.reason, stderr: r3.stderr });
      const stop2 = await cleanStop(srv.child, `${pairLabel} ${id}`);
      if (!stop2.ok) return failR({ exit: 0 }, { actual: { exit: stop2.code }, reason: stop2.reason, stderr: stop2.stderr });
      return true;
    } catch (e) {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
      return failR(null, { actual: null, reason: e.message, stderr: '' });
    } finally {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
    }
  }

  // ---- Check B: SIGKILL leaves the dirty epoch; restart must fail closed ----
  async function checkB(ctx, pairLabel) {
    const id = 'durable-crash-fail-closed';
    const base = baseArgs(ctx.tmp);
    const dir = join(ctx.tmp, 'durable-a'); // still check A's store
    const failR = (expected, run) => { recordFailure(id, pairLabel, expected, run); return false; };
    let srv;
    try {
      srv = await spawnServer(ctx.server, [...base, '--durable-dir', dir], `${pairLabel} ${id} start`);
      const t = Math.floor(Date.now() / 1000);
      const n3 = b64u(randomBytes(16));
      const r1 = await sendSigned(ctx.client, srv.port, t, n3, pairLabel);
      if (!r1.ok || r1.status !== 200) return failR({ http_status: 200 }, { actual: { status: r1.status, code: r1.code }, reason: r1.reason, stderr: r1.stderr });
      const crashR = await crash(srv.child, `${pairLabel} ${id}`);
      srv = null;
      if (!crashR.ok || crashR.outcome.signal !== 'SIGKILL') {
        return failR({ closed_by_sigkill: true, actual_close: true }, { actual: crashR.outcome ?? null, reason: crashR.reason ?? `child close signal was ${crashR.outcome.signal}` });
      }
      const markerR = removeCrashOwnerMarker(ctx.server, dir, `${pairLabel} ${id}`);
      if (!markerR.ok) return failR({ stale_marker_removed_after_close: true }, { actual: null, reason: markerR.reason });
      const refusal = await expectStartupRefusal(ctx.server, [...base, '--durable-dir', dir], `${pairLabel} ${id} restart`);
      if (!refusal.refused) {
        return failR({ exit: 1, stdout: '', stderr_contains: DURABLE_RECOVERY_DIAGNOSTIC[ctx.server] }, { actual: { exit: refusal.code ?? null, stdout: refusal.stdout ?? '' }, reason: refusal.reason, stderr: refusal.stderr });
      }
      return true;
    } catch (e) {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
      return failR(null, { actual: null, reason: e.message });
    } finally {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
    }
  }

  // ---- Check C: W=2, reuse after retention expired under an advanced H ----
  async function checkC(ctx, pairLabel) {
    const id = 'durable-expiry-reuse';
    const base = baseArgs(ctx.tmp);
    const dir = join(ctx.tmp, 'durable-c');
    mkdirSync(dir, { mode: 0o700 });
    const wArgs = ['--durable-dir', dir, '--durable-window', '2'];
    const failR = (expected, run) => { recordFailure(id, pairLabel, expected, run); return false; };
    await durableInit(ctx.server, [...base, ...wArgs, '--durable-init'], `${pairLabel} ${id}`);
    let srv;
    try {
      srv = await spawnServer(ctx.server, [...base, ...wArgs], `${pairLabel} ${id} start`);
      const t0 = Math.floor(Date.now() / 1000);
      const n4 = b64u(randomBytes(16));
      const r1 = await sendSigned(ctx.client, srv.port, t0, n4, pairLabel);
      if (!r1.ok || r1.status !== 200) return failR({ http_status: 200 }, { actual: { status: r1.status, code: r1.code }, reason: r1.reason, stderr: r1.stderr });
      const stop1 = await cleanStop(srv.child, `${pairLabel} ${id}`);
      srv = null;
      if (!stop1.ok) return failR({ exit: 0 }, { actual: { exit: stop1.code }, reason: stop1.reason, stderr: stop1.stderr });
      await waitExpiry(t0);
      srv = await spawnServer(ctx.server, [...base, ...wArgs], `${pairLabel} ${id} restart`);
      const t2 = Math.floor(Date.now() / 1000);
      const r2 = await sendSigned(ctx.client, srv.port, t2, n4, pairLabel);
      if (!r2.ok || r2.status !== 200) return failR({ http_status: 200 }, { actual: { status: r2.status, code: r2.code }, reason: r2.reason, stderr: r2.stderr });
      const r3 = await resend(srv.port, r2.header);
      if (!r3.ok || r3.status !== 401 || r3.code !== 'replayed_nonce') {
        return failR({ http_status: 401, code: 'replayed_nonce' }, { actual: { status: r3.status, code: r3.code }, reason: r3.reason ?? 'immediate resend accepted' });
      }
      const stop2 = await cleanStop(srv.child, `${pairLabel} ${id}`);
      srv = null;
      if (!stop2.ok) return failR({ exit: 0 }, { actual: { exit: stop2.code }, reason: stop2.reason, stderr: stop2.stderr });
      return true;
    } catch (e) {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
      return failR(null, { actual: null, reason: e.message });
    } finally {
      if (srv) { await stopChild(srv.child); allChildren.delete(srv.child); }
    }
  }

  const matrixCells = {};
  const pairSummaries = [];

  for (const client of clientLangs) {
    matrixCells[client] = {};
    for (const server of serverLangs) {
      const pairLabel = `client=${client} server=${server}`;
      process.stdout.write(`== pair ${pairLabel} ==\n`);
      const result = await runPair(client, server, pairLabel);
      matrixCells[client][server] = { passed: result.passed, total: CHECKS.length };
      pairSummaries.push({ pairLabel, passed: result.passed, total: CHECKS.length });
      process.stdout.write(`pair ${pairLabel}: ${result.passed}/${CHECKS.length}\n`);
    }
  }

  return { failures, matrixCells, pairSummaries };

  // Bounded retry of the startup port race only.
  async function runPair(client, server, pairLabel) {
    const attempts = 3;
    for (let attempt = 1; ; attempt++) {
      try {
        return await runPairOnce(client, server, pairLabel);
      } catch (e) {
        if (!(e instanceof StartupPortRace) || attempt >= attempts) {
          if (e instanceof StartupPortRace) fail(e.message);
          throw e;
        }
        process.stdout.write(`pair ${pairLabel}: startup port race (${e.message.split('\n')[0]}); retrying with fresh ports (attempt ${attempt + 1}/${attempts})\n`);
        for (const c of allChildren) killTree(c);
        allChildren.clear();
      }
    }
  }

  // One (client, server) cell: the three durable checks in sequence.
  async function runPairOnce(client, server, pairLabel) {
    const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-durable-'));
    tmpRoots.push(tmp);
    writeFileSync(join(tmp, 'state.json'), JSON.stringify({ version: 1, keys: registry.keys, invites: [] }, null, 2) + '\n');
    const ctx = { tmp, client, server };
    const results = {};
    try {
      results['durable-restart-replay'] = await checkA(ctx, pairLabel);
      if (results['durable-restart-replay']) process.stdout.write('PASS durable-restart-replay\n');
      results['durable-crash-fail-closed'] = await checkB(ctx, pairLabel);
      if (results['durable-crash-fail-closed']) process.stdout.write('PASS durable-crash-fail-closed\n');
      results['durable-expiry-reuse'] = await checkC(ctx, pairLabel);
      if (results['durable-expiry-reuse']) process.stdout.write('PASS durable-expiry-reuse\n');
    } finally {
      for (const c of [...allChildren]) { await stopChild(c); allChildren.delete(c); }
    }
    return { passed: Object.values(results).filter(Boolean).length };
  }
}

function printMatrix(matrixCells, serverLangs, clientLangs) {
  const head = 'client \\ server'.padEnd(18) + serverLangs.map((s) => s.padEnd(14)).join('');
  process.stdout.write(head + '\n');
  for (const c of clientLangs) {
    const row = c.padEnd(18) + serverLangs.map((s) => {
      const cell = matrixCells[c]?.[s];
      return (cell ? (cell.total && cell.passed === cell.total ? 'pass' : `fail:${cell.total - cell.passed}`) : '-').padEnd(14);
    }).join('');
    process.stdout.write(row + '\n');
  }
}

// ---- self-test (harness-level only, NOT SDK evidence) ----------------------------

async function selfTest() {
  const fakeServer = join(SCRIPT_DIR, 'tools', 'fake-durable-server.mjs');
  const fakeClient = join(SCRIPT_DIR, 'tools', 'fake-durable-client.mjs');
  const targets = { fake: { server: [process.execPath, fakeServer], client: [process.execPath, fakeClient] } };
  const loaded = loadFixtures();
  let checks = 0;
  const ok = (cond, what) => {
    if (!cond) { process.stderr.write(`self-test failed: ${what}\n`); process.exit(1); }
    checks++;
    process.stdout.write(`self-test: ${what}\n`);
  };

  // 1. --list exits 0 printing exactly the three check ids.
  const list = await new Promise((res) => {
    const child = spawn(process.execPath, [join(SCRIPT_DIR, 'durable.mjs'), '--list'], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', (c) => res({ code: c, out }));
  });
  const ids = list.out.split('\n').map((s) => s.split('\t')[0].trim()).filter(Boolean);
  ok(list.code === 0 && JSON.stringify(ids) === JSON.stringify(CHECKS), '--list exits 0 listing 3 checks');

  // 2. Full fake pair run in-process: all three checks pass.
  process.stdout.write('self-test: running the full matrix with bundled fakes (fake/fake)...\n');
  const res = await runMatrix({ clientLangs: ['fake'], serverLangs: ['fake'], targets, ...loaded });
  ok(res.failures.length === 0, `fake pair run passes all 3 checks (got ${res.failures.length} failures)`);
  ok(res.pairSummaries.length === 1 && res.pairSummaries[0].passed === CHECKS.length, 'fake pair summary is 3/3');
  ok(res.matrixCells.fake?.fake?.passed === CHECKS.length, 'matrix cell fake/fake is pass');

  // 3. Negative control: deviated nonce must fail the run with exit 1 and FAIL.
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-durable-selftest-'));
  const targetsPath = join(tmp, 'targets.json');
  writeFileSync(targetsPath, JSON.stringify(targets, null, 2) + '\n');
  try {
    const negative = await new Promise((res2) => {
      const child = spawn(process.execPath, [join(SCRIPT_DIR, 'durable.mjs'), '--targets', targetsPath, '--servers', 'fake', '--clients', 'fake'], {
        cwd: REPO_ROOT, env: { ...process.env, JACK_FAKE_DEVIATE: 'forget' }, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => { out += d; });
      child.stderr.on('data', (d) => { err += d; });
      child.on('close', (c) => res2({ code: c, out, err }));
    });
    ok(negative.code === 1 && negative.out.includes('FAIL'), `negative control exits 1 and prints FAIL (got ${negative.code}; stderr: ${negative.err.trim().slice(0, 300)})`);
  } finally {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  // 4. Crash gate: serving on a dirty store must refuse with empty stdout.
  const tmp2 = mkdtempSync(join(tmpdir(), 'mcp-jack-durable-selftest-crash-'));
  try {
    const dir = join(tmp2, 'd');
    const { mkdirSync } = await import('node:fs');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'nonces'), JSON.stringify({ committed: {}, clean: false }));
    const refusal = await new Promise((res2) => {
      const child = spawn(process.execPath, [fakeServer, '--durable-dir', dir, '--aud', 'a', '--state', join(tmp2, 's.json'), '--server-seed-hex', 'aa'.repeat(32)], {
        cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = '';
      child.stdout.on('data', (d) => { out += d; });
      child.on('close', (c) => res2({ code: c, out }));
    });
    ok(refusal.code !== 0 && refusal.out === '', `crash gate refuses a dirty store with empty stdout (got exit ${refusal.code})`);
  } finally {
    try { rmSync(tmp2, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  process.stdout.write(`self-test: ok (${checks} checks)\n`);
  process.exit(0);
}

// ---- main -------------------------------------------------------------------------

const cli = parseArgs(process.argv.slice(2));
const targets = readJson(cli.targets, 'targets file');
if (!targets || typeof targets !== 'object' || Array.isArray(targets) || Object.keys(targets).length === 0) {
  fail(`invalid targets file: ${cli.targets}`);
}

if (cli.list) {
  for (const id of CHECKS) process.stdout.write(`${id}\t${CHECK_DOCS[id]}\n`);
  process.exit(0);
}

if (cli.selfTest) {
  await selfTest();
}

const targetKeys = Object.keys(targets);
const clientLangs = splitLangs(cli.clients, targetKeys, '--clients');
const serverLangs = splitLangs(cli.servers, targetKeys, '--servers');
if (clientLangs.length === 0) fail('no client languages selected');
if (serverLangs.length === 0) fail('no server languages selected');
validateTargets(targets, [...new Set([...clientLangs, ...serverLangs])]);

const loaded = loadFixtures();
const res = await runMatrix({ ...loaded, targets, clientLangs, serverLangs });

printMatrix(res.matrixCells, serverLangs, clientLangs);
const failedPairs = new Set(res.failures.map((f) => f.pair)).size;
if (res.failures.length === 0) {
  process.stdout.write('durable matrix: all pairs pass\n');
  process.exit(0);
} else {
  process.stdout.write(`durable matrix: ${res.failures.length} failure(s) across ${failedPairs} pair(s)\n`);
  process.exit(1);
}
