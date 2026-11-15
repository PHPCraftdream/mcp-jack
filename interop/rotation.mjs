// Dependency-free Node rotation-interop matrix harness (3x3) for the
// candidate server-key rotation contract. Node >= 20, node: builtins only.
//   node interop/rotation.mjs [--targets <file>] [--servers <l,l,...>]
//        [--clients <l,l,...>] [--list] [--self-test]
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const ROTATION_INTERVAL = 172800; // candidate default: A = P + 48h
const CHECKS = [
  'announce',
  's1-pre-rotation',
  's2-refresh-overlap',
  's3-overlap-old-key',
  'n1-cursor-beyond-head',
  'n2-cursor-malformed',
  'n3-ring-lacks-cursor',
  'n4-wrong-audience',
  'n5-tampered-page',
  'n5b-tamper-no-commit',
  'c1-fake-page-accepted',
  's4-cutoff-successor',
  's5-old-key-after-cutoff',
  'c2-state-stable',
];
const USAGE = `usage: node interop/rotation.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>] [--list] [--self-test]`;

function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
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

// Validate the target doc for the rotation roles: every selected language
// must provide BOTH rotation_server and rotation_client as non-empty argv
// arrays (rust carries its fixed mode args as pre-args).
function validateTargets(targets, langs) {
  for (const lang of langs) {
    const t = targets[lang];
    for (const role of ['rotation_server', 'rotation_client']) {
      if (!t || !Array.isArray(t[role]) || t[role].length === 0) {
        fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
      }
    }
  }
}

// Resolve a target argv like run.mjs: bare commands from PATH, relative paths
// from the repo root, with .exe tolerance on Windows.
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
  // on timeout and on early close (buffered output is still delivered first).
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

// Reserve an ephemeral loopback port the child can then bind exactly.
function allocPort() {
  return new Promise((res, rej) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => res(port));
    });
    srv.on('error', rej);
  });
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.stdin.end(); } catch { /* best effort */ }
  const timeout = new Promise((r) => setTimeout(r, 2000));
  await Promise.race([child._closeOutcome, timeout]);
  killTree(child);
}

// ---- expected comparison -------------------------------------------------------

function subsetMatches(expected, actual) {
  if (Array.isArray(expected)) return JSON.stringify(expected) === JSON.stringify(actual);
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    return Object.keys(expected).every((k) => k in actual && subsetMatches(expected[k], actual[k]));
  }
  return expected === actual;
}

// ---- fixtures -----------------------------------------------------------------

function loadFixtures() {
  const keysList = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'keys fixture').keys;
  const keys = Object.fromEntries(keysList.map((k) => [k.name, k]));
  for (const name of ['svc', 'erin', 'alice']) {
    if (!keys[name]) fail(`keys fixture is missing the '${name}' identity`);
  }
  const registry = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'registry.json'), 'registry fixture');
  return { keys, registry };
}

// ---- core runner -----------------------------------------------------------------

async function runMatrix(opts) {
  const { clientLangs, serverLangs, targets, keys, registry } = opts;
  const failures = [];
  const allChildren = new Set();
  let processesSpawned = 0;
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

  const setClock = (path, t) => writeFileSync(path, String(t) + '\n');

  async function runClientStep(lang, args, env, label, pairLabel, timeoutMs = 20000) {
    const t = resolveTarget(targets[lang].rotation_client, 'rotation_client', `client=${lang}`);
    let child;
    try {
      child = makeChild(t.cmd, [...t.args, ...args], env);
    } catch (e) {
      return { failed: true, reason: `cannot spawn client for ${pairLabel}: ${t.display} (${e.message})`, exitCode: null, stderr: '', result: null };
    }
    allChildren.add(child);
    let code;
    try {
      code = await waitClose(child, timeoutMs, `client ${label}`);
    } catch (e) {
      allChildren.delete(child);
      return { failed: true, reason: e.message, exitCode: null, stderr: child._stderrTail(), result: null };
    }
    allChildren.delete(child);
    if (code !== 0) {
      return { failed: true, reason: `client ${label} exited ${code} (expected 0)`, exitCode: code, stderr: child._stderrTail(), result: null };
    }
    const lines = child._stdoutText().split('\n').filter((l) => l.trim() !== '');
    if (lines.length === 0) {
      return { failed: true, reason: `client ${label} produced no output`, exitCode: code, stderr: child._stderrTail(), result: null };
    }
    let result;
    try { result = JSON.parse(lines[lines.length - 1]); } catch {
      return { failed: true, reason: `client ${label} last stdout line is not JSON`, exitCode: code, stderr: child._stderrTail(), result: null };
    }
    if (!['ok', 'rejected', 'client_error'].includes(result.outcome)) {
      return { failed: true, reason: `client ${label} reported invalid outcome`, exitCode: code, stderr: child._stderrTail(), result: null };
    }
    return { failed: false, result, exitCode: code, stderr: child._stderrTail() };
  }

  function recordFailure(id, pairLabel, expected, run, extraReason) {
    failures.push({ scenario: id, pair: pairLabel });
    process.stdout.write(`FAIL ${id}${extraReason ? ` (${extraReason})` : ''}\n`);
    const exp = expected ?? {};
    process.stdout.write(`  check: ${id}\n  pair: ${pairLabel}\n`);
    process.stdout.write(`  expected: ${JSON.stringify(exp)}\n`);
    process.stdout.write(`  actual: ${run.result ? JSON.stringify(run.result) : '(no result)'}\n`);
    if (run.reason) process.stdout.write(`  reason: ${run.reason}\n`);
    if (run.stderr) process.stdout.write(`  client stderr tail:\n${run.stderr.split('\n').map((l) => '    ' + l).join('\n')}\n`);
  }

  // Subset comparison: outcome/http_status/code exact (undefined = not
  // compared), data compared recursively when the expectation mentions it.
  function checkResult(id, pairLabel, expected, run) {
    if (run.failed) { recordFailure(id, pairLabel, expected, run); return false; }
    const bad = [];
    for (const field of ['outcome', 'http_status', 'code']) {
      if (expected[field] !== undefined && run.result[field] !== expected[field]) {
        bad.push(`${field} ${JSON.stringify(run.result[field])} vs ${JSON.stringify(expected[field])}`);
      }
    }
    if (expected.data !== undefined && !subsetMatches(expected.data, run.result.data)) {
      bad.push('data mismatch');
    }
    if (bad.length === 0) return true;
    recordFailure(id, pairLabel, expected, { ...run, reason: `mismatch: ${bad.join(', ')}` });
    return false;
  }

  async function spawnRotationServer(lang, role, args, label) {
    const t = resolveTarget(targets[lang][role], role, `${role}=${lang}`);
    let child;
    try {
      child = makeChild(t.cmd, [...t.args, ...args]);
    } catch (e) {
      fail(`cannot spawn ${role} for ${label}: ${t.display} (${e.message})`);
    }
    allChildren.add(child);
    processesSpawned++;
    let line;
    try {
      line = await child._nextLine(10000, `${role} ${label}`);
    } catch (e) {
      fail(`${role} failed to become ready for ${label}: ${e.message}`);
    }
    let ready;
    try { ready = JSON.parse(line); } catch {
      fail(`malformed ready line from ${role} (${label}): ${line}`);
    }
    if (ready.ready !== true || !Number.isInteger(ready.port) || ready.port <= 0) {
      fail(`malformed ready line from ${role} (${label}): ${line}`);
    }
    return { child, port: ready.port, ready };
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

  return { failures, matrixCells, pairSummaries, processesSpawned };

  // ---- one (client, server) cell: the full 14-check rotation sequence ----
  async function runPair(client, server, pairLabel) {
    const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-rotation-'));
    tmpRoots.push(tmp);
    const T = Math.floor(Date.now() / 1000) + 120;
    let A = T + ROTATION_INTERVAL;
    let headHash = null;
    const portA = await allocPort();
    const portB = await allocPort();
    const portC = await allocPort();
    const urlA = `http://127.0.0.1:${portA}`;
    const urlB = `http://127.0.0.1:${portB}`;
    const urlC = `http://127.0.0.1:${portC}`;

    const clkSrvPri = join(tmp, 'clk-srv-pri');
    const clkSrvFresh = join(tmp, 'clk-srv-fresh');
    const clkFakeSrv = join(tmp, 'clk-fake-srv');
    const clkCliMain = join(tmp, 'clk-cli-main');
    const clkCliFake = join(tmp, 'clk-cli-fake');
    const modePath = join(tmp, 'mode');
    for (const p of [clkSrvPri, clkSrvFresh, clkFakeSrv, clkCliMain, clkCliFake]) setClock(p, T);

    const serverArgs = (port, store, clock) => ([
      '--aud', registry.aud,
      '--url', `http://127.0.0.1:${port}`,
      '--state', join(tmp, 'state.json'),
      '--server-seed-hex', keys.svc.seed_hex,
      '--rotation-store', join(tmp, store),
      '--clock-file', clock,
      '--port', String(port),
    ]);
    let pri;
    let fresh;
    try {
      pri = await spawnRotationServer(server, 'rotation_server', [
        ...serverArgs(portA, 'server-pri.store', clkSrvPri),
        '--ring-seed', `ring-1=${keys.erin.seed_hex}`,
      ], `${pairLabel} primary`);
      if (pri.ready.port !== portA) fail(`primary rotation server bound ${pri.ready.port}, expected ${portA} (${pairLabel})`);
      if (pri.ready.server_public_key !== keys.svc.public_key || pri.ready.server_kid !== keys.svc.kid) {
        fail(`primary rotation server identity mismatch (${pairLabel}): ${JSON.stringify(pri.ready)}`);
      }
      fresh = await spawnRotationServer(server, 'rotation_server', serverArgs(portB, 'server-fresh.store', clkSrvFresh), `${pairLabel} fresh`);
      if (fresh.ready.port !== portB) fail(`fresh rotation server bound ${fresh.ready.port}, expected ${portB} (${pairLabel})`);
      if (fresh.ready.server_public_key !== keys.svc.public_key) {
        fail(`fresh rotation server identity mismatch (${pairLabel}): ${JSON.stringify(fresh.ready)}`);
      }
    } catch (e) {
      fail(`${pairLabel}: ${e.message}`);
    }

    const results = {}; // id -> passed
    const passed = () => Object.values(results).filter(Boolean).length;
    const stopAll = async () => {
      await stopChild(pri.child);
      await stopChild(fresh.child);
      await stopChild(fakeChild);
      allChildren.delete(pri.child);
      allChildren.delete(fresh.child);
      allChildren.delete(fakeChild);
    };

    // Fake peer: driver-owned, spawned via its own argv (not the targets doc).
    const fakeArgv = [
      process.execPath, join(SCRIPT_DIR, 'tools', 'rotation-fake.mjs'),
      '--port', String(portC), '--clock-file', clkFakeSrv, '--mode-file', modePath,
      '--aud', registry.aud, '--url', urlC,
      '--k0-seed-hex', keys.svc.seed_hex, '--k1-seed-hex', keys.erin.seed_hex,
      '--k1-kid', keys.erin.kid, '--p', String(T),
    ];
    const fakeChild = makeChild(fakeArgv[0], fakeArgv.slice(1));
    allChildren.add(fakeChild);
    processesSpawned++;
    try {
      const line = await fakeChild._nextLine(10000, `fake peer ${pairLabel}`);
      const ready = JSON.parse(line);
      if (ready.ready !== true || ready.port !== portC) {
        fail(`fake rotation peer failed to bind ${portC} (${pairLabel}): ${line}`);
      }
    } catch (e) {
      fail(`fake rotation peer failed for ${pairLabel}: ${e.message}`);
    }

    // The fake peer's mode file starts at "page" (it serves no traffic before
    // the n5 negative control, so the tamper write below lands first in the
    // sequence).
    writeFileSync(modePath, 'page\n');

    const clientEnv = { JACK_ROTATION_MODE_FILE: modePath };
    const mainClient = (step, extra = []) => ([
      '--step', step, '--url', urlA, '--aud', registry.aud,
      '--seed-hex', keys.alice.seed_hex, '--anchor', keys.svc.public_key,
      '--store', join(tmp, 'cli-main.store'), '--clock-file', clkCliMain, ...extra,
    ]);
    const fakeClient = (step, extra = []) => ([
      '--step', step, '--url', urlC, '--aud', registry.aud,
      '--seed-hex', keys.alice.seed_hex, '--anchor', keys.svc.public_key,
      '--store', join(tmp, 'cli-fake.store'), '--clock-file', clkCliFake, ...extra,
    ]);
    const expect = (outcome, http_status, code, data) => ({ outcome, http_status, code, data });

    try {
      // ---- announce ----
      try {
        pri.child.stdin.write(JSON.stringify({ op: 'announce', reference: 'ring-1', kid: keys.erin.kid }) + '\n');
        const line = await pri.child._nextLine(10000, `announce ${pairLabel}`);
        const ann = JSON.parse(line);
        const okAnn = ann.announced === true
          && ann.ordinal === 1
          && ann.head_ordinal === 1
          && ann.published_at === T
          && ann.activates_at === ann.published_at + ROTATION_INTERVAL
          && /^[A-Za-z0-9_-]{43}$/.test(ann.head_hash ?? '');
        if (okAnn) {
          A = ann.activates_at;
          headHash = ann.head_hash;
          results['announce'] = true;
          process.stdout.write('PASS announce\n');
        } else {
          recordFailure('announce', pairLabel, { announced: true, ordinal: 1, head_ordinal: 1, published_at: T, activates_at: T + ROTATION_INTERVAL, head_hash: '43-char base64url' }, { failed: false, result: ann, exitCode: null, stderr: pri.child._stderrTail() });
          results['announce'] = false;
        }
      } catch (e) {
        recordFailure('announce', pairLabel, { announced: true }, { failed: true, reason: e.message, exitCode: null, stderr: pri.child._stderrTail(), result: null });
        results['announce'] = false;
      }

      if (results['announce'] !== true) {
        // A failed announce poisons every later step (no A, no head hash):
        // fail the remaining checks without hanging the harness.
        for (const id of CHECKS.slice(1)) {
          results[id] = false;
          recordFailure(id, pairLabel, null, { failed: true, reason: 'announce failed', exitCode: null, stderr: '', result: null }, 'announce failed');
        }
        await stopAll();
        return { passed: passed() };
      }

      // ---- s1: plain call before rotation ----
      {
        const r = await runClientStep(client, mainClient('call'), clientEnv, `s1 ${pairLabel}`, pairLabel);
        results['s1-pre-rotation'] = checkResult('s1-pre-rotation', pairLabel, expect('ok', 200, null, { signed_by: keys.svc.kid }), r);
      }
      // ---- s2: refresh within the overlap ----
      setClock(clkCliMain, T + 2);
      setClock(clkSrvPri, T + 2);
      {
        const r = await runClientStep(client, mainClient('refresh'), clientEnv, `s2 ${pairLabel}`, pairLabel);
        results['s2-refresh-overlap'] = checkResult('s2-refresh-overlap', pairLabel, expect('ok', 200, null, {
          committed: true, terminal_ordinal: 1, head_ordinal: 1, complete: true, revision: 2, head_hash: headHash,
        }), r);
      }
      // ---- s3: still served by the old key during overlap ----
      setClock(clkCliMain, T + 3);
      setClock(clkSrvPri, T + 3);
      {
        const r = await runClientStep(client, mainClient('call'), clientEnv, `s3 ${pairLabel}`, pairLabel);
        results['s3-overlap-old-key'] = checkResult('s3-overlap-old-key', pairLabel, expect('ok', 200, null, { signed_by: keys.svc.kid }), r);
      }
      // ---- n1: wire cursor beyond head ----
      setClock(clkCliMain, T + 4);
      {
        const r = await runClientStep(client, mainClient('wire', ['--tool', 'jack.server.key', '--cursor', `2:${headHash}`]), clientEnv, `n1 ${pairLabel}`, pairLabel);
        results['n1-cursor-beyond-head'] = checkResult('n1-cursor-beyond-head', pairLabel, expect('rejected', 409, 'rotation_checkpoint_unavailable', null), r);
      }
      // ---- n2: malformed wire cursor ----
      {
        const r = await runClientStep(client, mainClient('wire', ['--tool', 'jack.server.key', '--cursor', '0:not-a-hash']), clientEnv, `n2 ${pairLabel}`, pairLabel);
        results['n2-cursor-malformed'] = checkResult('n2-cursor-malformed', pairLabel, expect('rejected', 400, 'invalid_params', null), r);
      }
      // ---- n3: fresh server ring lacks the cursor ----
      setClock(clkCliMain, T + 5);
      {
        const args = mainClient('wire', ['--tool', 'jack.server.key', '--cursor', `1:${headHash}`]);
        args[args.indexOf('--url') + 1] = urlB;
        const r = await runClientStep(client, args, clientEnv, `n3 ${pairLabel}`, pairLabel);
        results['n3-ring-lacks-cursor'] = checkResult('n3-ring-lacks-cursor', pairLabel, expect('rejected', 409, 'rotation_checkpoint_unavailable', null), r);
      }
      // ---- n4: wrong audience probe ----
      setClock(clkCliMain, T + 6);
      {
        const args = mainClient('wire', ['--tool', 'ping']);
        args[args.indexOf('--aud') + 1] = registry.aud + '.wrong';
        const r = await runClientStep(client, args, clientEnv, `n4 ${pairLabel}`, pairLabel);
        results['n4-wrong-audience'] = checkResult('n4-wrong-audience', pairLabel, expect('rejected', 401, 'bad_signature', null), r);
      }
      // ---- n5: tampered page from the fake peer must be refused ----
      setClock(clkCliFake, T + 7);
      writeFileSync(modePath, 'page-tamper\n');
      {
        const r = await runClientStep(client, fakeClient('refresh'), clientEnv, `n5 ${pairLabel}`, pairLabel);
        results['n5-tampered-page'] = checkResult('n5-tampered-page', pairLabel, expect('client_error', null, 'rotation_record_invalid', null), r);
      }
      // ---- n5b: the tampered page must not have been committed ----
      {
        const r = await runClientStep(client, fakeClient('state'), clientEnv, `n5b ${pairLabel}`, pairLabel);
        results['n5b-tamper-no-commit'] = checkResult('n5b-tamper-no-commit', pairLabel, expect('ok', undefined, null, { head_ordinal: 0 }), r);
      }
      // ---- c1: a valid page from the fake peer is accepted ----
      writeFileSync(modePath, 'page\n');
      setClock(clkCliFake, T + 8);
      {
        const r = await runClientStep(client, fakeClient('refresh'), clientEnv, `c1 ${pairLabel}`, pairLabel);
        results['c1-fake-page-accepted'] = checkResult('c1-fake-page-accepted', pairLabel, expect('ok', 200, null, { committed: true, terminal_ordinal: 1 }), r);
      }
      // ---- s4: exactly at the cutoff the successor signs ----
      setClock(clkCliMain, A);
      setClock(clkSrvPri, A);
      {
        const r = await runClientStep(client, mainClient('call'), clientEnv, `s4 ${pairLabel}`, pairLabel);
        results['s4-cutoff-successor'] = checkResult('s4-cutoff-successor', pairLabel, expect('ok', 200, null, { signed_by: keys.erin.kid }), r);
      }
      // ---- s5: old-key peer response after the cutoff is refused ----
      writeFileSync(modePath, 'old-key\n');
      setClock(clkCliFake, A);
      {
        const r = await runClientStep(client, fakeClient('call'), clientEnv, `s5 ${pairLabel}`, pairLabel);
        results['s5-old-key-after-cutoff'] = checkResult('s5-old-key-after-cutoff', pairLabel, expect('client_error', null, 'rotation_key_interval', null), r);
      }
      // ---- c2: trust state never mutated by the failures above ----
      {
        const r = await runClientStep(client, mainClient('state'), clientEnv, `c2 ${pairLabel}`, pairLabel);
        results['c2-state-stable'] = checkResult('c2-state-stable', pairLabel, expect('ok', undefined, null, { head_ordinal: 1, revision: 2 }), r);
      }
    } finally {
      await stopAll();
    }
    return { passed: passed() };
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

// ---- self-test -----------------------------------------------------------------

async function selfTest() {
  const fakeServer = join(SCRIPT_DIR, 'tools', 'fake-rotation-server.mjs');
  const fakeClient = join(SCRIPT_DIR, 'tools', 'fake-rotation-client.mjs');
  const targets = { fake: { rotation_server: [process.execPath, fakeServer], rotation_client: [process.execPath, fakeClient] } };
  const loaded = loadFixtures();
  let checks = 0;
  const ok = (cond, what) => {
    if (!cond) { process.stderr.write(`self-test failed: ${what}\n`); process.exit(1); }
    checks++;
    process.stdout.write(`self-test: ${what}\n`);
  };

  // 1. Clean in-process run with the fake pseudo-language: all 14 checks per
  // pair must pass and exactly 3 processes (primary + fresh + fake) spawn.
  const res = await runMatrix({
    clientLangs: ['fake'], serverLangs: ['fake'], targets, ...loaded,
  });
  ok(res.failures.length === 0, `clean fake run passes (0 failures, got ${res.failures.length})`);
  ok(res.pairSummaries.length === 1 && res.pairSummaries[0].passed === CHECKS.length && res.pairSummaries[0].total === CHECKS.length,
    `fake pair runs exactly ${CHECKS.length} checks, all passing`);
  ok(res.matrixCells.fake?.fake && res.matrixCells.fake.fake.passed === res.matrixCells.fake.fake.total, 'matrix cell fake/fake is pass');
  ok(res.processesSpawned === 3, `exactly 3 processes spawned (primary + fresh + fake), got ${res.processesSpawned}`);

  // 2..5. Deviation controls run as subprocesses against a temp targets file.
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-rotation-selftest-'));
  const targetsPath = join(tmp, 'targets.json');
  writeFileSync(targetsPath, JSON.stringify(targets, null, 2) + '\n');
  const runChild = (args, extraEnv) => new Promise((res2) => {
    const child = spawn(process.execPath, [join(SCRIPT_DIR, 'rotation.mjs'), ...args], {
      cwd: REPO_ROOT, env: { ...process.env, ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', (c) => res2({ code: c, out }));
  });
  const deviate = async (name) => {
    const r = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake'], { JACK_ROTATION_DEVIATE: name });
    ok(r.code === 1, `deviate ${name} exits 1 (got ${r.code})`);
    ok(r.out.includes(`FAIL ${name}`), `deviate ${name} prints FAIL ${name}`);
  };
  try {
    await deviate('announce');
    await deviate('s1-pre-rotation');
    await deviate('n5b-tamper-no-commit');
    await deviate('s5-old-key-after-cutoff');

    // 6. --list prints exactly the named check ids.
    const list = await runChild(['--list'], {});
    const ids = list.out.split('\n').map((s) => s.trim()).filter(Boolean);
    ok(list.code === 0 && JSON.stringify(ids) === JSON.stringify(CHECKS), '--list prints exactly the 14 check ids');

    // 7. A targets file missing the rotation roles must exit 2.
    const legacyPath = join(tmp, 'legacy-targets.json');
    writeFileSync(legacyPath, JSON.stringify({ fake: { server: [process.execPath, fakeServer], client: [process.execPath, fakeClient] } }, null, 2) + '\n');
    const legacy = await runChild(['--targets', legacyPath, '--servers', 'fake', '--clients', 'fake'], {});
    ok(legacy.code === 2, `targets missing rotation roles exit 2 (got ${legacy.code})`);
  } finally {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
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
  for (const id of CHECKS) process.stdout.write(id + '\n');
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
  process.stdout.write('rotation matrix: all pairs pass\n');
  process.exit(0);
} else {
  process.stdout.write(`${res.failures.length} failure(s) across ${failedPairs} pair(s)\n`);
  process.exit(1);
}
