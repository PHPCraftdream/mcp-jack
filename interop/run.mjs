// Dependency-free Node matrix harness for mcp-jack cross-language interop
// tests (docs/design/interop.md). Node >= 20, node: builtins only.
//   node interop/run.mjs [--targets <file>] [--servers go,rust] [--clients ...]
//                        [--scenario <id>] [--list] [--self-test]
import { spawn } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
// Fixture keys copied for every client run so multi-step scenarios can sign
// steps with non-primary identities without reading fixtures from cwd.
const SEEDS_PATH = join(REPO_ROOT, 'spec', 'fixtures', 'keys.json');

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256b64u = (b) => b64u(createHash('sha256').update(b).digest());
const USAGE = `usage: node interop/run.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>] [--scenario <id>] [--list] [--self-test]`;

function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

function parseArgs(argv) {
  const out = { targets: join(SCRIPT_DIR, 'targets.json'), servers: null, clients: null, scenario: null, list: false, selfTest: false };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--targets': out.targets = argv[++i]; break;
      case '--servers': out.servers = argv[++i]; break;
      case '--clients': out.clients = argv[++i]; break;
      case '--scenario': out.scenario = argv[++i]; break;
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

// Resolve a target argv: bare commands come from PATH, relative paths from the
// repo root; on Windows try appending .exe when the file itself is missing.
function resolveTarget(argv, role, pairLabel) {
  // Check non-primary arguments that look like file paths (e.g. a script run
  // via "node <script>") so a missing target fails upfront with exit 2 instead
  // of surfacing later as a module-not-found error from the child.
  for (const arg of argv.slice(1)) {
    if (!arg.includes('/') && !arg.includes('\\')) continue;
    let p = resolve(REPO_ROOT, arg);
    if (!existsSync(p) && process.platform === 'win32' && existsSync(p + '.exe')) p = p + '.exe';
    if (!existsSync(p)) fail(`target binary not found for pair ${pairLabel}: ${p}`);
  }
  let cmd = argv[0];
  if (!cmd.includes('/') && !cmd.includes('\\') && !(process.platform === 'win32' && /^[a-zA-Z]:/.test(cmd))) {
    if (argv.length === 1) {
      // Bare executable: let spawn do PATH lookup, but check existence to
      // produce a good error message.
      const found = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':')
        .map((d) => join(d, cmd)).find((p) => existsSync(p) || (process.platform === 'win32' && existsSync(p + '.exe')));
      if (!found) fail(`target binary not found for pair ${pairLabel}: ${cmd}`);
      cmd = process.platform === 'win32' && !existsSync(found) ? found + '.exe' : found;
    }
    return { cmd, args: argv.slice(1), display: join(argv[0]) };
  }
  const abs = resolve(REPO_ROOT, cmd);
  let exe = abs;
  if (!existsSync(exe) && process.platform === 'win32' && !exe.toLowerCase().endsWith('.exe')) {
    if (existsSync(exe + '.exe')) exe = exe + '.exe';
  }
  if (!existsSync(exe)) fail(`target binary not found for pair ${pairLabel}: ${exe}`);
  return { cmd: exe, args: argv.slice(1), display: exe };
}

// ---- child process helpers -------------------------------------------------

function makeChild(cmd, args, opts) {
  const child = spawn(cmd, args, { cwd: REPO_ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let stderr = '';
  let stdout = '';
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-4000); });
  child.stdout.on('data', (d) => { stdout += d; });
  child._stderrTail = () => stderr;
  child._stdoutText = () => stdout;
  return child;
}

function killTree(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try { child.kill(); } catch { /* best effort */ }
}

// Read stdout until the first non-empty line (with timeout), reject on early
// exit or unparseable output.
function firstStdoutLine(child, label, timeoutMs) {
  return new Promise((res, rej) => {
    let buf = '';
    // Consume only COMPLETE newline-terminated lines; a chunk without '\n'
    // (e.g. split ready-line mode) must not resolve prematurely.
    const timer = setTimeout(() => { cleanup(); killTree(child); rej(new Error(`${label}: timeout after ${timeoutMs}ms waiting for output\nstderr tail:\n${child._stderrTail()}`)); }, timeoutMs);
    const done = (fn) => { cleanup(); fn(); };
    const onData = (d) => {
      buf += d;
      let idx;
      while ((idx = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (line.trim() === '') continue;
        cleanup(); child.stdout.pause();
        return res(line);
      }
    };
    const onExit = (code) => done(() => rej(new Error(`${label}: exited (code ${code}) before producing output\nstderr tail:\n${child._stderrTail()}`)));
    const onError = (e) => done(() => rej(new Error(`spawn error: ${e.message}`)));
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off('data', onData); child.stdout.off('end', onEnd);
      child.off('exit', onExit); child.off('error', onError);
    };
    // An unterminated remainder at EOF is never a ready line: the exit
    // handler reports the missing output.
    const onEnd = () => {};
    child.stdout.on('data', onData);
    child.stdout.on('end', onEnd);
    child.on('exit', onExit);
    child.on('error', onError);
  });
}

// Wait until the child has exited AND its stdio pipes have been fully
// drained. 'exit' only signals the process: data written right before exit
// may still be in flight, so reading captured stdout after 'exit' races the
// final writes (observed as a spurious "produced no output" in CI). 'close'
// fires once every stdio pipe is closed, i.e. all output is captured.
function waitClose(child, timeoutMs, label, onSpawnError) {
  return new Promise((res, rej) => {
    const timer = setTimeout(() => { killTree(child); rej(new Error(`${label}: timeout after ${timeoutMs}ms`)); }, timeoutMs);
    child.on('close', (code) => { clearTimeout(timer); res(code); });
    child.on('error', (e) => { clearTimeout(timer); if (onSpawnError) onSpawnError(e); rej(e); });
  });
}

// ---- expected comparison ---------------------------------------------------

function resolveKidPlaceholders(v, keys) {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const ks = Object.keys(v);
    if (ks.length === 1 && ks[0] === '$kid' && typeof v.$kid === 'string') return keys[v.$kid].kid;
    return Object.fromEntries(ks.map((k) => [k, resolveKidPlaceholders(v[k], keys)]));
  }
  if (Array.isArray(v)) return v.map((x) => resolveKidPlaceholders(x, keys));
  return v;
}

function subsetMatches(expected, actual) {
  if (Array.isArray(expected)) return JSON.stringify(expected) === JSON.stringify(actual);
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    return Object.keys(expected).every((k) => k in actual && subsetMatches(expected[k], actual[k]));
  }
  return expected === actual;
}

// ---- state / policy file construction --------------------------------------

function buildStateDoc(registry, overrides) {
  const keys = JSON.parse(JSON.stringify(registry.keys));
  if (overrides) {
    for (const [name, ov] of Object.entries(overrides)) {
      const k = keys.find((x) => x.name === name);
      if (!k) fail(`registry override for unknown key '${name}'`);
      for (const [field, val] of Object.entries(ov)) {
        // Only "now+<seconds>" is defined; used so "not yet valid" keys work
        // regardless of when the test runs.
        if (val === 'now+3600') k[field] = Math.floor(Date.now() / 1000) + 3600;
        else if (/^now\+\d+$/.test(val)) k[field] = Math.floor(Date.now() / 1000) + parseInt(val.slice(4), 10);
        else k[field] = val;
      }
    }
  }
  return { version: 1, keys, invites: [] };
}

function buildPolicyDoc(policy) {
  const doc = JSON.parse(JSON.stringify(policy));
  // The fixture policy has no echo rule; splice one in after ping/tools-list
  // so the echo scenario is allowed.
  doc.rules.splice(2, 0, { match: { method: 'tools/call', tool: 'echo' }, scope: null });
  return doc;
}

// ---- core runner ------------------------------------------------------------

async function runMatrix(opts) {
  const { clientLangs, serverLangs, targets, keys, registry, policy, scenarios, signCases, scenarioFilter, phases } = opts;
  const failures = [];
  const allChildren = new Set();
  let signRuns = 0;
  let serversSpawned = 0;
  const registerExitHandlers = () => {
    const killAll = () => { for (const c of allChildren) killTree(c); };
    process.on('exit', killAll);
    process.on('SIGINT', () => { killAll(); process.exit(130); });
    process.on('SIGTERM', () => { killAll(); process.exit(143); });
  };
  registerExitHandlers();

  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-interop-'));
  process.on('exit', () => { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ } });

  const policyPath = join(tmp, 'policy.json');
  writeFileSync(policyPath, JSON.stringify(buildPolicyDoc(policy), null, 2) + '\n');
  const baseStatePath = join(tmp, 'state.json');
  writeFileSync(baseStatePath, JSON.stringify(buildStateDoc(registry, null), null, 2) + '\n');

  const resolveServerArgv = (lang, statePath) => {
    const t = resolveTarget(targets[lang].server, 'server', `server=${lang}`);
    return { cmd: t.cmd, args: [...t.args, '--aud', registry.aud, '--policy', policyPath, '--state', statePath, '--server-seed-hex', keys.svc.seed_hex], display: t.display };
  };

  const pinFor = (sc, readyKey) => (keys[sc.server_public_key] ? keys[sc.server_public_key].public_key : readyKey);

  async function spawnServer(statePath, label) {
    const argv = resolveServerArgv(label.lang, statePath);
    let child;
    try {
      child = makeChild(argv.cmd, argv.args);
    } catch (e) {
      fail(`cannot spawn server for ${label.lang}: ${argv.display} (${e.message})`);
    }
    allChildren.add(child);
    serversSpawned++;
    let line;
    try {
      line = await firstStdoutLine(child, `server ${label.name} (${label.lang})`, 10000);
    } catch (e) {
      fail(`server failed to become ready for pair server=${label.lang}: ${e.message}`);
    }
    let ready;
    try { ready = JSON.parse(line); } catch { fail(`malformed ready line from server (${label.lang}): ${line}`); }
    if (ready.ready !== true || !Number.isInteger(ready.port) || ready.port <= 0 || !ready.server_public_key || !ready.server_kid) {
      fail(`malformed ready line from server (${label.lang}): ${line}`);
    }
    return { child, port: ready.port, pin: ready.server_public_key };
  }

  function clientArgv(lang, sc, pin, port, extraArgs) {
    const t = resolveTarget(targets[lang].client, 'client', `client=${lang}`);
    const args = [...t.args, '--url', `http://127.0.0.1:${port}`, '--seed-hex', keys[sc.identity].seed_hex, '--server-public-key', pin, '--aud', registry.aud, '--scenario', sc.id, '--seeds', SEEDS_PATH];
    for (const [k, v] of Object.entries(sc.args ?? {})) args.push('--arg', `${k}=${v}`);
    if (extraArgs) args.push(...extraArgs);
    return { cmd: t.cmd, args, display: t.display };
  }

  async function runClient(lang, argv, label, pairLabel, timeoutMs = 20000) {
    let child;
    try {
      child = makeChild(argv.cmd, argv.args);
    } catch (e) {
      fail(`cannot spawn client for ${pairLabel}: ${argv.display} (${e.message})`);
    }
    allChildren.add(child);
    let code;
    try {
      code = await waitClose(child, timeoutMs, `client ${label}`, (e) => fail(`cannot spawn client for ${pairLabel}: ${argv.display} (${e.message})`));
    } catch (e) {
      return { failed: true, reason: e.message, exitCode: null, stderr: child._stderrTail(), result: null };
    }
    if (code === null || typeof code !== 'number') {
      return { failed: true, reason: `client ${label}: spawn error`, exitCode: null, stderr: child._stderrTail(), result: null };
    }
    if (code !== 0) {
      // Any nonzero exit (or signal death) is a harness-level failure; only
      // clean exits may contribute a parsed result to the comparison.
      return { failed: true, reason: `client ${label} exited ${code === null ? 'by signal' : code} (expected 0)`, exitCode: code, stderr: child._stderrTail(), result: null };
    }
    const out = child._stdoutText();
    const lines = out.split('\n').filter((l) => l.trim() !== '');
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

  function recordFailure(scenarioId, pairLabel, expected, run) {
    failures.push({ scenario: scenarioId, pair: pairLabel });
    process.stdout.write(`FAIL ${scenarioId}\n`);
    const exp = expected ?? {};
    process.stdout.write(`  scenario: ${scenarioId}\n  pair: ${pairLabel}\n`);
    process.stdout.write(`  expected: outcome=${exp.outcome} http_status=${exp.http_status} code=${exp.code}\n`);
    if (exp.data !== undefined) process.stdout.write(`  expected data subset: ${JSON.stringify(exp.data)}\n`);
    process.stdout.write(`  actual: ${run.result ? JSON.stringify(run.result) : '(no result)'}\n`);
    process.stdout.write(`  client exit code: ${run.exitCode}\n`);
    process.stdout.write(`  client stderr tail:\n${(run.stderr || '').split('\n').map((l) => '    ' + l).join('\n')}\n`);
    process.stdout.write(`  reason: ${run.reason ?? ''}\n`);
  }

  function check(sc, run, pairLabel) {
    if (run.failed) { recordFailure(sc.id, pairLabel, sc.expected, run); return false; }
    const expected = {
      outcome: sc.expected.outcome,
      http_status: sc.expected.http_status,
      code: sc.expected.code,
      data: sc.expected.data === undefined ? undefined : resolveKidPlaceholders(sc.expected.data, keys),
    };
    const okOut = run.result.outcome === expected.outcome;
    const okStatus = run.result.http_status === expected.http_status;
    const okCode = run.result.code === expected.code;
    const okData = expected.data === undefined || (expected.data === null ? run.result.data === null : subsetMatches(expected.data, run.result.data));
    if (okOut && okStatus && okCode && okData) return true;
    recordFailure(sc.id, pairLabel, sc.expected, {
      ...run,
      reason: `mismatch: outcome ${run.result.outcome} vs ${expected.outcome}, http_status ${run.result.http_status} vs ${expected.http_status}, code ${run.result.code} vs ${expected.code}${okData ? '' : ', data mismatch'}`,
    });
    return false;
  }

  const scenarioIds = Object.keys(scenarios.scenarios).filter((id) => !scenarioFilter || scenarioFilter.includes(id));
  const ordered = scenarios.scenario_order.filter((id) => scenarioIds.includes(id));
  // Keep any scenario present but missing from scenario_order (defensive).
  for (const id of scenarioIds) if (!ordered.includes(id)) ordered.push(id);

  const pairSummaries = [];
  const matrixCells = {}; // client -> server -> {passed, total}

  for (const client of clientLangs) {
    matrixCells[client] = {};
    for (const server of serverLangs) {
      const pairLabel = `client=${client} server=${server}`;
      const pairId = `${client}-${server}`;
      process.stdout.write(`== pair ${pairLabel} ==\n`);
      let shared = null; // lazily spawned server for non-fresh scenarios
      let passed = 0;
      for (const id of ordered) {
        const sc = { id, ...scenarios.scenarios[id] };
        // A scenario needs its own pristine server when fresh (its steps expect
        // a state change) or when it carries registry_overrides (the override
        // must be baked into the server's state file).
        const dedicated = sc.fresh || sc.registry_overrides != null;
        if (!dedicated) {
          if (!shared) shared = await spawnServer(baseStatePath, { lang: server, name: `${pairId}-shared` });
          const argv = clientArgv(client, sc, pinFor(sc, shared.pin), shared.port);
          const run = await runClient(client, argv, `${pairLabel} ${id}`, pairLabel);
          if (check(sc, run, pairLabel)) { passed++; process.stdout.write(`PASS ${id}\n`); }
        } else {
          const statePath = join(tmp, `state-${pairId}-${id}.json`);
          writeFileSync(statePath, JSON.stringify(buildStateDoc(registry, sc.registry_overrides), null, 2) + '\n');
          const srv = await spawnServer(statePath, { lang: server, name: `${pairId}-${id}` });
          const argv = clientArgv(client, sc, pinFor(sc, srv.pin), srv.port);
          const run = await runClient(client, argv, `${pairLabel} ${id}`, pairLabel);
          killTree(srv.child);
          allChildren.delete(srv.child);
          if (check(sc, run, pairLabel)) { passed++; process.stdout.write(`PASS ${id}\n`); }
        }
      }
      matrixCells[client][server] = { passed, total: ordered.length };
      pairSummaries.push({ pairLabel, passed, total: ordered.length });
      process.stdout.write(`pair ${pairLabel}: ${passed}/${ordered.length}\n`);
    }
  }

  // ---- byte-exactness phases ----
  const phaseLangs = [];
  for (const l of [...Object.keys(targets)]) if ((clientLangs.includes(l) || serverLangs.includes(l)) && !phaseLangs.includes(l)) phaseLangs.push(l);
  if (phases) {
    // Phase 1: sign-only, every selected language must reproduce the oracle.
    process.stdout.write('== sign phase ==\n');
    for (const c of signCases.cases) {
      for (const lang of phaseLangs) {
        const label = `sign ${c.id} lang=${lang}`;
        const argv = clientArgv(lang, { id: 'sign-only', identity: c.identity, args: {} }, keys.svc.public_key, 0, ['--ts', String(c.ts), '--nonce', c.nonce, '--arg', `method=${c.method}`, '--arg', `target=${c.target}`, '--arg', `body-b64u=${c.body_b64u}`]);
        signRuns++;
        const run = await runClient(lang, argv, label, `sign lang=${lang}`);
        const bad = run.failed ? run.reason
          : run.result.outcome !== 'ok' ? `outcome ${run.result.outcome}`
          : run.result.data?.signing_string !== c.expected.signing_string ? 'signing_string mismatch'
          : run.result.data?.jack_auth !== c.expected.jack_auth ? 'jack_auth mismatch'
          : run.result.data?.kid !== c.expected.kid ? 'kid mismatch'
          : null;
        if (bad) {
          failures.push({ scenario: label, pair: `lang=${lang}` });
          process.stdout.write(`FAIL ${label}\n  deviation: ${bad}\n  expected: ${JSON.stringify({ signing_string: c.expected.signing_string, jack_auth: c.expected.jack_auth, kid: c.expected.kid })}\n  actual: ${run.result ? JSON.stringify(run.result.data) : '(no result)'}\n  client stderr tail:\n${(run.stderr || '').split('\n').map((l) => '    ' + l).join('\n')}\n`);
        } else {
          process.stdout.write(`PASS ${label}\n`);
        }
      }
    }
    // Phase 2: verify-only, each signing language's header verified by each server language.
    process.stdout.write('== verify phase ==\n');
    for (const signLang of phaseLangs) {
      for (const verifyLang of serverLangs) {
        const t = resolveTarget(targets[verifyLang].server, 'server', `server=${verifyLang}`);
        const cases = [...signCases.cases.map((c) => ({ ...c, tamper: false }))];
        // Negative control: flip the last byte of the ascii-body signature once
        // per (sign, verify) pair; the server must reject with bad_signature.
        const ascii = signCases.cases.find((c) => c.id === 'ascii-body');
        const body = Buffer.from(ascii.body_b64u, 'base64url');
        body[body.length - 1] ^= 0x01;
        cases.push({ id: 'ascii-body', identity: ascii.identity, method: ascii.method, target: ascii.target, aud: ascii.aud, ts: ascii.ts, nonce: ascii.nonce, body_b64u: b64u(body), expected: ascii.expected, tamper: true });
        for (const c of cases) {
          const label = `verify ${c.id} sign=${signLang} verify=${verifyLang}`;
          let child;
          try {
            child = makeChild(t.cmd, [...t.args, '--verify-only', '--aud', c.aud, '--policy', policyPath, '--state', baseStatePath, '--server-seed-hex', keys.svc.seed_hex]);
          } catch (e) {
            fail(`cannot spawn server for verify phase (${verifyLang}): ${t.display} (${e.message})`);
          }
          allChildren.add(child);
          child.stdin.write(JSON.stringify({ method: c.method, target: c.target, jack_auth: c.expected.jack_auth, body_b64u: c.body_b64u }) + '\n');
          child.stdin.end();
          let run;
          try {
            const code = await waitClose(child, 10000, label, (e) => fail(`cannot spawn server for verify phase (${verifyLang}): ${t.display} (${e.message})`));
            const out = child._stdoutText();
            const lines = out.split('\n').filter((l) => l.trim() !== '');
            const verdict = lines.length ? JSON.parse(lines[lines.length - 1]) : null;
            run = { failed: false, verdict, exitCode: code, stderr: child._stderrTail() };
          } catch (e) {
            run = { failed: true, verdict: null, exitCode: null, stderr: child._stderrTail(), reason: e.message };
            killTree(child);
          }
          allChildren.delete(child);
          const want = c.tamper ? { verify: 'reject', code: 'bad_signature' } : { verify: 'accept', kid: c.expected.kid };
          const ok = !run.failed && run.exitCode === 0 && run.verdict && run.verdict.verify === want.verify && (c.tamper ? run.verdict.code === want.code : run.verdict.kid === want.kid);
          if (ok) {
            process.stdout.write(`PASS ${label}\n`);
          } else {
            failures.push({ scenario: label, pair: `sign=${signLang} verify=${verifyLang}` });
            process.stdout.write(`FAIL ${label}\n  expected: ${JSON.stringify(want)}\n  actual: ${JSON.stringify(run.verdict)}\n  reason: ${run.reason ?? ''}\n  server stderr tail:\n${(run.stderr || '').split('\n').map((l) => '    ' + l).join('\n')}\n`);
          }
        }
      }
    }
  }

  for (const c of allChildren) killTree(c);
  return { failures, matrixCells, pairSummaries, serversSpawned, phaseLangs, signRuns };
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

// ---- self-test ---------------------------------------------------------------

async function selfTest() {
  const fakeServer = join(SCRIPT_DIR, 'tools', 'fake-server.mjs');
  const fakeClient = join(SCRIPT_DIR, 'tools', 'fake-client.mjs');
  const targets = { fake: { server: [process.execPath, fakeServer], client: [process.execPath, fakeClient] } };
  const loaded = loadFixtures();
  let checks = 0;
  const ok = (cond, what) => {
    if (!cond) { process.stderr.write(`self-test failed: ${what}\n`); process.exit(1); }
    checks++;
    process.stdout.write(`self-test: ${what}\n`);
  };

  // 1. Full runner in-process with the fakes as a pseudo-language. Split ready
  // mode makes the fake server deliver the ready line in two chunks, exercising
  // the newline-aware parser in firstStdoutLine.
  process.env.JACK_READY_MODE = 'split';
  const res = await runMatrix({
    clientLangs: ['fake'], serverLangs: ['fake'], targets,
    scenarioFilter: ['ping', 'denied-tool', 'last-admin', 'key-not-yet-valid'], phases: true, ...loaded,
  });
  ok(res.failures.length === 0, `matrix+sign+verify phases pass with fakes (${res.failures.length} failures)`);
  ok(res.serversSpawned === 3, `exactly 3 servers spawned (shared + fresh last-admin + dedicated override key-not-yet-valid), got ${res.serversSpawned}`);
  ok(res.phaseLangs.length === 1, `sign phase ran for 1 language, 8 cases`);
  ok(res.signRuns === 8, 'sign phase ran 8 sign-only invocations (1 language x 8 cases)');

  // 1b. Override negative control: without registry_overrides erin's key is
  // already valid, so the state-dependent fake client reports the wrong code
  // and the run must fail.
  const clone = JSON.parse(JSON.stringify(loaded.scenarios));
  delete clone.scenarios['key-not-yet-valid'].registry_overrides;
  const res2 = await runMatrix({
    clientLangs: ['fake'], serverLangs: ['fake'], targets,
    scenarioFilter: ['key-not-yet-valid'], phases: false, ...loaded, scenarios: clone,
  });
  ok(res2.failures.length > 0, 'override negative control: without registry_overrides key-not-yet-valid fails');

  // 2. Negative controls run in subprocesses against a temp targets file.
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-interop-selftest-'));
  const targetsPath = join(tmp, 'targets.json');
  writeFileSync(targetsPath, JSON.stringify(targets, null, 2) + '\n');
  // Spawn run.mjs as a child and capture (exit code, stdout).
  const runChild = (args, extraEnv) => new Promise((res2) => {
    const child = spawn(process.execPath, [join(SCRIPT_DIR, 'run.mjs'), ...args], {
      cwd: REPO_ROOT, env: { ...process.env, ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    // Drain-aware capture: read `out` only after the child's stdio pipes are
    // closed ('close'), never on bare 'exit'.
    child.on('close', (c) => res2({ code: c, out }));
  });
  try {
    const code = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake', '--scenario', 'ping'], { JACK_SELFTEST_DEVIATE: 'ping' });
    ok(code.code === 1, `negative control exits 1 (got ${code.code})`);
    ok(code.out.includes('FAIL'), 'negative control prints FAIL');

    // 3. Client exiting 2 with a matching JSON result must still be a
    // harness-level failure.
    const exit2 = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake', '--scenario', 'ping'], { JACK_SELFTEST_EXIT2: 'ping' });
    ok(exit2.code === 1, `exit-2 control exits 1 (got ${exit2.code})`);
    ok(exit2.out.includes('FAIL'), 'exit-2 control prints FAIL');

    // 4. Verify-only server exiting nonzero must fail the verify phase.
    const verifyExit = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake'], { JACK_SELFTEST_VERIFY_EXIT2: '1' });
    ok(verifyExit.code === 1, `verify-exit-2 control exits 1 (got ${verifyExit.code})`);
    ok(verifyExit.out.includes('FAIL verify'), 'verify-exit-2 control prints FAIL verify');

    // 5. Authenticated 403 without a signature must surface as client_error.
    const unsig = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake', '--scenario', 'denied-tool'], { JACK_UNSIGNED_403: '1' });
    ok(unsig.code === 1, `unsigned-403 control exits 1 (got ${unsig.code})`);
    ok(unsig.out.includes('client_error'), 'unsigned-403 control reports client_error');
    ok(unsig.out.includes('missing_auth'), 'unsigned-403 control reports missing_auth');

    // 6. Blank-line-before-ready must not confuse the ready-line parser.
    const blank = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake', '--scenario', 'ping'], { JACK_READY_MODE: 'blank' });
    ok(blank.code === 0, `blank-ready control exits 0 (got ${blank.code})`);
    ok(blank.out.includes('PASS ping'), 'blank-ready control prints PASS ping');

    // 7. Exit-before-drain regression: with JACK_SELFTEST_PIPE_HOLDER the
    // fake client keeps its stdout pipe open from a grandchild process,
    // writes nothing itself, and exits; the grandchild emits the canonical
    // ping result ~300ms later. A capture resolving on 'exit' would
    // deterministically see an empty stream (the exact CI flake); only a
    // drain-aware capture passes.
    const drained = await runChild(['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake', '--scenario', 'ping'], { JACK_SELFTEST_PIPE_HOLDER: 'ping' });
    ok(drained.code === 0, `exit-before-drain control exits 0 (got ${drained.code})`);
    ok(drained.out.includes('PASS ping'), 'exit-before-drain control prints PASS ping');
  } finally {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  process.stdout.write(`self-test: ok (${checks} checks)\n`);
  process.exit(0);
}

// ---- fixtures ----------------------------------------------------------------

function loadFixtures() {
  const keysList = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'keys fixture').keys;
  const keys = Object.fromEntries(keysList.map((k) => [k.name, k]));
  const registry = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'registry.json'), 'registry fixture');
  const policy = readJson(join(REPO_ROOT, 'spec', 'fixtures', 'policy.json'), 'policy fixture');
  const scenarios = readJson(join(SCRIPT_DIR, 'scenarios.json'), 'scenarios');
  const signCases = readJson(join(SCRIPT_DIR, 'sign-cases.json'), 'sign cases');
  for (const id of Object.keys(scenarios.scenarios)) {
    const sc = scenarios.scenarios[id];
    if (!keys[sc.identity]) fail(`scenario '${id}' references unknown identity '${sc.identity}'`);
  }
  return { keys, registry, policy, scenarios, signCases };
}

// ---- main ----------------------------------------------------------------------

const cli = parseArgs(process.argv.slice(2));
const targets = readJson(cli.targets, 'targets file');
const targetKeys = Object.keys(targets);
for (const lang of targetKeys) {
  const t = targets[lang];
  if (!t || !Array.isArray(t.server) || !Array.isArray(t.client) || t.server.length === 0 || t.client.length === 0) {
    fail(`invalid targets entry for '${lang}'`);
  }
}

if (cli.list) {
  const scenarios = readJson(join(SCRIPT_DIR, 'scenarios.json'), 'scenarios');
  for (const id of scenarios.scenario_order) {
    const sc = scenarios.scenarios[id];
    if (!sc) continue;
    process.stdout.write(`${id}\tfresh=${sc.fresh}\texpected=${sc.expected.outcome}\tcode=${sc.expected.code}\n`);
  }
  for (const c of readJson(join(SCRIPT_DIR, 'sign-cases.json'), 'sign cases').cases) {
    process.stdout.write(`${c.id}\n`);
  }
  process.exit(0);
}

if (cli.selfTest) {
  await selfTest();
}

if (cli.scenario && !(readJson(join(SCRIPT_DIR, 'scenarios.json'), 'scenarios').scenarios[cli.scenario])) {
  fail(`unknown scenario '${cli.scenario}'`);
}

const loaded = loadFixtures();
const clientLangs = splitLangs(cli.clients, targetKeys, '--clients');
const serverLangs = splitLangs(cli.servers, targetKeys, '--servers');
if (clientLangs.length === 0) fail('no client languages selected');
if (serverLangs.length === 0) fail('no server languages selected');

const res = await runMatrix({
  ...loaded, targets,
  clientLangs, serverLangs,
  scenarioFilter: cli.scenario ? [cli.scenario] : null,
  phases: !cli.scenario,
});

printMatrix(res.matrixCells, serverLangs, clientLangs);
const failedPairs = new Set(res.failures.map((f) => f.pair)).size;
if (res.failures.length === 0) {
  process.stdout.write('matrix: all pairs pass\n');
  process.exit(0);
} else {
  process.stdout.write(`matrix: ${res.failures.length} failure(s) across ${failedPairs} pair(s)\n`);
  process.exit(1);
}
