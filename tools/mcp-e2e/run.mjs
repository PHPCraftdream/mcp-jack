// Dependency-free Node driver for the official MCP SDK end-to-end
// compatibility matrix (tools/mcp-e2e). Full chain per cell:
//
//   OFFICIAL stdio MCP client fixture -> `jack bridge` -> signed `jack gateway`
//   -> OFFICIAL Streamable HTTP MCP server fixture (unix socket)
//
// run as a 3x3 matrix (clients go/ts/rust x servers go/ts/rust) plus one tamper
// cell per client (server pinned to go), and driver-side GET probes recording
// the design-doc "G4" GET behaviour.
//
// Node >= 22, node: builtins only. Exit codes: 2 usage / artifact-resolution
// failure; 1 if any cell FAILED; 0 otherwise (SKIP cells allowed but reported).
//
//   node tools/mcp-e2e/run.mjs [--clients go,ts,rust] [--servers go,ts,rust] [--list] [--keep]
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createServer as httpCreateServer, request as httpRequest } from 'node:http';
import { connect as tcpConnect, createServer as tcpCreateServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---- constants ----------------------------------------------------------------

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const TS_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'ts');
const GO_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'go');
const RUST_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'rust');
const PROTO = '2025-11-25';
const LANGS = ['go', 'ts', 'rust'];
const PINS = {
  go: 'go-sdk v1.8.0',
  ts: '@modelcontextprotocol/client+server 2.4.0',
  rust: 'rmcp =3.9.0',
  protocol: '2025-11-25',
};
// Per-client GET/501 tolerance notes derived from each SDK's stream-open code
// path; printed verbatim in the G4 summary section.
const TOLERANCES = {
  go: '405 benign (connectStandaloneSSE); non-SSE 501 warns and closes, not fatal; SSE 501 fatal',
  ts: '405 benign; 501 (either content type) fatal ClientHttpFailedToOpenStream',
  rust: '405 -> ServerDoesNotSupportSse (benign); 501 (either content type) HTTP status error',
};
const USAGE = 'usage: node tools/mcp-e2e/run.mjs [--clients go,ts,rust] [--servers go,ts,rust] [--list] [--keep]';

const POLL_MS = 200;
const READY_TIMEOUT_MS = 10000;
const SDK_TIMEOUT_MS = 30000;
const STOP_GRACE_MS = 2000;
const PROBE_STEP_MS = 10000;
const PROBE_SILENCE_MS = 1500;
const GET_TIMEOUT_MS = 5000;
const TAIL_CAP = 8192; // gateway/bridge stdout+stderr tails stay bounded at 8 KB

const tracked = new Set(); // every spawned child; killed on any exit path

// Frames for the driver-side purity probe conversation over the bridge stdio.
const INIT_FRAME = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: PROTO, capabilities: {}, clientInfo: { name: 'e2e-purity-probe', version: '0.0.0' } },
};
const INITIALIZED_FRAME = { jsonrpc: '2.0', method: 'notifications/initialized' };
const LIST_FRAME = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

// ---- tiny utilities -------------------------------------------------------------

function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseJsonOr(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Content-type essence: everything before ';', trimmed, lowercased.
function essence(contentType) {
  if (typeof contentType !== 'string' || contentType === '') return '-';
  return contentType.split(';')[0].trim().toLowerCase();
}

// Configs and other driver-written private files: mode 0600 (the jack CLI
// rejects anything else).
function writePrivate(path, content) {
  writeFileSync(path, content);
  chmodSync(path, 0o600);
}

// Clip long text for expected-vs-actual report lines.
function clipText(text, emptyLabel) {
  if (text === undefined || text === null || text === '') return emptyLabel;
  const t = text.length > 120 ? `${text.slice(0, 117)}...` : text;
  return JSON.stringify(t);
}

// ---- cli --------------------------------------------------------------------

function parseArgs(argv) {
  const out = { clients: null, servers: null, list: false, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const val = () => {
      i += 1;
      if (i >= argv.length) fail(`missing value for ${flag}\n${USAGE}`);
      return argv[i];
    };
    switch (flag) {
      case '--clients': out.clients = val(); break;
      case '--servers': out.servers = val(); break;
      case '--list': out.list = true; break;
      case '--keep': out.keep = true; break;
      default: fail(`unknown flag: ${flag}\n${USAGE}`);
    }
  }
  return out;
}

function splitLangs(value, all, flag) {
  if (value === null) return [...all];
  const parts = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const p of parts) {
    if (!all.includes(p)) fail(`unknown ${flag} language '${p}' (known: ${all.join(', ')})\n${USAGE}`);
  }
  return parts;
}

// ---- child process helpers ------------------------------------------------------

// Spawn with stdio pipes and continuous drain from the first byte: pipes never
// back up and captured tails stay capped. `close` (not `exit`) is the capture
// barrier — all stdio pipes are drained only after `close`.
function makeChild(cmd, args, opts = {}) {
  const cap = typeof opts.cap === 'number' ? opts.cap : TAIL_CAP;
  const child = spawn(cmd, args, {
    cwd: REPO_ROOT,
    env: opts.env ? { ...process.env, ...opts.env } : process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let stdout = '';
  let stderr = '';
  let stdoutBytes = 0;
  child.stdout.on('data', (d) => {
    stdoutBytes += d.length;
    stdout = (stdout + d.toString('utf8')).slice(-cap);
  });
  child.stderr.on('data', (d) => {
    stderr = (stderr + d.toString('utf8')).slice(-cap);
  });
  // Consuming 'error' keeps spawn failures (ENOENT) from crashing the driver;
  // _failed surfaces them to whoever is waiting.
  child._failed = new Promise((res) => {
    child.once('error', res);
  });
  // EPIPE after child death is expected; the write callback carries the error.
  child.stdin.on('error', () => {});
  child._stdout = () => stdout;
  child._stderr = () => stderr;
  child._stdoutBytes = () => stdoutBytes;
  child._close = new Promise((res) => {
    child.once('close', (code, signal) => res({ code, signal }));
  });
  tracked.add(child);
  return child;
}

// SIGTERM, wait STOP_GRACE_MS, then SIGKILL if still alive.
async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill('SIGTERM');
  } catch {
    return;
  }
  const gone = await Promise.race([child._close.then(() => true), sleep(STOP_GRACE_MS).then(() => false)]);
  if (gone) return;
  try {
    child.kill('SIGKILL');
  } catch { /* already dead */ }
  await Promise.race([child._close, sleep(STOP_GRACE_MS)]);
}

// ---- readiness waits --------------------------------------------------------------

function freePort() {
  return new Promise((res, rej) => {
    const srv = tcpCreateServer();
    srv.once('error', rej);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => res(port));
    });
  });
}

async function waitForFile(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      statSync(path);
      return true;
    } catch { /* not there yet */ }
    if (Date.now() >= deadline) return false;
    await sleep(POLL_MS);
  }
}

async function waitForTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const open = await new Promise((res) => {
      const s = tcpConnect({ host: '127.0.0.1', port });
      const t = setTimeout(() => {
        s.destroy();
        res(false);
      }, POLL_MS);
      s.once('connect', () => {
        clearTimeout(t);
        s.destroy();
        res(true);
      });
      s.once('error', () => {
        clearTimeout(t);
        res(false);
      });
    });
    if (open) return true;
    if (Date.now() >= deadline) return false;
    await sleep(POLL_MS);
  }
}

// One-shot raw HTTP request; resolves with {status, contentType, body} or
// {error} instead of rejecting so callers can record transport errors.
function rawRequest(options, timeoutMs) {
  return new Promise((resolve) => {
    // agent:false keeps the one-shot socket off the keep-alive pool so the
    // driver can exit deterministically once everything is torn down.
    const req = httpRequest({ ...options, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, contentType: res.headers['content-type'] ?? null, body: Buffer.concat(chunks) }));
      res.on('error', (e) => resolve({ error: e.message }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timeout after ${timeoutMs}ms`)));
    req.on('error', (e) => resolve({ error: e.message }));
    req.end();
  });
}

// ---- capture/tamper proxy ------------------------------------------------------

// Forwarding capture proxy: one upstream request per client request, response
// buffered and replayed with the upstream status/headers. In tamper mode the
// response's first byte '{' -> '[' is flipped on a same-length Buffer copy so
// the upstream content-length header stays valid for the client.
function startProxy(proxyPort, gwPort, tamper) {
  const captures = [];
  const server = httpCreateServer((req, res) => {
    req.on('error', () => {
      try {
        res.destroy();
      } catch { /* client gone */ }
    });
    res.on('error', () => { /* client vanished mid-response */ });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const entry = {
        method: req.method,
        path: req.url,
        accept: typeof req.headers.accept === 'string' ? req.headers.accept : null,
        content_type: typeof req.headers['content-type'] === 'string' ? req.headers['content-type'] : null,
        mcp_protocol_version: typeof req.headers['mcp-protocol-version'] === 'string' ? req.headers['mcp-protocol-version'] : null,
        has_jack_auth: req.headers['jack-auth'] !== undefined,
        request_body: Buffer.concat(chunks).toString('utf8'),
      };
      const upstream = httpRequest(
        {
          host: '127.0.0.1',
          port: gwPort,
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: `127.0.0.1:${gwPort}` },
          agent: false,
        },
        (up) => {
          const out = [];
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            const body = Buffer.concat(out);
            entry.status = up.statusCode;
            entry.response_content_type = typeof up.headers['content-type'] === 'string' ? up.headers['content-type'] : null;
            entry.response_body = body.toString('utf8');
            let send = body;
            if (tamper && send.length > 0 && send[0] === 0x7b) {
              send = Buffer.from(send); // same-length copy: content-length stays valid
              send[0] = 0x5b;
              entry.tampered = true;
            }
            captures.push(entry);
            const headers = {};
            for (const [k, v] of Object.entries(up.headers)) {
              if (v !== undefined) headers[k] = v;
            }
            try {
              res.writeHead(up.statusCode, headers);
              res.end(send);
            } catch { /* client already gone */ }
          };
          up.on('data', (c) => out.push(c));
          up.on('end', finish);
          up.on('error', (e) => {
            if (done) return;
            done = true;
            entry.error = e.message;
            captures.push(entry);
            res.destroy();
          });
        },
      );
      upstream.on('error', (e) => {
        entry.error = e.message;
        captures.push(entry);
        try {
          res.writeHead(502, { 'content-type': 'text/plain' });
          res.end('mcp-e2e proxy: upstream request failed');
        } catch { /* client already gone */ }
      });
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(proxyPort, '127.0.0.1', () => {
      server.off('error', reject);
      server.on('error', () => { /* late socket errors must not kill the run */ });
      resolve({
        port: proxyPort,
        captures,
        close: () => new Promise((done) => {
          if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
          server.close(() => done());
        }),
      });
    });
  });
}

// ---- purity probe (framing oracle) ------------------------------------------------

// write a newline-delimited JSON frame; rejects via the write callback on EPIPE.
function writeFrame(child, frame) {
  return new Promise((resolve, reject) => {
    child.stdin.write(JSON.stringify(frame) + '\n', (e) => (e ? reject(e) : resolve()));
  });
}

// Complete-line collector over bridge stdout with per-step timeouts. Only
// newline-terminated lines count; unterminated remainders surface via
// `partial` at the end-of-conversation checks.
function makeFrameCollector(child) {
  let partial = '';
  const lines = [];
  let waiter = null;
  child.stdout.on('data', (d) => {
    partial += d.toString('utf8');
    let idx;
    while ((idx = partial.indexOf('\n')) !== -1) {
      lines.push(partial.slice(0, idx));
      partial = partial.slice(idx + 1);
    }
    if (waiter && lines.length >= waiter.need) {
      const w = waiter;
      waiter = null;
      w.resolve();
    }
  });
  return {
    count: () => lines.length,
    line: (i) => lines[i],
    waitLines(need, timeoutMs, label) {
      if (lines.length >= need) return Promise.resolve();
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn, arg) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          waiter = null;
          fn(arg);
        };
        const timer = setTimeout(
          () => finish(reject, new Error(`${label}: timeout after ${timeoutMs}ms (want frame ${need}, have ${lines.length})`)),
          timeoutMs,
        );
        child._close.then((r) => finish(reject, new Error(`${label}: bridge exited early (code ${r.code} signal ${r.signal}) with ${lines.length} frame(s); stderr tail: ${child._stderr().trim()}`)));
        waiter = { need, resolve: () => finish(resolve) };
      });
    },
  };
}

// A probe frame must be a bare JSON-RPC response object: jsonrpc 2.0, scalar
// id, and never a method field (requests never travel upstream->bridge).
function frameViolation(line) {
  const o = parseJsonOr(line);
  if (!o || typeof o !== 'object' || Array.isArray(o)) return 'not a JSON object';
  if (o.jsonrpc !== '2.0') return `jsonrpc ${JSON.stringify(o.jsonrpc)}`;
  if (!('id' in o) || (typeof o.id !== 'number' && typeof o.id !== 'string')) return 'id missing or not numeric/string';
  if ('method' in o) return 'response carries a method field';
  return null;
}

// Driver-side framing/purity oracle: raw newline-delimited JSON over the
// bridge stdio — explicitly NOT an official MCP client. `tamper` switches to
// the negative variant: the flipped response must fail the bridge's response
// verification locally (exit 1, zero stdout, exact diagnostic).
async function runPurityProbe(chk, jackBin, configPath, marker, tamper) {
  const child = makeChild(jackBin, ['bridge', '--config', configPath]);
  try {
    if (tamper) {
      try {
        await writeFrame(child, INIT_FRAME);
      } catch (e) {
        chk.bad(`tamper probe: bridge stdin write failed: ${e.message}`);
        return;
      }
      const outcome = await Promise.race([
        child._close.then((r) => ({ kind: 'close', ...r })),
        sleep(PROBE_STEP_MS).then(() => ({ kind: 'timeout' })),
      ]);
      if (outcome.kind === 'timeout') {
        chk.bad('tamper probe: bridge did not exit within 10s after the tampered initialize');
        return;
      }
      chk.must(outcome.code === 1, 'tamper probe bridge exit code', '1', String(outcome.code));
      chk.must(child._stdoutBytes() === 0, 'tamper probe bridge stdout bytes', '0', String(child._stdoutBytes()));
      const tail = child._stderr().trim();
      chk.must(
        tail === 'jack: remote call failed; no retry performed',
        'tamper probe bridge stderr',
        "'jack: remote call failed; no retry performed'",
        clipText(tail, "''"),
      );
      return;
    }

    const frames = makeFrameCollector(child);
    try {
      await writeFrame(child, INIT_FRAME);
      await frames.waitLines(1, PROBE_STEP_MS, 'probe initialize response');
      const r1 = parseJsonOr(frames.line(0));
      chk.must(
        r1 && r1.jsonrpc === '2.0' && r1.id === 1 && !('error' in r1) && r1.result && r1.result.protocolVersion === PROTO,
        'probe initialize response shape',
        `id=1 result.protocolVersion=${PROTO} no error`,
        clipText(frames.line(0), '(no frame)'),
      );
      chk.must(frames.count() === 1, 'probe stdout frames after initialize', 'exactly 1', String(frames.count()));

      await writeFrame(child, INITIALIZED_FRAME);
      await sleep(PROBE_SILENCE_MS);
      chk.must(frames.count() === 1, 'probe silence after notifications/initialized', 'no new frame within 1.5s', `${frames.count()} frame(s)`);

      await writeFrame(child, LIST_FRAME);
      await frames.waitLines(2, PROBE_STEP_MS, 'probe tools/list response');
      const r2 = parseJsonOr(frames.line(1));
      const tools = r2 && r2.result && Array.isArray(r2.result.tools) ? r2.result.tools : null;
      chk.must(
        r2 && r2.jsonrpc === '2.0' && r2.id === 2 && !('error' in r2) && tools && tools.some((t) => t && t.name === 'echo'),
        'probe tools/list response shape',
        "id=2 result.tools includes 'echo'",
        clipText(frames.line(1), '(no frame)'),
      );
      chk.must(frames.count() === 2, 'probe stdout frames after tools/list', 'exactly 2', String(frames.count()));

      await writeFrame(child, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: marker } } });
      await frames.waitLines(3, PROBE_STEP_MS, 'probe tools/call response');
      const r3 = parseJsonOr(frames.line(2));
      chk.must(
        r3 && r3.jsonrpc === '2.0' && r3.id === 3 && !('error' in r3) && JSON.stringify(r3).includes(marker),
        'probe tools/call response shape',
        `id=3 no error, contains ${marker}`,
        clipText(frames.line(2), '(no frame)'),
      );
      chk.must(frames.count() === 3, 'probe stdout frames after tools/call', 'exactly 3', String(frames.count()));

      child.stdin.end();
      const done = await Promise.race([
        child._close.then((r) => ({ kind: 'close', ...r })),
        sleep(PROBE_STEP_MS).then(() => ({ kind: 'timeout' })),
      ]);
      if (done.kind === 'timeout') throw new Error('bridge did not exit within 10s after stdin closed');
      chk.must(done.code === 0, 'probe bridge exit code', '0', String(done.code));
      chk.must(child._stderr().length === 0, 'probe bridge stderr empty', "''", clipText(child._stderr(), "''"));

      const parts = child._stdout().split('\n');
      const trailing = parts.pop();
      chk.must(trailing === '', 'probe stdout fully newline-terminated', "'' trailing", trailing === undefined ? '(empty stdout)' : clipText(trailing, "''"));
      chk.must(parts.length === 3, 'probe stdout total frames', 'exactly 3', String(parts.length));
      for (let i = 0; i < parts.length; i++) {
        const v = frameViolation(parts[i]);
        chk.must(v === null, `probe frame ${i} is a bare JSON-RPC response object`, 'valid response object', v ?? 'valid');
      }
    } catch (e) {
      throw new CellFail(`probe conversation aborted: ${e.message}`);
    }
  } finally {
    if (child.exitCode === null && child.signalCode === null) await stopChild(child);
  }
}

// ---- artifact resolution -----------------------------------------------------------

// env override probe: {set, ok, path} so "set but missing" can downgrade the
// whole language to SKIP-able unavailability instead of silently building.
function envArtifact(name) {
  const v = process.env[name];
  if (v === undefined || v === '') return { set: false, ok: false, path: null };
  return { set: true, ok: existsSync(v), path: v };
}

// Prebuilt probe for rust release binaries; cargo emits '<name>.exe' on Windows.
function probeRustBinary(base) {
  if (existsSync(base)) return base;
  if (process.platform === 'win32' && existsSync(`${base}.exe`)) return `${base}.exe`;
  return null;
}

function buildOr(cmd, args, cwd, what) {
  process.stderr.write(`building ${what}: ${cmd} ${args.join(' ')} (cwd ${cwd})\n`);
  try {
    execFileSync(cmd, args, { cwd, stdio: 'pipe' });
  } catch (e) {
    const tail = e.stderr ? e.stderr.toString().trim() : '';
    fail(`${what} build failed:\n${tail !== '' ? tail : e.message}`);
  }
}

function resolveGoFixtures(ensureBuildDir, event) {
  const client = envArtifact('GO_CLIENT_BIN');
  const server = envArtifact('GO_SERVER_BIN');
  const envReason = client.set && !client.ok ? `GO_CLIENT_BIN set but missing: ${client.path}`
    : server.set && !server.ok ? `GO_SERVER_BIN set but missing: ${server.path}` : null;
  if (envReason !== null) return { ok: false, client: null, server: null, reason: envReason };
  if (client.ok && server.ok) {
    event(`go client: ${client.path}`);
    event(`go server: ${server.path}`);
    return { ok: true, client: client.path, server: server.path, reason: null };
  }
  if (!existsSync(join(GO_DIR, 'go.sum'))) {
    fail('missing tools/mcp-e2e/go/go.sum - the parent must generate and commit it');
  }
  const buildDir = ensureBuildDir();
  let outClient = client.path;
  let outServer = server.path;
  if (!client.ok) {
    outClient = join(buildDir, 'mcp-e2e-go-client');
    buildOr('go', ['build', '-o', outClient, './cmd/client'], GO_DIR, 'go client');
    event(`go client: ${outClient} (built)`);
  }
  if (!server.ok) {
    outServer = join(buildDir, 'mcp-e2e-go-server');
    buildOr('go', ['build', '-o', outServer, './cmd/server'], GO_DIR, 'go server');
    event(`go server: ${outServer} (built)`);
  }
  return { ok: true, client: outClient, server: outServer, reason: null };
}

function resolveRustFixtures(event) {
  const client = envArtifact('RUST_CLIENT_BIN');
  const server = envArtifact('RUST_SERVER_BIN');
  const envReason = client.set && !client.ok ? `RUST_CLIENT_BIN set but missing: ${client.path}`
    : server.set && !server.ok ? `RUST_SERVER_BIN set but missing: ${server.path}` : null;
  if (envReason !== null) return { ok: false, client: null, server: null, reason: envReason };
  if (client.ok && server.ok) {
    event(`rust client: ${client.path}`);
    event(`rust server: ${server.path}`);
    return { ok: true, client: client.path, server: server.path, reason: null };
  }
  // Prebuilt probe first: use the release pair if both exist, no lockfile
  // required; only the build path demands a committed Cargo.lock.
  const probe = (kind) => probeRustBinary(join(RUST_DIR, 'target', 'release', `mcp-e2e-rust-${kind}`));
  let preClient = probe('client');
  let preServer = probe('server');
  if (preClient === null || preServer === null) {
    if (!existsSync(join(RUST_DIR, 'Cargo.lock'))) {
      fail('missing tools/mcp-e2e/rust/Cargo.lock - the parent must generate and commit it');
    }
    buildOr('cargo', ['build', '--locked', '--release'], RUST_DIR, 'rust fixtures');
    preClient = probe('client');
    preServer = probe('server');
    if (preClient === null || preServer === null) {
      fail('cargo build succeeded but tools/mcp-e2e/rust/target/release/mcp-e2e-rust-{client,server} not found');
    }
    event(`rust client: ${preClient} (built)`);
    event(`rust server: ${preServer} (built)`);
  } else {
    event(`rust client: ${preClient} (prebuilt)`);
    event(`rust server: ${preServer} (prebuilt)`);
  }
  return { ok: true, client: client.ok ? client.path : preClient, server: server.ok ? server.path : preServer, reason: null };
}

function resolveTsFixtures(event) {
  const entry = join(TS_DIR, 'node_modules', '@modelcontextprotocol', 'client', 'package.json');
  if (!existsSync(entry)) {
    if (!existsSync(join(TS_DIR, 'package-lock.json'))) {
      fail('missing tools/mcp-e2e/ts/package-lock.json - the parent must generate and commit it');
    }
    buildOr('npm', ['ci', '--no-audit', '--no-fund'], TS_DIR, 'ts fixtures');
    if (!existsSync(entry)) fail('npm ci completed but tools/mcp-e2e/ts/node_modules/@modelcontextprotocol/client is still missing');
    event('ts fixtures: npm ci installed node_modules');
  } else {
    event(`ts fixtures: ${entry}`);
  }
  return { ok: true, client: join(TS_DIR, 'client.mjs'), server: join(TS_DIR, 'server.mjs'), reason: null };
}

// Only languages that at least one selected cell needs are resolved: a
// filtered run (--clients go --servers go) must not demand a rust toolchain.
// The tamper cells pin the server to go, so go is always needed.
function resolveArtifacts(workDir, needed) {
  let buildDir = null;
  const ensureBuildDir = () => {
    if (buildDir === null) {
      buildDir = join(workDir, 'build');
      mkdirSync(buildDir, { recursive: true, mode: 0o700 });
      chmodSync(buildDir, 0o700);
    }
    return buildDir;
  };
  const event = (line) => process.stderr.write(`artifact ${line}\n`);

  let jackBin = process.env.JACK_BIN;
  let jackBuilt = false;
  if (jackBin !== undefined && jackBin !== '') {
    if (!existsSync(jackBin)) fail(`JACK_BIN set but missing: ${jackBin}`);
    event(`jack: ${jackBin}`);
  } else {
    jackBin = join(ensureBuildDir(), 'jack');
    buildOr('go', ['build', '-o', jackBin, './cmd/jack'], REPO_ROOT, 'jack');
    jackBuilt = true;
    event(`jack: ${jackBin} (built)`);
  }

  const fixtures = {
    go: { ok: true, client: null, server: null, reason: null },
    ts: { ok: true, client: null, server: null, reason: null },
    rust: { ok: true, client: null, server: null, reason: null },
  };
  if (needed.has('go')) fixtures.go = resolveGoFixtures(ensureBuildDir, event);
  if (needed.has('rust')) fixtures.rust = resolveRustFixtures(event);
  if (needed.has('ts')) fixtures.ts = resolveTsFixtures(event);
  return { jack: jackBin, jackBuilt, fixtures };
}

// ---- per-cell runner -----------------------------------------------------------------

class CellFail extends Error {}

function makeChecks() {
  const lines = [];
  let failed = false;
  const push = (prefix, text) => {
    lines.push(`${prefix} ${text}`);
    if (prefix === 'FAIL') failed = true;
  };
  return {
    ok: (text) => push('OK', text),
    bad: (text) => push('FAIL', text),
    note: (text) => push('INFO', text),
    // must: record and continue (independent checks).
    must(cond, name, expected, actual) {
      if (cond) this.ok(name);
      else this.bad(`${name} (expected ${expected}, got ${actual})`);
      return cond;
    },
    // fatal: record-and-abort; runCell turns the CellFail into the FAIL line.
    fatal(cond, name, expected, actual) {
      if (cond) {
        this.ok(name);
        return true;
      }
      throw new CellFail(`${name} (expected ${expected}, got ${actual})`);
    },
    pass: () => !failed,
    lines: () => [...lines],
  };
}

// jack CLI via spawnSync; non-zero exit aborts the cell with the documented
// `jack <subcommand> failed: <stderr tail>` message.
function runJack(jackBin, args, sub) {
  const r = spawnSync(jackBin, args, { cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true });
  if (r.error) throw new CellFail(`jack ${sub} failed: could not spawn (${r.error.message})`);
  if (r.status !== 0) throw new CellFail(`jack ${sub} failed: ${(r.stderr ?? '').trim()}`);
}

function clientArgv(lang, jackBin, configPath, marker, artifacts) {
  const f = artifacts.fixtures[lang];
  switch (lang) {
    case 'go': return { cmd: f.client, args: [jackBin, configPath, marker] };
    case 'ts': return { cmd: process.execPath, args: [join(TS_DIR, 'client.mjs'), jackBin, configPath, marker] };
    case 'rust': return { cmd: f.client, args: [jackBin, configPath, marker] };
    default: throw new CellFail(`unknown client language ${lang}`);
  }
}

function serverArgv(lang, sockPath, artifacts) {
  const f = artifacts.fixtures[lang];
  switch (lang) {
    case 'go': return { cmd: f.server, args: [sockPath] };
    case 'ts': return { cmd: process.execPath, args: [join(TS_DIR, 'server.mjs'), sockPath] };
    case 'rust': return { cmd: f.server, args: [sockPath] };
    default: throw new CellFail(`unknown server language ${lang}`);
  }
}

function cellName(cell) {
  return `${cell.client}-client x ${cell.server}-server${cell.tamper ? ' tamper' : ''}`;
}

// SDK client fixture run with SIGTERM-then-SIGKILL escalation at the timeout.
// A timeout is reported as code null (killed); spawn errors as kind spawn_error.
async function runSdkClient(argv, timeoutMs) {
  const child = makeChild(argv.cmd, argv.args, { cap: 65536 });
  const outcome = await Promise.race([
    child._close.then((r) => ({ kind: 'close', ...r })),
    child._failed.then((e) => ({ kind: 'spawn_error', error: e })),
    sleep(timeoutMs).then(() => ({ kind: 'timeout' })),
  ]);
  if (outcome.kind === 'spawn_error') return { kind: 'spawn_error', message: outcome.error.message };
  let code;
  if (outcome.kind === 'timeout') {
    await stopChild(child);
    code = null;
  } else {
    code = outcome.code;
  }
  return { kind: 'run', code, stdout: child._stdout(), stderr: child._stderr() };
}

// Hop assertions over the SDK client's captures (snapshot taken before the
// purity probe ran, so the probe's own traffic cannot pollute the count).
function assertHops(chk, g4, captures, marker) {
  g4.bridge_get_count = captures.filter((c) => c.method !== 'POST').length;
  chk.fatal(captures.length === 4, 'proxy captured exactly the 4 SDK client requests', '4', String(captures.length));
  chk.fatal(g4.bridge_get_count === 0, 'bridge never GETs (all captured methods POST)', '0 GET requests', `${g4.bridge_get_count} non-POST capture(s) among ${captures.length}`);
  for (let i = 0; i < captures.length; i++) {
    const cap = captures[i];
    chk.fatal(cap.has_jack_auth === true, `hop ${i} carries Jack-Auth`, 'true', String(cap.has_jack_auth));
    const accept = typeof cap.accept === 'string' ? cap.accept.toLowerCase() : '';
    chk.fatal(
      accept.includes('application/json') && accept.includes('text/event-stream'),
      `hop ${i} accept advertises json+event-stream`,
      'both values',
      String(cap.accept),
    );
  }
  const [h0, h1, h2, h3] = captures;

  const b0 = parseJsonOr(h0.request_body);
  chk.fatal(b0 && b0.method === 'initialize', 'hop 0 method initialize', 'initialize', clipText(h0.request_body, "''"));
  chk.fatal(b0 && b0.params && b0.params.protocolVersion === PROTO, 'hop 0 requests protocolVersion 2025-11-25', PROTO, b0 && b0.params ? String(b0.params.protocolVersion) : '-');
  chk.fatal(h0.status === 200, 'hop 0 status', '200', String(h0.status));
  chk.fatal(essence(h0.response_content_type) === 'application/json', 'hop 0 response content-type essence', 'application/json', essence(h0.response_content_type));
  const r0 = parseJsonOr(h0.response_body);
  chk.fatal(r0 && r0.result && r0.result.protocolVersion === PROTO, 'hop 0 response protocolVersion', PROTO, r0 && r0.result ? String(r0.result.protocolVersion) : '-');
  chk.fatal(b0 && r0 && b0.id === r0.id, 'hop 0 response id echoes request id', String(b0 ? b0.id : '-'), String(r0 ? r0.id : '-'));

  const b1 = parseJsonOr(h1.request_body);
  chk.fatal(b1 && b1.method === 'notifications/initialized' && !('id' in b1), 'hop 1 notification without id', 'notifications/initialized, no id', clipText(h1.request_body, "''"));
  chk.fatal(h1.status === 202, 'hop 1 status', '202', String(h1.status));
  chk.fatal(h1.response_body.length === 0, 'hop 1 response body empty', '0 bytes', `${h1.response_body.length} bytes`);

  const b2 = parseJsonOr(h2.request_body);
  chk.fatal(b2 && b2.method === 'tools/list', 'hop 2 method tools/list', 'tools/list', clipText(h2.request_body, "''"));
  chk.fatal(h2.status === 200, 'hop 2 status', '200', String(h2.status));
  chk.fatal(essence(h2.response_content_type) === 'application/json', 'hop 2 response content-type essence', 'application/json', essence(h2.response_content_type));
  const r2 = parseJsonOr(h2.response_body);
  const tools = r2 && r2.result && Array.isArray(r2.result.tools) ? r2.result.tools : null;
  chk.fatal(tools && tools.some((t) => t && t.name === 'echo'), 'hop 2 tools include echo', "tools[] name 'echo'", tools ? `[${tools.map((t) => (t && t.name) ?? '-').join(',')}]` : '-');

  const b3 = parseJsonOr(h3.request_body);
  chk.fatal(b3 && b3.method === 'tools/call', 'hop 3 method tools/call', 'tools/call', clipText(h3.request_body, "''"));
  chk.fatal(b3 && b3.params && b3.params.name === 'echo', 'hop 3 calls echo', 'echo', b3 && b3.params ? String(b3.params.name) : '-');
  chk.fatal(
    b3 && b3.params && b3.params.arguments && b3.params.arguments.text === marker,
    'hop 3 carries the marker argument',
    marker,
    b3 && b3.params && b3.params.arguments ? String(b3.params.arguments.text) : '-',
  );
  chk.fatal(h3.status === 200, 'hop 3 status', '200', String(h3.status));
  const r3 = parseJsonOr(h3.response_body);
  chk.fatal(
    r3 && !r3.error && JSON.stringify(r3).includes(marker),
    'hop 3 response ok and contains marker',
    `no error, contains ${marker}`,
    r3 ? (r3.error ? `error ${JSON.stringify(r3.error)}` : 'marker missing from response') : 'body not JSON',
  );
  chk.ok('hop assertions: 4 signed POSTs verified (initialize, notifications/initialized, tools/list, tools/call)');
}

// G4 GET probes: raw upstream GET over the official server's unix socket and
// an unauthenticated gateway GET. ts upstream GET is recorded only (source
// leaves its stateless GET behaviour open); go/rust and the gateway 401 are
// asserted. Transport errors are recorded; only asserted probes FAIL.
async function getProbes(chk, g4, sockPath, gwPort, serverLang) {
  const up = await rawRequest(
    { socketPath: sockPath, path: '/mcp', method: 'GET', headers: { accept: 'text/event-stream', 'mcp-protocol-version': PROTO } },
    GET_TIMEOUT_MS,
  );
  g4.upstream_status = up.error ? '-' : String(up.status);
  g4.upstream_ct = up.error ? '-' : essence(up.contentType);
  const bodyHead = up.error ? '-' : up.body.toString('utf8').slice(0, 80);
  chk.note(`upstream GET raw: status=${g4.upstream_status} content_type=${g4.upstream_ct} body[:80]=${JSON.stringify(bodyHead)}`);
  if (serverLang === 'ts') {
    if (up.error) chk.note(`upstream GET transport error recorded: ${up.error}`);
    else chk.note(`upstream GET recorded, not asserted for ts server: status=${up.status}`);
  } else {
    chk.must(!up.error && up.status === 405, 'upstream GET rejected with stateless 405', '405', up.error ? `transport error: ${up.error}` : String(up.status));
  }

  const gg = await rawRequest(
    { host: '127.0.0.1', port: gwPort, path: '/mcp', method: 'GET', headers: { accept: 'application/json, text/event-stream' } },
    GET_TIMEOUT_MS,
  );
  g4.gateway_status = gg.error ? '-' : String(gg.status);
  chk.must(!gg.error && gg.status === 401, 'gateway GET unauthenticated rejected with 401', '401', gg.error ? `transport error: ${gg.error}` : String(gg.status));
}

async function runCellFlow(ctx) {
  const { chk, g4, client, server, tamper, artifacts, cellDir, index, jackBin } = ctx;
  const held = ctx.held;

  // Short file names keep the unix socket path well under the sun_path limit.
  const S_KEY = join(cellDir, 'server.key');
  const S_PUB = join(cellDir, 'server.pub.json');
  const U_KEY = join(cellDir, 'user.key');
  const U_PUB = join(cellDir, 'user.pub.json');
  const STATE = join(cellDir, 'state.json');
  const INVITE = join(cellDir, 'invite.code');
  const GW_JSON = join(cellDir, 'gateway.json');
  const CLIENT_JSON = join(cellDir, 'client.json');
  const SOCK = join(cellDir, 'mcp.sock');
  const SERVER_LOG = join(cellDir, 'server.jsonl');

  mkdirSync(cellDir, { recursive: true, mode: 0o700 });
  chmodSync(cellDir, 0o700);

  // ---- provisioning ----
  runJack(jackBin, ['keygen', 'server', '--secret', S_KEY, '--public', S_PUB], 'keygen server');
  runJack(jackBin, ['keygen', 'user', '--secret', U_KEY, '--public', U_PUB], 'keygen user');
  runJack(jackBin, ['bootstrap', '--state', STATE, '--invite-file', INVITE], 'bootstrap');
  const serverPub = parseJsonOr(readFileSync(S_PUB, 'utf8'));
  chk.fatal(
    serverPub && typeof serverPub.server_public_key === 'string' && typeof serverPub.server_kid === 'string',
    'server public file has server_public_key and server_kid',
    'both present',
    serverPub ? 'fields missing or non-string' : 'file is not JSON',
  );

  // ---- ports and gateway config ----
  const gwPort = await freePort();
  const proxyPort = await freePort();
  const gatewayConfig = {
    version: 1,
    aud: 'e2e',
    server_seed_file: S_KEY,
    state_file: STATE,
    listen: `127.0.0.1:${gwPort}`,
    upstream_socket: SOCK,
    upstream_url: 'http://upstream/mcp',
    call_timeout_ms: 10000,
    max_concurrent: 8,
  };
  writePrivate(GW_JSON, JSON.stringify(gatewayConfig) + '\n');

  // ---- official upstream server fixture ----
  const srvArgv = serverArgv(server, SOCK, artifacts);
  const serverChild = makeChild(srvArgv.cmd, srvArgv.args, { env: { E2E_SERVER_LOG: SERVER_LOG } });
  held.serverChild = serverChild;
  const srvStart = await Promise.race([
    waitForFile(SOCK, READY_TIMEOUT_MS).then((ok) => ({ kind: ok ? 'ready' : 'timeout' })),
    serverChild._close.then((r) => ({ kind: 'exit', ...r })),
  ]);
  if (srvStart.kind === 'exit') {
    throw new CellFail(`official server exited before binding ${SOCK} (code ${srvStart.code} signal ${srvStart.signal})\nstderr tail:\n${serverChild._stderr()}`);
  }
  if (srvStart.kind === 'timeout') {
    throw new CellFail(`official server did not bind ${SOCK} within 10s\nstderr tail:\n${serverChild._stderr()}`);
  }
  chk.ok(`official server bound ${SOCK}`);

  // ---- signed gateway ----
  const gw = makeChild(jackBin, ['gateway', '--config', GW_JSON]);
  held.gatewayChild = gw;
  const gwStart = await Promise.race([
    waitForTcp(gwPort, READY_TIMEOUT_MS).then((ok) => ({ kind: ok ? 'ready' : 'timeout' })),
    gw._close.then((r) => ({ kind: 'exit', ...r })),
    gw._failed.then((e) => ({ kind: 'spawn_error', error: e })),
  ]);
  if (gwStart.kind === 'exit') {
    throw new CellFail(`gateway exited during startup (code ${gwStart.code} signal ${gwStart.signal})\nstderr tail:\n${gw._stderr()}`);
  }
  if (gwStart.kind === 'spawn_error') throw new CellFail(`gateway spawn error: ${gwStart.error.message}`);
  if (gwStart.kind === 'timeout') {
    throw new CellFail(`gateway did not listen on 127.0.0.1:${gwPort} within 10s\nstderr tail:\n${gw._stderr()}`);
  }
  chk.ok(`gateway listening on 127.0.0.1:${gwPort}`);

  // ---- client config: enroll hits the gateway directly (proxy not in path yet) ----
  const clientConfig = {
    version: 1,
    endpoint: `http://127.0.0.1:${gwPort}/mcp`,
    aud: 'e2e',
    server_public_key: serverPub.server_public_key,
    server_kid: serverPub.server_kid,
    key_file: U_KEY,
    key_format: 'raw-seed',
    call_timeout_ms: 10000,
  };
  writePrivate(CLIENT_JSON, JSON.stringify(clientConfig) + '\n');
  runJack(jackBin, ['enroll', '--config', CLIENT_JSON, '--invite-file', INVITE, '--name', 'e2e-user'], 'enroll');
  chk.ok('jack enroll signed a tools/call through the gateway');

  // ---- capture/tamper proxy in front of the gateway; repoint the client ----
  const proxy = await startProxy(proxyPort, gwPort, tamper);
  held.proxy = proxy;
  clientConfig.endpoint = `http://127.0.0.1:${proxyPort}/mcp`;
  writePrivate(CLIENT_JSON, JSON.stringify(clientConfig) + '\n');

  // ---- official SDK client run: client fixture -> bridge -> gateway -> upstream ----
  const marker = `e2e-${client}-${server}-${process.pid}-${index}`;
  const cliArgv = clientArgv(client, jackBin, CLIENT_JSON, marker, artifacts);
  const run = await runSdkClient(cliArgv, SDK_TIMEOUT_MS);
  if (run.kind === 'spawn_error') {
    chk.fatal(false, 'official client fixture spawned', 'child process started', `spawn error: ${run.message}`);
  }
  const code = run.code;
  // Диагностика: хвосты stdout/stderr SDK-клиента всегда видны в логе CI.
  chk.note(`client stderr tail: ${JSON.stringify(run.stderr.slice(-1500))}`);
  chk.note(`client stdout tail: ${JSON.stringify(run.stdout.slice(-600))}`);
  const stdoutLines = run.stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  const parsed = stdoutLines.length > 0 ? parseJsonOr(stdoutLines[stdoutLines.length - 1]) : null;
  // Snapshot before the purity probe adds its own 4 requests to the proxy.
  const sdkSnapCount = proxy.captures.length;

  if (!tamper) {
    chk.must(code === 0, 'official client exit code', '0', code === null ? 'killed after 30s timeout' : String(code));
    chk.must(
      parsed && parsed.ok === true,
      'client summary ok=true',
      'ok=true',
      stdoutLines.length === 0 ? 'no stdout lines' : parsed === null ? 'last stdout line is not JSON' : `ok=${parsed.ok}`,
    );
    chk.must(parsed && parsed.client === client, 'client summary language', client, parsed ? String(parsed.client) : '-');
    chk.must(parsed && parsed.marker_found === true, 'marker echoed end-to-end', 'marker_found=true', parsed ? String(parsed.marker_found) : '-');
    const leak = run.stderr.split(/\r?\n/).find((l) => l.startsWith('jack:'));
    chk.must(leak === undefined, 'no jack: diagnostic in client stderr', 'none', leak === undefined ? 'none' : leak.trim());
  } else {
    const accepted = code === 0 && parsed && parsed.ok === true;
    chk.must(
      !accepted,
      'tampered upstream response rejected by official client',
      'non-zero exit or ok!=true',
      `exit ${code === null ? 'killed (timeout)' : code}, ok=${parsed ? parsed.ok : 'missing'}`,
    );
  }

  // ---- driver-side framing/purity oracle (NOT an official MCP client) ----
  await runPurityProbe(chk, jackBin, CLIENT_JSON, marker, tamper);

  if (tamper) {
    const first = proxy.captures[0];
    chk.must(
      first && first.status === 200 && first.tampered === true,
      'tamper proxy first capture: upstream 200 with flipped first byte',
      'status 200, tampered=true',
      first ? `status ${first.status}, tampered=${String(first.tampered)}` : 'no capture recorded',
    );
  } else {
    assertHops(chk, g4, proxy.captures.slice(0, sdkSnapCount), marker);
    await getProbes(chk, g4, SOCK, gwPort, server);
  }

  const gwBytes = held.gatewayChild._stdoutBytes();
  chk.note(`gateway stdout bytes: ${gwBytes}`);
  chk.must(gwBytes === 0, 'gateway stdout stayed empty', '0 bytes', `${gwBytes} bytes`);
}

async function runCell(opts) {
  const { workDir, index, client, server, tamper, artifacts, keep } = opts;
  const name = cellName({ client, server, tamper });
  const chk = makeChecks();
  const g4 = {
    skipped: false,
    upstream_status: '-',
    upstream_ct: '-',
    upstream_mode: server === 'ts' ? 'recorded' : 'asserted',
    gateway_status: '-',
    bridge_get_count: '-',
  };

  const fcl = artifacts.fixtures[client];
  const fsv = artifacts.fixtures[server];
  if (!fcl.ok || !fsv.ok) {
    const reasons = [];
    if (!fcl.ok) reasons.push(`${client} client fixture unavailable: ${fcl.reason}`);
    if (!fsv.ok) reasons.push(`${server} server fixture unavailable: ${fsv.reason}`);
    chk.note(reasons.join('; '));
    g4.skipped = true;
    return { name, result: 'SKIP', details: chk.lines(), g4, tamper };
  }

  const cellDir = join(workDir, `c${index}`);
  const held = { serverChild: null, gatewayChild: null, proxy: null };
  try {
    try {
      await runCellFlow({ chk, g4, client, server, tamper, artifacts, cellDir, index, jackBin: artifacts.jack, held });
    } finally {
      // SIGTERM -> 2s -> SIGKILL, proxy closed last so nothing reconnects.
      if (held.gatewayChild) await stopChild(held.gatewayChild);
      if (held.serverChild) await stopChild(held.serverChild);
      if (held.proxy) await held.proxy.close();
    }
  } catch (e) {
    if (e instanceof CellFail) chk.bad(e.message);
    else chk.bad(`internal error: ${e.message}`);
  }

  const pass = chk.pass();
  if (pass && !keep) {
    try {
      rmSync(cellDir, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
  return { name, result: pass ? 'PASS' : 'FAIL', details: chk.lines(), g4, tamper };
}

// ---- reporting -----------------------------------------------------------------

function printHeader(artifacts) {
  process.stdout.write(`pinned: go=${PINS.go}; ts=${PINS.ts}; rust=${PINS.rust}; protocol=${PINS.protocol}\n`);
  process.stdout.write(`artifact jack: ${artifacts.jack}${artifacts.jackBuilt ? ' (built)' : ''}\n`);
  for (const lang of LANGS) {
    const f = artifacts.fixtures[lang];
    if (f.client === null && f.server === null) continue; // language not selected
    if (f.ok) process.stdout.write(`artifact ${lang}: client=${f.client} server=${f.server}\n`);
    else process.stdout.write(`artifact ${lang}: unavailable (${f.reason})\n`);
  }
}

function printCell(record) {
  process.stdout.write(`CELL ${record.name}\n`);
  process.stdout.write(`RESULT ${record.result}\n`);
  for (const line of record.details) process.stdout.write(`${line}\n`);
}

function printSummary(records) {
  const passed = records.filter((r) => r.result === 'PASS').length;
  const skipped = records.filter((r) => r.result === 'SKIP').length;
  const failed = records.filter((r) => r.result === 'FAIL').length;
  process.stdout.write(`SUMMARY cells=${records.length} passed=${passed} skipped=${skipped} failed=${failed}\n`);
  process.stdout.write('G4 GET behaviour:\n');
  for (const r of records) {
    if (r.tamper) continue;
    const g = r.g4;
    if (g.skipped) {
      process.stdout.write(`  ${r.name}: skipped\n`);
      continue;
    }
    process.stdout.write(`  ${r.name}: upstream GET status=${g.upstream_status} content_type=${g.upstream_ct} (405 ${g.upstream_mode}); gateway GET status=${g.gateway_status} (401 asserted); bridge GET count=${g.bridge_get_count}; client tolerances (source-derived): ${TOLERANCES[r.client]}\n`);
  }
  for (const r of records) {
    if (!r.tamper) continue;
    process.stdout.write(`TAMPER ${r.name}: ${r.result}\n`);
  }
}

// ---- main ------------------------------------------------------------------------

async function main() {
  const cli = parseArgs(process.argv.slice(2));
  const clients = splitLangs(cli.clients, LANGS, '--clients');
  const servers = splitLangs(cli.servers, LANGS, '--servers');
  if (clients.length === 0) fail(`no client languages selected\n${USAGE}`);
  if (servers.length === 0) fail(`no server languages selected\n${USAGE}`);

  const cells = [];
  for (const c of clients) {
    for (const s of servers) cells.push({ client: c, server: s, tamper: false });
  }
  // One tamper cell per selected client; the upstream is always the go server.
  for (const c of clients) cells.push({ client: c, server: 'go', tamper: true });

  if (cli.list) {
    for (const cell of cells) process.stdout.write(`${cellName(cell)}\n`);
    return;
  }

  const workDir = realpathSync(mkdtempSync(join(tmpdir(), 'jack-e2e-')));
  // Belt and braces: any exit path kills children spawned but not yet reaped.
  process.on('exit', () => {
    for (const child of tracked) {
      try {
        child.kill('SIGKILL');
      } catch { /* already gone */ }
    }
  });

  const needed = new Set([...clients, ...servers]);
  needed.add('go'); // tamper cells always need the go server fixture
  const artifacts = resolveArtifacts(workDir, needed);

  printHeader(artifacts);
  const matrixCount = cells.filter((c) => !c.tamper).length;
  process.stdout.write(`cells: ${cells.length} (${matrixCount} matrix + ${cells.length - matrixCount} tamper)\n`);

  const records = [];
  let index = 0;
  for (const cell of cells) {
    index += 1;
    const record = await runCell({ workDir, index, ...cell, artifacts, keep: cli.keep });
    printCell(record);
    records.push(record);
  }

  printSummary(records);
  const failed = records.filter((r) => r.result === 'FAIL').length;
  for (const child of tracked) {
    try {
      child.kill('SIGKILL');
    } catch { /* already gone */ }
  }
  // Keep the per-cell work dirs and build dir on failure or with --keep.
  if (!cli.keep && failed === 0) {
    try {
      rmSync(workDir, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
  process.exitCode = failed > 0 ? 1 : 0;
}

main().catch((e) => {
  for (const child of tracked) {
    try {
      child.kill('SIGKILL');
    } catch { /* already gone */ }
  }
  process.stderr.write(`tools/mcp-e2e/run.mjs: ${(e && e.message) ? e.message : String(e)}\n`);
  process.exit(1);
});
