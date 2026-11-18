import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, TS_DIR, PROTO, READY_TIMEOUT_MS, SDK_TIMEOUT_MS, GET_TIMEOUT_MS, fail, sleep, parseJsonOr, essence, writePrivate, clipText, CellFail, KnownLimit } from './config.mjs';
import { makeChild, stopChild, freePort, waitForFile, waitForTcp, rawRequest } from './child.mjs';
import { startProxy, runPurityProbe } from './proxy.mjs';

export function makeChecks() {
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
export function runJack(jackBin, args, sub) {
  const r = spawnSync(jackBin, args, { cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true });
  if (r.error) throw new CellFail(`jack ${sub} failed: could not spawn (${r.error.message})`);
  if (r.status !== 0) throw new CellFail(`jack ${sub} failed: ${(r.stderr ?? '').trim()}`);
}

export function clientArgv(lang, jackBin, configPath, marker, artifacts) {
  const f = artifacts.fixtures[lang];
  switch (lang) {
    case 'go': return { cmd: f.client, args: [jackBin, configPath, marker] };
    case 'ts': return { cmd: process.execPath, args: [join(TS_DIR, 'client.mjs'), jackBin, configPath, marker] };
    case 'rust': return { cmd: f.client, args: [jackBin, configPath, marker] };
    default: throw new CellFail(`unknown client language ${lang}`);
  }
}

export function serverArgv(lang, sockPath, artifacts) {
  const f = artifacts.fixtures[lang];
  switch (lang) {
    case 'go': return { cmd: f.server, args: [sockPath] };
    case 'ts': return { cmd: process.execPath, args: [join(TS_DIR, 'server.mjs'), sockPath] };
    case 'rust': return { cmd: f.server, args: [sockPath] };
    default: throw new CellFail(`unknown server language ${lang}`);
  }
}

export function cellName(cell) {
  return `${cell.client}-client x ${cell.server}-server${cell.tamper ? ' tamper' : ''}`;
}

// SDK client fixture run with SIGTERM-then-SIGKILL escalation at the timeout.
// A timeout is reported as code null (killed); spawn errors as kind spawn_error.
export async function runSdkClient(argv, timeoutMs) {
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
export function assertHops(chk, g4, captures, marker) {
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
export async function getProbes(chk, g4, sockPath, gwPort, serverLang) {
  const up = await rawRequest(
    { socketPath: sockPath, path: '/mcp', method: 'GET', headers: { host: 'upstream', accept: 'text/event-stream', 'mcp-protocol-version': PROTO } },
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

export async function runCellFlow(ctx) {
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
  // Diagnostics: the SDK client's stdout/stderr tails are always visible in the CI log.
  chk.note(`client stderr tail: ${JSON.stringify(run.stderr.slice(-1500))}`);
  chk.note(`client stdout tail: ${JSON.stringify(run.stdout.slice(-600))}`);
  chk.note(`proxy received (${proxy.received.length}): ${JSON.stringify(proxy.received.slice(0, 8))}`);
  chk.note(`upstream server log: ${(() => { try { return JSON.stringify(readFileSync(SERVER_LOG, 'utf8').slice(0, 1500)); } catch (e) { return `unreadable (${e.code ?? 'error'})`; } })()}`);
  chk.note(`gateway stderr tail: ${JSON.stringify(held.gatewayChild._stderr().slice(-1500))}`);
  chk.note(`proxy captures (${proxy.captures.length}): ${(() => { try { return JSON.stringify(proxy.captures.slice(0, 6)).slice(0, 1500); } catch { return 'unserializable'; } })()}`);
  const stdoutLines = run.stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
  const parsed = stdoutLines.length > 0 ? parseJsonOr(stdoutLines[stdoutLines.length - 1]) : null;
  // Snapshot before the purity probe adds its own 4 requests to the proxy.
  const sdkSnapCount = proxy.captures.length;

  // Known limitation: TS server 2.4.0 answers initialize with an SSE stream even in JSON mode,
  // and the gateway by design rejects SSE with a signed 501 streaming_unsupported (v0.1: no streams).
  // Applies to the tamper variant too: the tampered bytes are the 501 body, which is itself the
  // known limitation. Skipped only via --allow-skip-ts-server (fail by default, see runCell).
  const firstCapture = proxy.captures[0];
  if (server === 'ts' && firstCapture && firstCapture.status === 501 && /streaming_unsupported/.test(firstCapture.response_body ?? '')) {
    throw new KnownLimit('official TS server 2.4.0 answered initialize with text/event-stream (200) despite responseMode json; the gateway refuses SSE by design with a signed 501 streaming_unsupported');
  }

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

export async function runCell(opts) {
  const { workDir, index, client, server, tamper, artifacts, keep, allowSkipTsServer } = opts;
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
    const text = reasons.join('; ');
    // Skip is reserved for the known TS-server limitation and only via the opt-in flag.
    if (allowSkipTsServer && server === 'ts') {
      chk.note(`SKIP (allowed by --allow-skip-ts-server): ${text}`);
      g4.skipped = true;
      return { name, result: 'SKIP', details: chk.lines(), g4, tamper };
    }
    chk.bad(`cell cannot run${server === 'ts' ? ' (pass --allow-skip-ts-server to skip TS-server cells)' : ''}: ${text}`);
    return { name, result: 'FAIL', details: chk.lines(), g4, tamper };
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
    if (e instanceof KnownLimit) {
      // Known TS-server limitation: fail by default; skip only via the opt-in flag.
      if (allowSkipTsServer && server === 'ts') {
        chk.note(`SKIP (allowed by --allow-skip-ts-server) KNOWN-LIMIT: ${e.message}`);
        g4.skipped = true;
        return { name, result: 'SKIP', details: chk.lines(), g4, tamper };
      }
      chk.bad(`FAILED by known TS-server limitation (pass --allow-skip-ts-server to skip): ${e.message}`);
      return { name, result: 'FAIL', details: chk.lines(), g4, tamper };
    }
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
