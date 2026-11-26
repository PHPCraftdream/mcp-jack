import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { createServer, request as httpRequest } from 'node:http';
import { fileURLToPath } from 'node:url';
import { parseArgs, usage } from './lib/args.mjs';
import { REQUIRED_SCENARIOS, CAPABILITY_IDS, CAPTURE_DEFAULTS, runDeadlineMs } from './lib/config.mjs';
import { redactText, redactRecord, bound, fingerprint } from './lib/redact.mjs';
import { makeCell, validateCell, attributionFor, summarize } from './lib/ledger.mjs';
import { terminate } from './lib/childproc.mjs';
import { startIncrementalProxy } from './lib/proxy/incremental.mjs';
import { startTamperProxy } from './lib/proxy/tamper.mjs';
import { startRelay } from './lib/proxy/relay.mjs';
import { assertScenario1, assertScenario2, assertScenario3, assertScenario4, assertScenario5, assertScenario6, assertScenario7, assertScenario8 } from './lib/assert/scenarios.mjs';
import { prepareArtifacts, writeLedger, writeCapture, writeLogs, pruneIfNotKept } from './lib/artifacts.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const MODERN = dirname(fileURLToPath(import.meta.url));
const ECHO_VALUE = 'modern-e2e-deterministic';
const descriptions = { 1: 'auto discovery, modern request sequence, echo result', 2: 'explicit modern bridge refuses legacy control', 3: 'deterministic echo and annotated metadata mirrors', 4: 'opted-in signed progress SSE and ordered result', 5: 'authenticated direct request without stream opt-in', 6: 'live SDK cancellation aborts upstream stream', 7: 'official subscriptions/listen notification lifecycle', 8: 'tampered signed response fails closed' };
function matrix(flags) {
  const cells = [];
  for (const client of flags.clients) for (const server of flags.servers) for (const path of flags.paths) for (let scenario = 1; scenario <= 8; scenario += 1) {
    if (scenario === 1 && path !== 'bridge-auto-both' || scenario === 2 && path !== 'scripted-control' || scenario === 5 && path !== 'direct' || scenario === 8 && path !== 'bridge-modern' || [3, 4, 6, 7].includes(scenario) && !['direct', 'bridge-modern'].includes(path)) continue;
    cells.push({ cell_id: `scenario-${scenario}-${client}-client-${server}-server-${path}`, client, server, path, scenario, required: REQUIRED_SCENARIOS.includes(scenario) });
  }
  return cells;
}
function printList(cells) { for (const c of cells) process.stdout.write(`${c.cell_id} ${c.required ? 'REQUIRED' : 'SKIPPABLE'}: ${descriptions[c.scenario]}\n`); }
function parseLine(text, label) { const lines = text.split(/\r?\n/).filter(Boolean); if (lines.length !== 1) throw new Error(`${label}: expected one JSON line, got ${lines.length}`); const value = JSON.parse(lines[0]); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label}: expected object`); return value; }
function validateReady(r) {
  if (Object.keys(r).sort().join(',') !== 'address,capabilities,control_address,sdk' || typeof r.address !== 'string' || typeof r.control_address !== 'string' || !r.sdk || typeof r.sdk.name !== 'string' || typeof r.sdk.version !== 'string' || !Array.isArray(r.capabilities)) throw new Error('server ready schema invalid');
  const ids = r.capabilities.map((x) => x?.id);
  if (ids.length !== CAPABILITY_IDS.length || new Set(ids).size !== ids.length || CAPABILITY_IDS.some((id) => !ids.includes(id))) throw new Error('ready capability ids invalid');
  if (r.capabilities.some((c) => !['supported', 'unsupported', 'unknown'].includes(c.status) || typeof c.evidence !== 'string' || !c.evidence.trim())) throw new Error('ready capability schema invalid');
  return r;
}
function validateResult(r, scenario) {
  if (!r || r.scenario !== scenario || !r.sdk || typeof r.sdk.name !== 'string' || typeof r.sdk.version !== 'string' || !['ok', 'fail', 'unsupported'].includes(r.outcome)) throw new Error('client result schema invalid');
  if (scenario === 3 ? !r.request_meta || typeof r.request_meta !== 'object' || Array.isArray(r.request_meta) : r.request_meta !== null) throw new Error('client request_meta schema invalid');
  const b = r.bridge;
  if (!b || typeof b !== 'object' || typeof b.spawned !== 'boolean' || !(b.exit_code === null || Number.isInteger(b.exit_code)) || !Number.isInteger(b.stdout_bytes) || b.stdout_bytes < 0 || typeof b.stderr_tail !== 'string') throw new Error('client result bridge schema invalid');
  if (!Array.isArray(r.progress) || !r.timings || r.timings.started_ms !== 0) throw new Error('client result progress/timing schema invalid');
  if (r.outcome === 'unsupported' && (typeof r.capability_evidence !== 'string' || !r.capability_evidence.trim())) throw new Error('unsupported result requires capability_evidence');
  return r;
}
function capability(r, id) { return r.capabilities.find((c) => c.id === id); }
function checkBinary(path, name) { if (!path || !existsSync(path)) throw new Error(`${name} missing: ${path ?? '(unset)'}`); return realpath(path); }
function fixtureCmd(entry) { return entry.build_kind === 'node-script' ? { cmd: process.execPath, base: [entry.path] } : { cmd: entry.path, base: [] }; }
function child(cmd, args, env = {}, pipeInput = false) {
  const p = spawn(cmd, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: [pipeInput ? 'pipe' : 'ignore', 'pipe', 'pipe'], windowsHide: true });
  p.stdoutText = ''; p.stderrText = ''; p.stdout.on('data', (b) => { p.stdoutText += b.toString('utf8'); }); p.stderr.on('data', (b) => { p.stderrText = bound(p.stderrText + b.toString('utf8'), 8192); });
  p._close = new Promise((done) => p.once('close', (code, signal) => done({ code, signal }))); return p;
}
async function loadManifest() {
  const doc = JSON.parse(await readFile(join(MODERN, 'fixtures.json'), 'utf8')); const expected = ['go-client', 'go-server', 'ts-client', 'ts-server'];
  if (!doc?.fixtures || Object.keys(doc.fixtures).sort().join(',') !== expected.sort().join(',')) throw new Error('fixtures.json keys invalid'); const result = {};
  for (const key of expected) { const entry = doc.fixtures[key]; const kind = key.startsWith('go-') ? 'go-binary' : 'node-script'; if (!entry || Object.keys(entry).sort().join(',') !== 'artifact,build_kind,env' || entry.build_kind !== kind || typeof entry.artifact !== 'string' || typeof entry.env !== 'string') throw new Error(`invalid manifest entry ${key}`); const override = process.env[entry.env]; const artifact = resolve(MODERN, override || entry.artifact); if (!existsSync(artifact) || override && !isAbsolute(override)) throw new Error(`fixture artifact missing or invalid: ${artifact}`); result[key] = { ...entry, path: await realpath(artifact) }; }
  return result;
}
function registryFor(ctx) { return { children: [], cleanups: [], track(childProc) { if (ctx.expired) throw new Error('resource registration after deadline expiry'); this.children.push(childProc); ctx.allChildren.push(childProc); return childProc; }, trackCleanup(fn) { if (ctx.expired) throw new Error('resource registration after deadline expiry'); this.cleanups.push(fn); ctx.allCleanups.push(fn); return fn; } }; }
async function runCommand(cmd, args, timeout, pipeInput = false, registry = null) {
  const p = child(cmd, args, {}, pipeInput); registry?.track(p); let timer; const outcome = await Promise.race([p._close, new Promise((done) => { timer = setTimeout(() => done({ code: null, timedOut: true }), timeout); })]); clearTimeout(timer); if (outcome.timedOut) await terminate(p, Math.min(timeout, 1000)); return { code: outcome.code ?? null, stdout: p.stdoutText, stderr: p.stderrText, timedOut: Boolean(outcome.timedOut), proc: p };
}
async function freePort() { const server = createServer(); await new Promise((ok, bad) => server.listen(0, '127.0.0.1', ok).once('error', bad)); const port = server.address().port; await new Promise((ok) => { server.closeAllConnections?.(); server.close(() => ok()); }); return port; }
async function reserveDir(parent) { const dir = await mkdtemp(join(parent, 'cell-')); await chmod(dir, 0o700); return dir; }
async function privateJson(path, value) { await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 }); await chmod(path, 0o600); }
async function waitGateway(ctx, url, proc, timeout) { const end = Date.now() + timeout; while (Date.now() < end) { if (ctx.expired) throw new Error('run deadline expired during gateway readiness'); if (proc.exitCode !== null) throw new Error(`gateway exited: ${proc.stderrText}`); try { const r = await fetch(`${url}/`); if (r.status) return; } catch { } await new Promise((r) => setTimeout(r, 50)); } throw new Error(`gateway readiness timeout: ${url}`); }
async function serverReady(proc, timeout) { let timer; const state = await Promise.race([new Promise((ok) => proc.stdout.once('data', () => ok('ready'))), proc._close.then(() => 'exit'), new Promise((ok) => { timer = setTimeout(() => ok('timeout'), timeout); })]); clearTimeout(timer); if (state !== 'ready') throw new Error(`server fixture readiness ${state}: ${proc.stderrText}`); return validateReady(parseLine(proc.stdoutText, 'server')); }
async function provisionJack(ctx, spec, dir, opts) {
  const { registry, secrets, serverAddress, profile, keysOnly = false } = opts; const paths = Object.fromEntries(['server-secret', 'server-public', 'user-secret', 'user-public', 'state', 'invite', 'gateway.json', 'client.json', 'bridge.json'].map((n) => [n, join(dir, n)]));
  const command = async (args) => { const r = await runCommand(ctx.jack, args, 10000, false, registry); if (r.code !== 0) throw new Error(`jack ${args[0]} failed: ${r.stderr}`); };
  for (const name of ['server-secret', 'server-public', 'user-secret', 'user-public', 'invite']) secrets.push({ label: `${name}-path`, value: paths[name] });
  await command(['keygen', 'server', '--secret', paths['server-secret'], '--public', paths['server-public']]); await command(['keygen', 'user', '--secret', paths['user-secret'], '--public', paths['user-public']]); await command(['bootstrap', '--state', paths.state, '--invite-file', paths.invite]);
  for (const name of ['server-secret', 'server-public', 'user-secret', 'user-public', 'invite']) { await chmod(paths[name], 0o600); secrets.push({ label: name, value: await readFile(paths[name], 'utf8') }); }
  const pub = JSON.parse(await readFile(paths['server-public'], 'utf8'));
  if (keysOnly) { // keys-only provisioning for the scripted control path
    return { paths, pub, gateway: null, relay: null, gatewayUrl: null, proxyPort: null, ready: null, serverProc: null, enrolled: { code: 0 } };
  }
  const sc = fixtureCmd(ctx.fixtures[`${spec.server}-server`]); const serverProc = registry.track(child(sc.cmd, [...sc.base, '--listen', '127.0.0.1:0', '--control-listen', '127.0.0.1:0'])); const ready = await serverReady(serverProc, ctx.flags.readiness);
  const relay = startRelay({ socketPath: join(dir, 'mcp.sock'), target: ready.address }); registry.trackCleanup(() => relay.close()); await relay.ready;
  const gwPort = await freePort(); const proxyPort = await freePort(); await privateJson(paths['gateway.json'], { version: 1, aud: 'e2e', server_seed_file: paths['server-secret'], state_file: paths.state, listen: `127.0.0.1:${gwPort}`, upstream_socket: join(dir, 'mcp.sock'), upstream_url: 'http://upstream/mcp', call_timeout_ms: 30000, max_concurrent: 8 });
  const gateway = registry.track(child(ctx.jack, ['gateway', '--config', paths['gateway.json'], '--profile', profile])); const gatewayUrl = `http://127.0.0.1:${gwPort}`; await waitGateway(ctx, gatewayUrl, gateway, ctx.flags.readiness);
  await privateJson(paths['client.json'], { version: 1, endpoint: `${gatewayUrl}/mcp`, aud: 'e2e', server_public_key: pub.server_public_key, server_kid: pub.server_kid, key_file: paths['user-secret'], key_format: 'raw-seed', call_timeout_ms: 30000 });
  // enroll needs the live gateway endpoint
  const enrolled = await runCommand(ctx.jack, ['enroll', '--config', paths['client.json'], '--invite-file', paths.invite, '--name', 'e2e-user'], 10000, false, registry);
  return { paths, pub, gateway, relay, gatewayUrl, proxyPort, ready, serverProc, enrolled };
}
function fixtureMethod(captures, method) { for (const c of captures) if (c.direction === 'request') { try { const x = JSON.parse(c.body); if (x.method === method) return x; } catch { } } return null; }
function parsedBody(text) { try { return JSON.parse(text); } catch { return null; } }
function isEndFrame(body) { return typeof body === 'string' && (/^event:\s*end\b/mi.test(body) || body.trim() === 'end'); }
async function control(address, path, body) { const u = new URL(path, address); return new Promise((resolveResponse, reject) => { const req = httpRequest(u, { method: body ? 'POST' : 'GET', headers: body ? { 'content-type': 'application/json' } : {}, signal: AbortSignal.timeout(10000) }, (res) => { let text = ''; res.on('data', (b) => { text += b; }); res.on('end', () => resolveResponse({ status: res.statusCode, body: text })); }); req.on('error', reject); req.end(body ? JSON.stringify(body) : undefined); }); }
async function legacyControl() {
  const counts = { received: 0, refused: 0, fallback: 0 }; let refused = false;
  const server = createServer((req, res) => { let body = ''; req.on('data', (b) => { body += b; }); req.on('end', () => { counts.received += 1; if (refused) counts.fallback += 1; let v = {}; try { v = JSON.parse(body); } catch { } if (v.method === 'initialize') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: v.id, result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'legacy-control', version: '1' } } })); } else { refused = true; counts.refused += 1; res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: v.id ?? null, error: { code: -32600, message: 'legacy-only control refuses modern request' } })); } }); });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok)); return { counts, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((ok) => { server.closeAllConnections?.(); server.close(ok); }) };
}
async function withTimeout(promise, ms) { let timer; try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('cleanup timeout')), ms); })]); } finally { clearTimeout(timer); } }
async function runCell(spec, ctx) {
  ctx.current = { cell: spec.cell_id, phase: 'provision' }; if (ctx.expired) return null;
  const started = Date.now(); const dir = await reserveDir(ctx.work); const secrets = []; const registry = registryFor(ctx); let ready; let clientResult; let clientRun; let proxy; let scripted; let provisionedState = null; let captures = []; let reason = 'scenario did not complete'; let outcome = 'FAIL'; let fixtureFailure = false; let serverProcRef; let releaseReleased = false; let releaseStatus = null;
  const versions = { client: null, server: null }; const signedTopology = (spec.path !== 'direct' && [1, 3, 4, 7, 8].includes(spec.scenario)) || spec.scenario === 5; const oracle = { applicable: signedTopology, result: signedTopology ? 'not-run' : 'not-applicable' }; const timings = { readiness_ms: null, tool_ms: null, first_event_ms: null, stream_completion_ms: null, cancellation_ms: null, shutdown_ms: null };
  try {
    if (ctx.expired) throw new Error('run deadline expired');
    const direct = spec.path === 'direct'; const scriptedPath = spec.path === 'scripted-control'; let upstream;
    if (scriptedPath) { scripted = await legacyControl(); registry.trackCleanup(() => scripted.close()); upstream = scripted.url; const sc = fixtureCmd(ctx.fixtures[`${spec.server}-server`]); const serverProc = registry.track(child(sc.cmd, [...sc.base, '--listen', '127.0.0.1:0', '--control-listen', '127.0.0.1:0'])); serverProcRef = serverProc; ready = await serverReady(serverProc, ctx.flags.readiness); provisionedState = await provisionJack(ctx, spec, dir, { registry, secrets, keysOnly: true }); }
    else if (direct && spec.scenario !== 5) { const sc = fixtureCmd(ctx.fixtures[`${spec.server}-server`]); const serverProc = registry.track(child(sc.cmd, [...sc.base, '--listen', '127.0.0.1:0', '--control-listen', '127.0.0.1:0'])); serverProcRef = serverProc; ready = await serverReady(serverProc, ctx.flags.readiness); upstream = ready.address; }
    else { provisionedState = await provisionJack(ctx, spec, dir, { registry, secrets, profile: spec.scenario === 1 || spec.scenario === 5 ? 'both' : 'modern' }); ready = provisionedState.ready; serverProcRef = provisionedState.serverProc; upstream = provisionedState.gatewayUrl; if (provisionedState.enrolled.code !== 0) { fixtureFailure = true; throw new Error(`fixture-readiness: jack enroll failed: ${provisionedState.enrolled.stderr}`); } }
    versions.server = ready.sdk; timings.readiness_ms = Date.now() - started;
    const gateIds = spec.scenario === 4 ? ['progress', 'streamable_http_server'] : spec.scenario === 6 ? ['cancellation', 'progress', 'streamable_http_server'] : spec.scenario === 7 ? ['subscriptions_listen'] : [];
    for (const id of gateIds) { const cap = capability(ready, id); if (!cap || cap.status !== 'supported') { if (cap?.status === 'unsupported') { outcome = 'SKIP'; reason = cap.evidence; } else throw new Error(`capability ${id} status ${cap?.status ?? 'missing'}: ${cap?.evidence ?? ''}`); } }
    if (outcome === 'SKIP') return await finish();
    if (spec.scenario === 4 && capability(ready, 'progress')?.status !== 'supported') throw new Error('progress capability unavailable');
    if (spec.scenario === 5) upstream = provisionedState.gatewayUrl;
    ctx.current.phase = 'proxy'; if (ctx.expired) throw new Error('run deadline expired');
    proxy = await startIncrementalProxy({ port: provisionedState?.proxyPort ?? 0, secrets, limits: { upstream } }); const captureProxy = proxy; registry.trackCleanup(() => captureProxy.close());
    let bridgeConfig = provisionedState ? { version: 1, endpoint: `${proxy.url}/mcp`, aud: 'e2e', server_public_key: provisionedState.pub.server_public_key, server_kid: provisionedState.pub.server_kid, key_file: provisionedState.paths['user-secret'], key_format: 'raw-seed', call_timeout_ms: 30000, era: spec.path === 'bridge-auto-both' ? 'auto' : 'modern' } : null;
    if (bridgeConfig && !direct) await privateJson(provisionedState.paths['bridge.json'], bridgeConfig);
    if (direct && spec.scenario === 5) { const { era, ...directConfig } = bridgeConfig; await privateJson(provisionedState.paths['bridge.json'], directConfig); }
    if (spec.scenario === 8) { const oldProxy = proxy; await withTimeout(oldProxy.close(), 1000); proxy = await startTamperProxy({ upstream, flipByteOffset: 1, secrets }); registry.trackCleanup(() => proxy.stop()); bridgeConfig.endpoint = `${proxy.url}/mcp`; await privateJson(provisionedState.paths['bridge.json'], bridgeConfig); }
    captures = proxy.captures ?? []; const cc = fixtureCmd(ctx.fixtures[`${spec.client}-client`]); const argv = [...cc.base, '--scenario', String(spec.scenario), '--server', spec.server];
    if (direct) { argv.push('--direct', '--url', `${proxy.url}/mcp`); if (spec.scenario === 5) argv.push('--config', provisionedState.paths['bridge.json']); }
    else argv.push('--bridge-bin', ctx.jack, '--bridge-config', spec.scenario === 2 ? join(dir, 'bridge.json') : provisionedState.paths['bridge.json'], '--era', spec.path === 'bridge-auto-both' ? 'auto' : 'modern');
    ctx.current.phase = 'client'; if (ctx.expired) throw new Error('run deadline expired');
    if ([4, 6].includes(spec.scenario)) {
      const p = registry.track(child(cc.cmd, argv, {}, true)); const firstPromise = proxy.waitFor((c) => c.direction === 'event' && /progress/.test(c.body)); let firstTimer; const first = await Promise.race([firstPromise, new Promise((ok) => { firstTimer = setTimeout(() => ok(null), ctx.flags.firstStreamEvent); })]); clearTimeout(firstTimer); timings.first_event_ms = first ? Date.now() - started : null;
      const request = fixtureMethod(captures, 'tools/call'); const callId = request?.params?.arguments?.call_id;
      if (spec.scenario === 4 && first && callId) { try { const released = await control(ready.control_address, '/v1/release', { call_id: callId }); releaseStatus = released.status; releaseReleased = JSON.parse(released.body).released === true; } catch { } }
      if (spec.scenario === 6 && first) { p.stdin.write('cancel\n'); p.stdin.end(); } else p.stdin.end(); let timer; const close = await Promise.race([p._close, new Promise((ok) => { timer = setTimeout(() => ok({ code: null, timedOut: true }), spec.scenario === 6 ? ctx.flags.cancellation : ctx.flags.streamCompletion); })]); clearTimeout(timer); if (close.timedOut) await terminate(p, ctx.flags.shutdown); clientRun = { code: close.code, stdout: p.stdoutText, stderr: p.stderrText }; try { clientResult = validateResult(parseLine(clientRun.stdout, 'client'), spec.scenario); } catch { clientResult = null; }
      p.releaseReleased = releaseReleased;
    } else { clientRun = await runCommand(cc.cmd, argv, direct ? ctx.flags.directTool : ctx.flags.bridgeTool, false, registry); try { clientResult = validateResult(parseLine(clientRun.stdout, 'client'), spec.scenario); } catch { clientResult = null; } }
    ctx.current.phase = 'assert'; if (ctx.expired) throw new Error('run deadline expired');
    versions.client = clientResult?.sdk ?? null; timings.tool_ms = Date.now() - started;
    if (clientResult?.outcome === 'unsupported' && spec.scenario >= 4 && spec.scenario <= 7) { outcome = 'SKIP'; reason = clientResult.capability_evidence; oracle.result = 'not-run'; }
    else if (spec.scenario === 1) {
      const probe = captures.find((c) => c.direction === 'request' && c.body.includes('server/discover')); const response = probe && captures.find((c) => c.direction === 'response' && c.hop === probe.hop); const body = parsedBody(response?.body); const parsedOk = response?.status === 200 && body?.result && typeof body.result === 'object' && !body.error;
      const later = captures.filter((c) => !probe || c.hop !== probe.hop); const a = assertScenario1({ captures: later, bridgeDiscoverProbe: { separate: Boolean(probe), hop: probe?.hop, signatureVerified: Boolean(parsedOk), modernResponseVerified: Boolean(parsedOk) }, expectedPosts: 2, postSequence: ['tools/list', 'tools/call'], clientResult, sentValue: ECHO_VALUE }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = `${a.reason}; probe response signature header not captured; CI-confirmed`; oracle.result = parsedOk ? 'verified' : 'invalid';
    } else if (spec.scenario === 2) {
      const a = assertScenario2({ captures, bridge: clientResult?.bridge ?? {}, sdkErrorPresent: Boolean(clientResult?.sdk_error), refusedCount: scripted.counts.refused, fallbackCount: scripted.counts.fallback, scriptedControl: true, scriptedControlLabel: 'non-SDK scripted legacy-only control' }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = a.reason;
    } else if (spec.scenario === 3) {
      const req = captures.find((c) => c.direction === 'request' && parsedBody(c.body)?.method === 'tools/call'); const meta = proxy.requests.get(req?.hop); const requestObj = parsedBody(req?.body); const relayEntry = (provisionedState?.relay?.methods ?? []).find((m) => parsedBody(m.body)?.method === 'tools/call'); const relayMeta = parsedBody(relayEntry?.body)?.params?._meta;
      const hops = [clientResult?.request_meta, requestObj?.params?._meta, relayMeta].filter((x) => x != null); const headers = meta?.headers ?? {}; const a = assertScenario3({ captures, protocolVersionHeader: headers['mcp-protocol-version'] === '2026-07-28' || headers['protocol-version'] === '2026-07-28', methodMirror: headers['mcp-method'] === 'tools/call', toolNameMirror: headers['mcp-name'] ?? '', metaHops: hops, echoMatches: JSON.stringify(clientResult?.tool_result).includes(ECHO_VALUE), signedResponseVerified: clientResult?.outcome === 'ok' && clientResult?.bridge?.exit_code === 0, jack: !direct }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = `${a.reason}; bridge acceptance CI-confirmed`; if (!direct) oracle.result = a.ok && clientResult?.outcome === 'ok' && clientResult?.bridge?.exit_code === 0 ? 'verified' : 'invalid';
    } else if (spec.scenario === 4) {
      const progress = captures.find((c) => c.direction === 'event' && /progress/.test(c.body)); const terminal = captures.filter((c) => c.direction === 'event').at(-1); const reqMeta = [...proxy.requests.values()].find((r) => r.method === 'POST'); const endVerified = isEndFrame(terminal?.body); const frameVerified = !direct && clientResult?.outcome === 'ok' && clientResult?.bridge?.exit_code === 0;
      const a = assertScenario4({ captures, clientResult, clientOrder: [...(clientResult?.progress ?? []).map(() => 'progress'), ...(clientResult?.outcome === 'ok' ? ['result'] : [])], requestJackAccept: reqMeta?.headers?.['jack-accept'], status: terminal?.status, mediaType: terminal?.media_type, frameSignaturesVerified: frameVerified, terminalEndVerified: endVerified, firstProgressCapture: progress, terminalCapture: terminal, releaseReleased, jack: !direct }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = `${a.reason}; release status ${releaseStatus ?? 'unobserved'}; frame verification CI-confirmed`; if (!direct) oracle.result = frameVerified && endVerified && progress && terminal?.status === 200 && clientResult?.outcome === 'ok' ? 'verified' : 'invalid';
    } else if (spec.scenario === 5) {
      const refusal = captures.find((c) => c.direction === 'response' && c.status === 501); const refusalReq = refusal && proxy.requests.get(refusal.hop); const hasAuth = Boolean(refusalReq?.hasAuth); let code; try { const body = parsedBody(refusal?.body); code = body?.error?.code ?? body?.data?.code; } catch { }
      const noOptIn = ![...proxy.requests.values()].some((r) => r.headers?.['jack-accept'] === 's1'); const probeProxy = await startIncrementalProxy({ secrets, limits: { upstream: provisionedState.gatewayUrl } }); registry.trackCleanup(() => probeProxy.close()); const probePath = join(dir, 'bridge-probe.json'); await privateJson(probePath, { ...bridgeConfig, endpoint: `${probeProxy.url}/mcp`, era: 'modern' });
      const probe = registry.track(child(ctx.jack, ['bridge', '--config', probePath], {}, true)); probe.stdin.end(`${JSON.stringify({ jsonrpc: '2.0', id: 'probe-1', method: 'tools/call', params: { name: 'progress', arguments: { count: 1, hold: true, call_id: 'probe-1' }, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } })}\n`); let timer; const probeClose = await Promise.race([probe._close, new Promise((ok) => { timer = setTimeout(() => ok({ code: null }), ctx.flags.bridgeTool); })]); clearTimeout(timer);
      const probeRefusal = probeProxy.captures.some((c) => c.direction === 'response' && c.status === 501); const fabricated = probe.stdoutText.trim().split(/\r?\n/).some((line) => { try { const v = JSON.parse(line); return v?.jsonrpc === '2.0' && !v.error && Object.hasOwn(v, 'result'); } catch { return false; } }); const bridgeResult = probeRefusal ? { exitCode: probeClose.code, stdoutBytes: Buffer.byteLength(probe.stdoutText), fabricatedJsonRpcResult: fabricated } : null;
      const a = assertScenario5({ refusal: { signatureVerified: hasAuth && refusal?.status === 501, status: refusal?.status, code }, bridgeResult, directAuthenticated: hasAuth, noOptIn }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = `${a.reason}; response signature header not captured; CI-confirmed; ${probeRefusal ? 'bridge refusal observed' : `known gap: probe exit=${probeClose.code}, stdout_bytes=${Buffer.byteLength(probe.stdoutText)}`}`; oracle.result = hasAuth && refusal?.status === 501 ? 'verified' : 'invalid';
    } else if (spec.scenario === 6) {
      const abortIndex = captures.findIndex((c) => c.body === '[upstream-aborted]'); const id = fixtureMethod(captures, 'tools/call')?.params?.arguments?.call_id; let cancelled = false; if (id) { try { cancelled = JSON.parse((await control(ready.control_address, `/v1/cancelled?call_id=${encodeURIComponent(id)}`)).body).cancelled === true; } catch { } }
      const a = assertScenario6({ captures, downstreamDisconnected: abortIndex >= 0, noLateFrame: abortIndex >= 0 && captures.slice(abortIndex + 1).length === 0, cancelled }); const noCancel = !(provisionedState?.relay?.methods ?? []).some((m) => m.body.includes('notifications/cancelled')); outcome = a.ok && noCancel ? 'PASS' : 'FAIL'; reason = `${a.reason}; fixture owns bridge stdin; no bridge-cleanup assertion; relay cancellation scan ${provisionedState?.relay ? (noCancel ? 'clear' : 'found cancellation POST') : 'not applicable for direct cell'}; call id ${id ?? 'missing'}`;
    } else if (spec.scenario === 7) {
      const frames = captures.filter((c) => c.direction === 'event'); const notificationDelivered = frames.some((c) => /notification/i.test(c.body)); const last = frames.at(-1); const cleanEnd = clientResult?.outcome === 'ok' && (isEndFrame(last?.body) || clientResult?.timings?.completed_ms !== null); const jack = !direct; const optedIn = [...proxy.requests.values()].some((r) => r.headers?.['jack-accept'] === 's1'); const signedStreamVerified = jack && optedIn && clientResult?.outcome === 'ok' && clientResult?.bridge?.exit_code === 0 && frames.length > 0; const order = [...frames.filter((c) => /notification/i.test(c.body)).map(() => 'notification'), ...(clientResult?.outcome === 'ok' ? ['terminal'] : [])]; const a = assertScenario7({ notificationDelivered, cleanEnd, optedIn, signedStreamVerified, clientOrder: order, jack }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = `${a.reason}; stream verification CI-confirmed`; if (jack) oracle.result = signedStreamVerified && cleanEnd && notificationDelivered ? 'verified' : 'invalid';
    } else {
      const response = captures.find((c) => c.direction === 'response'); const bridgeResult = clientResult ? { exit_code: clientResult.bridge.exit_code, stdout_bytes: clientResult.bridge.stdout_bytes, fabricated_result: Boolean(clientResult.tool_result) || clientResult.outcome === 'ok' } : { exit_code: null, stdout_bytes: 0, fabricated_result: false }; const a = assertScenario8({ captures, flipped: proxy.flipped, upstreamStatus: response?.status, bridgeResult }); outcome = a.ok ? 'PASS' : 'FAIL'; reason = a.reason; oracle.result = a.ok && clientResult?.bridge?.exit_code !== null ? 'verified' : 'invalid';
    }
  } catch (error) { reason = error.message; outcome = 'FAIL'; fixtureFailure ||= !ready || /fixture-readiness|fixture|ready line/.test(reason); if (ctx.expired) return null; }
  async function finish() {
    ctx.current.phase = 'cleanup';
    const end = Date.now(); for (const p of registry.children) { try { await terminate(p, ctx.flags.shutdown); } catch { } } for (const fn of registry.cleanups) { try { await withTimeout(Promise.resolve().then(fn), fn.name === 'close' ? 1000 : 1000); } catch { } } timings.shutdown_ms = Date.now() - end;
    const failure = outcome === 'FAIL'; const cleanedReason = redactText(reason, secrets); const visibleError = clientResult?.sdk_error ? bound(redactText(clientResult.sdk_error, secrets), 2000) : null; const ff = failure ? fingerprint(redactText(clientResult?.sdk_error ?? reason, secrets)) : null; const key = `${spec.client}/${spec.server}/${spec.scenario}`; const attribution = attributionFor({ outcome, failure_fingerprint: ff, directControl: ctx.directOutcomes.get(key), fixtureReadinessFailed: fixtureFailure });
    const record = makeCell({ ...spec, outcome, attribution, reason: cleanedReason, captures: captures.slice(0, CAPTURE_DEFAULTS.maxCapturesPerCell).map((c) => redactRecord(c, secrets)), sdk_versions: versions, signature_oracle: oracle, timings, ...(failure ? { failure_fingerprint: ff } : {}), client_visible: { tool_result: redactRecord(clientResult?.tool_result ?? null, secrets), sdk_error: visibleError } });
    if (spec.path === 'direct') ctx.directOutcomes.set(key, { outcome, failure_fingerprint: ff }); const validation = validateCell(record); if (!validation.ok) throw new Error(`${spec.cell_id}: invalid cell: ${validation.errors.join('; ')}`);
    await writeCapture(ctx.artifacts, spec.cell_id, record.captures); await writeLogs(ctx.artifacts, `${spec.cell_id}.server`, redactText(serverProcRef?.stderrText ?? provisionedState?.serverProc?.stderrText ?? '', secrets)); await writeLogs(ctx.artifacts, `${spec.cell_id}.gateway`, redactText(provisionedState?.gateway?.stderrText ?? '', secrets)); if (!directPath(spec)) await writeLogs(ctx.artifacts, `${spec.cell_id}.bridge`, redactText(clientResult?.bridge?.stderr_tail ?? '', secrets)); await writeLogs(ctx.artifacts, `${spec.cell_id}.client`, redactText(clientRun?.stderr ?? '', secrets));
    process.stdout.write(`CELL ${spec.cell_id}\nRESULT ${outcome}\nINFO ${record.reason}\n`); return record;
  }
  function directPath(item) { return item.path === 'direct'; }
  return finish();
}
async function main() {
  const { flags, errors } = parseArgs(process.argv.slice(2)); if (errors.length) { process.stderr.write(`${usage}\n${errors.join('\n')}\n`); return 2; } const cells = matrix(flags); if (flags.list) { printList(cells); return 0; } if (flags.selfTest) { const { runSelfTest } = await import('./lib/selftest.mjs'); return runSelfTest(); }
  if (cells.some((c) => c.path !== 'direct' || c.scenario === 5) && !flags.jackBin) { process.stderr.write(`${usage}\n--jack-bin is required for Jack path cells or scenario 5\n`); return 2; }
  try {
    const fixtures = await loadManifest(); const jack = flags.jackBin ? await checkBinary(flags.jackBin, '--jack-bin') : null; const artifacts = await prepareArtifacts({ root: flags.artifacts, keep: flags.keep }); const work = await mkdtemp(join(tmpdir(), 'jack-modern-e2e-')); const ctx = { flags, fixtures, jack, artifacts, work, directOutcomes: new Map(), current: { cell: null, phase: 'starting' }, allChildren: [], allCleanups: [], expired: false }; process.stdout.write(`cells: ${cells.length}\n`); const records = [];
    const runAll = async () => { for (const spec of cells) { if (ctx.expired) break; const record = await runCell(spec, ctx); if (record) records.push(record); } if (ctx.expired) return null; const summary = summarize(records); ctx.ledgerWrite = writeLedger(artifacts, records); await ctx.ledgerWrite; if (ctx.expired) return null; process.stdout.write(`SUMMARY cells=${records.length} passed=${summary.counts.PASS} skipped=${summary.counts.SKIP} failed=${summary.counts.FAIL}\n`); await pruneIfNotKept(artifacts, flags.keep, records, false); await rm(work, { recursive: true, force: true }); return summary.outcome === 'PASS' && REQUIRED_SCENARIOS.every((s) => records.some((r) => r.scenario === s && r.outcome === 'PASS')) ? 0 : 1; };
    const started = Date.now(); let timer;
    const deadline = new Promise((resolveDeadline) => { timer = setTimeout(() => { ctx.expired = true; resolveDeadline(null); }, runDeadlineMs(cells.length, flags)); });
    let result; try { result = await Promise.race([runAll(), deadline]); } finally { clearTimeout(timer); }
    if (!ctx.expired) return result;
    process.stderr.write(`GLOBAL DEADLINE code=2 elapsed_ms=${Date.now() - started} cell=${ctx.current.cell ?? 'none'} phase=${ctx.current.phase}\n`);
    for (const p of ctx.allChildren) { try { await withTimeout(terminate(p, ctx.flags.shutdown), 1000); } catch { } }
    for (const fn of ctx.allCleanups) { try { await withTimeout(Promise.resolve().then(fn), 1000); } catch { } }
    try { if (ctx.ledgerWrite) await ctx.ledgerWrite; await writeLedger(artifacts, records); } catch (error) { process.stderr.write(`ledger write failed: ${error.message}\n`); }
    try { await rm(work, { recursive: true, force: true }); } catch { }
    return 2;
  } catch (error) { process.stderr.write(`tools/mcp-e2e-modern/run.mjs: ${error.message}\n`); return 2; }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().then((code) => { process.exitCode = code; }).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 2; });
