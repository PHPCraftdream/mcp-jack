import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const started = Date.now();
const elapsed = () => Math.max(0, Date.now() - started);
const argv = process.argv.slice(2);
const value = (flag) => { const i = argv.indexOf(flag); return i < 0 ? undefined : argv[i + 1]; };
const scenario = Number(value('--scenario'));
const serverLabel = value('--server');
const direct = argv.includes('--direct');
const bridgeMode = argv.includes('--bridge-bin');
let sdk = { name: '@modelcontextprotocol/client', version: 'unknown' };
const result = {
  scenario, sdk, outcome: 'fail', tool_result: null, sdk_error: null, request_meta: null,
  bridge: { spawned: false, exit_code: null, stdout_bytes: 0, stderr_tail: '' },
  progress: [], capability_evidence: null,
  sdk_notes: 'pinned-modern connect issues a server/discover probe before attaching; on stdio the SDK probes via a sibling bridge process, so probe POSTs may appear at the capture proxy separate from session traffic',
  timings: { started_ms: 0, first_event_ms: null, completed_ms: null, cancelled_ms: null },
};
let client;
let transport;
let bridgeBytes = 0;
let bridgeStderr = '';
let bridgeExit = null;
let callId;
let cancellation;
try {
  const require = createRequire(import.meta.url);
  try {
    const pkgPath = require.resolve('@modelcontextprotocol/client/package.json');
    sdk = JSON.parse(await readFile(pkgPath, 'utf8'));
  } catch { }
  result.sdk = { name: sdk.name ?? '@modelcontextprotocol/client', version: sdk.version ?? 'unknown' };
  if (![1,2,3,4,5,6,7,8].includes(scenario) || !['go','ts'].includes(serverLabel) || direct === bridgeMode) throw new Error('invalid fixture arguments');
  const requestMeta = scenario === 3 ? { 'e2e': { case: 'scenario-3', marker: 'modern-e2e-deterministic' } } : null;
  result.request_meta = requestMeta;
  function assertNotError(res, label) {
    if (res?.isError) {
      const text = Array.isArray(res.content) ? res.content.map((c) => c?.text ?? '').filter(Boolean).join('; ') : '';
      throw new Error(`${label} tools/call returned isError${text ? `: ${text}` : ''}`);
    }
  }
  if (direct) {
    if (!value('--url') || bridgeMode) throw new Error('direct mode requires --url only');
    transport = new StreamableHTTPClientTransport(new URL(value('--url')));
  } else {
    const bin = value('--bridge-bin');
    const config = value('--bridge-config');
    if (!bin || !config || value('--era') !== (scenario === 1 ? 'auto' : 'modern')) throw new Error('bridge mode requires matching era and config');
    result.bridge.spawned = true;
    transport = new StdioClientTransport({ command: bin, args: ['bridge', '--config', config], stderr: 'pipe', env: process.env });
    const startTransport = transport.start.bind(transport);
    transport.start = async () => {
      await startTransport();
      const child = transport._process;
      child?.stdout?.on('data', (chunk) => { bridgeBytes += chunk.length; });
      child?.once('close', (code) => { bridgeExit = code; });
    };
    transport.stderr?.on('data', (chunk) => { bridgeStderr = (bridgeStderr + chunk.toString('utf8')).slice(-2000); });
  }
  client = new Client({ name: 'mcp-e2e-modern-ts-client', version: '1' }, {
    versionNegotiation: { mode: { pin: '2026-07-28' } },
    supportedProtocolVersions: ['2026-07-28'],
  });
  if (scenario === 5) {
    result.outcome = 'unsupported';
    result.capability_evidence = 'no official SDK provides Jack request signing and the lock allows no extra signer, so the authenticated direct refusal control cannot be built from official SDK parts; StreamableHTTPClientTransport options do support custom request headers, but signing is not an SDK capability; the 501 streaming_unsupported refusal oracle is the repository gateway integration test internal/cli/internal/gateway/integration/gateway_profile_test.go (modern request without Jack-Accept: s1)';
    throw Object.assign(new Error('unsupported-scenario-5'), { unsupported: true });
  }
  if (scenario !== 5) await client.connect(transport);
  if (scenario === 7) {
    let notified;
    const gotNotification = new Promise((resolve) => { notified = resolve; });
    client.setNotificationHandler('notifications/tools/list_changed', () => notified(true));
    const sub = await client.listen({ toolsListChanged: true });
    await Promise.race([gotNotification, new Promise((_, reject) => setTimeout(() => reject(new Error('listen notification timeout')), 5000))]);
    const endState = await Promise.race([
      sub.closed.then((cause) => ({ cause })),
      new Promise((resolve) => { const t = setTimeout(() => resolve({ timeout: true }), 5000); t.unref?.(); }),
    ]);
    if (endState.timeout) {
      await sub.close();
      throw new Error('subscriptions/listen stream still open after notification; closed locally; no clean server-side end observed');
    }
    if (endState.cause !== 'graceful') throw new Error(`subscriptions/listen ended without a clean server-side end (cause: ${endState.cause})`);
    result.tool_result = { notification: 'notifications/tools/list_changed', honored_filter: sub.honoredFilter, end: endState.cause };
    result.timings.completed_ms = elapsed();
    result.outcome = 'ok';
  } else {
    if (scenario === 1 || scenario === 3 || scenario === 8) {
      const tools = await client.listTools();
      if (!tools.tools.some((tool) => tool.name === 'echo')) throw new Error('echo tool missing from tools/list');
    }
    if (scenario === 1 || scenario === 2 || scenario === 3 || scenario === 8) {
      const res = await client.callTool({ name: 'echo', arguments: { value: 'modern-e2e-deterministic' }, ...(requestMeta ? { _meta: requestMeta } : {}) });
      assertNotError(res, 'echo');
      result.tool_result = res;
      result.timings.completed_ms = elapsed();
      result.outcome = 'ok';
    } else if (scenario === 4 || scenario === 6) {
      callId = scenario === 4 ? 's4' : 's6';
      cancellation = new AbortController();
      if (scenario === 6) {
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (line) => {
          if (line.split(/\r?\n/).includes('cancel')) {
            result.timings.cancelled_ms = elapsed();
            cancellation.abort('fixture cancellation command');
          }
        });
        process.stdin.resume();
      }
      const res = await client.callTool({ name: 'progress', arguments: { count: scenario === 4 ? 3 : 1, hold: true, call_id: callId } }, {
        signal: cancellation.signal,
        onprogress: (event) => {
          if (result.timings.first_event_ms === null) result.timings.first_event_ms = elapsed();
          result.progress.push({ progress: event.progress, ...(event.total === undefined ? {} : { total: event.total }) });
        },
      });
      assertNotError(res, 'progress');
      result.tool_result = res;
      result.timings.completed_ms = elapsed();
      result.outcome = 'ok';
    }
  }
} catch (error) {
  if (!error?.unsupported) {
    result.sdk_error = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    result.outcome = 'fail';
  }
} finally {
  try { await client?.close(); } catch (error) { if (!result.sdk_error) result.sdk_error = String(error); }
  if (result.bridge.spawned && transport) {
    const child = transport._process;
    if (child?.exitCode !== null && child?.exitCode !== undefined) bridgeExit = child.exitCode;
    result.bridge.exit_code = bridgeExit;
    result.bridge.stdout_bytes = bridgeBytes;
    result.bridge.stderr_tail = bridgeStderr.slice(-2000);
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
