// Self-test for the modern matrix (contract.md section 8). It proves three
// things the matrix itself cannot: that the tamper proxy rewrites exactly the
// bytes it claims (unit and live relay), that the independent fakes and the
// driver agree on a clean run, and that the negative controls are still
// negative - a deviating client, a disabled proxy and a non-stripping server
// each have to fail the matrix. The module owns its exit code because
// interop/modern.mjs falls through to the matrix once selfTest() returns.
//
// node interop/modern.mjs --self-test
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as S from './support.mjs';
import { loadScenarios, runMatrix } from './matrix.mjs';
import { startTamperProxy, transformHead } from './proxy.mjs';

const HEAD_END = '\r\n\r\n';
// The raw head every proxy check rewrites: repeated X-Order lines prove that
// neither rewriting nor relaying folds or reorders header instances.
const HEAD = 'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Order: a\r\nX-Order: b\r\nJack-Auth: v1 kid=k,ts=1,nonce=n,sig=s\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: region.echo\r\n\r\n';
const JACK_AUTH_LINE = 'Jack-Auth: v1 kid=k,ts=1,nonce=n,sig=s';

// Split a raw head into its request line and header lines, dropping the
// terminator so a line count is comparable across rewrites.
const headLines = (text) => text.slice(0, -HEAD_END.length).split('\r\n');

// Send one raw head through the real relay to an upstream that records what it
// receives, answers once and closes. Everything is torn down here so a failed
// assertion in the caller cannot leave a listener or socket behind.
async function relayCheck(head) {
  let upstreamText = '';
  let answered = false;
  const upstream = net.createServer((socket) => {
    socket.setEncoding('latin1');
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      upstreamText += chunk;
      // One head is enough for a request; the proxy writes the head before it
      // pipes the body, so the terminator marks the end of what matters here.
      if (!answered && upstreamText.includes(HEAD_END)) {
        answered = true;
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      }
    });
  });
  let proxy = null;
  try {
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(0, '127.0.0.1', resolve);
    });
    const upstreamPort = upstream.address().port;
    proxy = await startTamperProxy({ upstreamPort, preset: 'tamper-name-once' });

    // Read the relayed reply to the socket's end: waiting for the close proves
    // the answer actually travelled back through the relay, not just upstream.
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port: proxy.port }, () => socket.write(head, 'latin1'));
      socket.setEncoding('latin1');
      let text = '';
      let finished = false;
      // A relay that never answers would hang the whole self-test, so the wait
      // is bounded; a real failure is a failed assertion, not a stuck run.
      const timer = setTimeout(() => {
        finished = true;
        socket.destroy();
        reject(new Error('tamper relay did not answer within 10s'));
      }, 10000);
      // A client socket has allowHalfOpen false by default, so the FIN that
      // follows the upstream answer ends the read; 'close' is a safety net for
      // a reset.
      const done = () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(text);
      };
      socket.on('data', (chunk) => { text += chunk; });
      socket.on('end', done);
      socket.on('close', done);
      // Clearing the timer on a connection error keeps a rejection from holding
      // the process open for the rest of the timeout.
      socket.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });

    return {
      upstreamText,
      first: upstreamText.indexOf('X-Order: a'),
      second: upstreamText.indexOf('X-Order: b'),
      requests: proxy.requests(),
    };
  } finally {
    if (proxy !== null) {
      try { await proxy.close(); } catch { /* best effort */ }
    }
    try { upstream.closeAllConnections(); } catch { /* older Node */ }
    await new Promise((resolve) => upstream.close(() => resolve()));
  }
}

// Run interop/modern.mjs as a child so the negative controls exercise the real
// CLI: argument validation, exit codes and the driver's own output. Output is
// drained on both pipes so a chatty failure can never block the child.
function runChild(args, extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(S.REPO_ROOT, 'interop', 'modern.mjs'), ...args], {
      cwd: S.REPO_ROOT,
      env: { ...process.env, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

export async function selfTest() {
  const fakeDir = join(S.SCRIPT_DIR, '..', 'tools', 'fakes', 'modern');
  const fakeServer = join(fakeDir, 'fake-modern-server.mjs');
  const fakeClient = join(fakeDir, 'fake-modern-client.mjs');
  if (!existsSync(fakeServer)) S.fail(`missing self-test fake: ${fakeServer}`);
  if (!existsSync(fakeClient)) S.fail(`missing self-test fake: ${fakeClient}`);

  const targets = { fake: { modern_server: [process.execPath, fakeServer], modern_client: [process.execPath, fakeClient] } };
  const scenarios = loadScenarios();
  const fixtures = S.loadFixtures();
  let checks = 0;
  const ok = (condition, what) => {
    if (!condition) {
      process.stderr.write('self-test failed: ' + what + '\n');
      process.exit(1);
    }
    checks += 1;
    process.stdout.write('self-test: ' + what + '\n');
  };

  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-modern-selftest-'));
  const removeTmp = () => {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  // ok() exits directly, which skips finally blocks; the exit hook is what
  // still removes the temp dir on the first failed assertion.
  process.once('exit', removeTmp);
  try {
    const targetsPath = join(tmp, 'targets.json');
    writeFileSync(targetsPath, JSON.stringify(targets));

    // ---- 1. proxy rewrite units, no process needed ---------------------------
    const original = headLines(HEAD);

    const passthrough = transformHead(HEAD, 'pass', false);
    ok(passthrough.head === HEAD && passthrough.applied === false,
      'pass returns the head unchanged and leaves the latch untouched');

    const named = transformHead(HEAD, 'tamper-name-once', false);
    ok(named.applied === true && named.head.includes('Mcp-Name: region.other'),
      'tamper-name-once rewrites Mcp-Name and latches');
    ok(named.head.includes(JACK_AUTH_LINE),
      'tamper-name-once leaves the Jack-Auth line untouched');
    const orderA = named.head.indexOf('X-Order: a');
    const orderB = named.head.indexOf('X-Order: b');
    ok(orderA !== -1 && orderB !== -1 && orderA < orderB,
      'tamper-name-once keeps repeated X-Order instances in order');
    const latched = transformHead(named.head, 'tamper-name-once', true);
    ok(latched.head === named.head && latched.applied === true,
      'an already applied preset returns a later head unchanged');

    const duplicated = transformHead(HEAD, 'duplicate-version', false);
    ok(duplicated.applied === true && (duplicated.head.match(/MCP-Protocol-Version:/g) || []).length === 2,
      'duplicate-version emits exactly two MCP-Protocol-Version lines');
    const duplicateLines = headLines(duplicated.head);
    const versionIndex = duplicateLines.indexOf('MCP-Protocol-Version: 2026-07-28');
    const withoutDuplicate = duplicateLines.filter((line, i) => i !== versionIndex);
    ok(versionIndex !== -1 && duplicateLines[versionIndex + 1] === duplicateLines[versionIndex]
      && JSON.stringify(withoutDuplicate) === JSON.stringify(original),
      'duplicate-version inserts one copy and keeps every other line in place');

    const session = transformHead(HEAD, 'add-session', false);
    const sessionLines = headLines(session.head);
    ok(session.applied === true
      && sessionLines[sessionLines.length - 2] === 'Mcp-Session-Id: sess-1'
      && sessionLines[sessionLines.length - 1] === 'Last-Event-ID: 7',
      'add-session appends the two session headers as the last header lines');
    ok(sessionLines.length === original.length + 2 && session.head.endsWith(HEAD_END),
      'add-session adds exactly two lines and keeps the head terminator');

    const method = transformHead(HEAD, 'tamper-method-once', false);
    ok(method.applied === true && method.head.includes('Mcp-Method: tools/list')
      && method.head.includes('Mcp-Name: region.echo'),
      'tamper-method-once rewrites Mcp-Method and leaves Mcp-Name');

    let unknownThrew = false;
    try {
      transformHead(HEAD, 'nope', false);
    } catch {
      unknownThrew = true;
    }
    ok(unknownThrew, 'an unknown preset throws');

    // ---- 2. the same rewrite on the wire, through the real relay ------------
    const relay = await relayCheck(HEAD);
    ok(relay.upstreamText.includes('Mcp-Name: region.other'),
      'the relay forwards the rewritten Mcp-Name upstream');
    ok(relay.first !== -1 && relay.second !== -1 && relay.first < relay.second,
      'the relay preserves repeated header instances and their order');
    ok(relay.requests === 1, `the relay forwarded exactly one request (got ${relay.requests})`);

    // ---- 3. clean in-process matrix run with the fakes ---------------------
    // The run count is taken from the table: a scenario with a runs array owns
    // one server and one client process per run, everything else one each.
    const totalRuns = scenarios.order.reduce((sum, id) => {
      const runs = scenarios.scenarios[id].runs;
      return sum + (Array.isArray(runs) && runs.length > 0 ? runs.length : 1);
    }, 0);

    const res = await runMatrix({
      clientLangs: ['fake'],
      serverLangs: ['fake'],
      targets,
      fixtures,
      scenarios,
      scenarioFilter: null,
    });
    ok(res.failures.length === 0,
      `the in-process fake run has no failures (got ${res.failures.length})`);
    ok(res.pairSummaries.length === 1
      && res.pairSummaries[0].passed === scenarios.order.length
      && res.pairSummaries[0].total === scenarios.order.length,
      `the fake pair passes all ${scenarios.order.length} scenarios`);
    ok(res.matrixCells.fake?.fake?.passed === scenarios.order.length,
      'the fake/fake matrix cell passes every scenario');
    ok(res.processesSpawned === 2 * totalRuns,
      `the fake pair spawns one server and one client per run (${2 * totalRuns}, got ${res.processesSpawned})`);

    // ---- 4. subprocess controls --------------------------------------------
    const matrixArgs = ['--targets', targetsPath, '--servers', 'fake', '--clients', 'fake'];

    const deviated = await runChild(matrixArgs, { JACK_MODERN_DEVIATE: 'modern-discover' });
    ok(deviated.code === 1, `a deviating client exits 1 (got ${deviated.code})`);
    ok(deviated.out.includes('FAIL modern-discover'), 'a deviating client fails modern-discover');

    const noTamper = await runChild(matrixArgs, { JACK_MODERN_SELFTEST_NO_TAMPER: '1' });
    ok(noTamper.code === 1, `the no-tamper control exits 1 (got ${noTamper.code})`);
    ok(noTamper.out.includes('FAIL modern-mismatch-name'),
      'modern-mismatch-name fails when the proxy is disabled');
    ok(noTamper.out.includes('FAIL modern-repeated-version'),
      'modern-repeated-version fails when the proxy is disabled');

    const noStrip = await runChild(matrixArgs, { JACK_MODERN_SERVER_DEVIATE: 's8' });
    ok(noStrip.code === 1, `the no-strip control exits 1 (got ${noStrip.code})`);
    ok(noStrip.out.includes('FAIL modern-session-stripped'),
      'a server that does not strip session headers fails modern-session-stripped');

    const listed = await runChild(['--list'], {});
    const listedIds = listed.out.split('\n').map((line) => line.trim()).filter(Boolean);
    ok(listed.code === 0 && JSON.stringify(listedIds) === JSON.stringify(scenarios.order),
      `--list prints exactly the ${scenarios.order.length} scenario ids in order`);

    // Targets that carry the rotation-style roles only: the modern roles are
    // missing, which is a usage error and must not look like a scenario mismatch.
    const roleLessPath = join(tmp, 'roles-targets.json');
    writeFileSync(roleLessPath, JSON.stringify({ fake: { server: ['node', 'x'], client: ['node', 'y'] } }));
    const roleLess = await runChild(['--targets', roleLessPath, '--servers', 'fake', '--clients', 'fake'], {});
    ok(roleLess.code === 2, `targets without the modern roles exit 2 (got ${roleLess.code})`);

    // ---- 5. the clean subprocess path --------------------------------------
    // Contract, driver and fakes agree only if the real CLI reports a full pass.
    const clean = await runChild(matrixArgs, {});
    ok(clean.code === 0, `the clean subprocess run exits 0 (got ${clean.code})`);
    ok(clean.out.includes('modern matrix: all pairs pass'),
      'the clean subprocess prints the all-pairs-pass line');
    ok(clean.out.includes('INTEROP-SUMMARY matrix=modern'),
      'the clean subprocess prints the modern summary line');
  } finally {
    removeTmp();
  }

  process.stdout.write(`self-test: ok (${checks} checks)\n`);
  process.exit(0);
}
