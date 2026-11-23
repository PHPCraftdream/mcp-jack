// Modern matrix driver: one (client language, server language) cell runs every scenario of interop/modern-scenarios.json against a dedicated server, optionally through the tamper proxy, and verifies the responses itself with the pinned fixture key.
import { join, resolve } from 'node:path';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as S from './support.mjs';
import { startTamperProxy } from './proxy.mjs';

// The fixed clock every run writes into --clock-file (contract section 2), so
// every timestamp in a run is exactly this value on both sides.
export const FIXED_NOW = 1800000000;

// Spec 01 section 5: the only refusal family that may lack a Jack-Auth
// signature, and only with status 401.
export const UNSIGNED_401_CODES = new Set([
  'missing_auth',
  'malformed_auth',
  'unsupported_version',
  'unknown_key',
  'key_inactive',
  'timestamp_out_of_window',
  'bad_signature',
  'replayed_nonce',
]);

// Live children and the temp root are module state because the exit handlers
// are installed once and must still see processes spawned by later calls.
const allChildren = new Set();
let activeTmpRoot = null;
let exitHandlersInstalled = false;

// An ephemeral port may be claimed by another process between allocPort() and
// the server's bind. That is an environment race, so the whole pair is retried
// with fresh ports; product checks themselves are never retried.
class StartupPortRace extends Error {}

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// Compact rendering for diagnostics: a raw JSON dump can be huge, and the
// first kilobyte already tells which member differs.
function truncateJson(value) {
  const text = JSON.stringify(value) ?? String(value);
  return text.length > 1200 ? text.slice(0, 1200) + '...' : text;
}

// The contract's code derivation: an integer JSON-RPC error code first, then a
// string Jack envelope code, else null.
function wireCode(error) {
  if (!isObject(error)) return null;
  if (Number.isInteger(error.code)) return error.code;
  if (typeof error.code === 'string') return error.code;
  return null;
}

// Walk a dotted path through plain objects only; a missing intermediate is
// "absent", which is what absent_paths wants.
function resolvesPath(root, path) {
  let current = root;
  for (const part of path.split('.')) {
    if (!isObject(current) || !Object.prototype.hasOwnProperty.call(current, part)) return false;
    current = current[part];
  }
  return true;
}

// Small per-step summary for the actual: block; the full view is too wide.
const describeStep = (view) => ({
  name: view.name ?? null,
  http_status: view.http_status,
  signed: view.signed,
  code: wireCode(view.error),
});

// A reason may carry a child's stderr tail; keep the block readable by
// indenting continuation lines under the reason line.
const indentContinuation = (text, pad) => text.split('\n').map((line, i) => (i === 0 ? line : pad + line)).join('\n');

// Kill every live child; used by the exit and signal handlers.
function killAllChildren() {
  for (const child of allChildren) S.killTree(child);
}

// Register the cleanup handlers once per process: children are killed and the
// temp root removed even when the driver is interrupted or exits via fail().
function installExitHandlers() {
  if (exitHandlersInstalled) return;
  exitHandlersInstalled = true;
  process.on('exit', () => {
    killAllChildren();
    if (activeTmpRoot !== null) {
      try { rmSync(activeTmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });
  process.on('SIGINT', () => { killAllChildren(); process.exit(130); });
  process.on('SIGTERM', () => { killAllChildren(); process.exit(143); });
}

// Read the scenario table and validate its shape. Every problem names the file
// and the scenario id so a broken table is never mistaken for a product bug.
export function loadScenarios() {
  const path = join(S.SCRIPT_DIR, 'modern-scenarios.json');
  const doc = S.readJson(path, 'modern scenario table');
  if (!isObject(doc)) S.fail(`invalid scenario table: ${path} is not a JSON object`);
  if (!isObject(doc.scenarios)) S.fail(`invalid scenario table: ${path} has no 'scenarios' object`);
  const order = doc.scenario_order;
  if (!Array.isArray(order) || order.length === 0 || !order.every((id) => typeof id === 'string')) {
    S.fail(`invalid scenario table: ${path} 'scenario_order' is not a non-empty array of strings`);
  }
  const scenarios = doc.scenarios;
  for (const id of order) {
    const sc = scenarios[id];
    if (!isObject(sc)) S.fail(`invalid scenario table: ${path} names unknown scenario '${id}' in scenario_order`);
    const runs = Array.isArray(sc.runs) && sc.runs.length > 0 ? sc.runs : null;
    if (sc.expected === undefined && runs === null) {
      S.fail(`invalid scenario table: ${path} scenario '${id}' has neither 'expected' nor a non-empty 'runs' array`);
    }
    if (runs === null) continue;
    runs.forEach((run, index) => {
      if (!isObject(run)) S.fail(`invalid scenario table: ${path} scenario '${id}' run ${index} is not an object`);
      for (const field of ['server', 'client', 'expected']) {
        if (run[field] === undefined || run[field] === null) {
          S.fail(`invalid scenario table: ${path} scenario '${id}' run ${index} is missing '${field}'`);
        }
      }
    });
  }
  return { order, scenarios };
}

// Evaluate one run against its expectation. Neither the client's claim about a
// body nor its own classification is trusted: every response is re-parsed and
// re-verified here with the pinned fixture key.
function evaluateRun({ result, expected, serverKey, svcKid, logPath }) {
  const reasons = [];
  const rawSteps = result.data.steps;
  const views = [];

  for (let i = 0; i < rawSteps.length; i++) {
    const step = rawSteps[i];
    if (!isObject(step)) {
      reasons.push(`malformed step ${i}`);
      views.push(null);
      continue;
    }
    const status = Number.isInteger(step.http_status) ? step.http_status : null;
    const body = Buffer.from(String(step.response_body_b64u ?? ''), 'base64url');
    const parsed = S.parseJsonBody(body);
    const sig = S.verifyResponse(serverKey, step.response_auth ?? null, status, step.request_sig ?? '', body);
    const view = {
      name: step.name,
      http_method: step.http_method,
      http_target: step.http_target,
      jsonrpc_method: step.jsonrpc_method,
      http_status: step.http_status,
      id: parsed.id,
      result: parsed.result,
      error: parsed.error,
      request_headers: step.request_headers,
      request_body_b64u: step.request_body_b64u,
      response_body_b64u: step.response_body_b64u,
      response_content_type: step.response_content_type,
      response_allow: step.response_allow,
      response_session_id: step.response_session_id,
      signed: sig.present,
    };
    views.push(view);

    if (sig.present && !sig.ok) reasons.push(`bad response signature (${sig.code})`);
    else if (sig.present && sig.kid !== svcKid) reasons.push(`response signed by an unexpected kid ${sig.kid}`);
    // The unsigned-allowed family is exactly 401 plus a Jack envelope naming a
    // spec 01 section 5 code; every other unsigned response is a failure.
    const envelopeCode = isObject(parsed.json) && isObject(parsed.json.error) && typeof parsed.json.error.code === 'string'
      ? parsed.json.error.code
      : null;
    const unsignedAllowed = status === 401 && envelopeCode !== null && UNSIGNED_401_CODES.has(envelopeCode);
    if (!sig.present && !unsignedAllowed) reasons.push(`unsigned response (status ${status})`);
  }

  // Top-level report fields, strictly, only when the expectation states them.
  for (const field of ['outcome', 'http_status', 'code', 'era']) {
    if (expected[field] === undefined) continue;
    const actual = field === 'era' ? result.data?.era : result[field];
    if (actual !== expected[field]) {
      reasons.push(`${field} ${JSON.stringify(actual)} does not match expected ${JSON.stringify(expected[field])}`);
    }
  }

  // The client's own classification must agree with the driver's parse of the
  // last response; unsupported_version_no_overlap is a client decision that is
  // accepted exactly where the wire said -32022.
  const last = views.length > 0 ? views[views.length - 1] : null;
  if (last !== null) {
    if (result.http_status !== last.http_status) {
      reasons.push(`client http_status ${JSON.stringify(result.http_status)} does not match the last response status ${JSON.stringify(last.http_status)}`);
    }
    const lastCode = wireCode(last.error);
    const reportCode = result.code === undefined ? null : result.code;
    const accepted = reportCode === lastCode || (reportCode === 'unsupported_version_no_overlap' && lastCode === -32022);
    if (!accepted) {
      reasons.push(`client code ${JSON.stringify(reportCode)} does not match the last response code ${JSON.stringify(lastCode)}`);
    }
  }

  if (expected.steps !== undefined) {
    const expectedSteps = expected.steps;
    if (rawSteps.length !== expectedSteps.length) {
      reasons.push(`step count ${rawSteps.length}, expected ${expectedSteps.length}`);
    }
    const shared = Math.min(rawSteps.length, expectedSteps.length);
    for (let i = 0; i < shared; i++) {
      const view = views[i];
      if (view === null) continue; // already reported as malformed
      if (!S.subsetMatches(expectedSteps[i], view)) {
        reasons.push(`step ${i} (${view.name ?? '?'}) mismatch: expected ${truncateJson(expectedSteps[i])}, actual ${truncateJson(view)}`);
      }
    }
  }

  if (expected.result !== undefined) {
    const lastResult = last === null ? null : last.result;
    if (!S.subsetMatches(expected.result, lastResult)) {
      reasons.push(`result mismatch: expected ${truncateJson(expected.result)}, actual ${truncateJson(lastResult)}`);
    }
  }

  for (const path of expected.absent_paths ?? []) {
    if (last !== null && resolvesPath(last.result, path)) reasons.push(`result must not contain ${path}`);
  }

  if (expected.header_echo !== undefined) {
    const echoText = last === null ? undefined : last.result?.content?.[0]?.text;
    const parsedEcho = typeof echoText === 'string' ? S.parseHeaderEcho(echoText) : null;
    if (parsedEcho === null) {
      reasons.push("header echo is not 'name: value' lines");
    } else {
      const problem = S.headerPredicate(parsedEcho.map((entry) => [entry.name, entry.value]), expected.header_echo);
      if (problem !== null) reasons.push(`header echo: ${problem}`);
    }
  }

  for (const [stepName, spec] of Object.entries(expected.request_headers ?? {})) {
    const index = rawSteps.findIndex((step) => isObject(step) && step.name === stepName);
    if (index === -1) {
      reasons.push(`request header check names unknown step ${stepName}`);
      continue;
    }
    const headers = Array.isArray(rawSteps[index].request_headers) ? rawSteps[index].request_headers : [];
    const problem = S.headerPredicate(headers, spec);
    if (problem !== null) reasons.push(`request headers of ${stepName}: ${problem}`);
  }

  if (expected.server_request_log !== undefined) {
    const expectedLog = expected.server_request_log;
    let text = '';
    try {
      text = readFileSync(logPath, 'utf8');
    } catch (e) {
      // The driver truncated the file before the run, so ENOENT just means the
      // server never opened it: an empty log.
      if (e.code !== 'ENOENT') reasons.push(`cannot read request log: ${e.message}`);
    }
    const methods = [];
    for (const line of text.split('\n')) {
      if (line.trim() === '') continue;
      try {
        const entry = JSON.parse(line);
        methods.push(isObject(entry) ? entry.method ?? null : null);
      } catch {
        reasons.push('request log line is not JSON');
      }
    }
    if (JSON.stringify(methods) !== JSON.stringify(expectedLog)) {
      reasons.push(`request log [${methods.join(', ')}] does not match expected [${expectedLog.join(', ')}]`);
    }
  }

  return { reasons, views };
}

// Scenario invariants are evaluated over all runs of one scenario, after the
// per-run checks, so a scenario can fail purely for drifting bytes.
function checkInvariants(invariants, reports) {
  const problems = [];
  for (const name of invariants) {
    if (name === 'identical_request_bytes') {
      // A replay is a separate step, so the comparison is over steps, not runs.
      const steps = reports.flatMap((report) => report.steps).filter((step) => isObject(step));
      if (steps.length < 2) {
        problems.push(`invariant ${name} needs two runs`);
        continue;
      }
      const firstBody = steps[0].request_body_b64u;
      const firstSig = steps[0].request_sig;
      if (steps.some((step) => step.request_body_b64u !== firstBody || step.request_sig !== firstSig)) {
        problems.push('request bytes differ between steps');
      }
    } else if (name === 'identical_response_body_across_runs') {
      const lastSteps = reports.map((report) => (report.views.length > 0 ? report.views[report.views.length - 1] : null));
      if (reports.length < 2 || lastSteps[0] === null || lastSteps[1] === null) {
        problems.push(`invariant ${name} needs two runs`);
        continue;
      }
      if (lastSteps[0].response_body_b64u !== lastSteps[1].response_body_b64u
        || lastSteps[0].http_status !== lastSteps[1].http_status) {
        problems.push('response body differs between server profiles');
      }
    } else {
      // An unknown invariant name is a table defect, not a passing check.
      problems.push(`unknown invariant ${name}`);
    }
  }
  return problems;
}

export async function runMatrix({ clientLangs, serverLangs, targets, fixtures, scenarios, scenarioFilter = null }) {
  const failures = [];
  const matrixCells = {};
  const pairSummaries = [];
  let processesSpawned = 0;

  // One temp root per runMatrix call, not per pair: the clock and state files
  // are immutable for the whole matrix and shared by every child.
  const tmp = resolve(mkdtempSync(join(tmpdir(), 'mcp-jack-modern-')));
  activeTmpRoot = tmp;
  installExitHandlers();

  const clockPath = join(tmp, 'clk-clock');
  writeFileSync(clockPath, String(FIXED_NOW) + '\n');
  const statePath = join(tmp, 'state.json');
  writeFileSync(statePath, S.registryStateDoc(fixtures.registry));

  const svc = fixtures.keysByName.svc;
  const alice = fixtures.keysByName.alice;

  // Keep the table's order, never the filter's, so a partial run is a stable
  // subsequence of the full matrix.
  const selectedIds = scenarioFilter === null
    ? [...scenarios.order]
    : scenarios.order.filter((id) => scenarioFilter.includes(id));

  // Resolve a role's argv once per pair; the caller validated the targets, so
  // an empty argv here is a harness defect rather than a user error.
  function selectTarget(lang, role, label) {
    const argv = targets[lang]?.[role];
    if (!Array.isArray(argv) || argv.length === 0) S.fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
    return S.resolveTarget(argv, role, label);
  }

  for (const client of clientLangs) {
    matrixCells[client] = {};
    for (const server of serverLangs) {
      const pairLabel = `client=${client} server=${server}`;
      process.stdout.write(`== pair ${pairLabel} ==\n`);
      const result = await runPair(client, server, pairLabel);
      matrixCells[client][server] = { passed: result.passed, total: selectedIds.length };
      pairSummaries.push({ pairLabel, passed: result.passed, total: selectedIds.length });
      process.stdout.write(`pair ${pairLabel}: ${result.passed}/${selectedIds.length}\n`);
    }
  }

  return { failures, matrixCells, pairSummaries, processesSpawned };

  // ---- one (client, server) cell with a bounded retry of the startup port race only ----
  async function runPair(client, server, pairLabel) {
    const attempts = 3;
    for (let attempt = 1; ; attempt++) {
      try {
        const result = await runPairOnce(client, server, pairLabel);
        // Failures from a discarded attempt must not double count, so they are
        // only merged once the attempt completes.
        failures.push(...result.failures);
        return result;
      } catch (e) {
        if (!(e instanceof StartupPortRace) || attempt >= attempts) {
          if (e instanceof StartupPortRace) S.fail(e.message);
          throw e;
        }
        process.stdout.write(`pair ${pairLabel}: startup port race (${e.message.split('\n')[0]}); retrying with fresh ports (attempt ${attempt + 1}/${attempts})\n`);
        killAllChildren();
        allChildren.clear();
      }
    }
  }

  // ---- one (client, server) cell: every selected scenario against one dedicated server ----
  async function runPairOnce(client, server, pairLabel) {
    const serverTarget = selectTarget(server, 'modern_server', `server=${server}`);
    const clientTarget = selectTarget(client, 'modern_client', `client=${client}`);
    const cellFailures = [];
    let passed = 0;

    for (const id of selectedIds) {
      const sc = scenarios.scenarios[id];
      const declaredRuns = Array.isArray(sc.runs) && sc.runs.length > 0 ? sc.runs : null;
      const runs = declaredRuns ?? [{
        server: sc.server,
        client: sc.client,
        proxy: sc.proxy ?? null,
        expected: sc.expected,
      }];
      const invariants = Array.isArray(sc.invariants) ? sc.invariants : [];

      // The handler echoes the Host header, so parity between profiles needs
      // one port reused by every server of the scenario, allocated up front.
      const sharedPort = invariants.includes('identical_response_body_across_runs') ? await S.allocPort() : null;

      // Placeholders resolve once per run before any child starts; a bad
      // placeholder fails the scenario instead of crashing the matrix.
      const expectations = runs.map((run) => {
        try {
          return { ok: true, expected: S.resolvePlaceholders(run.expected, fixtures.keysByName) };
        } catch (e) {
          return { ok: false, reason: `cannot resolve expectation placeholders: ${e.message}` };
        }
      });

      const reports = [];
      let failedIndex = -1;
      let failedReasons = [];
      let failedExpected = null;
      let failedResult = null;

      for (let index = 0; index < runs.length; index++) {
        const expectedRun = expectations[index];
        if (!expectedRun.ok) {
          reports.push({ views: [], steps: [], reasons: [expectedRun.reason], result: null, stderr: '' });
          if (failedIndex === -1) {
            failedIndex = index;
            failedReasons = [expectedRun.reason];
            failedExpected = null;
            failedResult = null;
          }
          continue;
        }
        const report = await runOne({
          id,
          client,
          server,
          run: runs[index],
          runIndex: index,
          expected: expectedRun.expected,
          sharedPort,
          serverTarget,
          clientTarget,
          pairLabel,
        });
        reports.push(report);
        if (report.reasons.length > 0 && failedIndex === -1) {
          failedIndex = index;
          failedReasons = report.reasons;
          failedExpected = expectedRun.expected;
          failedResult = report.result;
        }
      }

      // Invariants run after every run; a violated invariant fails the
      // scenario even when each run matched its own expectation.
      const invariantProblems = checkInvariants(invariants, reports);
      if (invariantProblems.length > 0 && failedIndex === -1) {
        failedIndex = 0;
        failedReasons = invariantProblems;
        failedExpected = expectations[0]?.expected ?? null;
        failedResult = reports[0]?.result ?? null;
      }

      if (failedIndex === -1) {
        passed++;
        process.stdout.write(`PASS ${id}\n`);
        continue;
      }
      const failedReport = reports[failedIndex] ?? { views: [], stderr: '' };
      printFailure({
        id,
        pairLabel,
        runIndex: failedIndex,
        expected: failedExpected,
        result: failedResult,
        views: failedReport.views ?? [],
        reasons: failedReasons,
        stderr: failedReport.stderr ?? '',
      });
      cellFailures.push({ scenario: id, pair: pairLabel, run: failedIndex });
    }

    return { passed, failures: cellFailures };
  }

  // ---- one run: dedicated server, optional tamper proxy, one client process ----
  async function runOne({ id, client, server, run, runIndex, expected, sharedPort, serverTarget, clientTarget, pairLabel }) {
    const port = sharedPort ?? await S.allocPort();
    // The language names are in the log file name, like rotation.mjs, so a
    // leftover temp root after a crash is still attributable.
    const logPath = join(tmp, `log-${client}-${server}-${id}-${runIndex}.json`);
    // Truncate so the log holds exactly this run, per contract section 3.3.
    writeFileSync(logPath, '');

    const serverArgv = [
      '--profile', run.server?.profile ?? 'both',
      '--aud', fixtures.registry.aud,
      '--state', statePath,
      '--server-seed-hex', svc.seed_hex,
      '--clock-file', clockPath,
      '--port', String(port),
      '--request-log', logPath,
    ];
    if (Array.isArray(run.server?.supported_versions)) {
      serverArgv.push('--supported-versions', run.server.supported_versions.join(','));
    }
    if (run.server?.discover_version_mode) {
      serverArgv.push('--discover-version-mode', run.server.discover_version_mode);
    }

    const label = `${pairLabel} ${id} run ${runIndex}`;
    let serverChild = null;
    let clientChild = null;
    let proxy = null;

    // A run report snapshots the server stderr tail, which is still readable
    // after the child exits but not after a later run overwrites nothing.
    const report = (reasons, views = [], steps = [], result = null) => ({
      reasons,
      views,
      steps,
      result,
      stderr: serverChild === null ? '' : serverChild._stderrTail(),
    });

    try {
      serverChild = S.makeChild(serverTarget.cmd, [...serverTarget.args, ...serverArgv]);
      allChildren.add(serverChild);
      processesSpawned++;

      let readyLine;
      try {
        readyLine = await serverChild._nextLine(10000, `${label} modern_server`);
      } catch (e) {
        const tail = serverChild._stderrTail();
        const lastStderrLine = tail.split('\n').map((line) => line.trim()).filter(Boolean).pop() ?? '';
        // A child that closed during startup, or one whose stderr names a bind
        // failure, lost the port to the environment; a hang is a hard failure.
        if (/child closed before producing/.test(e.message) || /EADDRINUSE|address already in use/i.test(tail)) {
          throw new StartupPortRace(`${label}: modern_server could not bind 127.0.0.1:${port}: ${lastStderrLine || 'child closed during startup'}`);
        }
        S.fail(`${label}: ${e.message}`);
      }

      let ready = null;
      try {
        ready = JSON.parse(readyLine);
      } catch {
        ready = null;
      }
      if (!isObject(ready)) return report([`server ready line is not a JSON object: ${readyLine.slice(0, 400)}`]);

      const expectedProfile = run.server?.profile ?? 'both';
      const problems = [];
      if (ready.ready !== true) problems.push(`server ready line has ready=${JSON.stringify(ready.ready)}, expected true`);
      if (!Number.isInteger(ready.port)) {
        problems.push(`server ready line has port=${JSON.stringify(ready.port)}, expected integer ${port}`);
      } else if (ready.port !== port) {
        problems.push(`server bound port ${ready.port}, expected ${port}`);
      }
      if (ready.server_public_key !== svc.public_key) {
        problems.push(`server ready line has server_public_key=${JSON.stringify(ready.server_public_key)}, expected the pinned fixture svc public key`);
      }
      if (ready.server_kid !== svc.kid) {
        problems.push(`server ready line has server_kid=${JSON.stringify(ready.server_kid)}, expected the fixture svc kid`);
      }
      if (ready.profile !== expectedProfile) {
        problems.push(`server ready line has profile=${JSON.stringify(ready.profile)}, expected ${JSON.stringify(expectedProfile)}`);
      }
      if (problems.length > 0) return report(problems);

      let url = `http://127.0.0.1:${port}`;
      if (typeof run.proxy === 'string' && run.proxy !== '') {
        try {
          proxy = await startTamperProxy({
            upstreamPort: port,
            preset: run.proxy,
            disable: process.env.JACK_MODERN_SELFTEST_NO_TAMPER === '1',
          });
        } catch (e) {
          // A bad preset or a listener error is a harness problem; keep it as a
          // scenario failure so the rest of the matrix still runs.
          return report([`cannot start tamper proxy '${run.proxy}': ${e.message}`]);
        }
        url = `http://127.0.0.1:${proxy.port}`;
      }

      const clientArgv = [
        '--url', url,
        '--aud', fixtures.registry.aud,
        '--seed-hex', alice.seed_hex,
        '--anchor', svc.public_key,
        '--scenario', id,
        '--era', run.client?.era ?? 'modern',
        '--clock-file', clockPath,
        '--json-id', run.client?.json_id ?? '1',
      ];
      if (run.client?.probe_version) clientArgv.push('--probe-version', run.client.probe_version);

      clientChild = S.makeChild(clientTarget.cmd, [...clientTarget.args, ...clientArgv]);
      allChildren.add(clientChild);
      processesSpawned++;

      let exitCode;
      try {
        exitCode = await S.waitClose(clientChild, 30000, `${label} modern_client`);
      } catch (e) {
        return report([`client did not finish: ${e.message}`]);
      }
      const stderrTail = clientChild._stderrTail().slice(-1000);
      const lines = clientChild._stdoutText().split('\n').filter((line) => line.trim() !== '');
      const lastLine = lines.length > 0 ? lines[lines.length - 1].trim() : '';
      if (exitCode !== 0) {
        return report([`client exited ${exitCode}, expected 0; client stderr tail:\n${stderrTail}`]);
      }
      if (lastLine === '') {
        return report([`client printed no result line (exit ${exitCode}); client stderr tail:\n${stderrTail}`]);
      }
      let result;
      try {
        result = JSON.parse(lastLine);
      } catch {
        return report([`client result line is not JSON (exit ${exitCode}): ${lastLine.slice(0, 400)}; client stderr tail:\n${stderrTail}`]);
      }
      if (!isObject(result)) {
        return report([`client result line is not a JSON object (exit ${exitCode}): ${lastLine.slice(0, 400)}; client stderr tail:\n${stderrTail}`]);
      }

      const shape = [];
      if (result.scenario !== id) shape.push(`client reported scenario ${JSON.stringify(result.scenario)}, expected ${JSON.stringify(id)}`);
      if (!['ok', 'rejected', 'client_error'].includes(result.outcome)) {
        shape.push(`client outcome ${JSON.stringify(result.outcome)} is not one of ok, rejected, client_error`);
      }
      if (!Array.isArray(result.data?.steps)) shape.push("client data.steps is not an array");
      if (shape.length > 0) return report(shape, [], [], result);

      const evaluation = evaluateRun({ result, expected, serverKey: svc.public_key, svcKid: svc.kid, logPath });
      return {
        reasons: evaluation.reasons,
        views: evaluation.views,
        steps: result.data.steps,
        result,
        stderr: serverChild._stderrTail(),
      };
    } finally {
      // Tear down in reverse start order and always, even when StartupPortRace
      // unwinds the pair attempt, so the next attempt gets clean ports.
      if (proxy !== null) {
        try { await proxy.close(); } catch { /* best effort */ }
      }
      if (serverChild !== null) {
        await S.stopChild(serverChild);
        allChildren.delete(serverChild);
      }
      if (clientChild !== null) allChildren.delete(clientChild);
    }
  }

  // ---- failure diagnostics, in the interop/rotation.mjs style ----
  function printFailure({ id, pairLabel, runIndex, expected, result, views, reasons, stderr }) {
    const first = reasons[0] ?? 'failed';
    process.stdout.write(`FAIL ${id} (${first.split('\n')[0]})\n`);
    process.stdout.write(`  scenario: ${id}\n`);
    process.stdout.write(`  pair: ${pairLabel}\n`);
    process.stdout.write(`  run: ${runIndex}\n`);
    process.stdout.write(`  expected: ${truncateJson(expected ?? null)}\n`);
    const actual = result === null ? null : {
      outcome: result.outcome ?? null,
      http_status: result.http_status ?? null,
      code: result.code === undefined ? null : result.code,
      era: result.data?.era ?? null,
      steps: (views ?? []).filter((view) => isObject(view)).map(describeStep),
    };
    process.stdout.write(`  actual: ${truncateJson(actual)}\n`);
    for (const reason of reasons) {
      process.stdout.write(`  reason: ${indentContinuation(reason, '          ')}\n`);
    }
    process.stdout.write('  server stderr tail:\n');
    const tail = (stderr ?? '').trimEnd();
    if (tail === '') {
      process.stdout.write('    (none)\n');
    } else {
      for (const line of tail.split('\n').slice(-20)) process.stdout.write('    ' + line + '\n');
    }
  }
}
