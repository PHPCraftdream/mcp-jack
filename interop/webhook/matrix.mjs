// Webhook matrix driver: one cell is a (sender language, receiver language)
// pair; every selected scenario runs a dedicated receiver, the tamper relay
// where the scenario asks for one, and one sender, and the driver verifies the
// outcome itself (contract section 7).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as D from './derive.mjs';
import * as S from './support.mjs';
import { startRelay } from './relay.mjs';
import {
  buildRelayAttemptViews,
  buildDeliveryViews,
  evaluateScenario,
  splitSenderLines,
  truncateJson,
} from './evaluate.mjs';

// The scenario table lives next to this folder, not inside it.
export const SCENARIO_FILE = join(S.SCRIPT_DIR, '..', 'webhook-scenarios.json');
const MESSAGE_KINDS = ['event', 'gap', 'terminated', 'raw'];
// A plain JSON object: not null, not an array.
const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// Live children and the temp root are module state because the exit handlers
// are installed once and must still see processes spawned by later calls.
const allChildren = new Set();
let activeTmpRoot = null;
let exitHandlersInstalled = false;

function killAllChildren() {
  for (const child of allChildren) S.killTree(child);
}

function installExitHandlers() {
  if (exitHandlersInstalled) return;
  exitHandlersInstalled = true;
  process.on('exit', () => {
    killAllChildren();
    if (activeTmpRoot !== null) {
      try {
        rmSync(activeTmpRoot, { recursive: true, force: true });
      } catch {
        // best effort
      }
    }
  });
  process.on('SIGINT', () => {
    killAllChildren();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    killAllChildren();
    process.exit(143);
  });
}

// Read the scenario table and validate its shape. Every problem names the
// file and the scenario id so a broken table is never mistaken for a product
// bug.
export function loadScenarios() {
  const doc = S.readJson(SCENARIO_FILE, 'webhook scenario table');
  if (!isObject(doc)) S.fail(`invalid scenario table: ${SCENARIO_FILE} is not a JSON object`);
  if (!isObject(doc.scenarios)) S.fail(`invalid scenario table: ${SCENARIO_FILE} has no 'scenarios' object`);
  const order = doc.scenario_order;
  if (!Array.isArray(order) || order.length === 0 || !order.every((id) => typeof id === 'string')) {
    S.fail(`invalid scenario table: ${SCENARIO_FILE} 'scenario_order' is not a non-empty array of strings`);
  }
  const scenarios = doc.scenarios;
  for (const id of order) {
    const sc = scenarios[id];
    if (!isObject(sc)) S.fail(`invalid scenario table: ${SCENARIO_FILE} names unknown scenario '${id}' in scenario_order`);
    if (!isObject(sc.sender)) S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' has no 'sender' object`);
    if (!isObject(sc.receiver) || typeof sc.receiver.start !== 'boolean') {
      S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' has no 'receiver' object with a boolean 'start'`);
    }
    if (!isObject(sc.expected)) S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' has no 'expected' object`);
    for (const field of ['sender', 'deliveries']) {
      if (sc.expected[field] === undefined) {
        S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' expected is missing '${field}'`);
      }
    }
    if (sc.sender.messages !== undefined) {
      const messages = sc.sender.messages;
      if (!Array.isArray(messages) || messages.length === 0 || !messages.every((kind) => MESSAGE_KINDS.includes(kind))) {
        S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' sender.messages is not a non-empty array of ${MESSAGE_KINDS.join(', ')}`);
      }
    }
    if (sc.relay !== undefined && sc.relay !== null && typeof sc.relay !== 'string') {
      S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' relay is neither null nor a string`);
    }
    if (sc.gap !== undefined && !isObject(sc.gap)) {
      S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' gap is not an object`);
    }
    if (sc.shadow !== undefined && typeof sc.shadow !== 'boolean') {
      S.fail(`invalid scenario table: ${SCENARIO_FILE} scenario '${id}' shadow is not a boolean`);
    }
  }
  return { order, scenarios };
}

// One JSON object per non-empty stdout line; a line that is not one is a
// reason of its own and is skipped so the rest of the run is still judged.
function parseLines(text, label, reasons) {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (line === '') continue;
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      reasons.push(`the ${label} printed a line that is not a JSON object: ${line.slice(0, 200)}`);
      continue;
    }
    if (!isObject(value)) {
      reasons.push(`the ${label} printed a line that is not a JSON object: ${line.slice(0, 200)}`);
      continue;
    }
    out.push(value);
  }
  return out;
}

// Failure diagnostics, in the modern matrix's block shape: the headline names
// the scenario and the first reason, the block carries the table row, the
// driver's actual, one line per reason and both stderr tails.
function printFailure({ id, pairLabel, expected, actual, reasons, senderStderr, receiverStderr }) {
  const first = reasons[0] ?? 'failed';
  process.stdout.write(`FAIL ${id} (${first.split('\n')[0]})\n`);
  process.stdout.write(`  scenario: ${id}\n`);
  process.stdout.write(`  pair: ${pairLabel}\n`);
  process.stdout.write(`  expected: ${truncateJson(expected ?? null)}\n`);
  process.stdout.write(`  actual: ${truncateJson(actual ?? null)}\n`);
  for (const reason of reasons) {
    const lines = String(reason).split('\n');
    process.stdout.write(`  reason: ${lines[0]}\n`);
    for (const line of lines.slice(1)) process.stdout.write(`          ${line}\n`);
  }
  const tails = [['sender stderr tail', senderStderr], ['receiver stderr tail', receiverStderr]];
  for (const [title, text] of tails) {
    process.stdout.write(`  ${title}:\n`);
    const tail = String(text ?? '').trimEnd();
    if (tail === '') {
      process.stdout.write('    (none)\n');
    } else {
      for (const line of tail.split('\n').slice(-15)) process.stdout.write('    ' + line + '\n');
    }
  }
}

export async function runMatrix({ senders, receivers, targets, fixtures, scenarios, scenarioFilter = null }) {
  const failures = [];
  const skipped = [];
  const matrixCells = {};
  const pairSummaries = [];
  let processesSpawned = 0;

  // One temp root per runMatrix call, not per pair: the throw-away TLS files
  // are minted once and shared by every receiver and every relay.
  const tmp = resolve(mkdtempSync(join(tmpdir(), 'mcp-jack-webhook-')));
  activeTmpRoot = tmp;
  installExitHandlers();
  const tlsDir = join(tmp, 'tls');
  mkdirSync(tlsDir, { recursive: true });
  const tls = S.ensureTlsFiles(tlsDir);

  // Keep the table's order, never the filter's, so a partial run is a stable
  // subsequence of the full matrix.
  const selectedIds = scenarioFilter === null
    ? [...scenarios.order]
    : scenarios.order.filter((id) => scenarioFilter.includes(id));

  // Resolve a role's argv once per cell; the caller validated the targets, so
  // an empty argv here is a harness defect rather than a user error.
  function selectTarget(lang, role, label) {
    const argv = targets[lang]?.[role];
    if (!Array.isArray(argv) || argv.length === 0) S.fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
    return S.resolveTarget(argv, role, label);
  }

  for (const sender of senders) {
    matrixCells[sender] = {};
    for (const receiver of receivers) {
      const pairLabel = `sender=${sender} receiver=${receiver}`;
      process.stdout.write(`== pair ${pairLabel} ==\n`);
      const senderTarget = selectTarget(sender, 'webhook_sender', pairLabel);
      const receiverTarget = selectTarget(receiver, 'webhook_receiver', pairLabel);
      let passed = 0;
      let skippedHere = 0;

      for (const id of selectedIds) {
        const sc = scenarios.scenarios[id];
        const gapReason = isObject(sc.gap) && typeof sc.gap[sender] === 'string' ? sc.gap[sender] : null;
        if (gapReason !== null) {
          process.stdout.write(`SKIP ${id} (sender=${sender}: ${gapReason})\n`);
          skipped.push({ scenario: id, pair: pairLabel, sender });
          skippedHere++;
          continue;
        }
        const result = await runScenario({ id, sc, sender, receiver, pairLabel, senderTarget, receiverTarget });
        if (result.reasons.length === 0) {
          passed++;
          process.stdout.write(`PASS ${id}\n`);
        } else {
          printFailure({
            id,
            pairLabel,
            expected: result.expected,
            actual: result.actual,
            reasons: result.reasons,
            senderStderr: result.senderStderr,
            receiverStderr: result.receiverStderr,
          });
          failures.push({ scenario: id, pair: pairLabel });
        }
      }

      // A cell that a declared SDK gap excluded is not a failed check, so the
      // total of the cell is the scenarios it was actually asked to judge.
      const total = selectedIds.length - skippedHere;
      const cell = { passed, total, skipped: skippedHere };
      matrixCells[sender][receiver] = cell;
      pairSummaries.push({ pairLabel, ...cell });
      process.stdout.write(`pair ${pairLabel}: ${passed}/${total}${skippedHere > 0 ? ` (${skippedHere} skipped)` : ''}\n`);
    }
  }

  return { failures, skipped, matrixCells, pairSummaries, processesSpawned };

  // ---- one scenario: dedicated receiver, optional relay and shadow listener, one sender ----
  async function runScenario({ id, sc, sender, receiver, pairLabel, senderTarget, receiverTarget }) {
    const label = `${pairLabel} ${id}`;
    const receiverWanted = sc.receiver.start === true;
    // A preset makes the relay the sender's endpoint; `null` means no relay.
    const relayPreset = typeof sc.relay === 'string' ? sc.relay : null;
    // The self-test proves the tamper scenarios need the relay by forcing pass.
    const preset = relayPreset !== null && process.env.JACK_WEBHOOK_SELFTEST_NO_TAMPER === '1' ? 'pass' : relayPreset;

    let receiverPort = null;
    let receiverChild = null;
    let senderChild = null;
    let relay = null;
    let relayRecords = [];
    let shadow = null;
    let shadowConnections = 0;
    let expected = null;

    // A report snapshots both stderr tails while the children are still alive.
    const report = (reasons, actual = null) => ({
      reasons,
      expected,
      actual,
      senderStderr: senderChild === null ? '' : senderChild._stderrTail(),
      receiverStderr: receiverChild === null ? '' : receiverChild._stderrTail(),
    });

    const seedOf = (field, name) => {
      const entry = fixtures.keysByName[name];
      if (entry === undefined) S.fail(`scenario ${id} names unknown fixture key '${name}' in sender.${field}`);
      return entry.seed_hex;
    };

    if (!receiverWanted && relayPreset === null) {
      return report([`scenario ${id} starts neither a receiver nor a relay`]);
    }

    try {
      // Every file of a run carries the languages and the scenario in its name,
      // so a leftover temp root after a crash is still attributable. None of
      // these files carries the port, so they are written before it is chosen.
      const stem = `${sender}-${receiver}-${id}`;
      const senderClockPath = join(tmp, `clock-sender-${stem}`);
      const receiverClockPath = join(tmp, `clock-receiver-${stem}`);
      const senderOffset = Number.isInteger(sc.sender.clock_offset) ? sc.sender.clock_offset : 0;
      const receiverOffset = Number.isInteger(sc.receiver.clock_offset) ? sc.receiver.clock_offset : 0;
      S.writeClock(senderClockPath, D.CLOCK_BASE + senderOffset);
      S.writeClock(receiverClockPath, D.CLOCK_BASE + receiverOffset);
      const resolverPath = S.writeText(
        join(tmp, `resolver-${stem}.json`),
        JSON.stringify(sc.sender.resolver ?? { [D.CALLBACK_HOST]: ['127.0.0.1'] }),
      );
      let bodyPath = null;
      if (typeof sc.sender.body === 'string') {
        const bytes = D.RAW_BODIES[sc.sender.body];
        if (bytes === undefined) S.fail(`scenario ${id} names unknown raw body '${sc.sender.body}'`);
        bodyPath = join(tmp, `body-${stem}`);
        writeFileSync(bodyPath, bytes);
      }
      let cardPath = null;
      if (Array.isArray(sc.receiver.card)) {
        cardPath = S.writeText(join(tmp, `card-${stem}.json`), S.cardDocument(fixtures.keysByName, sc.receiver.card));
      }

      // The relay, when the scenario has one, IS the sender's endpoint, so it
      // binds first: the port it reports is a port a process listens on, and it
      // is the port the callback URL, the subscription id and every value
      // derived from them carry. Nothing else allocates it. The upstream side
      // stays unresolved until the receiver has proven its own port.
      if (preset !== null) {
        try {
          relay = await startRelay({
            upstreamPort: () => receiverPort,
            preset: preset,
            certPem: tls.certPem,
            keyPem: tls.keyPem,
            caPem: tls.caPem,
          });
        } catch (e) {
          // A bad preset or a listener error is a harness problem; keep it as
          // a scenario failure so the rest of the matrix still runs.
          return report([`cannot start the tamper relay '${preset}': ${e.message}`]);
        }
      }

      // A receiver takes its port from its command line, so the number exists
      // before the child does and only the ready line proves the bind. The probe
      // releases the port, so another process can take it in between: that case
      // is retried on a fresh port, with the callback URL, the subscription id
      // and every placeholder resolved again, so the sender is never aimed at an
      // endpoint nobody listens on.
      const portAttempts = receiverWanted ? 3 : 1;
      let url = '';
      let subscriptionId = '';
      let vars = { keysByName: fixtures.keysByName, subscriptionId, url };
      let receiverStartError = null;
      for (let attempt = 0; attempt < portAttempts; attempt++) {
        if (receiverWanted) receiverPort = await S.allocPort();
        const endpointPort = relay === null ? receiverPort : relay.port;
        if (endpointPort === null) return report([`scenario ${id} has no endpoint to dial`]);
        url = D.callbackUrl(endpointPort);
        subscriptionId = D.subscriptionId(url);
        vars = { keysByName: fixtures.keysByName, subscriptionId, url };
        if (!receiverWanted) break;

        // Resolved per attempt: `$sub` and `$url` belong to this port.
        const attemptCfg = D.resolvePlaceholders(sc.receiver, vars);
        const receiverArgs = [
          '--port', String(receiverPort),
          '--tls-cert', tls.certPem,
          '--tls-key', tls.keyPem,
          '--clock-file', receiverClockPath,
          '--secret-seed', D.SECRET_SEED,
          '--subscription-id', subscriptionId,
          '--callback-url', url,
          '--aud', D.AUD,
        ];
        if (cardPath !== null) receiverArgs.push('--card-file', cardPath, '--card-mcp-url', D.CARD_MCP_URL);
        if (attemptCfg.enforce === true) receiverArgs.push('--enforce-server-identity');
        if (attemptCfg.require_jack === true) receiverArgs.push('--require-jack');
        if (typeof attemptCfg.mcp_server_kid === 'string') receiverArgs.push('--mcp-server-kid', attemptCfg.mcp_server_kid);
        if (Number.isInteger(attemptCfg.enqueue_fail) && attemptCfg.enqueue_fail > 0) {
          receiverArgs.push('--enqueue-fail', String(attemptCfg.enqueue_fail));
        }
        if (attemptCfg.pending_secret === true) receiverArgs.push('--pending-secret');

        receiverChild = S.makeChild(receiverTarget.cmd, [...receiverTarget.args, ...receiverArgs], { SSL_CERT_FILE: tls.caPem });
        allChildren.add(receiverChild);
        processesSpawned++;

        // The ready line proves the port before anything dials it.
        let readyLine;
        try {
          readyLine = await receiverChild._nextLine(10000, `${label} webhook_receiver`);
        } catch (e) {
          await S.stopChild(receiverChild);
          allChildren.delete(receiverChild);
          receiverChild = null;
          receiverStartError = e.message;
          continue;
        }
        let ready = null;
        try {
          ready = JSON.parse(readyLine);
        } catch {
          ready = null;
        }
        if (!isObject(ready)) return report([`receiver ready line is not a JSON object: ${readyLine.slice(0, 400)}`]);
        const problems = [];
        if (ready.ready !== true) problems.push(`receiver ready line has ready=${JSON.stringify(ready.ready)}, expected true`);
        if (ready.role !== 'receiver') problems.push(`receiver ready line has role=${JSON.stringify(ready.role)}, expected "receiver"`);
        if (ready.port !== receiverPort) problems.push(`receiver bound port ${JSON.stringify(ready.port)}, expected ${receiverPort}`);
        if (ready.subscription_id !== subscriptionId) {
          problems.push(`receiver ready line has subscription_id ${JSON.stringify(ready.subscription_id)}, expected ${JSON.stringify(subscriptionId)}`);
        }
        // The route question is answered from the receiver's own registry, not
        // from the flag the driver passed: a pending secret must route nothing.
        const expectKnown = attemptCfg.pending_secret !== true;
        if (ready.subscription_known !== expectKnown) {
          const why = expectKnown ? 'the subscription is registered and routed at startup' : 'a pending secret routes nothing until the challenge';
          problems.push(`receiver ready line reports subscription_known=${JSON.stringify(ready.subscription_known)}, expected ${JSON.stringify(expectKnown)} (${why})`);
        }
        if (problems.length > 0) return report(problems);
        break;
      }
      if (receiverWanted && receiverChild === null) {
        return report([`${label}: ${receiverStartError ?? 'the receiver printed no ready line'}`]);
      }

      const senderCfg = D.resolvePlaceholders(sc.sender, vars);
      const receiverCfg = D.resolvePlaceholders(sc.receiver, vars);
      expected = D.resolvePlaceholders(sc.expected, vars);
      const messages = Array.isArray(senderCfg.messages) && senderCfg.messages.length > 0 ? senderCfg.messages : ['event'];
      const effectiveSubscriptionId = typeof senderCfg.subscription_id === 'string' && senderCfg.subscription_id !== ''
        ? senderCfg.subscription_id
        : subscriptionId;

      // The card names the keys the receiver may accept; the driver verifies
      // with the same public keys, so an unknown fixture name is fatal here.
      const cardNames = Array.isArray(receiverCfg.card) ? receiverCfg.card : [];
      const ctx = {
        scenario: id,
        url,
        subscriptionId,
        effectiveSubscriptionId,
        messages,
        secret: D.secretBytes(),
        cardKeys: cardNames.map((name) => {
          const entry = fixtures.keysByName[name];
          if (entry === undefined) S.fail(`scenario ${id} names unknown fixture key '${name}' in receiver.card`);
          return D.publicKeyFromB64u(entry.public_key);
        }),
      };

      // The shadow listener is the peer a rebinding dialer would reach: it
      // answers on the loopback alias at the receiver's port, so it starts once
      // the receiver holds that port on 127.0.0.1 and before the sender dials.
      if (sc.shadow === true) {
        if (receiverPort === null) return report([`scenario ${id} asks for the shadow listener without a receiver`]);
        try {
          shadow = await S.startShadowListener(receiverPort);
        } catch (e) {
          return report([`cannot start the shadow listener: ${e.message}`]);
        }
      }

      const senderArgs = [
        '--scenario', id,
        '--url', url,
        '--aud', D.AUD,
        '--clock-file', senderClockPath,
        '--secret-seed', D.SECRET_SEED,
        '--messages', messages.join(','),
        '--subscription-id', effectiveSubscriptionId,
        '--resolver-file', resolverPath,
        '--allowed-range', '127.0.0.0/8',
        '--tls-ca', tls.caPem,
        '--tls-ca-der', tls.caDer,
      ];
      if (senderCfg.allowlist === true) senderArgs.push('--allowlist', url);
      if (typeof senderCfg.signing_key === 'string') senderArgs.push('--signing-seed-hex', seedOf('signing_key', senderCfg.signing_key));
      if (typeof senderCfg.jack_key === 'string') senderArgs.push('--jack-seed-hex', seedOf('jack_key', senderCfg.jack_key));
      if (typeof senderCfg.rebind_address === 'string') senderArgs.push('--rebind-address', senderCfg.rebind_address);
      if (bodyPath !== null) senderArgs.push('--body-file', bodyPath);

      senderChild = S.makeChild(senderTarget.cmd, [...senderTarget.args, ...senderArgs], { SSL_CERT_FILE: tls.caPem });
      allChildren.add(senderChild);
      processesSpawned++;

      let exitCode;
      try {
        exitCode = await S.waitClose(senderChild, 30000, `${label} webhook_sender`);
      } catch (e) {
        return report([`sender did not finish: ${e.message}`]);
      }
      if (exitCode !== 0) {
        return report([`sender exited ${exitCode}, expected 0; sender stderr tail:\n${senderChild._stderrTail().slice(-1000)}`]);
      }

      // Teardown before judging: a receiver that is still running may not have
      // flushed its last delivery line yet.
      if (relay !== null) {
        try { await relay.close(); } catch { /* best effort */ }
        // `close` waits for an in-flight replay, so the records are complete here.
        relayRecords = relay.observations();
        relay = null;
      }
      if (shadow !== null) {
        // Every connection the alias accepted is evidence: a policy refusal
        // must not have dialled anything.
        shadowConnections = shadow.connections();
        try { await shadow.close(); } catch { /* best effort */ }
        shadow = null;
      }
      if (receiverChild !== null) await S.stopChild(receiverChild);

      // The driver rebuilds every view from the executables' own lines; their
      // verdicts are never trusted.
      const reasons = [];
      const split = splitSenderLines(parseLines(senderChild._stdoutText(), 'sender', reasons));
      reasons.push(...split.reasons);
      const deliveryLines = [];
      if (receiverWanted && receiverChild !== null) {
        const receiverLines = parseLines(receiverChild._stdoutText(), 'receiver', reasons);
        // Line 0 is the ready object the driver already checked.
        if (receiverLines.length === 0 || receiverLines[0].ready !== true) reasons.push('the receiver printed no ready line');
        for (const line of receiverLines.slice(1)) {
          if (line.event !== 'delivery') {
            reasons.push(`the receiver printed an unexpected line: ${truncateJson(line)}`);
            continue;
          }
          if (line.seq !== deliveryLines.length) {
            reasons.push(`delivery line carries seq ${JSON.stringify(line.seq)}, expected ${deliveryLines.length}`);
          }
          deliveryLines.push(line);
        }
      }

      const attempts = buildRelayAttemptViews(relayRecords, ctx);
      const deliveries = buildDeliveryViews(deliveryLines, ctx);
      const evaluation = evaluateScenario({
        expected,
        ctx,
        ready: split.ready,
        result: split.result,
        attempts,
        deliveries,
        shadowConnections,
        crossCheck: sc.cross_check !== false,
      });
      return report([...reasons, ...evaluation.reasons], evaluation.actual);
    } finally {
      // Idempotent teardown: stopChild returns immediately for a child that
      // already exited, and a closed relay or shadow listener is not reopened.
      if (relay !== null) {
        try { await relay.close(); } catch { /* best effort */ }
        relay = null;
      }
      if (shadow !== null) {
        try { await shadow.close(); } catch { /* best effort */ }
        shadow = null;
      }
      if (receiverChild !== null) {
        await S.stopChild(receiverChild);
        allChildren.delete(receiverChild);
      }
      if (senderChild !== null) allChildren.delete(senderChild);
    }
  }
}
