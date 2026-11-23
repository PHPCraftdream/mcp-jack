// Webhook (delivery profile) interop matrix entry point. One cell of the matrix
// is a (sender language, receiver language) pair; every selected scenario of
// interop/webhook-scenarios.json runs a dedicated webhook_receiver, through the
// tamper relay where the scenario asks for one, against one webhook_sender, and
// the driver verifies the outcome itself with the pinned fixture material.
// Node >= 20, node: builtins only.
//
// node interop/webhook.mjs [--targets <file>] [--senders <l,l,...>] [--receivers <l,l,...>]
//                          [--scenario <id>[,<id>...]] [--list] [--self-test]
import { join } from 'node:path';
import * as S from './webhook/support.mjs';
import { loadScenarios, runMatrix } from './webhook/matrix.mjs';

// The default targets file sits between the repository root and the support
// modules, and every child is spawned with REPO_ROOT as its cwd.
const REPO_ROOT = S.REPO_ROOT;
const USAGE = `usage: node interop/webhook.mjs [--targets <file>] [--senders <l,l,...>] [--receivers <l,l,...>] [--scenario <id>[,<id>...]] [--list] [--self-test]`;

function parseArgs(argv) {
  const out = {
    targets: join(REPO_ROOT, 'interop', 'targets.json'),
    senders: null,
    receivers: null,
    scenario: null,
    list: false,
    selfTest: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    switch (flag) {
      case '--targets': out.targets = argv[++i]; break;
      case '--senders': out.senders = argv[++i]; break;
      case '--receivers': out.receivers = argv[++i]; break;
      case '--scenario': {
        // Repeatable and comma-separated, collected in the order given.
        const ids = String(argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        out.scenario = [...(out.scenario ?? []), ...ids];
        break;
      }
      case '--list': out.list = true; break;
      case '--self-test': out.selfTest = true; break;
      default: S.fail(`unknown flag: ${flag}\n${USAGE}`);
    }
  }
  return out;
}

// Every selected language must provide both webhook roles as non-empty argv
// arrays; the same check the rotation harness runs for its own roles.
function validateTargets(targets, langs) {
  for (const lang of langs) {
    const entry = targets[lang];
    for (const role of ['webhook_sender', 'webhook_receiver']) {
      if (!entry || !Array.isArray(entry[role]) || entry[role].length === 0) {
        S.fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
      }
    }
  }
}

// One cell is `pass`, `pass+<n>skip` when a declared SDK gap excluded `n`
// scenarios, or `fail:<n>` for the scenarios that did not pass.
function cellLabel(cell) {
  const failed = cell.total - cell.passed;
  if (failed > 0) return `fail:${failed}`;
  return cell.skipped > 0 ? `pass+${cell.skipped}skip` : 'pass';
}

function printMatrix(matrixCells, senderLangs, receiverLangs) {
  const head = 'sender \\ receiver'.padEnd(20) + receiverLangs.map((receiver) => receiver.padEnd(14)).join('');
  process.stdout.write(head + '\n');
  for (const sender of senderLangs) {
    const row = sender.padEnd(20) + receiverLangs.map((receiver) => {
      const cell = matrixCells[sender]?.[receiver];
      return (cell === undefined ? '-' : cellLabel(cell)).padEnd(14);
    }).join('');
    process.stdout.write(row + '\n');
  }
}

// ---- main -------------------------------------------------------------------

const cli = parseArgs(process.argv.slice(2));
const targets = S.readJson(cli.targets, 'targets file');
if (!targets || typeof targets !== 'object' || Array.isArray(targets) || Object.keys(targets).length === 0) {
  S.fail(`invalid targets file: ${cli.targets}`);
}

const scenarios = loadScenarios();

if (cli.list) {
  for (const id of scenarios.order) process.stdout.write(id + '\n');
  process.exit(0);
}

if (cli.selfTest) {
  // The self-test module owns its own exit code; it drives this matrix against
  // the independent fakes in interop/tools/fakes/webhook/.
  const { selfTest } = await import('./webhook/selftest.mjs');
  await selfTest();
}

const targetKeys = Object.keys(targets);
const senderLangs = S.splitLangs(cli.senders, targetKeys, '--senders');
const receiverLangs = S.splitLangs(cli.receivers, targetKeys, '--receivers');
if (senderLangs.length === 0) S.fail('no sender languages selected');
if (receiverLangs.length === 0) S.fail('no receiver languages selected');
validateTargets(targets, [...new Set([...senderLangs, ...receiverLangs])]);

let scenarioFilter = null;
if (cli.scenario !== null) {
  for (const id of cli.scenario) {
    if (!scenarios.order.includes(id)) S.fail(`unknown scenario '${id}' (known: ${scenarios.order.join(', ')})`);
  }
  scenarioFilter = cli.scenario;
}

const res = await runMatrix({
  senders: senderLangs,
  receivers: receiverLangs,
  targets,
  fixtures: S.loadFixtures(),
  scenarios,
  scenarioFilter,
});

printMatrix(res.matrixCells, senderLangs, receiverLangs);
// `pairs` counts matrix cells, `checks` the selected scenarios per pair, and
// `passed` every scenario pass across all cells.
const pairs = senderLangs.length * receiverLangs.length;
const checks = (scenarioFilter ?? scenarios.order).length;
const passed = res.pairSummaries.reduce((sum, summary) => sum + summary.passed, 0);
const failedPairs = new Set(res.failures.map((failure) => failure.pair)).size;
if (res.failures.length === 0) {
  process.stdout.write('webhook matrix: all pairs pass\n');
  // A skip is a declared SDK gap, never a pass, so it is reported explicitly.
  const skippedCells = res.pairSummaries.filter((summary) => summary.skipped > 0).length;
  if (skippedCells > 0) {
    process.stdout.write(`webhook matrix: ${skippedCells} cell(s) skipped for a declared SDK gap\n`);
  }
  process.stdout.write(`INTEROP-SUMMARY matrix=webhook pairs=${pairs} checks=${checks} passed=${passed} failed=0 result=pass\n`);
  process.exit(0);
} else {
  process.stdout.write(`${res.failures.length} failure(s) across ${failedPairs} pair(s)\n`);
  process.stdout.write(`INTEROP-SUMMARY matrix=webhook pairs=${pairs} checks=${checks} passed=${passed} failed=${res.failures.length} result=fail\n`);
  process.exit(1);
}
