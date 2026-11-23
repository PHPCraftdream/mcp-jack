// Modern (MCP 2026-07-28) interop matrix entry point. One cell of the matrix
// is a (client language, server language) pair; every selected scenario of
// interop/modern-scenarios.json runs against a dedicated modern_server, through
// the tamper proxy where the scenario asks for it, and the driver verifies each
// response itself with the pinned fixture key. Node >= 20, node: builtins only.
//
// node interop/modern.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>]
//                      [--scenario <id>[,<id>...]] [--list] [--self-test]
import { join } from 'node:path';
import * as S from './modern/support.mjs';
import { loadScenarios, runMatrix } from './modern/matrix.mjs';

// Directory of the support modules (interop/modern) and the repository root.
// The default targets file sits between them, and every child is spawned with
// REPO_ROOT as its cwd by support.makeChild.
const SCRIPT_DIR = S.SCRIPT_DIR;
const REPO_ROOT = S.REPO_ROOT;
const USAGE = `usage: node interop/modern.mjs [--targets <file>] [--servers <l,l,...>] [--clients <l,l,...>] [--scenario <id>[,<id>...]] [--list] [--self-test]`;

function parseArgs(argv) {
  const out = {
    targets: join(SCRIPT_DIR, '..', 'targets.json'),
    servers: null,
    clients: null,
    scenario: null,
    list: false,
    selfTest: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    switch (flag) {
      case '--targets': out.targets = argv[++i]; break;
      case '--servers': out.servers = argv[++i]; break;
      case '--clients': out.clients = argv[++i]; break;
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

// Every selected language must provide both modern roles as non-empty argv
// arrays; the same check the rotation harness runs for its own roles.
function validateTargets(targets, langs) {
  for (const lang of langs) {
    const entry = targets[lang];
    for (const role of ['modern_server', 'modern_client']) {
      if (!entry || !Array.isArray(entry[role]) || entry[role].length === 0) {
        S.fail(`invalid targets entry for '${lang}': missing or empty '${role}'`);
      }
    }
  }
}

function printMatrix(matrixCells, serverLangs, clientLangs) {
  const head = 'client \\ server'.padEnd(18) + serverLangs.map((s) => s.padEnd(14)).join('');
  process.stdout.write(head + '\n');
  for (const client of clientLangs) {
    const row = client.padEnd(18) + serverLangs.map((server) => {
      const cell = matrixCells[client]?.[server];
      return (cell ? (cell.total > 0 && cell.passed === cell.total ? 'pass' : `fail:${cell.total - cell.passed}`) : '-').padEnd(14);
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
  // the independent fakes in interop/tools/fakes/modern/.
  const { selfTest } = await import('./modern/selftest.mjs');
  await selfTest();
}

const targetKeys = Object.keys(targets);
const clientLangs = S.splitLangs(cli.clients, targetKeys, '--clients');
const serverLangs = S.splitLangs(cli.servers, targetKeys, '--servers');
if (clientLangs.length === 0) S.fail('no client languages selected');
if (serverLangs.length === 0) S.fail('no server languages selected');
validateTargets(targets, [...new Set([...clientLangs, ...serverLangs])]);

let scenarioFilter = null;
if (cli.scenario !== null) {
  for (const id of cli.scenario) {
    if (!scenarios.order.includes(id)) S.fail(`unknown scenario '${id}' (known: ${scenarios.order.join(', ')})`);
  }
  scenarioFilter = cli.scenario;
}

const res = await runMatrix({
  clientLangs,
  serverLangs,
  targets,
  fixtures: S.loadFixtures(),
  scenarios,
  scenarioFilter,
});

printMatrix(res.matrixCells, serverLangs, clientLangs);
// `pairs` counts matrix cells, `checks` the selected scenarios per pair, and
// `passed` every scenario pass across all cells.
const pairs = clientLangs.length * serverLangs.length;
const checks = (scenarioFilter ?? scenarios.order).length;
const passed = res.pairSummaries.reduce((sum, summary) => sum + summary.passed, 0);
const failedPairs = new Set(res.failures.map((failure) => failure.pair)).size;
if (res.failures.length === 0) {
  process.stdout.write('modern matrix: all pairs pass\n');
  process.stdout.write(`INTEROP-SUMMARY matrix=modern pairs=${pairs} checks=${checks} passed=${passed} failed=0 result=pass\n`);
  process.exit(0);
} else {
  process.stdout.write(`${res.failures.length} failure(s) across ${failedPairs} pair(s)\n`);
  process.stdout.write(`INTEROP-SUMMARY matrix=modern pairs=${pairs} checks=${checks} passed=${passed} failed=${res.failures.length} result=fail\n`);
  process.exit(1);
}
