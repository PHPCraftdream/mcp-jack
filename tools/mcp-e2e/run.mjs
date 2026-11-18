// Dependency-free Node driver for the official MCP SDK end-to-end
// compatibility matrix (tools/mcp-e2e). Full chain per cell:
//
//   OFFICIAL stdio MCP client fixture -> `jack bridge` -> signed `jack gateway`
//   -> OFFICIAL Streamable HTTP MCP server fixture (unix socket)
//
// run as a 3x3 matrix (clients go/ts/rust x servers go/ts/rust) plus one tamper
// cell per client x server pair, and driver-side GET probes recording the
// design-doc "G4" GET behaviour.
//
// Node >= 22, node: builtins only. Exit codes: 2 usage / artifact-resolution
// failure; 1 if any cell FAILED; 0 only when every required cell ran — a
// TS-server cell that cannot run (known initialize->SSE->gateway 501 limit)
// FAILS by default and may be skipped only with --allow-skip-ts-server.
//
//   node tools/mcp-e2e/run.mjs [--clients go,ts,rust] [--servers go,ts,rust] [--list] [--keep]
//       [--allow-skip-ts-server]
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LANGS, PINS, TOLERANCES, USAGE, tracked, fail } from './lib/config.mjs';
import { parseArgs, splitLangs } from './lib/args.mjs';
import { resolveArtifacts } from './lib/artifacts.mjs';
import { cellName, runCell } from './lib/cell.mjs';

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

function printSummary(records, allowSkipTsServer) {
  const passed = records.filter((r) => r.result === 'PASS').length;
  const skipped = records.filter((r) => r.result === 'SKIP').length;
  const failed = records.filter((r) => r.result === 'FAIL').length;
  process.stdout.write(`SUMMARY cells=${records.length} passed=${passed} skipped=${skipped} failed=${failed}\n`);
  if (skipped > 0) {
    process.stdout.write(`SKIPPED cells (${allowSkipTsServer ? 'named skip via --allow-skip-ts-server' : 'unexpected'}):\n`);
    for (const r of records) {
      if (r.result === 'SKIP') process.stdout.write(`  SKIP ${r.name}\n`);
    }
  }
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
  // One tamper cell per selected client x server pair: tamper is asserted for
  // every server language, not only go.
  for (const c of clients) {
    for (const s of servers) cells.push({ client: c, server: s, tamper: true });
  }

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
  const artifacts = resolveArtifacts(workDir, needed);

  printHeader(artifacts);
  const matrixCount = cells.filter((c) => !c.tamper).length;
  process.stdout.write(`cells: ${cells.length} (${matrixCount} matrix + ${cells.length - matrixCount} tamper)\n`);

  const records = [];
  let index = 0;
  for (const cell of cells) {
    index += 1;
    const record = await runCell({ workDir, index, ...cell, artifacts, keep: cli.keep, allowSkipTsServer: cli.allowSkipTsServer });
    printCell(record);
    records.push(record);
  }

  printSummary(records, cli.allowSkipTsServer);
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
