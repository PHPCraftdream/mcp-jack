// Summarizes a `go test -coverprofile` file (go tool cover format) into
// machine-readable JSON and a human-readable TXT, partitioned into
// product / helper / interop groups. No thresholds, no invented metrics.
// Usage: node tools/coverage/go-summary.mjs <coverprofile> <out.json> <out.txt>
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const GENERATED_BY = "tools/coverage/go-summary.mjs";
const MAX_UNCOVERED = 200;
const GROUPS = ["product", "helper", "interop"];

// Group rules on the import-qualified path string: the root-module interop Go
// packages live under interop/go/, spec/ holds shared fixture/spec helper code,
// and everything else (including root-package files) is product.
export function groupFor(filePath) {
  if (filePath.startsWith("interop/go/") || filePath.includes("/interop/go/")) return "interop";
  if (filePath.includes("/spec/")) return "helper";
  return "product";
}

function roundPct(covered, total) {
  if (total === 0) return null;
  return Math.round((100 * covered) / total * 100) / 100;
}

// Block lines look like: <import>/<file>:<sl>.<sc>,<el>.<ec> <numStmt> <count>
const blockRe = /^(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$/;

export function parseProfile(text) {
  const lines = text.split(/\r?\n/);
  if (!lines[0] || !lines[0].startsWith("mode: ")) throw new Error("missing `mode:` header — not a go cover profile");
  const mode = lines[0].slice("mode: ".length);
  // Go's writer only ever emits set/count/atomic; anything else means the
  // input is not a healthy cover profile, so fail closed.
  const allowedModes = new Set(["set", "count", "atomic"]);
  if (!allowedModes.has(mode)) throw new Error(`unsupported cover profile mode: ${mode}`);
  // With -coverpkg=./... the same file is instrumented by several test
  // binaries, so identical blocks repeat. Dedupe on the exact block position
  // key; a block is covered when ANY observed count is nonzero.
  const blocks = new Map();
  for (const line of lines.slice(1)) {
    if (line === "") continue;
    const m = blockRe.exec(line);
    // Go's writer never emits a nonempty non-block line in a healthy profile;
    // skipping silently would corrupt the summary, so fail closed.
    if (!m) throw new Error(`malformed cover profile line: ${line}`);
    const [, file, sl, sc, el, ec, numStmt, count] = m;
    const key = `${file}:${sl}.${sc},${el}.${ec}`;
    const countNum = Number(count);
    const numStmtNum = Number(numStmt);
    // All numeric fields are written as decimal integers by Go's writer;
    // anything beyond safe-integer precision is corruption, not a big number.
    if (![sl, sc, el, ec].every((v) => Number.isSafeInteger(Number(v)))) {
      throw new Error(`malformed cover profile line (non-safe-integer field): ${line}`);
    }
    if (!Number.isSafeInteger(numStmtNum) || !Number.isSafeInteger(countNum)) {
      throw new Error(`malformed cover profile line (non-safe-integer field): ${line}`);
    }
    // Reversed coordinates — including columns within a single line — are
    // impossible from go tool cover and would silently distort line-span
    // accounting, so fail closed.
    if (Number(sl) < 1 || Number(sl) > Number(el) ||
        (Number(sl) === Number(el) && Number(sc) > Number(ec))) {
      throw new Error(`malformed cover profile line (reversed coordinates): ${line}`);
    }
    const existing = blocks.get(key);
    if (existing === undefined) {
      blocks.set(key, { file, startLine: Number(sl), endLine: Number(el), numStmt: numStmtNum, covered: countNum > 0 });
    } else {
      // Identical blocks from different -coverpkg test binaries must agree on
      // numStmt; disagreement means the profile mixes incompatible builds.
      if (existing.numStmt !== numStmtNum) throw new Error(`inconsistent numStmt for block: ${key}`);
      if (countNum > 0) {
        existing.covered = true;
      }
    }
  }
  return { mode, blocks: [...blocks.values()] };
}

function fileStats(blockList) {
  const filePath = blockList[0].file;
  const coveredLines = new Set();
  const spannedLines = new Set();
  for (const block of blockList) {
    for (let line = block.startLine; line <= block.endLine; line += 1) {
      spannedLines.add(line);
      if (block.covered) coveredLines.add(line);
    }
  }
  const linesTotal = spannedLines.size;
  const linesCovered = coveredLines.size;
  const statementsTotal = blockList.reduce((sum, block) => sum + block.numStmt, 0);
  const statementsCovered = blockList.reduce((sum, block) => sum + (block.covered ? block.numStmt : 0), 0);
  const allUncovered = [...spannedLines].filter((line) => !coveredLines.has(line)).sort((a, b) => a - b);
  return {
    path: filePath,
    group: groupFor(filePath),
    statementsTotal,
    statementsCovered,
    statementPct: roundPct(statementsCovered, statementsTotal),
    linesTotal,
    linesCovered,
    lineSpanPct: roundPct(linesCovered, linesTotal),
    uncoveredLines: allUncovered.slice(0, MAX_UNCOVERED),
    uncoveredLinesTruncated: allUncovered.length > MAX_UNCOVERED,
  };
}

function groupSummary(files) {
  const out = {};
  for (const group of GROUPS) {
    const members = files.filter((f) => f.group === group);
    const statementsTotal = members.reduce((sum, f) => sum + f.statementsTotal, 0);
    const statementsCovered = members.reduce((sum, f) => sum + f.statementsCovered, 0);
    const linesTotal = members.reduce((sum, f) => sum + f.linesTotal, 0);
    const linesCovered = members.reduce((sum, f) => sum + f.linesCovered, 0);
    out[group] = {
      files: members.length,
      statementsTotal,
      statementsCovered,
      statementPct: roundPct(statementsCovered, statementsTotal),
      linesTotal,
      linesCovered,
      lineSpanPct: roundPct(linesCovered, linesTotal),
    };
  }
  return out;
}

function renderTxt(json) {
  const lines = [
    "Statement percentages follow go tool cover semantics: covered statements / total statements from the block data.",
    "Line percentages are a custom line-span approximation (NOT the tool's statement metric); they drive the uncovered-line lists.",
    "Scope: only files in the supplied profile are measured; root-module interop Go packages under interop/go/ are included when present in the root ./... profile.",
  ];
  for (const group of GROUPS) {
    const g = json.groups[group];
    lines.push(`# group: ${group}`);
    for (const f of json.files.filter((f) => f.group === group)) {
      const stmtPct = f.statementPct === null ? "n/a" : `${f.statementPct}`;
      const spanPct = f.lineSpanPct === null ? "n/a" : `${f.lineSpanPct}`;
      lines.push(`stmt ${stmtPct}% | lines ${spanPct}% | ${f.statementsCovered}/${f.statementsTotal} stmts | ${f.path}`);
    }
    const stmtPct = g.statementPct === null ? "n/a" : `${g.statementPct}`;
    const spanPct = g.lineSpanPct === null ? "n/a" : `${g.lineSpanPct}`;
    lines.push(`TOTAL stmt ${stmtPct}% | lines ${spanPct}% | ${g.statementsCovered}/${g.statementsTotal} stmts`);
  }
  return `${lines.join("\n")}\n`;
}

// Run the main IO path only when this module is the entry point, so the
// regression tests can import the exported parser without triggering the CLI path.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [coverprofilePath, outJsonPath, outTxtPath] = process.argv.slice(2);
  if (!coverprofilePath || !outJsonPath || !outTxtPath) {
    console.error("usage: node tools/coverage/go-summary.mjs <coverprofile> <out.json> <out.txt>");
    process.exit(2);
  }
  const { mode, blocks } = parseProfile(readFileSync(coverprofilePath, "utf8"));
  if (blocks.length === 0) throw new Error("cover profile contains no coverage blocks");
  const byFile = new Map();
  for (const block of blocks) {
    const list = byFile.get(block.file) ?? [];
    list.push(block);
    byFile.set(block.file, list);
  }
  const files = [...byFile.values()].map(fileStats).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const allTotal = {
    files: files.length,
    statementsTotal: files.reduce((sum, f) => sum + f.statementsTotal, 0),
    statementsCovered: files.reduce((sum, f) => sum + f.statementsCovered, 0),
    linesTotal: files.reduce((sum, f) => sum + f.linesTotal, 0),
    linesCovered: files.reduce((sum, f) => sum + f.linesCovered, 0),
  };
  const json = {
    tool: "go tool cover (statement and line-span aggregation)",
    mode,
    generatedBy: GENERATED_BY,
    metricNote:
      "Statements follow go tool cover semantics (numStmt-weighted); line percentages are a custom line-span approximation used to list uncovered lines.",
    coverageScope:
      "Only Go blocks present in the supplied profile are measured. The root-module workflow runs go test ./... and includes the interop Go packages under interop/go/; no separate nested Go module is claimed.",
    groups: groupSummary(files),
    total: {
      ...allTotal,
      statementPct: roundPct(allTotal.statementsCovered, allTotal.statementsTotal),
      lineSpanPct: roundPct(allTotal.linesCovered, allTotal.linesTotal),
    },
    files,
  };

  writeFileSync(outJsonPath, `${JSON.stringify(json, null, 2)}\n`, "utf8");
  writeFileSync(outTxtPath, renderTxt(json), "utf8");
  console.log(`go statement coverage summary: ${files.length} files -> ${path.basename(outJsonPath)}, ${path.basename(outTxtPath)}`);
}
