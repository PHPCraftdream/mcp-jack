// Summarizes a cargo-llvm-cov lcov tracefile into machine-readable JSON and a
// human-readable TXT, partitioned into product / helper / interop groups.
// No thresholds, no invented metrics.
// Usage: node tools/coverage/lcov-summary.mjs <lcov.info> <out.json> <out.txt>
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const GENERATED_BY = "tools/coverage/lcov-summary.mjs";
const MAX_UNCOVERED = 200;
const GROUPS = ["product", "helper", "interop"];

// Group rules: src/bin/* are the interop executables (helper code, not
// published API); tests/ is test support (cargo-llvm-cov excludes tests/ by
// default anyway — classify defensively, never invent); everything under
// src/ is product.
function groupFor(filePath) {
  if (filePath.startsWith("src/bin/")) return "interop";
  if (filePath.startsWith("tests/")) return "helper";
  if (filePath.startsWith("src/")) return "product";
  return null;
}

function roundPct(covered, total) {
  if (total === 0) return null;
  return Math.round((100 * covered) / total * 100) / 100;
}

// cargo-llvm-cov usually writes workspace-relative SF paths
// (src/client/auth.rs) but absolute paths appear on some setups; normalize by
// keeping everything after the last `rust/` segment, then classify on
// forward slashes.
function normalizeSf(sfPath) {
  const marker = "rust/";
  const index = sfPath.lastIndexOf(marker);
  return index === -1 ? sfPath.replaceAll("\\", "/") : sfPath.slice(index + marker.length);
}

export function parseLcov(text) {
  const files = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("SF:")) {
      // A record still open when a new SF: arrives means the previous record
      // was truncated; merging or overwriting it would silently drop data.
      if (current !== null) throw new Error(`unterminated lcov record before: ${line}`);
      current = { sf: line.slice(3), da: [], seen: new Set() };
    } else if (line.startsWith("DA:")) {
      // A DA record outside any SF record means the tracefile is malformed;
      // silently dropping it would corrupt the totals, so fail closed.
      if (current === null) throw new Error(`lcov DA record outside any SF record: ${line}`);
      // lcov line numbers are 1-based and counts are non-negative integers;
      // the tightened regex rejects malformed and negative records alike.
      const m = /^DA:([1-9][0-9]*),(\d+)$/.exec(line);
      // A malformed DA record would silently drop line data and corrupt the
      // summary, so fail closed instead of skipping.
      if (!m) throw new Error(`malformed lcov DA record: ${line}`);
      const lineNo = Number(m[1]);
      const count = Number(m[2]);
      // lcov numbers are exact integers; anything beyond safe-integer
      // precision is corruption, not a big number.
      if (!Number.isSafeInteger(lineNo) || !Number.isSafeInteger(count)) {
        throw new Error(`lcov DA record out of safe-integer range: ${line}`);
      }
      if (current.seen.has(lineNo)) throw new Error(`duplicate lcov DA line: ${lineNo}`);
      current.seen.add(lineNo);
      current.da.push({ line: lineNo, count });
    } else if (line === "end_of_record" && current) {
      // A record with no DA lines carries no classifiable line data; accept it
      // and it silently disappears from the totals.
      if (current.da.length === 0) throw new Error(`lcov record without DA lines: ${current.sf}`);
      files.push(current);
      current = null;
    }
    // LF:/LH:/BRDA:/BRF:/BRH: and other lines are ignored: no branch metrics
    // are invented from BRDA records.
  }
  // A record still open at EOF means the tracefile was truncated.
  if (current !== null) throw new Error(`unterminated lcov record: ${current.sf}`);
  return files;
}

function fileStats(record) {
  const filePath = normalizeSf(record.sf);
  const group = groupFor(filePath);
  if (group === null) return null;
  const linesTotal = record.da.length;
  const linesCovered = record.da.filter((d) => d.count > 0).length;
  const allUncovered = record.da.filter((d) => d.count === 0).map((d) => d.line).sort((a, b) => a - b);
  return {
    path: filePath,
    group,
    linesTotal,
    linesCovered,
    pct: roundPct(linesCovered, linesTotal),
    uncoveredLines: allUncovered.slice(0, MAX_UNCOVERED),
    uncoveredLinesTruncated: allUncovered.length > MAX_UNCOVERED,
  };
}

function groupSummary(files) {
  const out = {};
  for (const group of GROUPS) {
    const members = files.filter((f) => f.group === group);
    const linesTotal = members.reduce((sum, f) => sum + f.linesTotal, 0);
    const linesCovered = members.reduce((sum, f) => sum + f.linesCovered, 0);
    out[group] = { files: members.length, linesTotal, linesCovered, pct: roundPct(linesCovered, linesTotal) };
  }
  return out;
}

function renderTxt(json) {
  const lines = [
    "Rust line/region coverage via cargo-llvm-cov (LLVM source-based coverage); branch coverage requires an unstable nightly flag and is not reported.",
    "cargo-llvm-cov excludes vendored sources and tests/ by default; src/bin/* are interop helper executables.",
  ];
  for (const group of GROUPS) {
    const g = json.groups[group];
    lines.push(`# group: ${group}`);
    for (const f of json.files.filter((f) => f.group === group)) {
      const pct = f.pct === null ? "n/a" : `${f.pct}`;
      lines.push(`${pct}%  ${f.linesCovered}/${f.linesTotal}  ${f.path}`);
    }
    const pct = g.pct === null ? "n/a" : `${g.pct}`;
    lines.push(`TOTAL ${pct}%  ${g.linesCovered}/${g.linesTotal}`);
  }
  return `${lines.join("\n")}\n`;
}

// Run the main IO path only when this module is the entry point, so the
// regression tests can import the exported parser without triggering the CLI path.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [lcovPath, outJsonPath, outTxtPath] = process.argv.slice(2);
  if (!lcovPath || !outJsonPath || !outTxtPath) {
    console.error("usage: node tools/coverage/lcov-summary.mjs <lcov.info> <out.json> <out.txt>");
    process.exit(2);
  }
  const records = parseLcov(readFileSync(lcovPath, "utf8"));
  const files = records
    .map(fileStats)
    .filter((f) => f !== null)
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (files.length === 0) throw new Error("lcov tracefile contains no classifiable SF records");
  const allTotal = {
    files: files.length,
    linesTotal: files.reduce((sum, f) => sum + f.linesTotal, 0),
    linesCovered: files.reduce((sum, f) => sum + f.linesCovered, 0),
  };
  const json = {
    tool: "cargo-llvm-cov (LLVM source-based coverage)",
    mode: null,
    generatedBy: GENERATED_BY,
    groups: groupSummary(files),
    total: { ...allTotal, pct: roundPct(allTotal.linesCovered, allTotal.linesTotal) },
    files,
  };

  writeFileSync(outJsonPath, `${JSON.stringify(json, null, 2)}\n`, "utf8");
  writeFileSync(outTxtPath, renderTxt(json), "utf8");
  console.log(`rust coverage summary: ${files.length} files -> ${path.basename(outJsonPath)}, ${path.basename(outTxtPath)}`);
}
