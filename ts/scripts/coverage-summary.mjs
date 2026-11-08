// Summarizes Node V8 raw coverage (NODE_V8_COVERAGE) of the tsc-emitted
// JavaScript under dist-test into machine-readable JSON and a human-readable
// TXT, partitioned into product / interop helper / tests groups.
// No thresholds, no invented metrics.
// Usage: node scripts/coverage-summary.mjs <raw-coverage-dir> <out-dir>
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const GENERATED_BY = "ts/scripts/coverage-summary.mjs";
export const MAX_UNCOVERED = 200;
const GROUPS = ["product", "helper", "interop"];
const GROUP_LABELS = { product: "product", helper: "tests", interop: "interop" };
const distTest = path.resolve(process.cwd(), "dist-test");

// ---------------------------------------------------------------------------
// Exported pure core (regression-test surface). No IO, no process state.
// ---------------------------------------------------------------------------

// Fail-closed parse of one raw V8 coverage payload file. Any shape violation
// throws; callers must not swallow these errors. Node never legitimately
// emits empty functions/ranges arrays in per-process raw files, so empty
// arrays and non-integer/negative/reversed offsets are malformed here.
export function parseRawPayload(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`malformed raw V8 coverage payload: JSON parse failed (${err.message})`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("malformed raw V8 coverage payload: payload is not an object");
  }
  if (!Array.isArray(parsed.result)) {
    throw new Error("malformed raw V8 coverage payload: result is not an array");
  }
  for (const entry of parsed.result) {
    if (entry === null || typeof entry !== "object") {
      throw new Error("malformed raw V8 coverage payload: result entry is not an object");
    }
    if (typeof entry.url !== "string") {
      throw new Error("malformed raw V8 coverage payload: result entry url is not a string");
    }
    if (!Array.isArray(entry.functions)) {
      throw new Error("malformed raw V8 coverage payload: functions is not an array");
    }
    if (entry.functions.length === 0) {
      throw new Error("malformed raw V8 coverage payload: functions is empty");
    }
    for (const fn of entry.functions) {
      if (fn === null || typeof fn !== "object") {
        throw new Error("malformed raw V8 coverage payload: function is not an object");
      }
      if (!Array.isArray(fn.ranges)) {
        throw new Error("malformed raw V8 coverage payload: ranges is not an array");
      }
      if (fn.ranges.length === 0) {
        throw new Error("malformed raw V8 coverage payload: function ranges is empty");
      }
      for (const range of fn.ranges) {
        if (range === null || typeof range !== "object") {
          throw new Error("malformed raw V8 coverage payload: range is not an object");
        }
        if (!Number.isSafeInteger(range.startOffset)) {
          throw new Error("malformed raw V8 coverage payload: range startOffset is not a safe integer");
        }
        if (!Number.isSafeInteger(range.endOffset)) {
          throw new Error("malformed raw V8 coverage payload: range endOffset is not a safe integer");
        }
        if (!Number.isSafeInteger(range.count)) {
          throw new Error("malformed raw V8 coverage payload: range count is not a safe integer");
        }
        if (range.startOffset < 0) {
          throw new Error("malformed raw V8 coverage payload: range startOffset is negative");
        }
        if (range.endOffset < range.startOffset) {
          throw new Error("malformed raw V8 coverage payload: range endOffset is before startOffset");
        }
        if (range.count < 0) {
          throw new Error("malformed raw V8 coverage payload: range count is negative");
        }
      }
    }
  }
  return parsed;
}

// Innermost range wins WITHIN ONE execution: painting ranges shortest-first
// means the shortest containing range paints each code unit first and longer
// (outer) ranges can never overwrite it. Offsets are UTF-16 code-unit
// positions of the source STRING; a range beyond the source fails closed.
export function effectiveVerdict(sourceLength, ranges) {
  const painted = new Uint8Array(sourceLength);
  const covered = new Uint8Array(sourceLength);
  const ordered = [...ranges].sort((a, b) => (a.endOffset - a.startOffset) - (b.endOffset - b.startOffset));
  for (const range of ordered) {
    // V8 offsets are code-unit positions inside the emitted source STRING.
    // A range beyond the source is profile corruption, not a partial line,
    // so fail closed instead of clamping it into a fake measurement.
    if (range.startOffset < 0 || range.endOffset > sourceLength) {
      throw new Error(
        `coverage range [${range.startOffset}, ${range.endOffset}) exceeds the emitted source length ${sourceLength}`
      );
    }
    const isCovered = range.count > 0 ? 1 : 0;
    for (let i = range.startOffset; i < range.endOffset; i += 1) {
      if (painted[i] === 0) {
        painted[i] = 1;
        covered[i] = isCovered;
      }
    }
  }
  return { painted, covered };
}

// Union-of-executions semantics: a code unit is covered when ANY execution
// covered it, and in-range (painted) when ANY execution painted it.
export function mergeVerdicts(target, verdict) {
  if (target === null) {
    return {
      painted: Uint8Array.from(verdict.painted),
      covered: Uint8Array.from(verdict.covered),
    };
  }
  const length = target.painted.length;
  const painted = new Uint8Array(length);
  const covered = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    painted[i] = target.painted[i] | verdict.painted[i];
    covered[i] = target.covered[i] | verdict.covered[i];
  }
  return { painted, covered };
}

// Line classification in UTF-16 code-unit space (NOT bytes): line starts are
// found by scanning for \n code units, so non-ASCII content cannot shift
// offsets. A line is covered when any of its code units has covered === 1,
// uncovered when some are painted but none covered, and excluded from totals
// when none of its code units is painted.
export function classifyLines(source, verdict) {
  const starts = [0];
  for (let i = 0; i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) starts.push(i + 1);
  }
  const coveredLines = new Set();
  const uncoveredLines = [];
  for (let line = 0; line < starts.length; line += 1) {
    const from = starts[line];
    const to = line + 1 < starts.length ? starts[line + 1] : source.length;
    let sawAny = false;
    let sawCovered = false;
    for (let i = from; i < to; i += 1) {
      if (verdict.painted[i] === 0) continue;
      sawAny = true;
      if (verdict.covered[i] === 1) sawCovered = true;
    }
    if (sawCovered) coveredLines.add(line);
    else if (sawAny) uncoveredLines.push(line + 1);
  }
  const linesTotal = coveredLines.size + uncoveredLines.length;
  const linesCovered = coveredLines.size;
  return {
    linesTotal,
    linesCovered,
    uncoveredLines: uncoveredLines.slice(0, MAX_UNCOVERED),
    uncoveredLinesTruncated: uncoveredLines.length > MAX_UNCOVERED,
  };
}

// Group rules on the dist-test-relative posix path: src/interop/ is helper
// code NOT published by ts/package.json ("files" ships only dist, dist/client,
// dist/server); test/ is the test suite itself; other src/ files are product.
// Everything else (tsc, node: internals, scripts) is ignored entirely.
export function groupFor(relPosix) {
  if (relPosix.startsWith("src/interop/")) return "interop";
  if (relPosix.startsWith("src/")) return "product";
  if (relPosix.startsWith("test/")) return "helper";
  return null;
}

function roundPct(covered, total) {
  if (total === 0) return null;
  return Math.round((100 * covered) / total * 100) / 100;
}

// A raw URL is accepted only when it resolves inside dist-test and is a .js
// file; malformed URLs are out-of-scope by design.
function entryRelPath(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "file:") return null;
  let filePath;
  try {
    filePath = fileURLToPath(parsed);
  } catch {
    return null;
  }
  const absolute = path.resolve(filePath);
  if (!absolute.endsWith(".js")) return null;
  const rel = path.relative(distTest, absolute);
  if (rel === "" || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
  return rel.split(path.sep).join("/");
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
    "Node V8 line coverage of the tsc-EMITTED JavaScript under dist-test, not TypeScript source lines.",
    "Per-line verdicts derive from V8 function/block ranges with the innermost range winning; branch coverage is not measured.",
    "Lines are classified in UTF-16 code-unit space (V8 offsets); executions are combined by union: a line is covered when any process covered it.",
  ];
  for (const group of GROUPS) {
    const g = json.groups[group];
    lines.push(`# group: ${GROUP_LABELS[group]}`);
    for (const f of json.files.filter((f) => f.group === group)) {
      const pct = f.pct === null ? "n/a" : `${f.pct}`;
      lines.push(`${pct}%  ${f.linesCovered}/${f.linesTotal}  ${f.path}`);
    }
    const pct = g.pct === null ? "n/a" : `${g.pct}`;
    lines.push(`TOTAL ${pct}%  ${g.linesCovered}/${g.linesTotal}`);
  }
  if (json.inventory.unloaded.length > 0) {
    lines.push("# not loaded by any test (recorded, not measured):");
    for (const rel of json.inventory.unloaded) lines.push(rel);
  }
  return `${lines.join("\n")}\n`;
}

// Aggregates parsed per-execution payloads into per-file records and the
// source inventory. This is the exact function the CLI runs, so reverting to
// cross-file range flattening here fails the regression controls. Fail-closed:
// readSource/listSources errors propagate; empty inputs and zero measured
// lines throw.
export function aggregateExecutions({ executions, readSource, listSources }) {
  // executions: [{ name, payload }] — payload already validated by parseRawPayload.
  if (!Array.isArray(executions) || executions.length === 0) {
    throw new Error("raw coverage contains no executions");
  }
  const inventoryList = listSources();
  if (!Array.isArray(inventoryList) || inventoryList.length === 0) {
    throw new Error("dist-test contains no classifiable .js sources");
  }
  const byFile = new Map();
  let skippedOutOfScope = 0;
  for (const { payload } of executions) {
    for (const entry of payload.result) {
      const relPosix = entryRelPath(entry.url);
      if (relPosix === null || groupFor(relPosix) === null) {
        skippedOutOfScope += 1;
        continue;
      }
      const ranges = entry.functions.flatMap((fn) => fn.ranges);
      let acc = byFile.get(relPosix);
      if (acc === undefined) {
        // Read the emitted source STRING once per file; offsets are code-unit
        // positions so the string must be decoded here, not kept as bytes.
        const source = readSource(relPosix);
        acc = { source, verdict: null };
        byFile.set(relPosix, acc);
      }
      // Per (execution, entry) verdict, merged with union semantics — ranges
      // are NEVER appended across executions.
      const verdict = effectiveVerdict(acc.source.length, ranges);
      acc.verdict = mergeVerdicts(acc.verdict, verdict);
    }
  }
  if (byFile.size === 0) throw new Error("raw coverage contains no accepted dist-test entries");
  const files = [...byFile.entries()]
    .map(([relPosix, { source, verdict }]) => {
      const stats = classifyLines(source, verdict);
      // A loaded record that measures nothing means the profile's ranges do not correspond to the emitted source — corruption, not a low number.
      if (stats.linesTotal === 0) throw new Error(`coverage record measures no lines: ${relPosix}`);
      return {
        path: relPosix,
        group: groupFor(relPosix),
        loaded: true,
        ...stats,
        pct: roundPct(stats.linesCovered, stats.linesTotal),
      };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const measuredTotal = files.reduce((sum, f) => sum + f.linesTotal, 0);
  if (measuredTotal === 0) throw new Error("raw coverage contains no measured lines");
  const inventory = {
    files: inventoryList.length,
    loaded: inventoryList.filter((rel) => byFile.has(rel)).length,
    unloaded: inventoryList.filter((rel) => !byFile.has(rel)).sort(),
  };
  return { files, inventory, skippedOutOfScope };
}

function readRawDir(dir) {
  try {
    return readdirSync(dir);
  } catch (err) {
    throw new Error(`cannot read raw coverage directory ${dir}: ${err.code}`);
  }
}

// Run the main IO path only when this module is the entry point, so the
// regression tests can import the pure core without triggering process.exit.
if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [rawDir, outDir] = process.argv.slice(2);
  if (!rawDir || !outDir) {
    console.error("usage: node scripts/coverage-summary.mjs <raw-coverage-dir> <out-dir>");
    process.exit(2);
  }

  const rawNames = readRawDir(rawDir).filter((name) => name.endsWith(".json")).sort();
  if (rawNames.length === 0) throw new Error(`no raw V8 coverage JSON files found in ${rawDir}`);
  const executions = rawNames.map((name) => ({
    name,
    payload: parseRawPayload(readFileSync(path.join(rawDir, name), "utf8")),
  }));

  const readSource = (relPosix) => {
    try {
      // Read the emitted source STRING; offsets are code-unit positions so
      // the string must be decoded here, not kept as bytes.
      return readFileSync(path.join(distTest, ...relPosix.split("/")), "utf8");
    } catch (err) {
      throw new Error(`coverage references unreadable file ${relPosix}: ${err.code}`);
    }
  };
  const listSources = () => {
    // Source inventory: every classifiable .js file that exists under dist-test.
    const walk = readdirSync(distTest, { recursive: true, withFileTypes: true });
    const inventoryFiles = [];
    for (const dirent of walk) {
      if (!dirent.isFile() || !dirent.name.endsWith(".js")) continue;
      const parent = dirent.parentPath !== undefined ? dirent.parentPath : path.dirname(dirent.path ?? "");
      const rel = path.relative(distTest, path.join(parent, dirent.name)).split(path.sep).join("/");
      if (groupFor(rel) !== null) inventoryFiles.push(rel);
    }
    if (inventoryFiles.length === 0) throw new Error("dist-test contains no classifiable .js sources");
    return inventoryFiles;
  };

  const { files, inventory, skippedOutOfScope } = aggregateExecutions({ executions, readSource, listSources });

  const allTotal = {
    files: files.length,
    linesTotal: files.reduce((sum, f) => sum + f.linesTotal, 0),
    linesCovered: files.reduce((sum, f) => sum + f.linesCovered, 0),
  };
  const json = {
    tool: "Node V8 coverage (NODE_V8_COVERAGE)",
    mode: null,
    generatedBy: GENERATED_BY,
    groups: groupSummary(files),
    total: { ...allTotal, pct: roundPct(allTotal.linesCovered, allTotal.linesTotal) },
    inventory,
    files,
  };

  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, "summary.json"), `${JSON.stringify(json, null, 2)}\n`, "utf8");
  writeFileSync(path.join(outDir, "summary.txt"), renderTxt(json), "utf8");
  console.error(`skipped out-of-scope raw entries: ${skippedOutOfScope}`);
  console.log(`ts coverage summary: ${files.length} files, ${inventory.unloaded.length} unloaded -> ${path.join(outDir, "summary.json")}, ${path.join(outDir, "summary.txt")}`);
}
