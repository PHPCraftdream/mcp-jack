// Regression tests for the pure core AND the CLI aggregation path of
// ts/scripts/coverage-summary.mjs: union-of-executions merging, UTF-16 (not
// UTF-8 byte) line classification, innermost-range-wins painting, fail-closed
// payload parsing, and fail-closed aggregation (source reads, inventory,
// measured-lines guard).
// Run with: node --test scripts/coverage-summary.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  parseRawPayload,
  effectiveVerdict,
  mergeVerdicts,
  classifyLines,
  groupFor,
  aggregateExecutions,
  MAX_UNCOVERED,
} from "./coverage-summary.mjs";

// Builds a payload entry URL that entryRelPath maps to the given
// dist-test-relative posix path: the module resolves URLs against
// distTest = path.resolve(process.cwd(), "dist-test"), and the test's cwd is
// the ts/ directory, so pathToFileURL over the absolute dist-test path lands
// exactly inside distTest and containment (no ".." segments) holds.
function distTestUrl(relPosix) {
  return pathToFileURL(path.resolve(process.cwd(), "dist-test", ...relPosix.split("/"))).href;
}

function oneExecution(url, startOffset, endOffset, count) {
  return {
    name: "x.json",
    payload: {
      result: [{ url, functions: [{ functionName: "", ranges: [{ startOffset, endOffset, count }] }] }],
    },
  };
}

test("nested coverage ranges union across processes", () => {
  // Source "ab\ncd\n": 6 code units. Line 1 = units 0..2, line 2 = units 3..5.
  const source = "ab\ncd\n";
  // Process A paints 0..5 as uncovered (count 0).
  const a = effectiveVerdict(source.length, [{ startOffset: 0, endOffset: 6, count: 0 }]);
  // Process B paints 0..2 as covered (count 1).
  const b = effectiveVerdict(source.length, [{ startOffset: 0, endOffset: 3, count: 1 }]);
  const merged = mergeVerdicts(mergeVerdicts(null, a), b);
  // Units 0..2: painted by A and B, covered by B => covered.
  // Units 3..5: painted uncovered by A only => painted-uncovered.
  assert.deepEqual(classifyLines(source, merged), {
    linesTotal: 2,
    linesCovered: 1,
    uncoveredLines: [2],
    uncoveredLinesTruncated: false,
  });
});

test("identical ranges hit and unhit across executions merge to covered", () => {
  // Discriminating test against cross-file flattening: BOTH executions carry
  // the IDENTICAL range [0,3). Source "abc\n" is 4 code units, one line.
  // Union semantics: unit covered when any execution covered it -> line 1
  // covered. The old broken shortest-first flatten appended ranges across
  // executions, painting units 0..2 uncovered first and never overwriting,
  // which would report the line uncovered. Expect 1/1 covered, no uncovered.
  const url = distTestUrl("src/a.js");
  const executions = [
    { name: "a.json", payload: { result: [{ url, functions: [{ functionName: "", ranges: [{ startOffset: 0, endOffset: 3, count: 0 }] }] }] } },
    { name: "b.json", payload: { result: [{ url, functions: [{ functionName: "", ranges: [{ startOffset: 0, endOffset: 3, count: 1 }] }] }] } },
  ];
  const { files, skippedOutOfScope } = aggregateExecutions({
    executions,
    readSource: (rel) => (rel === "src/a.js" ? "abc\n" : ""),
    listSources: () => ["src/a.js"],
  });
  assert.equal(files.length, 1);
  assert.equal(files[0].path, "src/a.js");
  assert.equal(files[0].linesTotal, 1);
  assert.equal(files[0].linesCovered, 1);
  assert.deepEqual(files[0].uncoveredLines, []);
  assert.equal(files[0].pct, 100);
  assert.equal(skippedOutOfScope, 0);
});

test("inner uncovered range inside outer covered range stays uncovered", () => {
  // Source "aa\nbb\n": 6 code units. Line 1 = units 0..2, line 2 = units 3..5.
  // Same execution: outer covered {0,5} (ends before line 2) and inner
  // uncovered {3,5} covering all of line 2. Shortest-first painting makes
  // units 3..4 keep the inner uncovered verdict; with the outer range ending
  // at 5, no unit of line 2 is covered.
  const source = "aa\nbb\n";
  const verdict = effectiveVerdict(source.length, [
    { startOffset: 0, endOffset: 5, count: 5 },
    { startOffset: 3, endOffset: 5, count: 0 },
  ]);
  assert.deepEqual(classifyLines(source, verdict), {
    linesTotal: 2,
    linesCovered: 1,
    uncoveredLines: [2],
    uncoveredLinesTruncated: false,
  });
});

test("non-ASCII source keeps UTF-16 offsets aligned", () => {
  // "aé b\ncd\n": code units are a=0, é=1 (ONE UTF-16 unit), space=2, b=3,
  // \n=4, c=5, d=6, \n=7; source.length === 8. The uncovered range {5,7}
  // targets line 2 ("cd\n") exactly; line 1 is never painted.
  const source = "aé b\ncd\n";
  assert.equal(source.length, 8);
  const verdict = effectiveVerdict(source.length, [{ startOffset: 5, endOffset: 7, count: 0 }]);
  assert.deepEqual(classifyLines(source, verdict), {
    linesTotal: 1,
    linesCovered: 0,
    uncoveredLines: [2],
    uncoveredLinesTruncated: false,
  });
});

test("malformed payloads are rejected", () => {
  assert.throws(() => parseRawPayload("not json"), /malformed raw V8 coverage payload/);
  assert.throws(() => parseRawPayload("{}"), /malformed raw V8 coverage payload/);
  assert.throws(() => parseRawPayload(JSON.stringify({ result: "x" })), /malformed raw V8 coverage payload/);
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [{ url: 5, functions: [] }] })),
    /malformed raw V8 coverage payload/
  );
  const entry = (ranges, functions) => ({ url: "file:///x.js", functions: functions ?? [{ functionName: "", ranges }] });
  // Fractional offset 1.5 is not a safe integer.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([{ startOffset: 0, endOffset: 1.5, count: 1 }])] })),
    /range endOffset is not a safe integer/
  );
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([{ startOffset: 1.5, endOffset: 3, count: 1 }])] })),
    /range startOffset is not a safe integer/
  );
  // Negative count.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([{ startOffset: 0, endOffset: 3, count: -1 }])] })),
    /range count is negative/
  );
  // Reversed interval: endOffset < startOffset.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([{ startOffset: 3, endOffset: 1, count: 1 }])] })),
    /range endOffset is before startOffset/
  );
  // Negative startOffset.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([{ startOffset: -1, endOffset: 3, count: 1 }])] })),
    /range startOffset is negative/
  );
  // Empty functions array.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [{ url: "file:///x.js", functions: [] }] })),
    /functions is empty/
  );
  // Empty ranges array.
  assert.throws(
    () => parseRawPayload(JSON.stringify({ result: [entry([])] })),
    /function ranges is empty/
  );
});

test("valid minimal payload parses", () => {
  const payload = parseRawPayload(
    JSON.stringify({
      result: [
        {
          url: "file:///x.js",
          functions: [{ functionName: "", ranges: [{ startOffset: 0, endOffset: 1, count: 1 }] }],
        },
      ],
    })
  );
  assert.equal(payload.result.length, 1);
});

test("uncovered line list is capped", () => {
  // 900 lines of "x\n", all painted uncovered in one execution:
  // linesTotal 900, linesCovered 0, uncoveredLines capped at MAX_UNCOVERED.
  const source = "x\n".repeat(900);
  const verdict = effectiveVerdict(source.length, [{ startOffset: 0, endOffset: source.length, count: 0 }]);
  const stats = classifyLines(source, verdict);
  assert.equal(stats.linesTotal, 900);
  assert.equal(stats.linesCovered, 0);
  assert.equal(stats.uncoveredLines.length, MAX_UNCOVERED);
  assert.equal(stats.uncoveredLinesTruncated, true);
});

test("groupFor rules are unchanged", () => {
  assert.equal(groupFor("src/interop/foo.js"), "interop");
  assert.equal(groupFor("src/foo.js"), "product");
  assert.equal(groupFor("test/foo.test.js"), "helper");
  assert.equal(groupFor("other/foo.js"), null);
});

test("aggregateExecutions propagates readSource failures", () => {
  const url = distTestUrl("src/a.js");
  assert.throws(
    () =>
      aggregateExecutions({
        executions: [oneExecution(url, 0, 3, 1)],
        readSource: () => {
          throw new Error("coverage references unreadable file src/a.js: ENOENT");
        },
        listSources: () => ["src/a.js"],
      }),
    /coverage references unreadable file src\/a\.js: ENOENT/
  );
});

test("aggregateExecutions rejects an empty source inventory", () => {
  const url = distTestUrl("src/a.js");
  assert.throws(
    () =>
      aggregateExecutions({
        executions: [oneExecution(url, 0, 3, 1)],
        readSource: () => "abc\n",
        listSources: () => [],
      }),
    /dist-test contains no classifiable \.js sources/
  );
});

test("aggregateExecutions rejects ranges beyond the emitted source", () => {
  // Source "abc\n" is 4 code units. A range entirely past the end and a
  // range partially past the end are both profile corruption: clamping
  // would turn them into fake full or partial measurements, so the shared
  // aggregation core (the exact function the CLI runs) fails closed.
  const url = distTestUrl("src/a.js");
  assert.throws(
    () =>
      aggregateExecutions({
        executions: [oneExecution(url, 100, 200, 1)],
        readSource: () => "abc\n",
        listSources: () => ["src/a.js"],
      }),
    /exceeds the emitted source length/
  );
  assert.throws(
    () =>
      aggregateExecutions({
        executions: [oneExecution(url, 0, 100, 1)],
        readSource: () => "abc\n",
        listSources: () => ["src/a.js"],
      }),
    /exceeds the emitted source length/
  );
});

test("aggregateExecutions rejects payloads that paint no measured lines", () => {
  // A degenerate [0,0) range over an empty emitted source paints nothing:
  // corruption, not a zero-line file.
  const url = distTestUrl("src/a.js");
  assert.throws(
    () =>
      aggregateExecutions({
        executions: [oneExecution(url, 0, 0, 1)],
        readSource: () => "",
        listSources: () => ["src/a.js"],
      }),
    /coverage record measures no lines: src\/a\.js/
  );
});

test("aggregateExecutions splits inventory into loaded and unloaded", () => {
  // Only src/a.js is aggregated; src/b.js is listed but never loaded.
  const url = distTestUrl("src/a.js");
  const { files, inventory } = aggregateExecutions({
    executions: [oneExecution(url, 0, 4, 1)],
    readSource: (rel) => (rel === "src/a.js" ? "abc\n" : ""),
    listSources: () => ["src/b.js", "src/a.js"],
  });
  assert.equal(files.length, 1);
  assert.equal(inventory.files, 2);
  assert.equal(inventory.loaded, 1);
  assert.deepEqual(inventory.unloaded, ["src/b.js"]);
});
