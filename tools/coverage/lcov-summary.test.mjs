// Regression tests for the pure parser of tools/coverage/lcov-summary.mjs:
// record assembly, and fail-closed rejection of malformed, negative,
// duplicate, and truncated tracefiles.
// Run with: node --test tools/coverage/lcov-summary.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLcov } from "./lcov-summary.mjs";

test("valid single record with two DA lines parses", () => {
  // Two DA lines: line 12 covered, line 14 uncovered.
  const text = ["SF:src/main.rs", "DA:12,1", "DA:14,0", "end_of_record", ""].join("\n");
  const files = parseLcov(text);
  assert.equal(files.length, 1);
  assert.equal(files[0].sf, "src/main.rs");
  assert.equal(files[0].da.length, 2);
  assert.equal(files[0].da[0].line, 12);
  assert.equal(files[0].da[0].count, 1);
  assert.equal(files[0].da[1].count, 0);
});

test("malformed DA record is rejected", () => {
  const text = ["SF:src/main.rs", "DA:12", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /malformed lcov DA record/);
});

test("negative DA count is rejected", () => {
  // lcov counts are non-negative; the tightened regex rejects -1.
  const text = ["SF:src/main.rs", "DA:12,-1", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /malformed lcov DA record/);
});

test("duplicate DA line number is rejected", () => {
  const text = ["SF:src/main.rs", "DA:12,1", "DA:12,0", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /duplicate lcov DA line/);
});

test("DA line number 0 is rejected", () => {
  // lcov line numbers are 1-based; llvm-cov never emits line 0.
  const text = ["SF:src/main.rs", "DA:0,1", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /malformed lcov DA record/);
});

test("non-safe-integer DA number is rejected", () => {
  // A 20-digit count exceeds Number precision: corruption, not a big number.
  const text = ["SF:src/main.rs", "DA:12,12345678901234567890", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /out of safe-integer range/);
});

test("DA record outside any SF record is rejected", () => {
  // A stray DA line before any SF would silently disappear from the totals.
  const text = ["DA:12,1", "SF:src/main.rs", "DA:12,1", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /outside any SF record/);
});

test("DA-less record is rejected", () => {
  const text = ["SF:src/main.rs", "end_of_record", ""].join("\n");
  assert.throws(() => parseLcov(text), /lcov record without DA lines/);
});

test("unterminated final record is rejected", () => {
  // SF without end_of_record before EOF: the tracefile was truncated.
  const text = ["SF:src/main.rs", "DA:12,1", ""].join("\n");
  assert.throws(() => parseLcov(text), /unterminated lcov record/);
});

test("second SF while a record is open is rejected", () => {
  const text = ["SF:src/main.rs", "DA:12,1", "SF:src/other.rs", ""].join("\n");
  assert.throws(() => parseLcov(text), /unterminated lcov record before/);
});

test("valid multi-record file parses to two records", () => {
  const text = [
    "SF:src/main.rs",
    "DA:12,1",
    "end_of_record",
    "SF:src/util.rs",
    "DA:3,0",
    "DA:4,1",
    "end_of_record",
    "",
  ].join("\n");
  const files = parseLcov(text);
  assert.equal(files.length, 2);
  assert.equal(files[0].sf, "src/main.rs");
  assert.equal(files[1].sf, "src/util.rs");
});
