// Regression tests for the pure parser of tools/coverage/go-summary.mjs:
// block dedupe/merge semantics, and fail-closed rejection of malformed,
// mode-mismatched, reversed, and precision-corrupted cover profiles.
// Run with: node --test tools/coverage/go-summary.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseProfile } from "./go-summary.mjs";

// Builds a two-block profile for one file: block A (lines 1..2, 3 stmts) is
// hit, block B (lines 3..4, 5 stmts) is unhit.
function twoBlockProfile() {
  return [
    "mode: atomic",
    "example.com/pkg/a.go:1.2,2.3 3 1",
    "example.com/pkg/a.go:3.2,4.3 5 0",
  ].join("\n");
}

test("valid two-block profile parses", () => {
  // Block A: startLine 1, endLine 2, numStmt 3, count 1 -> covered.
  // Block B: startLine 3, endLine 4, numStmt 5, count 0 -> uncovered.
  const { mode, blocks } = parseProfile(twoBlockProfile());
  assert.equal(mode, "atomic");
  assert.equal(blocks.length, 2);
  assert.equal(blocks[0].numStmt, 3);
  assert.equal(blocks[0].covered, true);
  assert.equal(blocks[1].numStmt, 5);
  assert.equal(blocks[1].covered, false);
});

test("duplicate block with equal numStmt merges to covered", () => {
  // With -coverpkg the same block repeats across test binaries: identical
  // position and numStmt, first count 0 then count 7. The union semantics
  // (covered when ANY count is nonzero) must yield exactly ONE covered block.
  const text = [
    "mode: count",
    "example.com/pkg/a.go:1.2,2.3 3 0",
    "example.com/pkg/a.go:1.2,2.3 3 7",
  ].join("\n");
  const { blocks } = parseProfile(text);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].covered, true);
});

test("duplicate block with inconsistent numStmt is rejected", () => {
  const text = [
    "mode: count",
    "example.com/pkg/a.go:1.2,2.3 3 0",
    "example.com/pkg/a.go:1.2,2.3 4 7",
  ].join("\n");
  assert.throws(() => parseProfile(text), /inconsistent numStmt for block/);
});

test("unsupported mode is rejected", () => {
  const text = `mode: weighted\nexample.com/pkg/a.go:1.2,2.3 3 1`;
  assert.throws(() => parseProfile(text), /unsupported cover profile mode/);
});

test("malformed cover profile line is rejected", () => {
  const text = "mode: count\nthis is not a block line";
  assert.throws(() => parseProfile(text), /malformed cover profile line/);
});

test("reversed coordinates are rejected", () => {
  // startLine 5 > endLine 2: go tool cover never emits this.
  const text = "mode: count\nexample.com/pkg/a.go:5.2,2.3 3 1";
  assert.throws(() => parseProfile(text), /reversed coordinates/);
});

test("reversed same-line columns are rejected", () => {
  // Same line, start column 20 > end column 2: go tool cover never emits this.
  const text = "mode: count\nexample.com/pkg/a.go:1.20,1.2 3 1";
  assert.throws(() => parseProfile(text), /reversed coordinates/);
});

test("non-safe-integer field is rejected", () => {
  // 20-digit count exceeds Number.MAX_SAFE_INTEGER precision.
  const text = "mode: count\nexample.com/pkg/a.go:1.2,2.3 3 12345678901234567890";
  assert.throws(() => parseProfile(text), /non-safe-integer field/);
});

test("missing mode header is rejected", () => {
  // The parser message contains literal backticks around `mode:`.
  assert.throws(() => parseProfile("example.com/pkg/a.go:1.2,2.3 3 1"), /missing `mode:` header/);
});
