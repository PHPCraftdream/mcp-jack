/** Tests for scope/name syntax and policy pattern matching, ported from Go's pattern_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { matchPattern, validName, validScope } from "../src/syntax.js";
import { loadPatternVectors } from "./fixtures.js";

test("matchPattern over every pattern-vectors.json case", () => {
  const vectors = loadPatternVectors();
  for (const c of vectors.cases) {
    assert.equal(
      matchPattern(c.pattern, c.input),
      c.match,
      `case ${c.id}: MatchPattern(${JSON.stringify(c.pattern)}, ${JSON.stringify(c.input)})`,
    );
  }
});

test("matchPattern unit table", () => {
  // Only '*' is a metacharacter; everything else is a literal, and '*'
  // matches across newlines too (spec 02 section 3).
  const cases: readonly [pattern: string, input: string, want: boolean][] = [
    ["*", "", true],
    ["*", "anything\nat all", true],
    ["a*", "a\nb", true],
    ["*status", "svc.status.extra", false],
    ["a+b", "a+b", true],
    ["a+b", "aab", false],
    ["(x)", "(x)", true],
    ["?", "?", true],
    ["?", "a", false],
  ];
  for (const [pattern, input, want] of cases) {
    assert.equal(matchPattern(pattern, input), want, `MatchPattern(${JSON.stringify(pattern)}, ${JSON.stringify(input)})`);
  }
});

test("validScope accepts and rejects per spec 02 section 2", () => {
  const accept = ["read", "config:write", "a:b:c", "lifecycle", "a1_b"];
  const reject = ["", "Read", "1abc", "a::b", "a:b-", "read ", "a:b c", "read\n", "read\r\n", "read\u2028"];
  for (const s of accept) {
    assert.ok(validScope(s), `ValidScope(${JSON.stringify(s)}) should be true`);
  }
  for (const s of reject) {
    assert.ok(!validScope(s), `ValidScope(${JSON.stringify(s)}) should be false`);
  }
});

test("validName accepts and rejects per spec 03 section 1", () => {
  const accept = ["a", "alice-laptop", "A_1.b-c", "a".repeat(64)];
  const reject = ["", "a".repeat(65), "bad name", "bad:name", "bad/name", "alice\n", "alice\r", "alice "];
  for (const s of accept) {
    assert.ok(validName(s), `ValidName(${JSON.stringify(s)}) should be true`);
  }
  for (const s of reject) {
    assert.ok(!validName(s), `ValidName(${JSON.stringify(s)}) should be false`);
  }
});
