/** Tests for name syntax, per spec 03 section 1. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { validName } from "../src/syntax.js";

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
