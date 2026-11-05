/** parseJsonRaw literals: each keyword must consume exactly its own length. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJsonRaw } from "../src/server/verify.js";

test("literals true, false and null are consumed exactly", () => {
  const parsed = parseJsonRaw('{"a":false,"b":true,"c":null,"d":[false,true,null]}');
  assert.deepEqual(parsed.value, { a: false, b: true, c: null, d: [false, true, null] });
  assert.equal(parsed.source.members?.get("a")?.text, "false");
});

test("a keyword followed by garbage is rejected", () => {
  assert.throws(() => parseJsonRaw("[false1]"), /invalid JSON/);
  assert.throws(() => parseJsonRaw('{"a":false"}'), /invalid JSON/);
});
