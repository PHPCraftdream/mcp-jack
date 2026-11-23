/**
 * Tests for the value rules of the modern profile of spec 04: the section 2
 * character classes, the C3 encoder and C4 decoder of section 4, the
 * type-to-text projection and the `Mcp-Name` source table, driven against the
 * real SDK module.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeHeaderValue,
  decodeUtf8,
  encodeHeaderValue,
  isFieldValue,
  isModernVersion,
  isToken,
  isVersion,
  nameSourceOf,
  SAFE_INT_MAX,
  valueText,
} from "../../src/modern/values.js";

test("values: encode/decode round trip over odd values", () => {
  const inputs: readonly string[] = [
    "",
    "us-west1",
    "Seattle WA",
    " padded ",
    "\ta",
    "a\tb",
    "line1\nline2",
    "a\rb",
    "a\u0000b",
    "a\u007fb",
    "Hello, 世界",
    "🚀",
    "=?base64?literal?=",
    "=?BASE64?SGVsbG8=?=",
    "=?base64??=",
    "=?base64?",
    "abc?=",
    "x".repeat(100),
  ];
  for (const input of inputs) {
    assert.deepEqual(decodeHeaderValue(encodeHeaderValue(input)), { ok: true, text: input }, "Round trip must recover the text.");
  }
});

test("values: the sentinel is used only when section 4 requires it", () => {
  const encoded: readonly (readonly [string, string])[] = [
    ["", ""],
    ["us-west1", "us-west1"],
    [" padded ", "=?base64?IHBhZGRlZCA=?="],
    ["Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="],
    ["=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="],
    ["=?base64?abc", "=?base64?abc"],
    ["abc?=", "abc?="],
    ["=?Base64?SGVsbG8=?=", "=?Base64?SGVsbG8=?="],
  ];
  for (const [input, expected] of encoded) {
    assert.equal(encodeHeaderValue(input), expected, "The sentinel must be used exactly when required.");
  }
});

test("values: C4 rejects every non-canonical sentinel", () => {
  const bad: readonly string[] = [
    "=?base64?@@@@?=",
    "=?base64?SGVsbG8?=",
    "=?base64?SGVsbG9=?=",
    "=?base64?SGVs bG8=?=",
    "=?base64?SGVs\tbG8=?=",
    "=?base64?SGVsbG8_?=",
    "=?base64?/w==?=",
    "=?base64?wIA=?=",
    "=?base64?7aCA?=",
  ];
  for (const input of bad) {
    assert.deepEqual(decodeHeaderValue(input), { ok: false, reason: "bad_encoding" }, "A non-canonical sentinel must not decode.");
  }
  assert.deepEqual(decodeHeaderValue("=?base64??="), { ok: true, text: "" }, "The empty sentinel must decode to the empty string.");
  assert.deepEqual(decodeHeaderValue("=?BASE64?SGVsbG8=?="), { ok: true, text: "=?BASE64?SGVsbG8=?=" }, "An upper-case marker must be plain text.");
});

test("values: sentinel decode boundaries", () => {
  const bad: readonly string[] = [
    "=?base64?A?=",
    "=?base64?AAAAA?=",
    "=?base64?A===?=",
    "=?base64?====?=",
    "=?base64?AB==?=",
    "=?base64?SGVsbG8===?=",
    "=?base64?SGVsbG8=\u0000?=",
    "=?base64?SGVsbG8=/w==?=",
  ];
  for (const input of bad) {
    assert.deepEqual(decodeHeaderValue(input), { ok: false, reason: "bad_encoding" }, "An undecodable sentinel must not decode.");
  }

  const plain: readonly string[] = ["=?base64??=x", "x=?base64??="];
  for (const input of plain) {
    assert.deepEqual(decodeHeaderValue(input), { ok: true, text: input }, "A value that is not an envelope must stay plain text.");
  }
  assert.deepEqual(decodeHeaderValue("=?base64??="), { ok: true, text: "" }, "The empty sentinel must decode to the empty string, not plain text.");
  assert.deepEqual(decodeHeaderValue("=?base64?SGVsbG8=?="), { ok: true, text: "Hello" }, "A canonical sentinel must decode to its UTF-8 text.");
});

test("values: character classes", () => {
  const fieldValueOk: readonly string[] = ["a b", "\ta", ""];
  for (const value of fieldValueOk) {
    assert.equal(isFieldValue(value), true, "The value must be a field value.");
  }
  const fieldValueBad: readonly string[] = ["a\nb", "a\rb", "a\u0000b", "a\u007fb", "é"];
  for (const value of fieldValueBad) {
    assert.equal(isFieldValue(value), false, "The value must not be a field value.");
  }

  const tokenOk: readonly string[] = ["A-b_c.d", "a`b"];
  for (const value of tokenOk) {
    assert.equal(isToken(value), true, "The value must be a token.");
  }
  const tokenBad: readonly string[] = ["", "a b", "a:b", "a@b", 'a"b', "é"];
  for (const value of tokenBad) {
    assert.equal(isToken(value), false, "The value must not be a token.");
  }

  const versionOk: readonly string[] = ["2026-07-28", "2025-11-25"];
  for (const value of versionOk) {
    assert.equal(isVersion(value), true, "The value must be a version.");
  }
  const versionBad: readonly unknown[] = ["2026-7-28", "2026-07-28-draft", "DRAFT-2026", 42, ""];
  for (const value of versionBad) {
    assert.equal(isVersion(value), false, "The value must not be a version.");
  }

  assert.equal(isModernVersion("2026-07-28"), true, "The minimum must be modern.");
  assert.equal(isModernVersion("2026-07-27"), false, "A day before the minimum must not be modern.");
  assert.equal(isModernVersion("2025-11-25"), false, "A legacy version must not be modern.");
});

test("values: the name source table is closed", () => {
  const sources: readonly (readonly [string, string | null])[] = [
    ["tools/call", "name"],
    ["resources/read", "uri"],
    ["events/list", null],
    ["tools/list", null],
    ["constructor", null],
    ["__proto__", null],
    ["toString", null],
    ["tools/call ", null],
  ];
  for (const [method, expected] of sources) {
    assert.equal(nameSourceOf(method), expected, "Only a table row may have a source.");
  }
});

test("values: valueText edges", () => {
  const integers: readonly (readonly [unknown, string | null])[] = [
    [0, "0"],
    [-7, "-7"],
    [42, "42"],
    [SAFE_INT_MAX, "9007199254740991"],
    [SAFE_INT_MAX + 2, null],
    [1.5, null],
    [NaN, null],
    ["42", null],
    [null, null],
    [undefined, null],
  ];
  for (const [value, expected] of integers) {
    assert.equal(valueText(value, "integer"), expected, "An integer must render as decimal text.");
  }

  assert.equal(valueText(true, "boolean"), "true", "True must render as text.");
  assert.equal(valueText(false, "boolean"), "false", "False must render as text.");
  assert.equal(valueText("true", "boolean"), null, "A string is not a boolean.");

  assert.equal(valueText("x", "string"), "x", "A string must render as itself.");
  assert.equal(valueText(7, "string"), null, "A number is not a string.");

  assert.equal(valueText("x", "number"), null, "An unknown type must not render.");
  assert.equal(valueText("x", "object"), null, "An object type must not render.");
});

test("values: decodeUtf8 accepts valid UTF-8 only", () => {
  assert.equal(decodeUtf8(new Uint8Array([0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f])), "héllo", "Valid UTF-8 must decode.");
  assert.equal(decodeUtf8(new Uint8Array([0x7b, 0xff, 0x7d])), undefined, "An invalid byte must not decode.");
  assert.equal(decodeUtf8(new Uint8Array([0xef, 0xbb, 0xbf, 0x61])), "\uFEFFa", "A leading BOM must be kept.");
});
