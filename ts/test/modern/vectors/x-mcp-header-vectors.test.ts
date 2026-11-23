/**
 * Runner for the modern-profile `x-mcp-header` corpus of spec 04 section 8
 * (`spec/fixtures/modern/x-mcp-header-vectors.json`, 84 cases) driven against
 * the real SDK C5 validator, C6 projector and their C11 event-type reuse.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ANNOTATION_REASONS, projectArguments, validateAnnotations } from "../../../src/modern/annotations.js";
import type { ProjectionOutcome } from "../../../src/modern/annotations.js";
import type { JsonValue } from "../../support/fixtures/index.js";
import { arrayOf, flag, headerPairs, modernFixture, printSummary, record, text } from "./support.js";

test("x-mcp-header vectors: every case", () => {
  const what = "x-mcp-header-vectors.json";
  const corpus = record(modernFixture(what), what);
  const cases = arrayOf(corpus["cases"], what + ".cases");
  assert.equal(cases.length, 84, "x-mcp-header-vectors.json case count");
  assert.deepEqual(
    arrayOf(corpus["reason_codes"], what + ".reason_codes"),
    [...ANNOTATION_REASONS],
    "x-mcp-header-vectors.json C5 reason codes in rule order",
  );
  assert.equal(
    text(corpus, "projection_reason", what),
    "header_projection_invalid_value",
    "x-mcp-header-vectors.json projection reason",
  );

  let pass = 0;
  for (const raw of cases) {
    const c = record(raw, "case");
    const id = text(c, "id", "case");
    const kind = text(c, "kind", id);
    const expect = record(c["expect"], id + ": expect");

    if (kind === "validate") {
      const tool = record(c["tool"], id + ": tool");
      const result = validateAnnotations(tool["inputSchema"]);
      assert.equal(result.valid, flag(expect, "valid", id), id + ": valid");
      assert.deepEqual(result.reason, expect["reason"], id + ": reason");
    } else if (kind === "validate-event") {
      const event = record(c["event"], id + ": event");
      const result = validateAnnotations(event["inputSchema"]);
      assert.equal(result.valid, flag(expect, "valid", id), id + ": valid");
      assert.deepEqual(result.reason, expect["reason"], id + ": reason");
    } else if (kind === "project") {
      const tool = record(c["tool"], id + ": tool");
      assertProjection(projectArguments(tool["inputSchema"], c["arguments"]), expect, id);
    } else if (kind === "project-event") {
      const event = record(c["event"], id + ": event");
      assertProjection(projectArguments(event["inputSchema"], c["arguments"]), expect, id);
    } else {
      assert.fail(id + ": unknown kind " + kind);
    }
    pass += 1;
  }

  printSummary("x-mcp-header", pass);
  assert.equal(pass, 84, "x-mcp-header pass count");
});

/** C6/C11 assertion: the expected outcome is `headers` with these pairs, or `refuse` with this reason. */
function assertProjection(
  outcome: ProjectionOutcome,
  expect: { readonly [key: string]: JsonValue },
  id: string,
): void {
  const expected = text(expect, "outcome", id);
  if (expected === "headers") {
    if (outcome.outcome === "headers") {
      assert.deepEqual(
        outcome.headers.map(([name, value]) => [name, value]),
        headerPairs(expect["headers"], id + ": expect.headers"),
        id + ": headers",
      );
    } else {
      assert.fail(id + ": outcome: expected headers, got " + outcome.outcome);
    }
  } else if (expected === "refuse") {
    if (outcome.outcome === "refuse") {
      assert.equal(outcome.reason, text(expect, "reason", id), id + ": reason");
    } else {
      assert.fail(id + ": outcome: expected refuse, got " + outcome.outcome);
    }
  } else {
    assert.fail(id + ": unknown outcome " + expected);
  }
}
