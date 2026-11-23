/**
 * Runner for the modern-profile era-detection corpus of spec 04 section 8
 * (`spec/fixtures/modern/era-detection-vectors.json`, 38 cases) driven against
 * the real SDK C9 detector (`detectEra`) and its modern error-code set.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { detectEra } from "../../../src/modern/era.js";
import { arrayOf, flag, modernFixture, printSummary, record, text, textList } from "./support.js";

test("era-detection vectors: every case", () => {
  const what = "era-detection-vectors.json";
  const corpus = record(modernFixture(what), what);
  const cases = arrayOf(corpus["cases"], what + ".cases");
  assert.equal(cases.length, 38, "era-detection-vectors.json case count");
  assert.deepEqual(
    arrayOf(corpus["modern_error_codes"], what + ".modern_error_codes"),
    [-32020, -32021, -32022],
    "era-detection-vectors.json modern error codes",
  );

  let pass = 0;
  for (const raw of cases) {
    const c = record(raw, "case");
    const id = text(c, "id", "case");
    const expect = record(c["expect"], id + ": expect");
    const response = record(c["response"], id + ": response");

    const status = response["status"];
    assert.equal(typeof status, "number", id + ": response.status is a number");
    const probe = {
      verified: flag(response, "verified", id),
      status: Number(response["status"]),
      ...(typeof response["body_text"] === "string" ? { bodyText: response["body_text"] } : {}),
    };
    const detection = detectEra(probe, textList(c["clientVersions"], id + ": clientVersions"));

    assert.equal(detection.era, text(expect, "era", id), id + ": era");
    assert.equal(detection.action, text(expect, "action", id), id + ": action");
    assert.deepEqual(detection.reason, expect["reason"], id + ": reason");
    if (expect["supported"] !== undefined) {
      assert.deepEqual(detection.supported, expect["supported"], id + ": supported");
    } else {
      assert.equal(detection.supported, undefined, id + ": supported");
    }
    pass += 1;
  }

  printSummary("era-detection", pass);
  assert.equal(pass, 38, "era-detection pass count");
});
