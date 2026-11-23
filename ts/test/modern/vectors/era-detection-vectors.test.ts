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

test("era detection: recognition boundaries", () => {
  const legacy = { era: "legacy", action: "fallback_initialize", reason: "no_modern_error" };
  const clientVersions = ["2026-07-28"];

  const stringCode = detectEra(
    { verified: true, status: 400, bodyText: '{"jsonrpc":"1.0","error":{"code":"-32020","message":"x"}}' },
    clientVersions,
  );
  assert.deepEqual(stringCode, legacy, "A non-2.0 envelope is not a modern error.");

  const missingId = detectEra(
    { verified: true, status: 400, bodyText: '{"jsonrpc":"2.0","error":{"code":-32020,"message":"x"}}' },
    clientVersions,
  );
  assert.deepEqual(missingId, legacy, "A recognised error needs an id member.");

  const mixedSupported = detectEra(
    {
      verified: true,
      status: 400,
      bodyText: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x","data":{"supported":["2026-07-28",7]}}}',
    },
    clientVersions,
  );
  assert.deepEqual(
    mixedSupported,
    { era: "modern", action: "abort", reason: "unsupported_version_no_overlap" },
    "A mixed supported list is not usable.",
  );

  const retry = detectEra(
    {
      verified: true,
      status: 400,
      bodyText: '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"x","data":{"supported":["2025-11-25","2026-07-28"]}}}',
    },
    clientVersions,
  );
  assert.deepEqual(
    retry,
    { era: "modern", action: "retry_with_supported", reason: null, supported: ["2026-07-28"] },
    "The mutual versions keep server order.",
  );

  const notFound = detectEra(
    { verified: true, status: 404, bodyText: '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"x"}}' },
    clientVersions,
  );
  assert.deepEqual(notFound, legacy, "Only -32601 is a modern signal on a 404.");

  const methodNotAllowed = detectEra(
    { verified: true, status: 405, bodyText: '{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"x"}}' },
    clientVersions,
  );
  assert.deepEqual(methodNotAllowed, legacy, "A 405 is legacy whatever the body says.");
});
