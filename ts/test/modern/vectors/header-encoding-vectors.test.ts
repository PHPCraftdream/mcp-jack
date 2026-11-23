/**
 * Runner for the modern-profile value-encoding and request-construction corpus
 * of spec 04 section 8 (`spec/fixtures/modern/header-encoding-vectors.json`, 51
 * cases) driven against the real SDK builder (`buildRequestMirrors`, C1-C2) and
 * the C3 encoder and C4 decoder of section 4.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildRequestMirrors } from "../../../src/modern/request.js";
import { decodeHeaderValue, encodeHeaderValue, valueText as valueTextOf } from "../../../src/modern/values.js";
import { arrayOf, flag, headerPairs, modernFixture, printSummary, record, text } from "./support.js";

test("header-encoding vectors: every case", () => {
  const what = "header-encoding-vectors.json";
  const corpus = record(modernFixture(what), what);
  const cases = arrayOf(corpus["cases"], what + ".cases");
  assert.equal(cases.length, 51, "header-encoding-vectors.json case count");

  let pass = 0;
  for (const raw of cases) {
    const c = record(raw, "case");
    const id = text(c, "id", "case");
    const kind = text(c, "kind", id);
    const expect = record(c["expect"], id + ": expect");

    if (kind === "build") {
      const mirrors = buildRequestMirrors({
        version: text(c, "version", id),
        method: text(c, "method", id),
        ...(c["params"] !== undefined ? { params: c["params"] } : {}),
      });
      assert.deepEqual(mirrors.meta, expect["meta"], id + ": meta");
      assert.deepEqual(
        mirrors.headers.map(([name, value]) => [name, value]),
        headerPairs(expect["headers"], id + ": expect.headers"),
        id + ": headers",
      );
    } else if (kind === "encode") {
      const encoded = valueTextOf(c["value"], text(c, "type", id));
      if (typeof encoded === "string") {
        assert.equal(encodeHeaderValue(encoded), text(expect, "header_value", id), id + ": header_value");
      } else {
        assert.fail(id + ": value is not representable");
      }
    } else if (kind === "decode") {
      const decoded = decodeHeaderValue(text(c, "header_value", id));
      assert.equal(decoded.ok, flag(expect, "ok", id), id + ": ok");
      if (decoded.ok) {
        assert.equal(decoded.text, text(expect, "text", id), id + ": text");
      } else {
        assert.equal(decoded.reason, "bad_encoding", id + ": reason");
        assert.equal(text(expect, "reason", id), "bad_encoding", id + ": expected reason");
      }
    } else {
      assert.fail(id + ": unknown kind " + kind);
    }
    pass += 1;
  }

  printSummary("header-encoding", pass);
  assert.equal(pass, 51, "header-encoding pass count");
});
