/**
 * Runner for the modern-profile request classification corpus of spec 04
 * section 8 (`spec/fixtures/modern/modern-request-vectors.json`, 98 cases plus
 * one by-reference entry) driven against the real SDK classifier
 * (`classifyModernRequest`, rules S1-S12) and its two refusal body builders.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifyModernRequest,
  envelopeBodyText,
  refusalBodyText,
  toolsCallNameInvalid,
} from "../../../src/modern/server.js";
import type { ServerProfile } from "../../../src/modern/server.js";
import { arrayOf, fixture, flag, headerPairs, modernFixture, printSummary, record, text, textList } from "./support.js";

/** Strips a leading `fixtures/` from a by-reference file name; `fixture()` resolves `spec/fixtures/<name>`. */
function fixtureNameOf(file: string): string {
  return file.startsWith("fixtures/") ? file.slice("fixtures/".length) : file;
}

test("modern-request vectors: every case", () => {
  const what = "modern-request-vectors.json";
  const corpus = record(modernFixture(what), what);
  const cases = arrayOf(corpus["cases"], what + ".cases");
  const byReference = arrayOf(corpus["by_reference"], what + ".by_reference");
  assert.equal(cases.length, 98, "modern-request-vectors.json case count");
  assert.equal(byReference.length, 1, "modern-request-vectors.json by-reference count");

  let pass = 0;
  for (const raw of cases) {
    const c = record(raw, "case");
    const id = text(c, "id", "case");
    const request = record(c["request"], id + ": request");
    const method = text(request, "method", id + ": request");
    const target = text(request, "target", id + ": request");
    const headers = headerPairs(request["headers"], id + ": request.headers");
    const bodyText = request["body_text"];
    const input = {
      profile: text(c, "profile", id) as ServerProfile,
      method,
      target,
      headers,
      ...(typeof bodyText === "string" ? { bodyText } : {}),
    };
    const expect = record(c["expect"], id + ": expect");
    const outcome = text(expect, "outcome", id + ": expect");
    const decision = classifyModernRequest(input);

    if (outcome === "forward") {
      if (decision.outcome !== "forward") {
        assert.fail(id + ": outcome: expected forward, got " + decision.outcome);
      } else {
        assert.equal(decision.era, text(expect, "era", id + ": expect"), id + ": era");
        const forward = record(expect["forward"], id + ": expect.forward");
        assert.equal(decision.forward.method, text(forward, "method", id + ": forward"), id + ": forward.method");
        assert.equal(decision.forward.target, text(forward, "target", id + ": forward"), id + ": forward.target");
        assert.deepEqual(
          decision.forward.headers.map(([name, value]) => [name, value]),
          headerPairs(forward["headers"], id + ": expect.forward.headers"),
          id + ": forward.headers",
        );
        assert.equal(flag(expect, "consumes_nonce", id + ": expect"), true, id + ": consumes_nonce");
      }
    } else if (outcome === "refuse") {
      if (decision.outcome !== "refuse") {
        assert.fail(id + ": outcome: expected refuse, got " + decision.outcome);
      } else {
        const error = record(expect["error"], id + ": expect.error");
        const httpStatus = expect["http_status"];
        const code = error["code"];
        const message = error["message"];
        const expectId = expect["id"];
        assert.equal(decision.era, "modern", id + ": era");
        assert.equal(decision.httpStatus, httpStatus, id + ": http_status");
        assert.equal(decision.code, code, id + ": error.code");
        assert.equal(decision.message, message, id + ": error.message");
        assert.equal(flag(expect, "signed", id + ": expect"), true, id + ": signed");
        assert.equal(text(expect, "content_type", id + ": expect"), "application/json", id + ": content_type");
        assert.deepEqual(JSON.parse(decision.idText) as unknown, expectId, id + ": refusal id echo");
        assert.equal(decision.allowPost, httpStatus === 405, id + ": allowPost");
        assert.deepEqual(
          JSON.parse(refusalBodyText(decision.idText, decision.code, decision.message)) as unknown,
          { jsonrpc: "2.0", id: expectId, error: { code, message } },
          id + ": S10 refusal wire body",
        );
      }
    } else if (outcome === "refuse_invalid_request") {
      if (decision.outcome !== "refuse_invalid_request") {
        assert.fail(id + ": outcome: expected refuse_invalid_request, got " + decision.outcome);
      } else {
        const error = record(expect["error"], id + ": expect.error");
        const message = error["message"];
        assert.equal(decision.httpStatus, 400, id + ": http_status");
        assert.equal(decision.code, "invalid_request", id + ": code");
        assert.equal(decision.message, message, id + ": message");
        assert.deepEqual(
          JSON.parse(envelopeBodyText(decision.code, decision.message)) as unknown,
          { error: { code: "invalid_request", message } },
          id + ": classification envelope body",
        );
        assert.equal(flag(expect, "signed", id + ": expect"), true, id + ": signed");
        assert.equal(
          toolsCallNameInvalid(typeof bodyText === "string" ? bodyText : undefined),
          true,
          id + ": toolsCallNameInvalid",
        );
      }
    } else {
      assert.fail("case " + id + ": unknown outcome " + outcome);
    }
    pass += 1;
  }

  const entry = record(byReference[0], what + ".by_reference[0]");
  const entryId = text(entry, "id", "by-reference");
  const file = text(entry, "file", "by-reference");
  const vectors = textList(entry["vectors"], "by-reference");
  assert.equal(entryId, "cache-replay", "by-reference id");
  assert.equal(file, "fixtures/response-vectors.json", "by-reference file");
  assert.deepEqual(vectors, ["res-wrong-request-binding", "res-accept"], "by-reference vectors");
  const responseFile = record(fixture(fixtureNameOf(file)), "response-vectors.json");
  const responseCases = arrayOf(responseFile["cases"], "response-vectors.json.cases");
  const responseIds = new Set(
    responseCases.map((responseCase) => text(record(responseCase, "response-vectors.json.cases"), "id", "response case")),
  );
  for (const vectorId of vectors) {
    assert.ok(responseIds.has(vectorId), "cache-replay: " + vectorId + " must exist in response-vectors.json");
  }
  assert.ok(responseIds.has("res-wrong-request-binding"), "cache-replay: res-wrong-request-binding must exist");
  assert.ok(responseIds.has("res-accept"), "cache-replay: res-accept must exist");

  printSummary("modern-request", pass);
  assert.equal(pass, 98, "modern-request pass count");
});
