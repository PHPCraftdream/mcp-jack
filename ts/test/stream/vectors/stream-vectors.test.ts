/**
 * Runner for the client-verification corpus of signed streams (spec 05
 * section 9, `spec/fixtures/modern/stream-vectors.json`, 80 cases). Every case
 * is verified with the real SDK (`verifySignedStream`, sections 4.1-4.7 and
 * 6.3) and the fixture's messages, terminal and `mcp_complete` must match under
 * all three chunkings of the same body: whole body, one byte per chunk, and one
 * chunk per SSE event. A case that any chunking cannot reproduce fails the
 * test with its id, the chunking name, `got` and `want`; nothing is skipped or
 * excluded.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64URL } from "../../../src/core/encoding.js";
import { verifySignedStream } from "../../../src/stream/verify.js";
import type { StreamServerKey, StreamVerifyOptions, StreamVerifyResult } from "../../../src/stream/verify.js";
import {
  decodeStreamCorpus,
  expandExpectedMessages,
  expandStreamBody,
  fixture,
  normalizeResult,
  printSummary,
  streamChunkings,
} from "./support.js";
import type { StreamChunking, StreamVectorCase, StreamVectorResult } from "./support.js";

/** One SDK run, including the optional 6.3 completion flag. */
type CaseResult = StreamVerifyResult & { readonly mcpComplete?: boolean };

/** The corpus size of the CASES.md "streams" table for `stream-vectors.json`. */
const CASE_COUNT = 80;

/**
 * The per-frame clock of section 4.3 and `StreamVerifyOptions.now`: the first
 * call is the open header's single sample (`state.now`), every later call is
 * the next `state.frame_nows` sample, the last value repeating. Without
 * `frame_nows` every sample is `state.now`.
 */
function frameClock(c: StreamVectorCase): () => number {
  const state = c.state;
  let calls = 0;
  return () => {
    const call = calls;
    calls += 1;
    if (call === 0 || state.frameNowSamples.length === 0) {
      return state.now;
    }
    const index = Math.min(call - 1, state.frameNowSamples.length - 1);
    return state.frameNowSamples[index] ?? state.now;
  };
}

/** Verifies one case under one chunking with the fixture's state and the real SDK. */
function runCase(c: StreamVectorCase, chunking: StreamChunking): CaseResult {
  const state = c.state;
  const resolveKey = (kid: string): StreamServerKey | undefined => {
    if (kid !== state.pinnedServerKid) {
      return undefined;
    }
    return {
      kid,
      publicKey: decodeBase64URL(state.pinnedServerPublicKey),
      ...(state.successorActivation !== null ? { successorActivation: state.successorActivation } : {}),
    };
  };
  const options: StreamVerifyOptions = {
    resolveKey,
    now: frameClock(c),
    requestSig: state.requestSig,
    windowSeconds: state.windowSeconds,
    frameMaxBytes: state.frameMaxBytes,
    ...(state.streamIdleMs !== undefined ? { streamIdleMs: state.streamIdleMs } : {}),
    ...(c.consumer !== undefined ? { consumer: c.consumer } : {}),
  };
  return verifySignedStream({
    status: c.response.status,
    headers: c.response.headers,
    chunks: chunking.chunks,
    ...options,
    ...(c.silentAfterMs !== undefined ? { silentAfterMs: c.silentAfterMs } : {}),
    requestId: state.requestId,
  });
}

/** Fails with the case id, the chunking name, the normalised got and the fixture want. */
function assertMatchesFixture(got: CaseResult, want: StreamVectorResult, id: string, chunking: string): void {
  const normalized = normalizeResult(got);
  if (JSON.stringify(normalized) !== JSON.stringify(want)) {
    assert.fail(id + " [" + chunking + "]: got " + JSON.stringify(normalized) + " want " + JSON.stringify(want));
  }
}

test("stream vectors: every case in three chunkings", { timeout: 30_000 }, () => {
  const what = "stream-vectors.json";
  const cases = decodeStreamCorpus(fixture("modern/" + what));
  assert.equal(cases.length, CASE_COUNT, what + " case count");
  const ids = new Set<string>();
  for (const c of cases) {
    assert.ok(!ids.has(c.id), what + ": duplicate id " + c.id);
    assert.ok(c.id.startsWith("stream-"), c.id + ": id must start with stream-");
    ids.add(c.id);
  }
  // The CASES.md "Client verification" table lists one row per client case.
  assert.equal(ids.size, CASE_COUNT, what + ": unique ids must match the " + CASE_COUNT + "-row CASES.md table");

  let pass = 0;
  for (const c of cases) {
    const want: StreamVectorResult = {
      messages: expandExpectedMessages(c.expect.messages),
      terminal: c.expect.terminal,
    };
    const body = expandStreamBody(c);
    let first: StreamVectorResult | undefined;
    let firstName = "";
    for (const chunking of streamChunkings(body)) {
      const got = runCase(c, chunking);
      assertMatchesFixture(got, want, c.id, chunking.name);
      if (c.expect.mcpComplete !== undefined) {
        assert.equal(
          got.mcpComplete,
          c.expect.mcpComplete,
          c.id + " [" + chunking.name + "]: mcp_complete got " + String(got.mcpComplete)
            + " want " + String(c.expect.mcpComplete),
        );
      }
      const normalized = normalizeResult(got);
      if (first === undefined) {
        first = normalized;
        firstName = chunking.name;
      } else if (JSON.stringify(normalized) !== JSON.stringify(first)) {
        assert.fail(
          c.id + ": chunkings disagree: " + firstName + " got " + JSON.stringify(first)
            + ", " + chunking.name + " got " + JSON.stringify(normalized),
        );
      }
    }
    pass += 1;
  }

  assert.equal(pass, CASE_COUNT, "stream pass count");
  printSummary("stream", pass);
});
