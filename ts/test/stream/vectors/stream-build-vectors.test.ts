/**
 * Runner for the server-signing known-answer corpus of signed streams (spec 05
 * section 9, `spec/fixtures/modern/stream-build-vectors.json`, 8 cases). Every
 * case is signed with the real SDK `StreamSigner` and the fixture `svc` key,
 * then compared field by field and byte for byte against the fixture body.
 * Every case with a derivable terminal (the fixture's `expect.terminal`, a
 * 2.18 signal frame, or a trailing 2.16 end frame) is also fed back through
 * the real client verifier (`verifySignedStream`).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { InMemorySigner } from "../../../src/client/signing/signer.js";
import { decodeBase64URL } from "../../../src/core/encoding.js";
import { StreamSigner } from "../../../src/stream/signer.js";
import type { SignedStreamFrame } from "../../../src/stream/signer.js";
import { verifySignedStream } from "../../../src/stream/verify.js";
import { streamSignalCode } from "../../../src/stream/wire.js";
import { loadKeys } from "../../support/fixtures/index.js";
import { decodeHexBytes, decodeStreamBuildCorpus, fixture, normalizeResult, printSummary } from "./support.js";
import type { StreamBuildCase, StreamVectorTerminal } from "./support.js";

/** The corpus size of the CASES.md "Server signing" table for `stream-build-vectors.json`. */
const CASE_COUNT = 8;

/** The `svc` fixture key; its seed signs and its kid/public key pin the open header and every frame (3.1). */
function svcKey(): { readonly seedHex: string; readonly publicKey: string; readonly kid: string } {
  const svc = loadKeys().keys.find((key) => key.name === "svc");
  if (svc === undefined) {
    throw new Error("keys.json: no key named svc");
  }
  return svc;
}

/** Concatenates the exact 2.6 wire bytes of the signed frames. */
function concatFrames(frames: readonly SignedStreamFrame[]): Uint8Array {
  let total = 0;
  for (const frame of frames) {
    total += frame.bytes.length;
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const frame of frames) {
    body.set(frame.bytes, offset);
    offset += frame.bytes.length;
  }
  return body;
}

/** Signs one case, checks every known answer, and returns the produced body. */
function signCase(c: StreamBuildCase, svc: ReturnType<typeof svcKey>): Uint8Array {
  const signer = new StreamSigner({
    key: new InMemorySigner(decodeHexBytes(svc.seedHex)),
    requestSig: c.input.requestSig,
    sid: c.input.sid,
    openerTs: c.input.openTs,
    status: c.input.status,
  });
  // 3.1 key discipline: the open header and every frame use the one fixture key.
  assert.equal(signer.kid, c.input.kid, c.id + ": signer kid");
  assert.equal(signer.openAuthValue(), c.expect.jackAuth, c.id + ": open Jack-Auth value");
  assert.equal(signer.openSigningString(), c.expect.openSigningString, c.id + ": open signing string");

  const signed: SignedStreamFrame[] = [];
  c.input.frames.forEach((frame, index) => {
    const out = frame.data === "" ? signer.end(frame.ts) : signer.frame(frame.data, frame.ts);
    const want = c.expect.frames[index];
    if (want === undefined) {
      throw new Error(c.id + ": expect.frames[" + index + "] is missing");
    }
    assert.equal(out.seq, want.seq, c.id + ": frames[" + index + "].seq");
    assert.equal(out.ts, want.ts, c.id + ": frames[" + index + "].ts");
    assert.equal(out.prev, want.prev, c.id + ": frames[" + index + "].prev");
    assert.equal(out.dataHash, want.dataHash, c.id + ": frames[" + index + "].data_hash");
    assert.equal(out.signingString, want.signingString, c.id + ": frames[" + index + "].signing_string");
    assert.equal(out.sig, want.sig, c.id + ": frames[" + index + "].sig");
    signed.push(out);
  });
  assert.equal(signed.length, c.expect.frames.length, c.id + ": signed frame count");

  const body = concatFrames(signed);
  assert.deepEqual(body, decodeBase64URL(c.expect.streamB64u), c.id + ": stream_b64u body bytes");
  return body;
}

/**
 * A per-frame clock for the end-to-end re-verification. 4.3 step 3 samples the
 * clock once per frame, and a long stream may live far past the window after the
 * open header, so the sample must follow the frame under verification: the first
 * call is the open header's single sample, call k >= 1 is `frames[k - 1].ts`, and
 * calls beyond the frame count repeat the last frame's ts.
 */
function perFrameClock(c: StreamBuildCase): () => number {
  const frames = c.input.frames;
  let calls = 0;
  return () => {
    const index = calls - 1;
    calls += 1;
    if (index < 0) {
      return c.input.openTs;
    }
    const frame = frames[Math.min(index, frames.length - 1)];
    return frame === undefined ? c.input.openTs : frame.ts;
  };
}

/**
 * The terminal the built body implies: the fixture's own `expect.terminal`
 * wins when present; else a 2.18 signal stops verification at 4.3 step 6 with
 * that code and the signal frame counted in `frames_verified`; else a trailing
 * 2.16 end frame verifies `ok`; else undefined, meaning no re-verification.
 */
function expectedTerminal(c: StreamBuildCase): StreamVectorTerminal | undefined {
  if (c.expect.terminal !== undefined) {
    return c.expect.terminal;
  }
  for (let index = 0; index < c.input.frames.length; index++) {
    const frame = c.input.frames[index];
    const code = frame === undefined ? null : streamSignalCode(frame.data);
    if (code !== null) {
      return { state: "error", code, frames_verified: index + 1 };
    }
  }
  const last = c.input.frames[c.input.frames.length - 1];
  if (last !== undefined && last.data === "") {
    return { state: "ok" };
  }
  return undefined;
}

/** The data values the MCP layer receives: non-empty, non-signal, truncated at a 2.18 signal. */
function deliveredMessages(c: StreamBuildCase): readonly string[] {
  const delivered: string[] = [];
  for (const frame of c.input.frames) {
    // 4.3 step 6: the signal frame verifies but is never delivered, and neither
    // is anything after it.
    if (streamSignalCode(frame.data) !== null) {
      break;
    }
    if (frame.data !== "") {
      delivered.push(frame.data);
    }
  }
  return delivered;
}

test("stream-build vectors: every case", () => {
  const what = "stream-build-vectors.json";
  const cases = decodeStreamBuildCorpus(fixture("modern/" + what));
  assert.equal(cases.length, CASE_COUNT, what + " case count");
  const ids = new Set<string>();
  for (const c of cases) {
    assert.ok(!ids.has(c.id), what + ": duplicate id " + c.id);
    assert.ok(c.id.startsWith("build-"), c.id + ": id must start with build-");
    ids.add(c.id);
  }
  assert.equal(ids.size, CASE_COUNT, what + ": unique ids");

  const svc = svcKey();
  let pass = 0;
  for (const c of cases) {
    const body = signCase(c, svc);
    // The expectation comes from the fixture's `expect.terminal` when present,
    // else from the input frames: a 2.18 signal is 4.3 step 6, a trailing end
    // frame is `ok`. Only `build-open` derives none: it has no input frame at
    // all, so there is no trailing 2.16 end frame and 4.4 would make the empty
    // body `stream_truncated`, so it is not re-verified.
    const want = expectedTerminal(c);
    if (want !== undefined) {
      const result = verifySignedStream({
        status: 200,
        headers: [["Content-Type", "text/event-stream"], ["Jack-Auth", c.expect.jackAuth]],
        chunks: body.length === 0 ? [] : [{ bytes: body, arrivedAtMs: 0 }],
        resolveKey: (kid) => (kid === svc.kid ? { kid, publicKey: decodeBase64URL(svc.publicKey) } : undefined),
        now: perFrameClock(c),
        requestSig: c.input.requestSig,
        windowSeconds: 30,
      });
      assert.deepEqual(normalizeResult(result).terminal, want, c.id + ": re-verified terminal");
      assert.deepEqual(result.messages, deliveredMessages(c), c.id + ": delivered messages");
    }
    pass += 1;
  }

  assert.equal(pass, CASE_COUNT, "stream-build pass count");
  printSummary("stream-build", pass);
});
