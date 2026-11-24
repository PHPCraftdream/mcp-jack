import assert from "node:assert/strict";
import { test } from "node:test";
import { seedSignerByName, fixtureNow } from "../support/client-harness.js";
import { fixture } from "../support/fixtures/index.js";
import { StreamSigner } from "../../src/stream/signer.js";
import { STREAM_CLIENT_CODES, StreamVerifyError } from "../../src/stream/codes.js";
import { verifySignedStream } from "../../src/stream/verify.js";
import { corpus, mutateBytes, random, runProperty, settings } from "./helper.js";

const allowed = new Set<string>(STREAM_CLIENT_CODES);

test("fuzz signed stream bodies", () => {
  const { seed, iterations } = settings();
  const next = random(seed);
  const signerKey = seedSignerByName("svc");
  const requestSig = "request-signature";
  const signer = new StreamSigner({ key: signerKey, requestSig, sid: "q9nUNYuH-Xf_cgJBVu4_Dg", openerTs: fixtureNow });
  const validPayload = '{"jsonrpc":"2.0","id":1,"result":{}}';
  const valid = Uint8Array.from([...signer.frame(validPayload, fixtureNow).bytes, ...signer.end(fixtureNow).bytes]);
  const knownValidMessages = [validPayload];
  const boundaries = corpus("stream-boundaries.json") as { bodies: string[] };
  const vectors = fixture("modern/stream-vectors.json") as { cases?: { response?: { stream_b64u?: string[] } }[] };
  const vectorBodies = (vectors.cases ?? []).flatMap((entry) => {
    const firstChunk = entry.response?.stream_b64u?.[0];
    return typeof firstChunk === "string" ? [Buffer.from(firstChunk, "base64url")] : [];
  });
  const sources = [valid, ...boundaries.bodies.map((v) => new TextEncoder().encode(v)), ...vectorBodies];
  for (let i = 0; i < iterations; i++) {
    const sourceIndex = i % sources.length;
    const source = sources[sourceIndex]!;
    const isVectorSource = sourceIndex >= 1 + boundaries.bodies.length;
    const input = mutateBytes(source, next);
    runProperty(seed, i, { hex: Buffer.from(input).toString("hex"), json: Buffer.from(input).toString("utf8") }, () => {
      const messages: string[] = [];
      let result: ReturnType<typeof verifySignedStream>;
      try {
        result = verifySignedStream({ status: 200, headers: [["Content-Type", "text/event-stream"], ["Jack-Auth", signer.openAuthValue()]], chunks: [{ bytes: input, arrivedAtMs: 1 }], resolveKey: (kid) => kid === signer.kid ? { kid, publicKey: signerKey.publicKey() } : undefined, now: () => fixtureNow, requestSig, onMessage: (m) => messages.push(m) });
      } catch (error) {
        assert.ok(error instanceof StreamVerifyError, `unexpected throw ${String(error)}`);
        assert.ok(allowed.has(error.code), `untyped stream code ${error.code}`);
        if (isVectorSource) assert.deepEqual(messages, []);
        return;
      }
      assert.ok(result.terminal.state === "ok" || allowed.has(result.terminal.code), `unknown terminal ${JSON.stringify(result.terminal)}`);
      if (isVectorSource) {
        assert.ok(result.terminal.state === "error" && allowed.has(result.terminal.code), `fixture stream did not fail with a client code: ${JSON.stringify(result.terminal)}`);
        assert.deepEqual(messages, []);
      }
      assert.deepEqual(messages, knownValidMessages.slice(0, messages.length));
      if (result.terminal.state === "error") assert.equal(result.terminal.framesVerified >= 0, true);
    }, input);
  }
  const chainSigner = new StreamSigner({ key: signerKey, requestSig, sid: "q9nUNYuH-Xf_cgJBVu4_Dg", openerTs: fixtureNow });
  const first = chainSigner.frame('{"jsonrpc":"2.0","id":1,"result":{"n":1}}', fixtureNow);
  const second = chainSigner.frame('{"jsonrpc":"2.0","id":2,"result":{"n":2}}', fixtureNow);
  const end = chainSigner.end(fixtureNow);
  const chainedBody = Uint8Array.from([...first.bytes, ...second.bytes, ...end.bytes]);
  const chainOptions = { status: 200, headers: [["Content-Type", "text/event-stream"], ["Jack-Auth", chainSigner.openAuthValue()]] as const, chunks: [{ bytes: chainedBody, arrivedAtMs: 1 }], resolveKey: (kid: string) => kid === chainSigner.kid ? { kid, publicKey: signerKey.publicKey() } : undefined, now: () => fixtureNow, requestSig };
  runProperty(seed, iterations, { messages: [first.seq, second.seq], end: end.seq, hex: Buffer.from(chainedBody).toString("hex") }, () => {
    assert.deepEqual([first.seq, second.seq, end.seq], [0, 1, 2]);
    const verified = verifySignedStream(chainOptions);
    assert.deepEqual(verified.messages, ['{"jsonrpc":"2.0","id":1,"result":{"n":1}}', '{"jsonrpc":"2.0","id":2,"result":{"n":2}}']);
    assert.deepEqual(verified.terminal, { state: "ok" });
  }, chainedBody);
  {
    const mutated = mutateBytes(chainedBody, next);
    const mutatedInput = { hex: Buffer.from(mutated).toString("hex"), json: Buffer.from(mutated).toString("utf8") };
    runProperty(seed, iterations + 1, mutatedInput, () => {
      const mutatedMessages: string[] = [];
      try {
        const result = verifySignedStream({ ...chainOptions, chunks: [{ bytes: mutated, arrivedAtMs: 1 }], onMessage: (message) => mutatedMessages.push(message) });
        assert.ok(result.terminal.state === "ok" || allowed.has(result.terminal.code));
      } catch (error) {
        assert.ok(error instanceof StreamVerifyError, `unexpected throw ${String(error)}`);
        assert.ok(allowed.has(error.code), `untyped stream code ${error.code}`);
      }
      assert.deepEqual(mutatedMessages, ["{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"n\":1}}", "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"n\":2}}"].slice(0, mutatedMessages.length));
    }, mutated);
  }
  const lfSigner = new StreamSigner({ key: signerKey, requestSig, sid: "q9nUNYuH-Xf_cgJBVu4_Dg", openerTs: fixtureNow });
  const lfBody = Uint8Array.from([...lfSigner.frame("{\n}", fixtureNow).bytes, ...lfSigner.end(fixtureNow).bytes]);
  const lfChunks = [{ bytes: lfBody, arrivedAtMs: 1 }];
  const common = { status: 200, headers: [["Content-Type", "text/event-stream"], ["Jack-Auth", lfSigner.openAuthValue()]] as const, chunks: lfChunks, resolveKey: (kid: string) => kid === lfSigner.kid ? { kid, publicKey: signerKey.publicKey() } : undefined, now: () => fixtureNow, requestSig };
  runProperty(seed, iterations + 2, "verified LF consumer split", () => {
    const mcp = verifySignedStream({ ...common, consumer: "mcp" });
    const stdio = verifySignedStream({ ...common, consumer: "stdio" });
    assert.equal(mcp.messages.length, 1);
    assert.deepEqual(stdio.messages, []);
    assert.ok(stdio.terminal.state === "error" && stdio.terminal.code === "stream_bad_frame");
  }, lfBody);
  const rawCr = new TextEncoder().encode("event: message\rdata: x\n\n");
  runProperty(seed, iterations + 3, { raw_cr_hex: Buffer.from(rawCr).toString("hex") }, () => {
    const rejected = verifySignedStream({ ...chainOptions, chunks: [{ bytes: rawCr, arrivedAtMs: 1 }] });
    assert.ok(rejected.terminal.state === "error" && allowed.has(rejected.terminal.code));
  }, rawCr);
});
