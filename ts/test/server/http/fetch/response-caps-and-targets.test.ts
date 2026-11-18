import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeBase64URL } from "../../../../src/core/encoding.js";
import { signRequest, randomNonce } from "../../../../src/client/signing/auth.js";
import { NonceStore } from "../../../../src/server/registry/nonce.js";
import { Verifier } from "../../../../src/server/verify.js";
import { jackFetchHandler, RAW_TARGET_SYMBOL } from "../../../../src/server/http/fetch.js";
import type { JackRequest, ResponseKeyProvider } from "../../../../src/server/http/fetch.js";
import type { RotationResponseKeyRequest } from "../../../../src/rotation/server/provider.js";
import { fixtureAud, fixtureNow } from "../../../support/client-harness.js";
import { utf8, newRegistryState, seedByName, newHarness, signedRequest, assertSigned, errorCode, aliceSigner, type Probe, probeStream, filled, UPSTREAM_HEADERS, answer, assertOverflow, empty, nonstandardNoBodyStatus, validationConfig } from "./support.js";

test("response cap: single chunk at cap-1, cap and cap+1", async () => {
  for (const size of [7, 8]) {
    const r = await answer(8, () => new Response(filled(size), { headers: UPSTREAM_HEADERS }));
    assert.equal(r.response.status, 200, `size ${size}`);
    const out = await assertSigned(r.response, r.harness.serverPub, r.sig);
    assert.deepEqual(out, filled(size));
  }
  await assertOverflow(await answer(8, () => new Response(filled(9), { headers: UPSTREAM_HEADERS })));
});

test("response cap: multi-chunk body crossing the boundary in a later chunk", async () => {
  const ok = await answer(8, () => new Response(probeStream([filled(3), filled(5)], { pulls: 0, cancelled: false })));
  assert.equal(ok.response.status, 200);
  assert.deepEqual(await assertSigned(ok.response, ok.harness.serverPub, ok.sig), filled(8));

  const probe: Probe = { pulls: 0, cancelled: false };
  const over = await answer(8, () => new Response(probeStream([filled(3), filled(3), filled(3)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(over);
});

test("response cap: exactly-cap answer keeps exact bytes, status, statusText and headers", async () => {
  const r = await answer(
    8,
    () => new Response("abcdefgh", { status: 201, statusText: "Created", headers: { ...UPSTREAM_HEADERS, "content-length": "8" } }),
  );
  assert.equal(r.response.status, 201);
  assert.equal(r.response.statusText, "Created");
  assert.equal(r.response.headers.get("content-type"), "text/plain");
  assert.equal(r.response.headers.get("x-upstream"), "yes");
  assert.equal(r.response.headers.get("set-cookie"), "a=b");
  assert.equal(r.response.headers.get("content-length"), "8");
  const out = await assertSigned(r.response, r.harness.serverPub, r.sig);
  assert.equal(Buffer.from(out).toString("utf-8"), "abcdefgh");
});

test("response cap: overflow stops reading, cancels the source and never pulls later chunks", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([filled(4), filled(4), filled(4), filled(4), filled(4)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(r);
  // Pulls 1 and 2 fill the cap exactly, pull 3 crosses it; chunks 4 and 5 are never requested.
  assert.equal(probe.pulls, 3);
  assert.equal(probe.cancelled, true);
});

test("response cap: empty chunks interleaved with data at exactly the cap", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, filled(4), empty, empty, filled(4), empty], probe)));
  assert.equal(r.response.status, 200);
  assert.deepEqual(await assertSigned(r.response, r.harness.serverPub, r.sig), filled(8));
});

test("response cap: empty chunks interleaved with data crossing the cap", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, filled(4), empty, filled(5), filled(1)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(r);
  // Pulls: 1 empty, 2 data, 3 empty, 4 crossing chunk; the fifth chunk is never pulled.
  assert.equal(probe.pulls, 4);
  assert.equal(probe.cancelled, true);
});

test("response cap: a body of only empty chunks is a signed empty 200", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, empty, empty], probe)));
  assert.equal(r.response.status, 200);
  assert.equal((await assertSigned(r.response, r.harness.serverPub, r.sig)).length, 0);
});

test("response cap: default limit applies for undefined and 0", async () => {
  const limit = 1 << 20;
  for (const cfg of [undefined, 0]) {
    const ok = await answer(cfg, () => new Response(filled(limit)));
    assert.equal(ok.response.status, 200, `cfg ${String(cfg)}`);
    assert.equal((await assertSigned(ok.response, ok.harness.serverPub, ok.sig)).length, limit);
    await assertOverflow(await answer(cfg, () => new Response(filled(limit + 1), { headers: UPSTREAM_HEADERS })));
  }
});

test("response cap and request cap are independent", async () => {
  // A tiny request cap does not limit a large response.
  const big = await answer(undefined, () => new Response(filled(100)), 8);
  assert.equal(big.response.status, 200);
  assert.equal((await assertSigned(big.response, big.harness.serverPub, big.sig)).length, 100);

  // A tiny response cap does not limit a large request.
  const body = utf8('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + "x".repeat(200) + '"}}');
  const small = newHarness(undefined, async () => new Response(filled(8)), 8);
  const { request, sig } = signedRequest(aliceSigner(), "POST", "/mcp", body);
  const response = await small.handle(request);
  assert.equal(response.status, 200);
  assert.equal((await assertSigned(response, small.serverPub, sig)).length, 8);
  assert.equal(small.seen.body?.length, body.length);
});

test("response cap: invalid maxResponseBytes throws at construction", () => {
  const next = async (): Promise<Response> => new Response("");
  for (const bad of [NaN, Infinity, -Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "8"]) {
    assert.throws(
      () => jackFetchHandler({ ...validationConfig(), maxResponseBytes: bad as number }, next),
      Error,
      `maxResponseBytes ${String(bad)}`,
    );
  }
  for (const good of [undefined, 0, 1, 8, Number.MAX_SAFE_INTEGER]) {
    assert.doesNotThrow(() => jackFetchHandler({ ...validationConfig(), ...(good !== undefined ? { maxResponseBytes: good } : {}) }, next));
  }
});

test("maxBodyBytes: infinite or unsafe throws, legacy defaults stay", () => {
  const next = async (): Promise<Response> => new Response("");
  for (const bad of [Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => jackFetchHandler({ ...validationConfig(), maxBodyBytes: bad }, next), Error, `maxBodyBytes ${String(bad)}`);
  }
  for (const ok of [0, -1, NaN, -Infinity, 64, Number.MAX_SAFE_INTEGER]) {
    assert.doesNotThrow(() => jackFetchHandler({ ...validationConfig(), maxBodyBytes: ok }, next));
  }
});

test("response cap: an event stream larger than the cap stays 501 and is cancelled unread", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(
    8,
    () => new Response(probeStream([filled(64), filled(64)], probe), { headers: { "content-type": "text/event-stream; charset=utf-8" } }),
  );
  assert.equal(r.response.status, 501);
  assert.equal(errorCode(await assertSigned(r.response, r.harness.serverPub, r.sig)), "streaming_unsupported");
  assert.equal(probe.cancelled, true);
  assert.equal(probe.pulls, 0);
});

test("response cap: a read error mid-body still rejects the handler promise", async () => {
  let pulls = 0;
  const failing = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls += 1;
        if (pulls === 1) {
          controller.enqueue(filled(2));
          return;
        }
        controller.error(new Error("upstream broke"));
      },
    },
    { highWaterMark: 0 },
  );
  const harness = newHarness(undefined, async () => new Response(failing), 8);
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  await assert.rejects(harness.handle(request), /upstream broke/);
});

test("response cap: a non-Uint8Array chunk rejects with TypeError", async () => {
  const bad = new ReadableStream<unknown>({
    start(controller) {
      controller.enqueue("text");
    },
  }) as ReadableStream<Uint8Array>;
  const harness = newHarness(undefined, async () => new Response(bad));
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  await assert.rejects(harness.handle(request), TypeError);
});

test("response cap: null and empty bodies are signed 200 with no bytes", async () => {
  for (const make of [() => new Response(null), () => new Response("")]) {
    const r = await answer(8, make);
    assert.equal(r.response.status, 200);
    assert.equal((await assertSigned(r.response, r.harness.serverPub, r.sig)).length, 0);
  }
});

// Spec 01 section 5 binds the signature to the exact transmitted bytes; Fetch drops
// bodies for these statuses, so the signature input and declared length must be empty.
test("no-body statuses sign and return only transmitted bytes on static and rotation profiles", async () => {
  for (const status of [204, 205, 304] as const) {
    for (const withUpstreamBody of [false, true]) {
      const expectedUpstreamBytes = withUpstreamBody ? utf8(`upstream-${status}`) : new Uint8Array(0);
      let observedUpstreamBytes: Uint8Array | undefined;
      const next = (): Response => {
        const upstream = nonstandardNoBodyStatus(status, withUpstreamBody);
        observedUpstreamBytes = upstream.upstreamBytes;
        return upstream.response;
      };
      const r = await answer(undefined, next);
      assert.equal(r.response.status, status);
      assert.equal(r.response.headers.get("content-length"), "0");
      if (withUpstreamBody) {
        assert.ok(observedUpstreamBytes !== undefined && observedUpstreamBytes.length > 0, "nonstandard upstream body must be present");
        assert.deepEqual(observedUpstreamBytes, expectedUpstreamBytes);
      }
      assert.equal(r.response.body, null);
      assert.deepEqual(await assertSigned(r.response, r.harness.serverPub, r.sig), new Uint8Array(0));
    }
  }

  const server = seedByName("svc").signer;
  for (const status of [204, 205, 304] as const) {
    for (const withUpstreamBody of [false, true]) {
      const requested: RotationResponseKeyRequest[] = [];
      const provider: ResponseKeyProvider = {
        authorizeResponse(input) {
          requested.push({ ...input, body: Uint8Array.from(input.body) });
          return {
            signer: {
              publicKeyB64u: encodeBase64URL(server.publicKey()),
              publicKey: () => server.publicKey(),
              sign: (message: Uint8Array) => server.sign(message),
            },
            timestamp: fixtureNow,
            final: (): void => {},
            release: (): void => {},
          };
        },
      };
      const verifier = new Verifier({
        aud: fixtureAud,
        state: newRegistryState(),
        nonces: new NonceStore(),
        now: () => fixtureNow,
      });
      const handle = jackFetchHandler({ verifier, rotationKeys: provider }, async () => {
        const upstream = nonstandardNoBodyStatus(status, withUpstreamBody);
        assert.equal(upstream.upstreamBytes.length > 0, withUpstreamBody, "upstream body setup matches this case");
        return upstream.response;
      });
      const { request, sig } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
      const response = await handle(request);
      assert.equal(response.status, status);
      assert.equal(response.headers.get("content-length"), "0");
      assert.equal(response.body, null);
      assert.deepEqual(await assertSigned(response, server.publicKey(), sig), new Uint8Array(0));
      assert.equal(requested.length, 1);
      assert.equal(requested[0]?.status, status);
      assert.deepEqual(requested[0]?.body, new Uint8Array(0), "rotation authorization receives the transmitted body bytes");
    }
  }
});

test("response cap: a throwing next is still an unsigned 500", async () => {
  const harness = newHarness(undefined, async () => {
    throw new Error("boom");
  }, 8);
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  const response = await harness.handle(request);
  assert.equal(response.status, 500);
  assert.equal(response.headers.get("jack-auth"), null);
});

test("fetch adapter drops a fragment and verifies over the target before it", async () => {
  const harness = newHarness(undefined, async () => new Response("{}", { headers: { "content-type": "application/json" } }));
  const header = signRequest(aliceSigner(), fixtureAud, "GET", "/mcp?q=1", new Uint8Array(0), randomNonce(), fixtureNow);
  const response = await harness.handle(new Request("http://localhost/mcp?q=1#frag", { headers: { "jack-auth": header } }));
  assert.equal(response.status, 200);
  assert.equal(harness.seen.calls, 1);
});

test("fetch adapter refuses non-origin-form raw targets from the symbol", async () => {
  const harness = newHarness(undefined, async () => new Response("nope"));
  for (const raw of ["http://example.com/mcp", "*", "example.com:80", "/a b"]) {
    const request = new Request("http://localhost/mcp");
    (request as JackRequest)[RAW_TARGET_SYMBOL] = raw;
    const response = await harness.handle(request);
    assert.equal(response.status, 400, raw);
    assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "invalid_request", raw);
  }
  assert.equal(harness.seen.calls, 0);
});

test("fetch adapter accepts a percent-encoded non-ASCII target", async () => {
  const harness = newHarness(undefined, async () => new Response("{}", { headers: { "content-type": "application/json" } }));
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp?q=%C3%A9", new Uint8Array(0));
  const response = await harness.handle(request);
  assert.equal(response.status, 200);
});

test("fetch adapter answers malformed_auth for two Jack-Auth lines", async () => {
  const harness = newHarness(undefined, async () => new Response("nope"));
  const first = signRequest(aliceSigner(), fixtureAud, "GET", "/mcp", new Uint8Array(0), randomNonce(), fixtureNow);
  const second = signRequest(aliceSigner(), fixtureAud, "GET", "/mcp", new Uint8Array(0), randomNonce(), fixtureNow);
  const headers = new Headers();
  headers.append("jack-auth", first);
  headers.append("jack-auth", second);
  const response = await harness.handle(new Request("http://localhost/mcp", { headers }));
  assert.equal(response.status, 401);
  assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "malformed_auth");
  assert.equal(response.headers.get("jack-auth"), null);
  assert.equal(harness.seen.calls, 0);
});
