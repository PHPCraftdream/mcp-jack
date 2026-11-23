import assert from "node:assert/strict";
import { test } from "node:test";
import { HardenedTransport } from "../../../src/webhook/ssrf/client.js";
import type { HardenedDialTarget, HardenedRequest, HardenedResponse } from "../../../src/webhook/ssrf/client.js";
import { EndpointVerifier, VerificationCache, VerificationConfigurationError } from "../../../src/webhook/verification/routes.js";
import type { VerificationTransport } from "../../../src/webhook/verification/routes.js";
import { utf8 } from "../support/vectors.js";

const NOW = 1767225600;
const PAIR = { principal: "alice", canonicalUrl: "https://hooks.example.test/hooks/alice" };
const NONCE = "KfROIaIYzOA4LouilLN_Jw";
const now = () => NOW;

function recordingTransport(answer: (request: HardenedRequest) => HardenedResponse) {
  const seen: { target: HardenedDialTarget; request: HardenedRequest }[] = [];
  const transport = new HardenedTransport({
    resolver: { async resolve() { return ["93.184.216.34"]; } },
    dialer: async (target, request) => {
      seen.push({ target, request });
      return answer(request);
    },
  });
  return { transport, seen };
}

function response(status: number, body = ""): HardenedResponse {
  return { status, headers: {}, body: utf8(body) };
}

test("endpoint verifier rejects malformed dependencies at construction", () => {
  const valid: VerificationTransport = {
    async request() { return { ok: false, code: "connection_refused" }; },
  };
  const invalid = {
    "missing transport": {},
    "null transport": { transport: null },
    "missing request": { transport: {} },
    "non-callable request": { transport: { request: 42 } },
    "non-string allowlist entry": { transport: valid, allowlist: ["https://ok.test", 1] },
    "non-callable hook": { transport: valid, hook: 1 },
    "non-callable nonce source": { transport: valid, nonceSource: "x" },
    "invalid cache": { transport: valid, cache: {} },
    "invalid challenge store": { transport: valid, challenges: { issue: () => {} } },
    "invalid document cache": { transport: valid, documents: { get: () => undefined } },
  };
  for (const [label, deps] of Object.entries(invalid)) {
    assert.throws(() => new EndpointVerifier(deps as never), VerificationConfigurationError, label);
  }
});

test("a challenge signer cannot redirect the POST or cache a mismatched echo", async () => {
  const wrongEcho = JSON.stringify({ challenge: "A".repeat(22) });
  const { transport, seen } = recordingTransport((request) => response(request.method === "GET" ? 404 : 200, wrongEcho));
  const submittedPosts: { url: string; path: string }[] = [];
  const recordingVerifierTransport: VerificationTransport = {
    request(url, request) {
      // HardenedTransport derives the dialed path again, so capture what the verifier supplied too.
      if (request.method === "POST") submittedPosts.push({ url, path: request.path });
      return transport.request(url, request);
    },
  };
  const cache = new VerificationCache({ now });
  const verifier = new EndpointVerifier({ transport: recordingVerifierTransport, cache, now, nonceSource: () => NONCE });
  const result = await verifier.verify(PAIR, NOW + 300, {
    challenge: () => ({ headers: {}, url: "https://evil.example.test/x", path: "/evil" } as never),
  });
  assert.deepEqual(result, { verified: false, route: null, reason: "mismatch" });
  assert.deepEqual(await verifier.verify(PAIR, NOW + 300), { verified: false, route: null, reason: "no_route" });
  assert.deepEqual(submittedPosts, [{ url: PAIR.canonicalUrl, path: "/hooks/alice" }]);
  const posts = seen.filter(({ request }) => request.method === "POST");
  assert.deepEqual(posts.map(({ target, request }) => ({ host: target.hostHeader, path: request.path })), [
    { host: "hooks.example.test", path: "/hooks/alice" },
  ]);
});

test("malformed challenge signer results fail closed without a POST", async () => {
  const invalid = {
    "missing headers": {},
    "non-string header value": { headers: { "x-mcp": 1 } },
    "null result": null,
  };
  for (const [label, signed] of Object.entries(invalid)) {
    const { transport, seen } = recordingTransport(() => response(404));
    const verifier = new EndpointVerifier({ transport, now, nonceSource: () => NONCE });
    const result = await verifier.verify(PAIR, NOW + 300, { challenge: () => signed as never });
    assert.deepEqual(result, { verified: false, route: null, reason: "challenge_failed" }, label);
    assert.deepEqual(seen.filter(({ request }) => request.method === "POST"), [], label);
  }
});

test("a correct challenge echo verifies and caches only the challenged pair", async () => {
  const { transport } = recordingTransport((request) => request.method === "POST" && request.path === "/hooks/alice"
    ? response(200, JSON.stringify({ challenge: NONCE }))
    : response(404));
  const cache = new VerificationCache({ now });
  const verifier = new EndpointVerifier({ transport, cache, now, nonceSource: () => NONCE });
  const result = await verifier.verify(PAIR, NOW + 300, { challenge: () => ({ headers: {} }) });
  assert.deepEqual(result, { verified: true, route: "challenge", reason: null });
  assert.deepEqual(await verifier.verify(PAIR, NOW + 300), { verified: true, route: "cache", reason: null });
  assert.deepEqual(await verifier.verify({ principal: "bob", canonicalUrl: PAIR.canonicalUrl }, NOW + 300), {
    verified: false,
    route: null,
    reason: "no_route",
  });
});
