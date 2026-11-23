/**
 * Adapter-level modern-profile tests (spec 04 sections 3, 5, 5.1): the era
 * decision, the mirror refusals and the S8 forwarding removals are judged
 * through jackFetchHandler, i.e. on exactly what the wrapped handler receives.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MODERN,
  assertSigned,
  errorCode,
  mirrorsFor,
  modernRequest,
  modernToolCallBody,
  newModernHarness,
  seedSignerByName,
  utf8,
} from "./support.js";
import type { ModernHarness } from "./support.js";
import { HEADER_VALUES_SYMBOL, RAW_BODY_SYMBOL } from "../../../src/server/http/fetch.js";
import type { JackRequest } from "../../../src/server/http/fetch.js";

/** The forwarded values of one header name (name compared case-insensitively). */
function forwarded(harness: ModernHarness, name: string): string[] {
  const headers = harness.seen.headers ?? [];
  return headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
}

test("modern profile: the default profile keeps a mirrored request legacy", async () => {
  // No profile option at all: the adapter's own default must be legacy, so no
  // section 5 rule runs even though every mirror header is present and wrong.
  const harness = newModernHarness(undefined);
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body,
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/list"],
      ["Mcp-Name", "svc.status"],
      ["Mcp-Session-Id", "sess-1"],
    ],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 200, "a mirrored legacy request is forwarded");
  const out = await assertSigned(response, harness.serverPub, sig);
  const parsed = JSON.parse(Buffer.from(out).toString("utf-8")) as { result: { ok: boolean } };
  assert.equal(parsed.result.ok, true, "the wrapped handler's answer is forwarded, not a refusal");
  assert.equal(harness.seen.calls, 1);
  assert.deepEqual(forwarded(harness, "mcp-session-id"), ["sess-1"], "legacy forwards the session header untouched");
});

test("modern profile: a valid modern request is forwarded with the session headers removed", async () => {
  const harness = newModernHarness("modern");
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body,
    headers: [
      ...mirrorsFor("tools/call", "svc.status"),
      ["Mcp-Session-Id", "sess-1"],
      ["Last-Event-ID", "7"],
      ["Mcp-Param-Region", "eu"],
    ],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1);
  assert.deepEqual(forwarded(harness, "mcp-session-id"), [], "S8 removes Mcp-Session-Id");
  assert.deepEqual(forwarded(harness, "last-event-id"), [], "S8 removes Last-Event-ID");
  assert.deepEqual(forwarded(harness, "mcp-param-region"), ["eu"], "S7 forwards Mcp-Param-* unchanged");
  assert.equal(forwarded(harness, "mcp-method")[0], "tools/call", "S9 forwards the mirrors unchanged");
});

test("modern profile: S5 refusal is a signed JSON-RPC error", async () => {
  const harness = newModernHarness("modern");
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body,
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Name", "svc.status"],
    ],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 400);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("allow"), null, "only the 405 refusal carries Allow");
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32020, message: "Header mismatch: Mcp-Method is missing" },
  });
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: S2 refuses a both-profile GET with a signed 405", async () => {
  const harness = newModernHarness("both");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    method: "GET",
    headers: [["MCP-Protocol-Version", MODERN]],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    jsonrpc: "2.0",
    id: null,
    error: { code: -32600, message: "HTTP method not allowed" },
  });
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: a both-profile GET without a modern signal stays legacy", async () => {
  const harness = newModernHarness("both");
  const { request, sig } = modernRequest(seedSignerByName("alice"), { method: "GET" });
  const response = await harness.handle(request);

  assert.equal(response.status, 200, "0.1.x accepts GET in the legacy era");
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1, "the GET is forwarded, not refused by S2");
});

test("modern profile: S2 refuses a modern-profile DELETE before the mirrors", async () => {
  const harness = newModernHarness("modern");
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    method: "DELETE",
    body,
    headers: [
      ["MCP-Protocol-Version", MODERN],
      // Wrong on purpose: S2 must refuse before S5 ever looks at it.
      ["Mcp-Method", "tools/list"],
      ["Mcp-Name", "svc.status"],
    ],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 405, "S2 runs before S5");
  assert.equal(response.headers.get("allow"), "POST");
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    jsonrpc: "2.0",
    id: null,
    error: { code: -32600, message: "HTTP method not allowed" },
  });
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: the classification refusal carries the fixed message", async () => {
  const harness = newModernHarness("modern");
  const body = utf8(
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{' +
      '"io.modelcontextprotocol/protocolVersion":"' +
      MODERN +
      '","io.modelcontextprotocol/clientCapabilities":{}}}}',
  );
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body,
    headers: mirrorsFor("tools/call", "svc.status"),
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 400);
  const out = await assertSigned(response, harness.serverPub, sig);
  // The 01 section 4 envelope: no jsonrpc member, no id member.
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    error: { code: "invalid_request", message: "tools/call requires a string params.name" },
  });
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: a refusal consumes the nonce", async () => {
  const harness = newModernHarness("modern");
  const body = modernToolCallBody("1", "svc.status");
  const first = modernRequest(seedSignerByName("alice"), {
    body,
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Name", "svc.status"],
    ],
  });
  const firstResponse = await harness.handle(first.request);
  assert.equal(firstResponse.status, 400);
  const firstBody = await assertSigned(firstResponse, harness.serverPub, first.sig);
  assert.deepEqual(JSON.parse(Buffer.from(firstBody).toString("utf-8")), {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32020, message: "Header mismatch: Mcp-Method is missing" },
  });

  // The same signed bytes again: the refusal above already recorded the nonce,
  // and there is no rollback (spec 04 S10).
  const jackAuth = first.request.headers.get("jack-auth");
  assert.ok(jackAuth !== null);
  const replay = new Request("http://localhost/mcp", {
    method: "POST",
    headers: [["jack-auth", jackAuth]],
    body,
  });
  const second = await harness.handle(replay);
  assert.equal(second.status, 401);
  assert.equal(second.headers.get("www-authenticate"), "Jack-Auth");
  assert.equal(second.headers.get("jack-auth"), null, "a replayed nonce has no nonce-recorded receipt");
  assert.equal(errorCode(new Uint8Array(await second.arrayBuffer())), "replayed_nonce");
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: the legacy profile ignores modern mirrors entirely", async () => {
  const harness = newModernHarness("legacy");
  // A signed _meta modern version with NO MCP-Protocol-Version header: under a
  // non-legacy profile this would be version_header_missing, but the legacy
  // profile runs no section 5 rule at all.
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), { body });
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1);
});

test("modern profile: a comma-joined single-valued mirror is a repeated instance", async () => {
  // A bare Fetch Request has already merged repeated lines with ", ". Because
  // MCP-Protocol-Version is single-valued, each comma-separated piece counts
  // as one instance: the era comes from the first piece (modern) and S1 then
  // refuses the repetition — a merged-that-stays-one reading would forward it
  // as a legacy request instead.
  const harness = newModernHarness("both");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    headers: [["MCP-Protocol-Version", "2026-07-28, 2025-11-25"]],
    body: utf8('{"jsonrpc":"2.0","id":1,"method":"tools/list"}'),
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 400);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(
    Buffer.from(out).toString("utf-8"),
    '{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: a request metadata header appears more than once"}}',
  );
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: a comma-joined Mcp-Method is a repeated instance", async () => {
  // Mcp-Method is single-valued too: the merged value is split, so S1 refuses
  // the repetition before S5 could compare the first piece with the body.
  const harness = newModernHarness("both");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/list, tools/call"],
    ],
    body: utf8(
      '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{' +
        '"io.modelcontextprotocol/protocolVersion":"' +
        MODERN +
        '","io.modelcontextprotocol/clientCapabilities":{}}}}',
    ),
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 400);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32020, message: "Header mismatch: a request metadata header appears more than once" },
  });
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: a comma in Mcp-Name stays one instance", async () => {
  // Mcp-Name may legitimately contain a comma, so its merged value is NOT
  // split: the single instance decodes to the body value and is forwarded.
  const harness = newModernHarness("modern");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body: modernToolCallBody("1", "a,b"),
    headers: mirrorsFor("tools/call", "a,b"),
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1);
});

test("modern profile: the wrapped handler sees the forwarded instances in order", async () => {
  const harness = newModernHarness("modern");
  const body = modernToolCallBody("1", "svc.status");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    body,
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/call"],
      ["Mcp-Name", "svc.status"],
      ["Mcp-Param-Region", "eu"],
      ["Mcp-Session-Id", "s"],
      ["Mcp-Param-Region", "us"],
    ],
  });
  // The node adapter hands the TRUE received instances over on the symbol (a
  // Headers object would have merged the two Mcp-Param-Region lines and
  // lowercased every name); this test uses the same handoff.
  const jackAuth = request.headers.get("jack-auth");
  assert.ok(jackAuth !== null);
  (request as JackRequest)[HEADER_VALUES_SYMBOL] = [
    ["jack-auth", jackAuth],
    ["MCP-Protocol-Version", MODERN],
    ["Mcp-Method", "tools/call"],
    ["Mcp-Name", "svc.status"],
    ["Mcp-Param-Region", "eu"],
    ["Mcp-Session-Id", "s"],
    ["Mcp-Param-Region", "us"],
  ];
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1);
  const raw = harness.seen.rawHeaders ?? [];
  const eu = raw.findIndex(([n, v]) => n === "Mcp-Param-Region" && v === "eu");
  const us = raw.findIndex(([n, v]) => n === "Mcp-Param-Region" && v === "us");
  assert.ok(eu >= 0, "the first instance is forwarded with its received casing");
  assert.ok(us > eu, "the second instance follows the first, in received order");
  assert.deepEqual(raw.filter(([n]) => n.toLowerCase() === "mcp-session-id"), [], "S8 removes Mcp-Session-Id");
});

test("modern profile: DELETE with a non-JSON body is a signed 405", async () => {
  // A non-POST body is never read or parsed: the non-JSON body cannot become a
  // classification refusal, and S2 answers the signed 405 with id null.
  const harness = newModernHarness("modern");
  const { request, sig } = modernRequest(seedSignerByName("alice"), {
    method: "DELETE",
    body: utf8("not json"),
    headers: [["MCP-Protocol-Version", MODERN]],
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(
    Buffer.from(out).toString("utf-8"),
    '{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"HTTP method not allowed"}}',
  );
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: PUT with a non-JSON body in the legacy era keeps the 0.1.x answer", async () => {
  // No modern signal at all under profile both: the adapter's own 0.1.x 405 is
  // unsigned and keeps the 01 section 4 envelope, whatever the body bytes are.
  const harness = newModernHarness("both");
  const { request } = modernRequest(seedSignerByName("alice"), { method: "PUT", body: utf8("not json") });
  const response = await harness.handle(request);

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("jack-auth"), null, "the adapter's own 405 is unsigned");
  assert.equal(response.headers.get("allow"), null);
  assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "method_not_allowed");
  assert.equal(harness.seen.calls, 0);
});

test("modern profile: GET with a body is a signed 405", async () => {
  // undici refuses a GET body, so the bytes travel on RAW_BODY_SYMBOL exactly
  // like the node adapter hands them over; the signature is taken from a
  // modernRequest call over the same method, target and bytes.
  const harness = newModernHarness("modern");
  const body = utf8("not json");
  const { request, sig } = modernRequest(seedSignerByName("alice"), { method: "GET", body });
  const jackAuth = request.headers.get("jack-auth");
  assert.ok(jackAuth !== null);
  const req = new Request("http://localhost/mcp", {
    method: "GET",
    headers: [
      ["jack-auth", jackAuth],
      ["MCP-Protocol-Version", MODERN],
    ],
  });
  (req as JackRequest)[RAW_BODY_SYMBOL] = body;
  const response = await harness.handle(req);

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.deepEqual(JSON.parse(Buffer.from(out).toString("utf-8")), {
    jsonrpc: "2.0",
    id: null,
    error: { code: -32600, message: "HTTP method not allowed" },
  });
  assert.equal(harness.seen.calls, 0);
});
