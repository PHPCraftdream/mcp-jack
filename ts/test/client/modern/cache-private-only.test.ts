/**
 * Spec 04 C8: the private result cache never shares a verified result with
 * anything but the exact request it answered. The exemption asserted here is
 * that the cache is private to one ModernClient and one request signature, so
 * a cached entry can never answer a different request, another client, or a
 * foreign-signed response.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ModernClient, PrivateResultCache, resultCacheKey } from "../../../src/client/modern.js";
import { Code, JackError } from "../../../src/core/errors.js";
import type { RequestAuth } from "../../../src/core/auth-header.js";
import type { JsonValue, SignedReply } from "../../../src/client/rpc.js";
import { replyHeaders } from "../../../src/client/rpc.js";
import { bodyOf, newModernClient, newModernServer, rpcResult } from "./support.js";
import type { ModernServer, RecordedRequest } from "./support.js";

/** howManyCalls counts the `tools/call` requests the fake server received (a modern call also reads the catalog once per client). */
function howManyCalls(server: ModernServer): number {
  return server.requests.filter((req) => bodyOf(req)["method"] === "tools/call").length;
}

/** The JSON-RPC id of one recorded request, 1 when it is not a number. */
function idOf(req: RecordedRequest): number {
  const id = bodyOf(req)["id"];
  return typeof id === "number" ? id : 1;
}

test("client_cache_private_only", async () => {
  // 1. A server whose tools/call answers carry a private-cache hint (ttlMs
  // 60000) plus a public cacheScope that must not widen the cache.
  const server = newModernServer();
  let ttlMs = 60000;
  server.handle = (req) => {
    const body = bodyOf(req);
    if (body["method"] === "tools/list") {
      // An empty catalog: no tool is annotated, so no Mcp-Param-* header is projected.
      return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    }
    const result: JsonValue = { structuredContent: { area: 1 }, ttlMs, cacheScope: "public" };
    return server.sign(200, req.auth, rpcResult(idOf(req), result));
  };
  const client = newModernClient(server, "modern");
  const mc = new ModernClient(client, { cacheResults: true });

  // 2. The same request twice: the second answer comes from the private cache.
  const first = await mc.call("tools/call", { name: "svc.status" });
  const second = await mc.call("tools/call", { name: "svc.status" });
  assert.deepEqual(first, { area: 1 }, "cache: the first call returns the structured content");
  assert.deepEqual(second, { area: 1 }, "cache: the cached call returns the same value");
  assert.equal(howManyCalls(server), 1, "cache: the same request is reused within ttl");

  // 2b. Defensive copies on both sides: mutating a served value changes neither
  // the stored entry nor the value a later lookup returns.
  (first as { area: number }).area = 99;
  const third = await mc.call("tools/call", { name: "svc.status" });
  assert.deepEqual(third, { area: 1 }, "cache: a mutated served value does not change what the cache returns next");
  assert.equal(howManyCalls(server), 1, "cache: the mutated value is still a cache hit");
  (third as { area: number }).area = 7;
  assert.deepEqual(await mc.call("tools/call", { name: "svc.status" }), { area: 1 }, "cache: a mutation of a cache hit is not stored");

  // 3. C8: a different request is a different key and reaches the server.
  const other = await mc.call("tools/call", { name: "svc.other" });
  assert.deepEqual(other, { area: 1 }, "cache: a different request is answered by the server");
  assert.equal(howManyCalls(server), 2, "cache: a different request is not served from the cache");

  // 4. ttlMs: 0 is never reused, so both calls reach the server.
  ttlMs = 0;
  await mc.call("tools/call", { name: "svc.zero" });
  await mc.call("tools/call", { name: "svc.zero" });
  assert.equal(howManyCalls(server), 4, "cache: a zero ttl answer is never reused");
  ttlMs = 60000;

  // 5. Two ModernClients over the SAME Client own separate caches.
  const mc2 = new ModernClient(client, { cacheResults: true });
  const fromSecond = await mc2.call("tools/call", { name: "svc.status" });
  assert.deepEqual(fromSecond, { area: 1 }, "cache: the second client returns the structured content");
  assert.equal(howManyCalls(server), 5, "cache: two clients over one transport do not share a cache");

  // 6. A response bound to another request's signature is refused, never cached.
  const attackServer = newModernServer();
  let firstAuth: RequestAuth | null = null;
  let callSeq = 0;
  attackServer.handle = (req) => {
    const body = bodyOf(req);
    if (body["method"] === "tools/list") {
      return attackServer.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    }
    callSeq++;
    if (callSeq === 1) {
      // The first answer is bound to its own request and is cached.
      firstAuth = req.auth;
      return attackServer.sign(200, req.auth, rpcResult(idOf(req), { structuredContent: { area: 1 }, ttlMs: 60000 }));
    }
    if (firstAuth === null) {
      throw new Error("cache test: no first request to replay");
    }
    // The attacker signs a DIFFERENT answer over the FIRST request's signature.
    return attackServer.sign(200, firstAuth, rpcResult(idOf(req), { structuredContent: { area: 2 }, ttlMs: 60000 }));
  };
  const attackClient = new ModernClient(newModernClient(attackServer, "modern"), { cacheResults: true });
  const cachedFirst = await attackClient.call("tools/call", { name: "svc.status" });
  assert.deepEqual(cachedFirst, { area: 1 }, "cache: the first answer of the fresh server is cached");
  await assert.rejects(
    () => attackClient.call("tools/call", { name: "svc.foreign" }),
    (err: unknown): boolean => err instanceof JackError && err.code === Code.BAD_SIGNATURE,
    "cache: a response signed over another request is rejected",
  );
  assert.equal(howManyCalls(attackServer), 2, "cache: the foreign-signed request is sent and refused");

  // 7. PrivateResultCache unit edges.
  let now = 0;
  const unit = new PrivateResultCache(() => now);
  unit.put("unit", { area: 1 }, 0);
  assert.equal(unit.get("unit"), undefined, "cache: a zero ttl stores nothing");
  unit.put("unit", { area: 1 }, -1);
  assert.equal(unit.get("unit"), undefined, "cache: a negative ttl stores nothing");
  unit.put("unit", { area: 1 }, Number.POSITIVE_INFINITY);
  assert.equal(unit.get("unit"), undefined, "cache: a non-finite ttl stores nothing");
  unit.put("unit", { area: 1 }, Number.NaN);
  assert.equal(unit.get("unit"), undefined, "cache: a NaN ttl stores nothing");

  unit.put("unit", { area: 1 }, 1000);
  now = 999;
  assert.deepEqual(unit.get("unit"), { area: 1 }, "cache: an entry is served before its deadline");
  now = 1000;
  assert.equal(unit.get("unit"), undefined, "cache: an entry expires exactly at its deadline");

  now = 0;
  unit.put("unit", { area: 1 }, 1000);
  unit.clear();
  assert.equal(unit.get("unit"), undefined, "cache: clear drops every entry");

  const key = resultCacheKey("tools/call", '{"name":"svc.status"}', "modern", "2026-07-28");
  assert.notEqual(resultCacheKey("tools/other", '{"name":"svc.status"}', "modern", "2026-07-28"), key, "cache: the key differs for a different method");
  assert.notEqual(resultCacheKey("tools/call", '{"name":"svc.other"}', "modern", "2026-07-28"), key, "cache: the key differs for different params text");
  assert.notEqual(resultCacheKey("tools/call", '{"name":"svc.status"}', "legacy", "2026-07-28"), key, "cache: the key differs for a different era");
  const otherVersionKey = resultCacheKey("tools/call", '{"name":"svc.status"}', "modern", "2025-11-25");
  assert.notEqual(otherVersionKey, key, "cache: the key differs for a different negotiated version");

  // A value stored under one version is never served for a key built under
  // another version, even with the same method and params text.
  const versions = new PrivateResultCache(() => 0);
  versions.put(key, { area: 1 }, 60000);
  assert.deepEqual(versions.get(key), { area: 1 }, "cache: the entry is served under its own version");
  assert.equal(versions.get(otherVersionKey), undefined, "cache: an entry is not served under another negotiated version");

  // The store and the load both copy: a mutation through either side is invisible.
  const source = { area: 1 };
  versions.put(key, source, 60000);
  source.area = 42;
  assert.deepEqual(versions.get(key), { area: 1 }, "cache: the stored value is a copy of the caller's value");
  const served = versions.get(key) as { area: number };
  served.area = 43;
  assert.deepEqual(versions.get(key), { area: 1 }, "cache: each load returns its own copy");
});

test("client_result_cache_key_without_version", () => {
  // An existing 3-argument caller must keep compiling and keep a stable key:
  // the omitted version is the empty one, so that call keeps the
  // version-agnostic key of its era, method and params.
  const key = resultCacheKey("tools/call", '{"name":"svc.status"}', "modern");
  assert.equal(
    key,
    "modern" + "\u0000" + "tools/call" + "\u0000" + "" + "\u0000" + '{"name":"svc.status"}',
    "cache: a 3-argument key uses the empty version",
  );
  assert.notEqual(
    resultCacheKey("tools/call", '{"name":"svc.status"}', "modern", "2026-07-28"),
    key,
    "cache: a negotiated version keys a different entry than the version-agnostic one",
  );
});

test("client_reply_headers_absent", () => {
  // A caller-built reply must not need a header list: an absent one reads as
  // no headers, so a test double compiles without inventing header pairs.
  const withoutHeaders: SignedReply = { status: 200, bodyText: "{}", json: {} };
  assert.deepEqual(replyHeaders(withoutHeaders), [], "reply: an absent header list reads as no headers");

  const pairs = [
    ["content-type", "application/json"],
    ["mcp-session-id", "session-1"],
  ] as const;
  const withHeaders: SignedReply = { status: 200, bodyText: "{}", json: {}, headers: pairs };
  assert.deepEqual(replyHeaders(withHeaders), pairs, "reply: the present header pairs are returned as given");
});
