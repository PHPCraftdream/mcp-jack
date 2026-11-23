/**
 * Spec 04 C10: a `-32020` header refusal on a modern `tools/call` drops the
 * cached catalog, re-reads `tools/list` and retries the call exactly once, so
 * the retry projects the CURRENT `x-mcp-header` annotations instead of the ones
 * the client had read before the catalog moved.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ModernClient } from "../../../src/client/modern.js";
import type { JsonValue } from "../../../src/client/rpc.js";
import { bodyOf, headerValues, newModernClient, newModernServer, rpcError, rpcResult } from "./support.js";
import type { ModernServer, RecordedRequest } from "./support.js";

/** The label every assertion message of this case starts with. */
const CASE = "client_header_resync";

/** requestsOf returns the recorded requests whose body method is method, in arrival order. */
function requestsOf(server: ModernServer, method: string): RecordedRequest[] {
  return server.requests.filter((req) => bodyOf(req)["method"] === method);
}

/** The JSON-RPC id of one recorded request, 1 when it is not a number. */
function idOf(req: RecordedRequest): number {
  const id = bodyOf(req)["id"];
  return typeof id === "number" ? id : 1;
}

/** The `params._meta` member of one recorded request, or undefined when the request carries no `_meta` object. */
function metaOf(req: RecordedRequest): { readonly [key: string]: JsonValue } | undefined {
  const params = bodyOf(req)["params"];
  if (params === null || typeof params !== "object" || Array.isArray(params)) return undefined;
  const meta = params["_meta"];
  if (meta === null || typeof meta !== "object" || Array.isArray(meta)) return undefined;
  return meta;
}

/** The first catalog the server advertises: the region argument is the annotated header. */
const FIRST_CATALOG: JsonValue = {
  tools: [
    {
      name: "svc.status",
      inputSchema: {
        type: "object",
        properties: {
          region: { type: "string", "x-mcp-header": "Region" },
          tenant: { type: "string" },
        },
      },
    },
  ],
};

/** The moved catalog: the annotation is now on tenant and region carries none. */
const LATER_CATALOG: JsonValue = {
  tools: [
    {
      name: "svc.status",
      inputSchema: {
        type: "object",
        properties: {
          region: { type: "string" },
          tenant: { type: "string", "x-mcp-header": "Tenant" },
        },
      },
    },
  ],
};

test("client_header_resync", async () => {
  // 1. A server whose catalog moves the annotation from region to tenant after
  // the first read, and whose first call refuses the stale projection.
  const server = newModernServer();
  let catalogReads = 0;
  let calls = 0;
  server.handle = (req) => {
    const body = bodyOf(req);
    const id = idOf(req);
    if (body["method"] === "tools/list") {
      catalogReads++;
      return server.sign(200, req.auth, rpcResult(id, catalogReads === 1 ? FIRST_CATALOG : LATER_CATALOG));
    }
    calls++;
    if (calls === 1) {
      return server.sign(400, req.auth, rpcError(id, -32020, "Header mismatch: Mcp-Name is not a valid base64 sentinel encoding"));
    }
    return server.sign(200, req.auth, rpcResult(id, { structuredContent: { ok: true }, ttlMs: 0 }));
  };
  const mc = new ModernClient(newModernClient(server, "modern"));

  // 2. The call is refused once and answered on the single retry.
  const value = await mc.call("tools/call", { name: "svc.status", arguments: { region: "eu", tenant: "acme" } });
  assert.deepEqual(value, { ok: true }, CASE + ": the retried call returns the structured content");

  // 3. C10: one catalog read, one refused call, one re-read and one retry.
  const methods = server.requests.map((req) => bodyOf(req)["method"]);
  assert.deepEqual(methods, ["tools/list", "tools/call", "tools/list", "tools/call"], CASE + ": the resync reads the catalog again and retries once");

  const callsSeen = requestsOf(server, "tools/call");
  assert.equal(callsSeen.length, 2, CASE + ": exactly one refused call and one retry are recorded");
  const first = callsSeen[0];
  const retried = callsSeen[1];
  if (first === undefined || retried === undefined) {
    throw new Error(CASE + ": expected two tools/call requests");
  }

  // 4. The projection of each call follows the catalog it read.
  assert.deepEqual(headerValues(first, "mcp-param-region"), ["eu"], CASE + ": the first call projects the stale region header");
  assert.deepEqual(headerValues(first, "mcp-param-tenant"), [], CASE + ": the first call projects no tenant header");
  assert.deepEqual(headerValues(retried, "mcp-param-region"), [], CASE + ": the retried call drops the moved region header");
  assert.deepEqual(headerValues(retried, "mcp-param-tenant"), ["acme"], CASE + ": the retried call projects the current tenant header");

  // 5. Both calls stay modern requests with fresh JSON-RPC ids.
  for (const req of callsSeen) {
    const meta = metaOf(req);
    assert.equal(
      meta === undefined ? undefined : meta["io.modelcontextprotocol/protocolVersion"],
      "2026-07-28",
      CASE + ": both calls advertise the modern version in _meta",
    );
    assert.deepEqual(headerValues(req, "Mcp-Method"), ["tools/call"], CASE + ": both calls mirror the method header");
    assert.deepEqual(headerValues(req, "Mcp-Name"), ["svc.status"], CASE + ": both calls mirror the name header");
  }
  assert.notEqual(idOf(first), idOf(retried), CASE + ": the retried call uses a new JSON-RPC id");
});

/** The label every assertion message of the cached-resync case starts with. */
const CACHED_CASE = "client_header_resync_cached";

/** The array member `member` of a catalog answer, undefined for any other shape. */
function arrayMember(value: JsonValue, member: string): JsonValue[] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entries = value[member];
  return Array.isArray(entries) ? entries : undefined;
}

/** The catalog answer with a positive ttl: C8 stores an answer only when its `ttlMs` is above zero, so only this shape is a live cache entry. */
function cacheable(catalog: JsonValue, member: string): JsonValue {
  const entries = arrayMember(catalog, member);
  if (entries === undefined) throw new Error("modern client test: catalog answer has no " + member + " array");
  const answer: { [key: string]: JsonValue } = { ttlMs: 60000 };
  answer[member] = entries;
  return answer;
}

test("client_header_resync_cached", async () => {
  // 1. The same moving catalog with the private result cache switched on: the
  // first tools/list answer carries a ttl, so C8 really stores it and the
  // resync has to drop that entry as well as the memoised catalog.
  const server = newModernServer();
  let catalogReads = 0;
  let calls = 0;
  server.handle = (req) => {
    const body = bodyOf(req);
    const id = idOf(req);
    if (body["method"] === "tools/list") {
      catalogReads++;
      return server.sign(200, req.auth, rpcResult(id, cacheable(catalogReads === 1 ? FIRST_CATALOG : LATER_CATALOG, "tools")));
    }
    calls++;
    if (calls === 1) {
      return server.sign(400, req.auth, rpcError(id, -32020, "Header mismatch: Mcp-Name is not a valid base64 sentinel encoding"));
    }
    return server.sign(200, req.auth, rpcResult(id, { structuredContent: { ok: true }, ttlMs: 0 }));
  };
  const mc = new ModernClient(newModernClient(server, "modern"), { cacheResults: true });

  // 2. The call is refused once and answered on the single retry.
  const value = await mc.call("tools/call", { name: "svc.status", arguments: { region: "eu", tenant: "acme" } });
  assert.deepEqual(value, { ok: true }, CACHED_CASE + ": the retried call returns the structured content");

  // 3. The cached tools/list result would otherwise be served again and the
  // stale schema re-projected, so the resync must invalidate it: exactly two
  // catalog reads reach the server, one before the refusal and one before the
  // retry, even though the first answer is a live C8 entry.
  assert.equal(
    requestsOf(server, "tools/list").length,
    2,
    CACHED_CASE + ": the resync re-reads the catalog from the wire even though C8 cached the first answer",
  );
  assert.equal(requestsOf(server, "tools/call").length, 2, CACHED_CASE + ": the refused call and its one retry are the only calls sent");

  const [first, retried] = requestsOf(server, "tools/call");
  if (first === undefined || retried === undefined) {
    throw new Error(CACHED_CASE + ": expected two tools/call requests");
  }

  // 4. The first call projects the first catalog, the retry the re-read one.
  assert.deepEqual(headerValues(first, "mcp-param-region"), ["eu"], CACHED_CASE + ": the first call projects the region header of the first catalog");
  assert.deepEqual(headerValues(first, "mcp-param-tenant"), [], CACHED_CASE + ": the first call projects no tenant header");
  assert.deepEqual(headerValues(retried, "mcp-param-region"), [], CACHED_CASE + ": the retry drops the region header the stale schema annotated");
  assert.deepEqual(
    headerValues(retried, "mcp-param-tenant"),
    ["acme"],
    CACHED_CASE + ": the retry projects the tenant header of the freshly read catalog",
  );
});
