/**
 * Spec 04 C12: a `-32020` header refusal on a modern `events/poll` drops the
 * cached `events/list` catalog, re-reads it and retries the call exactly once,
 * while a method with no catalog (`prompts/get`) is never resynced.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ModernClient } from "../../../src/client/modern.js";
import { RPCError } from "../../../src/client/errors.js";
import type { JsonValue } from "../../../src/client/rpc.js";
import { bodyOf, headerValues, newModernClient, newModernServer, rpcError, rpcResult } from "./support.js";
import type { ModernServer, RecordedRequest } from "./support.js";

/** The label every assertion message of this case starts with. */
const CASE = "client_events_resync";

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
  events: [
    {
      name: "incident.created",
      inputSchema: {
        type: "object",
        properties: {
          region: { type: "string", "x-mcp-header": "Region" },
        },
      },
    },
  ],
};

/** The moved catalog: the annotation is now on zone and region carries none. */
const LATER_CATALOG: JsonValue = {
  events: [
    {
      name: "incident.created",
      inputSchema: {
        type: "object",
        properties: {
          zone: { type: "string", "x-mcp-header": "Zone" },
        },
      },
    },
  ],
};

test("client_events_resync", async () => {
  // 1. A server whose event catalog moves the annotation from region to zone
  // after the first read, and whose first poll refuses the stale projection.
  const server = newModernServer();
  let catalogReads = 0;
  let polls = 0;
  server.handle = (req) => {
    const body = bodyOf(req);
    const id = idOf(req);
    if (body["method"] === "events/list") {
      catalogReads++;
      return server.sign(200, req.auth, rpcResult(id, catalogReads === 1 ? FIRST_CATALOG : LATER_CATALOG));
    }
    polls++;
    if (polls === 1) {
      return server.sign(400, req.auth, rpcError(id, -32020, "Header mismatch: Mcp-Name does not match the body value"));
    }
    return server.sign(200, req.auth, rpcResult(id, { structuredContent: { events: [] }, ttlMs: 0 }));
  };
  const mc = new ModernClient(newModernClient(server, "modern"));

  // 2. The poll is refused once and answered on the single retry.
  const value = await mc.call("events/poll", { name: "incident.created", arguments: { region: "eu", zone: "z1" } });
  assert.deepEqual(value, { events: [] }, CASE + ": the retried poll returns the structured content");

  // 3. C12: one catalog read, one refused poll, one re-read and one retry.
  const methods = server.requests.map((req) => bodyOf(req)["method"]);
  assert.deepEqual(methods, ["events/list", "events/poll", "events/list", "events/poll"], CASE + ": the resync reads the catalog again and retries once");

  const pollsSeen = requestsOf(server, "events/poll");
  assert.equal(pollsSeen.length, 2, CASE + ": exactly one refused poll and one retry are recorded");
  const first = pollsSeen[0];
  const retried = pollsSeen[1];
  if (first === undefined || retried === undefined) {
    throw new Error(CASE + ": expected two events/poll requests");
  }

  // 4. The projection of each poll follows the catalog it read.
  assert.deepEqual(headerValues(first, "mcp-param-region"), ["eu"], CASE + ": the first poll projects the stale region header");
  assert.deepEqual(headerValues(first, "mcp-param-zone"), [], CASE + ": the first poll projects no zone header");
  assert.deepEqual(headerValues(retried, "mcp-param-region"), [], CASE + ": the retried poll drops the moved region header");
  assert.deepEqual(headerValues(retried, "mcp-param-zone"), ["z1"], CASE + ": the retried poll projects the current zone header");

  // 5. Both polls stay modern requests for the same event type.
  for (const req of pollsSeen) {
    const meta = metaOf(req);
    assert.equal(
      meta === undefined ? undefined : meta["io.modelcontextprotocol/protocolVersion"],
      "2026-07-28",
      CASE + ": both polls advertise the modern version in _meta",
    );
    assert.deepEqual(headerValues(req, "Mcp-Method"), ["events/poll"], CASE + ": both polls mirror the method header");
    assert.deepEqual(headerValues(req, "Mcp-Name"), ["incident.created"], CASE + ": both polls mirror the name header");
  }
  assert.notEqual(idOf(first), idOf(retried), CASE + ": the retried poll uses a new JSON-RPC id");

  // 6. A method with no catalog is refused but never resynced: prompts/get is
  // sent once, and neither catalog is read at all.
  const server2 = newModernServer();
  server2.handle = (req) => server2.sign(400, req.auth, rpcError(idOf(req), -32020, "Header mismatch: Mcp-Name does not match the body value"));
  await assert.rejects(
    new ModernClient(newModernClient(server2, "modern")).call("prompts/get", { name: "summarize" }),
    (err: unknown): boolean => err instanceof RPCError && err.code === -32020,
    CASE + ": a refused prompts/get surfaces the -32020 error",
  );
  assert.equal(requestsOf(server2, "prompts/get").length, 1, CASE + ": the refused prompts/get is sent exactly once");
  assert.equal(requestsOf(server2, "tools/list").length, 0, CASE + ": prompts/get never reads the tools catalog");
  assert.equal(requestsOf(server2, "events/list").length, 0, CASE + ": prompts/get never reads the events catalog");
});

/** The label every assertion message of the cached-resync case starts with. */
const CACHED_CASE = "client_events_resync_cached";

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

test("client_events_resync_cached", async () => {
  // 1. The same moving event catalog with the private result cache switched
  // on: the first events/list answer carries a ttl, so C8 really stores it and
  // the resync has to drop that entry as well as the memoised catalog.
  const server = newModernServer();
  let catalogReads = 0;
  let polls = 0;
  server.handle = (req) => {
    const body = bodyOf(req);
    const id = idOf(req);
    if (body["method"] === "events/list") {
      catalogReads++;
      return server.sign(200, req.auth, rpcResult(id, cacheable(catalogReads === 1 ? FIRST_CATALOG : LATER_CATALOG, "events")));
    }
    polls++;
    if (polls === 1) {
      return server.sign(400, req.auth, rpcError(id, -32020, "Header mismatch: Mcp-Name does not match the body value"));
    }
    return server.sign(200, req.auth, rpcResult(id, { structuredContent: { events: [] }, ttlMs: 0 }));
  };
  const mc = new ModernClient(newModernClient(server, "modern"), { cacheResults: true });

  // 2. The poll is refused once and answered on the single retry.
  const value = await mc.call("events/poll", { name: "incident.created", arguments: { region: "eu", zone: "z1" } });
  assert.deepEqual(value, { events: [] }, CACHED_CASE + ": the retried poll returns the structured content");

  // 3. The cached events/list result would otherwise be served again and the
  // stale schema re-projected, so the resync must invalidate it: exactly two
  // catalog reads reach the server, one before the refusal and one before the
  // retry, even though the first answer is a live C8 entry.
  assert.equal(
    requestsOf(server, "events/list").length,
    2,
    CACHED_CASE + ": the resync re-reads the catalog from the wire even though C8 cached the first answer",
  );
  assert.equal(requestsOf(server, "events/poll").length, 2, CACHED_CASE + ": the refused poll and its one retry are the only polls sent");

  const [first, retried] = requestsOf(server, "events/poll");
  if (first === undefined || retried === undefined) {
    throw new Error(CACHED_CASE + ": expected two events/poll requests");
  }

  // 4. The first poll projects the first catalog, the retry the re-read one.
  assert.deepEqual(headerValues(first, "mcp-param-region"), ["eu"], CACHED_CASE + ": the first poll projects the region header of the first catalog");
  assert.deepEqual(headerValues(first, "mcp-param-zone"), [], CACHED_CASE + ": the first poll projects no zone header");
  assert.deepEqual(headerValues(retried, "mcp-param-region"), [], CACHED_CASE + ": the retry drops the region header the stale schema annotated");
  assert.deepEqual(
    headerValues(retried, "mcp-param-zone"),
    ["z1"],
    CACHED_CASE + ": the retry projects the zone header of the freshly read catalog",
  );
});
