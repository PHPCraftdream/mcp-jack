/**
 * Spec 04 C5/C11: the client excludes an invalid tool from a `tools/list`
 * result and an invalid event type from an `events/list` result, whichever
 * entry point reads the catalog. A plain `call("tools/list")` filters exactly
 * as `listTools()` does, and both report each exclusion through `onExcluded`.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { ModernClient } from "../../../src/client/modern.js";
import type { JsonValue } from "../../../src/client/rpc.js";
import type { AnnotationReason } from "../../../src/modern/annotations.js";
import { bodyOf, newModernClient, newModernServer, rpcResult } from "./support.js";
import type { RecordedRequest } from "./support.js";

/** The JSON-RPC id of one recorded request, 1 when it is not a number. */
function idOf(req: RecordedRequest): number {
  const id = bodyOf(req)["id"];
  return typeof id === "number" ? id : 1;
}

/** The array member `member` of a JSON object result, undefined for any other shape. */
function arrayMember(value: JsonValue, member: string): JsonValue[] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entries = value[member];
  return Array.isArray(entries) ? entries : undefined;
}

/** A valid tool: the annotation sits on a property reachable through `properties`. */
const VALID_TOOL: JsonValue = {
  name: "svc.status",
  inputSchema: {
    type: "object",
    properties: { region: { type: "string", "x-mcp-header": "Region" } },
  },
};

/** An excluded tool: the annotation is at the schema root, so it is not statically reachable. */
const INVALID_TOOL: JsonValue = {
  name: "bad.root",
  inputSchema: { type: "object", "x-mcp-header": "Root" },
};

/** A valid event type: the annotation sits on a reachable string property. */
const VALID_EVENT: JsonValue = {
  name: "svc.tick",
  inputSchema: {
    type: "object",
    properties: { region: { type: "string", "x-mcp-header": "Region" } },
  },
};

/** An excluded event type: the annotated property is an object, not a primitive. */
const INVALID_EVENT: JsonValue = {
  name: "bad.event",
  inputSchema: {
    type: "object",
    properties: { payload: { type: "object", "x-mcp-header": "Payload" } },
  },
};

test("client_catalog_filter", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    const body = bodyOf(req);
    const id = idOf(req);
    if (body["method"] === "tools/list") {
      return server.sign(200, req.auth, rpcResult(id, { tools: [VALID_TOOL, INVALID_TOOL] }));
    }
    if (body["method"] === "events/list") {
      return server.sign(200, req.auth, rpcResult(id, { events: [VALID_EVENT, INVALID_EVENT] }));
    }
    return server.sign(200, req.auth, rpcResult(id, { structuredContent: { area: 1 } }));
  };

  const excluded: [string, AnnotationReason][] = [];
  const mc = new ModernClient(newModernClient(server, "modern"), {
    onExcluded: (name: string, reason: AnnotationReason) => {
      excluded.push([name, reason]);
    },
  });

  // A plain tools/list call filters exactly as listTools() does.
  const listed = await mc.call("tools/list");
  assert.deepEqual(arrayMember(listed, "tools"), [VALID_TOOL], "catalog: call(tools/list) excludes the invalid tool");
  assert.deepEqual(listed, { tools: [VALID_TOOL] }, "catalog: the filtered tools/list result keeps its other members");
  assert.deepEqual(await mc.listTools(), [VALID_TOOL], "catalog: listTools returns the same filtered list");

  // The same for events/list.
  const events = await mc.call("events/list");
  assert.deepEqual(arrayMember(events, "events"), [VALID_EVENT], "catalog: call(events/list) drops the invalid event type");
  assert.deepEqual(await mc.listEvents(), [VALID_EVENT], "catalog: listEvents returns the same filtered list");

  // Any other method is untouched.
  assert.deepEqual(await mc.call("tools/call", { name: "svc.status" }), { area: 1 }, "catalog: a non-catalog result is not filtered");

  // Both exclusions were reported with their C5/C11 reason.
  assert.ok(
    excluded.some(([name, reason]) => name === "bad.root" && reason === "annotation_not_statically_reachable"),
    "catalog: onExcluded reports the tool name and reason",
  );
  assert.ok(
    excluded.some(([name, reason]) => name === "bad.event" && reason === "annotation_type_not_primitive"),
    "catalog: onExcluded reports the event name and reason",
  );
});
