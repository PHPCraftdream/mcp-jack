/**
 * Spec 04 C1/C2: `buildRequestMirrors` builds the request `_meta` and the
 * mirror header list. C1 requires `clientCapabilities` to be a JSON object, and
 * C2 fixes the order of the returned pair list (and nothing about the wire
 * order, which the transport owns).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, buildRequestMirrors } from "../../src/modern/request.js";
import type { JsonValue } from "../../src/core/json-raw.js";

/** The modern protocol version these cases mirror. */
const VERSION = "2026-07-28";

test("request mirrors: clientCapabilities must be a JSON object", () => {
  // C1 allows any JSON object, including {}; a number, a string, an array and
  // null are not objects and are refused before any request is built.
  for (const bad of [7, "x", [], null] as JsonValue[]) {
    assert.throws(
      () => buildRequestMirrors({ version: VERSION, method: "tools/list", clientCapabilities: bad }),
      (err: unknown): boolean =>
        err instanceof Error && err.message === "modern profile: clientCapabilities must be a JSON object",
      "mirrors: " + JSON.stringify(bad) + " is not a JSON object",
    );
  }

  const empty = buildRequestMirrors({ version: VERSION, method: "tools/list", clientCapabilities: {} });
  assert.deepEqual(empty.meta[META_CLIENT_CAPABILITIES], {}, "mirrors: {} is accepted as the capabilities");

  const capabilities = { roots: { listChanged: true }, sampling: {} };
  const shaped = buildRequestMirrors({ version: VERSION, method: "tools/list", clientCapabilities: capabilities });
  assert.deepEqual(shaped.meta[META_CLIENT_CAPABILITIES], capabilities, "mirrors: an object is copied into _meta");
});

test("request mirrors: the C2 list order", () => {
  const mirrors = buildRequestMirrors({ version: VERSION, method: "tools/call", params: { name: "x" } });

  // C2 position 1 to 3: version, method, then the encoded name of an S6 method.
  assert.deepEqual(
    mirrors.headers,
    [
      ["MCP-Protocol-Version", VERSION],
      ["Mcp-Method", "tools/call"],
      ["Mcp-Name", "x"],
    ],
    "mirrors: the header list is in C2 order",
  );

  // C1: protocolVersion and clientCapabilities, and no clientInfo when none is given.
  assert.deepEqual(
    Object.keys(mirrors.meta),
    [META_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES],
    "mirrors: _meta holds protocolVersion and clientCapabilities only",
  );
  assert.equal(mirrors.meta[META_PROTOCOL_VERSION], VERSION, "mirrors: the version is mirrored into _meta");
  assert.deepEqual(mirrors.meta[META_CLIENT_CAPABILITIES], {}, "mirrors: capabilities default to {}");
});
