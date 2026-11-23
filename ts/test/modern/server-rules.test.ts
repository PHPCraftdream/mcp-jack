/**
 * Tests for the server rules S1-S12 of the modern profile of spec 04 section 5:
 * the era decision, the mirror-header checks, the refusal table and the
 * classification refusal, driven against the real request classifier.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifyModernRequest,
  envelopeBodyText,
  INVALID_TOOL_NAME_MESSAGE,
  MODERN_REFUSALS,
  refusalBodyText,
  toolsCallNameInvalid,
} from "../../src/modern/server.js";
import type { ModernRefusalReason, ModernRequestDecision } from "../../src/modern/server.js";
import type { HeaderPair } from "../../src/modern/values.js";

type ForwardDecision = Extract<ModernRequestDecision, { readonly outcome: "forward" }>;
type RefusalDecision = Extract<ModernRequestDecision, { readonly outcome: "refuse" }>;
type ClassificationDecision = Extract<ModernRequestDecision, { readonly outcome: "refuse_invalid_request" }>;

/** A `params._meta` fragment carrying a modern protocol version. */
const META_MODERN = '"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}';
/** A `params._meta` fragment carrying a pre-modern protocol version. */
const META_OLD = '"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}';
/** A `tools/list` request with no body mirrors. */
const LIST_PLAIN = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}';
/** A `tools/list` request carrying a modern `_meta` version. */
const LIST_META = '{"jsonrpc":"2.0","id":1,"method":"tools/list",' + META_MODERN + "}";
/** A `tools/list` request carrying a pre-modern `_meta` version. */
const LIST_META_OLD = '{"jsonrpc":"2.0","id":1,"method":"tools/list",' + META_OLD + "}";
/** A `tools/call` request with a valid name and a modern `_meta` version. */
const CALL_META =
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}';

/** A POST of `bodyText` under `profile`. */
function post(profile: "legacy" | "modern" | "both", headers: readonly HeaderPair[], bodyText: string): ModernRequestDecision {
  return classifyModernRequest({ profile, method: "POST", target: "/mcp", headers, bodyText });
}

/** The decision narrowed to a forward. */
function forwardOf(decision: ModernRequestDecision): ForwardDecision {
  assert.equal(decision.outcome, "forward", "The request must be forwarded.");
  return decision as ForwardDecision;
}

/** The decision narrowed to a section 5 refusal. */
function refuseOf(decision: ModernRequestDecision): RefusalDecision {
  assert.equal(decision.outcome, "refuse", "The request must be refused.");
  return decision as RefusalDecision;
}

/** The decision narrowed to the classification refusal. */
function classificationOf(decision: ModernRequestDecision): ClassificationDecision {
  assert.equal(decision.outcome, "refuse_invalid_request", "The request must fail classification.");
  return decision as ClassificationDecision;
}

test("server rules: the legacy era forwards untouched", () => {
  const headers: readonly HeaderPair[] = [
    ["Mcp-Session-Id", "session-1"],
    ["Mcp-Name", "=x"],
    ["MCP-Protocol-Version", "2026-07-28"],
  ];
  const decision = classifyModernRequest({ profile: "legacy", method: "POST", target: "/mcp", headers, bodyText: LIST_META });
  const forward = forwardOf(decision);
  assert.equal(forward.era, "legacy", "The legacy profile must take the legacy era.");
  assert.equal(forward.forward.method, "POST", "The method must be forwarded unchanged.");
  assert.equal(forward.forward.target, "/mcp", "The target must be forwarded unchanged.");
  assert.deepEqual(forward.forward.headers, headers, "The header list must be forwarded unchanged.");
  assert.deepEqual(
    forward.forward.headers.map(([name, value]) => [name, value]),
    headers.map(([name, value]) => [name, value]),
    "Header order and casing must be preserved.",
  );
});

test("server rules: the both-profile era decision (S3)", () => {
  type EraRow = {
    readonly label: string;
    readonly headers: readonly HeaderPair[];
    readonly body: string;
    readonly era: "legacy" | "modern";
    readonly reason?: ModernRefusalReason;
  };
  const rows: readonly EraRow[] = [
    { label: "no signal", headers: [], body: LIST_PLAIN, era: "legacy" },
    {
      label: "pre-modern header",
      headers: [["MCP-Protocol-Version", "2025-11-25"]],
      body: LIST_PLAIN,
      era: "legacy",
    },
    {
      label: "modern header only",
      headers: [["MCP-Protocol-Version", "2026-07-28"]],
      body: LIST_PLAIN,
      era: "modern",
      reason: "version_meta_missing",
    },
    { label: "modern meta only", headers: [], body: LIST_META, era: "modern", reason: "version_header_missing" },
    {
      label: "modern header with an older meta",
      headers: [["MCP-Protocol-Version", "2026-07-28"]],
      body: LIST_META_OLD,
      era: "modern",
      reason: "version_mismatch",
    },
    {
      label: "malformed header with a modern meta",
      headers: [["MCP-Protocol-Version", "2026-7-28"]],
      body: LIST_META,
      era: "modern",
      reason: "version_header_malformed",
    },
    {
      label: "malformed header without a meta",
      headers: [["MCP-Protocol-Version", "2026-7-28"]],
      body: LIST_PLAIN,
      era: "legacy",
    },
    {
      label: "repeated modern header",
      headers: [
        ["MCP-Protocol-Version", "2026-07-28"],
        ["MCP-Protocol-Version", "2026-07-28"],
      ],
      body: LIST_PLAIN,
      era: "modern",
      reason: "header_repeated",
    },
  ];
  for (const row of rows) {
    const decision = post("both", row.headers, row.body);
    if (row.reason === undefined) {
      const forward = forwardOf(decision);
      assert.equal(forward.era, row.era, row.label + ": the era must match.");
    } else {
      const refusal = refuseOf(decision);
      assert.equal(refusal.era, "modern", row.label + ": the era must be modern.");
      assert.equal(refusal.message, MODERN_REFUSALS[row.reason].message, row.label + ": the reason must match.");
    }
  }
});

test("server rules: header names are case-insensitive and values case-sensitive", () => {
  const headers: readonly HeaderPair[] = [
    ["mcp-protocol-version", "2026-07-28"],
    ["MCP-METHOD", "tools/call"],
    ["Mcp-name", "demo"],
  ];
  const forward = forwardOf(post("both", headers, CALL_META));
  assert.equal(forward.era, "modern", "Any casing of the mirror names must select the modern era.");
  assert.deepEqual(forward.forward.headers, headers, "Every mirror header must be forwarded.");

  const mismatched = refuseOf(
    post(
      "both",
      [
        ["mcp-protocol-version", "2026-07-28"],
        ["Mcp-Method", "Tools/Call"],
        ["Mcp-Name", "demo"],
      ],
      CALL_META,
    ),
  );
  assert.equal(
    mismatched.message,
    MODERN_REFUSALS.method_header_mismatch.message,
    "The method value must compare case-sensitively.",
  );
});

test("server rules: S1 rejects repeated and invalid mirror values", () => {
  const repeated: readonly (readonly HeaderPair[])[] = [
    [
      ["Mcp-Protocol-Version", "2026-07-28"],
      ["Mcp-Protocol-Version", "2026-07-28"],
    ],
    [
      ["Mcp-Method", "tools/list"],
      ["Mcp-Method", "tools/list"],
    ],
    [
      ["Mcp-Name", "a"],
      ["Mcp-Name", "a"],
    ],
  ];
  for (const headers of repeated) {
    const refusal = refuseOf(post("modern", headers, LIST_PLAIN));
    assert.equal(refusal.message, MODERN_REFUSALS.header_repeated.message, "Every repeated mirror must be refused.");
  }

  for (const value of ["a\u0000b", "a\u007fb", "caf\u00e9"]) {
    const refusal = refuseOf(post("modern", [["Mcp-Param-Region", value]], LIST_PLAIN));
    assert.equal(refusal.message, MODERN_REFUSALS.header_value_invalid.message, "An invalid field value must be refused.");
  }

  const valid: readonly HeaderPair[] = [
    ["Mcp-Protocol-Version", "2026-07-28"],
    ["Mcp-Method", "tools/list"],
    ["Mcp-Param-Region", "a\tb"],
    ["Mcp-Param-", "x"],
  ];
  const forward = forwardOf(post("modern", valid, LIST_META));
  assert.equal(forward.era, "modern", "A valid request must be forwarded.");
  assert.deepEqual(forward.forward.headers, valid, "HTAB and a bare prefix must be forwarded.");
});

test("server rules: S4/S5/S6 rows and ids", () => {
  type RefusalRow = {
    readonly reason: ModernRefusalReason;
    readonly method: string;
    readonly headers: readonly HeaderPair[];
    readonly bodyText: string;
    readonly idText: string;
  };
  const version: HeaderPair = ["MCP-Protocol-Version", "2026-07-28"];
  const callHeaders: readonly HeaderPair[] = [version, ["Mcp-Method", "tools/call"]];
  const rows: readonly RefusalRow[] = [
    { reason: "method_not_allowed", method: "GET", headers: [], bodyText: "", idText: "null" },
    { reason: "header_value_invalid", method: "POST", headers: [["Mcp-Param-Region", "a\u0000b"]], bodyText: LIST_PLAIN, idText: "1" },
    {
      reason: "header_repeated",
      method: "POST",
      headers: [
        ["Mcp-Method", "tools/list"],
        ["Mcp-Method", "tools/list"],
      ],
      bodyText: LIST_PLAIN,
      idText: "1",
    },
    { reason: "version_header_missing", method: "POST", headers: [], bodyText: LIST_PLAIN, idText: "1" },
    {
      reason: "version_header_malformed",
      method: "POST",
      headers: [["MCP-Protocol-Version", "2026-7-28"]],
      bodyText: LIST_META,
      idText: "1",
    },
    { reason: "version_meta_missing", method: "POST", headers: [version], bodyText: LIST_PLAIN, idText: "1" },
    { reason: "version_mismatch", method: "POST", headers: [version], bodyText: LIST_META_OLD, idText: "1" },
    { reason: "method_header_missing", method: "POST", headers: [version], bodyText: LIST_META, idText: "1" },
    {
      reason: "method_header_mismatch",
      method: "POST",
      headers: [version, ["Mcp-Method", "resources/list"]],
      bodyText: LIST_META,
      idText: "1",
    },
    {
      reason: "name_header_not_applicable",
      method: "POST",
      headers: [version, ["Mcp-Method", "tools/list"], ["Mcp-Name", "x"]],
      bodyText: LIST_META,
      idText: "1",
    },
    {
      reason: "name_source_missing",
      method: "POST",
      headers: [version, ["Mcp-Method", "resources/read"]],
      bodyText: '{"jsonrpc":"2.0","id":1,"method":"resources/read",' + META_MODERN + "}",
      idText: "1",
    },
    { reason: "name_header_missing", method: "POST", headers: callHeaders, bodyText: CALL_META, idText: "1" },
    {
      reason: "name_header_bad_encoding",
      method: "POST",
      headers: [...callHeaders, ["Mcp-Name", "=?base64?@@@@?="]],
      bodyText: CALL_META,
      idText: "1",
    },
    {
      reason: "name_header_mismatch",
      method: "POST",
      headers: [...callHeaders, ["Mcp-Name", "other"]],
      bodyText: CALL_META,
      idText: "1",
    },
  ];
  const covered = new Set<ModernRefusalReason>();
  for (const row of rows) {
    covered.add(row.reason);
    const entry = MODERN_REFUSALS[row.reason];
    const refusal = refuseOf(
      classifyModernRequest({ profile: "modern", method: row.method, target: "/mcp", headers: row.headers, bodyText: row.bodyText }),
    );
    assert.equal(refusal.httpStatus, entry.httpStatus, row.reason + ": the status must match the table.");
    assert.equal(refusal.code, entry.code, row.reason + ": the code must match the table.");
    assert.equal(refusal.message, entry.message, row.reason + ": the message must match the table.");
    assert.equal(refusal.era, "modern", row.reason + ": the era must be modern.");
    assert.equal(refusal.allowPost, row.reason === "method_not_allowed", row.reason + ": only S2 allows POST.");
    assert.equal(refusal.idText, row.idText, row.reason + ": the id text must be the raw id.");
  }
  assert.equal(covered.size, Object.keys(MODERN_REFUSALS).length, "Every fixed reason must be covered.");

  const stringId = refuseOf(post("modern", [], '{"jsonrpc":"2.0","id":"abc","method":"tools/list"}'));
  assert.equal(stringId.idText, '"abc"', "A string id must be echoed as raw source text.");

  const notification = forwardOf(post("modern", [], '{"jsonrpc":"2.0","method":"tools/list"}'));
  assert.equal(notification.era, "modern", "A notification without mirrors must be forwarded.");
  assert.deepEqual(notification.forward.headers, [], "A notification without mirrors must forward no headers.");

  const notificationMismatch = refuseOf(
    post("modern", [["Mcp-Name", "other"]], '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"demo"}}'),
  );
  assert.equal(
    notificationMismatch.message,
    MODERN_REFUSALS.name_header_mismatch.message,
    "A mismatched notification name must be refused.",
  );
  assert.equal(notificationMismatch.idText, "null", "A notification has no id text.");

  const sentinelBody =
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":" padded ","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}';
  const sentinel = forwardOf(post("modern", [...callHeaders, ["Mcp-Name", "=?base64?IHBhZGRlZCA=?="]], sentinelBody));
  assert.equal(sentinel.era, "modern", "A sentinel mirror must be accepted.");

  const paddedBody =
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"padded","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}';
  const padded = refuseOf(post("modern", [...callHeaders, ["Mcp-Name", " padded "]], paddedBody));
  assert.equal(padded.message, MODERN_REFUSALS.name_header_mismatch.message, "A padded raw value must not match.");

  const badEncoding = refuseOf(post("modern", [...callHeaders, ["Mcp-Name", "=?base64?@@@@?="]], CALL_META));
  assert.equal(
    badEncoding.message,
    MODERN_REFUSALS.name_header_bad_encoding.message,
    "A non-canonical sentinel must be refused.",
  );

  for (const method of ["tools/list", "events/list", "subscriptions/listen"]) {
    const body =
      '{"jsonrpc":"2.0","id":1,"method":"' + method + '","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}';
    const refusal = refuseOf(post("modern", [version, ["Mcp-Method", method], ["Mcp-Name", "x"]], body));
    assert.equal(
      refusal.message,
      MODERN_REFUSALS.name_header_not_applicable.message,
      method + ": the name header must not apply.",
    );
  }

  const uriRefusal = refuseOf(
    post(
      "modern",
      [version, ["Mcp-Method", "resources/read"]],
      '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":7,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}',
    ),
  );
  assert.equal(uriRefusal.message, MODERN_REFUSALS.name_source_missing.message, "A non-string uri must miss its source.");
});

test("server rules: S2 and S12", () => {
  const get = refuseOf(classifyModernRequest({ profile: "modern", method: "GET", target: "/mcp", headers: [], bodyText: "" }));
  assert.equal(get.message, MODERN_REFUSALS.method_not_allowed.message, "A GET must not be allowed.");
  assert.equal(get.idText, "null", "A GET has no id text.");
  assert.equal(get.allowPost, true, "The S2 refusal must allow POST.");

  const missingVersion = refuseOf(post("modern", [], LIST_PLAIN));
  assert.equal(missingVersion.allowPost, false, "Only S2 may allow POST.");
  const mismatch = refuseOf(
    post(
      "modern",
      [
        ["MCP-Protocol-Version", "2026-07-28"],
        ["Mcp-Method", "tools/call"],
        ["Mcp-Name", "other"],
      ],
      CALL_META,
    ),
  );
  assert.equal(mismatch.allowPost, false, "Only S2 may allow POST.");

  const headers: readonly HeaderPair[] = [
    ["Mcp-Session-Id", "session-1"],
    ["Content-Type", "application/json"],
  ];
  const forward = forwardOf(post("modern", headers, '{"jsonrpc":"2.0","id":7,"result":{}}'));
  assert.equal(forward.era, "modern", "A client response must forward in the modern era.");
  assert.deepEqual(forward.forward.headers, [["Content-Type", "application/json"]], "The session header must be removed.");
});

test("server rules: the classification refusal and the body contract", () => {
  const invalidBodies: readonly string[] = ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}', '{"jsonrpc":"2.0","method":"tools/call"}'];
  for (const body of invalidBodies) {
    const refusal = classificationOf(post("modern", [], body));
    assert.equal(refusal.httpStatus, 400, "The classification refusal must be a 400.");
    assert.equal(refusal.code, "invalid_request", "The classification refusal must use the string code.");
    assert.equal(refusal.message, INVALID_TOOL_NAME_MESSAGE, "The classification refusal must carry the fixed message.");
    assert.equal(toolsCallNameInvalid(body), true, "The body must classify as an invalid tool name.");
  }
  assert.equal(toolsCallNameInvalid("{},](["), false, "Unparsable JSON is not an invalid tool name.");
  assert.equal(toolsCallNameInvalid('{"jsonrpc":"2.0","id":7,"result":{}}'), false, "A response object is not a tool call.");
  assert.equal(toolsCallNameInvalid(undefined), false, "No body is not an invalid tool name.");

  assert.equal(
    refusalBodyText("1", -32020, "Header mismatch: Mcp-Name is missing"),
    '{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: Mcp-Name is missing"}}',
    "The refusal body must be the signed JSON-RPC error.",
  );
  assert.equal(
    envelopeBodyText("invalid_request", "x"),
    '{"error":{"code":"invalid_request","message":"x"}}',
    "The envelope body must be the classification error.",
  );

  assert.throws(() => post("modern", [], ""), /modern era requires a classified body/, "A modern POST without a body must throw.");
  assert.throws(
    () => post("modern", [], "[1,2]"),
    /not an acceptable JSON-RPC object/,
    "A body that is not a JSON object must throw.",
  );
});
