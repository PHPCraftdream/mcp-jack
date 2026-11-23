/**
 * Tests for the `x-mcp-header` rules of the modern profile of spec 04 section
 * 6: C5 validation, C6 projection and the C11 catalog filtering, driven against
 * the real SDK module.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  filterEventTypes,
  filterToolDefinitions,
  PROJECTION_REASON,
  projectArguments,
  validateAnnotations,
} from "../../src/modern/annotations.js";
import type { AnnotationReason } from "../../src/modern/annotations.js";
import type { JsonValue } from "../../src/core/json-raw.js";
import { SAFE_INT_MAX } from "../../src/modern/values.js";

/** A schema whose single property carries the annotation `name` and the given limits. */
function schemaFor(name: JsonValue, typeValue?: JsonValue, minimum?: JsonValue, maximum?: JsonValue): JsonValue {
  const node: { [key: string]: JsonValue } = {};
  if (typeValue !== undefined) node["type"] = typeValue;
  if (minimum !== undefined) node["minimum"] = minimum;
  if (maximum !== undefined) node["maximum"] = maximum;
  node["x-mcp-header"] = name;
  return { type: "object", properties: { field: node } };
}

/** The schema under a single top-level keyword, used to place an annotation off the reachable chain. */
function underKeyword(keyword: string, value: JsonValue): JsonValue {
  return { [keyword]: value };
}

test("annotations: intervening keyword positions never turn a name into an annotation", () => {
  const allOf: JsonValue = {
    type: "object",
    properties: {
      region: { type: "string", "x-mcp-header": "Region", allOf: [{ type: "string" }] },
    },
  };
  assert.deepEqual(validateAnnotations(allOf), { valid: true, reason: null }, "An allOf beside an annotation must stay valid.");

  const emptyPropertyName: JsonValue = { type: "object", properties: { "": { type: "string", "x-mcp-header": "Empty" } } };
  assert.deepEqual(
    validateAnnotations(emptyPropertyName),
    { valid: true, reason: null },
    "An empty property name must be reachable.",
  );

  const propertyNamedProperties: JsonValue = {
    type: "object",
    properties: { properties: { type: "string", "x-mcp-header": "Keyword" } },
  };
  assert.deepEqual(
    validateAnnotations(propertyNamedProperties),
    { valid: true, reason: null },
    "A property named properties is a name, not a keyword.",
  );

  const propertyNamedAnnotation: JsonValue = { type: "object", properties: { "x-mcp-header": { type: "string" } } };
  assert.deepEqual(
    validateAnnotations(propertyNamedAnnotation),
    { valid: true, reason: null },
    "A property named after the keyword must not be an annotation.",
  );

  const insideAllOf: JsonValue = {
    type: "object",
    properties: {
      outer: { allOf: [{ properties: { inner: { type: "string", "x-mcp-header": "Inner" } } }] },
    },
  };
  assert.deepEqual(
    validateAnnotations(insideAllOf),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "An annotation inside an allOf must be unreachable.",
  );
});

test("annotations: every unreachable position", () => {
  const annotated: JsonValue = { type: "string", "x-mcp-header": "Header" };
  const positions: readonly (readonly [string, JsonValue])[] = [
    ["items", annotated],
    ["oneOf", [annotated]],
    ["anyOf", [annotated]],
    ["not", annotated],
    ["if", annotated],
    ["then", annotated],
    ["else", annotated],
    ["additionalProperties", annotated],
    ["patternProperties", { "^a": annotated }],
    ["contains", annotated],
    ["dependentSchemas", { dep: annotated }],
    ["propertyNames", annotated],
    ["$defs", { Named: annotated }],
    ["unevaluatedProperties", annotated],
  ];
  for (const [keyword, value] of positions) {
    assert.deepEqual(
      validateAnnotations(underKeyword(keyword, value)),
      { valid: false, reason: "annotation_not_statically_reachable" },
      keyword + ": an annotation here must be unreachable.",
    );
  }
  assert.deepEqual(
    validateAnnotations({ type: "object", "x-mcp-header": "Root" }),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "An annotation at the root must be unreachable.",
  );
});

test("annotations: applicator traversal boundaries", () => {
  const deep: JsonValue = {
    type: "object",
    properties: {
      a: { type: "object", properties: { b: { type: "object", properties: { c: { type: "string", "x-mcp-header": "Deep" } } } } },
    },
  };
  assert.deepEqual(validateAnnotations(deep), { valid: true, reason: null }, "A deep properties chain must be reachable.");
  assert.deepEqual(
    projectArguments(deep, { a: { b: { c: "v" } } }),
    { outcome: "headers", headers: [["Mcp-Param-Deep", "v"]] },
    "A deep properties chain must project its header.",
  );

  const namedItems: JsonValue = { type: "object", properties: { items: { type: "string", "x-mcp-header": "Items" } } };
  assert.deepEqual(validateAnnotations(namedItems), { valid: true, reason: null }, "A property named items must be reachable.");
  assert.deepEqual(
    projectArguments(namedItems, { items: "v" }),
    { outcome: "headers", headers: [["Mcp-Param-Items", "v"]] },
    "A property named items must project its header.",
  );

  const insideItems: JsonValue = {
    type: "object",
    items: { type: "object", properties: { x: { type: "string", "x-mcp-header": "X" } } },
  };
  assert.deepEqual(
    validateAnnotations(insideItems),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "An annotation under items must be unreachable.",
  );

  const insidePrefixItems: JsonValue = { type: "array", prefixItems: [{ type: "string", "x-mcp-header": "Prefix" }] };
  assert.deepEqual(
    validateAnnotations(insidePrefixItems),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "An annotation under prefixItems must be unreachable.",
  );

  const insideUnevaluatedItems: JsonValue = { type: "array", unevaluatedItems: { type: "string", "x-mcp-header": "Unevaluated" } };
  assert.deepEqual(
    validateAnnotations(insideUnevaluatedItems),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "An annotation under unevaluatedItems must be unreachable.",
  );

  const underDefs: JsonValue = {
    type: "object",
    $defs: { Named: { type: "string", "x-mcp-header": "Named" } },
    properties: { p: { $ref: "#/$defs/Named" } },
  };
  assert.deepEqual(
    validateAnnotations(underDefs),
    { valid: false, reason: "annotation_not_statically_reachable" },
    "A $defs annotation reached through $ref must be unreachable.",
  );

  const propertiesNotObject: JsonValue = { type: "object", properties: 7 };
  assert.deepEqual(
    validateAnnotations(propertiesNotObject),
    { valid: true, reason: null },
    "A non-object properties member must collect no annotation.",
  );
  assert.deepEqual(
    projectArguments(propertiesNotObject, {}),
    { outcome: "headers", headers: [] },
    "A non-object properties member must project no header.",
  );

  const propertyNamedAnnotation: JsonValue = { allOf: [{ properties: { "x-mcp-header": { type: "string" } } }] };
  assert.deepEqual(
    validateAnnotations(propertyNamedAnnotation),
    { valid: true, reason: null },
    "A property named x-mcp-header under allOf is not an annotation.",
  );
});

test("annotations: the C5 rule order and tokens", () => {
  const cases: readonly (readonly [string, JsonValue, AnnotationReason])[] = [
    ["non-string name", schemaFor(7), "annotation_name_not_string"],
    ["empty name", schemaFor(""), "annotation_name_empty"],
    ["carriage return", schemaFor("a\rb"), "annotation_name_control"],
    ["line feed", schemaFor("a\nb"), "annotation_name_control"],
    ["NUL", schemaFor("a\u0000b"), "annotation_name_control"],
    ["DEL", schemaFor("a\u007fb"), "annotation_name_control"],
    ["space", schemaFor("a b"), "annotation_name_not_token"],
    ["colon", schemaFor("a:b"), "annotation_name_not_token"],
    ["at sign", schemaFor("a@b"), "annotation_name_not_token"],
    ["quote", schemaFor('a"b'), "annotation_name_not_token"],
    ["non-ASCII letter", schemaFor("é"), "annotation_name_not_token"],
    ["missing type", schemaFor("A"), "annotation_type_not_primitive"],
    ["number type value", schemaFor("A", 7), "annotation_type_not_primitive"],
    ["object type value", schemaFor("A", {}), "annotation_type_not_primitive"],
    ["array type value", schemaFor("A", ["string"]), "annotation_type_not_primitive"],
    ["null type value", schemaFor("A", null), "annotation_type_not_primitive"],
    ["list type value", schemaFor("A", ["string", "null"]), "annotation_type_not_primitive"],
    ["number type name", schemaFor("A", "number"), "annotation_type_not_primitive"],
    ["object type name", schemaFor("A", "object"), "annotation_type_not_primitive"],
    ["minimum below the bound", schemaFor("A", "integer", -SAFE_INT_MAX - 2), "annotation_integer_range_invalid"],
    [
      "maximum above the bound",
      schemaFor("A", "integer", undefined, SAFE_INT_MAX + 2),
      "annotation_integer_range_invalid",
    ],
  ];
  for (const [label, schema, reason] of cases) {
    assert.deepEqual(validateAnnotations(schema), { valid: false, reason }, label + ": the reason must match.");
  }

  const duplicate: JsonValue = {
    type: "object",
    properties: {
      first: { type: "string", "x-mcp-header": "Region" },
      second: { type: "object", properties: { third: { type: "integer", "x-mcp-header": "region" } } },
    },
  };
  assert.deepEqual(
    validateAnnotations(duplicate),
    { valid: false, reason: "annotation_name_duplicate" },
    "A case-insensitive duplicate must be refused.",
  );

  const orderFirst: JsonValue = {
    type: "object",
    properties: { ok: { type: "string", "x-mcp-header": "Ok" } },
    items: { type: "string", "x-mcp-header": "" },
  };
  assert.deepEqual(
    validateAnnotations(orderFirst),
    { valid: false, reason: "annotation_name_empty" },
    "The name rule must run before the reachability rule.",
  );

  const bounds: JsonValue = schemaFor("A", "integer", -SAFE_INT_MAX, SAFE_INT_MAX);
  assert.deepEqual(validateAnnotations(bounds), { valid: true, reason: null }, "The exact bounds must be valid.");
});

test("annotations: projection order, omission and refusal", () => {
  const schema: JsonValue = {
    type: "object",
    properties: {
      zeta: { type: "string", "x-mcp-header": "Zeta" },
      alpha: { type: "string", "x-mcp-header": "Alpha" },
      mid: { type: "integer", "x-mcp-header": "Mid" },
      outer: { type: "object", properties: { inner: { type: "string", "x-mcp-header": "Inner" } } },
    },
  };
  assert.deepEqual(
    projectArguments(schema, { zeta: "z", alpha: " spaced ", mid: 3 }),
    {
      outcome: "headers",
      headers: [
        ["Mcp-Param-Zeta", "z"],
        ["Mcp-Param-Alpha", "=?base64?IHNwYWNlZCA=?="],
        ["Mcp-Param-Mid", "3"],
      ],
    },
    "The headers must follow document order.",
  );

  const none = { outcome: "headers", headers: [] };
  assert.deepEqual(projectArguments(schema, {}), none, "Absent arguments must omit every header.");
  assert.deepEqual(
    projectArguments(schema, { zeta: null, alpha: null, mid: null, outer: null }),
    none,
    "Null values must omit every header.",
  );
  assert.deepEqual(projectArguments(schema, { outer: {} }), none, "A missing inner member must omit its header.");
  assert.deepEqual(projectArguments(schema, { outer: { inner: null } }), none, "A null intermediate must omit its header.");

  assert.deepEqual(
    projectArguments(schema, { mid: 7 }),
    { outcome: "headers", headers: [["Mcp-Param-Mid", "7"]] },
    "Only present arguments must be sent.",
  );

  const typed: JsonValue = {
    type: "object",
    properties: {
      count: { type: "integer", "x-mcp-header": "Count" },
      flag: { type: "boolean", "x-mcp-header": "Flag" },
      note: { type: "string", "x-mcp-header": "Note" },
    },
  };
  const mismatched: readonly JsonValue[] = [
    { count: "7" },
    { count: 1.5 },
    { count: SAFE_INT_MAX + 2 },
    { flag: "true" },
    { note: {} },
  ];
  for (const args of mismatched) {
    assert.deepEqual(
      projectArguments(typed, args),
      { outcome: "refuse", reason: PROJECTION_REASON },
      "A mismatched argument must refuse the request.",
    );
  }
});

test("annotations: catalog filtering", () => {
  const goodTool: JsonValue = {
    name: "good",
    inputSchema: { type: "object", properties: { a: { type: "string", "x-mcp-header": "A" } } },
  };
  const badTool: JsonValue = { name: "bad", inputSchema: { type: "object", "x-mcp-header": "Root" } };
  const unnamedTool: JsonValue = { inputSchema: { type: "object", properties: { a: { "x-mcp-header": 7 } } } };
  const noSchemaTool: JsonValue = { name: "noSchema" };
  const tools: readonly JsonValue[] = [goodTool, badTool, unnamedTool, 42, noSchemaTool, null];

  const excludedTools: [string, AnnotationReason][] = [];
  const keptTools = filterToolDefinitions(tools, (name, reason) => {
    excludedTools.push([name, reason]);
  });
  assert.deepEqual(keptTools, [goodTool, 42, noSchemaTool, null], "Only invalid tools must be dropped.");
  assert.deepEqual(
    excludedTools,
    [
      ["bad", "annotation_not_statically_reachable"],
      ["", "annotation_name_not_string"],
    ],
    "The excluded tools must be reported in input order.",
  );

  const goodEvent: JsonValue = {
    name: "ready",
    inputSchema: { type: "object", properties: { kind: { type: "integer", "x-mcp-header": "Kind" } } },
  };
  const duplicateEvent: JsonValue = {
    name: "broken",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "string", "x-mcp-header": "Kind" },
        b: { type: "string", "x-mcp-header": "kind" },
      },
    },
  };
  const excludedEvents: [string, AnnotationReason][] = [];
  const keptEvents = filterEventTypes([goodEvent, duplicateEvent, 7], (name, reason) => {
    excludedEvents.push([name, reason]);
  });
  assert.deepEqual(keptEvents, [goodEvent, 7], "Only invalid event types must be dropped.");
  assert.deepEqual(excludedEvents, [["broken", "annotation_name_duplicate"]], "The excluded event must be reported.");
});

test("annotations: a cyclic schema terminates", () => {
  const node: { [key: string]: JsonValue } = {};
  node["properties"] = { self: node as unknown as JsonValue };
  assert.equal(validateAnnotations(node as unknown as JsonValue).valid, true, "A cyclic schema must not loop.");
  assert.deepEqual(
    projectArguments(node as unknown as JsonValue, {}),
    { outcome: "headers", headers: [] },
    "A cyclic schema must project no headers.",
  );
});
