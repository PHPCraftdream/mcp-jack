/**
 * `x-mcp-header` rules of the modern profile of spec 04 section 6: C5 validation
 * of a tool definition's annotation set, C6 projection of the arguments into
 * `Mcp-Param-*` headers, and the C11 reuse of exactly the same two rules for
 * event type descriptors. Port of `collectAnnotations`, `validateAnnotations`
 * and `projectArguments` in
 * `spec/tools/modern/headers/reference/client.mjs`, plus the per-entry filtering
 * the client applies to a `tools/list` or `events/list` result.
 */

import type { JsonValue } from "../core/json-raw.js";
import { encodeHeaderValue, isToken, valueText, SAFE_INT_MAX } from "./values.js";
import type { HeaderPair } from "./values.js";

/** The schema keyword that names a header parameter: a string value in a property schema becomes `Mcp-Param-{value}` (spec 04 section 6, C5). */
export const ANNOTATION_KEY = "x-mcp-header";

/** The closed reason list of C5: the first rule of the fixed order that any annotation violates is the one reported. */
export type AnnotationReason =
  | "annotation_name_not_string"
  | "annotation_name_empty"
  | "annotation_name_control"
  | "annotation_name_not_token"
  | "annotation_name_duplicate"
  | "annotation_type_not_primitive"
  | "annotation_integer_range_invalid"
  | "annotation_not_statically_reachable";

/** The C5 reasons in rule order, which is also the order of the spec's reason table. */
export const ANNOTATION_REASONS: readonly AnnotationReason[] = [
  "annotation_name_not_string",
  "annotation_name_empty",
  "annotation_name_control",
  "annotation_name_not_token",
  "annotation_name_duplicate",
  "annotation_type_not_primitive",
  "annotation_integer_range_invalid",
  "annotation_not_statically_reachable",
];

/** The outcome of C5: valid, or the single reason that excludes the definition; `reason` is null exactly when `valid` is true. */
export interface AnnotationValidation {
  readonly valid: boolean;
  readonly reason: AnnotationReason | null;
}

/**
 * The one client-side error of C6 and C11: the argument value does not match the
 * annotated type, so the request must not be sent at all (spec 04 section 6).
 */
export const PROJECTION_REASON = "header_projection_invalid_value";

/** The outcome of C6: the headers to add in document order (possibly none), or the refusal to send because a value does not fit its annotated type. */
export type ProjectionOutcome =
  | { readonly outcome: "headers"; readonly headers: readonly HeaderPair[] }
  | { readonly outcome: "refuse"; readonly reason: typeof PROJECTION_REASON };

/** A JSON object: the object member of `JsonValue`, viewed through a read-only walk. */
type JsonObject = { [key: string]: JsonValue };

/** One collected annotation: where it sits, the schema node that owns it, its value and its statically reachable property chain. */
interface AnnotationEntry {
  /** Member names from the schema root to the owning schema node (array indices as decimal strings). */
  readonly path: readonly string[];
  /** The property names of the reachable chain in order, or null when the path is not statically reachable. */
  readonly propPath: readonly string[] | null;
  /** The schema node that carries the keyword. */
  readonly node: JsonObject;
  /** The raw keyword value; a non-string fails C5. */
  readonly name: JsonValue | undefined;
}

/** A path is statically reachable iff it alternates properties -> name pairs from the schema root (any other segment, an odd length or the root itself is not). An empty property name is legal. Returns the property names along that chain. */
function staticPropertyPath(path: readonly string[]): readonly string[] | null {
  if (path.length < 2 || path.length % 2 !== 0) return null;
  const names: string[] = [];
  for (let i = 0; i < path.length; i += 2) {
    if (path[i] !== "properties") return null;
    const name = path[i + 1];
    if (name === undefined) return null;
    names.push(name);
  }
  return names;
}

/** True when the string holds a code point below 0x20 or exactly 0x7f, both of which a header name cannot carry. */
function hasControl(s: string): boolean {
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && (cp < 0x20 || cp === 0x7f)) return true;
  }
  return false;
}

/** True for a JSON object (not null, not an array). */
function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Keywords whose value is a name map: its members are property, pattern, definition or schema names, never keywords. */
const NAME_MAP_KEYWORDS: ReadonlySet<string> = new Set([
  "properties",
  "patternProperties",
  "$defs",
  "definitions",
  "dependentSchemas",
]);

/** Keywords whose value is a schema or an array of schemas; a schema reached through one of them is still a schema, so its members are keywords. */
const SCHEMA_KEYWORDS: ReadonlySet<string> = new Set([
  "allOf",
  "anyOf",
  "oneOf",
  "not",
  "if",
  "then",
  "else",
  "items",
  "prefixItems",
  "contains",
  "additionalProperties",
  "additionalItems",
  "propertyNames",
  "unevaluatedProperties",
  "unevaluatedItems",
]);

/**
 * Structural traversal of an `inputSchema` in depth-first document order. The
 * recursion carries whether the current node is a schema (its members are
 * keywords) or a name map (its members are names): only the value of a name-map
 * keyword is a name map, the value of an applicator keyword is a schema again,
 * and any other keyword's value is walked as plain JSON (arrays element-wise),
 * so an annotation in an unknown position is still collected and then fails the
 * reachability rule. A member named `x-mcp-header` is an annotation only in a
 * schema node.
 */
function collectAnnotations(inputSchema: JsonValue | undefined): AnnotationEntry[] {
  const out: AnnotationEntry[] = [];
  // A JSON value from JSON.parse cannot be cyclic, but the type allows a cycle
  // and the walk must terminate, so every object and array is entered once.
  const visited = new Set<object>();
  const firstVisit = (value: object): boolean => {
    if (visited.has(value)) return false;
    visited.add(value);
    return true;
  };

  const push = (node: JsonObject, path: readonly string[]): void => {
    out.push({ path, propPath: staticPropertyPath(path), node, name: node[ANNOTATION_KEY] });
  };

  const walkValue = (node: JsonValue | undefined, path: readonly string[]): void => {
    if (Array.isArray(node)) {
      if (!firstVisit(node)) return;
      for (let i = 0; i < node.length; i++) walkValue(node[i], [...path, String(i)]);
      return;
    }
    if (!isJsonObject(node) || !firstVisit(node)) return;
    for (const key of Object.keys(node)) {
      if (key === ANNOTATION_KEY) push(node, path);
      else walkValue(node[key], [...path, key]);
    }
  };

  // The value of an applicator keyword is a schema, or an array of schemas.
  const walkSubschema = (node: JsonValue | undefined, path: readonly string[]): void => {
    if (Array.isArray(node)) {
      if (!firstVisit(node)) return;
      for (let i = 0; i < node.length; i++) walkSubschema(node[i], [...path, String(i)]);
      return;
    }
    walkSchema(node, path);
  };

  const walkNameMap = (node: JsonValue | undefined, path: readonly string[]): void => {
    if (!isJsonObject(node) || !firstVisit(node)) return;
    for (const name of Object.keys(node)) walkSchema(node[name], [...path, name]);
  };

  const walkSchema = (node: JsonValue | undefined, path: readonly string[]): void => {
    if (!isJsonObject(node) || !firstVisit(node)) return;
    for (const key of Object.keys(node)) {
      if (key === ANNOTATION_KEY) push(node, path);
      else if (NAME_MAP_KEYWORDS.has(key)) walkNameMap(node[key], [...path, key]);
      else if (SCHEMA_KEYWORDS.has(key)) walkSubschema(node[key], [...path, key]);
      else walkValue(node[key], [...path, key]);
    }
  };

  walkSchema(inputSchema, []);
  return out;
}

/**
 * C5: validate every `x-mcp-header` annotation of a tool or event type
 * `inputSchema`. Rules apply in a fixed order and each rule scans every
 * annotation in document order, so the first hit of the first failing rule is
 * reported; with no hit at all the definition is valid.
 */
export function validateAnnotations(inputSchema: JsonValue | undefined): AnnotationValidation {
  const annotations = collectAnnotations(inputSchema);
  const fail = (reason: AnnotationReason): AnnotationValidation => ({ valid: false, reason });
  for (const a of annotations) if (typeof a.name !== "string") return fail("annotation_name_not_string");
  for (const a of annotations) if (a.name === "") return fail("annotation_name_empty");
  for (const a of annotations) {
    if (typeof a.name !== "string") continue;
    if (hasControl(a.name)) return fail("annotation_name_control");
  }
  for (const a of annotations) {
    if (typeof a.name !== "string") continue;
    if (!isToken(a.name)) return fail("annotation_name_not_token");
  }
  const seen = new Set<string>();
  for (const a of annotations) {
    // The first loop already failed on a non-string name, so skipping repeats it.
    if (typeof a.name !== "string") continue;
    const folded = a.name.toLowerCase();
    if (seen.has(folded)) return fail("annotation_name_duplicate");
    seen.add(folded);
  }
  for (const a of annotations) if (a.propPath === null) return fail("annotation_not_statically_reachable");
  for (const a of annotations) {
    if (a.node["type"] !== "string" && a.node["type"] !== "integer" && a.node["type"] !== "boolean") {
      return fail("annotation_type_not_primitive");
    }
  }
  for (const a of annotations) {
    if (a.node["type"] !== "integer") continue;
    const min = a.node["minimum"];
    const max = a.node["maximum"];
    if ((typeof min === "number" && min < -SAFE_INT_MAX) || (typeof max === "number" && max > SAFE_INT_MAX)) {
      return fail("annotation_integer_range_invalid");
    }
  }
  return { valid: true, reason: null };
}

/** The result of reading the arguments along a property chain: absent or null anywhere omits the header. */
type PathRead = { readonly present: true; readonly value: JsonValue } | { readonly present: false };

/** Walks `args` along the property names; a missing member or a null anywhere omits the header. */
function readPath(args: JsonValue | undefined, propPath: readonly string[]): PathRead {
  let current: JsonValue | undefined = args;
  for (const name of propPath) {
    if (!isJsonObject(current) || !Object.hasOwn(current, name)) return { present: false };
    current = current[name];
  }
  return current === undefined || current === null ? { present: false } : { present: true, value: current };
}

/** The annotated type as a string for `valueText`; C6 runs after C5, and any other type keeps refusing the value. */
function typeNameOf(node: JsonObject): string {
  const type = node["type"];
  return typeof type === "string" ? type : "";
}

/**
 * C6: project the arguments of a call of a definition that passed C5 into its
 * `Mcp-Param-*` headers, in document order. An unreachable annotation is
 * skipped, an absent or null argument omits its header, and a value that does
 * not match the annotated type refuses the whole request.
 */
export function projectArguments(inputSchema: JsonValue | undefined, args: JsonValue | undefined): ProjectionOutcome {
  const headers: HeaderPair[] = [];
  for (const annotation of collectAnnotations(inputSchema)) {
    if (annotation.propPath === null) continue;
    const found = readPath(args, annotation.propPath);
    if (!found.present) continue;
    const text = valueText(found.value, typeNameOf(annotation.node));
    if (text === null) return { outcome: "refuse", reason: PROJECTION_REASON };
    headers.push(["Mcp-Param-" + String(annotation.name), encodeHeaderValue(text)]);
  }
  return { outcome: "headers", headers };
}

/**
 * Shared body of C5 and C11 filtering: validate each entry's `inputSchema` and
 * drop the invalid entries, reporting the entry name (empty when it is not a
 * string) and the reason through `onExcluded`. Non-object entries and objects
 * without an `inputSchema` pass unchanged, in input order.
 */
function filterByAnnotation(
  entries: readonly JsonValue[],
  onExcluded: ((name: string, reason: AnnotationReason) => void) | undefined,
): JsonValue[] {
  const kept: JsonValue[] = [];
  for (const entry of entries) {
    if (!isJsonObject(entry)) {
      kept.push(entry);
      continue;
    }
    const inputSchema = Object.hasOwn(entry, "inputSchema") ? entry["inputSchema"] : undefined;
    const validation = validateAnnotations(inputSchema);
    if (validation.valid) {
      kept.push(entry);
      continue;
    }
    const reason = validation.reason;
    if (onExcluded !== undefined && reason !== null) {
      const name = entry["name"];
      onExcluded(typeof name === "string" ? name : "", reason);
    }
  }
  return kept;
}

/** C5: the tools of a `tools/list` result that keep a valid annotation set, in input order; `onExcluded` receives the tool name and the reason. */
export function filterToolDefinitions(
  tools: readonly JsonValue[],
  onExcluded?: (name: string, reason: AnnotationReason) => void,
): JsonValue[] {
  return filterByAnnotation(tools, onExcluded);
}

/** C11: the event types of an `events/list` result that keep a valid annotation set, in input order; `onExcluded` receives the event name and the reason. */
export function filterEventTypes(
  eventTypes: readonly JsonValue[],
  onExcluded?: (name: string, reason: AnnotationReason) => void,
): JsonValue[] {
  return filterByAnnotation(eventTypes, onExcluded);
}
