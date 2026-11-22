// Reference implementation of the client rules of spec 04 section 6 (C5, C6, C9).
import { META_VERSION_KEY, MODERN_ERA_ERROR_CODES, NAME_SOURCE, PROJECTION_REASON, SAFE_INT_MAX } from '../spec-data.mjs';
import { encodeHeaderValue, isToken, textOfValue } from './values.mjs';

const ANNOTATION_KEY = 'x-mcp-header';
const NAME_MAP_KEYWORDS = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);

const isObj = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// A path is statically reachable iff it alternates properties -> name pairs from
// the schema root (any other segment, an odd length or the root itself is not).
// An empty property name is legal. Returns the property names along that chain.
function staticPropertyPath(path) {
  if (path.length < 2 || path.length % 2 !== 0) return null;
  for (let i = 0; i < path.length; i += 2) {
    if (path[i] !== 'properties') return null;
  }
  return path.filter((_, i) => i % 2 === 1);
}

const hasControl = (s) => {
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || cp === 0x7f) return true;
  }
  return false;
};

// Structural traversal: the recursion carries whether the current node is a
// schema (its members are keywords) or a name map (its members are property,
// pattern or definition names). A member named x-mcp-header is an annotation only
// in a schema node, so a property that is itself named "properties" keeps its own
// annotation and a property named "x-mcp-header" is never an annotation keyword.
export function collectAnnotations(inputSchema) {
  const out = [];
  const push = (node, path) => out.push({ path, propPath: staticPropertyPath(path), node, name: node[ANNOTATION_KEY] });

  function walkValue(node, path) {
    if (Array.isArray(node)) {
      node.forEach((child, index) => walkValue(child, [...path, String(index)]));
      return;
    }
    if (!isObj(node)) return;
    for (const key of Object.keys(node)) {
      if (key === ANNOTATION_KEY) push(node, path);
      else walkValue(node[key], [...path, key]);
    }
  }

  function walkNameMap(node, path) {
    if (!isObj(node)) return;
    for (const name of Object.keys(node)) walkSchema(node[name], [...path, name]);
  }

  function walkSchema(node, path) {
    if (!isObj(node)) return;
    for (const key of Object.keys(node)) {
      if (key === ANNOTATION_KEY) push(node, path);
      else if (NAME_MAP_KEYWORDS.has(key)) walkNameMap(node[key], [...path, key]);
      else walkValue(node[key], [...path, key]);
    }
  }

  walkSchema(inputSchema, []);
  return out;
}

// C5, fixed rule order: each rule scans every annotation in document order and
// the first hit of the first failing rule is reported.
export function validateAnnotations(inputSchema) {
  const annotations = collectAnnotations(inputSchema);
  const fail = (reason) => ({ valid: false, reason });
  for (const a of annotations) if (typeof a.name !== 'string') return fail('annotation_name_not_string');
  for (const a of annotations) if (a.name === '') return fail('annotation_name_empty');
  for (const a of annotations) if (hasControl(a.name)) return fail('annotation_name_control');
  for (const a of annotations) if (!isToken(a.name)) return fail('annotation_name_not_token');
  const seen = new Set();
  for (const a of annotations) {
    const folded = a.name.toLowerCase();
    if (seen.has(folded)) return fail('annotation_name_duplicate');
    seen.add(folded);
  }
  for (const a of annotations) if (a.propPath === null) return fail('annotation_not_statically_reachable');
  for (const a of annotations) {
    if (a.node.type !== 'string' && a.node.type !== 'integer' && a.node.type !== 'boolean') {
      return fail('annotation_type_not_primitive');
    }
  }
  for (const a of annotations) {
    if (a.node.type !== 'integer') continue;
    const min = a.node.minimum;
    const max = a.node.maximum;
    if ((typeof min === 'number' && min < -SAFE_INT_MAX) || (typeof max === 'number' && max > SAFE_INT_MAX)) {
      return fail('annotation_integer_range_invalid');
    }
  }
  return { valid: true, reason: null };
}

const isContainer = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// Walks the arguments along propPath; absent or null anywhere omits the header.
function readPath(args, propPath) {
  let current = args;
  for (const name of propPath) {
    if (!isContainer(current) || !Object.hasOwn(current, name)) return { present: false };
    current = current[name];
  }
  return current === undefined || current === null ? { present: false } : { present: true, value: current };
}

// C6: the caller has already run validateAnnotations; this only projects.
export function projectArguments(inputSchema, args) {
  const headers = [];
  for (const annotation of collectAnnotations(inputSchema)) {
    if (annotation.propPath === null) continue;
    const found = readPath(args, annotation.propPath);
    if (!found.present) continue;
    const text = textOfValue(found.value, annotation.node.type);
    if (text === null) return { outcome: 'refuse', reason: PROJECTION_REASON };
    headers.push(['Mcp-Param-' + annotation.name, encodeHeaderValue(text)]);
  }
  return { outcome: 'headers', headers };
}

// A body that is missing, empty, non-JSON or not an object carries no signal.
function parseBody(text) {
  if (typeof text !== 'string' || text.trim() === '') return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
}

const errorOf = (body) => (isContainer(body) && isContainer(body.error) ? body.error : null);

// A recognised JSON-RPC error: jsonrpc "2.0", an id member (null allowed) and an
// error object with an integer code and a string message. Anything else is not
// a signal: a bare {"error":{"code":...}} object is what a legacy endpoint or an
// intermediary can produce.
function recognisedError(text) {
  const body = parseBody(text);
  if (body === null || body.jsonrpc !== '2.0') return null;
  if (!Object.hasOwn(body, 'id')) return null;
  const idType = typeof body.id;
  if (!(body.id === null || idType === 'string' || idType === 'number')) return null;
  const error = errorOf(body);
  if (error === null || !Number.isInteger(error.code) || typeof error.message !== 'string') return null;
  return error;
}

// C9: era detection from the verified response only.
export function detectEra({ response, clientVersions = [] }) {
  if (response.verified !== true) return { era: 'none', action: 'abort', reason: 'unverified' };
  const status = response.status;
  if (status >= 200 && status <= 299) return { era: 'modern', action: 'stay_modern', reason: null };
  if (status === 400) {
    const error = recognisedError(response.body_text);
    if (error !== null && MODERN_ERA_ERROR_CODES.includes(error.code)) {
      if (error.code !== -32022) return { era: 'modern', action: 'stay_modern', reason: null };
      const supported = error.data?.supported;
      // A usable list is an array whose elements are all strings; a mixed array, a
      // non-array, an empty array or a missing member is not usable at all.
      const usable = Array.isArray(supported) && supported.every((version) => typeof version === 'string');
      const mutual = usable ? supported.filter((version) => clientVersions.includes(version)) : [];
      if (mutual.length > 0) return { era: 'modern', action: 'retry_with_supported', reason: null, supported: mutual };
      return { era: 'modern', action: 'abort', reason: 'unsupported_version_no_overlap' };
    }
    const body = parseBody(response.body_text);
    // Jack's own envelope has no jsonrpc member at all; a body that carries one
    // (any value, including "1.0") is not Jack's envelope.
    const jackEnvelope = isContainer(body) && isContainer(body.error)
      && typeof body.error.code === 'string' && !Object.hasOwn(body, 'jsonrpc');
    return { era: 'legacy', action: 'fallback_initialize', reason: jackEnvelope ? 'jack_envelope' : 'no_modern_error' };
  }
  if (status === 404) {
    const error = recognisedError(response.body_text);
    if (error !== null && error.code === -32601) {
      return { era: 'modern', action: 'stay_modern', reason: 'modern_method_not_found' };
    }
    return { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' };
  }
  if (status === 405) return { era: 'legacy', action: 'fallback_initialize', reason: 'no_modern_error' };
  return { era: 'none', action: 'abort', reason: 'no_era_signal' };
}

// C1 and C2: the request `_meta` and its mirror headers in C2 order. An Mcp-Name
// source field whose body value is not a string is a caller bug, not a skip.
export function buildMirrors({ version, method, params = {} }) {
  const meta = { [META_VERSION_KEY]: version, 'io.modelcontextprotocol/clientCapabilities': {} };
  const headers = [['MCP-Protocol-Version', version], ['Mcp-Method', method]];
  const sourceKey = Object.hasOwn(NAME_SOURCE, method) ? NAME_SOURCE[method] : null;
  if (sourceKey === 'name' || sourceKey === 'uri') {
    if (typeof params[sourceKey] !== 'string') {
      throw new Error('buildMirrors: params.' + sourceKey + ' must be a string for ' + method);
    }
    headers.push(['Mcp-Name', encodeHeaderValue(params[sourceKey])]);
  }
  return { meta, headers };
}
