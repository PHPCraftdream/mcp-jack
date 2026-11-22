// Reference implementation of the server rules of spec 04 section 5 (S1-S12).
// The era decision (S3) runs first; every other rule runs only in the modern era.
// The request is already authenticated (01 section 4) and its body already
// acceptable under 02 section 2, so anything else is a caller bug, not an outcome.
import { META_VERSION_KEY, MODERN_MIN, NAME_SOURCE, REASONS } from '../spec-data.mjs';
import { compareVersion, decodeHeaderValue, isFieldValue, isVersion } from './values.mjs';

const MIRROR_NAMES = ['mcp-protocol-version', 'mcp-method', 'mcp-name'];
const PARAM_PREFIX = 'mcp-param-';

const lower = (name) => name.toLowerCase();
const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isModernSignal = (value) => value !== null && isVersion(value) && compareVersion(value, MODERN_MIN) >= 0;

// M: the version member of params._meta only; a root-level _meta is never a mirror.
function metaVersion(body, bodyKind) {
  if (bodyKind !== 'request' && bodyKind !== 'notification') return null;
  if (!isPlainObject(body.params) || !isPlainObject(body.params._meta)) return null;
  const value = body.params._meta[META_VERSION_KEY];
  return typeof value === 'string' ? value : null;
}

export function classifyRequest({ profile, request }) {
  const find = (name) => request.headers.filter(([n]) => lower(n) === name);
  // S10: a refusal is a signed JSON-RPC error with Content-Type application/json.
  const refuse = (reason, era, id) => {
    const entry = REASONS[reason];
    return {
      outcome: 'refuse', era, signed: true,
      http_status: entry.http_status, content_type: 'application/json',
      jsonrpc: '2.0', id, error: { code: entry.jsonrpc_code, message: entry.message },
      consumes_nonce: true,
    };
  };
  const forward = (era, headers) => ({
    outcome: 'forward', era,
    forward: { method: request.method, target: request.target, headers },
    consumes_nonce: true,
  });

  let body = null;
  if (typeof request.body_text === 'string') {
    let parsed;
    try {
      parsed = JSON.parse(request.body_text);
    } catch {
      parsed = null;
    }
    if (!isPlainObject(parsed)) {
      throw new Error('classifyRequest: body is not an acceptable JSON-RPC object');
    }
    body = parsed;
  }

  let bodyKind = null;
  if (body !== null) {
    if (typeof body.method !== 'string') bodyKind = 'response';
    else if (typeof body.id === 'string' || typeof body.id === 'number') bodyKind = 'request';
    else bodyKind = 'notification';
  }
  const requestId = bodyKind === 'request' ? body.id : null;

  // S3 runs first: any well-formed modern version in a header instance or in the
  // signed _meta version selects the modern era. Ambiguity never buys the legacy
  // path, so a repeated header counts when any of its values is modern.
  const versionValues = find('mcp-protocol-version').map(([, value]) => value);
  const M = metaVersion(body, bodyKind);
  let era;
  if (profile === 'legacy') era = 'legacy';
  else if (profile === 'modern') era = 'modern';
  else era = versionValues.some(isModernSignal) || isModernSignal(M) ? 'modern' : 'legacy';

  // Legacy era: 01 and 02 apply byte-identically, no section 5 rule runs (S1
  // included), so the header list is forwarded unfiltered.
  if (era === 'legacy') return forward('legacy', request.headers);

  if (bodyKind === null && request.method === 'POST') {
    // A POST always has a body: 02 section 2 refuses an unacceptable one first.
    throw new Error('classifyRequest: modern era requires a classified body');
  }

  // S1: header syntax, modern era only.
  for (const name of MIRROR_NAMES) {
    if (find(name).length > 1) return refuse('header_repeated', era, requestId);
  }
  for (const [n, value] of request.headers) {
    const name = lower(n);
    // 'mcp-param-' alone has an empty {Name}, so it is not a recognised header.
    const recognisedParam = name.startsWith(PARAM_PREFIX) && name.length > PARAM_PREFIX.length;
    if (!MIRROR_NAMES.includes(name) && !recognisedParam) continue;
    if (!isFieldValue(value)) return refuse('header_value_invalid', era, requestId);
  }

  // S2: only POST is defined by the modern era.
  if (request.method !== 'POST') return refuse('method_not_allowed', era, null);

  const isRequest = bodyKind === 'request';

  // S12: a client-sent response object has no mirror obligation.
  if (bodyKind !== 'response') {
    const versions = find('mcp-protocol-version');
    if (versions.length === 0) {
      if (isRequest) return refuse('version_header_missing', era, requestId);
    } else {
      const header = versions[0][1];
      if (!isVersion(header)) return refuse('version_header_malformed', era, requestId);
      if (M === null) return refuse('version_meta_missing', era, requestId);
      if (header !== M) return refuse('version_mismatch', era, requestId);
    }

    const methods = find('mcp-method');
    if (methods.length === 0) {
      if (isRequest) return refuse('method_header_missing', era, requestId);
    } else if (methods[0][1] !== body.method) {
      return refuse('method_header_mismatch', era, requestId);
    }

    // S6: the source table is closed, so a method without a row must not carry
    // the header; Object.hasOwn keeps prototype names from matching a row.
    const names = find('mcp-name');
    const sourceKey = Object.hasOwn(NAME_SOURCE, body.method) ? NAME_SOURCE[body.method] : null;
    if (sourceKey === null) {
      if (names.length > 0) return refuse('name_header_not_applicable', era, requestId);
    } else {
      const sourceValue = body.params?.[sourceKey];
      // The mirror cannot be validated without a string source value.
      if (typeof sourceValue !== 'string') return refuse('name_source_missing', era, requestId);
      if (names.length === 0) {
        if (isRequest) return refuse('name_header_missing', era, requestId);
      } else {
        const decoded = decodeHeaderValue(names[0][1]);
        if (!decoded.ok) return refuse('name_header_bad_encoding', era, requestId);
        if (decoded.text !== sourceValue) return refuse('name_header_mismatch', era, requestId);
      }
    }
  }

  // S8: session and resume headers never reach the handler in the modern era.
  const forwardHeaders = request.headers.filter(([n]) => {
    const name = lower(n);
    return name !== 'mcp-session-id' && name !== 'last-event-id';
  });
  // S9: everything else forwarded unchanged, casing and order preserved.
  return forward('modern', forwardHeaders);
}
