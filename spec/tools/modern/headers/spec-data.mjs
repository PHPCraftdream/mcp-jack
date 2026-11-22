// Data tables transcribed from spec/04-modern-profile.md. Pure data, no logic.

export const MODERN_MIN = '2026-07-28';

// reason token -> { rule, http_status, jsonrpc_code, message }. Messages are
// verbatim from section 5.1: fixed strings, no trailing period, no echoed value.
export const REASONS = {
  method_not_allowed: {
    rule: 'S2', http_status: 405, jsonrpc_code: -32600,
    message: 'HTTP method not allowed',
  },
  header_value_invalid: {
    rule: 'S1', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax',
  },
  header_repeated: {
    rule: 'S1', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: a request metadata header appears more than once',
  },
  version_header_missing: {
    rule: 'S4', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version is missing',
  },
  version_header_malformed: {
    rule: 'S4', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version is malformed',
  },
  version_meta_missing: {
    rule: 'S4', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: params._meta protocolVersion is missing',
  },
  version_mismatch: {
    rule: 'S4', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion',
  },
  method_header_missing: {
    rule: 'S5', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Method is missing',
  },
  method_header_mismatch: {
    rule: 'S5', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Method does not match the body method',
  },
  name_header_not_applicable: {
    rule: 'S6', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Name is not defined for this method',
  },
  name_source_missing: {
    rule: 'S6', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: the body has no string value for the Mcp-Name source field',
  },
  name_header_missing: {
    rule: 'S6', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Name is missing',
  },
  name_header_bad_encoding: {
    rule: 'S6', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Name is not a valid base64 sentinel encoding',
  },
  name_header_mismatch: {
    rule: 'S6', http_status: 400, jsonrpc_code: -32020,
    message: 'Header mismatch: Mcp-Name does not match the body value',
  },
};

// Verification order of the server rules as implemented (ids only).
export const SERVER_ORDER = ['S3', 'S1', 'S2', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12'];

// Closed list of x-mcp-header validation reasons (spec C5).
export const ANNOTATION_REASONS = [
  'annotation_name_not_string',
  'annotation_name_empty',
  'annotation_name_control',
  'annotation_name_not_token',
  'annotation_name_duplicate',
  'annotation_type_not_primitive',
  'annotation_integer_range_invalid',
  'annotation_not_statically_reachable',
];

export const PROJECTION_REASON = 'header_projection_invalid_value';

// method -> 'name' | 'uri' | null: the Mcp-Name source field per method (spec S6).
export const NAME_SOURCE = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'events/poll': 'name',
  'events/stream': 'name',
  'events/subscribe': 'name',
  'events/unsubscribe': 'name',
  'resources/read': 'uri',
};

// Every numbered rule of spec 04. A rule is either mapped to at least one vector
// or listed in EXEMPT_RULES with the SDK test that carries it (spec section 8).
export const ALL_RULES = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'C10', 'C11', 'C12'];

export const EXEMPT_RULES = {
  C7: 'native jack.* result shape is SDK behaviour; M1 test native_result_era_shape',
  C8: 'cache binding is the 01 section 5 request-sig binding; cache-replay by-reference entry and M1 test client_cache_private_only',
  C10: 'SHOULD-only retry flow; M1 test client_header_resync',
  C12: 'SHOULD-only events retry flow; M1 test client_events_resync',
};

export const VECTOR_RULES = ALL_RULES.filter((rule) => !Object.hasOwn(EXEMPT_RULES, rule));
export const NON_VECTOR_RULES = Object.keys(EXEMPT_RULES);

export const ERA_ACTIONS = ['stay_modern', 'fallback_initialize', 'retry_with_supported', 'abort'];
export const ERA_REASONS = ['unverified', 'no_modern_error', 'jack_envelope', 'modern_method_not_found', 'unsupported_version_no_overlap', 'no_era_signal'];
export const MODERN_ERA_ERROR_CODES = [-32020, -32021, -32022];

// spec 02 section 2 item 4: a tools/call body whose params.name is not a string is
// refused at body classification, before the era decision, in the spec 01
// section 4 envelope. The response is signed (01 section 5). The message is
// fixed here so every implementation emits the same bytes.
export const CLASSIFICATION_REFUSAL = {
  http_status: 400,
  code: 'invalid_request',
  message: 'tools/call requires a string params.name',
};
export const SAFE_INT_MAX = 9007199254740991; // 2^53 - 1

export const META_VERSION_KEY = 'io.modelcontextprotocol/protocolVersion';
