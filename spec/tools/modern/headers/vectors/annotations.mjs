// C5, C6 and C11 vectors of spec 04 section 6. Data only: no build, no I/O, no
// clock, no randomness. Every invalid validation case violates exactly one
// constraint: all other annotations in its schema are valid, and the annotation
// node's own type is primitive unless the type rule is the one under test.
import { ANNOTATION_REASONS, PROJECTION_REASON } from '../spec-data.mjs';
import { encodeHeaderValue } from '../reference.mjs';

// Values that need a sentinel are encoded here, never typed by hand.
const ENC_REGION_JA = encodeHeaderValue('us west1/日本');

export const ANNOTATION_CASES = [
  // C5: definitions the client keeps.
  {
    id: 'ann-valid-string', rule: 'C5', kind: 'validate',
    description: 'a string property annotated with a token name is valid',
    tool: { name: 'execute_sql', inputSchema: {
      properties: { region: { type: 'string', description: 'The region', 'x-mcp-header': 'Region' } },
      required: ['region'],
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-integer', rule: 'C5', kind: 'validate',
    description: 'an integer property is a valid annotation target',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-boolean', rule: 'C5', kind: 'validate',
    description: 'a boolean property is a valid annotation target',
    tool: { name: 'deploy', inputSchema: { properties: { dryRun: { type: 'boolean', 'x-mcp-header': 'DryRun' } } } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-none', rule: 'C5', kind: 'validate',
    description: 'a schema without annotations is valid',
    tool: { name: 'search', inputSchema: { type: 'object', properties: { query: { type: 'string' } } } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-nested', rule: 'C5', kind: 'validate',
    description: 'an annotation behind a chain of properties members is valid',
    tool: { name: 'list_zones', inputSchema: {
      properties: { filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'Zone' } } } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-three', rule: 'C5', kind: 'validate',
    description: 'three distinct annotations of each primitive type are valid',
    tool: { name: 'inventory', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        tenant: { type: 'integer', 'x-mcp-header': 'Tenant' },
        zone: { type: 'boolean', 'x-mcp-header': 'Zone' },
      },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-ref-sibling', rule: 'C5', kind: 'validate',
    description: 'an annotation next to a $ref is validated at the property, not the target',
    tool: { name: 'resolve', inputSchema: {
      properties: { region: { type: 'string', $ref: '#/$defs/Region', 'x-mcp-header': 'Region' } },
      $defs: { Region: { type: 'string' } },
    } },
    expect: { valid: true, reason: null },
  },

  // C5: name constraints.
  {
    id: 'ann-name-not-number', rule: 'C5', kind: 'validate',
    description: 'a numeric annotation value is not a string',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 42 } } } },
    expect: { valid: false, reason: 'annotation_name_not_string' },
  },
  {
    id: 'ann-name-not-null', rule: 'C5', kind: 'validate',
    description: 'a null annotation value is not a string',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': null } } } },
    expect: { valid: false, reason: 'annotation_name_not_string' },
  },
  {
    id: 'ann-name-empty', rule: 'C5', kind: 'validate',
    description: 'an empty annotation value has no name',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': '' } } } },
    expect: { valid: false, reason: 'annotation_name_empty' },
  },
  {
    id: 'ann-name-cr', rule: 'C5', kind: 'validate',
    description: 'a CR inside the annotation value is a control byte',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Reg\rition' } } } },
    expect: { valid: false, reason: 'annotation_name_control' },
  },
  {
    id: 'ann-name-lf', rule: 'C5', kind: 'validate',
    description: 'an LF inside the annotation value is a control byte',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Reg\nion' } } } },
    expect: { valid: false, reason: 'annotation_name_control' },
  },
  {
    id: 'ann-name-nul', rule: 'C5', kind: 'validate',
    description: 'a NUL inside the annotation value is a control byte',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Reg\u0000ion' } } } },
    expect: { valid: false, reason: 'annotation_name_control' },
  },
  {
    id: 'ann-name-del', rule: 'C5', kind: 'validate',
    description: 'a DEL inside the annotation value is a control byte',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Reg\u007fion' } } } },
    expect: { valid: false, reason: 'annotation_name_control' },
  },
  {
    id: 'ann-name-space', rule: 'C5', kind: 'validate',
    description: 'a space is not a tchar, so the value is not a token',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Re gion' } } } },
    expect: { valid: false, reason: 'annotation_name_not_token' },
  },
  {
    id: 'ann-name-colon', rule: 'C5', kind: 'validate',
    description: 'a colon is not a tchar, so the value is not a token',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Region:1' } } } },
    expect: { valid: false, reason: 'annotation_name_not_token' },
  },
  {
    id: 'ann-name-at', rule: 'C5', kind: 'validate',
    description: 'an at sign is not a tchar, so the value is not a token',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': '@region' } } } },
    expect: { valid: false, reason: 'annotation_name_not_token' },
  },
  {
    id: 'ann-name-quote', rule: 'C5', kind: 'validate',
    description: 'a double quote is not a tchar, so the value is not a token',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': '"Region"' } } } },
    expect: { valid: false, reason: 'annotation_name_not_token' },
  },
  {
    id: 'ann-name-nonascii', rule: 'C5', kind: 'validate',
    description: 'a non-ASCII letter is not a tchar, so the value is not a token',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Ré' } } } },
    expect: { valid: false, reason: 'annotation_name_not_token' },
  },
  {
    id: 'ann-name-duplicate-same', rule: 'C5', kind: 'validate',
    description: 'the same name on two properties is a duplicate',
    tool: { name: 'lookup', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        zone: { type: 'string', 'x-mcp-header': 'Region' },
      },
    } },
    expect: { valid: false, reason: 'annotation_name_duplicate' },
  },
  {
    id: 'ann-name-duplicate-case', rule: 'C5', kind: 'validate',
    description: 'names differing only in case are duplicates',
    tool: { name: 'lookup', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        zone: { type: 'string', 'x-mcp-header': 'region' },
      },
    } },
    expect: { valid: false, reason: 'annotation_name_duplicate' },
  },
  {
    id: 'ann-name-duplicate-nested', rule: 'C5', kind: 'validate',
    description: 'a nested name duplicates a top-level one case-insensitively',
    tool: { name: 'lookup', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'REGION' } } },
      },
    } },
    expect: { valid: false, reason: 'annotation_name_duplicate' },
  },

  // C5: target type and integer range.
  {
    id: 'ann-type-number', rule: 'C5', kind: 'validate',
    description: 'type number is not a primitive annotation target',
    tool: { name: 'metrics', inputSchema: { properties: { ratio: { type: 'number', 'x-mcp-header': 'Ratio' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-type-object', rule: 'C5', kind: 'validate',
    description: 'type object is not a primitive annotation target',
    tool: { name: 'metrics', inputSchema: { properties: { body: { type: 'object', 'x-mcp-header': 'Body' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-type-array', rule: 'C5', kind: 'validate',
    description: 'type array is not a primitive annotation target',
    tool: { name: 'metrics', inputSchema: { properties: { tags: { type: 'array', 'x-mcp-header': 'Tags' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-type-null', rule: 'C5', kind: 'validate',
    description: 'type null is not a primitive annotation target',
    tool: { name: 'metrics', inputSchema: { properties: { nothing: { type: 'null', 'x-mcp-header': 'Nothing' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-type-missing', rule: 'C5', kind: 'validate',
    description: 'a property without a type is not a primitive annotation target',
    tool: { name: 'metrics', inputSchema: { properties: { region: { description: 'The region', 'x-mcp-header': 'Region' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-type-list', rule: 'C5', kind: 'validate',
    description: 'a type array is not exactly one primitive type',
    tool: { name: 'metrics', inputSchema: { properties: { region: { type: ['string', 'integer'], 'x-mcp-header': 'Region' } } } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-int-min-too-low', rule: 'C5', kind: 'validate',
    description: 'a minimum below -(2^53-1) is out of range',
    tool: { name: 'counters', inputSchema: {
      properties: { count: { type: 'integer', minimum: -9007199254740992, 'x-mcp-header': 'Count' } },
    } },
    expect: { valid: false, reason: 'annotation_integer_range_invalid' },
  },
  {
    id: 'ann-int-max-too-high', rule: 'C5', kind: 'validate',
    description: 'a maximum above 2^53-1 is out of range',
    tool: { name: 'counters', inputSchema: {
      properties: { count: { type: 'integer', maximum: 9007199254740992, 'x-mcp-header': 'Count' } },
    } },
    expect: { valid: false, reason: 'annotation_integer_range_invalid' },
  },
  {
    id: 'ann-int-bounds-ok', rule: 'C5', kind: 'validate',
    description: 'bounds of exactly +/-(2^53-1) are in range',
    tool: { name: 'counters', inputSchema: {
      properties: { count: { type: 'integer', minimum: -9007199254740991, maximum: 9007199254740991, 'x-mcp-header': 'Count' } },
    } },
    expect: { valid: true, reason: null },
  },

  // C5: positional reachability. Each annotated node is itself primitive, so the
  // position is the only failing constraint.
  {
    id: 'ann-unreachable-root', rule: 'C5', kind: 'validate',
    description: 'an annotation at the schema root is not on a property',
    tool: { name: 'settings', inputSchema: { properties: { mode: { type: 'string' } }, 'x-mcp-header': 'Root' } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-items', rule: 'C5', kind: 'validate',
    description: 'an annotation under items is not reachable through properties',
    tool: { name: 'tagging', inputSchema: {
      properties: { tags: { type: 'array', items: { type: 'string', 'x-mcp-header': 'Tag' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-oneof', rule: 'C5', kind: 'validate',
    description: 'an annotation inside oneOf is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { oneOf: [{ type: 'string', 'x-mcp-header': 'Choice' }] } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-anyof', rule: 'C5', kind: 'validate',
    description: 'an annotation inside anyOf is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { anyOf: [{ type: 'string', 'x-mcp-header': 'Choice' }] } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-allof', rule: 'C5', kind: 'validate',
    description: 'an annotation inside a property-level allOf is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { allOf: [{ type: 'string', 'x-mcp-header': 'Choice' }] } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-allof-property-annotated', rule: 'C5', kind: 'validate',
    description: 'an annotation on a property inside an allOf subschema is not reachable from the schema root',
    tool: { name: 'compose', inputSchema: {
      allOf: [{ properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } }],
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-not', rule: 'C5', kind: 'validate',
    description: 'an annotation inside not is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { not: { type: 'string', 'x-mcp-header': 'Choice' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-if', rule: 'C5', kind: 'validate',
    description: 'an annotation inside if is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { if: { type: 'string', 'x-mcp-header': 'Choice' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-then', rule: 'C5', kind: 'validate',
    description: 'an annotation inside then is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { then: { type: 'string', 'x-mcp-header': 'Choice' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-else', rule: 'C5', kind: 'validate',
    description: 'an annotation inside else is not reachable',
    tool: { name: 'choices', inputSchema: {
      properties: { choice: { else: { type: 'string', 'x-mcp-header': 'Choice' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-additional', rule: 'C5', kind: 'validate',
    description: 'an annotation under additionalProperties is not reachable',
    tool: { name: 'mapping', inputSchema: {
      properties: { bag: { type: 'object', additionalProperties: { type: 'string', 'x-mcp-header': 'Extra' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-pattern', rule: 'C5', kind: 'validate',
    description: 'an annotation under patternProperties is not reachable',
    tool: { name: 'mapping', inputSchema: {
      properties: { bag: { type: 'object', patternProperties: { '^x-': { type: 'string', 'x-mcp-header': 'Extra' } } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-contains', rule: 'C5', kind: 'validate',
    description: 'an annotation inside contains is not reachable',
    tool: { name: 'tagging', inputSchema: {
      properties: { tags: { type: 'array', contains: { type: 'string', 'x-mcp-header': 'Tag' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-dependent', rule: 'C5', kind: 'validate',
    description: 'an annotation inside dependentSchemas is not reachable',
    tool: { name: 'mapping', inputSchema: {
      properties: { doc: { type: 'object', dependentSchemas: { region: { type: 'string', 'x-mcp-header': 'Dep' } } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-propertynames', rule: 'C5', kind: 'validate',
    description: 'an annotation inside propertyNames is not reachable',
    tool: { name: 'mapping', inputSchema: {
      properties: { doc: { type: 'object', propertyNames: { type: 'string', 'x-mcp-header': 'Name' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-defs', rule: 'C5', kind: 'validate',
    description: 'an annotation in a $defs target is a definition, not a property',
    tool: { name: 'resolve', inputSchema: {
      type: 'object',
      properties: { region: { $ref: '#/$defs/Region' } },
      $defs: { Region: { type: 'string', 'x-mcp-header': 'Region' } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-unevaluated', rule: 'C5', kind: 'validate',
    description: 'an annotation under unevaluatedProperties is not reachable',
    tool: { name: 'mapping', inputSchema: {
      properties: { bag: { type: 'object', unevaluatedProperties: { type: 'string', 'x-mcp-header': 'Extra' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-unreachable-allof-element', rule: 'C5', kind: 'validate',
    description: 'an annotation on a top-level allOf element is not on a property',
    tool: { name: 'compose', inputSchema: { allOf: [{ type: 'string', 'x-mcp-header': 'Any' }] } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },

  // C6: projection of arguments that match their annotated type.
  {
    id: 'ann-project-string', rule: 'C6', kind: 'project',
    description: 'a present string argument becomes one Mcp-Param header',
    tool: { name: 'execute_sql', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        query: { type: 'string' },
      },
    } },
    arguments: { region: 'us-west1', query: 'SELECT 1' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', 'us-west1']] },
  },
  {
    id: 'ann-project-integer', rule: 'C6', kind: 'project',
    description: 'an integer argument is projected in its decimal form',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: 42 },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Count', '42']] },
  },
  {
    id: 'ann-project-integer-negative', rule: 'C6', kind: 'project',
    description: 'a negative integer keeps its sign',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: -7 },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Count', '-7']] },
  },
  {
    id: 'ann-project-integer-zero', rule: 'C6', kind: 'project',
    description: 'zero is projected, not treated as absent',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: 0 },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Count', '0']] },
  },
  {
    id: 'ann-project-boolean-false', rule: 'C6', kind: 'project',
    description: 'false is projected as the text false',
    tool: { name: 'deploy', inputSchema: { properties: { dry: { type: 'boolean', 'x-mcp-header': 'DryRun' } } } },
    arguments: { dry: false },
    expect: { outcome: 'headers', headers: [['Mcp-Param-DryRun', 'false']] },
  },
  {
    id: 'ann-project-empty-string', rule: 'C6', kind: 'project',
    description: 'an empty string argument produces an empty header value',
    tool: { name: 'execute_sql', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } } },
    arguments: { region: '' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', '']] },
  },
  {
    id: 'ann-project-encoded', rule: 'C6', kind: 'project',
    description: 'a value outside the field-value syntax is sent as a sentinel',
    tool: { name: 'execute_sql', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } } },
    arguments: { region: 'us west1/日本' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', ENC_REGION_JA]] },
  },
  {
    id: 'ann-project-nested', rule: 'C6', kind: 'project',
    description: 'a nested argument is projected along its properties path',
    tool: { name: 'list_zones', inputSchema: {
      properties: { filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'Zone' } } } },
    } },
    arguments: { filter: { zone: 'eu' } },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Zone', 'eu']] },
  },
  {
    id: 'ann-project-missing-argument', rule: 'C6', kind: 'project',
    description: 'an absent argument omits the header',
    tool: { name: 'list_zones', inputSchema: {
      properties: { filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'Zone' } } } },
    } },
    arguments: {},
    expect: { outcome: 'headers', headers: [] },
  },
  {
    id: 'ann-project-null-value', rule: 'C6', kind: 'project',
    description: 'a null annotation value omits the header',
    tool: { name: 'list_zones', inputSchema: {
      properties: { filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'Zone' } } } },
    } },
    arguments: { filter: { zone: null } },
    expect: { outcome: 'headers', headers: [] },
  },
  {
    id: 'ann-project-null-intermediate', rule: 'C6', kind: 'project',
    description: 'a null step on the path omits the header',
    tool: { name: 'list_zones', inputSchema: {
      properties: { filter: { type: 'object', properties: { zone: { type: 'string', 'x-mcp-header': 'Zone' } } } },
    } },
    arguments: { filter: null },
    expect: { outcome: 'headers', headers: [] },
  },
  {
    id: 'ann-project-order', rule: 'C6', kind: 'project',
    description: 'headers follow depth-first document order of properties',
    tool: { name: 'inventory', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        tenant: { type: 'string', 'x-mcp-header': 'Tenant' },
        zone: { type: 'string', 'x-mcp-header': 'Zone' },
      },
    } },
    arguments: { zone: 'z1', tenant: 'acme', region: 'eu' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', 'eu'], ['Mcp-Param-Tenant', 'acme'], ['Mcp-Param-Zone', 'z1']] },
  },
  {
    id: 'ann-project-partial', rule: 'C6', kind: 'project',
    description: 'only the annotations whose arguments are present are sent',
    tool: { name: 'inventory', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        tenant: { type: 'string', 'x-mcp-header': 'Tenant' },
      },
    } },
    arguments: { tenant: 'acme' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Tenant', 'acme']] },
  },

  // C6: arguments that do not match the annotated type refuse the request.
  {
    id: 'ann-project-refuse-string-for-integer', rule: 'C6', kind: 'project',
    description: 'a string for an integer annotation refuses the request',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: '5' },
    expect: { outcome: 'refuse', reason: PROJECTION_REASON },
  },
  {
    id: 'ann-project-refuse-fraction', rule: 'C6', kind: 'project',
    description: 'a fractional number for an integer annotation refuses the request',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: 1.5 },
    expect: { outcome: 'refuse', reason: PROJECTION_REASON },
  },
  {
    id: 'ann-project-refuse-unsafe-integer', rule: 'C6', kind: 'project',
    description: 'an integer beyond 2^53-1 refuses the request',
    tool: { name: 'report', inputSchema: { properties: { count: { type: 'integer', 'x-mcp-header': 'Count' } } } },
    arguments: { count: 1e21 },
    expect: { outcome: 'refuse', reason: PROJECTION_REASON },
  },
  {
    id: 'ann-project-refuse-string-for-boolean', rule: 'C6', kind: 'project',
    description: 'a string for a boolean annotation refuses the request',
    tool: { name: 'deploy', inputSchema: { properties: { dry: { type: 'boolean', 'x-mcp-header': 'DryRun' } } } },
    arguments: { dry: 'true' },
    expect: { outcome: 'refuse', reason: PROJECTION_REASON },
  },
  {
    id: 'ann-project-refuse-object-for-string', rule: 'C6', kind: 'project',
    description: 'an object for a string annotation refuses the request',
    tool: { name: 'execute_sql', inputSchema: { properties: { region: { type: 'string', 'x-mcp-header': 'Region' } } } },
    arguments: { region: {} },
    expect: { outcome: 'refuse', reason: PROJECTION_REASON },
  },

  // C5 and C6: a member named x-mcp-header inside a name map is a property
  // name, and an empty property name is legal.
  {
    id: 'ann-valid-property-named-x-mcp-header', rule: 'C5', kind: 'validate',
    description: 'a property whose name is x-mcp-header is a property, not an annotation',
    tool: { name: 'lookup', inputSchema: { properties: { 'x-mcp-header': { type: 'string' } } } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-property-named-x-mcp-header-annotated', rule: 'C5', kind: 'validate',
    description: 'a property named x-mcp-header may carry its own annotation',
    tool: { name: 'lookup', inputSchema: {
      properties: { 'x-mcp-header': { type: 'string', 'x-mcp-header': 'XHeader' } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-empty-property-name', rule: 'C5', kind: 'validate',
    description: 'an empty property name is legal and its annotation is reachable',
    tool: { name: 'lookup', inputSchema: {
      properties: { '': { type: 'string', 'x-mcp-header': 'Empty' } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-property-named-properties', rule: 'C5', kind: 'validate',
    description: 'a property named properties keeps its own annotation',
    tool: { name: 'lookup', inputSchema: {
      properties: { properties: { type: 'string', 'x-mcp-header': 'Props' } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-nested-property-named-properties', rule: 'C5', kind: 'validate',
    description: 'a property named properties nested under a name map keeps its annotation',
    tool: { name: 'lookup', inputSchema: {
      properties: { outer: { type: 'object', properties: { properties: { type: 'string', 'x-mcp-header': 'Inner' } } } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-valid-allof-property-named-x-mcp-header', rule: 'C5', kind: 'validate',
    description: 'a property named x-mcp-header inside an allOf subschema is a property, not an annotation',
    tool: { name: 'compose', inputSchema: {
      allOf: [{ properties: { 'x-mcp-header': { type: 'string' } } }],
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-project-property-named-x-mcp-header', rule: 'C6', kind: 'project',
    description: 'a property named x-mcp-header is projected like any other property',
    tool: { name: 'lookup', inputSchema: {
      properties: { 'x-mcp-header': { type: 'string', 'x-mcp-header': 'XHeader' } },
    } },
    arguments: { 'x-mcp-header': 'v1' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-XHeader', 'v1']] },
  },
  {
    id: 'ann-project-empty-property-name', rule: 'C6', kind: 'project',
    description: 'an empty property name is projected like any other property',
    tool: { name: 'lookup', inputSchema: {
      properties: { '': { type: 'string', 'x-mcp-header': 'Empty' } },
    } },
    arguments: { '': 'e' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Empty', 'e']] },
  },
  {
    id: 'ann-project-property-named-properties', rule: 'C6', kind: 'project',
    description: 'a property named properties is projected like any other property',
    tool: { name: 'lookup', inputSchema: {
      properties: { properties: { type: 'string', 'x-mcp-header': 'Props' } },
    } },
    arguments: { properties: 'v2' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Props', 'v2']] },
  },
  {
    id: 'ann-project-allof-property-named-x-mcp-header', rule: 'C6', kind: 'project',
    description: 'a property named x-mcp-header under allOf is not annotated, so nothing is projected',
    tool: { name: 'compose', inputSchema: {
      allOf: [{ properties: { 'x-mcp-header': { type: 'string' } } }],
    } },
    arguments: { 'x-mcp-header': 'v1' },
    expect: { outcome: 'headers', headers: [] },
  },

  // C11: event type descriptors validate as in C5 and project as in C6.
  {
    id: 'ann-event-valid', rule: 'C11', kind: 'validate-event',
    description: 'an annotated event inputSchema is valid',
    event: { name: 'email.received', inputSchema: {
      properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
    } },
    expect: { valid: true, reason: null },
  },
  {
    id: 'ann-event-invalid-type', rule: 'C11', kind: 'validate-event',
    description: 'a non-primitive annotated event property is invalid',
    event: { name: 'email.received', inputSchema: {
      properties: { region: { type: 'number', 'x-mcp-header': 'Region' } },
    } },
    expect: { valid: false, reason: 'annotation_type_not_primitive' },
  },
  {
    id: 'ann-event-invalid-unreachable', rule: 'C11', kind: 'validate-event',
    description: 'an annotation under items in an event schema is not reachable',
    event: { name: 'email.received', inputSchema: {
      properties: { tags: { type: 'array', items: { type: 'string', 'x-mcp-header': 'Tag' } } },
    } },
    expect: { valid: false, reason: 'annotation_not_statically_reachable' },
  },
  {
    id: 'ann-event-duplicate', rule: 'C11', kind: 'validate-event',
    description: 'event names differing only in case are duplicates',
    event: { name: 'email.received', inputSchema: {
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        zone: { type: 'string', 'x-mcp-header': 'region' },
      },
    } },
    expect: { valid: false, reason: 'annotation_name_duplicate' },
  },
  {
    id: 'ann-event-project', rule: 'C11', kind: 'project-event',
    description: 'a present event argument becomes one Mcp-Param header',
    event: { name: 'incident.created', inputSchema: {
      properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
    } },
    arguments: { region: 'eu-west' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', 'eu-west']] },
  },
  {
    id: 'ann-event-project-encoded', rule: 'C11', kind: 'project-event',
    description: 'an event argument outside the field-value syntax is sent as a sentinel',
    event: { name: 'incident.created', inputSchema: {
      properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
    } },
    arguments: { region: 'eu wést' },
    expect: { outcome: 'headers', headers: [['Mcp-Param-Region', encodeHeaderValue('eu wést')]] },
  },
  {
    id: 'ann-event-project-missing', rule: 'C11', kind: 'project-event',
    description: 'an absent event argument omits the header',
    event: { name: 'incident.created', inputSchema: {
      properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
    } },
    arguments: {},
    expect: { outcome: 'headers', headers: [] },
  },
];

export const ANNOTATION_REASON_CODES = ANNOTATION_REASONS;
