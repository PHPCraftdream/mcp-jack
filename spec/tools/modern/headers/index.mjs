// Deterministic generator for the header family of the modern profile (spec 04
// sections 3-6 and 8). build() is pure: no clock, no randomness, no I/O and no
// mutation of the imported case arrays. It returns { files, casesMarkdown } and
// writes nothing: the parent writes build().files into spec/fixtures/modern/
// and build().casesMarkdown into spec/tests/MODERN-HEADERS-CASES.md.
import { AUD, NOW, WINDOW } from '../../gen/core.mjs';
import {
  ALL_RULES, CLASSIFICATION_REFUSAL, EXEMPT_RULES, MODERN_MIN, NON_VECTOR_RULES,
  PROJECTION_REASON, REASONS, VECTOR_RULES,
} from './spec-data.mjs';
import {
  buildMirrors, classifyRequest, decodeHeaderValue, detectEra, encodeHeaderValue,
  projectArguments, textOfValue, validateAnnotations, deepEqual, stableStringify,
} from './reference.mjs';
import { BY_REFERENCE, REQUEST_CASES } from './vectors/requests.mjs';
import { ENCODING_CASES } from './vectors/encoding.mjs';
import { ANNOTATION_CASES, ANNOTATION_REASON_CODES } from './vectors/annotations.mjs';
import { ERA_CASES, ERA_ERROR_CODES } from './vectors/era.mjs';
import { buildCasesMarkdown } from './vectors/markdown.mjs';

// Wire shape of a resolved request expectation. Section 8: every refusal carries
// the full wire outcome, and a forward carries the era, the forwarded request
// and the nonce bookkeeping flag.
const REFUSAL_KEYS = ['consumes_nonce', 'content_type', 'era', 'error', 'http_status', 'id', 'jsonrpc', 'outcome', 'signed'];
const FORWARD_KEYS = ['consumes_nonce', 'era', 'forward', 'outcome'];
const FORWARD_FIELDS = ['headers', 'method', 'target'];
const CLASSIFICATION_KEYS = ['consumes_nonce', 'content_type', 'era', 'error', 'http_status', 'outcome', 'signed'];

// Rules that refuse with the reason of another rule: S3 decides the era and the
// following S4 refuses, S10 is defined as the refusals of S1, S2, S4, S5 and
// S6, and S11 is a notification checked by S4 and S6. Those cases cite the
// source rule of their reason, every other case cites its reason's own rule.
const REASON_SOURCES = { S3: ['S4'], S10: ['S1', 'S2', 'S4', 'S5', 'S6'], S11: ['S4', 'S6'] };

const disagree = (c, got, want) =>
  new Error(c.id + ': reference disagrees: got ' + stableStringify(got) + ', want ' + stableStringify(want));

const keysOf = (value) => Object.keys(value).sort();

function assertForwardShape(c, want) {
  if (!deepEqual(keysOf(want), FORWARD_KEYS)) throw new Error(c.id + ': forward expectation keys ' + keysOf(want).join(','));
  if (!deepEqual(keysOf(want.forward), FORWARD_FIELDS)) throw new Error(c.id + ': forward object keys ' + keysOf(want.forward).join(','));
  if (want.consumes_nonce !== true) throw new Error(c.id + ': forward consumes_nonce must be true');
  if (!['legacy', 'modern'].includes(want.era)) throw new Error(c.id + ': forward era ' + want.era);
}

// S10/spec section 8: every refusal carries the full wire outcome.
function assertRefusalShape(c, want) {
  if (!deepEqual(keysOf(want), REFUSAL_KEYS)) throw new Error(c.id + ': refusal keys ' + keysOf(want).join(','));
  if (want.signed !== true) throw new Error(c.id + ': refusal must be signed');
  if (want.content_type !== 'application/json') throw new Error(c.id + ': refusal content_type');
  if (want.jsonrpc !== '2.0') throw new Error(c.id + ': refusal jsonrpc');
  if (want.consumes_nonce !== true) throw new Error(c.id + ': refusal consumes_nonce must be true');
  if (typeof want.http_status !== 'number') throw new Error(c.id + ': refusal http_status');
  if (!deepEqual(keysOf(want.error), ['code', 'message'])) throw new Error(c.id + ': refusal error keys');
  if (typeof want.error.code !== 'number' || typeof want.error.message !== 'string' || want.error.message.length === 0) {
    throw new Error(c.id + ': refusal error members');
  }
  if (!('id' in want) || !(want.id === null || typeof want.id === 'string' || typeof want.id === 'number')) {
    throw new Error(c.id + ': refusal id');
  }
}

// 02 section 2 item 4: the era-neutral classification refusal has no jsonrpc or
// id member, a string error.code and the fixed message of spec-data.
function assertClassificationShape(c, want) {
  if (!deepEqual(keysOf(want), CLASSIFICATION_KEYS)) throw new Error(c.id + ': classification keys ' + keysOf(want).join(','));
  if (want.outcome !== 'refuse_invalid_request') throw new Error(c.id + ': classification outcome');
  if (want.signed !== true) throw new Error(c.id + ': classification must be signed');
  if (want.content_type !== 'application/json') throw new Error(c.id + ': classification content_type');
  if (want.era !== null) throw new Error(c.id + ': classification is era-neutral');
  if (want.consumes_nonce !== true) throw new Error(c.id + ': classification consumes_nonce must be true');
  if (want.http_status !== CLASSIFICATION_REFUSAL.http_status) throw new Error(c.id + ': classification http_status');
  if (!deepEqual(keysOf(want.error), ['code', 'message'])) throw new Error(c.id + ': classification error keys');
  if (want.error.code !== CLASSIFICATION_REFUSAL.code) throw new Error(c.id + ': classification error code');
  if (want.error.message !== CLASSIFICATION_REFUSAL.message) throw new Error(c.id + ': classification error message');
}

// One dispatcher, so the reference output is checked against the shape of the
// outcome it actually produced.
function assertRequestShape(c, value) {
  if (value.outcome === 'forward') assertForwardShape(c, value);
  else if (value.outcome === 'refuse') assertRefusalShape(c, value);
  else if (value.outcome === 'refuse_invalid_request') assertClassificationShape(c, value);
  else throw new Error(c.id + ': unknown request outcome ' + value.outcome);
}

export default {
  family: 'headers',
  build() {
    // 1. Request cases: classification-level era, mirror and refusal cases. The
    // stored expectation is the wire outcome the reference must reproduce.
    const resolvedRequests = REQUEST_CASES.map((c) => {
      if (!ALL_RULES.includes(c.rule) || !c.rule.startsWith('S')) {
        throw new Error(c.id + ': unknown request rule ' + c.rule);
      }
      let resolved;
      if (c.expect.outcome === 'forward') {
        resolved = { outcome: 'forward', era: c.expect.era, forward: c.expect.forward, consumes_nonce: true };
        assertForwardShape(c, resolved);
      } else if (c.expect.outcome === 'refuse_invalid_request') {
        if (c.rule !== 'S6') throw new Error(c.id + ': classification outcome must cite rule S6');
        resolved = {
          outcome: 'refuse_invalid_request', era: null, signed: true,
          http_status: CLASSIFICATION_REFUSAL.http_status, content_type: 'application/json',
          error: { code: CLASSIFICATION_REFUSAL.code, message: CLASSIFICATION_REFUSAL.message },
          consumes_nonce: true,
        };
        assertClassificationShape(c, resolved);
      } else {
        const reason = REASONS[c.expect.reason];
        if (reason === undefined) throw new Error(c.id + ': unknown reason ' + c.expect.reason);
        const sourceRule = reason.rule;
        if (sourceRule !== c.rule && !(REASON_SOURCES[c.rule] ?? []).includes(sourceRule)) {
          throw new Error(c.id + ': reason ' + c.expect.reason + ' belongs to rule ' + sourceRule + ', not ' + c.rule);
        }
        resolved = {
          outcome: 'refuse', era: c.expect.era, signed: true, http_status: reason.http_status,
          content_type: 'application/json', jsonrpc: '2.0', id: c.expect.id,
          error: { code: reason.jsonrpc_code, message: reason.message }, consumes_nonce: true,
        };
        assertRefusalShape(c, resolved);
      }
      const got = classifyRequest({ profile: c.profile, request: c.request });
      if (!deepEqual(got, resolved)) throw disagree(c, got, resolved);
      // The reference output itself must carry the section 8 wire shape.
      assertRequestShape(c, got);
      return { ...c, expect: resolved };
    });

    // 2. By-reference entries: cases that live in another vector file. They cite
    // an exempt rule and point at existing case ids instead of copying them.
    const byRefIds = BY_REFERENCE.map((entry, index) => {
      const label = 'by-reference entry ' + index;
      if (typeof entry.id !== 'string' || entry.id.length === 0) {
        throw new Error(label + ': id must be a non-empty string');
      }
      if (!Object.hasOwn(EXEMPT_RULES, entry.rule)) {
        throw new Error(entry.id + ': by-reference rule ' + entry.rule + ' is not exempt in spec section 8');
      }
      if (typeof entry.file !== 'string' || entry.file.length === 0) {
        throw new Error(entry.id + ': by-reference file must be a non-empty string');
      }
      if (!Array.isArray(entry.vectors) || entry.vectors.length === 0 || !entry.vectors.every((v) => typeof v === 'string')) {
        throw new Error(entry.id + ': by-reference vectors must be a non-empty array of strings');
      }
      return entry.id;
    });
    const duplicateRef = byRefIds.find((id, i) => byRefIds.indexOf(id) !== i);
    if (duplicateRef !== undefined) throw new Error('duplicate by-reference id: ' + duplicateRef);

    // 3. Encoding cases: C1/C2 mirrors, C3 encode with its C4 round trip, C4 decode.
    const resolvedEncoding = ENCODING_CASES.map((c) => {
      if (c.kind === 'build') {
        const got = buildMirrors({ version: c.version, method: c.method, params: c.params });
        if (!deepEqual(got, c.expect)) throw disagree(c, got, c.expect);
      } else if (c.kind === 'encode') {
        const text = textOfValue(c.value, c.type);
        if (text === null) throw new Error(c.id + ': value is not representable as type ' + c.type);
        const headerValue = encodeHeaderValue(text);
        if (headerValue !== c.expect.header_value) throw disagree(c, headerValue, c.expect.header_value);
        const decoded = decodeHeaderValue(c.expect.header_value);
        if (!deepEqual(decoded, { ok: true, text })) throw disagree(c, decoded, { ok: true, text });
      } else if (c.kind === 'decode') {
        const got = decodeHeaderValue(c.header_value);
        if (!deepEqual(got, c.expect)) throw disagree(c, got, c.expect);
      } else {
        throw new Error(c.id + ': unknown encoding kind ' + c.kind);
      }
      return { ...c, expect: c.expect };
    });

    // 4. Annotation cases: C5 and C11 validation, C6 and C11 projection of valid
    // definitions.
    const resolvedAnnotations = ANNOTATION_CASES.map((c) => {
      const schema = (c.tool ?? c.event).inputSchema;
      if (c.kind === 'validate' || c.kind === 'validate-event') {
        const got = validateAnnotations(schema);
        if (!deepEqual(got, c.expect)) throw disagree(c, got, c.expect);
      } else if (c.kind === 'project' || c.kind === 'project-event') {
        if (validateAnnotations(schema).valid !== true) {
          throw new Error(c.id + ': projection vector uses an invalid tool definition');
        }
        const got = projectArguments(schema, c.arguments);
        if (!deepEqual(got, c.expect)) throw disagree(c, got, c.expect);
      } else {
        throw new Error(c.id + ': unknown annotation kind ' + c.kind);
      }
      return { ...c, expect: c.expect };
    });

    // 5. Era cases: C9 detection from the verified response only.
    const resolvedEra = ERA_CASES.map((c) => {
      if (c.rule !== 'C9') throw new Error(c.id + ': era case must cite rule C9, not ' + c.rule);
      const got = detectEra({ response: c.response, clientVersions: c.clientVersions });
      if (!deepEqual(got, c.expect)) throw disagree(c, got, c.expect);
      return { ...c, expect: c.expect };
    });

    // 6. Case ids are unique across the whole family, and no case id is also a
    // by-reference id.
    const allCases = [...resolvedRequests, ...resolvedEncoding, ...resolvedAnnotations, ...resolvedEra];
    const ids = allCases.map((c) => c.id);
    const duplicate = ids.find((id, i) => ids.indexOf(id) !== i);
    if (duplicate !== undefined) throw new Error('duplicate case id: ' + duplicate);
    const overlap = byRefIds.find((id) => ids.includes(id));
    if (overlap !== undefined) throw new Error('case id reused by a by-reference entry: ' + overlap);

    // Rule partition (spec section 8): every non-exempt rule maps to at least one
    // existing vector id, every vector is mapped to its own rule, and no exempt
    // rule has a vector. The coverage test compares the spec's exemption table to
    // EXEMPT_RULES.
    const ruleMap = new Map();
    for (const c of allCases) {
      if (!ALL_RULES.includes(c.rule)) throw new Error(c.id + ': case cites unknown rule ' + c.rule);
      if (!ruleMap.has(c.rule)) ruleMap.set(c.rule, []);
      ruleMap.get(c.rule).push(c.id);
    }
    const mappedIds = [...ruleMap.values()].flat();
    if (mappedIds.length !== allCases.length) {
      throw new Error('rule map: ' + mappedIds.length + ' mapped ids for ' + allCases.length + ' cases');
    }
    if (new Set(mappedIds).size !== mappedIds.length) throw new Error('rule map: a case id is mapped twice');
    for (const rule of VECTOR_RULES) {
      if ((ruleMap.get(rule) ?? []).length === 0) throw new Error('rule ' + rule + ' has no mapped vector id');
    }
    for (const rule of NON_VECTOR_RULES) {
      if ((ruleMap.get(rule) ?? []).length > 0) throw new Error('exempt rule ' + rule + ' has vectors');
    }

    // 7. Files, in insertion order.
    const files = {
      'modern-request-vectors.json': {
        format: 'mcp-jack-modern-request-vectors-v1',
        note: 'Classification-level cases of spec 04 sections 3-6. Request authentication (mcp-jack/v1) runs before every case; the one era-neutral classification case cites the spec 02 section 2 item 4 refusal, and the legacy dispatch rules of spec 02 are covered by request-vectors.json.',
        clock: { now: NOW, window_seconds: WINDOW },
        aud: AUD,
        modern_min: MODERN_MIN,
        profiles: ['legacy', 'modern', 'both'],
        cases: resolvedRequests,
        by_reference: BY_REFERENCE,
      },
      'header-encoding-vectors.json': {
        format: 'mcp-jack-modern-header-encoding-v1',
        modern_min: MODERN_MIN,
        cases: resolvedEncoding,
      },
      'x-mcp-header-vectors.json': {
        format: 'mcp-jack-modern-x-mcp-header-v1',
        reason_codes: [...ANNOTATION_REASON_CODES],
        projection_reason: PROJECTION_REASON,
        cases: resolvedAnnotations,
      },
      'era-detection-vectors.json': {
        format: 'mcp-jack-modern-era-detection-v1',
        modern_error_codes: [...ERA_ERROR_CODES],
        cases: resolvedEra,
      },
    };

    // 8. Case index markdown.
    const casesMarkdown = buildCasesMarkdown({
      requestCases: resolvedRequests,
      byReference: BY_REFERENCE,
      encodingCases: resolvedEncoding,
      annotationCases: resolvedAnnotations,
      eraCases: resolvedEra,
      now: NOW,
      aud: AUD,
    });

    return { files, casesMarkdown };
  },
};
