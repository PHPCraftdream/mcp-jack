import { ROTATION_KEYS_PUBLIC, ROTATION_NEGATIVE, ROTATION_VALID, rotationRecordsForVerification } from './rotation-cases.mjs';
import { NONCE_EVENTS, ROTATION_CLIENT_CASES, ROTATION_EVENT_CASES } from './scenario-data.mjs';

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const caseTable = (rows, expected) => [
  '| Case | Source note | Hand-stated expectation |',
  '|---|---|---|',
  ...rows.map((row) => `| \`${row.id}\` | ${(row.description ?? '—').replaceAll('|', '\\|')} | \`${JSON.stringify(expected(row))}\` |`),
].join('\n');
const casesIndex = [
  '# Candidate source cases',
  '',
  'Generated from the hand-stated source expectations; this index is not a verifier or reference-model result.',
  '',
  `## Rotation record negative cases (${ROTATION_NEGATIVE.length})`,
  '',
  caseTable(ROTATION_NEGATIVE, ({ expected }) => ({ expected })),
  '',
  `## Durable nonce events (${NONCE_EVENTS.length})`,
  '',
  caseTable(NONCE_EVENTS, ({ expect }) => expect),
  '',
  `## Rotation client cases (${ROTATION_CLIENT_CASES.length})`,
  '',
  caseTable(ROTATION_CLIENT_CASES, ({ expect }) => expect),
  '',
  `## Rotation event cases (${ROTATION_EVENT_CASES.length})`,
  '',
  caseTable(ROTATION_EVENT_CASES, ({ expect }) => expect),
  '',
].join('\n') + '\n';

const outputs = {
  'fixtures/candidate/rotation-vectors.json': json({
    format: 'mcp-jack-candidate-rotation-v1',
    binding: { endpoint: 'https://svc.example.test/mcp', aud: 'https://svc.example.test' },
    limits: { record_bytes: 8192, page_links: 16, body_bytes: 262144, pending: 128, retired: 1024 },
    keys: ROTATION_KEYS_PUBLIC,
    valid_chains: ROTATION_VALID,
    source_controls: { decreasing_prefix: rotationRecordsForVerification.wrongP.wireText },
    malformed: ROTATION_NEGATIVE,
  }),
  'fixtures/candidate/nonce-vectors.json': json({
    format: 'mcp-jack-candidate-durable-nonce-v1',
    status_codes: { durability_unavailable: 503, state_changed: 503, clock_unsafe: 503, capacity_exhausted: 503 },
    cases: NONCE_EVENTS,
  }),
  'fixtures/candidate/rotation-state-vectors.json': json({
    format: 'mcp-jack-candidate-rotation-state-v1',
    tool: 'jack.server.key',
    arguments: { exact_fields: ['after_ordinal', 'after_hash'], reject_duplicate_names: true },
    result: { exact_fields: ['current', 'records', 'head', 'complete'], current_fields: ['kid', 'public_key'], head_fields: ['ordinal', 'hash'], max_links: 16 },
    server_errors: { invalid_params: 400, rotation_checkpoint_unavailable: 409, rotation_state_unavailable: 503 },
    client_local_errors: ['rotation_result_invalid', 'rotation_record_invalid', 'rotation_conflict', 'rotation_gap', 'rotation_bridge_expired', 'rotation_state_changed', 'rotation_state_unknown', 'rotation_key_interval', 'rotation_clock_unsafe', 'rotation_clock_unavailable'],
    client_cases: ROTATION_CLIENT_CASES,
    event_cases: ROTATION_EVENT_CASES,
  }),
  'tests/candidate/CASES.md': casesIndex,
};

export const expectedOutputs = () => outputs;
export const GENERATED = outputs;
