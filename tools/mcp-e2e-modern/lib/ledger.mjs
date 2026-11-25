import { REQUIRED_SCENARIOS, SKIPPABLE_SCENARIOS } from './config.mjs';

const outcomes = ['PASS', 'FAIL', 'SKIP'];
const attributions = ['sdk', 'fixture', 'jack'];
const oracleResults = ['verified', 'invalid', 'not-applicable', 'not-run'];
const captureKeys = ['hop', 'direction', 'method', 'status', 'media_type', 'body'];
const timingKeys = ['readiness_ms', 'tool_ms', 'first_event_ms', 'stream_completion_ms', 'cancellation_ms', 'shutdown_ms'];

export function makeCell(input = {}) {
  return {
    cell_id: input.cell_id ?? '',
    path: input.path ?? '',
    client: input.client ?? '',
    server: input.server ?? '',
    sdk_versions: input.sdk_versions ?? { client: null, server: null },
    scenario: input.scenario ?? null,
    outcome: input.outcome ?? 'FAIL',
    attribution: input.attribution ?? 'jack',
    reason: input.reason ?? '',
    captures: input.captures ?? [],
    signature_oracle: input.signature_oracle ?? { applicable: false, result: 'not-applicable' },
    timings: input.timings ?? Object.fromEntries(timingKeys.map((key) => [key, null])),
    ...(Object.hasOwn(input, 'failure_fingerprint') ? { failure_fingerprint: input.failure_fingerprint } : {}),
    client_visible: Object.hasOwn(input, 'client_visible') ? input.client_visible : { tool_result: null, sdk_error: null },
  };
}

export function validateCell(record) {
  const errors = [];
  const fields = ['cell_id', 'path', 'client', 'server', 'sdk_versions', 'scenario', 'outcome', 'attribution', 'reason', 'captures', 'signature_oracle', 'timings', 'client_visible'];
  const allowedFields = [...fields, 'failure_fingerprint'];
  if (!record || typeof record !== 'object' || Array.isArray(record)) return { ok: false, errors: ['record must be an object'] };
  if (Object.keys(record).some((key) => !allowedFields.includes(key)) || fields.some((key) => !Object.hasOwn(record, key))) errors.push('record fields do not match ledger schema');
  if (Object.hasOwn(record, 'failure_fingerprint') && record.failure_fingerprint !== null && typeof record.failure_fingerprint !== 'string') errors.push('failure_fingerprint must be string or null');
  if (record.client_visible !== null) {
    const visible = record.client_visible;
    if (!visible || typeof visible !== 'object' || Array.isArray(visible) || Object.keys(visible).length !== 2 || !Object.hasOwn(visible, 'tool_result') || !Object.hasOwn(visible, 'sdk_error')) errors.push('client_visible must contain tool_result and sdk_error');
    else for (const key of ['tool_result', 'sdk_error']) {
      const value = visible[key];
      if (value !== null && typeof value !== 'string' && (typeof value !== 'object' || Array.isArray(value))) errors.push(`client_visible.${key} must be nullable JSON object or string`);
    }
  }
  for (const key of ['cell_id', 'path', 'client', 'server', 'reason']) if (typeof record[key] !== 'string') errors.push(`${key} must be a string`);
  if (!Number.isInteger(record.scenario) || record.scenario < 1 || record.scenario > 8) errors.push('scenario must be an integer from 1 to 8');
  if (!outcomes.includes(record.outcome)) errors.push('invalid outcome');
  if (!attributions.includes(record.attribution)) errors.push('invalid attribution');
  if (!Array.isArray(record.captures)) errors.push('captures must be an array');
  else for (const [index, capture] of record.captures.entries()) {
    if (!capture || typeof capture !== 'object' || Object.keys(capture).length !== captureKeys.length || captureKeys.some((key) => !Object.hasOwn(capture, key))) errors.push(`captures[${index}] fields do not match schema`);
    else {
      for (const key of ['hop', 'direction', 'body']) if (typeof capture[key] !== 'string') errors.push(`captures[${index}].${key} must be a string`);
      if (!['request', 'response', 'event'].includes(capture.direction)) errors.push(`captures[${index}].direction is invalid`);
      if (capture.method !== null && typeof capture.method !== 'string') errors.push(`captures[${index}].method must be string or null`);
      if (capture.media_type !== null && typeof capture.media_type !== 'string') errors.push(`captures[${index}].media_type must be string or null`);
      if (capture.status !== null && !Number.isInteger(capture.status)) errors.push(`captures[${index}].status must be integer or null`);
    }
  }
  const versions = record.sdk_versions;
  if (!versions || typeof versions !== 'object' || !Object.hasOwn(versions, 'client') || !Object.hasOwn(versions, 'server') || Object.keys(versions).length !== 2) errors.push('sdk_versions must contain client and server');
  else for (const side of ['client', 'server']) {
    const sdk = versions[side];
    if (sdk !== null && (!sdk || typeof sdk !== 'object' || typeof sdk.name !== 'string' || typeof sdk.version !== 'string' || Object.keys(sdk).length !== 2)) errors.push(`sdk_versions.${side} must be name/version strings or null`);
  }
  const oracle = record.signature_oracle;
  if (!oracle || Object.keys(oracle).length !== 2 || typeof oracle.applicable !== 'boolean' || !oracleResults.includes(oracle.result)) errors.push('signature_oracle does not match schema');
  const timings = record.timings;
  if (!timings || Object.keys(timings).length !== timingKeys.length || timingKeys.some((key) => !Object.hasOwn(timings, key))) errors.push('timings do not match schema');
  else for (const key of timingKeys) if (timings[key] !== null && (!Number.isInteger(timings[key]) || timings[key] < 0)) errors.push(`timings.${key} must be a non-negative integer or null`);
  if (record.outcome === 'SKIP' && (!SKIPPABLE_SCENARIOS.includes(record.scenario) || !record.reason.trim())) errors.push('SKIP requires scenario 4-7 and capability evidence in reason');
  return { ok: errors.length === 0, errors };
}

export function attributionFor({ outcome, failure_fingerprint, directControl, fixtureReadinessFailed = false, fixtureEchoFailed = false } = {}) {
  if (directControl && outcome === directControl.outcome && typeof failure_fingerprint === 'string' && failure_fingerprint.length > 0 && typeof directControl.failure_fingerprint === 'string' && directControl.failure_fingerprint === failure_fingerprint) return 'sdk';
  if (fixtureReadinessFailed || fixtureEchoFailed) return 'fixture';
  return 'jack';
}

export function summarize(cells) {
  const counts = { PASS: 0, FAIL: 0, SKIP: 0 };
  const skipList = [];
  for (const cell of cells) {
    if (Object.hasOwn(counts, cell.outcome)) counts[cell.outcome] += 1;
    if (cell.outcome === 'SKIP') skipList.push({ cell_id: cell.cell_id, scenario: cell.scenario, evidence: cell.reason });
  }
  const required = cells.filter((cell) => REQUIRED_SCENARIOS.includes(cell.scenario));
  const requiredScenarioCoverage = REQUIRED_SCENARIOS.every((scenario) => required.some((cell) => cell.scenario === scenario && cell.outcome !== 'SKIP'));
  return { counts, skips: skipList, required: { pass: requiredScenarioCoverage && required.every((cell) => cell.outcome === 'PASS'), scenarios: REQUIRED_SCENARIOS, cells: required.length }, outcome: counts.FAIL > 0 || !requiredScenarioCoverage ? 'FAIL' : 'PASS' };
}
