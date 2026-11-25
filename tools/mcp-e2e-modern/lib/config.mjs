export const DEADLINES = Object.freeze({
  readiness: 10000,
  directTool: 30000,
  bridgeTool: 45000,
  firstStreamEvent: 10000,
  streamCompletion: 30000,
  cancellation: 10000,
  shutdown: 5000,
});

export const TIMEOUT_FLAGS = Object.freeze({
  readiness: '--readiness-timeout-ms',
  directTool: '--direct-tool-timeout-ms',
  bridgeTool: '--bridge-tool-timeout-ms',
  firstStreamEvent: '--first-stream-event-timeout-ms',
  streamCompletion: '--stream-completion-timeout-ms',
  cancellation: '--cancellation-timeout-ms',
  shutdown: '--shutdown-timeout-ms',
});

export const PATHS = Object.freeze(['direct', 'bridge-modern', 'bridge-auto-both', 'scripted-control']);
export const CLIENTS = Object.freeze(['go', 'ts']);
export const SERVERS = Object.freeze(['go', 'ts']);
export const REQUIRED_SCENARIOS = Object.freeze([1, 2, 3, 8]);
export const SKIPPABLE_SCENARIOS = Object.freeze([4, 5, 6, 7]);
export const CAPABILITY_IDS = Object.freeze([
  'stdio_client', 'streamable_http_server', 'stateless', 'progress',
  'cancellation', 'subscriptions_listen', 'server_discover', 'protocol_2026_07_28',
]);
export const CAPTURE_DEFAULTS = Object.freeze({ maxEvents: 200, maxBytesPerEvent: 16384, maxCapturesPerCell: 500 });
export const DEFAULTS = Object.freeze({
  clients: CLIENTS,
  servers: SERVERS,
  paths: PATHS,
  artifacts: 'artifacts/mcp-e2e-modern',
  ledger: 'ledger.jsonl',
  jackBin: null,
  keep: false,
  ...DEADLINES,
});
export const LEDGER_DEFAULT = DEFAULTS.ledger;
export const ARTIFACTS_DEFAULT = DEFAULTS.artifacts;

export function resolveConfig(overrides = {}) {
  const config = { ...DEFAULTS, ...overrides };
  for (const key of Object.keys(DEADLINES)) {
    if (!Number.isInteger(config[key]) || config[key] <= 0) throw new TypeError(`invalid ${TIMEOUT_FLAGS[key]} value`);
  }
  return Object.freeze(config);
}
