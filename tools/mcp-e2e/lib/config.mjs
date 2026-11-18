import { chmodSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---- constants ----------------------------------------------------------------

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const TS_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'ts');
export const GO_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'go');
export const RUST_DIR = join(REPO_ROOT, 'tools', 'mcp-e2e', 'rust');
export const PROTO = '2025-11-25';
export const LANGS = ['go', 'ts', 'rust'];
export const PINS = {
  go: 'go-sdk v1.8.0',
  ts: '@modelcontextprotocol/client+server 2.4.0',
  rust: 'rmcp =3.9.0',
  protocol: '2025-11-25',
};
// Per-client GET/501 tolerance notes derived from each SDK's stream-open code
// path; printed verbatim in the G4 summary section.
export const TOLERANCES = {
  go: '405 benign (connectStandaloneSSE); non-SSE 501 warns and closes, not fatal; SSE 501 fatal',
  ts: '405 benign; 501 (either content type) fatal ClientHttpFailedToOpenStream',
  rust: '405 -> ServerDoesNotSupportSse (benign); 501 (either content type) HTTP status error',
};
export const USAGE = 'usage: node tools/mcp-e2e/run.mjs [--clients go,ts,rust] [--servers go,ts,rust] [--list] [--keep] [--allow-skip-ts-server]';

export const POLL_MS = 200;
export const READY_TIMEOUT_MS = 10000;
export const SDK_TIMEOUT_MS = 30000;
export const STOP_GRACE_MS = 2000;
export const PROBE_STEP_MS = 10000;
export const PROBE_SILENCE_MS = 1500;
export const GET_TIMEOUT_MS = 5000;
export const TAIL_CAP = 8192; // gateway/bridge stdout+stderr tails stay bounded at 8 KB

export const tracked = new Set(); // every spawned child; killed on any exit path

// Frames for the driver-side purity probe conversation over the bridge stdio.
export const INIT_FRAME = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: PROTO, capabilities: {}, clientInfo: { name: 'e2e-purity-probe', version: '0.0.0' } },
};
export const INITIALIZED_FRAME = { jsonrpc: '2.0', method: 'notifications/initialized' };
export const LIST_FRAME = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

// ---- tiny utilities -------------------------------------------------------------

export function fail(msg, code = 2) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function parseJsonOr(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Content-type essence: everything before ';', trimmed, lowercased.
export function essence(contentType) {
  if (typeof contentType !== 'string' || contentType === '') return '-';
  return contentType.split(';')[0].trim().toLowerCase();
}

// Configs and other driver-written private files: mode 0600 (the jack CLI
// rejects anything else).
export function writePrivate(path, content) {
  writeFileSync(path, content);
  chmodSync(path, 0o600);
}

// Clip long text for expected-vs-actual report lines.
export function clipText(text, emptyLabel) {
  if (text === undefined || text === null || text === '') return emptyLabel;
  const t = text.length > 120 ? `${text.slice(0, 117)}...` : text;
  return JSON.stringify(t);
}

// ---- cell outcomes ----------------------------------------------------------------

export class CellFail extends Error {}

// A documented limitation, not a failure: the cell is marked SKIP with a reason.
export class KnownLimit extends Error {}
