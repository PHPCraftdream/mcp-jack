import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';

export const MAX_IPC_BYTES = 2 * 1024 * 1024;
const MAX_OPERATIONS = 1024;
const CLEANUP_MS = 2000;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OP_NAMES = new Set([
  'issue', 'generate', 'from-seed', 'import-private', 'import-credential',
  'import-public', 'validate-credential',
]);
const TRANSFER_CLASSES = new Set([
  'malformed_json', 'wrong_root_type', 'oversized_envelope', 'unknown_version',
  'unknown_type', 'bad_member_set', 'wrong_field_type', 'bad_encoding', 'bad_url',
  'invalid_public_key', 'seed_pub_mismatch', 'kid_mismatch', 'non_canonical_bytes',
  'wrong_envelope_type', 'private_material_rejected', 'not_private', 'server_identity_mismatch',
]);
const FAILURE_CODES = new Set([
  'invalid_argv', 'invalid_operations', 'invalid_options', 'input_too_large',
  'spawn_failed', 'stdin_failed', 'stdout_failed', 'output_too_large', 'timeout',
  'interrupted', 'cleanup_timeout', 'child_exit', 'invalid_output', 'invalid_utf8',
  'invalid_json', 'duplicate_member', 'invalid_results', 'internal_error',
]);
const SAFE_ID = /^[a-z0-9][a-z0-9-]{0,79}$/u;
const SAFE_LABEL_CHARS = /[^a-zA-Z0-9 _:/=.,-]/gu;

function safeLabel(value) {
  if (typeof value !== 'string') return 'transfer probe';
  const cleaned = value.slice(0, 120).replace(SAFE_LABEL_CHARS, '-').trim();
  return cleaned || 'transfer probe';
}

function makeFailure(code, label, stage) {
  const safeCode = FAILURE_CODES.has(code) ? code : 'internal_error';
  const context = stage ? `${safeLabel(label)} stage=${stage}` : safeLabel(label);
  return new TransferFailure(safeCode, context);
}

export class TransferFailure extends Error {
  constructor(code, label = 'transfer probe') {
    const safeCode = FAILURE_CODES.has(code) ? code : 'internal_error';
    const safe = safeLabel(label);
    super(`${safeCode}: ${safe}`);
    this.name = 'TransferFailure';
    this.code = safeCode;
    this.label = safe;
  }
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ownKeysExactly(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function validateOperations(operations, label, stage) {
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > MAX_OPERATIONS) {
    throw makeFailure('invalid_operations', label, stage);
  }
  const ids = new Set();
  for (const operation of operations) {
    if (!isRecord(operation) || typeof operation.id !== 'string' || !SAFE_ID.test(operation.id) ||
        typeof operation.op !== 'string' || !OP_NAMES.has(operation.op) || ids.has(operation.id)) {
      throw makeFailure('invalid_operations', label, stage);
    }
    ids.add(operation.id);
  }
  return operations;
}

function isCanonicalB64u(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(value)) return false;
  try {
    return Buffer.from(value, 'base64url').toString('base64url') === value;
  } catch {
    return false;
  }
}

function validateSuccessResult(operation, result) {
  const commonSigner = ['id', 'ok', 'public_key', 'kid', 'public_envelope_b64u', 'signatures_b64u'];
  let expected;
  switch (operation.op) {
    case 'issue':
      expected = ['id', 'ok', 'credential_b64u', 'public_key', 'kid', 'export_fresh'];
      break;
    case 'generate':
    case 'from-seed':
    case 'import-private':
      expected = commonSigner;
      break;
    case 'import-credential':
      expected = [...commonSigner, 'connection'];
      break;
    case 'import-public':
      expected = ['id', 'ok', 'public_key', 'kid', 'public_only', 'verification_results'];
      break;
    case 'validate-credential':
      expected = ['id', 'ok'];
      break;
    default:
      return false;
  }
  if (!ownKeysExactly(result, expected) || result.id !== operation.id || result.ok !== true) return false;
  if (operation.op === 'issue') {
    return isCanonicalB64u(result.credential_b64u) && isCanonicalB64u(result.public_key) &&
      isCanonicalB64u(result.kid) && typeof result.export_fresh === 'boolean';
  }
  if (operation.op === 'generate' || operation.op === 'from-seed' || operation.op === 'import-private' || operation.op === 'import-credential') {
    if (!isCanonicalB64u(result.public_key) || !isCanonicalB64u(result.kid) ||
        !isCanonicalB64u(result.public_envelope_b64u) || !Array.isArray(result.signatures_b64u) ||
        !result.signatures_b64u.every(isCanonicalB64u)) return false;
    if (operation.op === 'import-credential') {
      const connection = result.connection;
      if (!ownKeysExactly(connection, ['url', 'aud', 'server_public_key', 'server_kid']) ||
          typeof connection.url !== 'string' || typeof connection.aud !== 'string' ||
          !isCanonicalB64u(connection.server_public_key) || !isCanonicalB64u(connection.server_kid)) return false;
    }
    return true;
  }
  if (operation.op === 'import-public') {
    return isCanonicalB64u(result.public_key) && isCanonicalB64u(result.kid) &&
      result.public_only === true && Array.isArray(result.verification_results) &&
      result.verification_results.every((entry) => typeof entry === 'boolean');
  }
  return operation.op === 'validate-credential';
}

/** Validate the child response wrapper and return its results array. */
export function validateResults(operations, parsed, label) {
  try {
    validateOperations(operations, label, 'validate');
    if (!ownKeysExactly(parsed, ['results']) || !Array.isArray(parsed.results) || parsed.results.length !== operations.length) {
      throw makeFailure('invalid_results', label, 'validate');
    }
    const seen = new Set();
    for (let index = 0; index < operations.length; index += 1) {
      const operation = operations[index];
      const result = parsed.results[index];
      if (!isRecord(result) || typeof result.id !== 'string' || !SAFE_ID.test(result.id) ||
          result.id !== operation.id || seen.has(result.id)) {
        throw makeFailure('invalid_results', label, 'validate');
      }
      seen.add(result.id);
      if (result.ok === false) {
        if (!ownKeysExactly(result, ['id', 'ok', 'class']) || !TRANSFER_CLASSES.has(result.class)) {
          throw makeFailure('invalid_results', label, 'validate');
        }
      } else if (!validateSuccessResult(operation, result)) {
        throw makeFailure('invalid_results', label, 'validate');
      }
    }
    return parsed.results;
  } catch (error) {
    if (error instanceof TransferFailure) throw error;
    throw makeFailure('invalid_results', label, 'validate');
  }
}

function resolveArgv(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((arg) => typeof arg !== 'string') || argv[0].length === 0) {
    throw new TypeError('invalid argv');
  }
  const windows = process.platform === 'win32';
  const pathLike = (value) => value.includes('/') || value.includes('\\') || (windows && /^[a-zA-Z]:/u.test(value));
  const resolvePath = (value, allowExe) => {
    const absolute = resolve(REPO_ROOT, value);
    if (allowExe && windows && !absolute.toLowerCase().endsWith('.exe') && !existsSync(absolute) && existsSync(`${absolute}.exe`)) {
      return `${absolute}.exe`;
    }
    return absolute;
  };
  const command = pathLike(argv[0]) ? resolvePath(argv[0], true) : argv[0];
  const args = argv.slice(1).map((arg) => {
    if (!pathLike(arg) || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//u.test(arg)) return arg;
    return resolvePath(arg, false);
  });
  return [command, ...args];
}

function listen(emitter, event, handler, listeners) {
  emitter.on(event, handler);
  listeners.push([emitter, event, handler]);
}

function removeListeners(listeners) {
  for (const [emitter, event, handler] of listeners) {
    try { emitter.off(event, handler); } catch { /* best effort cleanup */ }
  }
  listeners.length = 0;
}

function waitBounded(promise, milliseconds) {
  let timer;
  return Promise.race([
    promise.then(() => true),
    new Promise((resolveWait) => { timer = setTimeout(() => resolveWait(false), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

function destroyStreams(child) {
  for (const stream of [child.stdin, child.stdout, child.stderr]) {
    try { stream?.destroy?.(); } catch { /* best effort cleanup */ }
  }
}

async function stopOwned(record) {
  if (!record.closed && !record.exited && Number.isInteger(record.child.pid) && record.child.pid > 0) {
    try { record.child.kill('SIGKILL'); } catch { /* best effort; only this owned PID */ }
  }
  if (record.closed) return;
  const closed = await waitBounded(record.closePromise, CLEANUP_MS);
  if (!closed) {
    destroyStreams(record.child);
    await waitBounded(record.closePromise, 100);
  }
}

const owned = new Set();

/** Number of child processes currently owned by this module. */
export function ownedCount() {
  return owned.size;
}

/** Kill and reap only children started by this module. */
export async function shutdownOwned() {
  const records = [...owned];
  for (const record of records) record.abort();
  await Promise.all(records.map((record) => record.done));
  await Promise.all(records.map((record) => stopOwned(record)));
  const unclosed = records.find((record) => !record.closed);
  if (unclosed) throw makeFailure('cleanup_timeout', unclosed.label, 'close');
}

/** Spawn a finite transfer probe and return its strictly validated results. */
export async function runProbe(argv, operations, label, options = {}) {
  try {
    validateOperations(operations, label, 'input');
  } catch (error) {
    if (error instanceof TransferFailure) throw error;
    throw makeFailure('invalid_operations', label, 'input');
  }
  if (!isRecord(options)) throw makeFailure('invalid_options', label, 'input');
  const { timeoutMs = 30000, spawnImpl = spawn } = options;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647 ||
      typeof spawnImpl !== 'function') throw makeFailure('invalid_options', label, 'input');
  let safeArgv;
  try {
    safeArgv = resolveArgv(argv);
  } catch {
    throw makeFailure('invalid_argv', label, 'input');
  }
  let input;
  try {
    input = Buffer.from(`${JSON.stringify({ operations })}\n`, 'utf8');
  } catch {
    throw makeFailure('invalid_operations', label, 'input');
  }
  if (input.length > MAX_IPC_BYTES) throw makeFailure('input_too_large', label, 'stdin');

  let child;
  try {
    child = spawnImpl(safeArgv[0], safeArgv.slice(1), {
      cwd: REPO_ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false,
    });
  } catch {
    throw makeFailure('spawn_failed', label, 'spawn');
  }
  if (!child || typeof child.on !== 'function' || typeof child.kill !== 'function' || !child.stdin || !child.stdout || !child.stderr) {
    throw makeFailure('spawn_failed', label, 'spawn');
  }

  let resolveClose;
  let resolveFailure;
  let resolveDone;
  const closePromise = new Promise((resolveCloseEvent) => { resolveClose = resolveCloseEvent; });
  const failurePromise = new Promise((resolveFailureEvent) => { resolveFailure = resolveFailureEvent; });
  const done = new Promise((resolveDoneEvent) => { resolveDone = resolveDoneEvent; });
  const listeners = [];
  const chunks = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdinFinished = false;
  let closed = false;
  let exited = false;
  let closeInfo;
  let failure;
  let timer;
  let cleanupFailure = false;
  const startedAt = Date.now();
  const record = {
    child,
    closePromise,
    done,
    label: safeLabel(label),
    get closed() { return closed; },
    get exited() { return exited; },
    abort() { markFailure('interrupted', 'signal'); },
  };
  const onExit = () => { exited = true; };
  child.on('exit', onExit);
  owned.add(record);

  function markFailure(code, stage) {
    if (failure || closed) return;
    failure = makeFailure(code, label, stage);
    resolveFailure(failure);
  }

  try {
    listen(child.stdout, 'data', (chunk) => {
      if (failure) return;
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stdoutBytes + data.length > MAX_IPC_BYTES) {
        stdoutBytes = MAX_IPC_BYTES + 1;
        markFailure('output_too_large', 'stdout');
        return;
      }
      stdoutBytes += data.length;
      chunks.push(data);
    }, listeners);
    listen(child.stdout, 'error', () => markFailure('stdout_failed', 'stdout'), listeners);
    listen(child.stderr, 'data', (chunk) => {
      stderrBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
    }, listeners);
    listen(child.stderr, 'error', () => {}, listeners);
    listen(child.stdin, 'finish', () => { stdinFinished = true; }, listeners);
    listen(child.stdin, 'error', () => markFailure('stdin_failed', 'stdin'), listeners);
    listen(child, 'error', () => markFailure('spawn_failed', 'spawn'), listeners);
    listen(child, 'close', (code, signal) => {
      closed = true;
      closeInfo = { code, signal };
      clearTimeout(timer);
      resolveClose(closeInfo);
    }, listeners);

    const remainingMs = Math.max(0, timeoutMs - (Date.now() - startedAt));
    timer = setTimeout(() => markFailure('timeout', 'close'), remainingMs);
    try {
      child.stdin.end(input);
    } catch {
      markFailure('stdin_failed', 'stdin');
    }

    const outcome = await Promise.race([
      closePromise.then((info) => ({ info })),
      failurePromise.then((reason) => ({ reason })),
    ]);
    if (outcome.reason) throw outcome.reason;
    if (failure) throw failure;
    if (outcome.info.code !== 0) throw makeFailure('child_exit', label, 'close');
    if (!stdinFinished) throw makeFailure('stdin_failed', label, 'stdin');

    const output = Buffer.concat(chunks, stdoutBytes);
    if (output.length === 0 || output[output.length - 1] !== 0x0a || output.indexOf(0x0a) !== output.length - 1) {
      throw makeFailure('invalid_output', label, 'stdout');
    }
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(output);
    } catch {
      throw makeFailure('invalid_utf8', label, 'stdout');
    }
    let jsonText = text.slice(0, -1);
    if (jsonText.endsWith('\r')) jsonText = jsonText.slice(0, -1);
    if (!jsonText.startsWith('{') || !jsonText.endsWith('}')) throw makeFailure('invalid_output', label, 'stdout');
    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      throw makeFailure('invalid_json', label, 'stdout');
    }
    return validateResults(operations, parsed, label);
  } catch (error) {
    const safeFailure = error instanceof TransferFailure ? error : makeFailure('internal_error', label, 'probe');
    if (!closed) {
      cleanupFailure = true;
      await stopOwned(record);
    }
    if (cleanupFailure && !closed) throw makeFailure('cleanup_timeout', label, 'close');
    throw safeFailure;
  } finally {
    clearTimeout(timer);
    removeListeners(listeners);
    if (closed) {
      owned.delete(record);
      try { child.off('exit', onExit); } catch { /* best effort cleanup */ }
    } else {
      const ignoreError = () => {};
      for (const emitter of [child, child.stdin, child.stdout, child.stderr]) {
        try { emitter.on('error', ignoreError); } catch { /* best effort late-error guard */ }
      }
      child.once('close', (code, signal) => {
        closed = true;
        closeInfo = { code, signal };
        clearTimeout(timer);
        resolveClose(closeInfo);
        owned.delete(record);
        try { child.off('exit', onExit); } catch { /* best effort cleanup */ }
      });
    }
    resolveDone();
    // Keep stderr accounting local only; never surface diagnostic contents.
    void stderrBytes;
    void closeInfo;
  }
}
