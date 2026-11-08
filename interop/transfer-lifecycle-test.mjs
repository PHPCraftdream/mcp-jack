import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { TransferCheckFailure } from './transfer-checks.mjs';
import { TransferFailure, ownedCount, runProbe } from './transfer-process.mjs';

const LABEL = 'transfer lifecycle self-test';
const operations = [{ id: 'control', op: 'validate-credential' }];
const childScript = fileURLToPath(new URL('./tools/transfer-child.mjs', import.meta.url));

export async function lifecycleTests(report) {
  let count = 0;
  const check = (condition) => { if (!condition) throw new TransferCheckFailure(LABEL); };
  const passed = (detail = '') => { count += 1; report(`self-test PASS ${LABEL}${detail ? ` ${detail}` : ''}`); };
  const invoke = (mode, options = {}) => runProbe(
    [process.execPath, childScript, mode], operations, LABEL, { timeoutMs: 5000, ...options },
  );
  const failure = async (mode, code, options) => {
    let error;
    try { await invoke(mode, options); } catch (caught) { error = caught; }
    check(error instanceof TransferFailure && error.code === code);
    check(ownedCount() === 0);
    return error;
  };

  for (const mode of ['good', 'final-chunks']) {
    const results = await invoke(mode);
    check(results.length === 1 && results[0].id === 'control' && results[0].ok === true);
    check(ownedCount() === 0);
    passed(mode);
  }
  for (const [mode, code] of [
    ['exit2', 'child_exit'], ['truncated', 'invalid_output'], ['invalid', 'invalid_output'],
    ['no-newline', 'invalid_output'], ['extra-output', 'invalid_output'],
    ['invalid-utf8', 'invalid_utf8'], ['overflow', 'output_too_large'],
  ]) {
    await failure(mode, code);
    passed(mode);
  }
  const secretError = await failure('stderr-secret', 'child_exit');
  check(!secretError.message.includes('TRANSFER-LIFECYCLE-SECRET'));
  passed('secret');

  let originalPid;
  let killedPid;
  let killedSignal;
  await failure('hang', 'timeout', {
    timeoutMs: 100,
    spawnImpl: (...args) => {
      const child = spawn(...args);
      originalPid = child.pid;
      const kill = child.kill.bind(child);
      child.kill = (signal) => { killedPid = child.pid; killedSignal = signal; return kill(signal); };
      return child;
    },
  });
  check(Number.isInteger(originalPid) && killedPid === originalPid && killedSignal === 'SIGKILL');
  passed('hang');

  await failure('good', 'spawn_failed', { spawnImpl: () => { throw new Error('untrusted spawn detail'); } });
  passed('spawn');

  let invalidOptions;
  try { await invoke('good', { timeoutMs: 0 }); } catch (error) { invalidOptions = error; }
  check(invalidOptions instanceof TransferFailure && invalidOptions.code === 'invalid_options');
  check(ownedCount() === 0);
  passed('invalidoptions');

  let afterExit = false;
  const synthetic = () => {
    const child = new EventEmitter();
    child.pid = 424242;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let request = '';
    child.stdin = new Writable({
      write(chunk, _encoding, callback) { request += chunk.toString(); callback(); },
      final(callback) {
        callback();
        setImmediate(() => {
          child.emit('exit', 0, null);
          setImmediate(() => {
            afterExit = true;
            const parsed = JSON.parse(request);
            const output = `${JSON.stringify({ results: parsed.operations.map(({ id }) => ({ id, ok: true })) })}\n`;
            child.stdout.end(output, () => child.emit('close', 0, null));
          });
        });
      },
    });
    child.kill = () => true;
    return child;
  };
  const syntheticResults = await runProbe(['synthetic-ipc'], operations, LABEL, { spawnImpl: synthetic });
  check(afterExit && syntheticResults.length === 1 && syntheticResults[0].ok === true);
  check(ownedCount() === 0);
  passed();

  let unclosableChild;
  let unclosableKilledPid;
  const unclosable = () => {
    const child = new EventEmitter();
    unclosableChild = child;
    child.pid = 424243;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
    child.kill = (signal) => { unclosableKilledPid = signal === 'SIGKILL' ? child.pid : undefined; return true; };
    return child;
  };
  let cleanupError;
  try {
    await runProbe(['synthetic-unclosable'], operations, LABEL, { timeoutMs: 50, spawnImpl: unclosable });
  } catch (error) {
    cleanupError = error;
  }
  check(cleanupError instanceof TransferFailure && cleanupError.code === 'cleanup_timeout');
  check(unclosableKilledPid === 424243 && ownedCount() === 1);
  unclosableChild.emit('close', 0, null);
  check(ownedCount() === 0);
  passed('unclosable child cleanup');
  return count;
}
