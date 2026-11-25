import { spawn } from 'node:child_process';
import { bound } from './redact.mjs';

export function spawnJson(fixtureCmd, args = [], env = {}, timeoutMs = 30000) {
  const started = Date.now();
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let spawnError = null;
    let child;
    let closed = false;
    const timer = setTimeout(() => {
      timedOut = true;
      if (child?.pid && child.exitCode === null && child.signalCode === null) {
        try { child.kill('SIGKILL'); } catch { /* already exited */ }
      }
    }, timeoutMs);
    try {
      child = spawn(fixtureCmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (error) {
      clearTimeout(timer);
      resolve({ record: null, stderr: '', code: null, signal: null, timings: { elapsed_ms: Date.now() - started, timed_out: false, error: error.message } });
      return;
    }
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr = bound(stderr + chunk, 8192); });
    child.on('error', (error) => { spawnError = error; });
    child.once('close', (code, signal) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      const lines = stdout.split(/\r?\n/);
      if (lines.at(-1) === '') lines.pop();
      let record = null;
      let error = spawnError?.message ?? null;
      if (!error && lines.length !== 1) error = `expected exactly one JSON line; got ${lines.length}`;
      if (!error) {
        try { record = JSON.parse(lines[0]); }
        catch { error = 'malformed JSON stdout'; }
      }
      if (!error && (!record || typeof record !== 'object' || Array.isArray(record))) {
        record = null;
        error = 'stdout JSON must be an object';
      }
      resolve({ record, stderr, code, signal, timings: { elapsed_ms: Date.now() - started, timed_out: timedOut, error } });
    });
  });
}

export async function terminate(proc, timeoutMs) {
  if (!proc) return { code: null, signal: null };
  const close = proc._close ?? new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  if (proc.exitCode !== null || proc.signalCode !== null) return close;
  try { proc.kill('SIGTERM'); } catch { return close; }
  let timer;
  const stopped = await Promise.race([close.then((result) => ({ done: true, result })), new Promise((resolve) => { timer = setTimeout(() => resolve({ done: false }), timeoutMs); })]);
  if (timer) clearTimeout(timer);
  if (stopped.done) return stopped.result;
  if (proc.pid && proc.exitCode === null && proc.signalCode === null) {
    try { proc.kill('SIGKILL'); } catch { /* already exited */ }
  }
  return close;
}
