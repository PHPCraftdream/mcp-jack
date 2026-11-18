import { spawn } from 'node:child_process';
import { statSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { connect as tcpConnect, createServer as tcpCreateServer } from 'node:net';
import { resolve } from 'node:path';
import { REPO_ROOT, POLL_MS, STOP_GRACE_MS, TAIL_CAP, tracked, sleep } from './config.mjs';

// ---- child process helpers ------------------------------------------------------

// Spawn with stdio pipes and continuous drain from the first byte: pipes never
// back up and captured tails stay capped. `close` (not `exit`) is the capture
// barrier — all stdio pipes are drained only after `close`.
export function makeChild(cmd, args, opts = {}) {
  const cap = typeof opts.cap === 'number' ? opts.cap : TAIL_CAP;
  const child = spawn(cmd, args, {
    cwd: REPO_ROOT,
    env: opts.env ? { ...process.env, ...opts.env } : process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let stdout = '';
  let stderr = '';
  let stdoutBytes = 0;
  child.stdout.on('data', (d) => {
    stdoutBytes += d.length;
    stdout = (stdout + d.toString('utf8')).slice(-cap);
  });
  child.stderr.on('data', (d) => {
    stderr = (stderr + d.toString('utf8')).slice(-cap);
  });
  // Consuming 'error' keeps spawn failures (ENOENT) from crashing the driver;
  // _failed surfaces them to whoever is waiting.
  child._failed = new Promise((res) => {
    child.once('error', res);
  });
  // EPIPE after child death is expected; the write callback carries the error.
  child.stdin.on('error', () => {});
  child._stdout = () => stdout;
  child._stderr = () => stderr;
  child._stdoutBytes = () => stdoutBytes;
  child._close = new Promise((res) => {
    child.once('close', (code, signal) => res({ code, signal }));
  });
  tracked.add(child);
  return child;
}

// SIGTERM, wait STOP_GRACE_MS, then SIGKILL if still alive.
export async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill('SIGTERM');
  } catch {
    return;
  }
  const gone = await Promise.race([child._close.then(() => true), sleep(STOP_GRACE_MS).then(() => false)]);
  if (gone) return;
  try {
    child.kill('SIGKILL');
  } catch { /* already dead */ }
  await Promise.race([child._close, sleep(STOP_GRACE_MS)]);
}

// ---- readiness waits --------------------------------------------------------------

export function freePort() {
  return new Promise((res, rej) => {
    const srv = tcpCreateServer();
    srv.once('error', rej);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => res(port));
    });
  });
}

export async function waitForFile(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      statSync(path);
      return true;
    } catch { /* not there yet */ }
    if (Date.now() >= deadline) return false;
    await sleep(POLL_MS);
  }
}

export async function waitForTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const open = await new Promise((res) => {
      const s = tcpConnect({ host: '127.0.0.1', port });
      const t = setTimeout(() => {
        s.destroy();
        res(false);
      }, POLL_MS);
      s.once('connect', () => {
        clearTimeout(t);
        s.destroy();
        res(true);
      });
      s.once('error', () => {
        clearTimeout(t);
        res(false);
      });
    });
    if (open) return true;
    if (Date.now() >= deadline) return false;
    await sleep(POLL_MS);
  }
}

// One-shot raw HTTP request; resolves with {status, contentType, body} or
// {error} instead of rejecting so callers can record transport errors.
export function rawRequest(options, timeoutMs) {
  return new Promise((resolve) => {
    // agent:false keeps the one-shot socket off the keep-alive pool so the
    // driver can exit deterministically once everything is torn down.
    const req = httpRequest({ ...options, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, contentType: res.headers['content-type'] ?? null, body: Buffer.concat(chunks) }));
      res.on('error', (e) => resolve({ error: e.message }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timeout after ${timeoutMs}ms`)));
    req.on('error', (e) => resolve({ error: e.message }));
    req.end();
  });
}
