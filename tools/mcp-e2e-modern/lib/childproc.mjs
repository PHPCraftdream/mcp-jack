export async function terminate(proc, timeoutMs) {
  if (!proc) return { code: null, signal: null };
  const close = proc._close ?? new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  const destroyPipes = () => { for (const s of [proc.stdout, proc.stderr, proc.stdin]) { try { s?.destroy(); } catch { } } };
  const boundedClose = async () => {
    let timer;
    try { return await Promise.race([close, new Promise((resolve) => { timer = setTimeout(() => resolve({ code: proc.exitCode ?? null, signal: proc.signalCode ?? null }), 1000); })]); }
    finally { clearTimeout(timer); }
  };
  if (proc.exitCode !== null || proc.signalCode !== null) { destroyPipes(); const result = await boundedClose(); destroyPipes(); return result; }
  try { proc.kill('SIGTERM'); } catch { destroyPipes(); const result = await boundedClose(); destroyPipes(); return result; }
  let timer;
  const stopped = await Promise.race([close.then((result) => ({ done: true, result })), new Promise((resolve) => { timer = setTimeout(() => resolve({ done: false }), timeoutMs); })]);
  if (timer) clearTimeout(timer);
  if (stopped.done) { destroyPipes(); const result = await boundedClose(); destroyPipes(); return result; }
  destroyPipes();
  if (proc.pid && proc.exitCode === null && proc.signalCode === null) { try { proc.kill('SIGKILL'); } catch { /* already exited */ } }
  const result = await boundedClose(); destroyPipes(); return result;
}
