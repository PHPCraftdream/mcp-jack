import { createServer as httpCreateServer, request as httpRequest } from 'node:http';
import { resolve } from 'node:path';
import { PROTO, PROBE_STEP_MS, PROBE_SILENCE_MS, INIT_FRAME, INITIALIZED_FRAME, LIST_FRAME, fail, sleep, parseJsonOr, clipText, CellFail } from './config.mjs';
import { makeChild, stopChild } from './child.mjs';

// ---- capture/tamper proxy ------------------------------------------------------

// Forwarding capture proxy: one upstream request per client request, response
// buffered and replayed with the upstream status/headers. In tamper mode the
// response's first byte '{' -> '[' is flipped on a same-length Buffer copy so
// the upstream content-length header stays valid for the client.
export function startProxy(proxyPort, gwPort, tamper) {
  const captures = [];
  // Diagnostics: requests are recorded on receipt, before the upstream responds.
  const received = [];
  const server = httpCreateServer((req, res) => {
    received.push(`${req.method} ${req.url}`);
    req.on('error', () => {
      try {
        res.destroy();
      } catch { /* client gone */ }
    });
    res.on('error', () => { /* client vanished mid-response */ });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const entry = {
        method: req.method,
        path: req.url,
        accept: typeof req.headers.accept === 'string' ? req.headers.accept : null,
        content_type: typeof req.headers['content-type'] === 'string' ? req.headers['content-type'] : null,
        mcp_protocol_version: typeof req.headers['mcp-protocol-version'] === 'string' ? req.headers['mcp-protocol-version'] : null,
        has_jack_auth: req.headers['jack-auth'] !== undefined,
        request_body: Buffer.concat(chunks).toString('utf8'),
      };
      const upstream = httpRequest(
        {
          host: '127.0.0.1',
          port: gwPort,
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: `127.0.0.1:${gwPort}` },
          agent: false,
        },
        (up) => {
          const out = [];
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            const body = Buffer.concat(out);
            entry.status = up.statusCode;
            entry.response_content_type = typeof up.headers['content-type'] === 'string' ? up.headers['content-type'] : null;
            entry.response_body = body.toString('utf8');
            let send = body;
            if (tamper && send.length > 0 && send[0] === 0x7b) {
              send = Buffer.from(send); // same-length copy: content-length stays valid
              send[0] = 0x5b;
              entry.tampered = true;
            }
            captures.push(entry);
            const headers = {};
            for (const [k, v] of Object.entries(up.headers)) {
              if (v !== undefined) headers[k] = v;
            }
            try {
              res.writeHead(up.statusCode, headers);
              res.end(send);
            } catch { /* client already gone */ }
          };
          up.on('data', (c) => out.push(c));
          up.on('end', finish);
          up.on('error', (e) => {
            if (done) return;
            done = true;
            entry.error = e.message;
            captures.push(entry);
            res.destroy();
          });
        },
      );
      upstream.on('error', (e) => {
        entry.error = e.message;
        captures.push(entry);
        try {
          res.writeHead(502, { 'content-type': 'text/plain' });
          res.end('mcp-e2e proxy: upstream request failed');
        } catch { /* client already gone */ }
      });
      // Without end() the request to the gateway never completes: the body is not sent.
      upstream.end(Buffer.concat(chunks));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(proxyPort, '127.0.0.1', () => {
      server.off('error', reject);
      server.on('error', () => { /* late socket errors must not kill the run */ });
      resolve({
        port: proxyPort,
        captures,
        received,
        close: () => new Promise((done) => {
          if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
          server.close(() => done());
        }),
      });
    });
  });
}

// ---- purity probe (framing oracle) ------------------------------------------------

// write a newline-delimited JSON frame; rejects via the write callback on EPIPE.
export function writeFrame(child, frame) {
  return new Promise((resolve, reject) => {
    child.stdin.write(JSON.stringify(frame) + '\n', (e) => (e ? reject(e) : resolve()));
  });
}

// Complete-line collector over bridge stdout with per-step timeouts. Only
// newline-terminated lines count; unterminated remainders surface via
// `partial` at the end-of-conversation checks.
export function makeFrameCollector(child) {
  let partial = '';
  const lines = [];
  let waiter = null;
  child.stdout.on('data', (d) => {
    partial += d.toString('utf8');
    let idx;
    while ((idx = partial.indexOf('\n')) !== -1) {
      lines.push(partial.slice(0, idx));
      partial = partial.slice(idx + 1);
    }
    if (waiter && lines.length >= waiter.need) {
      const w = waiter;
      waiter = null;
      w.resolve();
    }
  });
  return {
    count: () => lines.length,
    line: (i) => lines[i],
    waitLines(need, timeoutMs, label) {
      if (lines.length >= need) return Promise.resolve();
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn, arg) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          waiter = null;
          fn(arg);
        };
        const timer = setTimeout(
          () => finish(reject, new Error(`${label}: timeout after ${timeoutMs}ms (want frame ${need}, have ${lines.length})`)),
          timeoutMs,
        );
        child._close.then((r) => finish(reject, new Error(`${label}: bridge exited early (code ${r.code} signal ${r.signal}) with ${lines.length} frame(s); stderr tail: ${child._stderr().trim()}`)));
        waiter = { need, resolve: () => finish(resolve) };
      });
    },
  };
}

// A probe frame must be a bare JSON-RPC response object: jsonrpc 2.0, scalar
// id, and never a method field (requests never travel upstream->bridge).
export function frameViolation(line) {
  const o = parseJsonOr(line);
  if (!o || typeof o !== 'object' || Array.isArray(o)) return 'not a JSON object';
  if (o.jsonrpc !== '2.0') return `jsonrpc ${JSON.stringify(o.jsonrpc)}`;
  if (!('id' in o) || (typeof o.id !== 'number' && typeof o.id !== 'string')) return 'id missing or not numeric/string';
  if ('method' in o) return 'response carries a method field';
  return null;
}

// Driver-side framing/purity oracle: raw newline-delimited JSON over the
// bridge stdio — explicitly NOT an official MCP client. `tamper` switches to
// the negative variant: the flipped response must fail the bridge's response
// verification locally (exit 1, zero stdout, exact diagnostic).
export async function runPurityProbe(chk, jackBin, configPath, marker, tamper) {
  const child = makeChild(jackBin, ['bridge', '--config', configPath]);
  try {
    if (tamper) {
      try {
        await writeFrame(child, INIT_FRAME);
      } catch (e) {
        chk.bad(`tamper probe: bridge stdin write failed: ${e.message}`);
        return;
      }
      const outcome = await Promise.race([
        child._close.then((r) => ({ kind: 'close', ...r })),
        sleep(PROBE_STEP_MS).then(() => ({ kind: 'timeout' })),
      ]);
      if (outcome.kind === 'timeout') {
        chk.bad('tamper probe: bridge did not exit within 10s after the tampered initialize');
        return;
      }
      chk.must(outcome.code === 1, 'tamper probe bridge exit code', '1', String(outcome.code));
      chk.must(child._stdoutBytes() === 0, 'tamper probe bridge stdout bytes', '0', String(child._stdoutBytes()));
      const tail = child._stderr().trim();
      chk.must(
        tail === 'jack: remote call failed; no retry performed',
        'tamper probe bridge stderr',
        "'jack: remote call failed; no retry performed'",
        clipText(tail, "''"),
      );
      return;
    }

    const frames = makeFrameCollector(child);
    try {
      await writeFrame(child, INIT_FRAME);
      await frames.waitLines(1, PROBE_STEP_MS, 'probe initialize response');
      const r1 = parseJsonOr(frames.line(0));
      chk.must(
        r1 && r1.jsonrpc === '2.0' && r1.id === 1 && !('error' in r1) && r1.result && r1.result.protocolVersion === PROTO,
        'probe initialize response shape',
        `id=1 result.protocolVersion=${PROTO} no error`,
        clipText(frames.line(0), '(no frame)'),
      );
      chk.must(frames.count() === 1, 'probe stdout frames after initialize', 'exactly 1', String(frames.count()));

      await writeFrame(child, INITIALIZED_FRAME);
      await sleep(PROBE_SILENCE_MS);
      chk.must(frames.count() === 1, 'probe silence after notifications/initialized', 'no new frame within 1.5s', `${frames.count()} frame(s)`);

      await writeFrame(child, LIST_FRAME);
      await frames.waitLines(2, PROBE_STEP_MS, 'probe tools/list response');
      const r2 = parseJsonOr(frames.line(1));
      const tools = r2 && r2.result && Array.isArray(r2.result.tools) ? r2.result.tools : null;
      chk.must(
        r2 && r2.jsonrpc === '2.0' && r2.id === 2 && !('error' in r2) && tools && tools.some((t) => t && t.name === 'echo'),
        'probe tools/list response shape',
        "id=2 result.tools includes 'echo'",
        clipText(frames.line(1), '(no frame)'),
      );
      chk.must(frames.count() === 2, 'probe stdout frames after tools/list', 'exactly 2', String(frames.count()));

      await writeFrame(child, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: marker } } });
      await frames.waitLines(3, PROBE_STEP_MS, 'probe tools/call response');
      const r3 = parseJsonOr(frames.line(2));
      chk.must(
        r3 && r3.jsonrpc === '2.0' && r3.id === 3 && !('error' in r3) && JSON.stringify(r3).includes(marker),
        'probe tools/call response shape',
        `id=3 no error, contains ${marker}`,
        clipText(frames.line(2), '(no frame)'),
      );
      chk.must(frames.count() === 3, 'probe stdout frames after tools/call', 'exactly 3', String(frames.count()));

      child.stdin.end();
      const done = await Promise.race([
        child._close.then((r) => ({ kind: 'close', ...r })),
        sleep(PROBE_STEP_MS).then(() => ({ kind: 'timeout' })),
      ]);
      if (done.kind === 'timeout') throw new Error('bridge did not exit within 10s after stdin closed');
      chk.must(done.code === 0, 'probe bridge exit code', '0', String(done.code));
      chk.must(child._stderr().length === 0, 'probe bridge stderr empty', "''", clipText(child._stderr(), "''"));

      const parts = child._stdout().split('\n');
      const trailing = parts.pop();
      chk.must(trailing === '', 'probe stdout fully newline-terminated', "'' trailing", trailing === undefined ? '(empty stdout)' : clipText(trailing, "''"));
      chk.must(parts.length === 3, 'probe stdout total frames', 'exactly 3', String(parts.length));
      for (let i = 0; i < parts.length; i++) {
        const v = frameViolation(parts[i]);
        chk.must(v === null, `probe frame ${i} is a bare JSON-RPC response object`, 'valid response object', v ?? 'valid');
      }
    } catch (e) {
      throw new CellFail(`probe conversation aborted: ${e.message}`);
    }
  } finally {
    if (child.exitCode === null && child.signalCode === null) await stopChild(child);
  }
}
