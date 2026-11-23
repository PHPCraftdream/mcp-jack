// Tamper proxy for the modern matrix: a loopback TCP relay that rewrites a request AFTER the client signed it, preserving header instances and their order because it edits the raw request head itself.
import net from 'node:net';

export const PROXY_PRESETS = Object.freeze(['pass', 'tamper-name-once', 'duplicate-version', 'add-session', 'tamper-method-once']);

const HEAD_END = '\r\n\r\n';
const MAX_HEAD_BYTES = 64 * 1024;

// Lowercased header name of a raw header line; '' for a line without a colon.
const headerName = (line) => {
  const colon = line.indexOf(':');
  return colon === -1 ? '' : line.slice(0, colon).trim().toLowerCase();
};

// Replace only the value of a raw header line, keeping the received name
// casing and position; the proxy never re-renders names it did not touch.
const withValue = (line, value) => `${line.slice(0, line.indexOf(':') + 1)} ${value}`;

// Pure rewrite of one raw request head. `applied` is the per-proxy latch: every
// preset except `pass` acts at most once, and `applied` becomes true only when
// the head was actually changed, so a request without the target header lets
// the next one be tried.
export function transformHead(headText, preset, applied) {
  if (!PROXY_PRESETS.includes(preset)) throw new Error(`unknown proxy preset '${preset}'`);
  if (preset === 'pass' || applied) return { head: headText, applied };
  if (!headText.endsWith(HEAD_END)) return { head: headText, applied };
  const lines = headText.slice(0, -HEAD_END.length).split('\r\n');
  // Index 0 is the request line, so only header lines are considered.
  const first = (name) => lines.findIndex((line, i) => i > 0 && headerName(line) === name);
  const done = (changed) => ({ head: lines.join('\r\n') + HEAD_END, applied: changed });
  if (preset === 'tamper-name-once') {
    const i = first('mcp-name');
    if (i === -1) return { head: headText, applied };
    lines[i] = withValue(lines[i], 'region.other');
    return done(true);
  }
  if (preset === 'duplicate-version') {
    const i = first('mcp-protocol-version');
    if (i === -1) return { head: headText, applied };
    // Emitting the exact same line twice keeps the duplicate byte-identical.
    lines.splice(i, 0, lines[i]);
    return done(true);
  }
  if (preset === 'add-session') {
    // An instance the client already sent is left alone; only a missing one is
    // appended, so the server still sees at most one of each.
    if (!lines.some((line, i) => i > 0 && headerName(line) === 'mcp-session-id')) lines.push('Mcp-Session-Id: sess-1');
    if (!lines.some((line, i) => i > 0 && headerName(line) === 'last-event-id')) lines.push('Last-Event-ID: 7');
    return done(true);
  }
  const i = first('mcp-method');
  if (i === -1) return { head: headText, applied };
  lines[i] = withValue(lines[i], 'tools/list');
  return done(true);
}

// Start the relay on 127.0.0.1:0 and resolve once it listens. The returned
// close() destroys every socket so a run shuts down deterministically, and
// requests() reports how many request heads were forwarded. With `disable` the
// head is never rewritten: that control proves the tamper scenarios need the
// proxy.
export function startTamperProxy({ upstreamPort, preset = 'pass', disable = false }) {
  let applied = false;
  let forwarded = 0;
  const sockets = new Set();

  // The proxy writes the request bytes itself, which is why repeated header
  // instances and their order survive the relay untouched.
  const server = net.createServer((client) => {
    sockets.add(client);
    let buffered = Buffer.alloc(0);
    let upstream = null;
    let headDone = false;
    let clientEnded = false;

    const destroyBoth = () => {
      client.destroy();
      if (upstream) upstream.destroy();
    };

    const onData = (chunk) => {
      buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk]);
      const idx = buffered.indexOf(HEAD_END);
      if (idx === -1) {
        // A head this large is a harness failure, not something to forward.
        if (buffered.length > MAX_HEAD_BYTES) destroyBoth();
        return;
      }
      headDone = true;
      client.removeListener('data', onData);
      client.pause();
      let head = buffered.subarray(0, idx + HEAD_END.length).toString('latin1');
      const remainder = buffered.subarray(idx + HEAD_END.length);
      buffered = Buffer.alloc(0);
      if (!disable) {
        try {
          const transformed = transformHead(head, preset, applied);
          head = transformed.head;
          applied = transformed.applied;
        } catch {
          destroyBoth();
          return;
        }
      }
      upstream = net.connect({ host: '127.0.0.1', port: upstreamPort }, () => {
        // latin1 round-trips every byte of the head exactly, and the head is
        // written before piping so a body that arrived with it is framed by
        // the transformed headers, never by the originals.
        upstream.write(Buffer.concat([Buffer.from(head, 'latin1'), remainder]));
        forwarded++;
        if (clientEnded || client.readableEnded) {
          upstream.end();
          return;
        }
        client.pipe(upstream);
        upstream.pipe(client);
        client.resume();
      });
      sockets.add(upstream);
      upstream.on('error', destroyBoth);
      // Ending a direction closes the peer's direction, and the close handlers
      // below destroy both sockets; destroying on 'end' instead would drop a
      // body that is still buffered in flight.
      client.on('end', () => { if (upstream.connecting) clientEnded = true; else upstream.end(); });
      upstream.on('end', () => client.end());
      client.on('close', destroyBoth);
      upstream.on('close', destroyBoth);
    };

    client.on('data', onData);
    client.on('error', destroyBoth);
    client.on('end', () => { if (!headDone) destroyBoth(); });
  });

  const close = () => new Promise((resolveClose) => {
    for (const socket of sockets) socket.destroy();
    sockets.clear();
    if (!server.listening) return resolveClose();
    server.close(() => resolveClose());
  });

  return new Promise((resolveStart, rejectStart) => {
    // Reject rather than throw so callers see a bad preset through the same
    // promise they await for the listener.
    if (!PROXY_PRESETS.includes(preset)) return rejectStart(new Error(`unknown proxy preset '${preset}'`));
    server.once('error', rejectStart);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', rejectStart);
      // A post-start listener error has no caller to surface it to and must
      // not take the whole driver down.
      server.on('error', () => {});
      resolveStart({ port: server.address().port, close, requests: () => forwarded });
    });
  });
}
