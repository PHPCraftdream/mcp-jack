// HTTP-aware TCP/SSE relay. Response framing is decoded before event transforms and
// rebuilt only after the complete response body has been received.
import net from 'node:net';

const KNOWN = new Set(['drop', 'reorder', 'edit-data', 'truncate', 'splice', 'replay', 'after-cutoff']);
const MAX_HEAD = 64 * 1024;
const MAX_BODY = 32 *  1024 * 1024;
function parseEvent(bytes) {
  const text = bytes.toString('latin1');
  const fields = {};
  for (const line of text.split(/\r\n|\n|\r/)) {
    if (!line || line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const name = colon < 0 ? line : line.slice(0, colon);
    const raw = colon < 0 ? '' : line.slice(colon + 1);
    // SSE removes at most one optional leading space; event values are not trimmed.
    const value = raw.startsWith(' ') ? raw.slice(1) : raw;
    if (name === 'event') fields.kind = value;
    else if (name === 'jack') fields.jack = value;
    else if (name === 'data') fields.data = value;
  }
  const jack = fields.jack || '';
  for (const part of jack.split(',')) { const at = part.indexOf('='); if (at > 0) fields[part.slice(0, at).trim()] = part.slice(at + 1).trim(); }
  return { text, fields };
}
function editData(bytes) {
  const out = Buffer.from(bytes), text = out.toString('latin1');
  const match = /(?:^|\r?\n)data: ([^\r\n]+)/m.exec(text);
  if (!match) throw Error('edit-data relay cannot find a nonempty data field');
  const index = match.index + match[0].indexOf('data: ') + 6;
  out[index] = out[index] === 0x78 ? 0x79 : 0x78;
  return out;
}
function splitHead(buffer) {
  const at = buffer.indexOf('\r\n\r\n');
  if (at < 0) return null;
  const text = buffer.subarray(0, at).toString('latin1');
  const lines = text.split('\r\n');
  if (!/^HTTP\/1\.[01] \d{3}(?:\s|$)/.test(lines[0])) throw Error('malformed upstream HTTP status line');
  const headers = [];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon <= 0) throw Error('malformed upstream HTTP header');
    headers.push([line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim()]);
  }
  const transfer = headers.filter(([name]) => name === 'transfer-encoding').flatMap(([, value]) => value.split(',').map(v => v.trim().toLowerCase()));
  const lengths = headers.filter(([name]) => name === 'content-length').map(([, value]) => value);
  if (transfer.length && lengths.length) throw Error('ambiguous upstream HTTP framing');
  if (lengths.some(v => !/^(0|[1-9][0-9]*)$/.test(v)) || new Set(lengths).size > 1) throw Error('invalid upstream Content-Length');
  return { size: at + 4, lines, headers, chunked: transfer.at(-1) === 'chunked', length: lengths.length ? Number(lengths[0]) : null };
}
function decodeChunks(buffer, eof) {
  let at = 0; const parts = [];
  for (;;) {
    const lineEnd = buffer.indexOf('\r\n', at);
    if (lineEnd < 0) return eof ? (() => { throw Error('truncated chunk size'); })() : null;
    const line = buffer.subarray(at, lineEnd).toString('latin1');
    if (!/^[0-9a-fA-F]+(?:;[^\r\n]*)?$/.test(line)) throw Error('invalid chunk size');
    const size = Number.parseInt(line.split(';')[0], 16); at = lineEnd + 2;
    if (!Number.isSafeInteger(size)) throw Error('invalid chunk size');
    if (size === 0) {
      const end = buffer.indexOf('\r\n\r\n', at);
      if (buffer.subarray(at, at + 2).equals(Buffer.from('\r\n'))) return { body: Buffer.concat(parts), used: at + 2 };
      if (end < 0) return eof ? (() => { throw Error('truncated chunk trailers'); })() : null;
      return { body: Buffer.concat(parts), used: end + 4 };
    }
    if (buffer.length < at + size + 2) return eof ? (() => { throw Error('truncated chunk data'); })() : null;
    if (buffer[at + size] !== 13 || buffer[at + size + 1] !== 10) throw Error('invalid chunk terminator');
    parts.push(buffer.subarray(at, at + size)); at += size + 2;
  }
}
function eventTransform(body, transform, scenario, sendEvent) {
  let buffer = body, output = [], applied = false, responseEnded = false, held = new Map(), reordered = false;
  const deliver = bytes => {
    const { fields } = parseEvent(bytes), seq = Number(fields.seq);
    if (transform === 'drop' && !applied && seq === Number(scenario?.relay_options?.seq ?? 1)) { applied = true; return; }
    if (transform === 'splice' && fields.seq !== undefined && fields.kind !== 'jack-end' && !applied) {
      // This is explicitly a fixture frame from another stream; it is not generated or captured.
      output.push(Buffer.from(scenario.relayFrame)); applied = true; return;
    }
    if (transform === 'after-cutoff' && fields.kind === 'jack-end') {
      // Inject caller-supplied bytes bound to this response's SID; the relay rewrites seq to the replaced end frame's sequence.
      const supplied = parseEvent(scenario.relayCutoffFrame);
      if (supplied.fields.kind !== 'message' || scenario.relayCutoffSid !== scenario.activeSid)
        throw Error("relay transform 'after-cutoff' requires the pre-signed cutoff frame for the active sid");
      output.push(Buffer.from(supplied.text.replace(/jack: seq=\d+/, `jack: seq=${fields.seq}`))); applied = true; responseEnded = true; return;
    }
    if (transform === 'edit-data' && !applied && fields.seq !== undefined && fields.kind !== 'jack-end') { output.push(editData(bytes)); applied = true; return; }
    if (transform === 'truncate' && fields.kind === 'jack-end') { applied = true; responseEnded = true; return; }
    if (transform === 'replay' && !applied && seq === 0) { output.push(bytes, bytes); applied = true; return; }
    if (transform === 'reorder' && (seq === 0 || seq === 1)) {
      held.set(seq, bytes);
      if (held.has(0) && held.has(1)) { output.push(held.get(1), held.get(0)); held.clear(); applied = true; reordered = true; }
      return;
    }
    if (transform === 'reorder' && !reordered && fields.kind === 'jack-end') { for (const [, item] of [...held].sort((a, b) => a[0] - b[0])) output.push(item); held.clear(); }
    output.push(bytes);
  };
  while (true) {
    const crlf = buffer.indexOf('\r\n\r\n'), lf = buffer.indexOf('\n\n');
    let end, delim;
    if (crlf >= 0 && (lf < 0 || crlf <= lf)) { end = crlf; delim = 4; }
    else if (lf >= 0) { end = lf; delim = 2; } else break;
    deliver(buffer.subarray(0, end + delim)); buffer = buffer.subarray(end + delim);
    if (responseEnded) break;
  }
  if (buffer.length && !responseEnded) output.push(buffer);
  return { body: Buffer.concat(output), applied, responseEnded };
}
function rebuild(head, body, chunked) {
  const lines = head.lines.filter(line => !/^content-length\s*:/i.test(line) && !/^transfer-encoding\s*:/i.test(line) && !/^connection\s*:/i.test(line));
  if (chunked) {
    lines.push('Transfer-Encoding: chunked', 'Connection: close');
    const pieces = [];
    for (let at = 0; at < body.length; at += 4096) { const part = body.subarray(at, Math.min(at + 4096, body.length)); pieces.push(Buffer.from(`${part.length.toString(16)}\r\n`), part, Buffer.from('\r\n')); }
    pieces.push(Buffer.from('0\r\n\r\n'));
    return Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1'), ...pieces]);
  }
  lines.push(`Content-Length: ${body.length}`, 'Connection: close');
  return Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1'), body]);
}

export async function startRelay({ upstreamPort, transform = 'pass', scenario } = {}) {
  if (!KNOWN.has(transform) && transform !== 'pass') throw Error(`unknown relay transform: ${transform}`);
  if (!Number.isInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535) throw Error('invalid upstream port');
  if (transform === 'splice' && !Buffer.isBuffer(scenario?.relayFrame)) throw Error("relay transform 'splice' requires a pre-signed second-stream fixture frame");
  if (transform === 'after-cutoff' && typeof scenario?.relayCutoffSign !== 'function') throw Error("relay transform 'after-cutoff' requires a relayCutoffSign({sid,seq,prev}) callback signing the injected frame");
  const sockets = new Set(); let applied = false, closePromise;
  const track = socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {}); };
  const server = net.createServer(downstream => {
    track(downstream);
    const upstream = net.connect(upstreamPort, '127.0.0.1'); track(upstream);
    let requestEnded = false, responseBuffer = Buffer.alloc(0), head = null, completed = false;
    downstream.on('data', chunk => { if (!upstream.destroyed && !upstream.write(chunk)) downstream.pause(); });
    upstream.on('drain', () => downstream.resume());
    downstream.on('end', () => { requestEnded = true; upstream.end(); });
    downstream.on('close', () => { if (!requestEnded && !upstream.destroyed) upstream.destroy(); });
    upstream.on('error', () => downstream.destroy());
    if (transform === 'pass' || process.env.JACK_STREAM_SELFTEST_NO_TAMPER === '1') {
      upstream.on('data', chunk => { if (!downstream.destroyed && !downstream.write(chunk)) upstream.pause(); });
      downstream.on('drain', () => upstream.resume());
      upstream.on('end', () => { if (!downstream.destroyed) downstream.end(); });
      return;
    }
    if (transform === 'after-cutoff') {
      // Streaming path: forward each decoded event live so the client can verify it
      // under the clock in effect when it arrives; only the end frame is replaced.
      let headInfo = null, bodyBuf = Buffer.alloc(0), eventBuf = Buffer.alloc(0), activeSid = null, prevSig = null, injected = false, headSent = false;
      const fail = () => { if (!downstream.destroyed) downstream.destroy(); if (!upstream.destroyed) upstream.destroy(); };
      const emit = bytes => { if (!downstream.destroyed) downstream.write(bytes); };
      const chunkOut = bytes => emit(Buffer.concat([Buffer.from(`${bytes.length.toString(16)}\r\n`, 'latin1'), bytes, Buffer.from('\r\n')]));
      const pump = () => {
        if (injected) return;
        if (!headInfo) {
          const at = bodyBuf.indexOf('\r\n\r\n');
          if (at < 0) { if (bodyBuf.length > MAX_HEAD) fail(); return; }
          try { headInfo = splitHead(bodyBuf.subarray(0, at + 4)); } catch { fail(); return; }
          const activeAuth = headInfo.headers.find(([name]) => name === 'jack-auth')?.[1] || '';
          const openMatch = /^s1 kid=[A-Za-z0-9_-]+,ts=[0-9]+,sid=([A-Za-z0-9_-]+),sig=([A-Za-z0-9_-]+)$/.exec(activeAuth);
          activeSid = openMatch?.[1] || null; prevSig = openMatch?.[2] || null;
          bodyBuf = bodyBuf.subarray(at + 4);
        }
        if (!headSent) {
          const lines = headInfo.lines.filter(line => !/^(content-length|transfer-encoding|connection)\s*:/i.test(line));
          lines.push('Transfer-Encoding: chunked');
          emit(Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1')); headSent = true;
        }
        for (;;) {
          if (headInfo.chunked) {
            let decoded; try { decoded = decodeChunks(bodyBuf, false); } catch { fail(); return; }
            if (!decoded) break;
            bodyBuf = bodyBuf.subarray(decoded.used); eventBuf = Buffer.concat([eventBuf, decoded.body]);
          } else if (headInfo.length !== null) {
            if (bodyBuf.length < headInfo.length) break;
            eventBuf = Buffer.concat([eventBuf, bodyBuf.subarray(0, headInfo.length)]); bodyBuf = bodyBuf.subarray(headInfo.length);
          } else break;
        }
        for (;;) {
          const crlf = eventBuf.indexOf('\r\n\r\n'), lf = eventBuf.indexOf('\n\n');
          let end, delim;
          if (crlf >= 0 && (lf < 0 || crlf <= lf)) { end = crlf; delim = 4; }
          else if (lf >= 0) { end = lf; delim = 2; } else break;
          const event = eventBuf.subarray(0, end + delim); eventBuf = eventBuf.subarray(end + delim);
          const { fields } = parseEvent(event);
          if (fields.kind === 'jack-end') {
            let frame;
            try { frame = scenario.relayCutoffSign({ sid: activeSid, seq: Number(fields.seq), prev: prevSig }); } catch { fail(); return; }
            if (!Buffer.isBuffer(frame)) { fail(); return; }
            injected = true; applied = true;
            chunkOut(frame); emit(Buffer.from('0\r\n\r\n', 'latin1'));
            if (!downstream.destroyed) downstream.end();
            if (!upstream.destroyed) upstream.destroy();
            return;
          }
          chunkOut(event);
          if (fields.sig) prevSig = fields.sig;
        }
      };
      upstream.on('data', chunk => { bodyBuf = Buffer.concat([bodyBuf, chunk]); pump(); });
      upstream.on('end', () => { if (!injected) fail(); });
      return;
    }
    const finish = eof => {
      if (completed) return;
      if (!head) { head = splitHead(responseBuffer); if (!head) { if (eof) downstream.destroy(); return; } responseBuffer = responseBuffer.subarray(head.size); }
      let body, framingUsed = responseBuffer.length;
      if (head.chunked) { const decoded = decodeChunks(responseBuffer, eof); if (!decoded) return; body = decoded.body; framingUsed = decoded.used; }
      else if (head.length !== null) { if (responseBuffer.length < head.length) { if (eof) downstream.destroy(); return; } body = responseBuffer.subarray(0, head.length); framingUsed = head.length; }
      else { if (!eof) return; body = responseBuffer; }
      if (body.length > MAX_BODY) { downstream.destroy(); return; }
      const activeAuth = head.headers.find(([name]) => name === 'jack-auth')?.[1] || '';
      const activeSid = /^s1 kid=[A-Za-z0-9_-]+,ts=[0-9]+,sid=([A-Za-z0-9_-]+),sig=[A-Za-z0-9_-]+$/.exec(activeAuth)?.[1];
      const changed = eventTransform(body, transform, { ...scenario, activeSid }, null); applied ||= changed.applied;
      const out = rebuild(head, changed.body, head.chunked);
      completed = true;
      if (!downstream.destroyed) downstream.end(out);
      if (changed.responseEnded) upstream.destroy();
      if (responseBuffer.length > framingUsed && !head.chunked && head.length !== null) upstream.destroy();
    };
    upstream.on('data', chunk => {
      responseBuffer = responseBuffer.length ? Buffer.concat([responseBuffer, chunk]) : chunk;
      if (!head && responseBuffer.length > MAX_HEAD) { downstream.destroy(); upstream.destroy(); return; }
      try { finish(false); } catch { downstream.destroy(); upstream.destroy(); }
    });
    upstream.on('end', () => { try { finish(true); } catch { downstream.destroy(); } if (!completed && !downstream.destroyed) downstream.end(); });
    upstream.on('close', () => { if (!completed && !downstream.destroyed) downstream.end(); });
  });
  await new Promise((resolveListen, rejectListen) => { server.once('error', rejectListen); server.listen(0, '127.0.0.1', resolveListen); });
  return { port: server.address().port, applied: () => applied, close() {
    if (closePromise) return closePromise;
    closePromise = new Promise(resolveClose => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      if (!server.listening) { resolveClose(); return; }
      server.close(resolveClose);
    });
    return closePromise;
  } };
}
