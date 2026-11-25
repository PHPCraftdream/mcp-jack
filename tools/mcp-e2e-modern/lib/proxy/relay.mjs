import net from 'node:net';
import { chmodSync } from 'node:fs';

export function startRelay({ socketPath, target }) {
  const upstreamTarget = new URL(target);
  if (upstreamTarget.protocol !== 'http:') throw new TypeError('relay target must use http');
  const methods = [];
  const server = net.createServer((client) => {
    const upstream = net.createConnection({ host: upstreamTarget.hostname, port: Number(upstreamTarget.port || 80) });
    let headerBuffer = '';
    let bodyRemaining = 0;
    let chunkRemaining = null;
    let chunked = false;
    let chunkTerminator = false;
    let readingTrailers = false;
    let trailerBuffer = '';
    let chunkBuffer = '';
    let currentEntry = null;
    let headerLimitReached = false;
    const storeBody = (data) => {
      if (!currentEntry || currentEntry.body.length >= 4096) return;
      currentEntry.body += data.slice(0, 4096 - currentEntry.body.length);
    };
    client.on('data', (chunk) => {
      if (methods.length >= 200 || headerLimitReached) return;
      let input = chunkBuffer + chunk.toString('latin1');
      chunkBuffer = '';
      while (input && methods.length < 200 && !headerLimitReached) {
        if (chunked && currentEntry) {
          if (chunkRemaining !== null) {
            const consumed = Math.min(chunkRemaining, input.length);
            storeBody(input.slice(0, consumed));
            chunkRemaining -= consumed;
            input = input.slice(consumed);
            if (chunkRemaining === 0) chunkTerminator = true;
            else break;
            continue;
          }
          if (chunkTerminator) {
            if (input.length < 2) { chunkBuffer = input; break; }
            if (!input.startsWith('\r\n')) { headerLimitReached = true; break; }
            input = input.slice(2);
            chunkTerminator = false;
            continue;
          }
          if (readingTrailers) {
            trailerBuffer += input;
            const trailerEnd = trailerBuffer.indexOf('\r\n\r\n');
            if (trailerEnd >= 0) {
              input = trailerBuffer.slice(trailerEnd + 4);
              trailerBuffer = '';
              currentEntry = null;
              chunked = false;
              readingTrailers = false;
            } else {
              if (trailerBuffer === '\r\n') {
                input = '';
                trailerBuffer = '';
                currentEntry = null;
                chunked = false;
                readingTrailers = false;
              } else input = '';
            }
            continue;
          }
          const sizeEnd = input.indexOf('\r\n');
          if (sizeEnd < 0) { chunkBuffer = input; break; }
          const sizeText = input.slice(0, sizeEnd).split(';', 1)[0].trim();
          if (!/^[0-9a-f]+$/i.test(sizeText)) { headerLimitReached = true; break; }
          const size = Number.parseInt(sizeText, 16);
          input = input.slice(sizeEnd + 2);
          if (size === 0) readingTrailers = true;
          else chunkRemaining = size;
          continue;
        }
        if (bodyRemaining > 0) {
          const consumed = Math.min(bodyRemaining, input.length);
          storeBody(input.slice(0, consumed));
          bodyRemaining -= consumed;
          input = input.slice(consumed);
          if (bodyRemaining === 0) currentEntry = null;
          continue;
        }
        const delimiter = input.indexOf('\r\n\r\n');
        if (delimiter < 0) {
          headerBuffer += input;
          if (Buffer.byteLength(headerBuffer, 'latin1') > 65536) {
            headerBuffer = '';
            headerLimitReached = true;
          }
          break;
        }
        const header = headerBuffer + input.slice(0, delimiter);
        headerBuffer = '';
        input = input.slice(delimiter + 4);
        const lines = header.split('\r\n');
        const parsed = /^([^\s]+)\s+([^\s]+)\s+HTTP\/\d(?:\.\d)?$/.exec(lines[0] ?? '');
        currentEntry = parsed ? { method: parsed[1], path: parsed[2], body: '' } : null;
        if (currentEntry && methods.length < 200) methods.push(currentEntry);
        const lengthLine = lines.find((line) => /^content-length\s*:/i.test(line));
        const transferLine = lines.find((line) => /^transfer-encoding\s*:/i.test(line));
        chunked = Boolean(transferLine && /(?:^|,)\s*chunked(?:\s|,|$)/i.test(transferLine.split(':').slice(1).join(':')));
        if (chunked) {
          bodyRemaining = 0;
          chunkRemaining = null;
          chunkTerminator = false;
          readingTrailers = false;
          trailerBuffer = '';
        } else {
          bodyRemaining = lengthLine ? Math.max(0, Number(lengthLine.split(':', 2)[1].trim()) || 0) : 0;
          if (!bodyRemaining) currentEntry = null;
        }
      }
    });
    client.pipe(upstream);
    upstream.pipe(client);
    const destroyPeer = () => { client.destroy(); upstream.destroy(); };
    client.on('error', destroyPeer);
    upstream.on('error', destroyPeer);
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
  });
  const ready = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => { server.off('error', reject); chmodSync(socketPath, 0o600); resolve(); });
  });
  return {
    socketPath,
    ready,
    methods,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
